import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('ISO BMFF hash layout', () {
    test('builds bounded recursive MP4, MOV, and HEIF box trees', () async {
      final reader = const IsoBmffHashLayoutReader();
      final stco = _fullBox('stco', version: 0, flags: 1, payload: const [7]);
      final mp4 = <int>[
        ..._ftyp('mp42'),
        ..._box(
          'moov',
          _box('trak', _box('mdia', _box('minf', _box('stbl', stco)))),
        ),
      ];
      final mov = <int>[
        ..._ftyp('qt  '),
        ..._box('moov', _box('meta', _box('hdlr', const [0, 0, 0, 0]))),
      ];
      final heif = <int>[
        ..._ftyp('mif1'),
        ..._box('meta', <int>[
          0,
          0,
          0,
          0,
          ..._fullBox('iloc', payload: const [1, 2]),
        ]),
      ];

      final mp4Layout = await reader.read(MemoryByteSource(mp4), const []);
      final movLayout = await reader.read(MemoryByteSource(mov), const []);
      final heifLayout = await reader.read(MemoryByteSource(heif), const []);

      expect(
        mp4Layout.boxes[1].descendants.map((node) => node.path),
        contains('/moov/trak/mdia/minf/stbl/stco'),
      );
      final stcoNode = mp4Layout.boxes[1].descendants.last;
      expect(stcoNode.version, 0);
      expect(stcoNode.flags, 1);
      expect(movLayout.boxes[1].children.single.path, '/moov/meta');
      expect(movLayout.boxes[1].children.single.version, isNull);
      expect(
        movLayout.boxes[1].children.single.children.single.path,
        '/moov/meta/hdlr',
      );
      expect(heifLayout.boxes[1].version, 0);
      expect(heifLayout.boxes[1].children.single.path, '/meta/iloc');
    });

    test(
      'applies xpath, length, version, flags, data, and subset rules',
      () async {
        final reader = const IsoBmffHashLayoutReader();
        final target = _fullBox(
          'stco',
          version: 2,
          flags: 1,
          payload: const <int>[10, 11, 12, 13, 14, 15, 16, 17],
        );
        final source = <int>[
          ..._ftyp('mp42'),
          ..._box(
            'moov',
            _box('trak', _box('mdia', _box('minf', _box('stbl', target)))),
          ),
          ..._box('mdat', List<int>.filled(20, 9)),
        ];
        final targetOffset = _find(source, 'stco') - 4;
        final layout = await reader.read(
          MemoryByteSource(source),
          <IsoBmffExclusion>[
            IsoBmffExclusion(
              xpath: '/moov/trak/mdia/minf/stbl/stco',
              length: target.length,
              version: 2,
              flags: const <int>[0, 0, 3],
              exact: false,
              data: <IsoBmffDataMatch>[
                IsoBmffDataMatch(offset: 4, value: 'stco'.codeUnits),
              ],
              subset: const <IsoBmffSubset>[
                IsoBmffSubset(offset: 12, length: 3),
                IsoBmffSubset(offset: 17),
              ],
            ),
          ],
        );

        expect(layout.exclusions, <ByteRange>[
          ByteRange(targetOffset + 12, targetOffset + 15),
          ByteRange(targetOffset + 17, targetOffset + target.length),
        ]);

        final noMatch = await reader.read(
          MemoryByteSource(source),
          <IsoBmffExclusion>[
            IsoBmffExclusion(
              xpath: '/moov/trak/mdia/minf/stbl/stco',
              version: 3,
            ),
            IsoBmffExclusion(
              xpath: '/moov/trak/mdia/minf/stbl/stco',
              data: <IsoBmffDataMatch>[
                IsoBmffDataMatch(offset: 4, value: 'xxxx'.codeUnits),
              ],
            ),
          ],
        );
        expect(noMatch.exclusions, isEmpty);
      },
    );

    test('emits source and unsigned 64-bit top-level offset events', () async {
      final source = <int>[
        ..._ftyp('mp42'),
        ..._box('free', const [1, 2, 3]),
        ..._box('mdat', const [4, 5, 6, 7]),
      ];
      const logicalBase = 0x100000000;
      final layout = await const IsoBmffHashLayoutReader().read(
        MemoryByteSource(source),
        <IsoBmffExclusion>[
          IsoBmffExclusion(xpath: '/free'),
          IsoBmffExclusion(
            xpath: '/mdat',
            subset: const <IsoBmffSubset>[IsoBmffSubset(offset: 9, length: 1)],
          ),
        ],
        logicalOffset: logicalBase,
      );
      final offsets = layout.events
          .whereType<IsoBmffOffsetDigestEvent>()
          .toList();
      final mdatOffset = _find(source, 'mdat') - 4;

      expect(offsets.map((event) => event.boxOffset), <int>[0, mdatOffset]);
      expect(offsets.first.bytes, const <int>[0, 0, 0, 0, 0, 0, 0, 0]);
      expect(offsets.last.bytes, _uint64(mdatOffset));
      expect(
        layout.events.whereType<IsoBmffSourceDigestEvent>().any(
          (event) =>
              event.range.start <= mdatOffset && event.range.end > mdatOffset,
        ),
        isTrue,
      );
    });

    test('encodes top-level offsets above 32 bits as eight bytes', () async {
      const secondOffset = 0x100000000;
      final source = _SparseByteSource(secondOffset + 8, <int, List<int>>{
        0: <int>[0, 0, 0, 1, ...'free'.codeUnits],
        8: _uint64(secondOffset),
        secondOffset: <int>[0, 0, 0, 8, ...'mdat'.codeUnits],
      });
      final layout = await const IsoBmffHashLayoutReader(
        maxSourceSize: secondOffset + 8,
      ).read(source, const <IsoBmffExclusion>[]);

      final offsets = layout.events
          .whereType<IsoBmffOffsetDigestEvent>()
          .toList();
      expect(offsets, hasLength(2));
      expect(offsets.last.boxOffset, secondOffset);
      expect(offsets.last.bytes, const <int>[0, 0, 0, 1, 0, 0, 0, 0]);
    });

    test(
      'does not inject an offset for a fully excluded top-level box',
      () async {
        final source = <int>[
          ..._ftyp('mp42'),
          ..._box('free', const [1, 2]),
          ..._box('mdat', const [3, 4]),
        ];
        final layout = await const IsoBmffHashLayoutReader().read(
          MemoryByteSource(source),
          <IsoBmffExclusion>[IsoBmffExclusion(xpath: '/free')],
        );
        final freeOffset = _find(source, 'free') - 4;

        expect(
          layout.events.whereType<IsoBmffOffsetDigestEvent>().map(
            (event) => event.boxOffset,
          ),
          isNot(contains(freeOffset)),
        );
      },
    );

    test('rejects overlapping, unordered, and out-of-bounds maps', () async {
      final source = <int>[
        ..._ftyp('mp42'),
        ..._box('mdat', List<int>.filled(20, 0)),
      ];
      final reader = const IsoBmffHashLayoutReader();

      await expectLater(
        reader.read(MemoryByteSource(source), <IsoBmffExclusion>[
          IsoBmffExclusion(xpath: '/mdat'),
          IsoBmffExclusion(
            xpath: '/mdat',
            subset: const <IsoBmffSubset>[IsoBmffSubset(offset: 8, length: 2)],
          ),
        ]),
        throwsA(isA<MalformedBmffHashLayoutException>()),
      );
      await expectLater(
        reader.read(MemoryByteSource(source), <IsoBmffExclusion>[
          IsoBmffExclusion(
            xpath: '/mdat',
            subset: const <IsoBmffSubset>[
              IsoBmffSubset(offset: 12, length: 2),
              IsoBmffSubset(offset: 10, length: 1),
            ],
          ),
        ]),
        throwsA(isA<MalformedBmffHashLayoutException>()),
      );
      await expectLater(
        reader.read(MemoryByteSource(source), <IsoBmffExclusion>[
          IsoBmffExclusion(
            xpath: '/mdat',
            data: <IsoBmffDataMatch>[
              IsoBmffDataMatch(offset: 100, value: const [1]),
            ],
          ),
        ]),
        throwsA(isA<MalformedBmffHashLayoutException>()),
      );
    });

    test('describes ordered fragmented sources and C2PA metadata', () async {
      final init = <int>[
        ..._ftyp('mp42'),
        ..._box('moov', _box('mvex', const [])),
        ..._c2paBox('manifest', const [1, 2, 3], auxiliaryOffset: 48),
      ];
      final firstFragment = <int>[
        ..._box('moof', _fullBox('mfhd', payload: const [0, 0, 0, 1])),
        ..._box('mdat', List<int>.filled(24, 7)),
        ..._c2paBox('merkle', const [0xa1, 0x01, 0x02]),
      ];
      final secondFragment = <int>[
        ..._box('moof', <int>[
          ..._fullBox('mfhd', payload: const [0, 0, 0, 2]),
          ..._box('traf', _fullBox('tfhd', flags: 1)),
        ]),
        ..._box('mdat', List<int>.filled(24, 8)),
        ..._c2paBox('merkle', const [0xa1, 0x03, 0x04]),
      ];
      final fragmented = FragmentedIsoBmffSource(
        initializationSegment: MemoryByteSource(init),
        fragments: <RandomAccessByteSource>[
          MemoryByteSource(firstFragment),
          MemoryByteSource(secondFragment),
        ],
      );

      final layout = await const IsoBmffAssetHandler(format: AssetFormat.mp4)
          .getFragmentedBmffLayout(fragmented, <IsoBmffExclusion>[
            IsoBmffExclusion(
              xpath: '/mdat',
              subset: const <IsoBmffSubset>[IsoBmffSubset(offset: 16)],
            ),
            IsoBmffExclusion(xpath: '/uuid'),
          ]);

      expect(layout.segments, hasLength(3));
      expect(
        layout.logicalLength,
        init.length + firstFragment.length + secondFragment.length,
      );
      expect(layout.segments[0].logicalOffset, 0);
      expect(layout.segments[1].logicalOffset, init.length);
      expect(
        layout.segments[2].logicalOffset,
        init.length + firstFragment.length,
      );
      expect(layout.segments[0].c2paMetadata.single.purpose, 'manifest');
      expect(layout.segments[1].sequenceNumber, 1);
      expect(layout.segments[2].sequenceNumber, 2);
      expect(layout.segments[0].c2paMetadata.single.auxiliaryOffset, 48);
      expect(layout.segments[1].c2paMetadata.single.purpose, 'merkle');
      expect(layout.segments[2].c2paMetadata.single.isMerkle, isTrue);
      expect(
        layout.segments[1].c2paMetadata.single.logicalBoxOffset,
        init.length + _find(firstFragment, 'uuid') - 4,
      );
      expect(
        layout.segments[2].hashLayout.events
            .whereType<IsoBmffOffsetDigestEvent>()
            .every((event) => event.segmentIndex == 2),
        isTrue,
      );
    });

    test(
      'routes advanced layouts and enforces recursion and fragment limits',
      () async {
        final init = <int>[..._ftyp('mp42'), ..._box('moov', const [])];
        final fragment = <int>[
          ..._box('moof', _fullBox('mfhd', payload: const [0, 0, 0, 1])),
          ..._box('mdat', const [1]),
        ];
        final registryLayout = await AssetHandlerRegistry().getBmffHashLayout(
          MemoryByteSource(init),
          const <IsoBmffExclusion>[],
          fileExtension: 'mp4',
        );
        expect(registryLayout.boxes.map((node) => node.box.type), [
          'ftyp',
          'moov',
        ]);

        await expectLater(
          const IsoBmffHashLayoutReader(maxDepth: 1).read(
            MemoryByteSource(<int>[
              ..._ftyp('mp42'),
              ..._box('moov', _box('trak', _box('mdia', const []))),
            ]),
            const <IsoBmffExclusion>[],
          ),
          throwsA(isA<SegmentLimitExceededException>()),
        );
        await expectLater(
          const IsoBmffHashLayoutReader(maxFragments: 1).readFragmented(
            FragmentedIsoBmffSource(
              initializationSegment: MemoryByteSource(init),
              fragments: <RandomAccessByteSource>[
                MemoryByteSource(fragment),
                MemoryByteSource(fragment),
              ],
            ),
            const <IsoBmffExclusion>[],
          ),
          throwsA(isA<SegmentLimitExceededException>()),
        );
        await expectLater(
          const IsoBmffHashLayoutReader().readFragmented(
            FragmentedIsoBmffSource(
              initializationSegment: MemoryByteSource(init),
              fragments: <RandomAccessByteSource>[
                MemoryByteSource(<int>[
                  ..._box(
                    'moof',
                    _fullBox('mfhd', payload: const [0, 0, 0, 2]),
                  ),
                  ..._box('mdat', const [1]),
                ]),
                MemoryByteSource(fragment),
              ],
            ),
            const <IsoBmffExclusion>[],
          ),
          throwsA(isA<MalformedAssetFormatException>()),
        );
        await expectLater(
          const IsoBmffHashLayoutReader(maxTotalFragmentedSize: 1)
              .readFragmented(
                FragmentedIsoBmffSource(
                  initializationSegment: MemoryByteSource(init),
                  fragments: const <RandomAccessByteSource>[],
                ),
                const <IsoBmffExclusion>[],
              ),
          throwsA(isA<AssetLimitExceededException>()),
        );
      },
    );
  });
}

List<int> _ftyp(String brand) =>
    _box('ftyp', <int>[...brand.codeUnits, 0, 0, 0, 0, ...brand.codeUnits]);

List<int> _fullBox(
  String type, {
  int version = 0,
  int flags = 0,
  List<int> payload = const <int>[],
}) => _box(type, <int>[
  version,
  (flags >> 16) & 0xff,
  (flags >> 8) & 0xff,
  flags & 0xff,
  ...payload,
]);

List<int> _box(String type, List<int> payload) {
  final size = 8 + payload.length;
  return <int>[
    (size >> 24) & 0xff,
    (size >> 16) & 0xff,
    (size >> 8) & 0xff,
    size & 0xff,
    ...type.codeUnits,
    ...payload,
  ];
}

List<int> _c2paBox(String purpose, List<int> data, {int auxiliaryOffset = 0}) {
  final payload = <int>[
    ...IsoBmffAssetHandler.c2paUuid,
    0,
    0,
    0,
    0,
    ...purpose.codeUnits,
    0,
    if (purpose != 'merkle') ..._uint64(auxiliaryOffset),
    ...data,
  ];
  return _box('uuid', payload);
}

List<int> _uint64(int value) => <int>[
  (value >> 56) & 0xff,
  (value >> 48) & 0xff,
  (value >> 40) & 0xff,
  (value >> 32) & 0xff,
  (value >> 24) & 0xff,
  (value >> 16) & 0xff,
  (value >> 8) & 0xff,
  value & 0xff,
];

int _find(List<int> bytes, String value) {
  final pattern = value.codeUnits;
  for (var offset = 0; offset <= bytes.length - pattern.length; offset++) {
    var matches = true;
    for (var index = 0; index < pattern.length; index++) {
      if (bytes[offset + index] != pattern[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return offset;
  }
  throw StateError('$value not found');
}

final class _SparseByteSource implements RandomAccessByteSource {
  _SparseByteSource(this._length, this._regions);

  final int _length;
  final Map<int, List<int>> _regions;

  @override
  Future<int> get length async => _length;

  @override
  Future<Uint8List> read(ByteRange range) async {
    if (range.end > _length) {
      throw ByteRangeOutOfBoundsException(range, ByteRange(0, _length));
    }
    final output = Uint8List(range.length);
    for (final region in _regions.entries) {
      final overlapStart = range.start > region.key ? range.start : region.key;
      final regionEnd = region.key + region.value.length;
      final overlapEnd = range.end < regionEnd ? range.end : regionEnd;
      if (overlapStart >= overlapEnd) continue;
      output.setRange(
        overlapStart - range.start,
        overlapEnd - range.start,
        region.value,
        overlapStart - region.key,
      );
    }
    return output;
  }
}
