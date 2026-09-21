import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  for (final fixture in <_RiffFixture>[
    _RiffFixture(
      format: AssetFormat.webp,
      form: 'WEBP',
      chunks: [
        _chunk('VP8 ', const [1, 2, 3], padByte: 0x7f),
      ],
    ),
    _RiffFixture(
      format: AssetFormat.wav,
      form: 'WAVE',
      chunks: [
        _chunk('fmt ', List<int>.filled(16, 1)),
        _chunk('data', const [2, 3, 4, 5]),
      ],
    ),
    _RiffFixture(
      format: AssetFormat.avi,
      form: 'AVI ',
      chunks: [
        _chunk('LIST', const [1, 2, 3, 4]),
        _chunk('movi', const [5, 6]),
      ],
      trailing: _riff('AVIX', [
        _chunk('movi', const [7, 8, 9], padByte: 0x55),
      ]),
    ),
  ]) {
    group('${fixture.format.name} RIFF handler', () {
      final handler = RiffAssetHandler(format: fixture.format);

      test('detects and round-trips an embedded manifest', () async {
        final source = fixture.bytes;
        final manifest = Uint8List.fromList(
          List<int>.generate(301, (index) => index & 0xff),
        );
        final output = MemoryByteSink();

        expect(await handler.detect(MemoryByteSource(source)), isTrue);
        await handler.embedManifest(MemoryByteSource(source), manifest, output);

        final written = output.toBytes();
        expect(
          await handler.extractManifest(MemoryByteSource(written)),
          manifest,
        );
        expect(written, [
          ..._riff(fixture.form, [...fixture.chunks, _chunk('C2PA', manifest)]),
          ...fixture.trailing,
        ]);
        final rewrittenRiffEnd = 8 + _readLittle32(written, 4);
        if (fixture.format == AssetFormat.avi) {
          expect(
            String.fromCharCodes(
              written.sublist(rewrittenRiffEnd, rewrittenRiffEnd + 4),
            ),
            'RIFF',
          );
        } else {
          expect(rewrittenRiffEnd, written.length);
        }
      });
    });
  }

  group('RiffAssetHandler mutations', () {
    const handler = RiffAssetHandler(format: AssetFormat.webp);

    test(
      'uses uppercase C2PA, little-endian length, and even padding',
      () async {
        final source = _riff('WEBP', [
          _chunk('VP8 ', const [1, 2]),
        ]);
        final output = MemoryByteSink();
        await handler.embedManifest(
          MemoryByteSource(source),
          Uint8List.fromList(const [9, 8, 7]),
          output,
        );

        final written = output.toBytes();
        final chunkOffset = written.length - 12;
        expect(
          String.fromCharCodes(written.sublist(chunkOffset, chunkOffset + 4)),
          'C2PA',
        );
        expect(written.sublist(chunkOffset + 4, chunkOffset + 8), [3, 0, 0, 0]);
        expect(written.sublist(chunkOffset + 8), [9, 8, 7, 0]);
      },
    );

    test(
      'replaces at the end and removes while preserving unrelated bytes',
      () async {
        final prefixChunk = _chunk('VP8 ', const [1, 2, 3], padByte: 0x6a);
        final suffixChunk = _chunk('XMP ', const [4, 5]);
        final source = _riff('WEBP', [
          prefixChunk,
          _chunk('C2PA', const [1]),
          suffixChunk,
        ]);
        final replacement = Uint8List.fromList(const [8, 9, 10, 11]);
        final replaced = MemoryByteSink();

        await handler.replaceManifest(
          MemoryByteSource(source),
          replacement,
          replaced,
        );

        final expectedReplaced = _riff('WEBP', [
          prefixChunk,
          suffixChunk,
          _chunk('C2PA', replacement),
        ]);
        expect(replaced.toBytes(), expectedReplaced);

        final removed = MemoryByteSink();
        await handler.removeManifest(
          MemoryByteSource(replaced.toBytes()),
          removed,
        );
        expect(removed.toBytes(), _riff('WEBP', [prefixChunk, suffixChunk]));
      },
    );

    test('rejects duplicate and malformed chunks before output', () async {
      final duplicate = _riff('WEBP', [
        _chunk('C2PA', const [1]),
        _chunk('C2PA', const [2]),
      ]);
      final truncated = [
        ...'RIFF'.codeUnits,
        20,
        0,
        0,
        0,
        ...'WEBP'.codeUnits,
        ...'VP8 '.codeUnits,
        10,
        0,
        0,
        0,
        1,
      ];
      final duplicateOutput = MemoryByteSink();
      final malformedOutput = MemoryByteSink();

      await expectLater(
        handler.replaceManifest(
          MemoryByteSource(duplicate),
          Uint8List.fromList(const [3]),
          duplicateOutput,
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      await expectLater(
        handler.embedManifest(
          MemoryByteSource(truncated),
          Uint8List.fromList(const [3]),
          malformedOutput,
        ),
        throwsA(isA<TruncatedAssetException>()),
      );
      expect(duplicateOutput.toBytes(), isEmpty);
      expect(malformedOutput.toBytes(), isEmpty);
    });

    test('rejects root overflow, trailing corruption, and wrong forms', () {
      final overflow = [
        ...'RIFF'.codeUnits,
        0xff,
        0xff,
        0xff,
        0xff,
        ...'WEBP'.codeUnits,
      ];
      final trailing = [..._riff('WEBP', const []), 0];
      final wrongForm = _riff('WAVE', const []);

      expect(
        handler.extractManifest(MemoryByteSource(overflow)),
        throwsA(isA<TruncatedAssetException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(trailing)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(wrongForm)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('validates AVI AVIX continuation chunks', () {
      final handler = RiffAssetHandler(format: AssetFormat.avi);
      final malformed = [
        ..._riff('AVI ', const []),
        ..._riff('WAVE', const []),
      ];

      expect(
        handler.extractManifest(MemoryByteSource(malformed)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('enforces source, output, manifest, and chunk-count limits', () {
      final source = _riff('WEBP', [
        _chunk('VP8 ', const [1]),
      ]);
      final manifest = Uint8List(20);

      expect(
        const RiffAssetHandler(
          format: AssetFormat.webp,
          maxManifestSize: 10,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        RiffAssetHandler(
          format: AssetFormat.webp,
          maxSourceSize: source.length - 1,
        ).embedManifest(
          MemoryByteSource(source),
          Uint8List(1),
          MemoryByteSink(),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        RiffAssetHandler(
          format: AssetFormat.webp,
          maxOutputSize: source.length,
        ).embedManifest(
          MemoryByteSource(source),
          Uint8List(1),
          MemoryByteSink(),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        const RiffAssetHandler(
          format: AssetFormat.webp,
          maxChunkCount: 1,
        ).extractManifest(
          MemoryByteSource(
            _riff('WEBP', [_chunk('VP8 ', const []), _chunk('XMP ', const [])]),
          ),
        ),
        throwsA(isA<SegmentLimitExceededException>()),
      );
    });

    test('propagates sink failures and reports capabilities', () {
      final source = _riff('WEBP', const []);

      expect(
        handler.embedManifest(
          MemoryByteSource(source),
          Uint8List.fromList(const [1]),
          _FailingSink(),
        ),
        throwsA(isA<StateError>()),
      );
      expect(handler.capabilities.canExtractManifest, isTrue);
      expect(handler.capabilities.canEmbedManifest, isTrue);
      expect(handler.capabilities.canReplaceManifest, isTrue);
      expect(handler.capabilities.canRemoveManifest, isTrue);
    });
  });

  group('RIFF remote references', () {
    final fixtures = <(AssetFormat, String, List<List<int>>)>[
      (
        AssetFormat.webp,
        'WEBP',
        [
          _chunk('VP8L', const [0x2f, 0, 0, 0, 0]),
          _chunk('zzzz', const [7, 8]),
        ],
      ),
      (
        AssetFormat.wav,
        'WAVE',
        [
          _chunk('fmt ', const [1, 2]),
          _chunk('data', const [3, 4]),
        ],
      ),
      (
        AssetFormat.avi,
        'AVI ',
        [
          _chunk('LIST', const [1, 2]),
          _chunk('movi', const [3, 4]),
        ],
      ),
    ];

    for (final fixture in fixtures) {
      test('round-trips ${fixture.$1.name} XMP', () async {
        final handler = RiffAssetHandler(format: fixture.$1);
        final source = _riff(fixture.$2, fixture.$3);
        final preserved = fixture.$3.last;
        final embedded = MemoryByteSink();
        await handler.updateRemoteManifestReference(
          MemoryByteSource(source),
          'https://example.com/one',
          embedded,
        );
        expect(
          await handler.readRemoteManifestReference(
            MemoryByteSource(embedded.toBytes()),
          ),
          'https://example.com/one',
        );
        expect(_containsBytes(embedded.toBytes(), preserved), isTrue);
        if (fixture.$1 == AssetFormat.webp) {
          final vp8x = _indexOfAscii(embedded.toBytes(), 'VP8X');
          expect(vp8x, greaterThan(0));
          expect(embedded.toBytes()[vp8x + 8] & 0x04, 0x04);
        }

        final replaced = MemoryByteSink();
        await handler.updateRemoteManifestReference(
          MemoryByteSource(embedded.toBytes()),
          'self#jumbf=c2pa/two',
          replaced,
        );
        final removed = MemoryByteSink();
        await handler.removeRemoteManifestReference(
          MemoryByteSource(replaced.toBytes()),
          removed,
        );
        expect(
          await handler.readRemoteManifestReference(
            MemoryByteSource(removed.toBytes()),
          ),
          isNull,
        );
        expect(_containsBytes(removed.toBytes(), preserved), isTrue);
      });
    }

    test(
      'rejects duplicate and malformed XMP and propagates failures',
      () async {
        final packet = utf8.encode(_minimalXmp);
        final duplicate = _riff('WAVE', [
          _chunk('XMP ', packet),
          _chunk('XMP ', packet),
        ]);
        await expectLater(
          const RiffAssetHandler(format: AssetFormat.wav)
              .readXmp(MemoryByteSource(duplicate)),
          throwsA(isA<MalformedAssetFormatException>()),
        );
        await expectLater(
          const RiffAssetHandler(format: AssetFormat.wav)
              .readRemoteManifestReference(
                MemoryByteSource(
                  _riff('WAVE', [_chunk('XMP ', utf8.encode('<bad'))]),
                ),
              ),
          throwsA(isA<MalformedAssetFormatException>()),
        );
        await expectLater(
          const RiffAssetHandler(format: AssetFormat.wav)
              .readRemoteManifestReference(
                MemoryByteSource(
                  _riff('WAVE', [
                    _chunk('XMP ', const [0xff]),
                  ]),
                ),
              ),
          throwsA(isA<MalformedAssetFormatException>()),
        );
        await expectLater(
          const RiffAssetHandler(
            format: AssetFormat.wav,
            maxRemoteReferenceLength: 3,
          ).updateRemoteManifestReference(
            MemoryByteSource(
              _riff('WAVE', [
                _chunk('fmt ', const [1, 2]),
              ]),
            ),
            'long',
            MemoryByteSink(),
          ),
          throwsA(isA<AssetLimitExceededException>()),
        );
        await expectLater(
          const RiffAssetHandler(format: AssetFormat.wav)
              .updateRemoteManifestReference(
                MemoryByteSource(
                  _riff('WAVE', [
                    _chunk('fmt ', const [1, 2]),
                  ]),
                ),
                'https://example.com',
                _FailingSink(),
              ),
          throwsA(isA<StateError>()),
        );
      },
    );
  });
}

const _minimalXmp =
    '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
    '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    '<rdf:Description/></rdf:RDF></x:xmpmeta>';

final class _RiffFixture {
  const _RiffFixture({
    required this.format,
    required this.form,
    required this.chunks,
    this.trailing = const [],
  });

  final AssetFormat format;
  final String form;
  final List<List<int>> chunks;
  final List<int> trailing;

  List<int> get firstRiff => _riff(form, chunks);
  List<int> get bytes => [...firstRiff, ...trailing];
}

List<int> _riff(String form, List<List<int>> chunks) {
  final payload = <int>[
    ...form.codeUnits,
    for (final chunk in chunks) ...chunk,
  ];
  return [...'RIFF'.codeUnits, ..._little32(payload.length), ...payload];
}

List<int> _chunk(String type, List<int> data, {int padByte = 0}) => [
  ...type.codeUnits,
  ..._little32(data.length),
  ...data,
  if (data.length.isOdd) padByte,
];

List<int> _little32(int value) => [
  value & 0xff,
  (value >> 8) & 0xff,
  (value >> 16) & 0xff,
  (value >> 24) & 0xff,
];

int _readLittle32(List<int> bytes, int offset) =>
    bytes[offset] |
    (bytes[offset + 1] << 8) |
    (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24);

int _indexOfAscii(List<int> bytes, String value) {
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
  return -1;
}

bool _containsBytes(List<int> bytes, List<int> pattern) {
  for (var offset = 0; offset <= bytes.length - pattern.length; offset++) {
    var matches = true;
    for (var index = 0; index < pattern.length; index++) {
      if (bytes[offset + index] != pattern[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

final class _FailingSink implements WritableByteSink {
  @override
  Future<int> get length async => 0;

  @override
  Future<void> append(List<int> bytes) async {
    throw StateError('simulated sink failure');
  }

  @override
  Future<void> close() async {}
}
