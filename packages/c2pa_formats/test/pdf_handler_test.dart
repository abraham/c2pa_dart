import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('PdfAssetHandler', () {
    const handler = PdfAssetHandler();
    final manifest = Uint8List.fromList(<int>[0, 1, 2, 3, 0xff, 0x25]);

    test('detects PDF header and registry MIME/extension hints', () async {
      final pdf = _classicPdf(manifest: manifest);
      expect(await handler.detect(MemoryByteSource(pdf)), isTrue);
      expect(
        await AssetHandlerRegistry().detect(MemoryByteSource(pdf)),
        isA<AssetDetectionResult>().having(
          (result) => result.format,
          'format',
          AssetFormat.pdf,
        ),
      );
      expect(
        (await AssetHandlerRegistry().detect(
          MemoryByteSource(const <int>[]),
          mimeType: ' APPLICATION/PDF ; version=1.7 ',
        )).format,
        AssetFormat.pdf,
      );
      expect(
        (await AssetHandlerRegistry().detect(
          MemoryByteSource(const <int>[]),
          fileExtension: '..PDF',
        )).format,
        AssetFormat.pdf,
      );
    });

    test('extracts the C2PA associated-file stream', () async {
      final pdf = _classicPdf(manifest: manifest);

      expect(await handler.extractManifest(MemoryByteSource(pdf)), manifest);
    });

    test('embeds with an incremental associated-file revision', () async {
      final source = _classicPdf(manifest: null);
      final output = MemoryByteSink();

      await handler.embedManifest(MemoryByteSource(source), manifest, output);

      final bytes = output.toBytes();
      expect(bytes.sublist(0, source.length), source);
      expect(await handler.extractManifest(MemoryByteSource(bytes)), manifest);
      expect(_containsAscii(bytes, '/AFRelationship /C2PA_Manifest'), isTrue);
      expect(_containsAscii(bytes, '/EmbeddedFiles'), isTrue);
      expect(_containsAscii(bytes, '/Prev '), isTrue);
    });

    test(
      'replaces and removes through multiple incremental revisions',
      () async {
        final source = _classicPdf(manifest: null, rootGeneration: 2);
        final embedded = MemoryByteSink();
        await handler.embedManifest(
          MemoryByteSource(source),
          manifest,
          embedded,
        );
        final replacement = Uint8List.fromList(<int>[9, 8, 7, 6]);
        final replaced = MemoryByteSink();
        await handler.replaceManifest(
          MemoryByteSource(embedded.toBytes()),
          replacement,
          replaced,
        );
        expect(
          replaced.toBytes().sublist(0, embedded.toBytes().length),
          embedded.toBytes(),
        );
        expect(
          await handler.extractManifest(MemoryByteSource(replaced.toBytes())),
          replacement,
        );

        final removed = MemoryByteSink();
        await handler.removeManifest(
          MemoryByteSource(replaced.toBytes()),
          removed,
        );
        expect(
          removed.toBytes().sublist(0, replaced.toBytes().length),
          replaced.toBytes(),
        );
        await expectLater(
          handler.extractManifest(MemoryByteSource(removed.toBytes())),
          throwsA(isA<ManifestNotFoundException>()),
        );
      },
    );

    test('replaces a FlateDecode manifest stream', () async {
      final source = _classicPdf(manifest: manifest, flateManifest: true);
      final replacement = Uint8List.fromList(<int>[5, 4, 3, 2, 1]);
      final output = MemoryByteSink();

      expect(await handler.extractManifest(MemoryByteSource(source)), manifest);
      await handler.replaceManifest(
        MemoryByteSource(source),
        replacement,
        output,
      );
      expect(
        await handler.extractManifest(MemoryByteSource(output.toBytes())),
        replacement,
      );
    });

    test('reads catalog XMP metadata without interpreting it', () async {
      const xmp =
          '<?xpacket begin="﻿"?>'
          '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
          '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
          '<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/" '
          'dcterms:provenance="https://example.test/c2pa"/>'
          '</rdf:RDF></x:xmpmeta>';
      final pdf = _classicPdf(manifest: manifest, xmp: xmp);

      expect(await handler.readXmp(MemoryByteSource(pdf)), xmp);
      expect(
        await AssetHandlerRegistry().readXmp(
          MemoryByteSource(pdf),
          mimeType: 'application/pdf',
        ),
        xmp,
      );
    });

    test('supports FlateDecode xref and compressed object streams', () async {
      final pdf = _xrefStreamPdf(manifest);

      expect(await handler.extractManifest(MemoryByteSource(pdf)), manifest);

      final output = MemoryByteSink();
      final replacement = Uint8List.fromList(<int>[4, 3, 2, 1]);
      await handler.replaceManifest(MemoryByteSource(pdf), replacement, output);
      expect(output.toBytes().sublist(0, pdf.length), pdf);
      expect(
        await handler.extractManifest(MemoryByteSource(output.toBytes())),
        replacement,
      );
    });

    test(
      'mutates hybrid-reference input with a classic incremental xref',
      () async {
        final pdf = _hybridPdf();
        final output = MemoryByteSink();

        await handler.embedManifest(MemoryByteSource(pdf), manifest, output);

        expect(output.toBytes().sublist(0, pdf.length), pdf);
        expect(
          await handler.extractManifest(MemoryByteSource(output.toBytes())),
          manifest,
        );
      },
    );

    test('follows Prev across an incremental cross-reference update', () async {
      final base = _classicPdf(manifest: manifest);
      final updated = _appendIncrementalInfoObject(base);

      expect(
        await handler.extractManifest(MemoryByteSource(updated)),
        manifest,
      );
    });

    test(
      'rejects missing, duplicate, and malformed manifest references',
      () async {
        await expectLater(
          handler.extractManifest(
            MemoryByteSource(_classicPdf(manifest: null)),
          ),
          throwsA(isA<ManifestNotFoundException>()),
        );
        await expectLater(
          handler.extractManifest(
            MemoryByteSource(_classicPdf(manifest: manifest, duplicate: true)),
          ),
          throwsA(isA<MalformedAssetFormatException>()),
        );
        await expectLater(
          handler.extractManifest(
            MemoryByteSource(
              _classicPdf(manifest: manifest, brokenEmbeddedFile: true),
            ),
          ),
          throwsA(isA<MalformedAssetFormatException>()),
        );
      },
    );

    test('rejects malformed header, EOF, startxref, and xref data', () async {
      final valid = _classicPdf(manifest: manifest);
      final badStart = Uint8List.fromList(valid);
      final marker = _lastAsciiIndex(badStart, 'startxref\n');
      badStart[marker + 'startxref\n'.length] = 0x39;

      expect(
        await handler.detect(MemoryByteSource(utf8.encode('not a pdf'))),
        isFalse,
      );
      await expectLater(
        handler.extractManifest(
          MemoryByteSource(valid.sublist(0, valid.length - 6)),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      await expectLater(
        handler.extractManifest(MemoryByteSource(badStart)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      await expectLater(
        handler.extractManifest(
          MemoryByteSource(_classicPdf(manifest: manifest, corruptXref: true)),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects encrypted documents and configured limits', () async {
      await expectLater(
        handler.extractManifest(
          MemoryByteSource(_classicPdf(manifest: manifest, encrypted: true)),
        ),
        throwsA(isA<UnsupportedPdfFeatureException>()),
      );
      await expectLater(
        const PdfAssetHandler(maxManifestSize: 2)
            .extractManifest(MemoryByteSource(_classicPdf(manifest: manifest))),
        throwsA(isA<AssetLimitExceededException>()),
      );
      await expectLater(
        const PdfAssetHandler(maxSourceSize: 32)
            .extractManifest(MemoryByteSource(_classicPdf(manifest: manifest))),
        throwsA(isA<AssetLimitExceededException>()),
      );
      await expectLater(
        const PdfAssetHandler(maxOutputSize: 64).embedManifest(
          MemoryByteSource(_classicPdf(manifest: null)),
          manifest,
          MemoryByteSink(),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
    });

    test(
      'rejects signed and DocMDP-restricted documents before output',
      () async {
        for (final source in <Uint8List>[
          _classicPdf(manifest: null, signed: true),
          _classicPdf(manifest: null, docMdp: true),
        ]) {
          final output = MemoryByteSink();
          await expectLater(
            handler.embedManifest(MemoryByteSource(source), manifest, output),
            throwsA(isA<UnsupportedPdfFeatureException>()),
          );
          expect(output.toBytes(), isEmpty);
        }
      },
    );

    test('enforces mutation state and stages sink writes', () async {
      await expectLater(
        handler.embedManifest(
          MemoryByteSource(_classicPdf(manifest: manifest)),
          manifest,
          MemoryByteSink(),
        ),
        throwsA(isA<ManifestAlreadyExistsException>()),
      );
      await expectLater(
        handler.replaceManifest(
          MemoryByteSource(_classicPdf(manifest: null)),
          manifest,
          MemoryByteSink(),
        ),
        throwsA(isA<ManifestNotFoundException>()),
      );
      await expectLater(
        handler.removeManifest(
          MemoryByteSource(_classicPdf(manifest: null)),
          MemoryByteSink(),
        ),
        throwsA(isA<ManifestNotFoundException>()),
      );
      for (final malformed in <Uint8List>[
        _classicPdf(manifest: manifest, duplicate: true),
        _classicPdf(manifest: manifest, brokenEmbeddedFile: true),
      ]) {
        final output = MemoryByteSink();
        await expectLater(
          handler.replaceManifest(
            MemoryByteSource(malformed),
            manifest,
            output,
          ),
          throwsA(isA<MalformedAssetFormatException>()),
        );
        expect(output.toBytes(), isEmpty);
      }
      await expectLater(
        handler.embedManifest(
          MemoryByteSource(_classicPdf(manifest: null)),
          manifest,
          _FailingSink(),
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('reports mutation capabilities and unsupported layouts', () async {
      expect(handler.capabilities.canExtractManifest, isTrue);
      expect(handler.capabilities.canReadXmp, isTrue);
      expect(handler.capabilities.canEmbedManifest, isTrue);
      expect(handler.capabilities.canReplaceManifest, isTrue);
      expect(handler.capabilities.canRemoveManifest, isTrue);
      expect(handler.capabilities.canProvideDataHashLayout, isFalse);
      expect(handler.capabilities.canProvideBoxHashLayout, isFalse);
      expect(handler.capabilities.canEmbedRemoteReference, isFalse);

      final source = MemoryByteSource(_classicPdf(manifest: manifest));
      await expectLater(
        handler.embedRemoteReference(
          source,
          'https://example.test',
          MemoryByteSink(),
        ),
        throwsA(isA<UnsupportedXmpOperationException>()),
      );
      await expectLater(
        AssetHandlerRegistry().getDataHashLayout(
          source,
          mimeType: 'application/pdf',
        ),
        throwsA(isA<UnsupportedHashLayoutException>()),
      );
      await expectLater(
        AssetHandlerRegistry().getBoxHashLayout(
          source,
          mimeType: 'application/pdf',
        ),
        throwsA(isA<UnsupportedHashLayoutException>()),
      );
    });
  });
}

Uint8List _classicPdf({
  required Uint8List? manifest,
  String? xmp,
  bool duplicate = false,
  bool brokenEmbeddedFile = false,
  bool encrypted = false,
  bool corruptXref = false,
  bool flateManifest = false,
  bool signed = false,
  bool docMdp = false,
  int rootGeneration = 0,
}) {
  final objects = <int, List<int>>{};
  if (manifest == null) {
    objects[1] = ascii.encode(
      '<< /Type /Catalog${xmp == null ? '' : ' /Metadata 4 0 R'}'
      '${docMdp ? ' /Perms << /DocMDP 7 0 R >>' : ''} >>',
    );
  } else {
    objects[1] = ascii.encode(
      '<< /Type /Catalog /AF [2 0 R${duplicate ? ' 5 0 R' : ''}]'
      '${xmp == null ? '' : ' /Metadata 4 0 R'}'
      '${docMdp ? ' /Perms << /DocMDP 7 0 R >>' : ''} >>',
    );
    objects[2] = ascii.encode(
      '<< /Type /Filespec /AFRelationship /C2PA_Manifest '
      '/EF << /F ${brokenEmbeddedFile ? '99' : '3'} 0 R >> >>',
    );
    objects[3] = flateManifest
        ? _streamObject(
            Uint8List.fromList(ZLibEncoder().convert(manifest)),
            dictionary: '/Filter /FlateDecode ',
          )
        : _streamObject(manifest);
    if (duplicate) {
      objects[5] = ascii.encode(
        '<< /Type /Filespec /AFRelationship /C2PA_Manifest '
        '/EF << /F 3 0 R >> >>',
      );
    }
  }
  if (xmp != null) {
    objects[4] = _streamObject(
      Uint8List.fromList(utf8.encode(xmp)),
      dictionary: '/Type /Metadata /Subtype /XML ',
    );
  }
  if (encrypted) objects[6] = ascii.encode('<< /Filter /Standard >>');
  if (signed || docMdp) {
    objects[7] = ascii.encode(
      '<< /Type /Sig /ByteRange [0 1 2 3] /Contents <00> >>',
    );
  }
  return _writeClassicPdf(
    objects,
    root: 1,
    rootGeneration: rootGeneration,
    encrypt: encrypted ? 6 : null,
    corruptXref: corruptXref,
  );
}

Uint8List _writeClassicPdf(
  Map<int, List<int>> objects, {
  required int root,
  int rootGeneration = 0,
  int? encrypt,
  bool corruptXref = false,
}) {
  final output = BytesBuilder(copy: false)..add(ascii.encode('%PDF-1.7\n'));
  final maximum = objects.keys.fold<int>(0, (a, b) => a > b ? a : b);
  final offsets = List<int>.filled(maximum + 1, 0);
  for (var number = 1; number <= maximum; number++) {
    final object = objects[number];
    if (object == null) continue;
    offsets[number] = output.length;
    final generation = number == root ? rootGeneration : 0;
    output
      ..add(ascii.encode('$number $generation obj\n'))
      ..add(object)
      ..add(ascii.encode('\nendobj\n'));
  }
  final xrefOffset = output.length;
  output.add(ascii.encode('xref\n0 ${maximum + 1}\n'));
  output.add(ascii.encode('0000000000 65535 f \n'));
  for (var number = 1; number <= maximum; number++) {
    final offset = offsets[number];
    output.add(
      ascii.encode(
        offset == 0
            ? '0000000000 00000 f \n'
            : '${(corruptXref && number == root ? 9999999999 : offset).toString().padLeft(10, '0')} '
                  '${(number == root ? rootGeneration : 0).toString().padLeft(5, '0')} n \n',
      ),
    );
  }
  output.add(
    ascii.encode(
      'trailer\n<< /Size ${maximum + 1} /Root $root $rootGeneration R'
      '${encrypt == null ? '' : ' /Encrypt $encrypt 0 R'} >>\n'
      'startxref\n$xrefOffset\n%%EOF\n',
    ),
  );
  return output.takeBytes();
}

Uint8List _streamObject(Uint8List content, {String dictionary = ''}) {
  return Uint8List.fromList(<int>[
    ...ascii.encode('<< $dictionary/Length ${content.length} >>\nstream\n'),
    ...content,
    ...ascii.encode('\nendstream'),
  ]);
}

Uint8List _xrefStreamPdf(Uint8List manifest) {
  final output = BytesBuilder(copy: false)..add(ascii.encode('%PDF-1.7\n'));
  final offsets = <int, int>{};

  offsets[3] = output.length;
  output
    ..add(ascii.encode('3 0 obj\n'))
    ..add(_streamObject(manifest))
    ..add(ascii.encode('\nendobj\n'));

  final catalog = ascii.encode('<< /Type /Catalog /AF [2 0 R] >>');
  final fileSpec = ascii.encode(
    '<< /Type /Filespec /AFRelationship /C2PA_Manifest '
    '/EF << /F 3 0 R >> >>',
  );
  final objectHeader = ascii.encode('1 0 2 ${catalog.length} ');
  final objectData = Uint8List.fromList(<int>[
    ...objectHeader,
    ...catalog,
    ...fileSpec,
  ]);
  offsets[5] = output.length;
  output
    ..add(ascii.encode('5 0 obj\n'))
    ..add(
      _streamObject(
        Uint8List.fromList(ZLibEncoder().convert(objectData)),
        dictionary:
            '/Type /ObjStm /N 2 /First ${objectHeader.length} '
            '/Filter /FlateDecode ',
      ),
    )
    ..add(ascii.encode('\nendobj\n'));

  offsets[6] = output.length;
  final xrefData = BytesBuilder(copy: false);
  for (var number = 0; number <= 6; number++) {
    if (number == 0 || number == 4) {
      xrefData.add(_xrefRow(0, 0, number == 0 ? 65535 : 0));
    } else if (number == 1 || number == 2) {
      xrefData.add(_xrefRow(2, 5, number - 1));
    } else {
      xrefData.add(_xrefRow(1, offsets[number]!, 0));
    }
  }
  final compressedXref = Uint8List.fromList(
    ZLibEncoder().convert(xrefData.takeBytes()),
  );
  output
    ..add(ascii.encode('6 0 obj\n'))
    ..add(
      _streamObject(
        compressedXref,
        dictionary:
            '/Type /XRef /Size 7 /Root 1 0 R /W [1 4 2] '
            '/Filter /FlateDecode ',
      ),
    )
    ..add(ascii.encode('\nendobj\nstartxref\n${offsets[6]}\n%%EOF\n'));
  return output.takeBytes();
}

Uint8List _hybridPdf() {
  final output = BytesBuilder(copy: false)..add(ascii.encode('%PDF-1.7\n'));
  final offsets = List<int>.filled(4, 0);
  offsets[1] = output.length;
  output.add(ascii.encode('1 0 obj\n<< /Type /Catalog >>\nendobj\n'));

  offsets[3] = output.length;
  output
    ..add(ascii.encode('3 0 obj\n'))
    ..add(
      _streamObject(
        Uint8List.fromList(_xrefRow(1, offsets[3], 0)),
        dictionary: '/Type /XRef /Size 4 /W [1 4 2] /Index [3 1] ',
      ),
    )
    ..add(ascii.encode('\nendobj\n'));

  final xrefOffset = output.length;
  output.add(ascii.encode('xref\n0 4\n0000000000 65535 f \n'));
  for (var number = 1; number <= 3; number++) {
    output.add(
      ascii.encode(
        offsets[number] == 0
            ? '0000000000 00000 f \n'
            : '${offsets[number].toString().padLeft(10, '0')} 00000 n \n',
      ),
    );
  }
  output.add(
    ascii.encode(
      'trailer\n<< /Size 4 /Root 1 0 R /XRefStm ${offsets[3]} >>\n'
      'startxref\n$xrefOffset\n%%EOF\n',
    ),
  );
  return output.takeBytes();
}

List<int> _xrefRow(int type, int field1, int field2) => <int>[
  type,
  (field1 >> 24) & 0xff,
  (field1 >> 16) & 0xff,
  (field1 >> 8) & 0xff,
  field1 & 0xff,
  (field2 >> 8) & 0xff,
  field2 & 0xff,
];

Uint8List _appendIncrementalInfoObject(Uint8List base) {
  final previousXref = _readStartxref(base);
  final output = BytesBuilder(copy: false)..add(base);
  final objectOffset = output.length;
  output.add(ascii.encode('7 0 obj\n<< /Producer (test) >>\nendobj\n'));
  final xrefOffset = output.length;
  output.add(
    ascii.encode(
      'xref\n7 1\n${objectOffset.toString().padLeft(10, '0')} 00000 n \n'
      'trailer\n<< /Size 8 /Root 1 0 R /Prev $previousXref >>\n'
      'startxref\n$xrefOffset\n%%EOF\n',
    ),
  );
  return output.takeBytes();
}

int _readStartxref(Uint8List bytes) {
  final offset = _lastAsciiIndex(bytes, 'startxref\n');
  final start = offset + 'startxref\n'.length;
  var end = start;
  while (bytes[end] >= 0x30 && bytes[end] <= 0x39) {
    end++;
  }
  return int.parse(ascii.decode(bytes.sublist(start, end)));
}

int _lastAsciiIndex(List<int> bytes, String value) {
  final pattern = ascii.encode(value);
  for (var offset = bytes.length - pattern.length; offset >= 0; offset--) {
    var matches = true;
    for (var i = 0; i < pattern.length; i++) {
      if (bytes[offset + i] != pattern[i]) {
        matches = false;
        break;
      }
    }
    if (matches) return offset;
  }
  throw StateError('pattern not found');
}

bool _containsAscii(List<int> bytes, String value) {
  final pattern = ascii.encode(value);
  for (var offset = 0; offset <= bytes.length - pattern.length; offset++) {
    var matches = true;
    for (var i = 0; i < pattern.length; i++) {
      if (bytes[offset + i] != pattern[i]) {
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
