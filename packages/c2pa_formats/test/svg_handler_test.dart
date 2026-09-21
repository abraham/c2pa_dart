import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('SvgAssetHandler', () {
    const handler = SvgAssetHandler();

    test('detects UTF-8 SVG with BOM and XML declaration', () async {
      final source = _bytes(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>',
        bom: true,
      );

      expect(await handler.detect(MemoryByteSource(source)), isTrue);
      expect(
        await AssetHandlerRegistry().detect(MemoryByteSource(source)),
        isA<AssetDetectionResult>()
            .having((result) => result.format, 'format', AssetFormat.svg)
            .having(
              (result) => result.method,
              'method',
              AssetDetectionMethod.magicBytes,
            ),
      );
    });

    test(
      'embeds, extracts, replaces, and removes without a DOM rewrite',
      () async {
        final source = _bytes(
          '<?xml version="1.0"?>\n'
          '<svg width = "10" xmlns="http://www.w3.org/2000/svg">'
          '<!--keep--><path d="M 0 0"/></svg>\n',
          bom: true,
        );
        final originalManifest = Uint8List.fromList(const [1, 2, 3]);
        final replacement = Uint8List.fromList(const [4, 5, 6]);
        final embedded = await _embed(handler, source, originalManifest);
        final embeddedText = utf8.decode(embedded.sublist(3));

        expect(embedded.sublist(0, 3), [0xef, 0xbb, 0xbf]);
        expect(embeddedText, contains('xmlns:c2pa="http://c2pa.org/manifest"'));
        expect(
          embeddedText,
          contains('<metadata><c2pa:manifest>AQID</c2pa:manifest></metadata>'),
        );
        expect(embeddedText, endsWith('<!--keep--><path d="M 0 0"/></svg>\n'));
        expect(
          await handler.extractManifest(MemoryByteSource(embedded)),
          originalManifest,
        );

        final replacedSink = MemoryByteSink();
        await handler.replaceManifest(
          MemoryByteSource(embedded),
          replacement,
          replacedSink,
        );
        final replaced = replacedSink.toBytes();
        expect(replaced, _replaceAscii(embedded, 'AQID', 'BAUG'));

        final removedSink = MemoryByteSink();
        await handler.removeManifest(MemoryByteSource(replaced), removedSink);
        expect(
          utf8.decode(removedSink.toBytes().sublist(3)),
          embeddedText.replaceFirst('<c2pa:manifest>AQID</c2pa:manifest>', ''),
        );
      },
    );

    test(
      'inserts into metadata and preserves comments and CDATA exactly',
      () async {
        const source =
            '<svg xmlns="http://www.w3.org/2000/svg" '
            'xmlns:c2pa="http://c2pa.org/manifest">'
            '<metadata id="m"><!-- fake <c2pa:manifest> -->'
            '<![CDATA[<not-markup/>]]></metadata>'
            '<text>é</text></svg>';
        final output = await _embed(
          handler,
          utf8.encode(source),
          Uint8List.fromList(const [9, 8, 7]),
        );
        final written = utf8.decode(output);

        expect(
          written,
          contains(
            '<metadata id="m"><c2pa:manifest>CQgH</c2pa:manifest>'
            '<!-- fake <c2pa:manifest> --><![CDATA[<not-markup/>]]></metadata>',
          ),
        );
        expect(written, contains('<text>é</text>'));
        expect(await handler.extractManifest(MemoryByteSource(output)), const [
          9,
          8,
          7,
        ]);
      },
    );

    test(
      'supports prefixed SVG namespaces and self-closing metadata',
      () async {
        const source =
            '<s:svg xmlns:s="http://www.w3.org/2000/svg">'
            '<s:metadata /></s:svg>';
        final output = await _embed(
          handler,
          utf8.encode(source),
          Uint8List.fromList(const [1, 3, 5]),
        );
        final written = utf8.decode(output);

        expect(written, contains('<s:metadata >'));
        expect(written, contains('</s:metadata>'));
        expect(await handler.extractManifest(MemoryByteSource(output)), const [
          1,
          3,
          5,
        ]);
      },
    );

    test('uses the effective metadata namespace binding', () async {
      const source =
          '<svg xmlns:c2pa="https://example.invalid"><metadata '
          'xmlns:c2pa="http://c2pa.org/manifest"></metadata></svg>';
      final output = await _embed(
        handler,
        utf8.encode(source),
        Uint8List.fromList(const [7]),
      );

      expect(await handler.extractManifest(MemoryByteSource(output)), const [
        7,
      ]);
      expect(utf8.decode(output), contains('https://example.invalid'));
    });

    test('replaces a self-closing namespaced manifest', () async {
      const source =
          '<svg><metadata><c2pa:manifest '
          'xmlns:c2pa="http://c2pa.org/manifest"/></metadata></svg>';
      final output = MemoryByteSink();

      await handler.replaceManifest(
        MemoryByteSource(utf8.encode(source)),
        Uint8List.fromList(const [2, 4, 6]),
        output,
      );

      expect(
        await handler.extractManifest(MemoryByteSource(output.toBytes())),
        const [2, 4, 6],
      );
      expect(
        utf8.decode(output.toBytes()),
        contains(
          '<c2pa:manifest xmlns:c2pa="http://c2pa.org/manifest">'
          'AgQG</c2pa:manifest>',
        ),
      );
    });

    test('rejects duplicate manifests and conflicting c2pa namespaces', () {
      const duplicate =
          '<svg xmlns:c2pa="http://c2pa.org/manifest"><metadata>'
          '<c2pa:manifest>AQ==</c2pa:manifest>'
          '<c2pa:manifest>Ag==</c2pa:manifest>'
          '</metadata></svg>';
      const conflict =
          '<svg xmlns:c2pa="https://example.invalid">'
          '<metadata></metadata></svg>';

      expect(
        handler.extractManifest(MemoryByteSource(utf8.encode(duplicate))),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.embedManifest(
          MemoryByteSource(utf8.encode(conflict)),
          Uint8List(1),
          MemoryByteSink(),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects malformed XML, invalid UTF-8, and invalid base64', () {
      const malformed = '<svg><metadata></svg>';
      const badBase64 =
          '<svg xmlns:c2pa="http://c2pa.org/manifest"><metadata>'
          '<c2pa:manifest>not base64!</c2pa:manifest>'
          '</metadata></svg>';

      expect(
        handler.extractManifest(MemoryByteSource(utf8.encode(malformed))),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.extractManifest(
          MemoryByteSource(const [0x3c, 0x73, 0x76, 0x67, 0x3e, 0xff]),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(utf8.encode(badBase64))),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects invalid entities, names, and unbound prefixes', () {
      for (final source in <String>[
        '<svg>&unknown;</svg>',
        '<svg>&#x110000;</svg>',
        '<svg>&#xD800;</svg>',
        '<svg><bad:name:again/></svg>',
        '<svg><x:item/></svg>',
        '<svg><g></g extra></svg>',
        '<svg>bad]]>text</svg>',
      ]) {
        expect(
          handler.extractManifest(MemoryByteSource(utf8.encode(source))),
          throwsA(isA<MalformedAssetFormatException>()),
          reason: source,
        );
      }
    });

    test('reads and updates XMP remote references byte-surgically', () async {
      const oldReference = 'https://old.example/manifest';
      const newReference = 'https://new.example/a?x=1&y=2';
      final source = utf8.encode(
        '<svg><metadata><!--before-->'
        '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/" '
        'dcterms:provenance="$oldReference"/>'
        '</rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
        '<![CDATA[after]]></metadata></svg>',
      );

      expect(
        await handler.readXmp(MemoryByteSource(source)),
        contains(oldReference),
      );
      final output = MemoryByteSink();
      await handler.embedRemoteReference(
        MemoryByteSource(source),
        newReference,
        output,
      );
      final expected = _replaceAscii(
        source,
        oldReference,
        'https://new.example/a?x=1&amp;y=2',
      );
      expect(output.toBytes(), expected);
      expect(
        await handler.readXmp(MemoryByteSource(output.toBytes())),
        contains('https://new.example/a?x=1&amp;y=2'),
      );
      expect(
        await handler.readRemoteManifestReference(
          MemoryByteSource(output.toBytes()),
        ),
        newReference,
      );

      final removed = MemoryByteSink();
      await handler.removeRemoteManifestReference(
        MemoryByteSource(output.toBytes()),
        removed,
      );
      expect(
        await handler.readRemoteManifestReference(
          MemoryByteSource(removed.toBytes()),
        ),
        isNull,
      );
      expect(utf8.decode(removed.toBytes()), contains('<!--before-->'));
      expect(utf8.decode(removed.toBytes()), contains('<![CDATA[after]]>'));
    });

    test('replaces an XMP provenance child element', () async {
      const source =
          '<svg><metadata>'
          '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
          '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
          'xmlns:dcterms="http://purl.org/dc/terms/">'
          '<rdf:Description><dcterms:provenance>old</dcterms:provenance>'
          '</rdf:Description></rdf:RDF><?xpacket end="w"?>'
          '</metadata></svg>';
      final output = MemoryByteSink();

      await handler.embedRemoteReference(
        MemoryByteSource(utf8.encode(source)),
        'new&amp;safe',
        output,
      );

      expect(
        utf8.decode(output.toBytes()),
        contains('<dcterms:provenance>new&amp;amp;safe</dcterms:provenance>'),
      );
    });

    test('creates XMP in existing metadata when absent', () async {
      const source = '<svg><metadata><!--keep--></metadata></svg>';
      final output = MemoryByteSink();
      await handler.embedRemoteReference(
        MemoryByteSource(utf8.encode(source)),
        'self#jumbf=c2pa/test',
        output,
      );
      final written = utf8.decode(output.toBytes());

      expect(written, contains('<?xpacket begin='));
      expect(written, contains('dcterms:provenance="self#jumbf=c2pa/test"'));
      expect(written, contains('<!--keep-->'));
      expect(
        await handler.readXmp(MemoryByteSource(output.toBytes())),
        isNotNull,
      );
    });

    test('routes XMP operations through the registry', () async {
      final output = MemoryByteSink();
      final registry = AssetHandlerRegistry();

      await registry.embedRemoteReference(
        MemoryByteSource(utf8.encode('<svg/>')),
        'https://example.com/manifest',
        output,
        fileExtension: '.SVG',
      );

      expect(
        await registry.readXmp(
          MemoryByteSource(output.toBytes()),
          mimeType: ' IMAGE/SVG+XML ',
        ),
        contains('https://example.com/manifest'),
      );
      expect(
        await registry.readRemoteManifestReference(
          MemoryByteSource(output.toBytes()),
          mimeType: 'image/svg+xml',
        ),
        'https://example.com/manifest',
      );
    });

    test('rejects duplicate remote references', () {
      const source =
          '<svg><metadata>'
          '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
          '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
          'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
          'xmlns:dcterms="http://purl.org/dc/terms/">'
          '<rdf:Description dcterms:provenance="one">'
          '<dcterms:provenance>two</dcterms:provenance>'
          '</rdf:Description></rdf:RDF></x:xmpmeta>'
          '<?xpacket end="w"?></metadata></svg>';
      expect(
        handler.readRemoteManifestReference(
          MemoryByteSource(utf8.encode(source)),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test(
      'uses a fresh provenance prefix when dcterms is already bound',
      () async {
        const source =
            '<svg><metadata>'
            '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
            '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
            '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            '<rdf:Description xmlns:dcterms="urn:unrelated" '
            'dcterms:keep="yes"/>'
            '</rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
            '</metadata></svg>';
        final output = MemoryByteSink();
        await handler.updateRemoteManifestReference(
          MemoryByteSource(utf8.encode(source)),
          'https://example.com/manifest',
          output,
        );
        final written = utf8.decode(output.toBytes());
        expect(written, contains('xmlns:dcterms="urn:unrelated"'));
        expect(written, contains('dcterms:keep="yes"'));
        expect(written, contains('xmlns:dcterms1="http://purl.org/dc/terms/"'));
        expect(
          await handler.readRemoteManifestReference(
            MemoryByteSource(output.toBytes()),
          ),
          'https://example.com/manifest',
        );
      },
    );

    test('reports DataHash text ranges and BoxHash unsupported', () async {
      final embedded = await _embed(
        handler,
        utf8.encode('<svg/>'),
        Uint8List.fromList(const [1, 2, 3]),
      );
      final layout = await handler.getDataHashLayout(
        MemoryByteSource(embedded),
      );
      final exclusion = layout.exclusions.single.range;

      expect(
        utf8.decode(embedded.sublist(exclusion.start, exclusion.end)),
        'AQID',
      );
      expect(handler.capabilities.canProvideDataHashLayout, isTrue);
      expect(handler.capabilities.canProvideBoxHashLayout, isFalse);
      expect(
        handler.getBoxHashLayout(MemoryByteSource(embedded)),
        throwsA(isA<UnsupportedHashLayoutException>()),
      );

      final absent = utf8.encode('<svg/>');
      final absentLayout = await handler.getDataHashLayout(
        MemoryByteSource(absent),
      );
      expect(absentLayout.exclusions, isEmpty);
      expect(absentLayout.insertionOffset, utf8.encode('<svg').length);
    });

    test('enforces limits and propagates sink failures', () {
      final source = utf8.encode('<svg/>');
      expect(
        const SvgAssetHandler(maxManifestSize: 2).embedManifest(
          MemoryByteSource(source),
          Uint8List(3),
          MemoryByteSink(),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        SvgAssetHandler(maxSourceSize: source.length - 1)
            .extractManifest(MemoryByteSource(source)),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        const SvgAssetHandler(maxOutputSize: 10).embedManifest(
          MemoryByteSource(source),
          Uint8List(3),
          MemoryByteSink(),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        handler.embedManifest(
          MemoryByteSource(source),
          Uint8List(3),
          _FailingSink(),
        ),
        throwsA(isA<StateError>()),
      );
      expect(
        const SvgAssetHandler(maxXmpSize: 10).readXmp(
          MemoryByteSource(
            utf8.encode(
              '<svg><metadata>'
              '<?xpacket begin="x" id="W5M0MpCehiHzreSzNTczkc9d"?>'
              '<xmp/><?xpacket end="w"?>'
              '</metadata></svg>',
            ),
          ),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
    });
  });
}

Future<List<int>> _embed(
  SvgAssetHandler handler,
  List<int> source,
  Uint8List manifest,
) async {
  final output = MemoryByteSink();
  await handler.embedManifest(MemoryByteSource(source), manifest, output);
  return output.toBytes();
}

List<int> _bytes(String value, {bool bom = false}) => [
  if (bom) ...const [0xef, 0xbb, 0xbf],
  ...utf8.encode(value),
];

List<int> _replaceAscii(List<int> source, String oldValue, String newValue) {
  final oldBytes = utf8.encode(oldValue);
  final offset = _indexOf(source, oldBytes);
  expect(offset, isNonNegative);
  return [
    ...source.sublist(0, offset),
    ...utf8.encode(newValue),
    ...source.sublist(offset + oldBytes.length),
  ];
}

int _indexOf(List<int> source, List<int> pattern) {
  for (var offset = 0; offset <= source.length - pattern.length; offset++) {
    var equal = true;
    for (var index = 0; index < pattern.length; index++) {
      if (source[offset + index] != pattern[index]) {
        equal = false;
        break;
      }
    }
    if (equal) return offset;
  }
  return -1;
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
