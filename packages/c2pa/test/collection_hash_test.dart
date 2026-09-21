import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:test/test.dart';

import 'x509_test_support.dart';

late TestCertificateChain _certificates;

void main() {
  setUpAll(() async {
    _certificates = await loadTestCertificateChain();
  });

  group('Collection Data Hash v1', () {
    test('owns data and emits deterministic normalized CBOR', () {
      final hash = Uint8List.fromList(List<int>.filled(32, 1));
      final assertion = CollectionHashAssertion(
        uris: {
          r'folder\b.txt': CollectionHashEntry(
            hash: hash,
            size: 3,
            format: 'text/plain',
            dataTypes: [CollectionDataType(type: 'document')],
          ),
          'a.txt': CollectionHashEntry(hash: Uint8List(32), size: 0),
        },
        algorithm: 'sha256',
        zipCentralDirectoryHash: Uint8List(32),
      );
      hash[0] = 9;
      final encoded = encodeCbor(assertion.toCborMap());
      final decoded = CollectionHashAssertion.fromCbor(decodeCbor(encoded));

      expect(assertion.uris.keys, ['a.txt', 'folder/b.txt']);
      expect(assertion.uris['folder/b.txt']!.hash!.first, 1);
      expect(decoded, assertion);
      expect(encodeCbor(decoded.toCborMap()), encoded);
      expect(() => normalizeCollectionUri('../bad'), throwsFormatException);
      expect(() => normalizeCollectionUri('/absolute'), throwsFormatException);
      expect(() => normalizeCollectionUri('%2e%2e/bad'), throwsFormatException);
      expect(
        () => CollectionHashAssertion(
          uris: {'a/b': CollectionHashEntry(), r'a\b': CollectionHashEntry()},
          algorithm: 'sha256',
        ),
        throwsFormatException,
      );
    });

    test('round-trips ZIP, EPUB, and OOXML', () async {
      final fixtures = <(List<int>, String)>[
        (
          _archive([_Entry('hello.txt', utf8.encode('hello'))]),
          'application/zip',
        ),
        (
          _archive([
            _Entry('mimetype', utf8.encode('application/epub+zip')),
            _Entry('OPS/chapter.xhtml', utf8.encode('<p>Hello</p>')),
          ]),
          'application/epub+zip',
        ),
        (
          _archive([
            _Entry('[Content_Types].xml', utf8.encode('<Types/>')),
            _Entry('word/document.xml', utf8.encode('<document/>')),
          ]),
          'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        ),
      ];
      for (final (bytes, mimeType) in fixtures) {
        final output = MemoryByteSink();
        await _builder('sha256').saveToSource(
          source: MemoryByteSource(bytes),
          output: output,
          mimeType: mimeType,
        );
        final reader = await _readZip(output.toBytes(), mimeType);
        expect(
          _codes(reader),
          contains(ValidationCode.assertionCollectionHashMatch.value),
          reason: mimeType,
        );
        expect(reader.validationResults.state, ValidationState.trusted);
      }
    });

    test('supports caller-supplied directory collections', () async {
      final source = _FakeCollectionSource({
        'a.txt': _item('a.txt', 'hello', format: 'text/plain'),
        'sub/b.json': _item(
          'sub/b.json',
          '{"ok":true}',
          format: 'application/json',
          dataTypes: [CollectionDataType(type: 'document')],
        ),
      });
      final manifest = await _builder('sha256').buildCollection(source);
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(manifest),
        collectionSource: source,
        context: _readerContext(),
      );
      expect(
        _codes(reader),
        contains(ValidationCode.assertionCollectionHashMatch.value),
      );
      expect(reader.validationResults.state, ValidationState.trusted);

      final changed = _FakeCollectionSource({
        'a.txt': _item('a.txt', 'changed', format: 'text/plain'),
        'sub/b.json': _item(
          'sub/b.json',
          '{"ok":true}',
          format: 'application/json',
          dataTypes: [CollectionDataType(type: 'document')],
        ),
      });
      expect(
        _codes(
          await C2paReader.fromSource(
            source: MemoryByteSource(manifest),
            collectionSource: changed,
            context: _readerContext(),
          ),
        ),
        contains(ValidationCode.assertionCollectionHashMismatch.value),
      );
    });

    test('detects ZIP tamper and missing or extra entries', () async {
      final output = MemoryByteSink();
      await _builder('sha256').saveToSource(
        source: MemoryByteSource(
          _archive([
            _Entry('a.txt', const [1, 2, 3]),
            _Entry('b.txt', const [4, 5]),
          ]),
        ),
        output: output,
        mimeType: 'application/zip',
      );
      final signed = output.toBytes();
      final layout = await AssetHandlerRegistry().getCollectionHashLayout(
        MemoryByteSource(signed),
        mimeType: 'application/zip',
      );
      final tampered = Uint8List.fromList(signed);
      tampered[layout.entries.first.range.end - 1] ^= 0xff;
      expect(
        _codes(await _readZip(tampered, 'application/zip')),
        contains(ValidationCode.assertionCollectionHashMismatch.value),
      );
      final centralTampered = Uint8List.fromList(signed);
      centralTampered[layout.centralDirectoryHashRanges.first.start + 12] ^=
          0x01;
      expect(
        _codes(await _readZip(centralTampered, 'application/zip')),
        contains(ValidationCode.assertionCollectionHashMismatch.value),
      );

      for (final remove in [true, false]) {
        final changed = await _rewriteCollectionHash(signed, (value) {
          final uris = Map<Object?, Object?>.from(value['uris'] as Map);
          if (remove) {
            uris.remove(uris.keys.first);
          } else {
            uris['extra.txt'] = {'hash': Uint8List(32), 'size': 0};
          }
          value['uris'] = uris;
        });
        expect(
          _codes(await _readZip(changed, 'application/zip')),
          contains(
            ValidationCode.assertionCollectionHashIncorrectFileCount.value,
          ),
        );
      }
    });

    test('rejects unsafe URIs and malformed central-directory data', () async {
      final output = MemoryByteSink();
      await _builder('sha256').saveToSource(
        source: MemoryByteSource(
          _archive([
            _Entry('a.txt', const [1, 2, 3]),
          ]),
        ),
        output: output,
        mimeType: 'application/zip',
      );
      final unsafe = await _rewriteCollectionHash(output.toBytes(), (value) {
        final uris = Map<Object?, Object?>.from(value['uris'] as Map);
        final metadata = uris.remove(uris.keys.first);
        uris['../a.txt'] = metadata;
        value['uris'] = uris;
      });
      expect(
        _codes(await _readZip(unsafe, 'application/zip')),
        contains(ValidationCode.assertionCollectionHashInvalidUri.value),
      );

      final malformed = await _rewriteCollectionHash(
        output.toBytes(),
        (value) => value.remove('zip_central_directory_hash'),
      );
      expect(
        _codes(await _readZip(malformed, 'application/zip')),
        contains(ValidationCode.assertionCollectionHashMalformed.value),
      );
      final malformedEntry = await _rewriteCollectionHash(output.toBytes(), (
        value,
      ) {
        final uris = Map<Object?, Object?>.from(value['uris'] as Map);
        final key = uris.keys.first;
        final metadata = Map<Object?, Object?>.from(uris[key] as Map)
          ..remove('hash');
        uris[key] = metadata;
        value['uris'] = uris;
      });
      expect(
        _codes(await _readZip(malformedEntry, 'application/zip')),
        contains(ValidationCode.assertionCollectionHashMalformed.value),
      );
    });

    test('builds a ZIP collection sidecar without embedding', () async {
      final asset = Uint8List.fromList(
        _archive([_Entry('sidecar.txt', utf8.encode('sidecar'))]),
      );
      final output = MemoryByteSink();
      await _builder('sha256').saveToSource(
        source: MemoryByteSource(asset),
        output: output,
        mimeType: 'application/zip',
        embedManifest: false,
      );
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(output.toBytes()),
        assetSource: MemoryByteSource(asset),
        assetMimeType: 'application/zip',
        context: _readerContext(),
      );
      expect(
        _codes(reader),
        contains(ValidationCode.assertionCollectionHashMatch.value),
      );
    });

    test('supports SHA-256, SHA-384, and SHA-512', () async {
      for (final algorithm in ['sha256', 'sha384', 'sha512']) {
        final output = MemoryByteSink();
        await _builder(algorithm).saveToSource(
          source: MemoryByteSource(
            _archive([
              _Entry('data.bin', const [1, 2, 3, 4]),
            ]),
          ),
          output: output,
          mimeType: 'application/zip',
        );
        expect(
          _codes(await _readZip(output.toBytes(), 'application/zip')),
          contains(ValidationCode.assertionCollectionHashMatch.value),
          reason: algorithm,
        );
      }
    });

    test(
      'directory file count and metadata mismatches are classified',
      () async {
        final source = _FakeCollectionSource({
          'a.txt': _item('a.txt', 'hello', format: 'text/plain'),
        });
        final manifest = await _builder('sha256').buildCollection(source);
        final missing = _FakeCollectionSource(const {});
        expect(
          _codes(
            await C2paReader.fromSource(
              source: MemoryByteSource(manifest),
              collectionSource: missing,
              context: _readerContext(),
            ),
          ),
          contains(
            ValidationCode.assertionCollectionHashIncorrectFileCount.value,
          ),
        );
        final wrongFormat = _FakeCollectionSource({
          'a.txt': _item('a.txt', 'hello', format: 'application/octet-stream'),
        });
        expect(
          _codes(
            await C2paReader.fromSource(
              source: MemoryByteSource(manifest),
              collectionSource: wrongFormat,
              context: _readerContext(),
            ),
          ),
          contains(ValidationCode.assertionCollectionHashMismatch.value),
        );
      },
    );
  });
}

C2paBuilder _builder(String hashAlgorithm) => C2paBuilder(
  definition: ManifestDefinition(
    label: 'urn:c2pa:collection-test',
    intent: const BuilderIntent.create(DigitalSourceType.digitalCapture),
    generatorInfo: ClaimGeneratorInfo(name: 'collection-test'),
    format: 'application/zip',
    instanceId: 'xmp:iid:collection-test',
    hashAlgorithm: hashAlgorithm,
  ),
  context: C2paContext(signer: _ReservedDigestSigner()),
  signingAlgorithm: 'ps256',
  x5chain: [_certificates.leaf, _certificates.intermediate],
);

C2paContext _readerContext() => C2paContext(
  verifier: _DigestVerifier(_certificates.leafSpki),
  trust: C2paTrustConfiguration(
    trustAnchors: [_certificates.root],
    evaluationTime: DateTime.utc(2027),
  ),
);

Future<C2paReader> _readZip(Uint8List bytes, String mimeType) =>
    C2paReader.fromSource(
      source: MemoryByteSource(bytes),
      mimeType: mimeType,
      context: _readerContext(),
    );

Set<String> _codes(C2paReader reader) =>
    reader.validationResults.issues.map((issue) => issue.code).toSet();

C2paCollectionItem _item(
  String uri,
  String contents, {
  String? format,
  List<CollectionDataType>? dataTypes,
}) => C2paCollectionItem(
  uri: uri,
  source: MemoryByteSource(utf8.encode(contents)),
  format: format,
  dataTypes: dataTypes,
);

final class _FakeCollectionSource implements C2paCollectionSource {
  const _FakeCollectionSource(this.items);

  final Map<String, C2paCollectionItem> items;

  @override
  Future<Iterable<C2paCollectionItem>> entries() async => items.values;
}

final class _ReservedDigestSigner implements C2paReservedSizeSigner {
  @override
  String get algorithm => 'ps256';

  @override
  int get reservedSignatureSize => 64;

  @override
  Future<Uint8List> sign(Uint8List data) async =>
      Uint8List.fromList(await HashAlgorithm.sha512.digest(data));
}

final class _DigestVerifier implements C2paVerifier {
  const _DigestVerifier(this.expectedKey);

  final Uint8List expectedKey;

  @override
  Future<bool> verify({
    required String algorithm,
    required Uint8List data,
    required Uint8List signature,
    required Uint8List publicKey,
  }) async {
    final expected = await HashAlgorithm.sha512.digest(data);
    return algorithm == 'ps256' &&
        _equalBytes(publicKey, expectedKey) &&
        _equalBytes(signature, expected);
  }
}

Future<Uint8List> _rewriteCollectionHash(
  Uint8List asset,
  void Function(Map<Object?, Object?> value) transform,
) async {
  final registry = AssetHandlerRegistry();
  final manifest = await registry.extractManifest(
    MemoryByteSource(asset),
    mimeType: 'application/zip',
  );

  JumbfNode rewrite(JumbfNode node) {
    if (node is! JumbfSuperBoxNode) return node;
    if (node.label == CollectionHashAssertion.label) {
      final payload = (node.children.single as JumbfCborNode).payload;
      final value = Map<Object?, Object?>.from(decodeCbor(payload) as Map);
      transform(value);
      return JumbfSuperBoxNode(
        description: node.description,
        children: [JumbfCborNode(encodeCbor(value))],
      );
    }
    return JumbfSuperBoxNode(
      description: node.description,
      children: node.children.map(rewrite),
    );
  }

  final rewritten = (rewrite(parseJumbf(manifest)) as JumbfSuperBoxNode)
      .encode();
  final output = MemoryByteSink();
  await registry.replaceManifest(
    MemoryByteSource(asset),
    rewritten,
    output,
    mimeType: 'application/zip',
  );
  return output.toBytes();
}

final class _Entry {
  const _Entry(this.name, this.data);

  final String name;
  final List<int> data;
}

List<int> _archive(List<_Entry> entries) {
  final output = <int>[];
  final central = <List<int>>[];
  for (final entry in entries) {
    final offset = output.length;
    final name = utf8.encode(entry.name);
    final crc = _crc32(entry.data);
    output.addAll([
      ..._little32(0x04034b50),
      ..._little16(20),
      ..._little16(0x0800),
      ..._little16(0),
      ..._little16(0),
      ..._little16(0),
      ..._little32(crc),
      ..._little32(entry.data.length),
      ..._little32(entry.data.length),
      ..._little16(name.length),
      ..._little16(0),
      ...name,
      ...entry.data,
    ]);
    central.add([
      ..._little32(0x02014b50),
      ..._little16(0x0314),
      ..._little16(20),
      ..._little16(0x0800),
      ..._little16(0),
      ..._little16(0),
      ..._little16(0),
      ..._little32(crc),
      ..._little32(entry.data.length),
      ..._little32(entry.data.length),
      ..._little16(name.length),
      ..._little16(0),
      ..._little16(0),
      ..._little16(0),
      ..._little16(0),
      ..._little32(0x81a40000),
      ..._little32(offset),
      ...name,
    ]);
  }
  final centralOffset = output.length;
  for (final record in central) {
    output.addAll(record);
  }
  final centralSize = output.length - centralOffset;
  output.addAll([
    ..._little32(0x06054b50),
    ..._little16(0),
    ..._little16(0),
    ..._little16(entries.length),
    ..._little16(entries.length),
    ..._little32(centralSize),
    ..._little32(centralOffset),
    ..._little16(0),
  ]);
  return output;
}

List<int> _little16(int value) => [value & 0xff, value >> 8 & 0xff];

List<int> _little32(int value) => [
  value & 0xff,
  value >> 8 & 0xff,
  value >> 16 & 0xff,
  value >> 24 & 0xff,
];

int _crc32(List<int> bytes) {
  var crc = 0xffffffff;
  for (final byte in bytes) {
    crc ^= byte;
    for (var bit = 0; bit < 8; bit++) {
      crc = crc & 1 == 0 ? crc >> 1 : (crc >> 1) ^ 0xedb88320;
    }
  }
  return (crc ^ 0xffffffff) & 0xffffffff;
}

bool _equalBytes(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) return false;
  }
  return true;
}
