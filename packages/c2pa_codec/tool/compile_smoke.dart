import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';

void main() {
  final largeInteger = BigInt.parse('18446744073709551615');
  final cbor = encodeCbor(<Object?>[largeInteger, 'c2pa']);
  final box = IsoBoxHeader.create(type: 'test', payloadSize: cbor.length);
  final jumbf = JumbfSuperBoxNode(
    description: JumbfDescription.fromUuidHex(
      contentType: JumbfUuid.c2paManifestStore,
      label: 'c2pa',
    ),
    children: [JumbfCborNode(cbor)],
  );
  final cose = CoseSign1(
    protectedHeaders: CoseHeaders({CoseHeaderLabels.alg: -7}),
    payload: jumbf.encode(),
    signature: Uint8List(64),
  );
  final brotli = decodeBrotli(
    _hex(
      '21a8000454686520717569636b2062726f776e20666f78206a756d7073206f76'
      '657220746865206c617a7920646f6703',
    ),
    maxOutputBytes: 43,
  );
  final compressedManifest = JumbfSuperBoxNode(
    description: JumbfDescription.fromUuidHex(
      contentType: JumbfUuid.c2paCompressedManifest,
      label: 'manifest',
    ),
    children: [
      JumbfBrotliNode(
        Uint8List.fromList(
          _hex(
            '21a400040000002a6a756d62000000226a756d6463326d6100110010800000aa'
            '00389b71036d616e69666573740003',
          ),
        ),
      ),
    ],
  );
  final decoded = decodeCbor(cbor);
  if (decoded is! List ||
      box.encode().length != 8 ||
      parseJumbf(jumbf.encode()).label != 'c2pa' ||
      decodeCoseSign1(cose.encode()).signature.length != 64 ||
      brotli.length != 43 ||
      decodeCompressedJumbf(
            compressedManifest.encode(),
            maxOutputBytes: 1024,
          ).manifest.label !=
          'manifest') {
    throw StateError('c2pa_codec smoke check failed');
  }
}

List<int> _hex(String value) => List<int>.generate(
  value.length ~/ 2,
  (index) => int.parse(value.substring(index * 2, index * 2 + 2), radix: 16),
  growable: false,
);
