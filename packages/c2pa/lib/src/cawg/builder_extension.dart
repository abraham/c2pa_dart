part of '../cawg_identity.dart';

/// Callback that timestamps CAWG COSE counter-signature bytes.
typedef CawgTimestampCallback = Future<Uint8List> Function(
  Uint8List counterSignatureBytes,
);

/// Convenience methods for adding CAWG identity assertions to a builder.
extension CawgBuilderExtension on C2paBuilder {
  /// Adds an X.509 COSE CAWG identity dynamic assertion.
  C2paBuilder withCawgX509Identity(
    CawgX509CredentialHolder holder, {
    int instance = 0,
  }) => withDynamicAssertion(holder.toDynamicAssertion(instance: instance));

  /// Adds an identity-claims aggregation dynamic assertion.
  C2paBuilder withCawgIdentityClaims(
    CawgIcaCredentialHolder holder, {
    int instance = 0,
  }) => withDynamicAssertion(holder.toDynamicAssertion(instance: instance));
}

Uint8List _withSigTst2(Uint8List cose, Uint8List timestampToken) {
  final tagged = cose.isNotEmpty && cose.first == 0xd2;
  final decoded = decodeCbor(tagged ? Uint8List.sublistView(cose, 1) : cose);
  if (decoded is! List || decoded.length != 4 || decoded[1] is! Map) {
    throw const FormatException('Malformed generated COSE_Sign1');
  }
  final unprotected = Map<Object?, Object?>.from(decoded[1] as Map);
  unprotected['sigTst2'] = {
    'tstTokens': [
      {'val': Uint8List.fromList(timestampToken)},
    ],
  };
  final encoded = encodeCbor([decoded[0], unprotected, decoded[2], decoded[3]]);
  return tagged ? Uint8List.fromList([0xd2, ...encoded]) : encoded;
}
