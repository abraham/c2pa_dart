part of '../cawg_identity.dart';

enum _CawgRoleEncoding { absent, legacyString, list }

/// CAWG identity assertion containing signer payload, signature, and padding.
final class CawgIdentityAssertion {
  /// Creates a CAWG identity assertion from its CBOR fields.
  ///
  /// Throws FormatException when the signature byte string is empty.
  CawgIdentityAssertion({
    required this.signerPayload,
    required Uint8List signature,
    Uint8List? pad1,
    Uint8List? pad2,
    Map<String, Object?> unknownFields = const {},
    Uint8List? rawBytes,
  }) : signature = Uint8List.fromList(signature).asUnmodifiableView(),
       pad1 = Uint8List.fromList(pad1 ?? const []).asUnmodifiableView(),
       pad2 = pad2 == null
           ? null
           : Uint8List.fromList(pad2).asUnmodifiableView(),
       unknownFields = freezeJsonMap(unknownFields),
       _rawBytes = rawBytes == null
           ? null
           : Uint8List.fromList(rawBytes).asUnmodifiableView() {
    if (signature.isEmpty) {
      throw const FormatException('CAWG identity signature must not be empty');
    }
  }

  /// Parses a CAWG identity assertion from a decoded CBOR map.
  factory CawgIdentityAssertion.fromCbor(Object? value) {
    final map = _stringMap(value, 'CAWG identity assertion');
    final signerPayload = map['signer_payload'];
    final signature = cborBytes(map['signature']);
    final pad1 = cborBytes(map['pad1']);
    final rawPad2 = map['pad2'];
    final pad2 = cborBytes(rawPad2);
    if (signerPayload == null ||
        signature == null ||
        pad1 == null ||
        (rawPad2 != null && pad2 == null)) {
      throw const FormatException('Malformed CAWG identity assertion');
    }
    return CawgIdentityAssertion(
      signerPayload: CawgSignerPayload.fromCbor(signerPayload),
      signature: signature,
      pad1: pad1,
      pad2: pad2,
      unknownFields: unknownFieldsOf(map, const {
        'signer_payload',
        'signature',
        'pad1',
        'pad2',
      }),
    );
  }

  /// Decodes a CAWG identity assertion from raw CBOR bytes.
  factory CawgIdentityAssertion.decode(Uint8List bytes) {
    final decoded = CawgIdentityAssertion.fromCbor(
      decodeCbor(
        bytes,
        requireCanonicalMapOrder: false,
        allowIndefiniteLength: true,
      ),
    );
    final signerPayloadBytes = _cborMapValueBytes(bytes, 'signer_payload');
    return CawgIdentityAssertion(
      signerPayload: decoded.signerPayload._withRawBytes(signerPayloadBytes),
      signature: decoded.signature,
      pad1: decoded.pad1,
      pad2: decoded.pad2,
      unknownFields: decoded.unknownFields,
      rawBytes: bytes,
    );
  }

  /// Payload signed by the CAWG identity signature.
  final CawgSignerPayload signerPayload;

  /// Signature bytes from the CAWG identity assertion.
  final Uint8List signature;

  /// First padding byte string, required to contain only zeros.
  final Uint8List pad1;

  /// Optional second padding byte string, also required to contain zeros.
  final Uint8List? pad2;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;
  final Uint8List? _rawBytes;

  /// Encodes the identity assertion as the CBOR map stored in the manifest.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    'signer_payload': signerPayload.toCborMap(),
    'signature': Uint8List.fromList(signature),
    'pad1': Uint8List.fromList(pad1),
    'pad2': ?(pad2 == null ? null : Uint8List.fromList(pad2!)),
  };

  /// Encodes the identity assertion to CBOR, preserving original bytes.
  Uint8List encode() => _rawBytes == null
      ? encodeCbor(toCborMap())
      : Uint8List.fromList(_rawBytes);

  /// Whether all present padding bytes are zero.
  bool get hasValidPadding =>
      pad1.every((value) => value == 0) &&
      (pad2?.every((value) => value == 0) ?? true);

  @override
  bool operator ==(Object other) =>
      other is CawgIdentityAssertion &&
      signerPayload == other.signerPayload &&
      deepEquals(signature, other.signature) &&
      deepEquals(pad1, other.pad1) &&
      deepEquals(pad2, other.pad2) &&
      deepEquals(unknownFields, other.unknownFields);

  @override
  int get hashCode => Object.hash(
    signerPayload,
    deepHash(signature),
    deepHash(pad1),
    deepHash(pad2),
    deepHash(unknownFields),
  );
}
