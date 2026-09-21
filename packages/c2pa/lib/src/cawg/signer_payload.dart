part of '../cawg_identity.dart';

/// Decoded CAWG `signer_payload` map used as signature input.
final class CawgSignerPayload {
  /// Creates a signer payload from referenced assertions and signature type.
  ///
  /// Throws FormatException when the signature type or any role is empty.
  factory CawgSignerPayload({
    required Iterable<ClaimHashedUri> referencedAssertions,
    required String signatureType,
    String? role,
    Iterable<String> roles = const [],
    Map<String, Object?> expected = const {},
    Map<String, Object?> unknownFields = const {},
  }) => CawgSignerPayload._(
    referencedAssertions: referencedAssertions,
    signatureType: signatureType,
    roles: [?role, ...roles],
    roleEncoding: _CawgRoleEncoding.list,
    expected: expected,
    unknownFields: unknownFields,
  );

  CawgSignerPayload._({
    required Iterable<ClaimHashedUri> referencedAssertions,
    required this.signatureType,
    required Iterable<String> roles,
    required this._roleEncoding,
    required Map<String, Object?> expected,
    required Map<String, Object?> unknownFields,
    Uint8List? rawBytes,
  }) : referencedAssertions = List<ClaimHashedUri>.unmodifiable(
         referencedAssertions,
       ),
       roles = List<String>.unmodifiable(roles),
       expected = freezeJsonMap(expected),
       unknownFields = freezeJsonMap(unknownFields),
       _rawBytes = rawBytes == null
           ? null
           : Uint8List.fromList(rawBytes).asUnmodifiableView() {
    if (signatureType.isEmpty) {
      throw const FormatException('CAWG signer_payload requires sig_type');
    }
    if (this.roles.any((role) => role.isEmpty)) {
      throw const FormatException(
        'CAWG signer_payload roles must not be empty',
      );
    }
  }

  /// Parses a CAWG `signer_payload` CBOR map.
  factory CawgSignerPayload.fromCbor(Object? value) {
    final map = _stringMap(value, 'CAWG signer_payload');
    final refs = map['referenced_assertions'];
    final sigType = map['sig_type'];
    final role = map['role'];
    if (refs is! List || sigType is! String) {
      throw const FormatException('Malformed CAWG signer_payload');
    }
    if (role != null &&
        role is! String &&
        (role is! List || !role.every((item) => item is String))) {
      throw const FormatException('CAWG role must be a string or string array');
    }
    final expected = <String, Object?>{};
    final unknown = <String, Object?>{};
    for (final entry in map.entries) {
      if (const {
        'referenced_assertions',
        'sig_type',
        'role',
      }.contains(entry.key)) {
        continue;
      }
      if (entry.key.startsWith('expected_')) {
        expected[entry.key] = entry.value;
      } else {
        unknown[entry.key] = entry.value;
      }
    }
    return CawgSignerPayload._(
      referencedAssertions: refs.map(ClaimHashedUri.fromCbor),
      signatureType: sigType,
      roles: role is String
          ? [role]
          : role is List
          ? role.cast<String>()
          : const [],
      roleEncoding: role == null
          ? _CawgRoleEncoding.absent
          : role is String
          ? _CawgRoleEncoding.legacyString
          : _CawgRoleEncoding.list,
      expected: expected,
      unknownFields: unknown,
    );
  }

  /// Assertions covered by the identity signature.
  final List<ClaimHashedUri> referencedAssertions;

  /// CAWG signature type such as `cawg.x509.cose`.
  final String signatureType;

  /// Optional non-empty roles associated with the signer.
  final List<String> roles;
  final _CawgRoleEncoding _roleEncoding;

  /// Legacy single role value, or null when zero or multiple roles exist.
  String? get role => roles.length == 1 ? roles.single : null;

  /// Fields whose keys start with `expected_` in the signer payload.
  final Map<String, Object?> expected;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;
  final Uint8List? _rawBytes;

  CawgSignerPayload _withRawBytes(Uint8List bytes) => CawgSignerPayload._(
    referencedAssertions: referencedAssertions,
    signatureType: signatureType,
    roles: roles,
    roleEncoding: _roleEncoding,
    expected: expected,
    unknownFields: unknownFields,
    rawBytes: bytes,
  );

  /// Encodes the signer payload as the CBOR map used for signing.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    ...expected,
    'referenced_assertions': referencedAssertions
        .map((reference) => reference.toCborMap())
        .toList(growable: false),
    'sig_type': signatureType,
    if (_roleEncoding != _CawgRoleEncoding.absent)
      'role': _roleEncoding == _CawgRoleEncoding.legacyString
          ? roles.single
          : roles,
  };

  /// Encodes the signer payload to CBOR, preserving original bytes when known.
  Uint8List encode() => _rawBytes == null
      ? encodeCbor(toCborMap())
      : Uint8List.fromList(_rawBytes);

  /// Encodes the signer payload as JSON with byte strings base64 encoded.
  Map<String, Object?> toJson() =>
      _bytesToBase64(toCborMap()) as Map<String, Object?>;

  @override
  bool operator ==(Object other) =>
      other is CawgSignerPayload &&
      deepEquals(referencedAssertions, other.referencedAssertions) &&
      signatureType == other.signatureType &&
      deepEquals(roles, other.roles) &&
      deepEquals(expected, other.expected) &&
      deepEquals(unknownFields, other.unknownFields);

  @override
  int get hashCode => Object.hash(
    deepHash(referencedAssertions),
    signatureType,
    deepHash(roles),
    deepHash(expected),
    deepHash(unknownFields),
  );
}
