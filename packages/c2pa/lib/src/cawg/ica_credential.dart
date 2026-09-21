part of '../cawg_identity.dart';

/// Factory that creates an ICA credential from the signer payload.
typedef CawgIcaCredentialFactory = CawgIdentityClaimsCredential Function(
  CawgSignerPayload signerPayload,
);

/// Signing material used to generate ICA identity assertions.
final class CawgIcaCredentialHolder {
  /// Creates an ICA credential holder for dynamic identity signing.
  ///
  /// Throws ArgumentError unless the signer uses Ed25519 or the reservation
  /// size is positive.
  CawgIcaCredentialHolder({
    required this.signer,
    required this.credentialFactory,
    required this.reservedAssertionSize,
    this.keyId,
    this.role,
    this.expected = const {},
  }) {
    if (_algorithmByName(signer.algorithm) != SigningAlgorithm.ed25519) {
      throw ArgumentError.value(
        signer.algorithm,
        'signer',
        'ICA requires Ed25519',
      );
    }
    if (reservedAssertionSize < 1) {
      throw ArgumentError.value(
        reservedAssertionSize,
        'reservedAssertionSize',
        'Must be positive',
      );
    }
  }

  /// Signer callback used to produce COSE signatures.
  final C2paSigner signer;

  /// Factory that must produce a credential matching the signer payload.
  final CawgIcaCredentialFactory credentialFactory;

  /// Exact byte size reserved for the generated identity assertion.
  final int reservedAssertionSize;

  /// Optional COSE key identifier encoded as UTF-8 in the protected header.
  final String? keyId;

  /// Optional signer role included in the generated signer payload.
  final String? role;

  /// Fields whose keys start with `expected_` in the signer payload.
  final Map<String, Object?> expected;

  /// Builds a dynamic assertion that signs the claim at generation time.
  C2paDynamicAssertion toDynamicAssertion({int instance = 0}) {
    final label = CawgIdentityLabels.instance(instance);
    return C2paDynamicAssertion(
      label: label,
      reservedSize: reservedAssertionSize,
      encoding: C2paDynamicAssertionEncoding.cbor,
      callback: (request) async {
        final signerPayload = CawgSignerPayload(
          referencedAssertions: request.claim.assertions.where(
            (reference) => !_isIdentityReference(reference.url),
          ),
          signatureType: CawgIdentityLabels.identityClaimsAggregation,
          role: role,
          expected: expected,
        );
        final credential = credentialFactory(signerPayload);
        if (!deepEquals(credential.c2paAsset, signerPayload.toJson())) {
          throw const FormatException(
            'ICA credential c2paAsset must match signer_payload',
          );
        }
        final protected = <CoseHeaderLabel, Object?>{
          CoseHeaderLabel.contentType: 'application/vc',
          if (keyId != null)
            CoseHeaderLabel.keyId: Uint8List.fromList(utf8.encode(keyId!)),
        };
        final credentialBytes = Uint8List.fromList(
          utf8.encode(jsonEncode(credential.toJson())),
        );
        final signature =
            await CoseSigner(
              backends: {
                SigningAlgorithm.ed25519: _CallbackSigningBackend(signer),
              },
            ).sign(
              algorithm: SigningAlgorithm.ed25519,
              payload: credentialBytes,
              protectedHeaders: CoseHeaders(protected),
            );
        return C2paDynamicAssertionOutput.cbor(
          label: label,
          data: _fitIdentityAssertion(
            payload: signerPayload,
            signature: signature,
            size: request.reservedSize,
          ).toCborMap(),
        );
      },
    );
  }
}

/// Issuer value from a CAWG identity-claims credential.
final class CawgIssuer {
  /// Creates an issuer with optional JSON object fields.
  CawgIssuer({required this.id, Map<String, Object?> fields = const {}})
    : fields = freezeJsonMap(fields);

  /// Parses a credential issuer from a string or JSON object.
  factory CawgIssuer.fromJson(Object? value) {
    if (value is String) return CawgIssuer(id: value);
    final map = _stringMap(value, 'VC issuer');
    final id = map['id'];
    if (id is! String) {
      throw const FormatException('VC issuer object requires id');
    }
    return CawgIssuer(id: id, fields: unknownFieldsOf(map, const {'id'}));
  }

  /// Issuer identifier string, commonly a DID.
  final String id;

  /// Additional issuer object fields preserved for JSON output.
  final Map<String, Object?> fields;

  /// Encodes the issuer as either a string or JSON object.
  Object toJson() => fields.isEmpty ? id : {...fields, 'id': id};

  @override
  bool operator ==(Object other) =>
      other is CawgIssuer && id == other.id && deepEquals(fields, other.fields);

  @override
  int get hashCode => Object.hash(id, deepHash(fields));
}

/// Verified identity provider entry in an ICA credential.
final class CawgIdentityProvider {
  /// Creates a verified identity provider.
  ///
  /// Throws FormatException when the URI or provider name is empty.
  CawgIdentityProvider({
    required this.id,
    required this.name,
    Map<String, Object?> unknownFields = const {},
  }) : unknownFields = freezeJsonMap(unknownFields) {
    if (id.toString().isEmpty || name.isEmpty) {
      throw const FormatException('Malformed verified identity provider');
    }
  }

  /// Parses a verified identity provider from JSON.
  factory CawgIdentityProvider.fromJson(Object? value) {
    final map = _stringMap(value, 'verified identity provider');
    final id = map['id'];
    final name = map['name'];
    final uri = id is String ? Uri.tryParse(id) : null;
    if (uri == null || name is! String) {
      throw const FormatException('Malformed verified identity provider');
    }
    return CawgIdentityProvider(
      id: uri,
      name: name,
      unknownFields: unknownFieldsOf(map, const {'id', 'name'}),
    );
  }

  /// Provider identifier URI.
  final Uri id;

  /// Human-readable provider name; must be non-empty.
  final String name;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as a JSON-compatible map.
  Map<String, Object?> toJson() => {
    ...unknownFields,
    'id': id.toString(),
    'name': name,
  };

  @override
  bool operator ==(Object other) =>
      other is CawgIdentityProvider &&
      id == other.id &&
      name == other.name &&
      deepEquals(unknownFields, other.unknownFields);

  @override
  int get hashCode => Object.hash(id, name, deepHash(unknownFields));
}

/// Verified identity claim embedded in an ICA credential.
final class CawgVerifiedIdentity {
  /// Creates a verified identity claim.
  ///
  /// Throws FormatException when required or supplied identity strings are
  /// empty.
  CawgVerifiedIdentity({
    required this.type,
    required DateTime verifiedAt,
    required this.provider,
    this.name,
    this.username,
    this.address,
    this.uri,
    Map<String, Object?> unknownFields = const {},
  }) : verifiedAt = verifiedAt.toUtc(),
       unknownFields = freezeJsonMap(unknownFields) {
    if (type.isEmpty ||
        (name != null && name!.isEmpty) ||
        (username != null && username!.isEmpty) ||
        (address != null && address!.isEmpty)) {
      throw const FormatException('Malformed verified identity');
    }
  }

  /// Parses a verified identity claim from JSON.
  factory CawgVerifiedIdentity.fromJson(Object? value) {
    final map = _stringMap(value, 'verified identity');
    final type = map['type'];
    final verifiedAt = map['verifiedAt'];
    if (type is! String || verifiedAt is! String) {
      throw const FormatException('Malformed verified identity');
    }
    final parsedTime = DateTime.tryParse(verifiedAt);
    final uri = map['uri'];
    if (parsedTime == null || (uri != null && uri is! String)) {
      throw const FormatException('Malformed verified identity');
    }
    return CawgVerifiedIdentity(
      type: type,
      verifiedAt: parsedTime,
      provider: CawgIdentityProvider.fromJson(map['provider']),
      name: map['name'] as String?,
      username: map['username'] as String?,
      address: map['address'] as String?,
      uri: uri == null ? null : Uri.parse(uri as String),
      unknownFields: unknownFieldsOf(map, const {
        'type',
        'name',
        'username',
        'address',
        'uri',
        'verifiedAt',
        'provider',
      }),
    );
  }

  /// Identity category such as a person, organization, or account.
  final String type;

  /// Optional display name for the verified identity.
  final String? name;

  /// Optional username or handle for the verified identity.
  final String? username;

  /// Optional address string for the verified identity.
  final String? address;

  /// Optional URI associated with the verified identity.
  final Uri? uri;

  /// UTC timestamp when the provider verified the identity.
  final DateTime verifiedAt;

  /// Provider that verified this identity.
  final CawgIdentityProvider provider;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as a JSON-compatible map.
  Map<String, Object?> toJson() => {
    ...unknownFields,
    'type': type,
    'name': ?name,
    'username': ?username,
    'address': ?address,
    'uri': ?uri?.toString(),
    'verifiedAt': verifiedAt.toIso8601String(),
    'provider': provider.toJson(),
  };

  @override
  bool operator ==(Object other) =>
      other is CawgVerifiedIdentity &&
      type == other.type &&
      name == other.name &&
      username == other.username &&
      address == other.address &&
      uri == other.uri &&
      verifiedAt == other.verifiedAt &&
      provider == other.provider &&
      deepEquals(unknownFields, other.unknownFields);

  @override
  int get hashCode => Object.hash(
    type,
    name,
    username,
    address,
    uri,
    verifiedAt,
    provider,
    deepHash(unknownFields),
  );
}
