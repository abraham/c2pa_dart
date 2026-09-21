part of '../cawg_identity.dart';

/// Identity Claims Aggregation verifiable credential.
final class CawgIdentityClaimsCredential {
  /// Creates an ICA credential from VC fields and credentialSubject data.
  ///
  /// Throws FormatException when no verified identities are supplied.
  CawgIdentityClaimsCredential({
    required Iterable<String> context,
    required Iterable<String> types,
    required this.issuer,
    required Iterable<CawgVerifiedIdentity> verifiedIdentities,
    required Map<String, Object?> c2paAsset,
    this.id,
    this.validFrom,
    this.validUntil,
    this.issuanceDate,
    this.expirationDate,
    Map<String, Object?> unknownFields = const {},
    Map<String, Object?> subjectUnknownFields = const {},
    Uint8List? rawJsonBytes,
  }) : context = List<String>.unmodifiable(context),
       types = List<String>.unmodifiable(types),
       verifiedIdentities = List<CawgVerifiedIdentity>.unmodifiable(
         verifiedIdentities,
       ),
       c2paAsset = freezeJsonMap(c2paAsset),
       unknownFields = freezeJsonMap(unknownFields),
       subjectUnknownFields = freezeJsonMap(subjectUnknownFields),
       _rawJsonBytes = rawJsonBytes == null
           ? null
           : Uint8List.fromList(rawJsonBytes).asUnmodifiableView() {
    if (this.verifiedIdentities.isEmpty) {
      throw const FormatException('verifiedIdentities must not be empty');
    }
  }

  /// Parses an ICA credential from a decoded JSON value.
  factory CawgIdentityClaimsCredential.fromJson(Object? value) {
    final map = _stringMap(value, 'ICA credential');
    final context = _strings(map['@context'], '@context');
    final types = _strings(map['type'], 'type');
    final subject = _stringMap(map['credentialSubject'], 'credentialSubject');
    final identities = subject['verifiedIdentities'];
    final asset = subject['c2paAsset'];
    if (identities is! List || asset is! Map) {
      throw const FormatException('Malformed ICA credentialSubject');
    }

    return CawgIdentityClaimsCredential(
      context: context,
      types: types,
      issuer: CawgIssuer.fromJson(map['issuer']),
      verifiedIdentities: identities.map(CawgVerifiedIdentity.fromJson),
      c2paAsset: _stringMap(asset, 'c2paAsset'),
      id: map['id'] as String?,
      validFrom: _optionalDate(map['validFrom'], 'validFrom'),
      validUntil: _optionalDate(map['validUntil'], 'validUntil'),
      issuanceDate: _optionalDate(map['issuanceDate'], 'issuanceDate'),
      expirationDate: _optionalDate(map['expirationDate'], 'expirationDate'),
      unknownFields: unknownFieldsOf(map, const {
        '@context',
        'type',
        'issuer',
        'id',
        'validFrom',
        'validUntil',
        'issuanceDate',
        'expirationDate',
        'credentialSubject',
      }),
      subjectUnknownFields: unknownFieldsOf(subject, const {
        'verifiedIdentities',
        'c2paAsset',
      }),
    );
  }

  /// Decodes an ICA credential from UTF-8 JSON bytes.
  factory CawgIdentityClaimsCredential.decode(Uint8List bytes) {
    final value = jsonDecode(utf8.decode(bytes));
    final parsed = CawgIdentityClaimsCredential.fromJson(value);
    return CawgIdentityClaimsCredential(
      context: parsed.context,
      types: parsed.types,
      issuer: parsed.issuer,
      verifiedIdentities: parsed.verifiedIdentities,
      c2paAsset: parsed.c2paAsset,
      id: parsed.id,
      validFrom: parsed.validFrom,
      validUntil: parsed.validUntil,
      issuanceDate: parsed.issuanceDate,
      expirationDate: parsed.expirationDate,
      unknownFields: parsed.unknownFields,
      subjectUnknownFields: parsed.subjectUnknownFields,
      rawJsonBytes: bytes,
    );
  }

  /// Verifiable Credential context values from `@context`.
  final List<String> context;

  /// Credential type values from `type`.
  final List<String> types;

  /// Credential issuer.
  final CawgIssuer issuer;

  /// Non-empty verified identities in `credentialSubject`.
  final List<CawgVerifiedIdentity> verifiedIdentities;

  /// Signer-payload JSON stored in `credentialSubject.c2paAsset`.
  final Map<String, Object?> c2paAsset;

  /// Optional credential identifier.
  final String? id;

  /// Optional UTC instant when the credential becomes valid.
  final DateTime? validFrom;

  /// Optional UTC instant when the credential stops being valid.
  final DateTime? validUntil;

  /// Optional VC 1.1 issuance timestamp.
  final DateTime? issuanceDate;

  /// Optional VC 1.1 expiration timestamp.
  final DateTime? expirationDate;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Additional `credentialSubject` fields preserved for JSON output.
  final Map<String, Object?> subjectUnknownFields;
  final Uint8List? _rawJsonBytes;

  /// Original credential JSON bytes, or null when constructed from fields.
  Uint8List? get rawJsonBytes => _rawJsonBytes == null
      ? null
      : Uint8List.fromList(_rawJsonBytes).asUnmodifiableView();

  /// Whether the credential declares the VC 1.1 context.
  bool get isVc11 => context.contains('https://www.w3.org/2018/credentials/v1');

  /// Whether the credential declares the VC 2.0 context.
  bool get isVc20 => context.contains('https://www.w3.org/ns/credentials/v2');

  /// Encodes this value as a JSON-compatible map.
  Map<String, Object?> toJson() => {
    ...unknownFields,
    '@context': context,
    'type': types,
    'issuer': issuer.toJson(),
    'id': ?id,
    'validFrom': ?validFrom?.toIso8601String(),
    'validUntil': ?validUntil?.toIso8601String(),
    'issuanceDate': ?issuanceDate?.toIso8601String(),
    'expirationDate': ?expirationDate?.toIso8601String(),
    'credentialSubject': {
      ...subjectUnknownFields,
      'verifiedIdentities': verifiedIdentities
          .map((identity) => identity.toJson())
          .toList(growable: false),
      'c2paAsset': c2paAsset,
    },
  };

  /// Encodes the credential to UTF-8 JSON, preserving original bytes.
  Uint8List encodeJson() => _rawJsonBytes == null
      ? Uint8List.fromList(utf8.encode(jsonEncode(toJson())))
      : Uint8List.fromList(_rawJsonBytes);

  @override
  bool operator ==(Object other) =>
      other is CawgIdentityClaimsCredential &&
      deepEquals(context, other.context) &&
      deepEquals(types, other.types) &&
      issuer == other.issuer &&
      deepEquals(verifiedIdentities, other.verifiedIdentities) &&
      deepEquals(c2paAsset, other.c2paAsset) &&
      id == other.id &&
      validFrom == other.validFrom &&
      validUntil == other.validUntil &&
      issuanceDate == other.issuanceDate &&
      expirationDate == other.expirationDate &&
      deepEquals(unknownFields, other.unknownFields) &&
      deepEquals(subjectUnknownFields, other.subjectUnknownFields);

  @override
  int get hashCode => Object.hash(
    deepHash(context),
    deepHash(types),
    issuer,
    deepHash(verifiedIdentities),
    deepHash(c2paAsset),
    id,
    validFrom,
    validUntil,
    issuanceDate,
    expirationDate,
    deepHash(unknownFields),
    deepHash(subjectUnknownFields),
  );
}
