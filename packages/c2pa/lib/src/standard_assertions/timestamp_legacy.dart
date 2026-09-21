part of '../standard_assertions.dart';

/// CBOR assertion for the `c2pa.time-stamp` label.
final class C2paTimestampAssertion implements C2paStandardAssertion {
  /// Creates a timestamp assertion from timestamp tokens keyed by identifier.
  ///
  /// Throws FormatException when any identifier or token is empty.
  C2paTimestampAssertion(Map<String, Uint8List> timestamps)
    : timestamps = Map<String, Uint8List>.unmodifiable(
        timestamps.map(
          (key, value) =>
              MapEntry(key, Uint8List.fromList(value).asUnmodifiableView()),
        ),
      ) {
    if (timestamps.entries.any(
      (entry) => entry.key.isEmpty || entry.value.isEmpty,
    )) {
      throw const FormatException(
        'Timestamp identifiers and tokens are required',
      );
    }
  }

  /// Parses a timestamp assertion from a CBOR map of byte strings.
  factory C2paTimestampAssertion.fromCbor(Object? value) {
    final map = _map(value, 'timestamp assertion');
    return C2paTimestampAssertion({
      for (final entry in map.entries)
        entry.key: _bytes(entry.value, 'timestamp token'),
    });
  }

  /// Assertion label for C2PA timestamp assertions.
  static const baseLabel = 'c2pa.time-stamp';

  /// Timestamp tokens keyed by non-empty timestamp identifier.
  final Map<String, Uint8List> timestamps;
  @override
  String get label => baseLabel;
  @override
  C2paStandardAssertionEncoding get encoding =>
      C2paStandardAssertionEncoding.cbor;
  @override
  String? get contentType => 'application/cbor';
  @override
  Map<String, Object?> toAssertionData() => {
    for (final entry in timestamps.entries)
      entry.key: Uint8List.fromList(entry.value),
  };

  /// Encodes this assertion as a CBOR-compatible map.
  Map<String, Object?> toCborMap() => toAssertionData();
  @override
  bool operator ==(Object other) =>
      other is C2paTimestampAssertion &&
      deepEquals(timestamps, other.timestamps);
  @override
  int get hashCode => deepHash(timestamps);
}

/// CBOR assertion for the `c2pa.certificate-status` label.
final class C2paCertificateStatusAssertion implements C2paStandardAssertion {
  /// Creates a certificate-status assertion from OCSP response values.
  C2paCertificateStatusAssertion({
    required Iterable<Uint8List> ocspValues,
    Map<String, Object?> unknownFields = const {},
  }) : ocspValues = List<Uint8List>.unmodifiable(
         ocspValues.map(
           (value) => Uint8List.fromList(value).asUnmodifiableView(),
         ),
       ),
       unknownFields = freezeJsonMap(unknownFields);

  /// Parses certificate status from CBOR `ocspVals` byte strings.
  factory C2paCertificateStatusAssertion.fromCbor(Object? value) {
    final map = _map(value, 'certificate status assertion');
    return C2paCertificateStatusAssertion(
      ocspValues: _requiredList(
        map,
        'ocspVals',
      ).map((item) => _bytes(item, 'OCSP value')),
      unknownFields: _unknown(map, const {'ocspVals'}),
    );
  }

  /// Parses certificate status from JSON base64 `ocspVals` strings.
  factory C2paCertificateStatusAssertion.fromJson(Map<String, Object?> json) =>
      C2paCertificateStatusAssertion(
        ocspValues: _requiredList(json, 'ocspVals').map((item) {
          if (item is! String) {
            throw const FormatException(
              'JSON OCSP values must be base64 strings',
            );
          }
          try {
            return Uint8List.fromList(base64.decode(item));
          } on FormatException {
            throw const FormatException('Invalid base64 OCSP value');
          }
        }),
        unknownFields: _unknown(json, const {'ocspVals'}),
      );

  /// Assertion label for C2PA certificate-status assertions.
  static const baseLabel = 'c2pa.certificate-status';

  /// OCSP response values serialized under `ocspVals`.
  final List<Uint8List> ocspValues;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;
  @override
  String get label => baseLabel;
  @override
  C2paStandardAssertionEncoding get encoding =>
      C2paStandardAssertionEncoding.cbor;
  @override
  String? get contentType => 'application/cbor';
  @override
  Map<String, Object?> toAssertionData() => {
    ...unknownFields,
    'ocspVals': ocspValues.map(Uint8List.fromList).toList(),
  };

  /// Encodes this assertion as a CBOR-compatible map.
  Map<String, Object?> toCborMap() => toAssertionData();

  /// Encodes this assertion as JSON with OCSP values base64 encoded.
  Map<String, Object?> toJson() => {
    ...unknownFields,
    'ocspVals': ocspValues.map(base64.encode).toList(),
  };
  @override
  bool operator ==(Object other) =>
      other is C2paCertificateStatusAssertion &&
      deepEquals(ocspValues, other.ocspValues) &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode =>
      Object.hash(deepHash(ocspValues), deepHash(unknownFields));
}

/// Legacy JSON assertion namespace represented by the assertion label.
enum C2paLegacyAssertionKind {
  /// Legacy `stds.exif` metadata assertion.
  exif,

  /// Legacy Schema.org CreativeWork assertion.
  creativeWork,

  /// Legacy generic `schema.org` assertion.
  schemaOrg,
}

/// Legacy JSON assertion using historical C2PA or Schema.org labels.
final class C2paLegacyJsonAssertion implements C2paStandardAssertion {
  /// Creates a legacy JSON assertion with validation for known kinds.
  ///
  /// Throws FormatException when the label is empty or required `@type`
  /// values are missing for CreativeWork or Schema.org assertions.
  C2paLegacyJsonAssertion({
    required this.kind,
    required Map<String, Object?> value,
    String? label,
  }) : value = freezeJsonMap(value),
       label = label ?? _legacyLabel(kind) {
    if (this.label.isEmpty) {
      throw const FormatException('Legacy assertion label is empty');
    }
    if (kind == C2paLegacyAssertionKind.creativeWork &&
        value['@type'] != 'CreativeWork') {
      throw const FormatException('CreativeWork requires @type CreativeWork');
    }
    if (kind == C2paLegacyAssertionKind.schemaOrg &&
        value['@type'] is! String) {
      throw const FormatException('Schema.org assertion requires @type');
    }
  }

  /// Parses a legacy JSON assertion and infers its kind from the label.
  factory C2paLegacyJsonAssertion.fromJson({
    required String label,
    required Map<String, Object?> value,
  }) => C2paLegacyJsonAssertion(
    kind: label == 'stds.exif'
        ? C2paLegacyAssertionKind.exif
        : label == 'stds.schema-org.CreativeWork'
        ? C2paLegacyAssertionKind.creativeWork
        : C2paLegacyAssertionKind.schemaOrg,
    value: value,
    label: label,
  );

  /// Legacy namespace selected for this JSON assertion.
  final C2paLegacyAssertionKind kind;
  @override
  final String label;

  /// JSON payload emitted unchanged for this legacy assertion.
  final Map<String, Object?> value;
  @override
  C2paStandardAssertionEncoding get encoding =>
      C2paStandardAssertionEncoding.json;
  @override
  String? get contentType => 'application/json';
  @override
  Map<String, Object?> toAssertionData() => value;

  /// Encodes this legacy assertion as a JSON-compatible map.
  Map<String, Object?> toJson() => value;
  @override
  bool operator ==(Object other) =>
      other is C2paLegacyJsonAssertion &&
      kind == other.kind &&
      label == other.label &&
      deepEquals(value, other.value);
  @override
  int get hashCode => Object.hash(kind, label, deepHash(value));
}
