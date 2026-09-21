import 'dart:collection';
import 'dart:typed_data';

import 'intent.dart';
import 'json_utils.dart';
import 'validation.dart';

/// Signature metadata extracted from a verified C2PA claim signature.
///
/// Date values are certificate validity or trusted signing instants in UTC
/// when serialized with [toJson].
final class SignatureInfo {
  /// Creates immutable signature metadata.
  ///
  /// [certificateChain] is copied defensively as DER-encoded certificates in
  /// leaf-first order.
  SignatureInfo({
    required this.algorithm,
    required this.serialNumber,
    required this.notBefore,
    required this.notAfter,
    required Iterable<Uint8List> certificateChain,
    this.issuer,
    this.commonName,
    this.time,
    this.revocationStatus,
  }) : certificateChain = List<Uint8List>.unmodifiable(
         certificateChain.map(
           (certificate) =>
               Uint8List.fromList(certificate).asUnmodifiableView(),
         ),
       );

  /// COSE signing algorithm name used by the claim signature.
  final String algorithm;

  /// Display name from the signing certificate subject, or `null` if absent.
  final String? issuer;

  /// Common name from the signing certificate subject, or `null` if absent.
  final String? commonName;

  /// Decimal serial number of the signing certificate.
  final String serialNumber;

  /// Earliest instant at which the signing certificate is valid.
  final DateTime notBefore;

  /// Latest instant at which the signing certificate is valid.
  final DateTime notAfter;

  /// Trusted timestamp for the signature, or `null` when none validated.
  final DateTime? time;

  /// OCSP revocation result; `true` means good and `false` revoked.
  ///
  /// A `null` value means no conclusive revocation status was available.
  final bool? revocationStatus;

  /// DER-encoded certificate chain in leaf-first order.
  final List<Uint8List> certificateChain;

  /// Converts the metadata to the C2PA `signature_info` JSON shape.
  /// Encodes this reference using C2PA snake-case JSON keys.
  /// Encodes this reference using the canonical C2PA `alg` key.
  /// Encodes this assertion to a JSON-compatible map.
  /// Encodes this ingredient using C2PA snake-case JSON keys.
  /// Encodes this manifest using C2PA snake-case JSON keys.
  Map<String, Object?> toJson() => {
    'alg': algorithm,
    'issuer': ?issuer,
    'common_name': ?commonName,
    'cert_serial_number': serialNumber,
    'not_before': notBefore.toUtc().toIso8601String(),
    'not_after': notAfter.toUtc().toIso8601String(),
    'time': ?time?.toUtc().toIso8601String(),
    'revocation_status': ?revocationStatus,
  };

  @override
  bool operator ==(Object other) =>
      other is SignatureInfo &&
      algorithm == other.algorithm &&
      issuer == other.issuer &&
      commonName == other.commonName &&
      serialNumber == other.serialNumber &&
      notBefore == other.notBefore &&
      notAfter == other.notAfter &&
      time == other.time &&
      revocationStatus == other.revocationStatus &&
      deepEquals(certificateChain, other.certificateChain);

  @override
  int get hashCode => Object.hash(
    algorithm,
    issuer,
    commonName,
    serialNumber,
    notBefore,
    notAfter,
    time,
    revocationStatus,
    deepHash(certificateChain),
  );
}

/// A C2PA resource reference such as a thumbnail or ingredient resource.
///
/// Unknown JSON members are preserved in [extra] for round-tripping.
final class ResourceReference {
  /// Creates an immutable resource reference.
  ResourceReference({
    required this.identifier,
    required this.format,
    Iterable<String> dataTypes = const [],
    Map<String, Object?> extra = const {},
  }) : dataTypes = List<String>.unmodifiable(dataTypes),
       extra = freezeJsonMap(extra);

  /// Decodes a resource reference from C2PA JSON.
  ///
  /// Throws a [TypeError] if required fields are absent or have wrong types.
  factory ResourceReference.fromJson(Map<String, Object?> json) =>
      ResourceReference(
        identifier: json['identifier'] as String,
        format: json['format'] as String,
        dataTypes: switch (json['data_types'] ?? json['dataTypes']) {
          final List<Object?> value => value.cast<String>(),
          _ => const [],
        },
        extra: unknownFields(json, const {
          'identifier',
          'format',
          'data_types',
          'dataTypes',
        }),
      );

  /// JUMBF or external identifier for the referenced resource.
  final String identifier;

  /// MIME type describing the referenced resource bytes.
  final String format;

  /// Optional semantic data type URIs associated with the resource.
  final List<String> dataTypes;

  /// Unrecognized JSON members preserved without mutation.
  final Map<String, Object?> extra;

  /// Encodes this reference using C2PA snake-case JSON keys.
  Map<String, Object?> toJson() => {
    ...extra,
    'identifier': identifier,
    'format': format,
    if (dataTypes.isNotEmpty) 'data_types': dataTypes,
  };

  @override
  bool operator ==(Object other) =>
      other is ResourceReference &&
      identifier == other.identifier &&
      format == other.format &&
      deepEquals(dataTypes, other.dataTypes) &&
      deepEquals(extra, other.extra);

  @override
  int get hashCode =>
      Object.hash(identifier, format, deepHash(dataTypes), deepHash(extra));
}

/// A URI paired with the digest expected for its target bytes.
///
/// The digest is stored as the JSON value already carried by the manifest, not
/// recalculated by this value object.
final class HashedUri {
  /// Creates an immutable hashed URI.
  HashedUri({
    required this.url,
    required this.hash,
    this.algorithm,
    Map<String, Object?> extra = const {},
  }) : extra = freezeJsonMap(extra);

  /// Decodes a hashed URI from either `alg` or legacy `algorithm` JSON.
  ///
  /// Throws a [TypeError] if required fields are absent or have wrong types.
  factory HashedUri.fromJson(Map<String, Object?> json) => HashedUri(
    url: json['url'] as String,
    hash: json['hash'] as String,
    algorithm: (json['alg'] ?? json['algorithm']) as String?,
    extra: unknownFields(json, const {'url', 'hash', 'alg', 'algorithm'}),
  );

  /// Referenced URI, often a `self#jumbf=` URI inside the manifest store.
  final String url;

  /// Digest value as serialized by the manifest JSON.
  final String hash;

  /// Hash algorithm name, or `null` when the claim default applies.
  final String? algorithm;

  /// Unrecognized JSON members preserved without mutation.
  final Map<String, Object?> extra;

  /// Encodes this reference using the canonical C2PA `alg` key.
  Map<String, Object?> toJson() => {
    ...extra,
    'url': url,
    'hash': hash,
    'alg': ?algorithm,
  };

  @override
  bool operator ==(Object other) =>
      other is HashedUri &&
      url == other.url &&
      hash == other.hash &&
      algorithm == other.algorithm &&
      deepEquals(extra, other.extra);

  @override
  int get hashCode => Object.hash(url, hash, algorithm, deepHash(extra));
}

/// A decoded manifest assertion with arbitrary JSON-compatible data.
///
/// The assertion payload is frozen recursively so callers cannot mutate the
/// parsed manifest graph.
final class ManifestAssertion {
  /// Creates an immutable assertion value.
  ManifestAssertion({
    required this.label,
    required Object? data,
    this.instance = 0,
    Map<String, Object?> extra = const {},
  }) : data = freezeJson(data),
       extra = freezeJsonMap(extra);

  /// Decodes a generic assertion object from JSON.
  ///
  /// Missing `instance` values default to `0`, matching C2PA label suffix
  /// semantics for the first assertion instance.
  factory ManifestAssertion.fromJson(Map<String, Object?> json) =>
      ManifestAssertion(
        label: json['label'] as String,
        data: json['data'],
        instance: json['instance'] as int? ?? 0,
        extra: unknownFields(json, const {'label', 'data', 'instance'}),
      );

  /// Assertion label without the containing manifest path.
  final String label;

  /// Zero-based assertion instance number; `0` is omitted from JSON.
  final int instance;

  /// JSON-compatible assertion payload, or `null` for explicit null payloads.
  final Object? data;

  /// Unrecognized JSON members preserved without mutation.
  final Map<String, Object?> extra;

  /// Encodes this assertion to a JSON-compatible map.
  Map<String, Object?> toJson() => {
    ...extra,
    'label': label,
    if (instance != 0) 'instance': instance,
    'data': data,
  };

  @override
  bool operator ==(Object other) =>
      other is ManifestAssertion &&
      label == other.label &&
      instance == other.instance &&
      deepEquals(data, other.data) &&
      deepEquals(extra, other.extra);

  @override
  int get hashCode =>
      Object.hash(label, instance, deepHash(data), deepHash(extra));
}

/// An ingredient entry describing source provenance for a manifest.
///
/// Optional manifest identifiers are `null` when the producer did not provide
/// that link in the ingredient assertion.
final class Ingredient {
  /// Creates an immutable ingredient summary.
  Ingredient({
    required this.title,
    required this.relationship,
    this.format,
    this.instanceId,
    this.documentId,
    this.activeManifest,
    this.thumbnail,
    this.validationResults,
    Map<String, Object?> extra = const {},
  }) : extra = freezeJsonMap(extra);

  /// Decodes an ingredient summary from C2PA JSON.
  ///
  /// Unknown fields are retained in [extra] and missing relationships default
  /// to the `componentOf` [Relationship].
  factory Ingredient.fromJson(Map<String, Object?> json) {
    final thumbnail = switch (json['thumbnail']) {
      final Map<String, Object?> value => ResourceReference.fromJson(value),
      _ => null,
    };
    final validationResults = switch (json['validation_results'] ??
        json['validationResults']) {
      final Map<String, Object?> value => ValidationResults.fromJson(value),
      _ => null,
    };
    return Ingredient(
      title: json['title'] as String,
      relationship:
          enumByName(Relationship.values, json['relationship']) ??
          Relationship.componentOf,
      format: json['format'] as String?,
      instanceId: (json['instance_id'] ?? json['instanceId']) as String?,
      documentId: (json['document_id'] ?? json['documentId']) as String?,
      activeManifest:
          (json['active_manifest'] ?? json['activeManifest']) as String?,
      thumbnail: thumbnail,
      validationResults: validationResults,
      extra: unknownFields(json, const {
        'title',
        'relationship',
        'format',
        'instance_id',
        'instanceId',
        'document_id',
        'documentId',
        'active_manifest',
        'activeManifest',
        'thumbnail',
        'validation_results',
        'validationResults',
      }),
    );
  }

  /// Human-readable ingredient title from the manifest.
  final String title;

  /// C2PA relationship between this ingredient and the active asset.
  final Relationship relationship;

  /// MIME type for the ingredient asset, or `null` if unspecified.
  /// MIME type for the described asset, or `null` if unspecified.
  final String? format;

  /// Ingredient instance identifier, or `null` if the assertion omits it.
  /// Claim instance identifier, or `null` if the claim omits it.
  final String? instanceId;

  /// Stable document identifier, or `null` if the assertion omits it.
  final String? documentId;

  /// URI of the ingredient's active manifest, or `null` if unknown.
  final String? activeManifest;

  /// Thumbnail resource reference, or `null` when no thumbnail is declared.
  final ResourceReference? thumbnail;

  /// Validation status attested by the ingredient, or `null` if absent.
  final ValidationResults? validationResults;

  /// Unrecognized JSON members preserved without mutation.
  final Map<String, Object?> extra;

  /// Encodes this ingredient using C2PA snake-case JSON keys.
  Map<String, Object?> toJson() => {
    ...extra,
    'title': title,
    'relationship': relationship.name,
    'format': ?format,
    'instance_id': ?instanceId,
    'document_id': ?documentId,
    'active_manifest': ?activeManifest,
    'thumbnail': ?thumbnail?.toJson(),
    'validation_results': ?validationResults?.toJson(),
  };

  @override
  bool operator ==(Object other) =>
      other is Ingredient &&
      title == other.title &&
      relationship == other.relationship &&
      format == other.format &&
      instanceId == other.instanceId &&
      documentId == other.documentId &&
      activeManifest == other.activeManifest &&
      thumbnail == other.thumbnail &&
      validationResults == other.validationResults &&
      deepEquals(extra, other.extra);

  @override
  int get hashCode => Object.hash(
    title,
    relationship,
    format,
    instanceId,
    documentId,
    activeManifest,
    thumbnail,
    validationResults,
    deepHash(extra),
  );
}

/// A high-level JSON view of one C2PA manifest.
///
/// Lists and unknown JSON fields are immutable and safe to retain after
/// parsing.
final class Manifest {
  /// Creates an immutable manifest summary.
  Manifest({
    required this.label,
    this.title,
    this.format,
    this.instanceId,
    this.claimGenerator,
    this.claimVersion,
    Iterable<ManifestAssertion> assertions = const [],
    Iterable<Ingredient> ingredients = const [],
    this.thumbnail,
    Map<String, Object?> extra = const {},
  }) : assertions = List<ManifestAssertion>.unmodifiable(assertions),
       ingredients = List<Ingredient>.unmodifiable(ingredients),
       extra = freezeJsonMap(extra);

  /// Decodes a manifest summary from C2PA JSON.
  ///
  /// Throws a [TypeError] if assertion or ingredient arrays contain values
  /// that are not JSON objects.
  factory Manifest.fromJson(Map<String, Object?> json) {
    final thumbnail = switch (json['thumbnail']) {
      final Map<String, Object?> value => ResourceReference.fromJson(value),
      _ => null,
    };
    return Manifest(
      label: json['label'] as String,
      title: json['title'] as String?,
      format: json['format'] as String?,
      instanceId: (json['instance_id'] ?? json['instanceId']) as String?,
      claimGenerator:
          (json['claim_generator'] ?? json['claimGenerator']) as String?,
      claimVersion: ClaimVersion.fromJson(
        json['claim_version'] ?? json['claimVersion'],
      ),
      assertions: (json['assertions'] as List<Object?>? ?? const [])
          .cast<Map<String, Object?>>()
          .map(ManifestAssertion.fromJson),
      ingredients: (json['ingredients'] as List<Object?>? ?? const [])
          .cast<Map<String, Object?>>()
          .map(Ingredient.fromJson),
      thumbnail: thumbnail,
      extra: unknownFields(json, const {
        'label',
        'title',
        'format',
        'instance_id',
        'instanceId',
        'claim_generator',
        'claimGenerator',
        'claim_version',
        'claimVersion',
        'assertions',
        'ingredients',
        'thumbnail',
      }),
    );
  }

  /// Manifest label used in `self#jumbf=/c2pa/...` references.
  final String label;

  /// Human-readable manifest title, or `null` if the claim omits it.
  final String? title;

  /// MIME type for the described asset, or `null` if unspecified.
  final String? format;

  /// Claim instance identifier, or `null` if the claim omits it.
  final String? instanceId;

  /// Name of the claim generator, or `null` if the claim omits it.
  final String? claimGenerator;

  /// C2PA claim version, or `null` if the JSON value is absent or unknown.
  final ClaimVersion? claimVersion;

  /// Assertion summaries declared by this manifest.
  final List<ManifestAssertion> assertions;

  /// Ingredients declared by this manifest.
  final List<Ingredient> ingredients;

  /// Manifest thumbnail reference, or `null` when none is declared.
  final ResourceReference? thumbnail;

  /// Unrecognized JSON members preserved without mutation.
  final Map<String, Object?> extra;

  /// Assertions grouped by label with immutable value lists.
  Map<String, List<ManifestAssertion>> get assertionsByLabel {
    final grouped = <String, List<ManifestAssertion>>{};
    for (final assertion in assertions) {
      grouped.putIfAbsent(assertion.label, () => []).add(assertion);
    }
    return UnmodifiableMapView(
      grouped.map(
        (label, values) =>
            MapEntry(label, List<ManifestAssertion>.unmodifiable(values)),
      ),
    );
  }

  /// Encodes this manifest using C2PA snake-case JSON keys.
  Map<String, Object?> toJson() => {
    ...extra,
    'label': label,
    'title': ?title,
    'format': ?format,
    'instance_id': ?instanceId,
    'claim_generator': ?claimGenerator,
    'claim_version': ?claimVersion?.number,
    'assertions': assertions
        .map((assertion) => assertion.toJson())
        .toList(growable: false),
    'ingredients': ingredients
        .map((ingredient) => ingredient.toJson())
        .toList(growable: false),
    'thumbnail': ?thumbnail?.toJson(),
  };

  @override
  bool operator ==(Object other) =>
      other is Manifest &&
      label == other.label &&
      title == other.title &&
      format == other.format &&
      instanceId == other.instanceId &&
      claimGenerator == other.claimGenerator &&
      claimVersion == other.claimVersion &&
      deepEquals(assertions, other.assertions) &&
      deepEquals(ingredients, other.ingredients) &&
      thumbnail == other.thumbnail &&
      deepEquals(extra, other.extra);

  @override
  int get hashCode => Object.hash(
    label,
    title,
    format,
    instanceId,
    claimGenerator,
    claimVersion,
    deepHash(assertions),
    deepHash(ingredients),
    thumbnail,
    deepHash(extra),
  );
}
