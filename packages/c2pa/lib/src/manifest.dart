import 'dart:collection';
import 'dart:typed_data';

import 'intent.dart';
import 'json_utils.dart';
import 'validation.dart';

final class SignatureInfo {
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

  final String algorithm;
  final String? issuer;
  final String? commonName;
  final String serialNumber;
  final DateTime notBefore;
  final DateTime notAfter;
  final DateTime? time;
  final bool? revocationStatus;
  final List<Uint8List> certificateChain;

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

final class ResourceReference {
  ResourceReference({
    required this.identifier,
    required this.format,
    Iterable<String> dataTypes = const [],
    Map<String, Object?> extra = const {},
  }) : dataTypes = List<String>.unmodifiable(dataTypes),
       extra = freezeJsonMap(extra);

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

  final String identifier;
  final String format;
  final List<String> dataTypes;
  final Map<String, Object?> extra;

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

final class HashedUri {
  HashedUri({
    required this.url,
    required this.hash,
    this.algorithm,
    Map<String, Object?> extra = const {},
  }) : extra = freezeJsonMap(extra);

  factory HashedUri.fromJson(Map<String, Object?> json) => HashedUri(
    url: json['url'] as String,
    hash: json['hash'] as String,
    algorithm: (json['alg'] ?? json['algorithm']) as String?,
    extra: unknownFields(json, const {'url', 'hash', 'alg', 'algorithm'}),
  );

  final String url;
  final String hash;
  final String? algorithm;
  final Map<String, Object?> extra;

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

final class ManifestAssertion {
  ManifestAssertion({
    required this.label,
    required Object? data,
    this.instance = 0,
    Map<String, Object?> extra = const {},
  }) : data = freezeJson(data),
       extra = freezeJsonMap(extra);

  factory ManifestAssertion.fromJson(Map<String, Object?> json) =>
      ManifestAssertion(
        label: json['label'] as String,
        data: json['data'],
        instance: json['instance'] as int? ?? 0,
        extra: unknownFields(json, const {'label', 'data', 'instance'}),
      );

  final String label;
  final int instance;
  final Object? data;
  final Map<String, Object?> extra;

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

final class Ingredient {
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

  final String title;
  final Relationship relationship;
  final String? format;
  final String? instanceId;
  final String? documentId;
  final String? activeManifest;
  final ResourceReference? thumbnail;
  final ValidationResults? validationResults;
  final Map<String, Object?> extra;

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

final class Manifest {
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

  final String label;
  final String? title;
  final String? format;
  final String? instanceId;
  final String? claimGenerator;
  final ClaimVersion? claimVersion;
  final List<ManifestAssertion> assertions;
  final List<Ingredient> ingredients;
  final ResourceReference? thumbnail;
  final Map<String, Object?> extra;

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
