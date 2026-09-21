import 'dart:typed_data';

import 'intent.dart';
import 'json_utils.dart';

final class ClaimHashedUri {
  ClaimHashedUri({
    required this.url,
    required Uint8List hash,
    this.algorithm,
    Map<String, Object?> extra = const {},
  }) : hash = Uint8List.fromList(hash).asUnmodifiableView(),
       extra = freezeJsonMap(extra);

  factory ClaimHashedUri.fromCbor(Object? value) {
    final map = _stringMap(value, 'hashed URI');
    final url = map['url'];
    final hash = cborBytes(map['hash']);
    final algorithm = map['alg'];
    if (url is! String || url.isEmpty) {
      throw const FormatException('A hashed URI requires a non-empty url');
    }
    if (hash == null || hash.isEmpty) {
      throw const FormatException('A hashed URI requires a byte-string hash');
    }
    if (algorithm != null && algorithm is! String) {
      throw const FormatException('A hashed URI alg must be a string');
    }
    return ClaimHashedUri(
      url: url,
      hash: hash,
      algorithm: algorithm as String?,
      extra: unknownFields(map, const {'url', 'alg', 'hash'}),
    );
  }

  final String url;
  final String? algorithm;
  final Uint8List hash;
  final Map<String, Object?> extra;

  Map<String, Object?> toCborMap() => {
    ...extra,
    'url': url,
    'alg': ?algorithm,
    'hash': Uint8List.fromList(hash),
  };

  @override
  bool operator ==(Object other) =>
      other is ClaimHashedUri &&
      url == other.url &&
      algorithm == other.algorithm &&
      deepEquals(hash, other.hash) &&
      deepEquals(extra, other.extra);

  @override
  int get hashCode =>
      Object.hash(url, algorithm, deepHash(hash), deepHash(extra));
}

final class ClaimGeneratorInfo {
  ClaimGeneratorInfo({
    required this.name,
    this.version,
    this.icon,
    this.operatingSystem,
    Map<String, Object?> extra = const {},
  }) : extra = freezeJsonMap(extra);

  factory ClaimGeneratorInfo.fromCbor(Object? value) {
    final map = _stringMap(value, 'claim generator info');
    final name = map['name'];
    if (name is! String || name.isEmpty) {
      throw const FormatException(
        'claim_generator_info requires a non-empty name',
      );
    }
    final version = map['version'];
    final operatingSystem =
        map['operating_system'] ??
        map['schema.org.SoftwareApplication.operatingSystem'];
    if (version != null && version is! String) {
      throw const FormatException(
        'claim_generator_info version must be a string',
      );
    }
    if (operatingSystem != null && operatingSystem is! String) {
      throw const FormatException(
        'claim_generator_info operating system must be a string',
      );
    }
    return ClaimGeneratorInfo(
      name: name,
      version: version as String?,
      icon: freezeJson(map['icon']),
      operatingSystem: operatingSystem as String?,
      extra: unknownFields(map, const {
        'name',
        'version',
        'icon',
        'operating_system',
        'schema.org.SoftwareApplication.operatingSystem',
      }),
    );
  }

  final String name;
  final String? version;
  final Object? icon;
  final String? operatingSystem;
  final Map<String, Object?> extra;

  Map<String, Object?> toCborMap() => {
    ...extra,
    'name': name,
    'version': ?version,
    'icon': ?icon,
    'operating_system': ?operatingSystem,
  };

  @override
  bool operator ==(Object other) =>
      other is ClaimGeneratorInfo &&
      name == other.name &&
      version == other.version &&
      deepEquals(icon, other.icon) &&
      operatingSystem == other.operatingSystem &&
      deepEquals(extra, other.extra);

  @override
  int get hashCode => Object.hash(
    name,
    version,
    deepHash(icon),
    operatingSystem,
    deepHash(extra),
  );
}

sealed class Claim {
  Claim({
    required this.version,
    required this.label,
    required this.instanceId,
    required this.signatureUri,
    required Uint8List rawBytes,
    required Iterable<ClaimGeneratorInfo> claimGeneratorInfo,
    required Iterable<ClaimHashedUri> assertions,
    required Iterable<ClaimHashedUri> createdAssertions,
    required Iterable<ClaimHashedUri> gatheredAssertions,
    required Iterable<String> redactions,
    required Map<String, Object?> unknownFields,
    this.claimGenerator,
    this.format,
    this.title,
    this.algorithm,
    this.softAlgorithm,
  }) : rawBytes = Uint8List.fromList(rawBytes).asUnmodifiableView(),
       claimGeneratorInfo = List<ClaimGeneratorInfo>.unmodifiable(
         claimGeneratorInfo,
       ),
       assertions = List<ClaimHashedUri>.unmodifiable(assertions),
       createdAssertions = List<ClaimHashedUri>.unmodifiable(createdAssertions),
       gatheredAssertions = List<ClaimHashedUri>.unmodifiable(
         gatheredAssertions,
       ),
       redactions = List<String>.unmodifiable(redactions),
       unknownFields = freezeJsonMap(unknownFields);

  final ClaimVersion version;
  final String label;
  final String instanceId;
  final String signatureUri;
  final String? claimGenerator;
  final List<ClaimGeneratorInfo> claimGeneratorInfo;
  final String? format;
  final String? title;
  final List<ClaimHashedUri> assertions;
  final List<ClaimHashedUri> createdAssertions;
  final List<ClaimHashedUri> gatheredAssertions;
  final List<String> redactions;
  final String? algorithm;
  final String? softAlgorithm;
  final Map<String, Object?> unknownFields;
  final Uint8List rawBytes;

  Map<String, Object?> toCborMap();

  @override
  bool operator ==(Object other) =>
      other is Claim &&
      runtimeType == other.runtimeType &&
      version == other.version &&
      label == other.label &&
      instanceId == other.instanceId &&
      signatureUri == other.signatureUri &&
      claimGenerator == other.claimGenerator &&
      deepEquals(claimGeneratorInfo, other.claimGeneratorInfo) &&
      format == other.format &&
      title == other.title &&
      deepEquals(assertions, other.assertions) &&
      deepEquals(createdAssertions, other.createdAssertions) &&
      deepEquals(gatheredAssertions, other.gatheredAssertions) &&
      deepEquals(redactions, other.redactions) &&
      algorithm == other.algorithm &&
      softAlgorithm == other.softAlgorithm &&
      deepEquals(unknownFields, other.unknownFields) &&
      deepEquals(rawBytes, other.rawBytes);

  @override
  int get hashCode => Object.hashAll([
    runtimeType,
    version,
    label,
    instanceId,
    signatureUri,
    claimGenerator,
    deepHash(claimGeneratorInfo),
    format,
    title,
    deepHash(assertions),
    deepHash(createdAssertions),
    deepHash(gatheredAssertions),
    deepHash(redactions),
    algorithm,
    softAlgorithm,
    deepHash(unknownFields),
    deepHash(rawBytes),
  ]);
}

final class ClaimV1 extends Claim {
  ClaimV1({
    required super.label,
    required super.instanceId,
    required super.signatureUri,
    required super.claimGenerator,
    required super.claimGeneratorInfo,
    required super.format,
    required super.assertions,
    required super.rawBytes,
    super.title,
    super.redactions = const [],
    super.algorithm,
    super.softAlgorithm,
    super.unknownFields = const {},
  }) : super(
         version: ClaimVersion.v1,
         createdAssertions: const [],
         gatheredAssertions: const [],
       );

  @override
  Map<String, Object?> toCborMap() => {
    ...this.unknownFields,
    'claim_generator': claimGenerator,
    'claim_generator_info': claimGeneratorInfo
        .map((info) => info.toCborMap())
        .toList(growable: false),
    'signature': signatureUri,
    'assertions': assertions
        .map((reference) => reference.toCborMap())
        .toList(growable: false),
    'dc:format': format,
    'instanceID': instanceId,
    'dc:title': ?title,
    if (redactions.isNotEmpty) 'redacted_assertions': redactions,
    'alg': ?algorithm,
    'alg_soft': ?softAlgorithm,
  };
}

final class ClaimV2 extends Claim {
  ClaimV2({
    required super.label,
    required super.instanceId,
    required super.signatureUri,
    required ClaimGeneratorInfo claimGeneratorInfo,
    required super.createdAssertions,
    required super.rawBytes,
    super.gatheredAssertions = const [],
    super.title,
    super.redactions = const [],
    super.algorithm,
    super.softAlgorithm,
    super.unknownFields = const {},
  }) : super(
         version: ClaimVersion.v2,
         claimGeneratorInfo: [claimGeneratorInfo],
         assertions: [...createdAssertions, ...gatheredAssertions],
       );

  ClaimGeneratorInfo get generatorInfo => claimGeneratorInfo.single;

  @override
  Map<String, Object?> toCborMap() => {
    ...this.unknownFields,
    'instanceID': instanceId,
    'claim_generator_info': generatorInfo.toCborMap(),
    'signature': signatureUri,
    'created_assertions': createdAssertions
        .map((reference) => reference.toCborMap())
        .toList(growable: false),
    if (gatheredAssertions.isNotEmpty)
      'gathered_assertions': gatheredAssertions
          .map((reference) => reference.toCborMap())
          .toList(growable: false),
    'dc:title': ?title,
    if (redactions.isNotEmpty) 'redacted_assertions': redactions,
    'alg': ?algorithm,
    'alg_soft': ?softAlgorithm,
  };
}

Claim decodeClaim({
  required String label,
  required Uint8List bytes,
  required int maxNestingDepth,
  required Object? Function(List<int>, {int maxNestingDepth}) decoder,
}) {
  final decoded = decoder(bytes, maxNestingDepth: maxNestingDepth);
  final map = _stringMap(decoded, 'claim');
  final hasV1 = map['assertions'] is List;
  final hasV2 = map['created_assertions'] is List;
  if (hasV1 == hasV2) {
    throw const FormatException(
      'A claim must contain exactly one version-specific assertion list',
    );
  }

  final instanceId = _requiredString(map, 'instanceID');
  final signature = _requiredString(map, 'signature');
  final title = _optionalString(map, 'dc:title');
  final algorithm = _optionalString(map, 'alg');
  final softAlgorithm = _optionalString(map, 'alg_soft');
  final redactions = _stringList(map['redacted_assertions'], 'redactions');

  if (hasV1) {
    final generator = _requiredString(map, 'claim_generator');
    final format = _requiredString(map, 'dc:format');
    final generatorInfo = _generatorInfoList(map['claim_generator_info']);
    final assertions = _hashedUriList(map['assertions'], 'assertions');
    return ClaimV1(
      label: label,
      instanceId: instanceId,
      signatureUri: signature,
      claimGenerator: generator,
      claimGeneratorInfo: generatorInfo,
      format: format,
      assertions: assertions,
      rawBytes: bytes,
      title: title,
      redactions: redactions,
      algorithm: algorithm,
      softAlgorithm: softAlgorithm,
      unknownFields: unknownFields(map, _v1Fields),
    );
  }

  final generatorInfo = ClaimGeneratorInfo.fromCbor(
    map['claim_generator_info'],
  );
  final created = _hashedUriList(
    map['created_assertions'],
    'created_assertions',
  );
  final gathered = _hashedUriList(
    map['gathered_assertions'],
    'gathered_assertions',
  );
  return ClaimV2(
    label: label,
    instanceId: instanceId,
    signatureUri: signature,
    claimGeneratorInfo: generatorInfo,
    createdAssertions: created,
    gatheredAssertions: gathered,
    rawBytes: bytes,
    title: title,
    redactions: redactions,
    algorithm: algorithm,
    softAlgorithm: softAlgorithm,
    unknownFields: unknownFields(map, _v2Fields),
  );
}

const _v1Fields = {
  'claim_generator',
  'claim_generator_info',
  'signature',
  'assertions',
  'dc:format',
  'instanceID',
  'dc:title',
  'redacted_assertions',
  'alg',
  'alg_soft',
};

const _v2Fields = {
  'instanceID',
  'claim_generator_info',
  'signature',
  'created_assertions',
  'gathered_assertions',
  'dc:title',
  'redacted_assertions',
  'alg',
  'alg_soft',
};

Map<String, Object?> _stringMap(Object? value, String name) {
  if (value is! Map) throw FormatException('$name must be a map');
  final result = <String, Object?>{};
  for (final entry in value.entries) {
    if (entry.key is! String) {
      throw FormatException('$name keys must be strings');
    }
    result[entry.key as String] = _freezeCbor(entry.value);
  }
  return Map<String, Object?>.unmodifiable(result);
}

Object? _freezeCbor(Object? value) {
  if (value is Uint8List) {
    return Uint8List.fromList(value).asUnmodifiableView();
  }
  if (value is List) {
    return List<Object?>.unmodifiable(value.map(_freezeCbor));
  }
  if (value is Map) {
    return Map<Object?, Object?>.unmodifiable(
      value.map(
        (key, nested) => MapEntry(_freezeCbor(key), _freezeCbor(nested)),
      ),
    );
  }
  return value;
}

String _requiredString(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is! String || value.isEmpty) {
    throw FormatException('$key is missing or invalid');
  }
  return value;
}

String? _optionalString(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value == null) return null;
  if (value is! String) throw FormatException('$key must be a string');
  return value;
}

List<String> _stringList(Object? value, String name) {
  if (value == null) return const [];
  if (value is! List || value.any((item) => item is! String)) {
    throw FormatException('$name must be a string array');
  }
  return List<String>.unmodifiable(value.cast<String>());
}

List<ClaimGeneratorInfo> _generatorInfoList(Object? value) {
  if (value == null) return const [];
  if (value is! List) {
    throw const FormatException('claim_generator_info must be an array');
  }
  return List<ClaimGeneratorInfo>.unmodifiable(
    value.map(ClaimGeneratorInfo.fromCbor),
  );
}

List<ClaimHashedUri> _hashedUriList(Object? value, String name) {
  if (value == null) return const [];
  if (value is! List) throw FormatException('$name must be an array');
  return List<ClaimHashedUri>.unmodifiable(value.map(ClaimHashedUri.fromCbor));
}
