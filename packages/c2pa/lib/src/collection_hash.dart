import 'dart:collection';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import 'json_utils.dart';

final class CollectionDataType {
  CollectionDataType({
    required this.type,
    this.version,
    Map<String, Object?> extra = const {},
  }) : extra = freezeJsonMap(extra) {
    if (type.trim().isEmpty || (version != null && version!.trim().isEmpty)) {
      throw const FormatException('Invalid collection data type');
    }
  }

  factory CollectionDataType.fromCbor(Object? value) {
    if (value is! Map || value.keys.any((key) => key is! String)) {
      throw const FormatException('Collection data type must be a map');
    }
    final map = value.cast<String, Object?>();
    if (map['type'] is! String ||
        (map['version'] != null && map['version'] is! String)) {
      throw const FormatException('Malformed collection data type');
    }
    return CollectionDataType(
      type: map['type'] as String,
      version: map['version'] as String?,
      extra: unknownFields(map, const {'type', 'version'}),
    );
  }

  final String type;
  final String? version;
  final Map<String, Object?> extra;

  Map<String, Object?> toCborMap() => {
    ...extra,
    'type': type,
    if (version != null) 'version': version,
  };

  @override
  bool operator ==(Object other) =>
      other is CollectionDataType &&
      type == other.type &&
      version == other.version &&
      deepEquals(extra, other.extra);

  @override
  int get hashCode => Object.hash(type, version, deepHash(extra));
}

final class CollectionHashEntry {
  CollectionHashEntry({
    List<int>? hash,
    this.size,
    this.format,
    Iterable<CollectionDataType>? dataTypes,
  }) : hash = hash == null
           ? null
           : Uint8List.fromList(hash).asUnmodifiableView(),
       dataTypes = dataTypes == null
           ? null
           : List<CollectionDataType>.unmodifiable(dataTypes) {
    if (size != null && size! < 0) {
      throw const FormatException('Collection entry size cannot be negative');
    }
    if (format != null && format!.trim().isEmpty) {
      throw const FormatException('Collection entry format cannot be empty');
    }
    if (this.dataTypes?.isEmpty ?? false) {
      throw const FormatException('Collection data_types cannot be empty');
    }
  }

  factory CollectionHashEntry.fromCbor(Object? value) {
    final map = _strictMap(value, const {
      'hash',
      'size',
      'dc:format',
      'data_types',
    }, 'URI entry');
    if ((map['hash'] != null && map['hash'] is! Uint8List) ||
        (map['size'] != null && map['size'] is! int) ||
        (map['dc:format'] != null && map['dc:format'] is! String) ||
        (map['data_types'] != null && map['data_types'] is! List)) {
      throw const FormatException('Malformed collection URI entry');
    }
    return CollectionHashEntry(
      hash: map['hash'] as Uint8List?,
      size: map['size'] as int?,
      format: map['dc:format'] as String?,
      dataTypes: (map['data_types'] as List<Object?>?)?.map(
        CollectionDataType.fromCbor,
      ),
    );
  }

  final Uint8List? hash;
  final int? size;
  final String? format;
  final List<CollectionDataType>? dataTypes;

  Map<String, Object?> toCborMap() => {
    if (hash != null) 'hash': hash,
    if (size != null) 'size': size,
    if (format != null) 'dc:format': format,
    if (dataTypes != null)
      'data_types': dataTypes!
          .map((item) => item.toCborMap())
          .toList(growable: false),
  };

  @override
  bool operator ==(Object other) =>
      other is CollectionHashEntry &&
      deepEquals(hash, other.hash) &&
      size == other.size &&
      format == other.format &&
      deepEquals(dataTypes, other.dataTypes);

  @override
  int get hashCode =>
      Object.hash(deepHash(hash), size, format, deepHash(dataTypes));
}

final class CollectionHashAssertion {
  CollectionHashAssertion({
    required Map<String, CollectionHashEntry> uris,
    required this.algorithm,
    List<int>? zipCentralDirectoryHash,
  }) : uris = UnmodifiableMapView(_normalizeEntries(uris)),
       zipCentralDirectoryHash = zipCentralDirectoryHash == null
           ? null
           : Uint8List.fromList(zipCentralDirectoryHash).asUnmodifiableView() {
    if (algorithm.trim().isEmpty) {
      throw const FormatException('Collection hash requires an algorithm');
    }
  }

  factory CollectionHashAssertion.fromCbor(Object? value) {
    final map = _strictMap(value, const {
      'uris',
      'alg',
      'zip_central_directory_hash',
    }, 'assertion');
    if (map['uris'] is! Map ||
        map['alg'] is! String ||
        (map['zip_central_directory_hash'] != null &&
            map['zip_central_directory_hash'] is! Uint8List)) {
      throw const FormatException('Malformed collection hash assertion');
    }
    final rawUris = map['uris'] as Map;
    if (rawUris.keys.any((key) => key is! String)) {
      throw const FormatException('Collection URI keys must be strings');
    }
    return CollectionHashAssertion(
      uris: {
        for (final entry in rawUris.entries)
          entry.key as String: CollectionHashEntry.fromCbor(entry.value),
      },
      algorithm: map['alg'] as String,
      zipCentralDirectoryHash: map['zip_central_directory_hash'] as Uint8List?,
    );
  }

  static const label = 'c2pa.hash.collection.data';
  static const version = 1;

  final Map<String, CollectionHashEntry> uris;
  final String algorithm;
  final Uint8List? zipCentralDirectoryHash;

  Map<String, Object?> toCborMap() => {
    'uris': {
      for (final entry in uris.entries) entry.key: entry.value.toCborMap(),
    },
    'alg': algorithm,
    if (zipCentralDirectoryHash != null)
      'zip_central_directory_hash': zipCentralDirectoryHash,
  };

  @override
  bool operator ==(Object other) =>
      other is CollectionHashAssertion &&
      deepEquals(uris, other.uris) &&
      algorithm == other.algorithm &&
      deepEquals(zipCentralDirectoryHash, other.zipCentralDirectoryHash);

  @override
  int get hashCode =>
      Object.hash(deepHash(uris), algorithm, deepHash(zipCentralDirectoryHash));
}

final class C2paCollectionItem {
  C2paCollectionItem({
    required String uri,
    required this.source,
    this.format,
    Iterable<CollectionDataType>? dataTypes,
  }) : uri = normalizeCollectionUri(uri),
       dataTypes = dataTypes == null
           ? null
           : List<CollectionDataType>.unmodifiable(dataTypes);

  final String uri;
  final RandomAccessByteSource source;
  final String? format;
  final List<CollectionDataType>? dataTypes;
}

abstract interface class C2paCollectionSource {
  Future<Iterable<C2paCollectionItem>> entries();
}

String normalizeCollectionUri(String value) {
  if (value.isEmpty || value.contains('\u0000')) {
    throw const FormatException('Collection URI must not be empty');
  }
  final normalizedSlashes = value.replaceAll('\\', '/');
  final parsed = Uri.tryParse(normalizedSlashes);
  if (parsed == null ||
      parsed.hasScheme ||
      parsed.hasAuthority ||
      parsed.hasQuery ||
      parsed.hasFragment ||
      normalizedSlashes.startsWith('/') ||
      RegExp(r'^[A-Za-z]:').hasMatch(normalizedSlashes)) {
    throw FormatException('Collection URI must be relative: $value');
  }
  final rawSegments = normalizedSlashes.split('/');
  if (rawSegments.any((segment) => segment.isEmpty)) {
    throw FormatException('Collection URI has an empty component: $value');
  }
  final segments = <String>[];
  for (final raw in rawSegments) {
    late String decoded;
    try {
      decoded = Uri.decodeComponent(raw);
    } on FormatException {
      throw FormatException('Collection URI has invalid encoding: $value');
    }
    if (decoded.isEmpty ||
        decoded == '.' ||
        decoded == '..' ||
        decoded.contains('/') ||
        decoded.contains('\\')) {
      throw FormatException('Collection URI is unsafe: $value');
    }
    segments.add(decoded);
  }
  return segments.join('/');
}

Map<String, CollectionHashEntry> _normalizeEntries(
  Map<String, CollectionHashEntry> entries,
) {
  final normalized = <String, CollectionHashEntry>{};
  for (final entry in entries.entries) {
    final uri = normalizeCollectionUri(entry.key);
    if (normalized.containsKey(uri)) {
      throw FormatException('Duplicate normalized collection URI: $uri');
    }
    normalized[uri] = entry.value;
  }
  final sorted = normalized.keys.toList()..sort();
  return {for (final uri in sorted) uri: normalized[uri]!};
}

Map<String, Object?> _strictMap(
  Object? value,
  Set<String> allowed,
  String name,
) {
  if (value is! Map || value.keys.any((key) => key is! String)) {
    throw FormatException('Collection hash $name must be a string-keyed map');
  }
  final map = value.cast<String, Object?>();
  if (map.keys.any((key) => !allowed.contains(key))) {
    throw FormatException('Collection hash $name contains unknown fields');
  }
  return map;
}
