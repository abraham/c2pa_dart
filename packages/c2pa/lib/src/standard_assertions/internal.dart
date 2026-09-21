part of '../standard_assertions.dart';

void _validateRangePayload(
  C2paRegionRangeType type,
  Map<String, Object?>? time,
  Map<String, Object?>? frame,
  Map<String, Object?>? text,
  Map<String, Object?>? item,
) {
  if (type == C2paRegionRangeType.temporal && time != null) {
    final kind = time['type'];
    if (kind != null && kind != 'npt') {
      throw const FormatException('Only npt temporal ranges are supported');
    }
    for (final field in const ['start', 'end']) {
      if (time[field] != null && time[field] is! String) {
        throw FormatException('Temporal $field must be a string');
      }
    }
  }
  if (type == C2paRegionRangeType.frame && frame != null) {
    for (final field in const ['start', 'end']) {
      if (frame[field] != null &&
          (frame[field] is! int || (frame[field] as int) < 0)) {
        throw FormatException('Frame $field must be a non-negative integer');
      }
    }
  }
  if (type == C2paRegionRangeType.textual && text != null) {
    final selectors = text['selectors'];
    if (selectors is! List || selectors.isEmpty) {
      throw const FormatException('Textual ranges require selectors');
    }
  }
  if (type == C2paRegionRangeType.identified && item != null) {
    _requiredString(item, 'identifier');
    _requiredString(item, 'value');
  }
}

String _thumbnailLabel(C2paThumbnailKind kind, String mediaType) {
  final extension = switch (mediaType.toLowerCase()) {
    'image/jpeg' || 'image/jpg' => 'jpeg',
    'image/png' => 'png',
    'image/svg+xml' => 'svg',
    'image/gif' => 'gif',
    'image/webp' => 'webp',
    'image/tiff' => 'tiff',
    _ => throw FormatException('Unsupported thumbnail media type: $mediaType'),
  };
  return 'c2pa.thumbnail.${kind.name}.$extension';
}

String _legacyLabel(C2paLegacyAssertionKind kind) => switch (kind) {
  C2paLegacyAssertionKind.exif => 'stds.exif',
  C2paLegacyAssertionKind.creativeWork => 'stds.schema-org.CreativeWork',
  C2paLegacyAssertionKind.schemaOrg => 'schema.org',
};

const _metadataContexts = <String, String>{
  'xmp': 'http://ns.adobe.com/xap/1.0/',
  'xmpMM': 'http://ns.adobe.com/xap/1.0/mm/',
  'xmpTPg': 'http://ns.adobe.com/xap/1.0/t/pg/',
  'crs': 'http://ns.adobe.com/camera-raw-settings/1.0/',
  'pdf': 'http://ns.adobe.com/pdf/1.3/',
  'dc': 'http://purl.org/dc/elements/1.1/',
  'Iptc4xmpExt': 'http://iptc.org/std/Iptc4xmpExt/2008-02-29/',
  'exif': 'http://ns.adobe.com/exif/1.0/',
  'exifEX': 'http://cipa.jp/exif/1.0/',
  'photoshop': 'http://ns.adobe.com/photoshop/1.0/',
  'tiff': 'http://ns.adobe.com/tiff/1.0/',
  'xmpDM': 'http://ns.adobe.com/xmp/1.0/DynamicMedia/',
  'plus': 'http://ns.useplus.org/ldf/xmp/1.0/',
};

const _metadataContextAliases = <String, Set<String>>{
  'xmp': {},
  'xmpMM': {},
  'xmpTPg': {},
  'crs': {},
  'pdf': {},
  'dc': {},
  'Iptc4xmpExt': {},
  'exif': {},
  'exifEX': {'http://cipa.jp/exif/1.0/exifEX', 'http://cipa.jp/exif/2.32/'},
  'photoshop': {},
  'tiff': {},
  'xmpDM': {},
  'plus': {},
};

Map<String, Object?> _map(Object? value, String name) {
  if (value is! Map) throw FormatException('$name must be a map');
  final result = <String, Object?>{};
  for (final entry in value.entries) {
    if (entry.key is! String) {
      throw FormatException('$name keys must be strings');
    }
    result[entry.key! as String] = entry.value;
  }
  return result;
}

List<Object?> _requiredList(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is! List) throw FormatException('$key must be an array');
  return value.cast<Object?>();
}

List<Object?>? _optionalList(Object? value) {
  if (value == null) return null;
  if (value is! List) throw const FormatException('Expected an array');
  return value.cast<Object?>();
}

String _requiredString(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is! String || value.isEmpty) {
    throw FormatException('$key must be a non-empty string');
  }
  return value;
}

String? _optionalString(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value == null) return null;
  if (value is! String) throw FormatException('$key must be a string');
  return value;
}

int _requiredInt(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is! int) throw FormatException('$key must be an integer');
  return value;
}

num _requiredNum(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is! num || !value.isFinite) {
    throw FormatException('$key must be a finite number');
  }
  return value;
}

num? _optionalNum(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value == null) return null;
  if (value is! num || !value.isFinite) {
    throw FormatException('$key must be a finite number');
  }
  return value;
}

bool? _optionalBool(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value == null) return null;
  if (value is! bool) throw FormatException('$key must be a boolean');
  return value;
}

Uint8List _bytes(Object? value, String name) {
  if (value is Uint8List) return Uint8List.fromList(value);
  if (value is List<int>) return Uint8List.fromList(value);
  throw FormatException('$name must be a byte string');
}

Uint8List? _optionalBytes(Map<String, Object?> map, String key) =>
    map[key] == null ? null : _bytes(map[key], key);

T _enum<T extends Enum>(List<T> values, Object? value, String name) {
  if (value is String) {
    for (final candidate in values) {
      if (candidate.name == value) return candidate;
    }
  }
  throw FormatException('Unsupported $name: $value');
}

Map<String, Object?> _unknown(
  Map<String, Object?> value,
  Set<String> knownKeys,
) => unknownFields(value, knownKeys);
