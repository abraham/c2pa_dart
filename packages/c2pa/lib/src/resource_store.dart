import 'dart:collection';
import 'dart:typed_data';

import 'exceptions.dart';
import 'json_utils.dart';
import 'settings.dart';

enum ResourceLimitKind { resourceBytes, totalBytes, count }

final class C2paResourceNotFoundException extends C2paResourceException {
  const C2paResourceNotFoundException(this.uri)
    : super('Resource not found: $uri');

  final String uri;
}

final class C2paResourceLimitException extends C2paResourceException {
  const C2paResourceLimitException({
    required this.kind,
    required this.limit,
    required this.actual,
  }) : super('Resource $kind limit exceeded: $actual > $limit');

  final ResourceLimitKind kind;
  final int limit;
  final int actual;
}

final class C2paDuplicateResourceException extends C2paResourceException {
  const C2paDuplicateResourceException(this.uri)
    : super('A resource already exists for URI: $uri');

  final String uri;
}

final class C2paAmbiguousResourceException extends C2paResourceException {
  C2paAmbiguousResourceException(this.uri, Iterable<String> matches)
    : matches = List<String>.unmodifiable(matches),
      super('Resource URI is ambiguous: $uri');

  final String uri;
  final List<String> matches;
}

final class C2paResourceUriException extends C2paResourceException {
  const C2paResourceUriException(this.uri)
    : super('Invalid C2PA/JUMBF resource URI: $uri');

  final String uri;
}

final class C2paResource {
  C2paResource({
    required this.uri,
    required this.manifestLabel,
    required this.label,
    required this.mimeType,
    required Uint8List bytes,
    this.name,
    Iterable<String> dataTypes = const [],
    Map<String, Object?> unknownFields = const {},
  }) : bytes = Uint8List.fromList(bytes).asUnmodifiableView(),
       dataTypes = List<String>.unmodifiable(dataTypes),
       unknownFields = freezeJsonMap(unknownFields);

  final String uri;
  final String manifestLabel;
  final String label;
  final String mimeType;
  final String? name;
  final List<String> dataTypes;
  final Map<String, Object?> unknownFields;
  final Uint8List bytes;
}

/// In-memory resource storage that takes ownership by copying byte inputs.
final class ResourceStore {
  ResourceStore({this.settings = const C2paSettings()});

  final C2paSettings settings;
  final Map<String, Uint8List> _resources = {};
  int _totalBytes = 0;

  int get length => _resources.length;
  int get totalBytes => _totalBytes;
  bool get isEmpty => _resources.isEmpty;
  bool get isNotEmpty => _resources.isNotEmpty;
  Set<String> get uris => UnmodifiableSetView(_resources.keys.toSet());

  void add(String uri, Uint8List bytes) {
    final key = normalizeUri(uri);
    if (_resources.containsKey(key)) {
      throw C2paDuplicateResourceException(key);
    }
    if (bytes.length > settings.maxResourceBytes) {
      throw C2paResourceLimitException(
        kind: ResourceLimitKind.resourceBytes,
        limit: settings.maxResourceBytes,
        actual: bytes.length,
      );
    }
    if (_resources.length + 1 > settings.maxResourceCount) {
      throw C2paResourceLimitException(
        kind: ResourceLimitKind.count,
        limit: settings.maxResourceCount,
        actual: _resources.length + 1,
      );
    }
    final nextTotal = _totalBytes + bytes.length;
    if (nextTotal > settings.maxTotalResourceBytes) {
      throw C2paResourceLimitException(
        kind: ResourceLimitKind.totalBytes,
        limit: settings.maxTotalResourceBytes,
        actual: nextTotal,
      );
    }

    _resources[key] = Uint8List.fromList(bytes);
    _totalBytes = nextTotal;
  }

  bool contains(String uri) => _resources.containsKey(normalizeUri(uri));

  Future<Uint8List> lookup(String uri) async {
    final key = normalizeUri(uri);
    final bytes = _resources[key];
    if (bytes == null) throw C2paResourceNotFoundException(key);
    return bytes.asUnmodifiableView();
  }

  static String normalizeUri(String value) {
    final input = value.trim();
    if (input.isEmpty || input.contains('\\')) {
      throw C2paResourceUriException(value);
    }

    final jumbf = RegExp(
      r'^(?:self)?#?jumbf=(.*)$',
      caseSensitive: false,
    ).firstMatch(input);
    if (jumbf != null) {
      final path = _normalizeJumbfPath(jumbf.group(1)!);
      return 'self#jumbf=$path';
    }
    if (input.startsWith('/')) {
      return 'self#jumbf=${_normalizeJumbfPath(input)}';
    }

    final uri = Uri.tryParse(input);
    if (uri == null || (!uri.isAbsolute && uri.fragment.isEmpty)) {
      throw C2paResourceUriException(value);
    }
    if (uri.fragment.toLowerCase().startsWith('jumbf=')) {
      final path = _normalizeJumbfPath(uri.fragment.substring(6));
      final base = uri.replace(fragment: '').toString();
      return '${base.isEmpty ? 'self' : base}#jumbf=$path';
    }

    return uri
        .replace(
          scheme: uri.scheme.toLowerCase(),
          host: uri.host.toLowerCase(),
          path: Uri(path: uri.path).normalizePath().path,
        )
        .toString();
  }

  static String _normalizeJumbfPath(String value) {
    var path = value.trim();
    if (!path.startsWith('/')) path = '/$path';
    final normalized = Uri(path: path).normalizePath().path;
    if (!normalized.startsWith('/')) {
      throw C2paResourceUriException(value);
    }
    return normalized;
  }
}
