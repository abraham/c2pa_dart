import 'dart:collection';
import 'dart:typed_data';

import 'exceptions.dart';
import 'json_utils.dart';
import 'settings.dart';

/// The resource quota that was exceeded.
enum ResourceLimitKind {
  /// A single resource exceeded [C2paSettings.maxResourceBytes].
  resourceBytes,

  /// All stored resources exceeded [C2paSettings.maxTotalResourceBytes].
  totalBytes,

  /// Resource count exceeded [C2paSettings.maxResourceCount].
  count,
}

/// Exception thrown when a normalized resource URI has no stored bytes.
final class C2paResourceNotFoundException extends C2paResourceException {
  /// Creates a not-found exception for normalized [uri].
  const C2paResourceNotFoundException(this.uri)
    : super('Resource not found: $uri');

  /// Normalized resource URI that was not found.
  final String uri;
}

/// Exception thrown when resource storage exceeds configured limits.
final class C2paResourceLimitException extends C2paResourceException {
  /// Creates a resource limit exception for [kind].
  const C2paResourceLimitException({
    required this.kind,
    required this.limit,
    required this.actual,
  }) : super('Resource $kind limit exceeded: $actual > $limit');

  /// Quota category that was exceeded.
  final ResourceLimitKind kind;

  /// Configured byte or count limit.
  final int limit;

  /// Actual byte or count value that exceeded [limit].
  final int actual;
}

/// Exception thrown when adding a resource URI that already exists.
final class C2paDuplicateResourceException extends C2paResourceException {
  /// Creates a duplicate-resource exception for normalized [uri].
  const C2paDuplicateResourceException(this.uri)
    : super('A resource already exists for URI: $uri');

  /// Normalized resource URI that already exists.
  final String uri;
}

/// Exception thrown when a resource lookup matches multiple resources.
final class C2paAmbiguousResourceException extends C2paResourceException {
  /// Creates an ambiguous-resource exception for [uri] and candidate [matches].
  C2paAmbiguousResourceException(this.uri, Iterable<String> matches)
    : matches = List<String>.unmodifiable(matches),
      super('Resource URI is ambiguous: $uri');

  /// Normalized resource URI requested by the caller.
  final String uri;

  /// Normalized resource URIs that matched the lookup.
  final List<String> matches;
}

/// Exception thrown when a resource URI cannot be normalized safely.
final class C2paResourceUriException extends C2paResourceException {
  /// Creates an invalid-resource-URI exception for the original [uri].
  const C2paResourceUriException(this.uri)
    : super('Invalid C2PA/JUMBF resource URI: $uri');

  /// Original resource URI value that failed validation.
  final String uri;
}

/// Manifest resource bytes decoded from a C2PA data box.
final class C2paResource {
  /// Creates an immutable resource record and copies [bytes].
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

  /// Fully normalized `self#jumbf=` URI for the resource data box.
  final String uri;

  /// Manifest label that owns this resource.
  final String manifestLabel;

  /// Data-box label within the owning manifest.
  final String label;

  /// MIME type stored in the resource `format` field.
  final String mimeType;

  /// Optional display name stored with the resource, or `null` if absent.
  final String? name;

  /// Optional data-type tags associated with the resource.
  final List<String> dataTypes;

  /// Unrecognized resource metadata preserved from the data box.
  final Map<String, Object?> unknownFields;

  /// Immutable resource payload bytes.
  final Uint8List bytes;
}

/// In-memory resource storage that takes ownership by copying byte inputs.
final class ResourceStore {
  /// Creates an empty in-memory store using [settings] for quotas.
  ResourceStore({this.settings = const C2paSettings()});

  /// Resource count and byte limits enforced by [add].
  final C2paSettings settings;
  final Map<String, Uint8List> _resources = {};
  int _totalBytes = 0;

  /// Number of resources currently stored.
  int get length => _resources.length;

  /// Total stored payload size in bytes.
  int get totalBytes => _totalBytes;

  /// Whether no resources are currently stored.
  bool get isEmpty => _resources.isEmpty;

  /// Whether at least one resource is currently stored.
  bool get isNotEmpty => _resources.isNotEmpty;

  /// Normalized resource URIs currently present in the store.
  Set<String> get uris => UnmodifiableSetView(_resources.keys.toSet());

  /// Stores [bytes] under [uri] after normalization and quota checks.
  ///
  /// Throws [C2paDuplicateResourceException] if the normalized URI already
  /// exists, [C2paResourceLimitException] if a byte or count quota is exceeded,
  /// or [C2paResourceUriException] if [uri] is invalid.
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

  /// Whether [uri] normalizes to a stored resource.
  ///
  /// Throws [C2paResourceUriException] if [uri] is invalid.
  bool contains(String uri) => _resources.containsKey(normalizeUri(uri));

  /// Looks up [uri] and returns immutable resource bytes.
  ///
  /// The lookup does not perform I/O, but the async API reports not-found and
  /// invalid-URI failures as future errors. Throws
  /// [C2paResourceNotFoundException] if no normalized URI is stored.
  Future<Uint8List> lookup(String uri) async {
    final key = normalizeUri(uri);
    final bytes = _resources[key];
    if (bytes == null) throw C2paResourceNotFoundException(key);
    return bytes.asUnmodifiableView();
  }

  /// Normalizes a C2PA resource URI or JUMBF path.
  ///
  /// Bare absolute JUMBF paths are returned as `self#jumbf=` URIs. Relative or
  /// malformed URI values and values containing backslashes throw
  /// [C2paResourceUriException].
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
