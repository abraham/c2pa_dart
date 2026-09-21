part of '../cli.dart';

abstract base class _C2paCommand extends Command<CliResult> {
  Future<void> Function(String path)? get onInputOpened =>
      (runner! as C2paCli).onInputOpened;

  Future<CliResult> _inspect(
    ArgResults options, {
    required bool validate,
  }) async {
    _requirePositionals(options, 1, '<asset>');
    final output = options['output'] as String?;
    await _validateOutputs(
      options,
      files: [?output],
      inputs: [options.rest.single, ?options['manifest'] as String?],
    );
    final reader = await _readAsset(options.rest.single, options);
    final format = options['format'] as String;
    final json = switch (format) {
      'sdk' => reader.encodeSdkJson(options: _jsonOptions(options)),
      'detailed' => reader.encodeDetailedJson(options: _jsonOptions(options)),
      'crjson' => reader.encodeCrJson(options: _jsonOptions(options)),
      _ => throw _CliUsageException('Unsupported JSON format: $format'),
    };
    await _writeTextOrStdout(json, output, options);
    final invalid = reader.validationResults.state == ValidationState.invalid;
    return CliResult(
      validate && invalid ? CliExitCode.validation : CliExitCode.success,
      stdout: output == null ? '$json\n' : '',
      stderr: validate && invalid ? 'C2PA validation failed.\n' : '',
    );
  }

  Future<C2paReader> _readAsset(String path, ArgResults options) async {
    final context = await _readerContext(options);
    final source = await _openSource(path, options);
    FileByteSource? manifestSource;
    try {
      final sidecar = options['manifest'] as String?;
      if (sidecar != null) manifestSource = await _openSource(sidecar, options);
      return await C2paReader.fromSource(
        source: manifestSource ?? source,
        assetSource: sidecar == null ? null : source,
        mimeType: sidecar == null ? options['mime-type'] as String? : null,
        fileName: sidecar ?? path,
        assetMimeType: sidecar == null ? null : options['mime-type'] as String?,
        assetFileName: sidecar == null ? null : path,
        context: context,
      );
    } finally {
      await manifestSource?.close();
      await source.close();
    }
  }

  Future<C2paContext> _readerContext(ArgResults options) async {
    final allowNetwork = options['allow-network'] as bool;
    final hosts = (options['allow-host'] as List<String>).toSet();
    if (allowNetwork && hosts.isEmpty) {
      throw const _CliUsageException(
        '--allow-network requires at least one --allow-host',
      );
    }
    if (!allowNetwork && hosts.isNotEmpty) {
      throw const _CliUsageException('--allow-host requires --allow-network');
    }
    final maxNetwork = _integer(options, 'max-network-bytes');
    final timeout = Duration(seconds: _integer(options, 'network-timeout'));
    final settings = C2paSettings(
      allowNetworkAccess: allowNetwork,
      maxNetworkBytes: maxNetwork,
      networkTimeout: timeout,
      maxManifestBytes: _integer(options, 'max-manifest-bytes'),
      maxResourceBytes: _integer(options, 'max-resource-bytes'),
      maxTotalResourceBytes: _integer(options, 'max-total-resource-bytes'),
    );
    final policy = RemoteManifestPolicy(
      enabled: allowNetwork,
      allowedHosts: hosts,
      maxBytes: maxNetwork,
      maxRedirects: 2,
    );
    return C2paContext(
      settings: settings,
      trust: await _trust(options, 'trust-anchor', 'trust-list-file'),
      cawgTrust: await _trust(
        options,
        'cawg-trust-anchor',
        'cawg-trust-list-file',
      ),
      remoteManifestPolicy: policy,
      remoteResolver: allowNetwork
          ? createC2paHttpRemoteResolver(
              policy: policy,
              timeouts: C2paHttpTimeouts(
                connect: timeout,
                read: timeout,
                overall: timeout,
              ),
            )
          : null,
    );
  }

  Future<C2paTrustConfiguration> _trust(
    ArgResults options,
    String anchorOption,
    String listOption,
  ) async {
    final anchors = <Uint8List>[];
    for (final path in options[anchorOption] as List<String>) {
      final text = utf8.decode(
        await _readBoundedFile(path, 4 * 1024 * 1024),
        allowMalformed: false,
      );
      anchors.addAll(parsePemCertificateBundle(text));
    }
    for (final path in options[listOption] as List<String>) {
      final text = utf8.decode(
        await _readBoundedFile(path, 4 * 1024 * 1024),
        allowMalformed: false,
      );
      anchors.addAll(
        parsePemCertificateBundle(
          text,
          duplicateHandling: PemDuplicateCertificateHandling.ignore,
        ),
      );
    }
    return C2paTrustConfiguration(
      verifyTrust: anchors.isNotEmpty,
      trustAnchors: anchors,
    );
  }

  Future<C2paContext> _signingContext(
    ArgResults options,
    String algorithm,
  ) async {
    final reserveSize = _nullableInteger(options, 'reserve-size') ?? 0;
    final command = options['signer-command'] as String?;
    final key = options['key'] as String?;
    if ((command == null) == (key == null)) {
      throw const _CliUsageException(
        'Specify exactly one of --key or --signer-command',
      );
    }
    final signer = command != null
        ? SubprocessC2paSigner(
            executable: command,
            arguments: options['signer-arg'] as List<String>,
            algorithm: algorithm,
            timeout: Duration(seconds: _integer(options, 'signer-timeout')),
            reservedSignatureSize: reserveSize,
          )
        : LocalKeyC2paSigner(
            keyPath: key!,
            algorithm: algorithm,
            opensslExecutable: options['openssl'] as String,
            timeout: Duration(seconds: _integer(options, 'signer-timeout')),
            ed25519TemporaryRoot: options['ed25519-temp-root'] as String?,
            reservedSignatureSize: reserveSize == 0 ? null : reserveSize,
          );
    return C2paContext(signer: signer);
  }

  Future<C2paBuilder> _builderFromDefinition(
    ArgResults options,
    C2paContext context, {
    String? signingAlgorithm,
  }) async {
    final path = _requiredOption(options, 'manifest');
    final bytes = await _readBoundedFile(path, 16 * 1024 * 1024);
    final Object? decoded = jsonDecode(utf8.decode(bytes));
    if (decoded is! Map<String, Object?>) {
      throw const FormatException('Manifest definition must be a JSON object');
    }
    final definition = await _manifestDefinition(
      decoded,
      await _resolveBaseDirectory(File(path).absolute.parent),
    );
    final certificates = <Uint8List>[];
    for (final certPath in options['cert'] as List<String>) {
      final certBytes = await _readBoundedFile(certPath, 4 * 1024 * 1024);
      final text = utf8.decode(certBytes, allowMalformed: true);
      if (text.contains('-----BEGIN CERTIFICATE-----')) {
        certificates.addAll(parsePemCertificateBundle(text));
      } else {
        certificates.add(certBytes);
      }
    }
    if (certificates.isEmpty) {
      throw const _CliUsageException('At least one --cert is required');
    }
    return C2paBuilder(
      definition: definition,
      context: context,
      signingAlgorithm:
          signingAlgorithm ?? (options['algorithm'] as String?) ?? 'es256',
      x5chain: certificates,
    );
  }

  Future<C2paBuilder> _signingBuilderFromArchive(
    ArgResults options,
    String path,
  ) async {
    final archived = await _builderFromArchive(path, C2paContext());
    final requested = options['algorithm'] as String?;
    if (requested != null &&
        _normalizeAlgorithm(requested) !=
            _normalizeAlgorithm(archived.signingAlgorithm)) {
      throw _CliUsageException(
        '--algorithm $requested does not match archive signing algorithm '
        '${archived.signingAlgorithm}',
      );
    }
    final context = await _signingContext(options, archived.signingAlgorithm);
    return C2paBuilder(
      definition: archived.definition,
      context: context,
      signingAlgorithm: archived.signingAlgorithm,
      x5chain: archived.x5chain,
      archiveBasePath: archived.archiveBasePath,
      remoteManifestUrl: archived.remoteManifestUrl,
      noEmbed: archived.noEmbed,
      archiveExtensions: archived.archiveExtensions,
      dynamicAssertions: archived.dynamicAssertions,
      cachedOcspResponses: archived.cachedOcspResponses,
      timestamp: archived.timestamp,
    );
  }

  Future<C2paBuilder> _builderFromArchive(
    String path,
    C2paContext context,
  ) async {
    final bytes = await _readBoundedFile(path, 64 * 1024 * 1024);
    final base = await _resolveBaseDirectory(File(path).absolute.parent);
    return C2paBuilder.fromArchive(
      bytes: bytes,
      context: context,
      options: C2paArchiveLoadOptions(
        resourceResolver: (request) async {
          final relative = [
            if (request.basePath != null) request.basePath!,
            request.path,
          ].join('/').replaceAll('\\', '/');
          if (!_safeRelative(relative)) {
            throw C2paUnsafeArchivePathException(request.path);
          }
          final file = await _containedRegularFile(base, relative);
          return _readBoundedFile(file.path, 50 * 1024 * 1024);
        },
      ),
    );
  }

  Future<ManifestDefinition> _manifestDefinition(
    Map<String, Object?> json,
    Directory base,
  ) async {
    String requiredString(String snake, [String? camel]) {
      final value = json[snake] ?? (camel == null ? null : json[camel]);
      if (value is! String || value.trim().isEmpty) {
        throw FormatException('$snake must be a non-empty string');
      }
      return value;
    }

    final generatorValue =
        json['claim_generator_info'] ?? json['claimGeneratorInfo'];
    final generator = generatorValue is Map
        ? ClaimGeneratorInfo.fromCbor(Map<String, Object?>.from(generatorValue))
        : ClaimGeneratorInfo(
            name: (json['claim_generator'] as String?) ?? 'c2patool_dart',
            version: c2patoolVersion,
          );
    final intentValue = json['intent'];
    final intent = intentValue is Map
        ? BuilderIntent.fromJson(Map<String, Object?>.from(intentValue))
        : const BuilderIntent.create(DigitalSourceType.other);
    final assertions = <AssertionDefinition>[];
    for (final value in (json['assertions'] as List<Object?>?) ?? const []) {
      if (value is! Map) {
        throw const FormatException('Each assertion must be an object');
      }
      final item = Map<String, Object?>.from(value);
      final label = item['label'];
      if (label is! String || label.isEmpty) {
        throw const FormatException('Each assertion requires a label');
      }
      final encoding = item['encoding'] ?? item['kind'] ?? 'cbor';
      if (encoding == 'binary') {
        final data = item['data'];
        if (data is! String || item['content_type'] is! String) {
          throw const FormatException(
            'Binary assertions need base64 data and content_type',
          );
        }
        assertions.add(
          AssertionDefinition.binary(
            label: label,
            contentType: item['content_type']! as String,
            data: base64Decode(data),
          ),
        );
      } else if (encoding == 'json') {
        assertions.add(
          AssertionDefinition.json(label: label, data: item['data']),
        );
      } else {
        assertions.add(
          AssertionDefinition.cbor(label: label, data: item['data']),
        );
      }
    }
    final resources = <ManifestResource>[];
    for (final value in (json['resources'] as List<Object?>?) ?? const []) {
      if (value is! Map) {
        throw const FormatException('Each resource must be an object');
      }
      final item = Map<String, Object?>.from(value);
      final path = item['path'];
      if (path is! String || !_safeRelative(path)) {
        throw FormatException('Unsafe resource path: $path');
      }
      final file = await _containedRegularFile(base, path);
      resources.add(
        ManifestResource(
          label: item['label'] as String,
          format: item['format'] as String,
          bytes: await _readBoundedFile(file.path, 50 * 1024 * 1024),
          name: item['name'] as String?,
          dataTypes:
              (item['data_types'] as List<Object?>?)?.cast<String>() ??
              const [],
        ),
      );
    }
    final actions = <C2paAction>[];
    for (final value in (json['actions'] as List<Object?>?) ?? const []) {
      actions.add(C2paAction.fromCbor(value));
    }
    final ingredients = <BuilderIngredient>[];
    for (final value in (json['ingredients'] as List<Object?>?) ?? const []) {
      if (value is! Map) {
        throw const FormatException('Each ingredient must be an object');
      }
      final item = Map<String, Object?>.from(value);
      final assertionValue = item['assertion'] ?? item;
      if (assertionValue is! Map) {
        throw const FormatException(
          'Each ingredient assertion must be an object',
        );
      }
      final assertionMap = Map<String, Object?>.from(assertionValue);
      final versionValue = item['version'] ?? assertionMap['version'];
      assertionMap.remove('id');
      assertionMap.remove('version');
      assertionMap.remove('assertion');
      assertionMap.remove('manifest');
      assertionMap.remove('manifests');
      final version = _ingredientVersion(versionValue);
      final assertion = IngredientAssertion.fromCbor(
        assertionMap,
        version: version,
      );
      final id = item['id'] ?? assertion.instanceId;
      if (id is! String || id.trim().isEmpty) {
        throw const FormatException(
          'Each ingredient requires an id or assertion instanceID',
        );
      }
      final manifestPaths = <String>[
        if (item['manifest'] case final String path) path,
        ...switch (item['manifests']) {
          final List<Object?> paths => paths.cast<String>(),
          null => const <String>[],
          _ => throw const FormatException(
            'Ingredient manifests must be a list of paths',
          ),
        },
      ];
      final manifestBoxes = <Uint8List>[];
      for (final path in manifestPaths) {
        if (!_safeRelative(path)) {
          throw FormatException('Unsafe ingredient manifest path: $path');
        }
        manifestBoxes.add(
          await _readBoundedFile(
            (await _containedRegularFile(base, path)).path,
            64 * 1024 * 1024,
          ),
        );
      }
      ingredients.add(
        BuilderIngredient(
          id: id,
          assertion: assertion,
          manifestBoxes: manifestBoxes,
        ),
      );
    }
    return ManifestDefinition(
      label: requiredString('label'),
      intent: intent,
      generatorInfo: generator,
      title: json['title'] as String?,
      format: requiredString('format'),
      instanceId: requiredString('instance_id', 'instanceId'),
      hashAlgorithm:
          (json['hash_algorithm'] ?? json['hashAlgorithm']) as String? ??
          'sha256',
      assertions: assertions,
      resources: resources,
      redactions:
          (json['redactions'] as List<Object?>?)?.cast<String>() ?? const [],
      ingredients: ingredients,
      actions: actions,
    );
  }

  C2paJsonOptions _jsonOptions(ArgResults options) => C2paJsonOptions(
    pretty: options['pretty'] as bool,
    binaryOutput: options['binary'] == 'base64'
        ? C2paBinaryOutput.base64
        : C2paBinaryOutput.redact,
  );

  Future<FileByteSource> _openSource(String path, ArgResults options) async {
    final maximum = _integer(options, 'max-input-bytes');
    final source = await FileByteSource.open(path);
    try {
      await onInputOpened?.call(path);
      final size = await source.length;
      if (size > maximum) {
        throw C2paResourceException(
          'Input file size $size exceeds the $maximum byte limit',
        );
      }
      return source;
    } on Object {
      await source.close();
      rethrow;
    }
  }

  Future<void> _writeTextOrStdout(
    String value,
    String? path,
    ArgResults options,
  ) async {
    if (path != null) {
      await _atomicWrite(
        path,
        utf8.encode('$value\n'),
        overwrite: options['force'] as bool,
      );
    }
  }

  Future<Uint8List> _readBoundedFile(String path, int maximum) async {
    RandomAccessFile? handle;
    try {
      handle = await File(path).open(mode: FileMode.read);
      await onInputOpened?.call(path);
      final openedLength = await handle.length();
      if (openedLength > maximum) {
        throw C2paResourceException(
          'File size $openedLength exceeds the $maximum byte limit: $path',
        );
      }

      final bytes = BytesBuilder(copy: false);
      var total = 0;
      while (true) {
        final remaining = maximum - total;
        final chunk = await handle.read(
          remaining >= 64 * 1024 ? 64 * 1024 : remaining + 1,
        );
        if (chunk.isEmpty) break;
        total += chunk.length;
        if (total > maximum) {
          throw C2paResourceException(
            'File exceeds the $maximum byte limit while reading: $path',
          );
        }
        bytes.add(chunk);
      }
      final finalLength = await handle.length();
      if (finalLength > maximum) {
        throw C2paResourceException(
          'File size $finalLength exceeds the $maximum byte limit: $path',
        );
      }
      return bytes.takeBytes();
    } on C2paException {
      rethrow;
    } on FileSystemException catch (error, stackTrace) {
      throw C2paResourceException(
        'Unable to read input file: $path',
        cause: error,
        stackTrace: stackTrace,
      );
    } finally {
      await handle?.close();
    }
  }
}

IngredientAssertionVersion _ingredientVersion(Object? value) => switch (value) {
  null || 3 || '3' || 'v3' => IngredientAssertionVersion.v3,
  1 || '1' || 'v1' => IngredientAssertionVersion.v1,
  2 || '2' || 'v2' => IngredientAssertionVersion.v2,
  _ => throw FormatException('Unsupported ingredient version: $value'),
};

Future<void> _atomicWrite(
  String path,
  List<int> bytes, {
  required bool overwrite,
}) async {
  final parent = File(path).absolute.parent;
  if (!await parent.exists()) {
    throw FileSystemException('Output directory does not exist', parent.path);
  }
  final sink = await FileByteSink.open(path, overwrite: overwrite);
  try {
    await sink.append(bytes);
    await sink.close();
  } on Object {
    await sink.abort();
    rethrow;
  }
}

Future<void> _validateOutputs(
  ArgResults options, {
  Iterable<String> files = const [],
  Iterable<String> directories = const [],
  Iterable<String> inputs = const [],
}) async {
  final force = options['force'] as bool;
  final inputPaths = <String>{};
  for (final path in inputs) {
    inputPaths.add(await _canonicalPath(path));
  }
  final directoryPaths = <String>{};
  for (final path in directories) {
    directoryPaths.add(await _canonicalPath(path));
  }
  final outputs = <String>{};
  for (final path in [...files, ...directories]) {
    final canonical = await _canonicalPath(path);
    if (!outputs.add(canonical)) {
      throw _CliUsageException('Output paths must be distinct: $path');
    }
    if (inputPaths.contains(canonical)) {
      throw _CliUsageException(
        'Input and output paths must be different: $path',
      );
    }
    final parent = File(path).absolute.parent;
    final canonicalParent = await _canonicalPath(parent.path);
    final parentType = await FileSystemEntity.type(parent.path);
    if (parentType != FileSystemEntityType.directory &&
        !directoryPaths.contains(canonicalParent)) {
      throw _CliUsageException(
        'Output directory does not exist or is not a directory: '
        '${parent.path}',
      );
    }
    final rawType = await FileSystemEntity.type(path, followLinks: false);
    final type = await FileSystemEntity.type(path);
    final isDirectoryOutput = directoryPaths.contains(canonical);
    if (rawType == FileSystemEntityType.link &&
        type == FileSystemEntityType.notFound) {
      throw _CliUsageException('Output path is a dangling link: $path');
    }
    if (type != FileSystemEntityType.notFound &&
        type !=
            (isDirectoryOutput
                ? FileSystemEntityType.directory
                : FileSystemEntityType.file)) {
      throw _CliUsageException(
        'Output path is not a ${isDirectoryOutput ? 'directory' : 'file'}: '
        '$path',
      );
    }
    if (!force && rawType != FileSystemEntityType.notFound) {
      throw _CliUsageException(
        'Output already exists: $path (use --force to replace it)',
      );
    }
  }
}

Future<String> _canonicalPath(String path) async {
  final absolute = File(path).absolute;
  final type = await FileSystemEntity.type(absolute.path);
  if (type == FileSystemEntityType.file) {
    return absolute.resolveSymbolicLinks();
  }
  if (type == FileSystemEntityType.directory) {
    return Directory(absolute.path).resolveSymbolicLinks();
  }
  if (type == FileSystemEntityType.link) {
    return Link(absolute.path).resolveSymbolicLinks();
  }
  final normalized = absolute.uri.normalizePath().toFilePath();
  final parent = File(normalized).parent;
  if (await parent.exists()) {
    return '${await parent.resolveSymbolicLinks()}'
        '${Platform.pathSeparator}${File(normalized).uri.pathSegments.last}';
  }
  return normalized;
}

Future<Directory> _resolveBaseDirectory(Directory base) async {
  try {
    final resolved = Directory(await base.absolute.resolveSymbolicLinks());
    if (await FileSystemEntity.type(resolved.path) !=
        FileSystemEntityType.directory) {
      throw C2paResourceException(
        'Permitted base path is not a directory: ${base.path}',
      );
    }
    return resolved;
  } on C2paException {
    rethrow;
  } on FileSystemException catch (error, stackTrace) {
    throw C2paResourceException(
      'Unable to resolve permitted base directory: ${base.path}',
      cause: error,
      stackTrace: stackTrace,
    );
  }
}

File _containedOutput(Directory base, String relative) {
  if (!_safeRelative(relative)) {
    throw C2paUnsafeArchivePathException(relative);
  }
  final baseUri = base.absolute.uri;
  final candidate = File.fromUri(baseUri.resolve(relative)).absolute;
  if (!candidate.uri.toString().startsWith(baseUri.toString())) {
    throw C2paUnsafeArchivePathException(relative);
  }
  return candidate;
}

Future<File> _containedRegularFile(
  Directory resolvedBase,
  String relative,
) async {
  if (!_safeRelative(relative)) {
    throw C2paUnsafeArchivePathException(relative);
  }
  final basePath = resolvedBase.absolute.uri.normalizePath().toFilePath();
  final candidate = File.fromUri(resolvedBase.absolute.uri.resolve(relative))
      .absolute;
  FileSystemEntity existing = candidate;
  while (await FileSystemEntity.type(existing.path, followLinks: false) ==
      FileSystemEntityType.notFound) {
    final parent = existing.parent;
    if (parent.path == existing.path) {
      throw C2paResourceException('Input path does not exist: $relative');
    }
    existing = parent;
  }

  String resolvedExisting;
  try {
    resolvedExisting = await existing.resolveSymbolicLinks();
  } on FileSystemException catch (error, stackTrace) {
    throw C2paResourceException(
      'Input path contains a broken link or symlink loop: $relative',
      cause: error,
      stackTrace: stackTrace,
    );
  }
  if (!_pathContainedBy(basePath, resolvedExisting)) {
    throw C2paUnsafeArchivePathException(relative);
  }

  if (existing.path != candidate.path) {
    throw C2paResourceException('Input path does not exist: $relative');
  }
  final resolvedCandidate = File(resolvedExisting);
  final type = await FileSystemEntity.type(resolvedCandidate.path);
  if (type != FileSystemEntityType.file) {
    throw C2paResourceException('Input path is not a regular file: $relative');
  }
  return resolvedCandidate;
}

bool _pathContainedBy(String base, String candidate) {
  final normalizedBase = Directory(base).absolute.uri.normalizePath();
  final normalizedCandidate = File(candidate).absolute.uri.normalizePath();
  if (normalizedCandidate == normalizedBase) return true;
  final basePath = normalizedBase.path.endsWith('/')
      ? normalizedBase.path
      : '${normalizedBase.path}/';
  return normalizedCandidate.path.startsWith(basePath);
}

bool _safeRelative(String value) {
  if (value.isEmpty || value.contains('\u0000')) return false;
  final normalized = value.replaceAll('\\', '/');
  if (normalized.startsWith('/') ||
      RegExp(r'^[A-Za-z]:/').hasMatch(normalized)) {
    return false;
  }
  return !normalized.split('/').any((part) => part.isEmpty || part == '..');
}

String _safeResourceName(String value, int index) {
  var safe = value.replaceAll(RegExp(r'[^A-Za-z0-9._-]'), '_');
  while (safe.contains('..')) {
    safe = safe.replaceAll('..', '_');
  }
  safe = safe.replaceFirst(RegExp(r'^\.+'), '');
  if (safe.isEmpty || safe == '.' || safe == '..') safe = 'resource';
  if (safe.length > 120) safe = safe.substring(0, 120);
  return '${index.toString().padLeft(4, '0')}-$safe';
}

String? _extension(String path) {
  final name = path.replaceAll('\\', '/').split('/').last;
  final index = name.lastIndexOf('.');
  return index <= 0 ? null : name.substring(index + 1);
}

Uri? _optionalUri(String? value) {
  if (value == null) return null;
  final uri = Uri.tryParse(value);
  if (uri == null ||
      !uri.isAbsolute ||
      uri.scheme != 'https' ||
      uri.host.isEmpty ||
      uri.userInfo.isNotEmpty) {
    throw const _CliUsageException(
      'Remote URL must be an absolute HTTPS URL without user info',
    );
  }
  return uri;
}

String _requiredOption(ArgResults options, String name) {
  final value = options[name] as String?;
  if (value == null || value.isEmpty) {
    throw _CliUsageException('--$name is required');
  }
  return value;
}

int _integer(ArgResults options, String name) {
  final value = int.tryParse(options[name] as String);
  if (value == null || value <= 0) {
    throw _CliUsageException('--$name must be a positive integer');
  }
  return value;
}

int? _nullableInteger(ArgResults options, String name) {
  final raw = options[name] as String?;
  if (raw == null) return null;
  final value = int.tryParse(raw);
  if (value == null || value <= 0) {
    throw _CliUsageException('--$name must be a positive integer');
  }
  return value;
}

void _requirePositionals(ArgResults options, int count, String usage) {
  if (options.rest.length != count) {
    throw _CliUsageException(
      '${options.name}${usage.isEmpty ? '' : ' $usage'} expects '
      '$count positional argument${count == 1 ? '' : 's'}',
    );
  }
}

CliResult _error(int code, String message) =>
    CliResult(code, stderr: 'Error: $message\n');

void _addReaderOptions(ArgParser parser) {
  parser
    ..addOption(
      'format',
      allowed: const ['sdk', 'detailed', 'crjson'],
      defaultsTo: 'sdk',
    )
    ..addFlag('pretty', negatable: false)
    ..addOption(
      'binary',
      allowed: const ['redact', 'base64'],
      defaultsTo: 'redact',
    )
    ..addOption(
      'manifest',
      help: 'Explicit sidecar manifest (takes precedence over embedded data)',
    )
    ..addOption('mime-type')
    ..addFlag('force', negatable: false, help: 'Replace existing output paths')
    ..addFlag('allow-network', negatable: false)
    ..addMultiOption('allow-host')
    ..addOption('max-network-bytes', defaultsTo: '${10 * 1024 * 1024}')
    ..addOption('network-timeout', defaultsTo: '10')
    ..addOption('max-input-bytes', defaultsTo: '${2 * 1024 * 1024 * 1024}')
    ..addOption('max-manifest-bytes', defaultsTo: '${64 * 1024 * 1024}')
    ..addOption('max-resource-bytes', defaultsTo: '${50 * 1024 * 1024}')
    ..addOption('max-total-resource-bytes', defaultsTo: '${200 * 1024 * 1024}')
    ..addMultiOption('trust-anchor', help: 'Local PEM certificate bundle')
    ..addMultiOption(
      'trust-list-file',
      help: 'Local bounded PEM trust-list file',
    )
    ..addMultiOption('cawg-trust-anchor', help: 'Local PEM certificate bundle')
    ..addMultiOption(
      'cawg-trust-list-file',
      help: 'Local bounded PEM CAWG trust-list file',
    );
}

void _addDefinitionOptions(ArgParser parser) {
  parser
    ..addOption('manifest')
    ..addMultiOption('cert')
    ..addOption('algorithm', defaultsTo: 'es256');
}

void _addSignerOptions(ArgParser parser) {
  parser
    ..addOption('key')
    ..addOption('signer-command')
    ..addMultiOption('signer-arg')
    ..addOption('signer-timeout', defaultsTo: '30')
    ..addOption('reserve-size')
    ..addOption('openssl', defaultsTo: 'openssl')
    ..addOption('ed25519-temp-root')
    ..addOption(
      'algorithm',
      help:
          'Signing algorithm (defaults to es256 for definitions; archives must '
          'match their stored algorithm)',
    );
}

void _addMutationOptions(ArgParser parser) {
  parser
    ..addOption('output', abbr: 'o')
    ..addFlag('force', negatable: false, help: 'Replace an existing output')
    ..addOption('mime-type')
    ..addOption('max-input-bytes', defaultsTo: '${2 * 1024 * 1024 * 1024}');
}

String _normalizeAlgorithm(String value) =>
    value.trim().toLowerCase().replaceAll(RegExp(r'[-_]'), '');
