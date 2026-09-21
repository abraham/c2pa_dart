import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:c2pa/c2pa.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io_vm.dart';

import 'signers.dart';

const c2patoolVersion = '0.1.0-dev.1';

abstract final class CliExitCode {
  static const success = 0;
  static const validation = 65;
  static const policy = 77;
  static const usage = 64;
  static const io = 74;
  static const signing = 75;
}

final class CliResult {
  const CliResult(this.exitCode, {this.stdout = '', this.stderr = ''});

  final int exitCode;
  final String stdout;
  final String stderr;
}

Future<int> runC2paCli(
  List<String> arguments, {
  IOSink? stdoutSink,
  IOSink? stderrSink,
}) async {
  // The process-owned sinks must remain open after this command returns.
  // ignore: close_sinks
  final out = stdoutSink ?? stdout;
  // ignore: close_sinks
  final err = stderrSink ?? stderr;
  final result = await C2paCli().run(arguments);
  if (result.stdout.isNotEmpty) out.write(result.stdout);
  if (result.stderr.isNotEmpty) err.write(result.stderr);
  return result.exitCode;
}

final class C2paCli {
  C2paCli({this.onInputOpened}) : parser = _createParser();

  final ArgParser parser;
  final Future<void> Function(String path)? onInputOpened;

  Future<CliResult> run(List<String> arguments) async {
    ArgResults options;
    try {
      options = parser.parse(arguments);
    } on FormatException catch (error) {
      return _usage(error.message);
    }
    if (options['version'] as bool) {
      return const CliResult(
        CliExitCode.success,
        stdout: 'c2patool_dart $c2patoolVersion\n',
      );
    }
    if (options['help'] as bool) {
      return CliResult(CliExitCode.success, stdout: _help());
    }
    if (options.command == null) {
      return _usage('A command is required');
    }
    if (options.command!['help'] as bool) {
      return CliResult(
        CliExitCode.success,
        stdout: _commandHelp(options.command!.name!),
      );
    }

    try {
      return switch (options.command!.name) {
        'inspect' => await _inspect(options.command!, validate: false),
        'validate' => await _inspect(options.command!, validate: true),
        'extract' => await _extract(options.command!),
        'sign' => await _sign(options.command!),
        'archive-save' => await _archiveSave(options.command!),
        'archive-load' => await _archiveLoad(options.command!),
        'remove' => await _remove(options.command!),
        'replace' => await _replace(options.command!),
        'remote' => await _remote(options.command!),
        'fragment-sign' => await _fragmentSign(options.command!),
        'fragment-inspect' => await _fragmentInspect(options.command!),
        _ => _usage('Unknown command: ${options.command!.name}'),
      };
    } on _CliUsageException catch (error) {
      return _usage(error.message);
    } on C2paUriPolicyException catch (error) {
      return _error(CliExitCode.policy, error.message);
    } on C2paNetworkException catch (error) {
      return _error(CliExitCode.policy, error.message);
    } on C2paValidationException catch (error) {
      return _error(CliExitCode.validation, error.message);
    } on C2paParseException catch (error) {
      return _error(CliExitCode.validation, error.message);
    } on C2paSigningException catch (error) {
      return _error(CliExitCode.signing, error.message);
    } on FileSystemException catch (error) {
      return _error(CliExitCode.io, error.message);
    } on C2paException catch (error) {
      return _error(CliExitCode.io, error.message);
    } on FormatException catch (error) {
      return _error(CliExitCode.validation, error.message);
    } on Object catch (error) {
      return _error(CliExitCode.io, error.toString());
    }
  }

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

  Future<CliResult> _extract(ArgResults options) async {
    _requirePositionals(options, 1, '<asset>');
    final manifestOutput = options['manifest-output'] as String?;
    final resourceDirectory = options['resources'] as String?;
    if (manifestOutput == null && resourceDirectory == null) {
      throw const _CliUsageException(
        'extract requires --manifest-output and/or --resources',
      );
    }
    final reader = await _readAsset(options.rest.single, options);
    final resourceOutputs = <File>[];
    if (resourceDirectory != null) {
      final directory = Directory(resourceDirectory);
      for (var index = 0; index < reader.resources.length; index++) {
        final resource = reader.resources[index];
        resourceOutputs.add(
          _containedOutput(
            directory,
            _safeResourceName(resource.name ?? resource.label, index),
          ),
        );
      }
    }
    await _validateOutputs(
      options,
      files: [?manifestOutput, ...resourceOutputs.map((file) => file.path)],
      directories: [?resourceDirectory],
      inputs: [options.rest.single, ?options['manifest'] as String?],
    );
    if (manifestOutput != null) {
      await _atomicWrite(
        manifestOutput,
        reader.manifestBytes,
        overwrite: options['force'] as bool,
      );
    }
    if (resourceDirectory != null) {
      final directory = Directory(resourceDirectory);
      await directory.create(recursive: true);
      for (var index = 0; index < reader.resources.length; index++) {
        await _atomicWrite(
          resourceOutputs[index].path,
          reader.resources[index].bytes,
          overwrite: options['force'] as bool,
        );
      }
    }
    return const CliResult(CliExitCode.success);
  }

  Future<CliResult> _sign(ArgResults options) async {
    _requirePositionals(options, 0, '');
    final output = _requiredOption(options, 'output');
    final input = options['input'] as String?;
    final sidecar = options['sidecar'] as bool;
    final archivePath = options['archive'] as String?;
    final assetOutput = options['asset-output'] as String?;
    final manifestPath = options['manifest'] as String?;
    if ((archivePath == null) == (manifestPath == null)) {
      throw const _CliUsageException(
        'sign requires exactly one of --manifest or --archive',
      );
    }
    if (archivePath != null && (options['cert'] as List<String>).isNotEmpty) {
      throw const _CliUsageException('--cert cannot be used with --archive');
    }
    if (input == null && sidecar) {
      throw const _CliUsageException('--sidecar requires --input');
    }
    if ((options['no-embed'] as bool) && (options['embed'] as bool)) {
      throw const _CliUsageException(
        '--embed and --no-embed are mutually exclusive',
      );
    }
    final requestedRemoteUrl = _optionalUri(options['remote-url'] as String?);
    final requestedNoEmbed = options['no-embed'] as bool;
    if (manifestPath != null &&
        requestedRemoteUrl != null &&
        (input == null ||
            (!sidecar && !requestedNoEmbed) ||
            assetOutput == null)) {
      throw const _CliUsageException(
        '--remote-url requires --input, --asset-output, and '
        '--sidecar or --no-embed',
      );
    }
    final C2paBuilder builder;
    if (archivePath == null) {
      final algorithm = (options['algorithm'] as String?) ?? 'es256';
      final context = await _signingContext(options, algorithm);
      builder = await _builderFromDefinition(
        options,
        context,
        signingAlgorithm: algorithm,
      );
    } else {
      builder = await _signingBuilderFromArchive(options, archivePath);
    }
    final effectiveNoEmbed = options['no-embed'] as bool
        ? true
        : options['embed'] as bool
        ? false
        : builder.noEmbed;
    final effectiveRemoteUrl = requestedRemoteUrl ?? builder.remoteManifestUrl;
    final createsSidecar = sidecar || effectiveNoEmbed;
    if (assetOutput != null && (input == null || !createsSidecar)) {
      throw const _CliUsageException(
        '--asset-output requires --input and --sidecar or --no-embed',
      );
    }
    if (assetOutput != null && effectiveRemoteUrl == null) {
      throw const _CliUsageException('--asset-output requires --remote-url');
    }
    if (effectiveRemoteUrl != null &&
        input != null &&
        (!createsSidecar || assetOutput == null)) {
      throw const _CliUsageException(
        '--remote-url requires --input, --asset-output, and '
        '--sidecar or --no-embed',
      );
    }
    await _validateOutputs(
      options,
      files: [output, ?assetOutput],
      inputs: [?input, ?archivePath, ?manifestPath],
    );
    final configured = builder.withArchiveConfiguration(
      remoteManifestUrl: effectiveRemoteUrl,
      noEmbed: effectiveNoEmbed,
    );

    if (input == null) {
      await _atomicWrite(
        output,
        await configured.build(),
        overwrite: options['force'] as bool,
      );
      return const CliResult(CliExitCode.success);
    }
    final source = await _openSource(input, options);
    try {
      if (createsSidecar) {
        final result = await configured.buildSidecar(
          source: source,
          remoteManifestUrl: effectiveRemoteUrl,
          mimeType: options['mime-type'] as String?,
          fileName: input,
        );
        await _atomicWrite(
          output,
          result.manifestBytes,
          overwrite: options['force'] as bool,
        );
        if (result.assetBytes != null) {
          await _atomicWrite(
            assetOutput!,
            result.assetBytes!,
            overwrite: options['force'] as bool,
          );
        }
      } else {
        final sink = await FileByteSink.open(
          output,
          overwrite: options['force'] as bool,
        );
        try {
          await configured.saveToSource(
            source: source,
            output: sink,
            mimeType: options['mime-type'] as String?,
            fileName: input,
          );
          await sink.close();
        } on Object {
          await sink.abort();
          rethrow;
        }
      }
    } finally {
      await source.close();
    }
    return const CliResult(CliExitCode.success);
  }

  Future<CliResult> _archiveSave(ArgResults options) async {
    _requirePositionals(options, 0, '');
    final output = _requiredOption(options, 'output');
    await _validateOutputs(
      options,
      files: [output],
      inputs: [_requiredOption(options, 'manifest')],
    );
    final context = C2paContext();
    final builder = await _builderFromDefinition(options, context);
    await _atomicWrite(
      output,
      builder
          .withArchiveConfiguration(
            basePath: options['base-path'] as String?,
            remoteManifestUrl: _optionalUri(options['remote-url'] as String?),
            noEmbed: options['no-embed'] as bool,
          )
          .toArchive(),
      overwrite: options['force'] as bool,
    );
    return const CliResult(CliExitCode.success);
  }

  Future<CliResult> _archiveLoad(ArgResults options) async {
    _requirePositionals(options, 0, '');
    final archive = _requiredOption(options, 'archive');
    final output = _requiredOption(options, 'output');
    final input = options['input'] as String?;
    final assetOutput = options['asset-output'] as String?;
    if (assetOutput != null && input == null) {
      throw const _CliUsageException('--asset-output requires --input');
    }
    await _validateOutputs(
      options,
      files: [output, ?assetOutput],
      inputs: [archive, ?input],
    );
    final builder = await _signingBuilderFromArchive(options, archive);
    final createsSidecar = options['no-embed'] as bool || builder.noEmbed;
    if (assetOutput != null && !createsSidecar) {
      throw const _CliUsageException(
        '--asset-output requires --no-embed or a no-embed archive',
      );
    }
    if (assetOutput != null && builder.remoteManifestUrl == null) {
      throw const _CliUsageException(
        '--asset-output requires a remote-manifest archive',
      );
    }
    if (builder.remoteManifestUrl != null &&
        input != null &&
        createsSidecar &&
        assetOutput == null) {
      throw const _CliUsageException(
        'A remote archive requires --asset-output',
      );
    }
    if (input == null) {
      await _atomicWrite(
        output,
        await builder.build(),
        overwrite: options['force'] as bool,
      );
      return const CliResult(CliExitCode.success);
    }
    final source = await _openSource(input, options);
    if (createsSidecar) {
      try {
        final result = await builder.buildSidecar(
          source: source,
          mimeType: options['mime-type'] as String?,
          fileName: input,
        );
        await _atomicWrite(
          output,
          result.manifestBytes,
          overwrite: options['force'] as bool,
        );
        if (result.assetBytes != null) {
          await _atomicWrite(
            assetOutput!,
            result.assetBytes!,
            overwrite: options['force'] as bool,
          );
        }
      } finally {
        await source.close();
      }
      return const CliResult(CliExitCode.success);
    }
    final sink = await FileByteSink.open(
      output,
      overwrite: options['force'] as bool,
    );
    try {
      await builder.saveToSource(
        source: source,
        output: sink,
        mimeType: options['mime-type'] as String?,
        fileName: input,
        embedManifest: !(options['no-embed'] as bool),
      );
      await sink.close();
    } on Object {
      await sink.abort();
      rethrow;
    } finally {
      await source.close();
    }
    return const CliResult(CliExitCode.success);
  }

  Future<CliResult> _remove(ArgResults options) async {
    _requirePositionals(options, 1, '<asset>');
    final output = _requiredOption(options, 'output');
    await _validateOutputs(
      options,
      files: [output],
      inputs: [options.rest.single],
    );
    final source = await _openSource(options.rest.single, options);
    final sink = await FileByteSink.open(
      output,
      overwrite: options['force'] as bool,
    );
    try {
      await AssetHandlerRegistry().removeManifest(
        source,
        sink,
        mimeType: options['mime-type'] as String?,
        fileExtension: _extension(options.rest.single),
      );
      await sink.close();
    } on Object {
      await sink.abort();
      rethrow;
    } finally {
      await source.close();
    }
    return const CliResult(CliExitCode.success);
  }

  Future<CliResult> _replace(ArgResults options) async {
    _requirePositionals(options, 1, '<asset>');
    final manifestPath = _requiredOption(options, 'manifest');
    final output = _requiredOption(options, 'output');
    await _validateOutputs(
      options,
      files: [output],
      inputs: [options.rest.single, manifestPath],
    );
    final manifest = await _readBoundedFile(
      manifestPath,
      _integer(options, 'max-manifest-bytes'),
    );
    final source = await _openSource(options.rest.single, options);
    final sink = await FileByteSink.open(
      output,
      overwrite: options['force'] as bool,
    );
    try {
      await AssetHandlerRegistry().replaceManifest(
        source,
        manifest,
        sink,
        mimeType: options['mime-type'] as String?,
        fileExtension: _extension(options.rest.single),
      );
      await sink.close();
    } on Object {
      await sink.abort();
      rethrow;
    } finally {
      await source.close();
    }
    return const CliResult(CliExitCode.success);
  }

  Future<CliResult> _remote(ArgResults options) async {
    _requirePositionals(options, 1, '<asset>');
    final output = _requiredOption(options, 'output');
    await _validateOutputs(
      options,
      files: [output],
      inputs: [options.rest.single],
    );
    final source = await _openSource(options.rest.single, options);
    try {
      final url = options['url'] as String?;
      final bytes = url == null
          ? await C2paBuilder.removeRemoteManifestReference(
              source: source,
              mimeType: options['mime-type'] as String?,
              fileName: options.rest.single,
            )
          : await C2paBuilder.updateRemoteManifestReference(
              source: source,
              remoteManifestUrl: _optionalUri(url)!,
              mimeType: options['mime-type'] as String?,
              fileName: options.rest.single,
            );
      await _atomicWrite(output, bytes, overwrite: options['force'] as bool);
    } finally {
      await source.close();
    }
    return const CliResult(CliExitCode.success);
  }

  Future<CliResult> _fragmentSign(ArgResults options) async {
    _requirePositionals(options, 0, '');
    final initPath = _requiredOption(options, 'init');
    final fragments = (options['fragment'] as List<String>);
    if (fragments.isEmpty) {
      throw const _CliUsageException(
        'fragment-sign requires at least one --fragment',
      );
    }
    final archivePath = options['archive'] as String?;
    final manifestPath = options['manifest'] as String?;
    if ((archivePath == null) == (manifestPath == null)) {
      throw const _CliUsageException(
        'fragment-sign requires exactly one of --manifest or --archive',
      );
    }
    if (archivePath != null && (options['cert'] as List<String>).isNotEmpty) {
      throw const _CliUsageException('--cert cannot be used with --archive');
    }
    if (options['variable-block-sizes'] as bool &&
        options['fixed-block-size'] != null) {
      throw const _CliUsageException(
        '--fixed-block-size and --variable-block-sizes are mutually exclusive',
      );
    }
    final outputPath = _requiredOption(options, 'output-dir');
    final outputDirectory = Directory(outputPath);
    final generatedOutputs = <String>[
      _containedOutput(outputDirectory, 'init.mp4').path,
      for (var index = 0; index < fragments.length; index++)
        _containedOutput(outputDirectory, 'fragment-$index.m4s').path,
    ];
    await _validateOutputs(
      options,
      files: generatedOutputs,
      directories: [outputPath],
      inputs: [initPath, ...fragments, ?archivePath, ?manifestPath],
    );
    await outputDirectory.create(recursive: true);
    final C2paBuilder builder;
    if (archivePath == null) {
      final algorithm = (options['algorithm'] as String?) ?? 'es256';
      final context = await _signingContext(options, algorithm);
      builder = await _builderFromDefinition(
        options,
        context,
        signingAlgorithm: algorithm,
      );
    } else {
      builder = await _signingBuilderFromArchive(options, archivePath);
    }
    final init = await _openSource(initPath, options);
    final sources = <FileByteSource>[];
    try {
      for (final path in fragments) {
        sources.add(await _openSource(path, options));
      }
      final result = await builder.buildFragmentedBmff(
        initializationSegment: init,
        fragments: sources,
        merkleReservationBytes: _integer(options, 'merkle-reservation'),
        fixedBlockSize: _nullableInteger(options, 'fixed-block-size'),
        useVariableBlockSizes: options['variable-block-sizes'] as bool,
        mimeType: options['mime-type'] as String?,
        fileName: initPath,
      );
      if (result.fragments.length != fragments.length) {
        throw C2paSigningException(
          'Fragment signer returned ${result.fragments.length} fragments for '
          '${fragments.length} inputs',
        );
      }
      await _atomicWrite(
        generatedOutputs.first,
        result.initializationSegment,
        overwrite: options['force'] as bool,
      );
      for (var index = 0; index < result.fragments.length; index++) {
        await _atomicWrite(
          generatedOutputs[index + 1],
          result.fragments[index],
          overwrite: options['force'] as bool,
        );
      }
    } finally {
      await init.close();
      for (final source in sources) {
        await source.close();
      }
    }
    return const CliResult(CliExitCode.success);
  }

  Future<CliResult> _fragmentInspect(ArgResults options) async {
    _requirePositionals(options, 0, '');
    final initPath = _requiredOption(options, 'init');
    final fragmentPaths = options['fragment'] as List<String>;
    if (fragmentPaths.isEmpty) {
      throw const _CliUsageException(
        'fragment-inspect requires at least one --fragment',
      );
    }
    final init = await _openSource(initPath, options);
    final fragments = <FileByteSource>[];
    try {
      for (final path in fragmentPaths) {
        fragments.add(await _openSource(path, options));
      }
      final reader = await C2paReader.fromFragmentedBmff(
        initializationSegment: init,
        fragments: fragments,
        mimeType: options['mime-type'] as String?,
        fileName: initPath,
        context: await _readerContext(options),
      );
      final json = reader.encodeSdkJson(options: _jsonOptions(options));
      return CliResult(
        reader.validationResults.state == ValidationState.invalid
            ? CliExitCode.validation
            : CliExitCode.success,
        stdout: '$json\n',
      );
    } finally {
      await init.close();
      for (final source in fragments) {
        await source.close();
      }
    }
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

  static IngredientAssertionVersion _ingredientVersion(Object? value) =>
      switch (value) {
        null || 3 || '3' || 'v3' => IngredientAssertionVersion.v3,
        1 || '1' || 'v1' => IngredientAssertionVersion.v1,
        2 || '2' || 'v2' => IngredientAssertionVersion.v2,
        _ => throw FormatException('Unsupported ingredient version: $value'),
      };

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

  static Future<void> _atomicWrite(
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

  static Future<void> _validateOutputs(
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

  static Future<String> _canonicalPath(String path) async {
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

  static Future<Directory> _resolveBaseDirectory(Directory base) async {
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

  static File _containedOutput(Directory base, String relative) {
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

  static Future<File> _containedRegularFile(
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
      throw C2paResourceException(
        'Input path is not a regular file: $relative',
      );
    }
    return resolvedCandidate;
  }

  static bool _pathContainedBy(String base, String candidate) {
    final normalizedBase = Directory(base).absolute.uri.normalizePath();
    final normalizedCandidate = File(candidate).absolute.uri.normalizePath();
    if (normalizedCandidate == normalizedBase) return true;
    final basePath = normalizedBase.path.endsWith('/')
        ? normalizedBase.path
        : '${normalizedBase.path}/';
    return normalizedCandidate.path.startsWith(basePath);
  }

  static bool _safeRelative(String value) {
    if (value.isEmpty || value.contains('\u0000')) return false;
    final normalized = value.replaceAll('\\', '/');
    if (normalized.startsWith('/') ||
        RegExp(r'^[A-Za-z]:/').hasMatch(normalized)) {
      return false;
    }
    return !normalized.split('/').any((part) => part.isEmpty || part == '..');
  }

  static String _safeResourceName(String value, int index) {
    var safe = value.replaceAll(RegExp(r'[^A-Za-z0-9._-]'), '_');
    while (safe.contains('..')) {
      safe = safe.replaceAll('..', '_');
    }
    safe = safe.replaceFirst(RegExp(r'^\.+'), '');
    if (safe.isEmpty || safe == '.' || safe == '..') safe = 'resource';
    if (safe.length > 120) safe = safe.substring(0, 120);
    return '${index.toString().padLeft(4, '0')}-$safe';
  }

  static String? _extension(String path) {
    final name = path.replaceAll('\\', '/').split('/').last;
    final index = name.lastIndexOf('.');
    return index <= 0 ? null : name.substring(index + 1);
  }

  static Uri? _optionalUri(String? value) {
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

  static String _requiredOption(ArgResults options, String name) {
    final value = options[name] as String?;
    if (value == null || value.isEmpty) {
      throw _CliUsageException('--$name is required');
    }
    return value;
  }

  static int _integer(ArgResults options, String name) {
    final value = int.tryParse(options[name] as String);
    if (value == null || value <= 0) {
      throw _CliUsageException('--$name must be a positive integer');
    }
    return value;
  }

  static int? _nullableInteger(ArgResults options, String name) {
    final raw = options[name] as String?;
    if (raw == null) return null;
    final value = int.tryParse(raw);
    if (value == null || value <= 0) {
      throw _CliUsageException('--$name must be a positive integer');
    }
    return value;
  }

  static void _requirePositionals(ArgResults options, int count, String usage) {
    if (options.rest.length != count) {
      throw _CliUsageException(
        '${options.name}${usage.isEmpty ? '' : ' $usage'} expects '
        '$count positional argument${count == 1 ? '' : 's'}',
      );
    }
  }

  CliResult _usage(String message) => CliResult(
    CliExitCode.usage,
    stderr: 'Usage error: $message\n\n${_help()}',
  );

  static CliResult _error(int code, String message) =>
      CliResult(code, stderr: 'Error: $message\n');

  String _help() =>
      'c2patool_dart $c2patoolVersion\n\n'
      'Usage: c2patool <command> [options]\n\n'
      'Commands:\n'
      '  inspect           Print SDK, detailed, or crJSON output\n'
      '  validate          Inspect and fail when validation is invalid\n'
      '  extract           Extract a manifest store and resources\n'
      '  sign              Build/sign standalone, embedded, or sidecar output\n'
      '  archive-save      Save a JSON definition as a working archive\n'
      '  archive-load      Load/sign a working archive\n'
      '  remove            Remove an embedded manifest\n'
      '  replace           Replace an embedded manifest\n'
      '  remote            Set/remove an asset remote-manifest URL\n'
      '  fragment-sign     Sign fragmented ISO BMFF input\n'
      '  fragment-inspect  Validate fragmented ISO BMFF input\n\n'
      '${parser.usage}\n';

  String _commandHelp(String name) =>
      'Usage: c2patool $name [options]\n\n'
      '${parser.commands[name]!.usage}\n';
}

final class _CliUsageException implements Exception {
  const _CliUsageException(this.message);
  final String message;
}

ArgParser _createParser() {
  final parser = ArgParser()
    ..addFlag('help', abbr: 'h', negatable: false)
    ..addFlag('version', negatable: false);
  parser.addCommand('inspect', _readerParser()..addOption('output', abbr: 'o'));
  parser.addCommand(
    'validate',
    _readerParser()..addOption('output', abbr: 'o'),
  );
  parser.addCommand(
    'extract',
    _readerParser()
      ..addOption('manifest-output')
      ..addOption('resources'),
  );
  parser.addCommand('sign', _signParser());
  parser.addCommand(
    'archive-save',
    _definitionParser()
      ..addOption('output', abbr: 'o')
      ..addOption('base-path')
      ..addOption('remote-url')
      ..addFlag('no-embed', negatable: false)
      ..addFlag(
        'force',
        negatable: false,
        help: 'Replace existing output paths',
      ),
  );
  parser.addCommand(
    'archive-load',
    _signerParser()
      ..addOption('archive')
      ..addOption('input', abbr: 'i')
      ..addOption('output', abbr: 'o')
      ..addOption('asset-output')
      ..addOption('mime-type')
      ..addFlag('no-embed', negatable: false)
      ..addFlag(
        'force',
        negatable: false,
        help: 'Replace existing output paths',
      )
      ..addOption('max-input-bytes', defaultsTo: '${2 * 1024 * 1024 * 1024}'),
  );
  parser.addCommand('remove', _mutationParser());
  parser.addCommand(
    'replace',
    _mutationParser()
      ..addOption('manifest')
      ..addOption('max-manifest-bytes', defaultsTo: '${64 * 1024 * 1024}'),
  );
  parser.addCommand(
    'remote',
    _mutationParser()..addOption('url', help: 'Omit to remove the URL'),
  );
  parser.addCommand(
    'fragment-sign',
    _signerParser()
      ..addOption('manifest')
      ..addOption('archive')
      ..addMultiOption('cert')
      ..addOption('init')
      ..addMultiOption('fragment')
      ..addOption('output-dir')
      ..addOption('mime-type')
      ..addOption('merkle-reservation', defaultsTo: '1048576')
      ..addOption('fixed-block-size')
      ..addFlag('variable-block-sizes', negatable: false)
      ..addFlag(
        'force',
        negatable: false,
        help: 'Replace an existing output directory',
      )
      ..addOption('max-input-bytes', defaultsTo: '${2 * 1024 * 1024 * 1024}'),
  );
  parser.addCommand(
    'fragment-inspect',
    _readerParser()
      ..addOption('init')
      ..addMultiOption('fragment'),
  );
  return parser;
}

ArgParser _readerParser() => ArgParser()
  ..addFlag('help', abbr: 'h', negatable: false)
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
  ..addMultiOption('trust-list-file', help: 'Local bounded PEM trust-list file')
  ..addMultiOption('cawg-trust-anchor', help: 'Local PEM certificate bundle')
  ..addMultiOption(
    'cawg-trust-list-file',
    help: 'Local bounded PEM CAWG trust-list file',
  );

ArgParser _signParser() => _signerParser()
  ..addOption('manifest')
  ..addOption('archive')
  ..addMultiOption('cert')
  ..addOption('input', abbr: 'i')
  ..addOption('output', abbr: 'o')
  ..addOption('asset-output')
  ..addOption('mime-type')
  ..addFlag('sidecar', negatable: false)
  ..addFlag('no-embed', negatable: false)
  ..addFlag(
    'embed',
    negatable: false,
    help: 'Override an archive configured for no-embed output',
  )
  ..addFlag('force', negatable: false, help: 'Replace existing output paths')
  ..addOption('remote-url')
  ..addOption('max-input-bytes', defaultsTo: '${2 * 1024 * 1024 * 1024}');

ArgParser _definitionParser() => ArgParser()
  ..addFlag('help', abbr: 'h', negatable: false)
  ..addOption('manifest')
  ..addMultiOption('cert')
  ..addOption('algorithm', defaultsTo: 'es256');

ArgParser _signerParser() => ArgParser()
  ..addFlag('help', abbr: 'h', negatable: false)
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

String _normalizeAlgorithm(String value) =>
    value.trim().toLowerCase().replaceAll(RegExp(r'[-_]'), '');

ArgParser _mutationParser() => ArgParser()
  ..addFlag('help', abbr: 'h', negatable: false)
  ..addOption('output', abbr: 'o')
  ..addFlag('force', negatable: false, help: 'Replace an existing output')
  ..addOption('mime-type')
  ..addOption('max-input-bytes', defaultsTo: '${2 * 1024 * 1024 * 1024}');
