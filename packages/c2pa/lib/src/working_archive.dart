import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_io/c2pa_io.dart';

import 'actions.dart';
import 'bmff_hash.dart';
import 'builder.dart';
import 'claim.dart';
import 'context.dart';
import 'exceptions.dart';
import 'ingredient.dart';
import 'intent.dart';
import 'reader.dart';
import 'resource_store.dart';
import 'timestamping.dart';

const _archiveUuid = '633270612d617263686976652d763100';
const _archiveLabel = 'c2pa.archive';
const _archiveFormat = 'c2pa.builder.archive';

/// Callback that resolves external resources while loading an archive.
typedef C2paArchiveResourceResolver = FutureOr<Uint8List?> Function(
  C2paArchiveResourceRequest request,
);

/// External resource request from a C2PA builder archive.
final class C2paArchiveResourceRequest {
  /// Creates an external archive resource request.
  const C2paArchiveResourceRequest({
    required this.uri,
    required this.path,
    this.basePath,
    this.format,
  });

  /// Archive resource URI to satisfy.
  final String uri;

  /// Safe relative path recorded for the external resource.
  final String path;

  /// Optional safe relative base path for resolving [path].
  final String? basePath;

  /// Optional media type recorded for the external resource.
  final String? format;
}

/// Options used when loading a C2PA builder archive.
final class C2paArchiveLoadOptions {
  /// Creates archive load options.
  const C2paArchiveLoadOptions({this.resourceResolver});

  /// Resolver for external resources, or `null` to reject them.
  final C2paArchiveResourceResolver? resourceResolver;
}

/// Encodes [builder] as a deterministic C2PA JUMBF working archive.
Uint8List encodeC2paBuilderArchive(C2paBuilder builder) {
  if (builder.timestamp?.usesCallback == true) {
    throw const C2paArchiveException(
      'Callback timestamp configuration cannot be serialized; '
      'supply a timestamp token before archiving',
    );
  }
  final document = <String, Object?>{
    'format': _archiveFormat,
    'version': 1,
    'builder': {
      'definition': _definitionToJson(builder.definition),
      'signingAlgorithm': builder.signingAlgorithm,
      'x5chain': builder.x5chain.map(_encodeBytes).toList(growable: false),
      if (builder.archiveBasePath != null)
        'basePath': _safeRelativePath(builder.archiveBasePath!),
      if (builder.remoteManifestUrl != null)
        'remoteUrl': builder.remoteManifestUrl.toString(),
      'noEmbed': builder.noEmbed,
      if (builder.cachedOcspResponses.isNotEmpty)
        'ocspResponses': builder.cachedOcspResponses
            .map(_encodeBytes)
            .toList(growable: false),
      if (builder.timestamp?.token case final token?)
        'timestamp': {
          'token': _encodeBytes(token),
          'reservedSize': builder.timestamp!.reservedSize,
          'hashAlgorithm': builder.timestamp!.hashAlgorithm,
        },
      if (builder.archiveExtensions.isNotEmpty)
        'extensions': _jsonValue(builder.archiveExtensions),
    },
  };
  final payload = Uint8List.fromList(
    utf8.encode(jsonEncode(_canonicalJson(document))),
  );
  return JumbfSuperBoxNode(
    description: JumbfDescription.fromUuidHex(
      contentType: _archiveUuid,
      label: _archiveLabel,
    ),
    children: [JumbfJsonNode(payload)],
  ).encode();
}

/// Loads a [C2paBuilder] from JUMBF or legacy ZIP archive bytes.
Future<C2paBuilder> loadC2paBuilderArchive({
  required List<int> bytes,
  required C2paContext context,
  C2paArchiveLoadOptions options = const C2paArchiveLoadOptions(),
}) async {
  final input = Uint8List.fromList(bytes);
  if (_isZip(input)) {
    return _loadLegacyZip(input, context, options);
  }
  return _loadJumbfArchive(input, context, options);
}

Future<C2paBuilder> _loadJumbfArchive(
  Uint8List bytes,
  C2paContext context,
  C2paArchiveLoadOptions options,
) async {
  if (bytes.length > context.settings.maxManifestBytes) {
    throw C2paMalformedArchiveException(
      'Working archive size ${bytes.length} exceeds '
      '${context.settings.maxManifestBytes} bytes',
    );
  }
  try {
    final root = parseJumbf(
      bytes,
      maxNestingDepth: context.settings.maxRecursionDepth,
      maxBoxCount: context.settings.maxJumbfBoxCount,
    );
    Future<C2paBuilder> builderFromUpstreamWorkingStore(
      C2paReader reader,
      C2paContext context,
    ) async {
      final entry = reader.activeManifest;
      final claim = reader.activeClaim;
      if (entry == null || claim == null) {
        throw const C2paMalformedArchiveException(
          'Working-store archive has no active manifest',
        );
      }
      var isBuilderArchive = false;
      final assertions = <AssertionDefinition>[];
      for (final raw in entry.assertions) {
        if (raw.label?.startsWith('org.contentauth.archive.metadata') == true) {
          final metadata = _assertionFromRaw(raw);
          final value = metadata.data;
          if (value is Map && value['archive:type'] == 'builder') {
            isBuilderArchive = true;
          }
          continue;
        }
        final label = raw.label;
        if (label == null ||
            label.startsWith('c2pa.hash.') ||
            label.startsWith('c2pa.actions') ||
            label.startsWith('c2pa.ingredient')) {
          continue;
        }
        assertions.add(_assertionFromRaw(raw));
      }
      if (!isBuilderArchive) {
        throw const C2paMalformedArchiveException(
          'C2PA manifest is not a builder working-store archive',
        );
      }

      final manifestRoot = parseJumbf(reader.manifestBytes);
      final manifestsByLabel = {
        for (final node in manifestRoot.children.whereType<JumbfSuperBoxNode>())
          if (node.label != null) node.label!: node.rawBytes,
      };
      final ingredients = <BuilderIngredient>[];
      for (var index = 0; index < entry.ingredients.length; index++) {
        final ingredient = entry.ingredients[index];
        final id = ingredient.instanceId ?? 'ingredient-$index';
        final activeUrl = ingredient.activeManifest?.url;
        final activeLabel = activeUrl == null
            ? null
            : Uri.decodeComponent(activeUrl.split('/').last);
        ingredients.add(
          BuilderIngredient(
            id: id,
            assertion: ingredient,
            manifestBoxes: [
              if (activeLabel != null && manifestsByLabel[activeLabel] != null)
                manifestsByLabel[activeLabel]!,
            ],
          ),
        );
      }

      final allActions = entry.actions
          .expand((assertion) => assertion.actions)
          .toList(growable: false);
      final generated = allActions.firstOrNull;
      final intent = switch (generated?.action) {
        C2paActionNames.opened
            when ingredients.any(
              (item) => item.assertion.relationship == Relationship.parentOf,
            ) =>
          const BuilderIntent.edit(),
        C2paActionNames.opened => const BuilderIntent.update(),
        _ => BuilderIntent.create(
          generated?.sourceType ?? DigitalSourceType.other,
        ),
      };
      final generator =
          claim.claimGeneratorInfo.firstOrNull ??
          ClaimGeneratorInfo(
            name: claim.claimGenerator ?? 'c2pa-rs working archive',
          );
      return C2paBuilder(
        definition: ManifestDefinition(
          label: entry.label,
          intent: intent,
          generatorInfo: generator,
          title: claim.title,
          format: claim.format ?? 'application/octet-stream',
          instanceId: claim.instanceId,
          hashAlgorithm: claim.algorithm ?? 'sha256',
          softBindingAlgorithm: claim.softAlgorithm,
          assertions: assertions,
          resources: _resourcesFromManifest(entry),
          redactions: claim.redactions,
          ingredients: ingredients,
          actions: generated == null ? allActions : allActions.skip(1),
        ),
        context: context,
        signingAlgorithm: 'es256',
        x5chain: const [],
      );
    }

    if (root.description.contentTypeHex == JumbfUuid.c2paManifestStore) {
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(bytes),
        context: context,
      );
      return await builderFromUpstreamWorkingStore(reader, context);
    }
    if (root.description.contentTypeHex != _archiveUuid ||
        root.label != _archiveLabel ||
        root.children.length != 1 ||
        root.children.single is! JumbfJsonNode) {
      throw const C2paMalformedArchiveException(
        'Not a supported C2PA JUMBF working archive',
      );
    }

    final payload = (root.children.single as JumbfJsonNode).payload;
    final decoded = jsonDecode(utf8.decode(payload));
    final document = _stringMap(decoded, 'working archive');
    if (document['format'] != _archiveFormat || document['version'] != 1) {
      throw const C2paMalformedArchiveException(
        'Unsupported C2PA working archive version',
      );
    }
    return await _builderFromArchiveMap(
      _stringMap(document['builder'], 'archive builder'),
      context,
      options,
    );
  } on C2paArchiveException {
    rethrow;
  } on C2paResourceException catch (error) {
    throw C2paArchiveResourceException(error.message, cause: error);
  } catch (error, stackTrace) {
    throw C2paMalformedArchiveException(
      'Failed to parse the C2PA JUMBF working archive',
      cause: error,
      stackTrace: stackTrace,
    );
  }
}

Future<C2paBuilder> _loadLegacyZip(
  Uint8List bytes,
  C2paContext context,
  C2paArchiveLoadOptions options,
) async {
  try {
    final entries = _readStoredZip(bytes);
    final manifestBytes = entries['manifest.json'];
    if (manifestBytes == null) {
      throw const C2paMalformedArchiveException(
        'Legacy builder archive is missing manifest.json',
      );
    }
    if (manifestBytes.length > context.settings.maxManifestBytes) {
      throw C2paMalformedArchiveException(
        'Legacy manifest.json exceeds ${context.settings.maxManifestBytes} bytes',
      );
    }
    final json = _stringMap(
      jsonDecode(utf8.decode(manifestBytes)),
      'legacy manifest',
    );
    final basePathValue = json['base_path'];
    final basePath = basePathValue == null
        ? null
        : _safeRelativePath(_requiredString(basePathValue, 'base_path'));

    final resourceStore = ResourceStore(settings: context.settings);
    final resources = <ManifestResource>[];
    for (final entry in entries.entries) {
      if (!entry.key.startsWith('resources/') || entry.key == 'resources/') {
        continue;
      }
      final id = entry.key.substring('resources/'.length);
      if (id.isEmpty || id.contains('/')) {
        throw C2paUnsafeArchivePathException(entry.key);
      }
      resourceStore.add(_archiveResourceUri(id), entry.value);
      resources.add(
        ManifestResource(
          label: id,
          format: 'application/octet-stream',
          bytes: entry.value,
        ),
      );
    }

    final ingredients = _legacyIngredients(json, entries);
    for (final entry in entries.entries) {
      if (!entry.key.startsWith('ingredients/') ||
          entry.key == 'ingredients/') {
        continue;
      }
      final parts = entry.key.split('/');
      if (parts.length != 3 ||
          int.tryParse(parts[1]) == null ||
          parts[2].isEmpty) {
        throw C2paMalformedArchiveException(
          'Invalid legacy ingredient resource path: ${entry.key}',
        );
      }
      final label = 'ingredient-${parts[1]}-${parts[2]}';
      resourceStore.add(_archiveResourceUri(label), entry.value);
      resources.add(
        ManifestResource(
          label: label,
          format: 'application/octet-stream',
          bytes: entry.value,
        ),
      );
    }

    final definition = _legacyDefinition(json, resources, ingredients);
    final known = <String>{
      'claim_version',
      'vendor',
      'claim_generator_info',
      'metadata',
      'title',
      'format',
      'instance_id',
      'thumbnail',
      'ingredients',
      'assertions',
      'redactions',
      'label',
      'hash_alg',
      'remote_url',
      'no_embed',
      'timestamp_manifest_labels',
      'base_path',
    };
    return C2paBuilder(
      definition: definition,
      context: context,
      signingAlgorithm: 'es256',
      x5chain: const [],
      archiveBasePath: basePath,
      remoteManifestUrl: _optionalUri(json['remote_url']),
      noEmbed: json['no_embed'] == true,
      archiveExtensions: {
        for (final entry in json.entries)
          if (!known.contains(entry.key))
            entry.key: _decodeJsonValue(entry.value),
      },
    );
  } on C2paArchiveException {
    rethrow;
  } on C2paResourceException catch (error) {
    throw C2paArchiveResourceException(error.message, cause: error);
  } catch (error, stackTrace) {
    throw C2paMalformedArchiveException(
      'Failed to parse legacy C2PA builder archive',
      cause: error,
      stackTrace: stackTrace,
    );
  }
}

Future<C2paBuilder> _builderFromArchiveMap(
  Map<String, Object?> map,
  C2paContext context,
  C2paArchiveLoadOptions options,
) async {
  final basePath = map['basePath'] == null
      ? null
      : _safeRelativePath(_requiredString(map['basePath'], 'basePath'));
  var definition = _definitionFromJson(
    _stringMap(map['definition'], 'manifest definition'),
  );

  final store = ResourceStore(settings: context.settings);
  for (final resource in definition.resources) {
    store.add(_archiveResourceUri(resource.label), resource.bytes);
  }
  final external = map['externalResources'];
  if (external != null) {
    if (external is! List) {
      throw const C2paMalformedArchiveException(
        'externalResources must be an array',
      );
    }
    final resolver = options.resourceResolver;
    if (resolver == null && external.isNotEmpty) {
      throw const C2paArchiveResourceException(
        'External archive resources require a caller-provided resolver',
      );
    }
    final resolved = <ManifestResource>[...definition.resources];
    for (final value in external) {
      final item = _stringMap(value, 'external resource');
      final uri = _requiredString(item['uri'], 'external resource uri');
      final path = _safeRelativePath(
        _requiredString(item['path'], 'external resource path'),
      );
      final format = item['format'] as String? ?? 'application/octet-stream';
      final data = await resolver!(
        C2paArchiveResourceRequest(
          uri: uri,
          path: path,
          basePath: basePath,
          format: format,
        ),
      );
      if (data == null) {
        throw C2paArchiveResourceException(
          'External archive resource was not resolved: $path',
          path: path,
        );
      }
      store.add(_archiveResourceUri(uri), data);
      resolved.add(ManifestResource(label: uri, format: format, bytes: data));
    }
    definition = definition.copyWith(resources: resolved);
  }

  final chain = _optionalList(map['x5chain'])
      .map((item) => _decodeBytes(item, 'x5chain entry'));
  final timestampMap = map['timestamp'] == null
      ? null
      : _stringMap(map['timestamp'], 'timestamp');
  final timestamp = timestampMap == null
      ? null
      : C2paTimestampConfig.token(
          _decodeBytes(timestampMap['token'], 'timestamp token'),
          reservedSize: timestampMap['reservedSize'] as int?,
          hashAlgorithm: timestampMap['hashAlgorithm'] as String? ?? 'sha256',
        );
  return C2paBuilder(
    definition: definition,
    context: context,
    signingAlgorithm: map['signingAlgorithm'] as String? ?? 'es256',
    x5chain: chain,
    archiveBasePath: basePath,
    remoteManifestUrl: _optionalUri(map['remoteUrl']),
    noEmbed: map['noEmbed'] == true,
    archiveExtensions: map['extensions'] == null
        ? const {}
        : _stringMap(_decodeJsonValue(map['extensions']), 'archive extensions'),
    cachedOcspResponses: _optionalList(map['ocspResponses'])
        .map((item) => _decodeBytes(item, 'OCSP response')),
    timestamp: timestamp,
  );
}

/// Creates an edit-mode [C2paBuilder] from a parsed reader.
Future<C2paBuilder> c2paBuilderFromReader({
  required C2paReader reader,
  C2paContext? context,
  String signingAlgorithm = 'es256',
  Iterable<Uint8List> x5chain = const [],
}) async {
  final entry = reader.activeManifest;
  final claim = reader.activeClaim;
  if (entry == null || claim == null) {
    throw const C2paValidationException(
      'A reader with an active manifest is required for editing',
    );
  }
  final assertions = <AssertionDefinition>[];
  for (final raw in entry.assertions) {
    final label = raw.label;
    if (label == null ||
        label.startsWith('c2pa.hash.') ||
        label.startsWith('c2pa.actions') ||
        label.startsWith('c2pa.ingredient') ||
        label.startsWith('org.contentauth.archive.metadata')) {
      continue;
    }
    assertions.add(_assertionFromRaw(raw));
  }
  final resources = _resourcesFromManifest(entry);
  final parent = await BuilderIngredient.fromReader(
    reader: reader,
    relationship: Relationship.parentOf,
  );
  final generator = claim.claimGeneratorInfo.isNotEmpty
      ? claim.claimGeneratorInfo.first
      : ClaimGeneratorInfo(
          name: claim.claimGenerator ?? 'c2pa-dart',
          version: '0.1.0-dev.1',
        );
  return C2paBuilder(
    definition: ManifestDefinition(
      label: '${entry.label}.edit',
      intent: const BuilderIntent.edit(),
      generatorInfo: generator,
      title: claim.title,
      format: claim.format ?? 'application/octet-stream',
      instanceId: '${claim.instanceId}:edit',
      hashAlgorithm: claim.algorithm ?? 'sha256',
      softBindingAlgorithm: claim.softAlgorithm,
      assertions: assertions,
      resources: resources,
      redactions: claim.redactions,
      ingredients: [parent],
    ),
    context: context ?? reader.context,
    signingAlgorithm: signingAlgorithm,
    x5chain: x5chain,
  );
}

AssertionDefinition _assertionFromRaw(C2paRawBox raw) {
  try {
    final node = parseJumbf(raw.bytes);
    final label = node.label ?? raw.label!;
    if (node.description.contentTypeHex == JumbfUuid.json) {
      final payload = node.children.whereType<JumbfJsonNode>().single.payload;
      return AssertionDefinition.json(
        label: label,
        data: jsonDecode(utf8.decode(payload)),
      );
    }
    if (node.description.contentTypeHex == JumbfUuid.cbor) {
      final payload = node.children.whereType<JumbfCborNode>().single.payload;
      return AssertionDefinition.cbor(
        label: label,
        data: decodeCbor(
          payload,
          requireCanonicalMapOrder: false,
          allowIndefiniteLength: true,
        ),
      );
    }
    if (node.description.contentTypeHex == JumbfUuid.c2paEmbeddedFile) {
      final description = node.children
          .whereType<JumbfEmbeddedFileDescriptionNode>()
          .single;
      final payload = node.children
          .whereType<JumbfEmbeddedFileNode>()
          .single
          .payload;
      return AssertionDefinition.binary(
        label: label,
        contentType: description.mediaType,
        data: payload,
      );
    }
    return AssertionDefinition.binary(
      label: label,
      contentType: 'application/x-c2pa-jumbf-assertion',
      data: raw.bytes,
    );
  } catch (error, stackTrace) {
    throw C2paMalformedArchiveException(
      'Unable to preserve assertion ${raw.label}',
      cause: error,
      stackTrace: stackTrace,
    );
  }
}

List<ManifestResource> _resourcesFromManifest(C2paManifestEntry entry) {
  final manifest = parseJumbf(entry.bytes);
  final stores = manifest.children.whereType<JumbfSuperBoxNode>().where(
    (node) => node.description.contentTypeHex == JumbfUuid.c2paDataBoxes,
  );
  if (stores.isEmpty) return const [];
  final result = <ManifestResource>[];
  for (final box in stores.single.children.whereType<JumbfSuperBoxNode>()) {
    final cbor = box.children.whereType<JumbfCborNode>().singleOrNull;
    if (cbor == null) continue;
    final value = decodeCbor(
      cbor.payload,
      requireCanonicalMapOrder: false,
      allowIndefiniteLength: true,
    );
    if (value is! Map || value['format'] is! String) continue;
    final data = value['data'];
    if (data is! Uint8List) continue;
    result.add(
      ManifestResource(
        label: box.label ?? 'resource-${result.length}',
        format: value['format']! as String,
        name: value['name'] as String?,
        dataTypes: (value['data_types'] ?? value['dataTypes']) is List
            ? ((value['data_types'] ?? value['dataTypes']) as List)
                  .whereType<String>()
            : const [],
        extra: {
          for (final entry in value.entries)
            if (!const {
              'format',
              'data',
              'name',
              'data_types',
              'dataTypes',
            }.contains(entry.key))
              entry.key.toString(): entry.value,
        },
        bytes: data,
      ),
    );
  }
  return result;
}

Map<String, Object?> _definitionToJson(ManifestDefinition definition) => {
  'label': definition.label,
  'intent': definition.intent.toJson(),
  'generatorInfo': _jsonValue(definition.generatorInfo.toCborMap()),
  'title': definition.title,
  'format': definition.format,
  'instanceId': definition.instanceId,
  'hashAlgorithm': definition.hashAlgorithm,
  'softBindingAlgorithm': definition.softBindingAlgorithm,
  'assertions': [
    for (final assertion in definition.assertions)
      {
        'label': assertion.label,
        'encoding': assertion.encoding.name,
        if (assertion.contentType != null) 'contentType': assertion.contentType,
        'data': _jsonValue(assertion.data),
      },
  ],
  'resources': [
    for (final resource in definition.resources)
      {
        'label': resource.label,
        'format': resource.format,
        'name': resource.name,
        'dataTypes': resource.dataTypes,
        if (resource.extra.isNotEmpty) 'extra': _jsonValue(resource.extra),
        'bytes': _encodeBytes(resource.bytes),
      },
  ],
  'redactions': definition.redactions,
  'ingredients': [
    for (final ingredient in definition.ingredients)
      {
        'id': ingredient.id,
        'assertion': _jsonValue(ingredient.assertion.toCborMap()),
        'manifestBoxes': ingredient.manifestBoxes
            .map(_encodeBytes)
            .toList(growable: false),
      },
  ],
  'actions': definition.actions
      .map((action) => _jsonValue(action.toCborMap()))
      .toList(growable: false),
  'bmffExclusions': definition.bmffExclusions
      .map((exclusion) => _jsonValue(exclusion.toCborMap()))
      .toList(growable: false),
  'bmffHashName': definition.bmffHashName,
};

ManifestDefinition _definitionFromJson(Map<String, Object?> map) {
  final assertions = _optionalList(map['assertions']).map((value) {
    final item = _stringMap(value, 'assertion');
    final encoding = AssertionEncoding.values.firstWhere(
      (candidate) => candidate.name == item['encoding'],
      orElse: () => throw const C2paMalformedArchiveException(
        'Unknown assertion encoding',
      ),
    );
    final label = _requiredString(item['label'], 'assertion label');
    final data = _decodeJsonValue(item['data']);
    return switch (encoding) {
      AssertionEncoding.json => AssertionDefinition.json(
        label: label,
        data: data,
      ),
      AssertionEncoding.cbor => AssertionDefinition.cbor(
        label: label,
        data: data,
      ),
      AssertionEncoding.binary => AssertionDefinition.binary(
        label: label,
        contentType: _requiredString(
          item['contentType'],
          'assertion contentType',
        ),
        data: _decodeBytes(data, 'assertion data'),
      ),
    };
  });
  final resources = _optionalList(map['resources']).map((value) {
    final item = _stringMap(value, 'resource');
    return ManifestResource(
      label: _requiredString(item['label'], 'resource label'),
      format: _requiredString(item['format'], 'resource format'),
      name: item['name'] as String?,
      dataTypes: _optionalList(item['dataTypes']).whereType<String>(),
      extra: item['extra'] == null
          ? const {}
          : _stringMap(_decodeJsonValue(item['extra']), 'resource extra'),
      bytes: _decodeBytes(item['bytes'], 'resource bytes'),
    );
  });
  final ingredients = _optionalList(map['ingredients']).map((value) {
    final item = _stringMap(value, 'ingredient');
    return BuilderIngredient(
      id: _requiredString(item['id'], 'ingredient id'),
      assertion: IngredientAssertion.fromCbor(
        _decodeJsonValue(item['assertion']),
        version: IngredientAssertionVersion.v3,
      ),
      manifestBoxes: _optionalList(item['manifestBoxes'])
          .map((value) => _decodeBytes(value, 'ingredient manifest')),
    );
  });
  return ManifestDefinition(
    label: _requiredString(map['label'], 'manifest label'),
    intent: BuilderIntent.fromJson(_stringMap(map['intent'], 'builder intent')),
    generatorInfo: ClaimGeneratorInfo.fromCbor(
      _decodeJsonValue(map['generatorInfo']),
    ),
    title: map['title'] as String?,
    format: _requiredString(map['format'], 'manifest format'),
    instanceId: _requiredString(map['instanceId'], 'manifest instanceId'),
    hashAlgorithm: map['hashAlgorithm'] as String? ?? 'sha256',
    softBindingAlgorithm: map['softBindingAlgorithm'] as String?,
    assertions: assertions,
    resources: resources,
    redactions: _optionalList(map['redactions']).cast<String>(),
    ingredients: ingredients,
    actions: _optionalList(map['actions'])
        .map((value) => C2paAction.fromCbor(_decodeJsonValue(value))),
    bmffExclusions: _optionalList(map['bmffExclusions'])
        .map((value) => BmffHashExclusion.fromCbor(_decodeJsonValue(value))),
    bmffHashName: map['bmffHashName'] as String?,
  );
}

ManifestDefinition _legacyDefinition(
  Map<String, Object?> map,
  List<ManifestResource> resources,
  List<BuilderIngredient> ingredients,
) {
  final infoValues = _optionalList(map['claim_generator_info']);
  final generator = infoValues.isEmpty
      ? ClaimGeneratorInfo(name: 'c2pa-rs legacy archive')
      : ClaimGeneratorInfo.fromCbor(_decodeJsonValue(infoValues.first));
  final assertions = <AssertionDefinition>[];
  for (final value in _optionalList(map['assertions'])) {
    final item = _stringMap(value, 'legacy assertion');
    final label = _requiredString(item['label'], 'assertion label');
    final data = _decodeJsonValue(item['data'] ?? item['value']);
    final kind = (item['kind'] ?? item['encoding'])?.toString().toLowerCase();
    assertions.add(
      kind == 'json'
          ? AssertionDefinition.json(label: label, data: data)
          : AssertionDefinition.cbor(label: label, data: data),
    );
  }
  final instanceId =
      map['instance_id'] as String? ?? 'xmp:iid:c2pa-archive-import';
  return ManifestDefinition(
    label:
        map['label'] as String? ??
        'urn:c2pa:archive:${base64Url.encode(utf8.encode(instanceId)).replaceAll('=', '')}',
    intent:
        ingredients.any(
          (item) => item.assertion.relationship == Relationship.parentOf,
        )
        ? const BuilderIntent.edit()
        : const BuilderIntent.create(DigitalSourceType.other),
    generatorInfo: generator,
    title: map['title'] as String?,
    format: map['format'] as String? ?? 'application/octet-stream',
    instanceId: instanceId,
    hashAlgorithm: map['hash_alg'] as String? ?? 'sha256',
    assertions: assertions,
    resources: resources,
    redactions: _optionalList(map['redactions']).cast<String>(),
    ingredients: ingredients,
  );
}

List<BuilderIngredient> _legacyIngredients(
  Map<String, Object?> manifest,
  Map<String, Uint8List> entries,
) {
  final values = _optionalList(manifest['ingredients']);
  final result = <BuilderIngredient>[];
  for (var index = 0; index < values.length; index++) {
    final source = _stringMap(values[index], 'legacy ingredient');
    final instanceId = source['instance_id'] as String?;
    final relationship = switch (source['relationship']) {
      'parentOf' || 'ParentOf' || 'parent_of' => Relationship.parentOf,
      'inputTo' || 'InputTo' || 'input_to' => Relationship.inputTo,
      _ => Relationship.componentOf,
    };
    final activeManifest = source['active_manifest'] as String?;
    final manifestBoxes = <Uint8List>[];
    if (activeManifest != null) {
      for (final entry in entries.entries) {
        if (!entry.key.startsWith('manifests/') || entry.key == 'manifests/') {
          continue;
        }
        final storedLabel = entry.key
            .substring('manifests/'.length)
            .replaceAll('_', ':');
        if (storedLabel.startsWith(activeManifest)) {
          manifestBoxes.add(entry.value);
        }
      }
    }
    const known = {
      'title',
      'format',
      'document_id',
      'instance_id',
      'relationship',
      'description',
      'informational_URI',
      'metadata',
      'label',
    };
    final assertion = IngredientAssertion(
      version: IngredientAssertionVersion.v3,
      relationship: relationship,
      title: source['title'] as String?,
      format: source['format'] as String?,
      documentId: source['document_id'] as String?,
      instanceId: instanceId,
      description: source['description'] as String?,
      informationalUri: source['informational_URI'] as String?,
      metadata: source['metadata'] is Map
          ? _stringMap(
              _decodeJsonValue(source['metadata']),
              'ingredient metadata',
            )
          : const {},
      unknownFields: {
        for (final entry in source.entries)
          if (!known.contains(entry.key))
            'legacy_${entry.key}': _decodeJsonValue(entry.value),
      },
    );
    result.add(
      BuilderIngredient(
        id: instanceId ?? source['label'] as String? ?? 'ingredient-$index',
        assertion: assertion,
        manifestBoxes: manifestBoxes,
      ),
    );
  }
  return result;
}

Object? _jsonValue(Object? value) {
  if (value is Uint8List || value is List<int>) {
    return {'@bytes': base64.encode(value as List<int>)};
  }
  if (value is Map) {
    return {
      for (final entry in value.entries)
        entry.key.toString(): _jsonValue(entry.value),
    };
  }
  if (value is Iterable) {
    return value.map(_jsonValue).toList(growable: false);
  }
  return value;
}

Object? _decodeJsonValue(Object? value) {
  if (value is Map) {
    final map = _stringMap(value, 'archive value');
    if (map.length == 1 && map['@bytes'] is String) {
      return _decodeBytes(map, 'archive bytes');
    }
    return {
      for (final entry in map.entries) entry.key: _decodeJsonValue(entry.value),
    };
  }
  if (value is List) {
    return value.map(_decodeJsonValue).toList(growable: false);
  }
  return value;
}

Map<String, Object?> _canonicalJson(Map<String, Object?> value) {
  final keys = value.keys.toList()..sort();
  return {
    for (final key in keys)
      key: switch (value[key]) {
        final Map<String, Object?> nested => _canonicalJson(nested),
        final Map<Object?, Object?> nested => _canonicalJson(
          nested.map((key, value) => MapEntry(key.toString(), value)),
        ),
        final List<Object?> list =>
          list
              .map(
                (item) => item is Map
                    ? _canonicalJson(
                        item.map(
                          (key, value) => MapEntry(key.toString(), value),
                        ),
                      )
                    : item,
              )
              .toList(growable: false),
        final other => other,
      },
  };
}

Map<String, Object?> _encodeBytes(List<int> value) => {
  '@bytes': base64.encode(value),
};

Uint8List _decodeBytes(Object? value, String name) {
  if (value is Uint8List) return Uint8List.fromList(value);
  if (value is List<int>) return Uint8List.fromList(value);
  final map = value is Map ? _stringMap(value, name) : null;
  final encoded = map?['@bytes'];
  if (encoded is! String) {
    throw C2paMalformedArchiveException('$name must contain encoded bytes');
  }
  try {
    return Uint8List.fromList(base64.decode(encoded));
  } on FormatException catch (error, stackTrace) {
    throw C2paMalformedArchiveException(
      '$name contains invalid base64',
      cause: error,
      stackTrace: stackTrace,
    );
  }
}

Uri? _optionalUri(Object? value) {
  if (value == null) return null;
  final uri = Uri.tryParse(_requiredString(value, 'remote URL'));
  if (uri == null || !uri.isAbsolute) {
    throw const C2paMalformedArchiveException(
      'Archive remote URL must be absolute',
    );
  }
  return uri;
}

String _safeRelativePath(String input) {
  if (input.isEmpty ||
      input.contains('\u0000') ||
      input.contains('\\') ||
      input.startsWith('/') ||
      RegExp(r'^[A-Za-z]:').hasMatch(input) ||
      input.startsWith('//')) {
    throw C2paUnsafeArchivePathException(input);
  }

  var decoded = input;
  for (var index = 0; index < 3; index++) {
    try {
      final next = Uri.decodeComponent(decoded);
      if (next == decoded) break;
      decoded = next;
    } on FormatException {
      throw C2paUnsafeArchivePathException(input);
    }
  }
  if (decoded.contains('\\') ||
      decoded.startsWith('/') ||
      decoded.split('/').any((part) => part == '..' || part == '.')) {
    throw C2paUnsafeArchivePathException(input);
  }
  return input;
}

String _archiveResourceUri(String label) =>
    '/c2pa/archive/${Uri.encodeComponent(label)}';

bool _isZip(Uint8List bytes) =>
    bytes.length >= 4 &&
    bytes[0] == 0x50 &&
    bytes[1] == 0x4b &&
    bytes[2] == 0x03 &&
    bytes[3] == 0x04;

Map<String, Uint8List> _readStoredZip(Uint8List bytes) {
  final end = _findEndOfCentralDirectory(bytes);
  final data = ByteData.sublistView(bytes);
  final count = data.getUint16(end + 10, Endian.little);
  final centralSize = data.getUint32(end + 12, Endian.little);
  final centralOffset = data.getUint32(end + 16, Endian.little);
  if (centralOffset + centralSize > end) {
    throw const C2paMalformedArchiveException(
      'ZIP central directory is out of bounds',
    );
  }
  final result = <String, Uint8List>{};
  var offset = centralOffset;
  for (var index = 0; index < count; index++) {
    if (offset + 46 > bytes.length ||
        data.getUint32(offset, Endian.little) != 0x02014b50) {
      throw const C2paMalformedArchiveException(
        'Malformed ZIP central directory',
      );
    }
    final method = data.getUint16(offset + 10, Endian.little);
    final compressedSize = data.getUint32(offset + 20, Endian.little);
    final uncompressedSize = data.getUint32(offset + 24, Endian.little);
    final nameLength = data.getUint16(offset + 28, Endian.little);
    final extraLength = data.getUint16(offset + 30, Endian.little);
    final commentLength = data.getUint16(offset + 32, Endian.little);
    final localOffset = data.getUint32(offset + 42, Endian.little);
    final nameEnd = offset + 46 + nameLength;
    if (nameEnd + extraLength + commentLength > bytes.length) {
      throw const C2paMalformedArchiveException('Truncated ZIP entry');
    }
    final name = utf8.decode(bytes.sublist(offset + 46, nameEnd));
    _safeRelativePath(
      name.endsWith('/') ? name.substring(0, name.length - 1) : name,
    );
    if (result.containsKey(name)) {
      throw C2paMalformedArchiveException('Duplicate ZIP entry: $name');
    }
    if (method != 0 || compressedSize != uncompressedSize) {
      throw const C2paMalformedArchiveException(
        'Compressed legacy ZIP entries are not supported',
      );
    }
    if (localOffset + 30 > bytes.length ||
        data.getUint32(localOffset, Endian.little) != 0x04034b50) {
      throw const C2paMalformedArchiveException('Malformed ZIP local entry');
    }
    final localNameLength = data.getUint16(localOffset + 26, Endian.little);
    final localExtraLength = data.getUint16(localOffset + 28, Endian.little);
    final payloadOffset = localOffset + 30 + localNameLength + localExtraLength;
    if (payloadOffset + compressedSize > bytes.length) {
      throw const C2paMalformedArchiveException('Truncated ZIP payload');
    }
    result[name] = Uint8List.fromList(
      bytes.sublist(payloadOffset, payloadOffset + compressedSize),
    );
    offset = nameEnd + extraLength + commentLength;
  }
  return result;
}

int _findEndOfCentralDirectory(Uint8List bytes) {
  final data = ByteData.sublistView(bytes);
  final minimum = bytes.length - 22;
  final lower = bytes.length > 65557 ? bytes.length - 65557 : 0;
  for (var offset = minimum; offset >= lower; offset--) {
    if (data.getUint32(offset, Endian.little) == 0x06054b50) return offset;
  }
  throw const C2paMalformedArchiveException(
    'ZIP end-of-central-directory record is missing',
  );
}

Map<String, Object?> _stringMap(Object? value, String name) {
  if (value is! Map) {
    throw C2paMalformedArchiveException('$name must be an object');
  }
  return {
    for (final entry in value.entries)
      if (entry.key is String) entry.key as String: entry.value,
  };
}

List<Object?> _optionalList(Object? value) {
  if (value == null) return const [];
  if (value is! List) {
    throw const C2paMalformedArchiveException(
      'Archive array field has the wrong type',
    );
  }
  return value.cast<Object?>();
}

String _requiredString(Object? value, String name) {
  if (value is! String || value.isEmpty) {
    throw C2paMalformedArchiveException('$name must be a non-empty string');
  }
  return value;
}
