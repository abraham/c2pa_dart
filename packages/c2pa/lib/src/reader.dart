import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:cryptography/cryptography.dart' as cryptography;

import 'actions.dart';
import 'bmff_hash.dart';
import 'box_hash.dart';
import 'cawg_identity.dart';
import 'claim.dart';
import 'collection_hash.dart';
import 'compressed_manifest.dart';
import 'context.dart';
import 'data_hash.dart';
import 'exceptions.dart';
import 'ingredient.dart';
import 'json_utils.dart';
import 'manifest.dart';
import 'remote_manifest.dart';
import 'resource_store.dart';
import 'settings.dart';
import 'signing.dart';
import 'standard_assertions.dart';
import 'validation.dart';
import 'validation_code.dart';

Object? _decodeManifestCbor(List<int> bytes, {int maxNestingDepth = 64}) =>
    decodeCbor(
      bytes,
      maxNestingDepth: maxNestingDepth,
      requireCanonicalMapOrder: false,
      allowIndefiniteLength: true,
    );

final class C2paRawBox {
  C2paRawBox({
    required this.boxType,
    required Uint8List bytes,
    this.contentType,
    this.label,
  }) : bytes = Uint8List.fromList(bytes).asUnmodifiableView();

  final String boxType;
  final String? contentType;
  final String? label;
  final Uint8List bytes;
}

final class C2paManifestEntry {
  C2paManifestEntry({
    required this.label,
    required this.contentType,
    required Uint8List bytes,
    Uint8List? logicalBytes,
    required Uint8List? signatureBytes,
    required Iterable<C2paRawBox> assertions,
    required Iterable<C2paRawBox> unknownBoxes,
    required Iterable<ValidationIssue> structuralIssues,
    Iterable<ValidationIssue> cryptographicIssues = const [],
    Iterable<IngredientAssertion> ingredients = const [],
    Iterable<ActionsAssertion> actions = const [],
    Iterable<C2paStandardAssertion> standardAssertions = const [],
    Iterable<CawgIdentityValidationResult> identityAssertions = const [],
    Iterable<C2paResource> resources = const [],
    this.compression = C2paManifestCompression.none,
    this.claim,
    this.signatureInfo,
  }) : bytes = Uint8List.fromList(bytes).asUnmodifiableView(),
       logicalBytes = Uint8List.fromList(logicalBytes ?? bytes)
           .asUnmodifiableView(),
       signatureBytes = signatureBytes == null
           ? null
           : Uint8List.fromList(signatureBytes).asUnmodifiableView(),
       assertions = List<C2paRawBox>.unmodifiable(assertions),
       unknownBoxes = List<C2paRawBox>.unmodifiable(unknownBoxes),
       structuralIssues = List<ValidationIssue>.unmodifiable(structuralIssues),
       cryptographicIssues = List<ValidationIssue>.unmodifiable(
         cryptographicIssues,
       ),
       ingredients = List<IngredientAssertion>.unmodifiable(ingredients),
       actions = List<ActionsAssertion>.unmodifiable(actions),
       standardAssertions = List<C2paStandardAssertion>.unmodifiable(
         standardAssertions,
       ),
       identityAssertions = List<CawgIdentityValidationResult>.unmodifiable(
         identityAssertions,
       ),
       resources = List<C2paResource>.unmodifiable(resources);

  final String label;
  final String contentType;
  final Uint8List bytes;
  final Uint8List logicalBytes;
  final C2paManifestCompression compression;
  bool get isCompressed => compression == C2paManifestCompression.brotli;
  int get storedSize => bytes.length;
  int get logicalSize => logicalBytes.length;
  final Claim? claim;
  final SignatureInfo? signatureInfo;
  final Uint8List? signatureBytes;
  final List<C2paRawBox> assertions;
  final List<C2paRawBox> unknownBoxes;
  final List<ValidationIssue> structuralIssues;
  final List<ValidationIssue> cryptographicIssues;
  final List<IngredientAssertion> ingredients;
  final List<ActionsAssertion> actions;
  final List<C2paStandardAssertion> standardAssertions;
  final List<CawgIdentityValidationResult> identityAssertions;
  final List<C2paResource> resources;

  List<C2paMetadataAssertion> get metadataAssertions =>
      List<C2paMetadataAssertion>.unmodifiable(
        standardAssertions.whereType<C2paMetadataAssertion>(),
      );
  List<C2paAssertionMetadata> get assertionMetadata =>
      List<C2paAssertionMetadata>.unmodifiable(
        standardAssertions.whereType<C2paAssertionMetadata>(),
      );
  List<C2paSoftBindingAssertion> get softBindings =>
      List<C2paSoftBindingAssertion>.unmodifiable(
        standardAssertions.whereType<C2paSoftBindingAssertion>(),
      );
  List<C2paEmbeddedData> get embeddedData =>
      List<C2paEmbeddedData>.unmodifiable(
        standardAssertions.whereType<C2paEmbeddedData>(),
      );
  List<C2paThumbnail> get thumbnails => List<C2paThumbnail>.unmodifiable(
    standardAssertions.whereType<C2paThumbnail>(),
  );
  List<C2paAssetReferenceAssertion> get assetReferences =>
      List<C2paAssetReferenceAssertion>.unmodifiable(
        standardAssertions.whereType<C2paAssetReferenceAssertion>(),
      );
  List<C2paAssetTypesAssertion> get assetTypes =>
      List<C2paAssetTypesAssertion>.unmodifiable(
        standardAssertions.whereType<C2paAssetTypesAssertion>(),
      );
  List<C2paTimestampAssertion> get timestamps =>
      List<C2paTimestampAssertion>.unmodifiable(
        standardAssertions.whereType<C2paTimestampAssertion>(),
      );
  List<C2paCertificateStatusAssertion> get certificateStatuses =>
      List<C2paCertificateStatusAssertion>.unmodifiable(
        standardAssertions.whereType<C2paCertificateStatusAssertion>(),
      );
  List<C2paLegacyJsonAssertion> get legacyAssertions =>
      List<C2paLegacyJsonAssertion>.unmodifiable(
        standardAssertions.whereType<C2paLegacyJsonAssertion>(),
      );

  List<ValidationIssue> get validationIssues =>
      List<ValidationIssue>.unmodifiable([
        ...structuralIssues,
        ...cryptographicIssues,
      ]);
}

/// Read-only structural view of an embedded or standalone C2PA manifest store.
final class C2paReader {
  C2paReader._({
    required this.context,
    required Uint8List manifestBytes,
    required Map<String, C2paManifestEntry> manifests,
    required Iterable<C2paRawBox> rawManifestEntries,
    required this.activeManifestLabel,
    required this.validationResults,
  }) : manifestBytes = Uint8List.fromList(manifestBytes).asUnmodifiableView(),
       manifests = UnmodifiableMapView(manifests),
       rawManifestEntries = List<C2paRawBox>.unmodifiable(rawManifestEntries);

  static Future<C2paReader> fromSource({
    required RandomAccessByteSource source,
    String? mimeType,
    String? fileName,
    RandomAccessByteSource? manifestSource,
    RandomAccessByteSource? assetSource,
    String? assetMimeType,
    String? assetFileName,
    Iterable<RandomAccessByteSource> fragments = const [],
    bool fragmentedBmff = false,
    C2paCollectionSource? collectionSource,
    C2paContext? context,
  }) async {
    final effectiveContext = context ?? C2paContext();
    await effectiveContext.reportProgress(
      const C2paProgressEvent(phase: C2paProgressPhase.loadingResource),
    );

    Uint8List? manifestBytes;
    Object? extractionError;
    StackTrace? extractionStackTrace;
    try {
      manifestBytes = await AssetHandlerRegistry().extractManifest(
        source,
        mimeType: mimeType,
        fileExtension: _fileExtension(fileName),
      );
    } on UnsupportedIsoBmffFeatureException catch (error, stackTrace) {
      throw C2paUnsupportedException(
        error.message,
        cause: error,
        stackTrace: stackTrace,
      );
    } on ManifestNotFoundException catch (error, stackTrace) {
      extractionError = error;
      extractionStackTrace = stackTrace;
    } on AssetFormatException catch (error, stackTrace) {
      throw C2paParseException(
        error.message,
        stage: C2paParseStage.extraction,
        validationCode: ValidationCode.generalError,
        cause: error,
        stackTrace: stackTrace,
      );
    } on Exception catch (error, stackTrace) {
      throw C2paParseException(
        'Failed to read the asset: $error',
        stage: C2paParseStage.extraction,
        validationCode: ValidationCode.generalError,
        cause: error,
        stackTrace: stackTrace,
      );
    }

    if (manifestBytes == null && manifestSource != null) {
      manifestBytes = await _readAll(manifestSource);
    }

    if (manifestBytes == null) {
      String? remoteReference;
      try {
        remoteReference = await AssetHandlerRegistry()
            .readRemoteManifestReference(
              source,
              mimeType: mimeType,
              fileExtension: _fileExtension(fileName),
            );
      } on UnsupportedXmpOperationException {
        remoteReference = null;
      } on AssetFormatException catch (error, stackTrace) {
        throw C2paParseException(
          error.message,
          stage: C2paParseStage.extraction,
          validationCode: ValidationCode.generalError,
          cause: error,
          stackTrace: stackTrace,
        );
      }
      if (remoteReference != null && remoteReference.trim().isNotEmpty) {
        final remoteUri = Uri.tryParse(remoteReference.trim());
        if (remoteUri == null) {
          throw C2paUriPolicyException(
            'The provenance reference is not a valid URI',
            violation: RemoteManifestPolicyViolation.invalidUri,
            uri: Uri(),
          );
        }
        await effectiveContext.reportProgress(
          C2paProgressEvent(
            phase: C2paProgressPhase.resolvingRemoteManifest,
            uri: remoteUri,
          ),
        );
        manifestBytes = await resolveRemoteManifest(
          uri: remoteUri,
          policy: effectiveContext.remoteManifestPolicy,
          timeout: effectiveContext.settings.networkTimeout,
          resolver: effectiveContext.remoteResolver,
          legacyResolver: effectiveContext.remoteManifestResolver,
          isCancelled: effectiveContext.isCancelled,
        );
      }
    }

    if (manifestBytes == null) {
      final error = extractionError;
      throw C2paParseException(
        error is AssetFormatException
            ? error.message
            : 'Failed to read a C2PA manifest${error == null ? '' : ': $error'}',
        stage: C2paParseStage.extraction,
        validationCode: error is ManifestNotFoundException
            ? ValidationCode.claimMissing
            : ValidationCode.generalError,
        cause: error,
        stackTrace: extractionStackTrace,
      );
    }

    final settings = effectiveContext.settings;
    if (manifestBytes.length > settings.maxManifestBytes) {
      throw C2paParseException(
        'Manifest store size ${manifestBytes.length} exceeds the configured '
        'limit of ${settings.maxManifestBytes} bytes',
        stage: C2paParseStage.jumbf,
        validationCode: ValidationCode.generalError,
      );
    }

    late JumbfSuperBoxNode root;
    try {
      root = parseJumbf(
        manifestBytes,
        maxNestingDepth: settings.maxRecursionDepth,
        maxBoxCount: settings.maxJumbfBoxCount,
      );
    } on JumbfException catch (error, stackTrace) {
      throw C2paParseException(
        error.message,
        stage: C2paParseStage.jumbf,
        validationCode: ValidationCode.generalError,
        cause: error,
        stackTrace: stackTrace,
      );
    }

    if (root.description.contentTypeHex != JumbfUuid.c2paManifestStore ||
        root.label != 'c2pa') {
      throw C2paParseException(
        'The root JUMBF box is not a C2PA manifest store',
        stage: C2paParseStage.manifestStore,
        validationCode: ValidationCode.claimMissing,
      );
    }

    await effectiveContext.reportProgress(
      const C2paProgressEvent(phase: C2paProgressPhase.validating),
    );
    await effectiveContext.reportProgress(
      const C2paProgressEvent(phase: C2paProgressPhase.verifying),
    );

    final bindingSource = assetSource ?? source;
    final bindingMimeType = assetSource == null ? mimeType : assetMimeType;
    final bindingFileName = assetSource == null ? fileName : assetFileName;
    final fragmentList = List<RandomAccessByteSource>.unmodifiable(fragments);
    final fragmentedSource = fragmentList.isEmpty && !fragmentedBmff
        ? null
        : FragmentedIsoBmffSource(
            initializationSegment: bindingSource,
            fragments: fragmentList,
          );
    BoxHashLayout? boxHashLayout;
    try {
      boxHashLayout = await AssetHandlerRegistry().getBoxHashLayout(
        bindingSource,
        mimeType: bindingMimeType,
        fileExtension: _fileExtension(bindingFileName),
      );
    } on UnsupportedHashLayoutException {
      boxHashLayout = null;
    }
    DataHashLayout? dataHashLayout;
    try {
      dataHashLayout = await AssetHandlerRegistry().getDataHashLayout(
        bindingSource,
        mimeType: bindingMimeType,
        fileExtension: _fileExtension(bindingFileName),
      );
    } on UnsupportedHashLayoutException {
      dataHashLayout = null;
    }
    ZipCollectionLayout? collectionHashLayout;
    try {
      collectionHashLayout = await AssetHandlerRegistry()
          .getCollectionHashLayout(
            bindingSource,
            mimeType: bindingMimeType,
            fileExtension: _fileExtension(bindingFileName),
          );
    } on UnsupportedCollectionHashLayoutException {
      collectionHashLayout = null;
    }

    final manifestNodes = root.children
        .whereType<JumbfSuperBoxNode>()
        .where(
          (child) => _manifestTypes.contains(child.description.contentTypeHex),
        )
        .toList(growable: false);
    final activeNode = manifestNodes.lastOrNull;
    final manifests = <String, C2paManifestEntry>{};
    final rawEntries = <C2paRawBox>[];
    var unlabeledManifestIndex = 0;
    for (final child in root.children) {
      rawEntries.add(_rawBox(child));
      if (child is! JumbfSuperBoxNode ||
          !_manifestTypes.contains(child.description.contentTypeHex)) {
        continue;
      }
      final label = child.label ?? '<unlabeled-${unlabeledManifestIndex++}>';
      var logicalNode = child;
      final storedBytes = child.rawBytes;
      var compression = C2paManifestCompression.none;
      if (child.description.contentTypeHex ==
          JumbfUuid.c2paCompressedManifest) {
        try {
          final expanded = decodeCompressedJumbf(
            child.rawBytes,
            maxOutputBytes: settings.maxDecompressedManifestBytes,
            maxNestingDepth: settings.maxRecursionDepth,
            maxBoxCount: settings.maxJumbfBoxCount,
          );
          logicalNode = expanded.manifest;
          compression = C2paManifestCompression.brotli;
        } on Object catch (error) {
          manifests[label] = C2paManifestEntry(
            label: label,
            contentType: JumbfUuid.c2paCompressedManifest,
            bytes: child.rawBytes,
            signatureBytes: null,
            assertions: const [],
            unknownBoxes: const [],
            structuralIssues: [
              ValidationIssue.known(
                code: ValidationCode.manifestCompressedInvalid,
                url: 'self#jumbf=/c2pa/$label',
                explanation: error.toString(),
              ),
            ],
            compression: C2paManifestCompression.invalid,
          );
          continue;
        }
      }
      manifests[label] = await _parseManifest(
        logicalNode,
        label,
        settings.maxRecursionDepth,
        effectiveContext,
        storedBytes: storedBytes,
        compression: compression,
        source: bindingSource,
        boxHashLayout: boxHashLayout,
        dataHashLayout: dataHashLayout,
        fragmentedSource: fragmentedSource,
        collectionHashLayout: collectionHashLayout,
        collectionSource: collectionSource,
        bindingMimeType: bindingMimeType,
        bindingFileName: bindingFileName,
        verifyHardBinding: identical(child, activeNode),
      );
    }

    final activeLabel = manifests.keys.lastOrNull;
    _validateResourceLimits(manifests.values, settings);
    final validationResults = await _structuralResults(
      manifests,
      activeLabel,
      settings,
    );
    return C2paReader._(
      context: effectiveContext,
      manifestBytes: manifestBytes,
      manifests: manifests,
      rawManifestEntries: rawEntries,
      activeManifestLabel: activeLabel,
      validationResults: validationResults,
    );
  }

  static Future<C2paReader> fromFragmentedBmff({
    required RandomAccessByteSource initializationSegment,
    required Iterable<RandomAccessByteSource> fragments,
    String? mimeType,
    String? fileName,
    C2paContext? context,
  }) => fromSource(
    source: initializationSegment,
    mimeType: mimeType,
    fileName: fileName,
    fragments: fragments,
    fragmentedBmff: true,
    context: context,
  );

  final C2paContext context;
  final Uint8List manifestBytes;
  final Map<String, C2paManifestEntry> manifests;
  final List<C2paRawBox> rawManifestEntries;
  final String? activeManifestLabel;
  final ValidationResults validationResults;

  C2paManifestEntry? get activeManifest {
    final label = activeManifestLabel;
    return label == null ? null : manifests[label];
  }

  Claim? get activeClaim => activeManifest?.claim;

  List<C2paResource> get resources => List<C2paResource>.unmodifiable(
    manifests.values.expand((entry) => entry.resources),
  );

  Future<C2paResource> lookupResource(
    String uri, {
    String? manifestLabel,
    bool includeIngredients = true,
  }) async {
    final normalized = uri.contains('#') || uri.startsWith('/')
        ? ResourceStore.normalizeUri(uri)
        : ResourceStore.normalizeUri(
            'self#jumbf=/c2pa.databoxes/${Uri.encodeComponent(uri)}',
          );
    final explicitManifest = _resourceManifestLabel(normalized);
    final scope = explicitManifest != null
        ? {explicitManifest}
        : _resourceScope(
            manifestLabel ?? activeManifestLabel,
            includeIngredients: includeIngredients,
          );
    final requestedLabel = _resourceLabel(normalized);
    final matches = <C2paResource>[
      for (final label in scope)
        for (final resource
            in manifests[label]?.resources ?? const <C2paResource>[])
          if (resource.uri == normalized ||
              (explicitManifest == null && resource.label == requestedLabel))
            resource,
    ];
    if (matches.isEmpty) throw C2paResourceNotFoundException(normalized);
    if (matches.length > 1) {
      throw C2paAmbiguousResourceException(
        normalized,
        matches.map((resource) => resource.uri),
      );
    }
    return matches.single;
  }

  Set<String> _resourceScope(String? root, {required bool includeIngredients}) {
    if (root == null || !manifests.containsKey(root)) return const {};
    final result = <String>{root};
    if (!includeIngredients) return result;
    final pending = <String>[root];
    while (pending.isNotEmpty) {
      final entry = manifests[pending.removeLast()];
      if (entry == null) continue;
      for (final ingredient in entry.ingredients) {
        final reference = ingredient.activeManifest ?? ingredient.c2paManifest;
        final label = reference == null
            ? null
            : _manifestReferenceLabel(reference.url);
        if (label != null &&
            manifests.containsKey(label) &&
            result.add(label)) {
          pending.add(label);
        }
      }
    }
    return result;
  }

  static Future<C2paManifestEntry> _parseManifest(
    JumbfSuperBoxNode node,
    String label,
    int maxNestingDepth,
    C2paContext context, {
    Uint8List? storedBytes,
    C2paManifestCompression compression = C2paManifestCompression.none,
    required RandomAccessByteSource source,
    required BoxHashLayout? boxHashLayout,
    required DataHashLayout? dataHashLayout,
    required FragmentedIsoBmffSource? fragmentedSource,
    required ZipCollectionLayout? collectionHashLayout,
    required C2paCollectionSource? collectionSource,
    required String? bindingMimeType,
    required String? bindingFileName,
    required bool verifyHardBinding,
  }) async {
    final issues = <ValidationIssue>[];
    final cryptographicIssues = <ValidationIssue>[];
    final claimBoxes = <JumbfSuperBoxNode>[];
    final signatureBoxes = <JumbfSuperBoxNode>[];
    final assertionStores = <JumbfSuperBoxNode>[];
    final unknown = <C2paRawBox>[];

    for (final child in node.children) {
      if (child is JumbfSuperBoxNode) {
        switch (child.description.contentTypeHex) {
          case JumbfUuid.c2paClaim:
            claimBoxes.add(child);
          case JumbfUuid.c2paSignature:
            signatureBoxes.add(child);
          case JumbfUuid.c2paAssertionStore:
            assertionStores.add(child);
          default:
            unknown.add(_rawBox(child));
        }
      } else {
        unknown.add(_rawBox(child));
      }
    }

    if (claimBoxes.isEmpty) {
      issues.add(_issue(ValidationCode.claimMissing, label));
    } else if (claimBoxes.length > 1) {
      issues.add(_issue(ValidationCode.claimMultiple, label));
    }
    if (signatureBoxes.isEmpty) {
      issues.add(_issue(ValidationCode.claimSignatureMissing, label));
    } else if (signatureBoxes.length > 1) {
      issues.add(_issue(ValidationCode.claimSignatureMismatch, label));
    }
    if (assertionStores.isEmpty) {
      issues.add(_issue(ValidationCode.assertionMissing, label));
    } else if (assertionStores.length > 1) {
      issues.add(_issue(ValidationCode.generalError, label));
    }

    Claim? claim;
    if (claimBoxes.length == 1) {
      final claimPayload = _singleCborPayload(claimBoxes.single);
      if (claimPayload == null) {
        issues.add(_issue(ValidationCode.claimMalformed, label));
      } else {
        try {
          claim = decodeClaim(
            label: label,
            bytes: claimPayload,
            maxNestingDepth: maxNestingDepth,
            decoder: _decodeManifestCbor,
          );
          if (_signaturePath(claim.signatureUri, label) == null) {
            issues.add(_issue(ValidationCode.claimMalformed, label));
          }
        } on FormatException {
          issues.add(_issue(ValidationCode.claimMalformed, label));
        } on CborDecodingException {
          issues.add(_issue(ValidationCode.claimMalformed, label));
        }
      }
    }

    Uint8List? signatureBytes;
    SignatureInfo? signatureInfo;
    if (signatureBoxes.length == 1) {
      signatureBytes = _singleCborPayload(signatureBoxes.single);
      if (signatureBytes == null) {
        issues.add(_issue(ValidationCode.claimSignatureMismatch, label));
      }
    }

    final assertionNodes = assertionStores.length == 1
        ? assertionStores.single.children.whereType<JumbfSuperBoxNode>().toList(
            growable: false,
          )
        : const <JumbfSuperBoxNode>[];
    final assertions = assertionNodes.map(_rawBox).toList(growable: false);
    final ingredients = <IngredientAssertion>[];
    final actions = <ActionsAssertion>[];
    final standardAssertions = <C2paStandardAssertion>[];
    final cawgAssertions = <(String, CawgIdentityAssertion)>[];
    final identityAssertions = <CawgIdentityValidationResult>[];
    for (final assertion in assertionNodes) {
      final assertionLabel = assertion.label;
      if (assertionLabel == null) continue;
      final payload = _singleCborPayload(assertion);
      if (CawgIdentityLabels.isIdentity(assertionLabel)) {
        if (payload == null) {
          identityAssertions.add(
            CawgIdentityValidationResult(
              assertionLabel: assertionLabel,
              statuses: const [
                CawgValidationStatus(
                  code: CawgStatusCodes.cborInvalid,
                  severity: CawgStatusSeverity.failure,
                ),
              ],
            ),
          );
          continue;
        }
        try {
          cawgAssertions.add((
            assertionLabel,
            CawgIdentityAssertion.decode(payload),
          ));
        } on Object catch (error) {
          identityAssertions.add(
            CawgIdentityValidationResult(
              assertionLabel: assertionLabel,
              statuses: [
                CawgValidationStatus(
                  code: CawgStatusCodes.cborInvalid,
                  severity: CawgStatusSeverity.failure,
                  explanation: error.toString(),
                ),
              ],
            ),
          );
        }
      } else if (_isIngredientLabel(assertionLabel)) {
        if (payload == null) {
          issues.add(
            _issue(ValidationCode.assertionIngredientMalformed, label),
          );
          continue;
        }
        try {
          ingredients.add(
            IngredientAssertion.fromCbor(
              _decodeManifestCbor(payload, maxNestingDepth: maxNestingDepth),
              version: _ingredientVersion(assertionLabel),
            ),
          );
        } on Object {
          issues.add(
            _issue(ValidationCode.assertionIngredientMalformed, label),
          );
        }
      } else if (_isActionsLabel(assertionLabel)) {
        if (payload == null) {
          issues.add(_issue(ValidationCode.assertionActionMalformed, label));
          continue;
        }
        try {
          actions.add(
            ActionsAssertion.fromCbor(
              _decodeManifestCbor(payload, maxNestingDepth: maxNestingDepth),
              version: _actionsVersion(assertionLabel),
            ),
          );
        } on Object {
          issues.add(_issue(ValidationCode.assertionActionMalformed, label));
        }
      } else {
        try {
          final standard = _decodeStandardAssertion(
            assertion,
            assertionLabel,
            maxNestingDepth,
          );
          if (standard != null) standardAssertions.add(standard);
        } on Object {
          issues.add(
            ValidationIssue.known(
              code: _malformedStandardAssertionCode(assertionLabel),
              url:
                  'self#jumbf=/c2pa/$label/c2pa.assertions/'
                  '${Uri.encodeComponent(assertionLabel)}',
            ),
          );
        }
      }
    }
    final ingredientIds = ingredients
        .map((ingredient) => ingredient.instanceId)
        .whereType<String>()
        .toSet();
    for (final actionAssertion in actions) {
      for (final action in actionAssertion.actions) {
        for (final id in action.parameters?.ingredientIds ?? const <String>[]) {
          if (!ingredientIds.contains(id)) {
            issues.add(
              ValidationIssue.known(
                code: ValidationCode.assertionActionIngredientMismatch,
                url:
                    'self#jumbf=/c2pa/$label/c2pa.assertions/'
                    '${actionAssertion.assertionLabel}',
              ),
            );
          }
        }
        if (compression == C2paManifestCompression.brotli &&
            assertionNodes.any((node) {
              final assertionLabel = node.label ?? '';
              return assertionLabel == DataHashAssertion.label ||
                  assertionLabel.startsWith('${DataHashAssertion.label}__') ||
                  assertionLabel == BmffHashAssertion.label ||
                  assertionLabel.startsWith('${BmffHashAssertion.label}__') ||
                  assertionLabel == CollectionHashAssertion.label ||
                  assertionLabel.startsWith(
                    '${CollectionHashAssertion.label}__',
                  );
            })) {
          issues.add(
            ValidationIssue.known(
              code: ValidationCode.manifestCompressedInvalid,
              url: 'self#jumbf=/c2pa/$label',
              explanation:
                  'Compressed manifests require a single-asset BoxHash binding',
            ),
          );
        }
      }
    }
    if (claim != null && assertionStores.length == 1) {
      cryptographicIssues.addAll(
        await _verifyAssertionReferences(claim, label, assertionNodes),
      );
      cryptographicIssues.addAll(
        await _verifyStandardAssertionReferences(
          standardAssertions,
          label,
          assertionNodes,
          claim.algorithm,
        ),
      );
    }
    if (claim != null) {
      final claimAssertions = [
        ...claim.assertions,
        ...claim.createdAssertions,
        ...claim.gatheredAssertions,
      ];
      for (final item in cawgAssertions) {
        identityAssertions.add(
          await const CawgIdentityValidator().validate(
            assertionLabel: item.$1,
            assertion: item.$2,
            claimAssertions: claimAssertions,
            context: context,
            identityAssertions: {
              for (final candidate in cawgAssertions)
                candidate.$1: candidate.$2,
            },
          ),
        );
      }
    }
    if (claim != null && verifyHardBinding) {
      cryptographicIssues.addAll(
        await _verifyHardBinding(
          claim: claim,
          manifestLabel: label,
          assertionNodes: assertionNodes,
          source: source,
          boxHashLayout: boxHashLayout,
          dataHashLayout: dataHashLayout,
          fragmentedSource: fragmentedSource,
          collectionHashLayout: collectionHashLayout,
          collectionSource: collectionSource,
          bindingMimeType: bindingMimeType,
          bindingFileName: bindingFileName,
          context: context,
          compressedManifest: compression == C2paManifestCompression.brotli,
          updateManifest:
              node.description.contentTypeHex == JumbfUuid.c2paUpdateManifest,
          maxNestingDepth: maxNestingDepth,
        ),
      );
    }

    if (claim != null && signatureBoxes.length == 1 && signatureBytes != null) {
      final result = await _verifyClaimSignature(
        claim: claim,
        manifestLabel: label,
        signatureBox: signatureBoxes.single,
        signatureBytes: signatureBytes,
        context: context,
        maxNestingDepth: maxNestingDepth,
      );
      cryptographicIssues.addAll(result.issues);
      signatureInfo = result.signatureInfo;
    }
    final resources = _decodeManifestResources(node, label, maxNestingDepth);

    return C2paManifestEntry(
      label: label,
      contentType: node.description.contentTypeHex,
      bytes: storedBytes ?? node.rawBytes,
      logicalBytes: node.rawBytes,
      compression: compression,
      claim: claim,
      signatureBytes: signatureBytes,
      assertions: assertions,
      unknownBoxes: unknown,
      structuralIssues: issues,
      cryptographicIssues: cryptographicIssues,
      ingredients: ingredients,
      actions: actions,
      standardAssertions: standardAssertions,
      identityAssertions: identityAssertions,
      resources: resources,
      signatureInfo: signatureInfo,
    );
  }

  static List<C2paResource> _decodeManifestResources(
    JumbfSuperBoxNode manifest,
    String manifestLabel,
    int maxNestingDepth,
  ) {
    final result = <C2paResource>[];
    for (final store in manifest.children.whereType<JumbfSuperBoxNode>()) {
      if (store.description.contentTypeHex != JumbfUuid.c2paDataBoxes) continue;
      for (final box in store.children.whereType<JumbfSuperBoxNode>()) {
        final label = box.label;
        final payload = _singleCborPayload(box);
        if (label == null || payload == null) continue;
        final decoded = _decodeManifestCbor(
          payload,
          maxNestingDepth: maxNestingDepth,
        );
        if (decoded is! Map ||
            decoded['format'] is! String ||
            decoded['data'] is! Uint8List) {
          continue;
        }
        final dataTypes = decoded['data_types'] ?? decoded['dataTypes'];
        result.add(
          C2paResource(
            uri:
                'self#jumbf=/c2pa/${Uri.encodeComponent(manifestLabel)}/'
                'c2pa.databoxes/${Uri.encodeComponent(label)}',
            manifestLabel: manifestLabel,
            label: label,
            mimeType: decoded['format']! as String,
            name: decoded['name'] as String?,
            dataTypes: dataTypes is List
                ? dataTypes.whereType<String>()
                : const [],
            unknownFields: {
              for (final entry in decoded.entries)
                if (!const {
                  'format',
                  'data',
                  'name',
                  'data_types',
                  'dataTypes',
                }.contains(entry.key))
                  entry.key.toString(): entry.value,
            },
            bytes: decoded['data']! as Uint8List,
          ),
        );
      }
    }
    return result;
  }

  static void _validateResourceLimits(
    Iterable<C2paManifestEntry> manifests,
    C2paSettings settings,
  ) {
    var count = 0;
    var total = 0;
    for (final resource in manifests.expand((entry) => entry.resources)) {
      count++;
      total += resource.bytes.length;
      if (resource.bytes.length > settings.maxResourceBytes) {
        throw C2paResourceLimitException(
          kind: ResourceLimitKind.resourceBytes,
          limit: settings.maxResourceBytes,
          actual: resource.bytes.length,
        );
      }
      if (count > settings.maxResourceCount) {
        throw C2paResourceLimitException(
          kind: ResourceLimitKind.count,
          limit: settings.maxResourceCount,
          actual: count,
        );
      }
      if (total > settings.maxTotalResourceBytes) {
        throw C2paResourceLimitException(
          kind: ResourceLimitKind.totalBytes,
          limit: settings.maxTotalResourceBytes,
          actual: total,
        );
      }
    }
  }

  static String? _resourceManifestLabel(String uri) {
    final path = _jumbfPath(uri);
    if (path == null ||
        path.length != 4 ||
        path.first != 'c2pa' ||
        path[2] != 'c2pa.databoxes') {
      return null;
    }
    return path[1];
  }

  static String _resourceLabel(String uri) {
    final path = _jumbfPath(uri);
    return path == null || path.isEmpty ? uri : path.last;
  }

  static Future<ValidationResults> _structuralResults(
    Map<String, C2paManifestEntry> manifests,
    String? activeLabel,
    C2paSettings settings,
  ) async {
    if (activeLabel == null) {
      return ValidationResults(
        activeManifest: StatusCodes(
          statuses: [ValidationIssue.known(code: ValidationCode.claimMissing)],
        ),
      );
    }

    final active = manifests[activeLabel]!;
    final ingredientDeltas = <IngredientDeltaValidationResult>[];
    final reachedLabels = <String>{};
    final referencedLabels = <String>{};
    var ingredientCount = 0;

    Future<void> visit(
      C2paManifestEntry owner,
      int depth,
      Set<String> ancestors,
    ) async {
      for (var index = 0; index < owner.ingredients.length; index++) {
        final ingredient = owner.ingredients[index];
        final uri =
            'self#jumbf=/c2pa/${owner.label}/c2pa.assertions/'
            '${_ingredientAssertionLabel(ingredient.version, index)}';
        final statuses = <ValidationIssue>[];
        final manifestReference =
            ingredient.activeManifest ?? ingredient.c2paManifest;
        final targetLabel = manifestReference == null
            ? null
            : _manifestReferenceLabel(manifestReference.url);
        if (targetLabel != null) referencedLabels.add(targetLabel);
        ingredientCount++;
        if (ingredientCount > settings.maxIngredientCount ||
            depth > settings.maxIngredientDepth) {
          statuses.add(
            ValidationIssue.known(
              code: ValidationCode.ingredientManifestMismatch,
              url: ingredient.activeManifest?.url,
              ingredientUri: uri,
              explanation: 'Ingredient recursion limit exceeded',
            ),
          );
        } else {
          final target = targetLabel == null ? null : manifests[targetLabel];
          if (manifestReference == null || target == null) {
            statuses.add(
              ValidationIssue.known(
                code: ValidationCode.ingredientManifestMissing,
                url: manifestReference?.url,
                ingredientUri: uri,
              ),
            );
          } else if (ancestors.contains(targetLabel)) {
            statuses.add(
              ValidationIssue.known(
                code: ValidationCode.ingredientManifestMismatch,
                url: manifestReference.url,
                ingredientUri: uri,
                explanation: 'Ingredient manifest cycle detected',
              ),
            );
          } else {
            final manifestMatches = await _matchesHashedUri(
              manifestReference,
              target.bytes,
              owner.claim?.algorithm,
            );
            statuses.add(
              ValidationIssue.known(
                code: manifestMatches
                    ? ValidationCode.ingredientManifestValidated
                    : ValidationCode.ingredientManifestMismatch,
                url: manifestReference.url,
                ingredientUri: uri,
              ),
            );
            final signatureReference = ingredient.claimSignature;
            if (ingredient.version == IngredientAssertionVersion.v3 &&
                signatureReference == null) {
              statuses.add(
                ValidationIssue.known(
                  code: ValidationCode.ingredientClaimSignatureMissing,
                  ingredientUri: uri,
                ),
              );
            } else if (signatureReference != null) {
              final signatureBox = parseJumbf(target.logicalBytes).children
                  .whereType<JumbfSuperBoxNode>()
                  .where(
                    (node) =>
                        node.description.contentTypeHex ==
                        JumbfUuid.c2paSignature,
                  )
                  .toList(growable: false);
              final signaturePath = _signaturePath(
                signatureReference.url,
                targetLabel!,
              );
              final matches =
                  signatureBox.length == 1 &&
                  signaturePath != null &&
                  !signaturePath.outsideManifest &&
                  await _matchesHashedUri(
                    signatureReference,
                    signatureBox.single.rawBytes,
                    owner.claim?.algorithm,
                  );
              statuses.add(
                ValidationIssue.known(
                  code: matches
                      ? ValidationCode.ingredientClaimSignatureValidated
                      : ValidationCode.ingredientClaimSignatureMismatch,
                  url: signatureReference.url,
                  ingredientUri: uri,
                ),
              );
            }
            statuses.addAll(
              target.validationIssues.map(
                (issue) => ValidationIssue(
                  code: issue.code,
                  url: issue.url,
                  explanation: issue.explanation,
                  ingredientUri: uri,
                ),
              ),
            );
            statuses.addAll(
              ingredient.validationResults?.issues.map(
                    (issue) => ValidationIssue(
                      code: issue.code,
                      url: issue.url,
                      explanation: issue.explanation,
                      ingredientUri: uri,
                    ),
                  ) ??
                  const [],
            );
            reachedLabels.add(targetLabel!);
            await visit(target, depth + 1, {...ancestors, targetLabel});
          }
        }
        ingredientDeltas.add(
          IngredientDeltaValidationResult(
            ingredientAssertionUri: uri,
            validationDeltas: StatusCodes(statuses: statuses),
          ),
        );
      }
    }

    await visit(active, 1, {activeLabel});
    for (final entry in manifests.entries) {
      if (entry.key == activeLabel ||
          reachedLabels.contains(entry.key) ||
          referencedLabels.contains(entry.key) ||
          entry.value.validationIssues.isEmpty) {
        continue;
      }
      ingredientDeltas.add(
        IngredientDeltaValidationResult(
          ingredientAssertionUri: entry.key,
          validationDeltas: StatusCodes(statuses: entry.value.validationIssues),
        ),
      );
    }
    return ValidationResults(
      activeManifest: StatusCodes(statuses: active.validationIssues),
      ingredientDeltas: ingredientDeltas,
    );
  }

  static Uint8List? _singleCborPayload(JumbfSuperBoxNode box) {
    if (box.children.length != 1) return null;
    final child = box.children.single;
    return child is JumbfCborNode ? child.payload : null;
  }

  static C2paRawBox _rawBox(JumbfNode node) {
    if (node is JumbfSuperBoxNode) {
      return C2paRawBox(
        boxType: node.boxType,
        contentType: node.description.contentTypeHex,
        label: node.label,
        bytes: node.rawBytes,
      );
    }
    return C2paRawBox(boxType: node.boxType, bytes: node.rawBytes);
  }

  static ValidationIssue _issue(ValidationCode code, String manifestLabel) =>
      ValidationIssue.known(code: code, url: 'self#jumbf=/c2pa/$manifestLabel');

  static bool _isIngredientLabel(String label) {
    final base = label.split('__').first;
    return base == IngredientAssertion.label ||
        base.startsWith('${IngredientAssertion.label}.v');
  }

  static IngredientAssertionVersion _ingredientVersion(String label) {
    final base = label.split('__').first;
    if (base.endsWith('.v3')) return IngredientAssertionVersion.v3;
    if (base.endsWith('.v2')) return IngredientAssertionVersion.v2;
    if (base == IngredientAssertion.label) return IngredientAssertionVersion.v1;
    throw FormatException('Unsupported ingredient assertion version: $label');
  }

  static String _ingredientAssertionLabel(
    IngredientAssertionVersion version,
    int index,
  ) {
    final base = version == IngredientAssertionVersion.v1
        ? IngredientAssertion.label
        : '${IngredientAssertion.label}.v${version.number}';
    return index == 0 ? base : '${base}__$index';
  }

  static bool _isActionsLabel(String label) {
    final base = label.split('__').first;
    return base == ActionsAssertion.label ||
        base.startsWith('${ActionsAssertion.label}.v');
  }

  static int _actionsVersion(String label) {
    final base = label.split('__').first;
    if (base == ActionsAssertion.label) return 1;
    if (base == ActionsAssertion.versionedLabel) return 2;
    throw FormatException('Unsupported actions assertion version: $label');
  }

  static C2paStandardAssertion? _decodeStandardAssertion(
    JumbfSuperBoxNode assertion,
    String label,
    int maxNestingDepth,
  ) {
    final base = label.split('__').first;
    final version = _versionedLabel(base);
    Object? cbor() {
      final payload = _singleCborPayload(assertion);
      if (payload == null) {
        throw const FormatException('Expected a CBOR assertion');
      }
      return _decodeManifestCbor(payload, maxNestingDepth: maxNestingDepth);
    }

    Map<String, Object?> json() {
      final node = assertion.children.whereType<JumbfJsonNode>().singleOrNull;
      if (node == null) {
        final fallback = _singleCborPayload(assertion);
        if (fallback != null) {
          final decoded = cbor();
          if (decoded is Map) {
            return decoded.map((key, value) => MapEntry(key.toString(), value));
          }
        }
        throw const FormatException('Expected a JSON assertion');
      }
      final decoded = jsonDecode(utf8.decode(node.payload));
      if (decoded is! Map) {
        throw const FormatException('JSON assertion must contain an object');
      }
      return decoded.map((key, value) => MapEntry(key.toString(), value));
    }

    if (base == C2paMetadataAssertion.baseLabel ||
        base.startsWith('${C2paMetadataAssertion.baseLabel}.v')) {
      return C2paMetadataAssertion.fromJson(json(), version: version ?? 1);
    }
    if (base == C2paAssertionMetadata.baseLabel ||
        base.startsWith('${C2paAssertionMetadata.baseLabel}.v')) {
      return C2paAssertionMetadata.fromCbor(cbor(), version: version ?? 1);
    }
    if (base == C2paSoftBindingAssertion.baseLabel) {
      return C2paSoftBindingAssertion.fromCbor(cbor());
    }
    if (base == C2paAssetReferenceAssertion.baseLabel) {
      return C2paAssetReferenceAssertion.fromCbor(cbor());
    }
    if (base == C2paAssetTypesAssertion.baseLabel ||
        base.startsWith('${C2paAssetTypesAssertion.baseLabel}.v')) {
      return C2paAssetTypesAssertion.fromCbor(cbor(), version: version ?? 1);
    }
    if (base == C2paTimestampAssertion.baseLabel) {
      return C2paTimestampAssertion.fromCbor(cbor());
    }
    if (base == C2paCertificateStatusAssertion.baseLabel) {
      return C2paCertificateStatusAssertion.fromCbor(cbor());
    }
    if (base.startsWith('c2pa.thumbnail.')) {
      return C2paThumbnail.fromEmbedded(_decodeEmbeddedData(assertion, label));
    }
    if (base == 'c2pa.embedded-data' ||
        base.startsWith('c2pa.embedded-data.') ||
        base.startsWith('c2pa.icon')) {
      return _decodeEmbeddedData(assertion, label);
    }
    if (base == 'stds.exif' ||
        base == 'stds.schema-org.CreativeWork' ||
        base == 'schema.org' ||
        base.startsWith('stds.schema-org.')) {
      return C2paLegacyJsonAssertion.fromJson(label: base, value: json());
    }
    return null;
  }

  static C2paEmbeddedData _decodeEmbeddedData(
    JumbfSuperBoxNode assertion,
    String label,
  ) {
    final description = assertion.children
        .whereType<JumbfEmbeddedFileDescriptionNode>()
        .singleOrNull;
    final data = assertion.children
        .whereType<JumbfEmbeddedFileNode>()
        .singleOrNull;
    if (description == null || data == null) {
      throw const FormatException('Malformed embedded data assertion');
    }
    return C2paEmbeddedData(
      label: label.split('__').first,
      contentType: description.mediaType,
      bytes: data.payload,
    );
  }

  static int? _versionedLabel(String label) {
    final match = RegExp(r'\.v([0-9]+)$').firstMatch(label);
    return match == null ? null : int.parse(match.group(1)!);
  }

  static ValidationCode _malformedStandardAssertionCode(String label) {
    final base = label.split('__').first;
    if (base.startsWith(C2paMetadataAssertion.baseLabel)) {
      return ValidationCode.assertionMetadataDisallowed;
    }
    if (base == C2paTimestampAssertion.baseLabel) {
      return ValidationCode.assertionTimestampMalformed;
    }
    if (base == 'stds.exif' ||
        base == 'stds.schema-org.CreativeWork' ||
        base == 'schema.org' ||
        base.startsWith('stds.schema-org.')) {
      return ValidationCode.assertionJsonInvalid;
    }
    return ValidationCode.assertionCborInvalid;
  }

  static Future<List<ValidationIssue>> _verifyStandardAssertionReferences(
    List<C2paStandardAssertion> assertions,
    String manifestLabel,
    List<JumbfSuperBoxNode> nodes,
    String? fallbackAlgorithm,
  ) async {
    final byLabel = <String, JumbfSuperBoxNode>{
      for (final node in nodes)
        if (node.label != null) node.label!: node,
    };
    final issues = <ValidationIssue>[];
    for (final metadata in assertions.whereType<C2paAssertionMetadata>()) {
      final reference = metadata.reference;
      if (reference == null) continue;
      final path = _assertionPath(reference.url, manifestLabel);
      final target = path?.outsideManifest == false
          ? byLabel[path!.assertionLabel]
          : null;
      if (target == null ||
          !await _matchesHashedUri(
            reference,
            target.rawBytes,
            fallbackAlgorithm,
          )) {
        issues.add(
          ValidationIssue.known(
            code: ValidationCode.hashedUriMismatch,
            url: reference.url,
          ),
        );
      }
    }
    return issues;
  }

  static String? _manifestReferenceLabel(String value) {
    final path = _jumbfPath(value);
    if (path == null || path.length != 2 || path.first != 'c2pa') return null;
    return path[1];
  }

  static Future<bool> _matchesHashedUri(
    ClaimHashedUri reference,
    Uint8List rawBox,
    String? fallbackAlgorithm,
  ) async {
    final algorithm = _hashAlgorithm(
      reference.algorithm ?? fallbackAlgorithm ?? '',
    );
    if (algorithm == null || reference.hash.length != algorithm.digestLength) {
      return false;
    }
    final digest = await algorithm.digest(_boxPayload(rawBox));
    return _constantTimeEqual(digest, reference.hash);
  }

  static _ManifestPath? _assertionPath(String value, String manifestLabel) {
    final path = _jumbfPath(value);
    if (path == null) return null;
    var index = 0;
    if (path.first == 'c2pa') {
      if (path.length < 4) return null;
      if (path[1] != manifestLabel) {
        return _ManifestPath(path: path, outsideManifest: true);
      }
      index = 2;
    }
    if (path.length != index + 2 || path[index] != 'c2pa.assertions') {
      return null;
    }
    return _ManifestPath(path: path, assertionLabel: path[index + 1]);
  }

  static _ManifestPath? _signaturePath(String value, String manifestLabel) {
    final path = _jumbfPath(value);
    if (path == null) return null;
    var index = 0;
    if (path.first == 'c2pa') {
      if (path.length < 3) return null;
      if (path[1] != manifestLabel) {
        return _ManifestPath(path: path, outsideManifest: true);
      }
      index = 2;
    }
    if (path.length != index + 1 || path[index] != 'c2pa.signature') {
      return null;
    }
    return _ManifestPath(path: path);
  }

  static List<String>? _jumbfPath(String value) {
    final marker = value.indexOf('jumbf=');
    final raw = marker < 0 ? value : value.substring(marker + 6);
    if (raw.contains('?') || raw.contains('#')) return null;
    final parts = <String>[];
    for (final part in raw.split('/').where((part) => part.isNotEmpty)) {
      try {
        final decoded = Uri.decodeComponent(part);
        if (decoded == '.' || decoded == '..' || decoded.contains('/')) {
          return null;
        }
        parts.add(decoded);
      } on FormatException {
        return null;
      }
    }
    return parts.isEmpty ? null : parts;
  }

  static Future<List<ValidationIssue>> _verifyAssertionReferences(
    Claim claim,
    String manifestLabel,
    List<JumbfSuperBoxNode> assertionNodes,
  ) async {
    final issues = <ValidationIssue>[];
    final byLabel = <String, JumbfSuperBoxNode>{};
    for (final node in assertionNodes) {
      final label = node.label;
      if (label != null) byLabel[label] = node;
    }

    final seenPaths = <String>{};
    final declaredLabels = <String>{};

    for (final reference in claim.assertions) {
      final path = _assertionPath(reference.url, manifestLabel);
      if (path == null) {
        issues.add(
          ValidationIssue.known(
            code: ValidationCode.assertionRequiredMissing,
            url: reference.url,
          ),
        );
        continue;
      }
      if (path.outsideManifest) {
        issues.add(
          ValidationIssue.known(
            code: ValidationCode.assertionOutsideManifest,
            url: reference.url,
          ),
        );
        continue;
      }
      final normalized = path.assertionLabel!;
      if (!seenPaths.add(normalized)) {
        issues.add(
          ValidationIssue.known(
            code: ValidationCode.hashedUriMismatch,
            url: reference.url,
            explanation: 'The claim contains a duplicate hashed URI',
          ),
        );
        continue;
      }
      declaredLabels.add(normalized);

      final assertion = byLabel[path.assertionLabel];
      if (assertion == null) {
        issues
          ..add(
            ValidationIssue.known(
              code: ValidationCode.assertionInaccessible,
              url: reference.url,
            ),
          )
          ..add(
            ValidationIssue.known(
              code: ValidationCode.assertionMissing,
              url: reference.url,
            ),
          );
        continue;
      }

      issues.add(
        ValidationIssue.known(
          code: ValidationCode.assertionAccessible,
          url: reference.url,
        ),
      );
      final algorithm = _hashAlgorithm(
        reference.algorithm ?? claim.algorithm ?? 'sha256',
      );
      if (algorithm == null) {
        issues.add(
          ValidationIssue.known(
            code: ValidationCode.algorithmUnsupported,
            url: reference.url,
          ),
        );
        continue;
      }
      final actual = await algorithm.digest(_boxPayload(assertion.rawBytes));
      issues.add(
        ValidationIssue.known(
          code: _constantTimeEqual(actual, reference.hash)
              ? ValidationCode.assertionHashedUriMatch
              : ValidationCode.assertionHashedUriMismatch,
          url: reference.url,
        ),
      );
    }
    for (final assertion in assertionNodes) {
      final assertionLabel = assertion.label;
      if (assertionLabel == null || !declaredLabels.contains(assertionLabel)) {
        issues.add(
          ValidationIssue.known(
            code: ValidationCode.assertionUndeclared,
            url: assertionLabel,
          ),
        );
      }
    }
    return issues;
  }

  static Future<List<ValidationIssue>> _verifyHardBinding({
    required Claim claim,
    required String manifestLabel,
    required List<JumbfSuperBoxNode> assertionNodes,
    required RandomAccessByteSource source,
    required BoxHashLayout? boxHashLayout,
    required DataHashLayout? dataHashLayout,
    required FragmentedIsoBmffSource? fragmentedSource,
    required ZipCollectionLayout? collectionHashLayout,
    required C2paCollectionSource? collectionSource,
    required String? bindingMimeType,
    required String? bindingFileName,
    required C2paContext context,
    required bool updateManifest,
    required bool compressedManifest,
    required int maxNestingDepth,
  }) async {
    final byLabel = <String, JumbfSuperBoxNode>{
      for (final node in assertionNodes)
        if (node.label != null) node.label!: node,
    };
    final bindings = <JumbfSuperBoxNode>[];
    for (final reference in claim.assertions) {
      final path = _assertionPath(reference.url, manifestLabel);
      if (path == null || path.outsideManifest) continue;
      final label = path.assertionLabel!;
      if (label == BoxHashAssertion.label ||
          label.startsWith('${BoxHashAssertion.label}__') ||
          label == DataHashAssertion.label ||
          label.startsWith('${DataHashAssertion.label}__') ||
          label == BmffHashAssertion.label ||
          label.startsWith('${BmffHashAssertion.label}__') ||
          label == CollectionHashAssertion.label ||
          label.startsWith('${CollectionHashAssertion.label}__')) {
        final node = byLabel[label];
        if (node != null) bindings.add(node);
      }
    }
    if (updateManifest) {
      return bindings.isEmpty
          ? const []
          : [
              ValidationIssue.known(
                code: ValidationCode.manifestUpdateInvalid,
                url: 'self#jumbf=/c2pa/$manifestLabel',
              ),
            ];
    }
    if (bindings.isEmpty) {
      return [
        ValidationIssue.known(
          code: ValidationCode.hardBindingsMissing,
          url: 'self#jumbf=/c2pa/$manifestLabel',
        ),
      ];
    }
    if (bindings.length != 1) {
      return [
        ValidationIssue.known(
          code: ValidationCode.hardBindingsMultiple,
          url: 'self#jumbf=/c2pa/$manifestLabel',
        ),
      ];
    }
    final assertionUrl =
        'self#jumbf=/c2pa/$manifestLabel/c2pa.assertions/'
        '${bindings.single.label}';
    final payload = _singleCborPayload(bindings.single);
    final isDataHash =
        bindings.single.label == DataHashAssertion.label ||
        bindings.single.label!.startsWith('${DataHashAssertion.label}__');
    final isBmffHash =
        bindings.single.label == BmffHashAssertion.label ||
        bindings.single.label!.startsWith('${BmffHashAssertion.label}__');
    final isCollectionHash =
        bindings.single.label == CollectionHashAssertion.label ||
        bindings.single.label!.startsWith('${CollectionHashAssertion.label}__');
    if (compressedManifest &&
        (fragmentedSource != null ||
            collectionHashLayout != null ||
            _isBmffMedia(bindingMimeType, bindingFileName))) {
      return [
        ValidationIssue.known(
          code: ValidationCode.manifestCompressedInvalid,
          url: 'self#jumbf=/c2pa/$manifestLabel',
          explanation:
              'Compressed manifests require a single-asset BoxHash binding',
        ),
      ];
    }
    if (payload == null) {
      return [
        ValidationIssue.known(
          code: isDataHash
              ? ValidationCode.assertionDataHashMalformed
              : isBmffHash
              ? ValidationCode.assertionBmffHashMalformed
              : isCollectionHash
              ? ValidationCode.assertionCollectionHashMalformed
              : ValidationCode.assertionBoxesHashMalformed,
          url: assertionUrl,
        ),
      ];
    }
    if (isBmffHash) {
      late BmffHashAssertion bmffHash;
      try {
        final decoded = _decodeManifestCbor(
          payload,
          maxNestingDepth: maxNestingDepth,
        );
        bmffHash = BmffHashAssertion.fromCbor(decoded);
      } on Object {
        return [
          ValidationIssue.known(
            code: ValidationCode.assertionBmffHashMalformed,
            url: assertionUrl,
          ),
        ];
      }
      final result = await _verifyBmffHash(
        bmffHash,
        source,
        claim.algorithm,
        fragmentedSource,
        bindingMimeType,
        bindingFileName,
        context,
      );
      return [
        ValidationIssue.known(
          code: switch (result) {
            _BmffHashResult.match => ValidationCode.assertionBmffHashMatch,
            _BmffHashResult.mismatch =>
              ValidationCode.assertionBmffHashMismatch,
            _BmffHashResult.malformed =>
              ValidationCode.assertionBmffHashMalformed,
          },
          url: assertionUrl,
        ),
      ];
    }
    if (isCollectionHash) {
      late CollectionHashAssertion collectionHash;
      try {
        collectionHash = CollectionHashAssertion.fromCbor(
          _decodeManifestCbor(payload, maxNestingDepth: maxNestingDepth),
        );
      } on FormatException catch (error) {
        return [
          ValidationIssue.known(
            code: error.message.toString().contains('URI')
                ? ValidationCode.assertionCollectionHashInvalidUri
                : ValidationCode.assertionCollectionHashMalformed,
            url: assertionUrl,
          ),
        ];
      } on Object {
        return [
          ValidationIssue.known(
            code: ValidationCode.assertionCollectionHashMalformed,
            url: assertionUrl,
          ),
        ];
      }
      final result = await _verifyCollectionHash(
        collectionHash,
        source,
        collectionHashLayout,
        collectionSource,
        context,
      );
      return [
        ValidationIssue.known(
          code: switch (result) {
            _CollectionHashResult.match =>
              ValidationCode.assertionCollectionHashMatch,
            _CollectionHashResult.mismatch =>
              ValidationCode.assertionCollectionHashMismatch,
            _CollectionHashResult.incorrectFileCount =>
              ValidationCode.assertionCollectionHashIncorrectFileCount,
            _CollectionHashResult.invalidUri =>
              ValidationCode.assertionCollectionHashInvalidUri,
            _CollectionHashResult.malformed =>
              ValidationCode.assertionCollectionHashMalformed,
          },
          url: assertionUrl,
        ),
      ];
    }
    if (isDataHash) {
      late DataHashAssertion dataHash;
      try {
        dataHash = DataHashAssertion.fromCbor(
          _decodeManifestCbor(payload, maxNestingDepth: maxNestingDepth),
        );
      } on Object {
        return [
          ValidationIssue.known(
            code: ValidationCode.assertionDataHashMalformed,
            url: assertionUrl,
          ),
        ];
      }
      final result = await _verifyDataHash(
        dataHash,
        dataHashLayout,
        source,
        claim.algorithm,
        context,
      );
      return [
        ValidationIssue.known(
          code: switch (result) {
            _DataHashResult.match => ValidationCode.assertionDataHashMatch,
            _DataHashResult.mismatch =>
              ValidationCode.assertionDataHashMismatch,
            _DataHashResult.malformed =>
              ValidationCode.assertionDataHashMalformed,
            _DataHashResult.additionalExclusions =>
              ValidationCode.assertionDataHashAdditionalExclusions,
          },
          url: assertionUrl,
        ),
      ];
    }
    late BoxHashAssertion boxHash;
    try {
      boxHash = BoxHashAssertion.fromCbor(
        _decodeManifestCbor(payload, maxNestingDepth: maxNestingDepth),
      );
    } on Object {
      return [
        ValidationIssue.known(
          code: ValidationCode.assertionBoxesHashMalformed,
          url: assertionUrl,
        ),
      ];
    }
    if (boxHashLayout == null) {
      return [
        ValidationIssue.known(
          code: ValidationCode.assertionBoxesHashMismatch,
          url: assertionUrl,
        ),
      ];
    }
    final verified = await _verifyBoxHashEntries(
      boxHash,
      boxHashLayout,
      source,
      claim.algorithm,
    );
    return [
      ValidationIssue.known(
        code: switch (verified) {
          _BoxHashResult.match => ValidationCode.assertionBoxesHashMatch,
          _BoxHashResult.mismatch => ValidationCode.assertionBoxesHashMismatch,
          _BoxHashResult.malformed =>
            ValidationCode.assertionBoxesHashMalformed,
        },
        url: assertionUrl,
      ),
    ];
  }

  static Future<_DataHashResult> _verifyDataHash(
    DataHashAssertion assertion,
    DataHashLayout? layout,
    RandomAccessByteSource source,
    String? claimAlgorithm,
    C2paContext context,
  ) async {
    final algorithm = _hashAlgorithm(
      assertion.algorithm ?? claimAlgorithm ?? '',
    );
    if (algorithm == null ||
        assertion.hash.length != algorithm.digestLength ||
        layout == null) {
      return _DataHashResult.malformed;
    }

    final declared = assertion.exclusions ?? const [];
    final expected = layout.exclusions;
    if (declared.length > expected.length) {
      return _DataHashResult.additionalExclusions;
    }
    var previousEnd = 0;
    for (final range in declared) {
      if (range.length <= 0 ||
          range.start < previousEnd ||
          range.end > layout.sourceLength) {
        return _DataHashResult.malformed;
      }
      previousEnd = range.end;
    }
    if (declared.length != expected.length) return _DataHashResult.mismatch;
    for (var index = 0; index < declared.length; index++) {
      if (declared[index].start != expected[index].range.start ||
          declared[index].length != expected[index].range.length) {
        return _DataHashResult.mismatch;
      }
    }
    final digest = await AssetHashEngine(isCancelled: context.isCancelled)
        .digestExcluding(
          source,
          algorithm,
          declared.map(
            (range) => ByteRange.fromStartAndLength(range.start, range.length),
          ),
        );
    return _constantTimeEqual(digest, assertion.hash)
        ? _DataHashResult.match
        : _DataHashResult.mismatch;
  }

  static Future<_BmffHashResult> _verifyBmffHash(
    BmffHashAssertion assertion,
    RandomAccessByteSource source,
    String? claimAlgorithm,
    FragmentedIsoBmffSource? fragmentedSource,
    String? mimeType,
    String? fileName,
    C2paContext context,
  ) async {
    if (assertion.merkle != null) {
      if (assertion.hash != null || fragmentedSource == null) {
        return _BmffHashResult.malformed;
      }
      return _verifyFragmentedBmffHash(
        assertion,
        fragmentedSource,
        claimAlgorithm,
        mimeType,
        fileName,
        context,
      );
    }
    final algorithm = _hashAlgorithm(
      assertion.algorithm ?? claimAlgorithm ?? '',
    );
    final expectedHash = assertion.hash;
    if (algorithm == null ||
        expectedHash == null ||
        expectedHash.length != algorithm.digestLength) {
      return _BmffHashResult.malformed;
    }
    late IsoBmffHashLayout layout;
    try {
      layout = await AssetHandlerRegistry().getBmffHashLayout(
        source,
        _isoBmffExclusions(assertion.exclusions),
        version: BmffHashAssertion.version,
      );
    } on UnsupportedIsoBmffFeatureException catch (error, stackTrace) {
      throw C2paUnsupportedException(
        error.message,
        cause: error,
        stackTrace: stackTrace,
      );
    } on AssetFormatException {
      return _BmffHashResult.malformed;
    } on ArgumentError {
      return _BmffHashResult.malformed;
    }
    if (layout.boxes.any(
      (box) =>
          box.path == '/moof' ||
          box.path == '/moov/mvex' ||
          box.descendants.any((child) => child.path == '/moov/mvex'),
    )) {
      throw const C2paUnsupportedException(
        'Fragmented BMFF hard bindings are not supported in this SDK slice',
      );
    }
    final digest = await AssetHashEngine(isCancelled: context.isCancelled)
        .digestEvents(
          source,
          algorithm,
          layout.events.map<AssetHashEvent>(
            (event) => switch (event) {
              IsoBmffSourceDigestEvent(:final range) => AssetHashRangeEvent(
                range,
              ),
              IsoBmffOffsetDigestEvent(:final bytes) =>
                AssetHashInjectedBytesEvent(bytes),
            },
          ),
        );
    return _constantTimeEqual(digest, expectedHash)
        ? _BmffHashResult.match
        : _BmffHashResult.mismatch;
  }

  static Future<_BmffHashResult> _verifyFragmentedBmffHash(
    BmffHashAssertion assertion,
    FragmentedIsoBmffSource source,
    String? claimAlgorithm,
    String? mimeType,
    String? fileName,
    C2paContext context,
  ) async {
    final maps = assertion.merkle!;
    if (maps.length != 1) return _BmffHashResult.malformed;
    final map = maps.single;
    final algorithm = _hashAlgorithm(
      map.algorithm ?? assertion.algorithm ?? claimAlgorithm ?? '',
    );
    if (algorithm == null ||
        map.initHash == null ||
        map.initHash!.length != algorithm.digestLength ||
        map.hashes.any((hash) => hash.length != algorithm.digestLength)) {
      return _BmffHashResult.malformed;
    }
    late FragmentedIsoBmffLayout layout;
    try {
      layout = await AssetHandlerRegistry().getFragmentedBmffLayout(
        source,
        _isoBmffExclusions(assertion.exclusions),
        mimeType: mimeType,
        fileExtension: _fileExtension(fileName),
        version: BmffHashAssertion.version,
      );
    } on MalformedAssetFormatException catch (error) {
      return error.message.contains('not ordered')
          ? _BmffHashResult.mismatch
          : _BmffHashResult.malformed;
    } on AssetFormatException {
      return _BmffHashResult.malformed;
    } on ArgumentError {
      return _BmffHashResult.malformed;
    }
    final fragmentSegments = layout.segments.skip(1).toList(growable: false);
    if (map.count != fragmentSegments.length) {
      return _BmffHashResult.mismatch;
    }
    if (map.variableBlockSizes != null) {
      final actualSizes = fragmentSegments
          .map((segment) => _bmffEventLength(segment.hashLayout.events))
          .toList(growable: false);
      if (!deepEquals(map.variableBlockSizes, actualSizes)) {
        return _BmffHashResult.malformed;
      }
    } else if (map.fixedBlockSize case final fixedBlockSize?) {
      if (fragmentSegments.any(
        (segment) =>
            _bmffEventLength(segment.hashLayout.events) > fixedBlockSize,
      )) {
        return _BmffHashResult.malformed;
      }
    }
    final initDigest = await _digestBmffEvents(
      source.initializationSegment,
      layout.segments.first.hashLayout,
      algorithm,
      context,
    );
    if (!_constantTimeEqual(initDigest, map.initHash!)) {
      return _BmffHashResult.mismatch;
    }

    final seenLocations = <int>{};
    for (var index = 0; index < fragmentSegments.length; index++) {
      final segment = fragmentSegments[index];
      final metadata = segment.c2paMetadata
          .where((item) => item.purpose == 'merkle')
          .toList(growable: false);
      if (metadata.length != 1) return _BmffHashResult.malformed;
      late BmffMerkleProof proof;
      try {
        proof = BmffMerkleProof.fromCbor(
          _decodeManifestCbor(
            await source.fragments[index].read(metadata.single.dataRange),
            maxNestingDepth: context.settings.maxRecursionDepth,
          ),
        );
      } on Object {
        return _BmffHashResult.malformed;
      }
      if (proof.uniqueId != map.uniqueId ||
          proof.localId != map.localId ||
          proof.location != index ||
          proof.location >= map.count ||
          (proof.hashes?.any((hash) => hash.length != algorithm.digestLength) ??
              false) ||
          !seenLocations.add(proof.location)) {
        return _BmffHashResult.malformed;
      }
      final leaf = await _digestBmffEvents(
        source.fragments[index],
        segment.hashLayout,
        algorithm,
        context,
      );
      if (!await _verifyMerkleProof(leaf, proof, map, algorithm)) {
        return _BmffHashResult.mismatch;
      }
    }
    return _BmffHashResult.match;
  }

  static Future<Uint8List> _digestBmffEvents(
    RandomAccessByteSource source,
    IsoBmffHashLayout layout,
    HashAlgorithm algorithm,
    C2paContext context,
  ) => AssetHashEngine(isCancelled: context.isCancelled).digestEvents(
    source,
    algorithm,
    layout.events.map<AssetHashEvent>(
      (event) => switch (event) {
        IsoBmffSourceDigestEvent(:final range) => AssetHashRangeEvent(range),
        IsoBmffOffsetDigestEvent(:final bytes) => AssetHashInjectedBytesEvent(
          bytes,
        ),
      },
    ),
  );

  static int _bmffEventLength(Iterable<IsoBmffDigestEvent> events) =>
      events.fold(
        0,
        (length, event) =>
            length +
            switch (event) {
              IsoBmffSourceDigestEvent(:final range) => range.length,
              IsoBmffOffsetDigestEvent(:final bytes) => bytes.length,
            },
      );

  static Future<bool> _verifyMerkleProof(
    Uint8List leaf,
    BmffMerkleProof proof,
    MerkleMap map,
    HashAlgorithm algorithm,
  ) async {
    var value = leaf;
    var index = proof.location;
    var layerSize = map.count;
    var proofIndex = 0;
    while (layerSize > map.hashes.length) {
      if (index.isOdd) {
        if (proofIndex >= (proof.hashes?.length ?? 0)) return false;
        value = Uint8List.fromList(
          await algorithm.digest([...proof.hashes![proofIndex++], ...value]),
        );
      } else if (index + 1 < layerSize) {
        if (proofIndex >= (proof.hashes?.length ?? 0)) return false;
        value = Uint8List.fromList(
          await algorithm.digest([...value, ...proof.hashes![proofIndex++]]),
        );
      }
      index ~/= 2;
      layerSize = (layerSize + 1) ~/ 2;
    }
    return proofIndex == (proof.hashes?.length ?? 0) &&
        index < map.hashes.length &&
        _constantTimeEqual(value, map.hashes[index]);
  }

  static List<IsoBmffExclusion> _isoBmffExclusions(
    Iterable<BmffHashExclusion> exclusions,
  ) => exclusions
      .map(
        (item) => IsoBmffExclusion(
          xpath: item.xpath,
          length: item.length,
          data: item.data.map(
            (data) => IsoBmffDataMatch(offset: data.offset, value: data.value),
          ),
          subset: item.subsets.map(
            (subset) =>
                IsoBmffSubset(offset: subset.offset, length: subset.length),
          ),
          version: item.version,
          flags: item.flags,
          exact: item.exact ?? true,
        ),
      )
      .toList(growable: false);

  static Future<_CollectionHashResult> _verifyCollectionHash(
    CollectionHashAssertion assertion,
    RandomAccessByteSource source,
    ZipCollectionLayout? zipLayout,
    C2paCollectionSource? collectionSource,
    C2paContext context,
  ) async {
    final algorithm = _hashAlgorithm(assertion.algorithm);
    if (algorithm == null ||
        assertion.uris.values.any(
          (entry) =>
              entry.hash == null ||
              entry.hash!.length != algorithm.digestLength ||
              entry.size == null,
        )) {
      return _CollectionHashResult.malformed;
    }
    if (zipLayout != null) {
      final expected = <String, ZipCollectionEntry>{};
      try {
        for (final entry in zipLayout.entries) {
          if (entry.isDirectory) continue;
          final uri = normalizeCollectionUri(entry.uri.path);
          if (expected.containsKey(uri)) {
            return _CollectionHashResult.invalidUri;
          }
          expected[uri] = entry;
        }
      } on FormatException {
        return _CollectionHashResult.invalidUri;
      }
      if (!_sameStringKeys(assertion.uris.keys, expected.keys)) {
        return _CollectionHashResult.incorrectFileCount;
      }
      final centralHash = assertion.zipCentralDirectoryHash;
      if (centralHash == null || centralHash.length != algorithm.digestLength) {
        return _CollectionHashResult.malformed;
      }
      final actualCentral = await AssetHashEngine(
        isCancelled: context.isCancelled,
      ).digestRanges(source, algorithm, zipLayout.centralDirectoryHashRanges);
      if (!_constantTimeEqual(actualCentral, centralHash)) {
        return _CollectionHashResult.mismatch;
      }
      for (final declared in assertion.uris.entries) {
        final actual = expected[declared.key]!;
        final metadata = declared.value;
        if (metadata.size != actual.range.length ||
            (metadata.format != null && metadata.format != actual.mimeType)) {
          return _CollectionHashResult.mismatch;
        }
        final digest = await AssetHashEngine(isCancelled: context.isCancelled)
            .digestRanges(source, algorithm, [actual.range]);
        if (!_constantTimeEqual(digest, metadata.hash!)) {
          return _CollectionHashResult.mismatch;
        }
      }
      return _CollectionHashResult.match;
    }

    if (collectionSource == null || assertion.zipCentralDirectoryHash != null) {
      return _CollectionHashResult.malformed;
    }
    late List<C2paCollectionItem> items;
    try {
      items = List<C2paCollectionItem>.from(await collectionSource.entries());
    } on Object {
      return _CollectionHashResult.mismatch;
    }
    final actual = <String, C2paCollectionItem>{};
    try {
      for (final item in items) {
        final uri = normalizeCollectionUri(item.uri);
        if (actual.containsKey(uri)) {
          return _CollectionHashResult.invalidUri;
        }
        actual[uri] = item;
      }
    } on FormatException {
      return _CollectionHashResult.invalidUri;
    }
    if (!_sameStringKeys(assertion.uris.keys, actual.keys)) {
      return _CollectionHashResult.incorrectFileCount;
    }
    for (final declared in assertion.uris.entries) {
      final item = actual[declared.key]!;
      final metadata = declared.value;
      final length = await item.source.length;
      if (metadata.size != length ||
          (metadata.format != null && metadata.format != item.format) ||
          (metadata.dataTypes != null &&
              !deepEquals(metadata.dataTypes, item.dataTypes))) {
        return _CollectionHashResult.mismatch;
      }
      final digest = await AssetHashEngine(isCancelled: context.isCancelled)
          .digestSource(item.source, algorithm);
      if (!_constantTimeEqual(digest, metadata.hash!)) {
        return _CollectionHashResult.mismatch;
      }
    }
    return _CollectionHashResult.match;
  }

  static bool _sameStringKeys(Iterable<String> left, Iterable<String> right) {
    final expected = right.toSet();
    final actual = left.toSet();
    return actual.length == expected.length && actual.containsAll(expected);
  }

  static Future<_BoxHashResult> _verifyBoxHashEntries(
    BoxHashAssertion assertion,
    BoxHashLayout layout,
    RandomAccessByteSource source,
    String? claimAlgorithm,
  ) async {
    if (assertion.boxes.length != layout.entries.length) {
      return _BoxHashResult.mismatch;
    }
    for (var index = 0; index < assertion.boxes.length; index++) {
      final expected = assertion.boxes[index];
      final actual = layout.entries[index];
      if (!_stringListsEqual(expected.names, actual.names)) {
        return _BoxHashResult.mismatch;
      }
      final physicalExcluded = _isExcludedBox(actual);
      if (expected.excluded != physicalExcluded) {
        return _BoxHashResult.mismatch;
      }
      final isC2pa =
          expected.names.length == 1 && expected.names.single == 'C2PA';
      if (isC2pa &&
          (!expected.excluded ||
              expected.hash.length != 1 ||
              expected.hash.single != 0 ||
              expected.pad.isNotEmpty)) {
        return _BoxHashResult.malformed;
      }
      if (!physicalExcluded) {
        final algorithm = _hashAlgorithm(
          expected.algorithm ?? claimAlgorithm ?? '',
        );
        if (algorithm == null || expected.hash.isEmpty) {
          return _BoxHashResult.malformed;
        }
        final digest = await AssetHashEngine().digestRangesIndependently(
          source,
          algorithm,
          [actual.range],
        );
        if (!_constantTimeEqual(digest.single.digest, expected.hash)) {
          return _BoxHashResult.mismatch;
        }
      }
    }
    return _BoxHashResult.match;
  }

  static bool _isExcludedBox(BoxHashEntry entry) =>
      entry.excluded ||
      (entry.names.length == 1 && entry.names.single == 'C2PA');

  static bool _stringListsEqual(List<String> left, List<String> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }

  static Future<_SignatureValidation> _verifyClaimSignature({
    required Claim claim,
    required String manifestLabel,
    required JumbfSuperBoxNode signatureBox,
    required Uint8List signatureBytes,
    required C2paContext context,
    required int maxNestingDepth,
  }) async {
    final path = _signaturePath(claim.signatureUri, manifestLabel);
    if (path == null ||
        path.outsideManifest ||
        signatureBox.label != 'c2pa.signature') {
      return _SignatureValidation([
        ValidationIssue.known(
          code: ValidationCode.claimSignatureMissing,
          url: claim.signatureUri,
        ),
      ]);
    }

    late CoseSign1 message;
    late _CoseEnvelope envelope;
    try {
      envelope = _CoseEnvelope.parse(
        signatureBytes,
        maxNestingDepth: maxNestingDepth,
      );
      message = CoseSign1.parse(
        envelope.sanitizedBytes,
        maxNestingDepth: maxNestingDepth,
      );
    } on Object {
      return _SignatureValidation([
        ValidationIssue.known(
          code: ValidationCode.claimSignatureMismatch,
          url: claim.signatureUri,
        ),
      ]);
    }

    late SigningAlgorithm algorithm;
    try {
      algorithm = SigningAlgorithm.fromCoseId(
        message.protectedHeaders[CoseHeaderLabel.algorithm] as int,
      );
    } on ArgumentError {
      return _SignatureValidation([
        ValidationIssue.known(
          code: ValidationCode.algorithmUnsupported,
          url: claim.signatureUri,
        ),
      ]);
    }

    final chain = _certificateChain(message);
    if (chain == null ||
        chain.isEmpty ||
        chain.length > context.trust.maxPathDepth) {
      return _SignatureValidation([
        ValidationIssue.known(
          code: ValidationCode.claimSignatureMismatch,
          url: claim.signatureUri,
          explanation: 'The COSE_Sign1 x5chain is missing or malformed',
        ),
        ValidationIssue.known(
          code: ValidationCode.signingCredentialInvalid,
          url: claim.signatureUri,
        ),
      ]);
    }

    late X509Certificate leaf;
    try {
      leaf = X509Certificate.parse(
        chain.first,
        allowUnknownCriticalExtensions: true,
      );
    } on FormatException {
      return _SignatureValidation([
        ValidationIssue.known(
          code: ValidationCode.claimSignatureMismatch,
          url: claim.signatureUri,
        ),
        ValidationIssue.known(
          code: ValidationCode.signingCredentialInvalid,
          url: claim.signatureUri,
        ),
      ]);
    }

    final issues = <ValidationIssue>[];
    final timestamp = await _verifyTimestamp(
      envelope: envelope,
      message: message,
      claim: claim,
      context: context,
    );
    issues.addAll(timestamp.issues);
    var signatureValid = false;
    try {
      final backend = context.verifier == null
          ? await _nativeVerificationBackend(algorithm, leaf)
          : _CallbackVerificationBackend(
              context.verifier!,
              leaf.subjectPublicKeyInfoDer,
            );
      signatureValid = await CoseVerifier(backends: {algorithm: backend})
          .verify(message, payload: claim.rawBytes);
      issues.add(
        ValidationIssue.known(
          code: signatureValid
              ? ValidationCode.claimSignatureValidated
              : ValidationCode.claimSignatureMismatch,
          url: claim.signatureUri,
        ),
      );
    } on UnsupportedBackendException {
      issues.add(
        ValidationIssue.known(
          code: ValidationCode.algorithmUnsupported,
          url: claim.signatureUri,
        ),
      );
    } on PlatformAlgorithmUnavailableException {
      issues.add(
        ValidationIssue.known(
          code: ValidationCode.algorithmUnsupported,
          url: claim.signatureUri,
        ),
      );
    } catch (_) {
      issues.add(
        ValidationIssue.known(
          code: ValidationCode.claimSignatureMismatch,
          url: claim.signatureUri,
        ),
      );
    }

    final evaluationTime =
        timestamp.trustedTime ??
        context.trust.evaluationTime?.toUtc() ??
        DateTime.now().toUtc();
    final insideValidity =
        !evaluationTime.isBefore(leaf.notBefore) &&
        !evaluationTime.isAfter(leaf.notAfter);
    if (signatureValid) {
      issues.add(
        ValidationIssue.known(
          code: insideValidity
              ? ValidationCode.claimSignatureInsideValidity
              : ValidationCode.claimSignatureOutsideValidity,
          url: claim.signatureUri,
        ),
      );
      if (timestamp.trustedTime != null && insideValidity) {
        issues.add(
          ValidationIssue.known(
            code: ValidationCode.timeOfSigningInsideValidity,
            url: claim.signatureUri,
          ),
        );
      }
    }

    final pathResult = await validateCertificatePath(
      chain.first,
      algorithm: algorithm,
      policy: TrustPolicy(
        trustAnchors: context.trust.trustAnchors,
        intermediates: [...chain.skip(1), ...context.trust.intermediates],
        allowedEndEntitySha256Hashes:
            context.trust.allowedEndEntitySha256Hashes,
        allowedEkuOids: context.trust.allowedEkuOids,
        evaluationTime: evaluationTime,
        maxDepth: context.trust.maxPathDepth,
      ),
    );
    final enforceTrust =
        context.trust.verifyTrust ||
        context.trust.trustAnchors.isNotEmpty ||
        context.trust.allowedEndEntitySha256Hashes.isNotEmpty;
    final profileIssues = enforceTrust
        ? const <CertificateProfileIssue>[]
        : validateC2paSignerCertificate(
            leaf,
            algorithm: algorithm,
            atTime: evaluationTime,
            allowedExtendedKeyUsageOids: context.trust.allowedEkuOids,
          );
    if (!insideValidity) {
      issues.add(
        ValidationIssue.known(
          code: ValidationCode.signingCredentialExpired,
          url: claim.signatureUri,
        ),
      );
    }
    if (!enforceTrust) {
      final nonValidityIssues = profileIssues.where(
        (issue) =>
            issue.code != CertificateProfileIssueCode.expired &&
            issue.code != CertificateProfileIssueCode.notYetValid,
      );
      if (nonValidityIssues.isNotEmpty) {
        issues.add(
          ValidationIssue.known(
            code: ValidationCode.signingCredentialInvalid,
            url: claim.signatureUri,
          ),
        );
      } else if (profileIssues.isEmpty) {
        issues.add(
          ValidationIssue.known(
            code: ValidationCode.signingCredentialUntrusted,
            url: claim.signatureUri,
          ),
        );
      }
    } else {
      switch (pathResult.status) {
        case CertificatePathStatus.trusted:
          issues.add(
            ValidationIssue.known(
              code: ValidationCode.signingCredentialTrusted,
              url: claim.signatureUri,
            ),
          );
        case CertificatePathStatus.untrusted:
          issues.add(
            ValidationIssue.known(
              code: ValidationCode.signingCredentialUntrusted,
              url: claim.signatureUri,
            ),
          );
        case CertificatePathStatus.invalid:
          final onlyValidityIssues =
              pathResult.issues.isNotEmpty &&
              pathResult.issues.every(
                (issue) =>
                    issue.code == CertificatePathIssueCode.certificateExpired ||
                    issue.code ==
                        CertificatePathIssueCode.certificateNotYetValid,
              );
          if (!onlyValidityIssues) {
            issues.add(
              ValidationIssue.known(
                code: ValidationCode.signingCredentialInvalid,
                url: claim.signatureUri,
              ),
            );
          }
        case CertificatePathStatus.ambiguous:
          issues.add(
            ValidationIssue.known(
              code: ValidationCode.signingCredentialInvalid,
              url: claim.signatureUri,
            ),
          );
      }
    }
    final ocsp = await _verifyOcsp(
      envelope: envelope,
      leaf: leaf,
      chain: chain,
      pathResult: pathResult,
      evaluationTime: evaluationTime,
      context: context,
      url: claim.signatureUri,
    );
    issues.addAll(ocsp.issues);
    final signatureInfo = SignatureInfo(
      algorithm: algorithm.name,
      issuer: _displayName(leaf.issuer),
      commonName: _nameAttribute(leaf.subject, '2.5.4.3'),
      serialNumber: leaf.serialNumber.toString(),
      notBefore: leaf.notBefore,
      notAfter: leaf.notAfter,
      time: timestamp.trustedTime,
      revocationStatus: ocsp.revocationStatus,
      certificateChain: chain,
    );
    return _SignatureValidation(issues, signatureInfo: signatureInfo);
  }

  static Future<_TimestampValidation> _verifyTimestamp({
    required _CoseEnvelope envelope,
    required CoseSign1 message,
    required Claim claim,
    required C2paContext context,
  }) async {
    final v2 = envelope.textHeaders['sigTst2'];
    final v1 = envelope.textHeaders['sigTst'];
    if (v2 == null && v1 == null) return const _TimestampValidation([]);
    final header = v2 ?? v1;
    var token = _timestampToken(header);
    if (token == null) {
      return _TimestampValidation([
        ValidationIssue.known(
          code: ValidationCode.timestampMalformed,
          url: claim.signatureUri,
        ),
      ]);
    }
    if (v1 != null) {
      token = _timestampTokenFromResponse(token) ?? token;
    }
    final data = v2 != null ? encodeCbor(message.signature) : claim.rawBytes;
    final signedBytes = encodeCbor(<Object?>[
      'CounterSignature',
      message.protectedBytes,
      Uint8List(0),
      data,
    ]);
    final trust = context.timestampTrust;
    final result = await verifyTimestampToken(
      token,
      signedBytes: signedBytes,
      trustPolicy: TrustPolicy(
        trustAnchors: trust.trustAnchors,
        intermediates: trust.intermediates,
        allowedEndEntitySha256Hashes: trust.allowedEndEntitySha256Hashes,
        evaluationTime: trust.evaluationTime,
        maxDepth: trust.maxPathDepth,
      ),
    );
    final issueCodes = result.issues.map((issue) => issue.code).toSet();
    if (issueCodes.contains(TimestampIssueCode.messageImprintMismatch) ||
        issueCodes.contains(TimestampIssueCode.messageDigestMismatch)) {
      return _TimestampValidation([
        ValidationIssue.known(
          code: ValidationCode.timestampMismatch,
          url: claim.signatureUri,
        ),
      ]);
    }
    switch (result.status) {
      case TimestampStatus.valid:
        return _TimestampValidation([
          ValidationIssue.known(
            code: ValidationCode.timestampValidated,
            url: claim.signatureUri,
          ),
          ValidationIssue.known(
            code: ValidationCode.timestampTrusted,
            url: claim.signatureUri,
          ),
        ], trustedTime: result.token?.timestampInfo.genTime.toUtc());
      case TimestampStatus.untrusted:
        return _TimestampValidation([
          ValidationIssue.known(
            code: ValidationCode.timestampValidated,
            url: claim.signatureUri,
          ),
          ValidationIssue.known(
            code: ValidationCode.timestampUntrusted,
            url: claim.signatureUri,
          ),
        ]);
      case TimestampStatus.invalid:
        final outsideValidity =
            issueCodes.contains(TimestampIssueCode.tsaCertificateProfile) &&
            (result.pathResult?.issues.any(
                  (issue) =>
                      issue.code ==
                          CertificatePathIssueCode.certificateExpired ||
                      issue.code ==
                          CertificatePathIssueCode.certificateNotYetValid,
                ) ??
                false);
        final untrusted = issueCodes.any(
          const {
            TimestampIssueCode.signerCertificateNotFound,
            TimestampIssueCode.signatureAlgorithmMismatch,
            TimestampIssueCode.invalidCmsSignature,
            TimestampIssueCode.tsaCertificateProfile,
            TimestampIssueCode.untrustedCertificatePath,
            TimestampIssueCode.unsupportedAlgorithm,
          }.contains,
        );
        return _TimestampValidation([
          ValidationIssue.known(
            code: outsideValidity
                ? ValidationCode.timestampOutsideValidity
                : untrusted
                ? ValidationCode.timestampUntrusted
                : ValidationCode.timestampMalformed,
            url: claim.signatureUri,
          ),
        ]);
      case TimestampStatus.malformed:
      case TimestampStatus.unsupported:
        return _TimestampValidation([
          ValidationIssue.known(
            code: ValidationCode.timestampMalformed,
            url: claim.signatureUri,
          ),
        ]);
    }
  }

  static Future<_OcspValidation> _verifyOcsp({
    required _CoseEnvelope envelope,
    required X509Certificate leaf,
    required List<Uint8List> chain,
    required CertificatePathValidationResult pathResult,
    required DateTime evaluationTime,
    required C2paContext context,
    required String url,
  }) async {
    final rVals = envelope.textHeaders['rVals'];
    final stapled = _firstByteString(rVals, 'ocspVals');
    if (rVals != null && stapled == null) {
      return _OcspValidation([
        ValidationIssue.known(
          code: ValidationCode.signingCredentialOcspUnknown,
          url: url,
        ),
      ]);
    }
    final issuer = chain.length > 1
        ? _parseCertificate(chain[1])
        : pathResult.path.length > 1
        ? pathResult.path[1]
        : null;
    if (stapled == null &&
        (!context.settings.enableOcspFetch ||
            !context.settings.allowNetworkAccess ||
            context.ocspTransport == null)) {
      return _OcspValidation([
        ValidationIssue.known(
          code: ValidationCode.signingCredentialOcspSkipped,
          url: url,
        ),
      ]);
    }
    if (issuer == null) {
      return _OcspValidation([
        ValidationIssue.known(
          code: stapled == null
              ? ValidationCode.signingCredentialOcspInaccessible
              : ValidationCode.signingCredentialOcspUnknown,
          url: url,
        ),
      ]);
    }
    final trust = context.trust;
    final policy = TrustPolicy(
      trustAnchors: trust.trustAnchors,
      intermediates: [...chain.skip(1), ...trust.intermediates],
      allowedEndEntitySha256Hashes: trust.allowedEndEntitySha256Hashes,
      evaluationTime: evaluationTime,
      maxDepth: trust.maxPathDepth,
    );
    late OcspVerificationResult result;
    try {
      if (stapled != null) {
        result = await verifyOcspResponse(
          stapled,
          certificate: leaf,
          issuer: issuer,
          trustPolicy: policy,
          evaluationTime: evaluationTime,
          maxAgeWithoutNextUpdate: context.settings.ocspMaxAgeWithoutNextUpdate,
          clockSkew: context.settings.ocspClockSkew,
        );
      } else {
        if (leaf.ocspUrls.isEmpty || context.settings.maxNetworkBytes < 1) {
          return _OcspValidation([
            ValidationIssue.known(
              code: ValidationCode.signingCredentialOcspInaccessible,
              url: url,
            ),
          ]);
        }
        result = await fetchAndVerifyOcsp(
          endpoint: leaf.ocspUrls.first,
          certificate: leaf,
          issuer: issuer,
          trustPolicy: policy,
          transport: (endpoint, request) => context
              .ocspTransport!(endpoint, Uint8List.fromList(request))
              .timeout(context.settings.networkTimeout),
          evaluationTime: evaluationTime,
          maxAgeWithoutNextUpdate: context.settings.ocspMaxAgeWithoutNextUpdate,
          clockSkew: context.settings.ocspClockSkew,
          maxRequestBytes: context.settings.maxOcspRequestBytes,
          maxResponseBytes:
              context.settings.maxOcspResponseBytes <
                  context.settings.maxNetworkBytes
              ? context.settings.maxOcspResponseBytes
              : context.settings.maxNetworkBytes,
        );
      }
    } on Object {
      return _OcspValidation([
        ValidationIssue.known(
          code: stapled == null
              ? ValidationCode.signingCredentialOcspInaccessible
              : ValidationCode.signingCredentialOcspUnknown,
          url: url,
        ),
      ]);
    }
    return switch (result.status) {
      OcspResultStatus.good => _OcspValidation([
        ValidationIssue.known(
          code: ValidationCode.signingCredentialNotRevoked,
          url: url,
        ),
      ], revocationStatus: true),
      OcspResultStatus.revoked => _OcspValidation([
        ValidationIssue.known(
          code: ValidationCode.signingCredentialRevoked,
          url: url,
        ),
      ], revocationStatus: false),
      OcspResultStatus.unknown || OcspResultStatus.malformed => _OcspValidation(
        [
          ValidationIssue.known(
            code: ValidationCode.signingCredentialOcspUnknown,
            url: url,
          ),
        ],
      ),
      OcspResultStatus.inaccessible => _OcspValidation([
        ValidationIssue.known(
          code: ValidationCode.signingCredentialOcspInaccessible,
          url: url,
        ),
      ]),
    };
  }

  static X509Certificate? _parseCertificate(List<int> der) {
    try {
      return X509Certificate.parse(der, allowUnknownCriticalExtensions: true);
    } on FormatException {
      return null;
    }
  }

  static Uint8List? _firstByteString(Object? value, String key) {
    if (value is! Map || value[key] is! List) return null;
    final values = value[key] as List;
    if (values.isEmpty) return null;
    final first = values.first;
    return first is Uint8List ? Uint8List.fromList(first) : null;
  }

  static Uint8List? _timestampToken(Object? value) {
    if (value is! Map || value['tstTokens'] is! List) return null;
    final values = value['tstTokens'] as List;
    if (values.length != 1 || values.single is! Map) return null;
    final token = (values.single as Map)['val'];
    return token is Uint8List ? Uint8List.fromList(token) : null;
  }

  static Uint8List? _timestampTokenFromResponse(Uint8List response) {
    try {
      final outer = _readDerElement(response, 0);
      if (outer.tag != 0x30 || outer.end != response.length) return null;
      final status = _readDerElement(response, outer.contentStart);
      if (status.tag != 0x30 || status.end >= outer.end) return null;
      final token = _readDerElement(response, status.end);
      if (token.tag != 0x30 || token.end != outer.end) return null;
      return Uint8List.sublistView(response, status.end, token.end);
    } on FormatException {
      return null;
    }
  }

  static _DerSlice _readDerElement(Uint8List bytes, int offset) {
    if (offset + 2 > bytes.length) {
      throw const FormatException('Truncated DER element');
    }
    final tag = bytes[offset];
    final firstLength = bytes[offset + 1];
    var cursor = offset + 2;
    late int length;
    if (firstLength < 0x80) {
      length = firstLength;
    } else {
      final width = firstLength & 0x7f;
      if (width == 0 || width > 4 || cursor + width > bytes.length) {
        throw const FormatException('Invalid DER length');
      }
      length = 0;
      for (var index = 0; index < width; index++) {
        length = (length << 8) | bytes[cursor++];
      }
    }
    final end = cursor + length;
    if (end > bytes.length) throw const FormatException('Truncated DER value');
    return _DerSlice(tag: tag, contentStart: cursor, end: end);
  }

  static List<Uint8List>? _certificateChain(CoseSign1 message) {
    final value =
        message.protectedHeaders[CoseHeaderLabel.x509Chain] ??
        message.unprotectedHeaders[CoseHeaderLabel.x509Chain];
    if (value is Uint8List) return [Uint8List.fromList(value)];
    if (value is List &&
        value.isNotEmpty &&
        value.every((item) => item is Uint8List)) {
      return List<Uint8List>.unmodifiable(
        value.cast<Uint8List>().map(Uint8List.fromList),
      );
    }
    return null;
  }

  static Future<CoseVerificationBackend> _nativeVerificationBackend(
    SigningAlgorithm algorithm,
    X509Certificate leaf,
  ) async {
    return switch (algorithm) {
      SigningAlgorithm.ed25519 => Ed25519VerificationBackend(
        cryptography.SimplePublicKey(
          leaf.subjectPublicKey,
          type: cryptography.KeyPairType.ed25519,
        ),
      ),
      SigningAlgorithm.es256 ||
      SigningAlgorithm.es384 ||
      SigningAlgorithm.es512 => WebCryptoEcdsaVerificationBackend(
        algorithm,
        await importEcdsaPublicKeySpki(algorithm, leaf.subjectPublicKeyInfoDer),
      ),
      SigningAlgorithm.ps256 ||
      SigningAlgorithm.ps384 ||
      SigningAlgorithm.ps512 => WebCryptoRsaPssVerificationBackend(
        algorithm,
        await importRsaPssPublicKeySpki(
          algorithm,
          // WebCrypto imports RSA keys through rsaEncryption SPKI. The
          // original RSASSA-PSS parameters remain enforced by profile checks.
          leaf.subjectPublicKeyAlgorithm.oid == '1.2.840.113549.1.1.10'
              ? _rsaEncryptionSubjectPublicKeyInfo(leaf.subjectPublicKey)
              : leaf.subjectPublicKeyInfoDer,
        ),
      ),
    };
  }

  static Uint8List _rsaEncryptionSubjectPublicKeyInfo(List<int> rsaPublicKey) =>
      Uint8List.fromList(
        _encodeDer(0x30, [
          ..._encodeDer(0x30, [
            ..._encodeDer(0x06, const [
              0x2a,
              0x86,
              0x48,
              0x86,
              0xf7,
              0x0d,
              0x01,
              0x01,
              0x01,
            ]),
            ..._encodeDer(0x05, const []),
          ]),
          ..._encodeDer(0x03, [0, ...rsaPublicKey]),
        ]),
      );

  static List<int> _encodeDer(int tag, List<int> value) => [
    tag,
    if (value.length < 128)
      value.length
    else ...[
      0x80 | _unsignedByteWidth(value.length),
      for (
        var shift = (_unsignedByteWidth(value.length) - 1) * 8;
        shift >= 0;
        shift -= 8
      )
        (value.length >> shift) & 0xff,
    ],
    ...value,
  ];

  static int _unsignedByteWidth(int value) {
    var width = 0;
    do {
      width++;
      value >>= 8;
    } while (value != 0);
    return width;
  }

  static String? _nameAttribute(X509DistinguishedName name, String oid) {
    for (final attribute in name.attributes.reversed) {
      if (attribute.oid == oid) return attribute.value;
    }
    return null;
  }

  static String? _displayName(X509DistinguishedName name) =>
      _nameAttribute(name, '2.5.4.10') ??
      _nameAttribute(name, '2.5.4.3') ??
      name.attributes.lastOrNull?.value;

  static HashAlgorithm? _hashAlgorithm(String value) {
    return switch (value.toLowerCase().replaceAll(RegExp(r'[-_]'), '')) {
      'sha256' => HashAlgorithm.sha256,
      'sha384' => HashAlgorithm.sha384,
      'sha512' => HashAlgorithm.sha512,
      _ => null,
    };
  }

  static Uint8List _boxPayload(Uint8List bytes) {
    if (bytes.length < 8) return Uint8List(0);
    final data = ByteData.sublistView(bytes);
    final size = data.getUint32(0, Endian.big);
    final headerSize = size == 1 ? 16 : 8;
    if (bytes.length < headerSize) return Uint8List(0);
    return Uint8List.sublistView(bytes, headerSize);
  }

  static bool _constantTimeEqual(List<int> left, List<int> right) {
    var difference = left.length ^ right.length;
    final length = left.length > right.length ? left.length : right.length;
    for (var index = 0; index < length; index++) {
      final leftByte = index < left.length ? left[index] : 0;
      final rightByte = index < right.length ? right[index] : 0;
      difference |= leftByte ^ rightByte;
    }
    return difference == 0;
  }

  static Future<Uint8List> _readAll(RandomAccessByteSource source) async {
    final length = await source.length;
    return source.read(ByteRange(0, length));
  }

  static String? _fileExtension(String? fileName) {
    if (fileName == null) return null;
    final slash = fileName.lastIndexOf(RegExp(r'[/\\]'));
    final dot = fileName.lastIndexOf('.');
    return dot <= slash || dot == fileName.length - 1
        ? null
        : fileName.substring(dot + 1);
  }
}

final class _ManifestPath {
  const _ManifestPath({
    required this.path,
    this.assertionLabel,
    this.outsideManifest = false,
  });

  final List<String> path;
  final String? assertionLabel;
  final bool outsideManifest;
}

final class _SignatureValidation {
  _SignatureValidation(Iterable<ValidationIssue> issues, {this.signatureInfo})
    : issues = List<ValidationIssue>.unmodifiable(issues);

  final List<ValidationIssue> issues;
  final SignatureInfo? signatureInfo;
}

final class _TimestampValidation {
  const _TimestampValidation(this.issues, {this.trustedTime});

  final List<ValidationIssue> issues;
  final DateTime? trustedTime;
}

final class _OcspValidation {
  const _OcspValidation(this.issues, {this.revocationStatus});

  final List<ValidationIssue> issues;
  final bool? revocationStatus;
}

enum _BoxHashResult { match, mismatch, malformed }

enum _DataHashResult { match, mismatch, malformed, additionalExclusions }

enum _BmffHashResult { match, mismatch, malformed }

enum _CollectionHashResult {
  match,
  mismatch,
  incorrectFileCount,
  invalidUri,
  malformed,
}

final class _CoseEnvelope {
  _CoseEnvelope({required this.sanitizedBytes, required this.textHeaders});

  final Uint8List sanitizedBytes;
  final Map<String, Object?> textHeaders;

  factory _CoseEnvelope.parse(Uint8List bytes, {required int maxNestingDepth}) {
    final tagged = bytes.isNotEmpty && bytes.first == 0xd2;
    final encoded = tagged ? Uint8List.sublistView(bytes, 1) : bytes;
    final decoded = _decodeManifestCbor(
      encoded,
      maxNestingDepth: maxNestingDepth,
    );
    if (decoded is! List || decoded.length != 4 || decoded[1] is! Map) {
      throw const FormatException('Malformed COSE_Sign1 envelope');
    }

    final headers = decoded[1] as Map;
    final textHeaders = <String, Object?>{};
    final numericHeaders = <Object?, Object?>{};
    for (final entry in headers.entries) {
      if (entry.key is String) {
        textHeaders[entry.key as String] = entry.value;
      } else {
        numericHeaders[entry.key] = entry.value;
      }
    }
    final sanitized = encodeCbor(<Object?>[
      decoded[0],
      numericHeaders,
      decoded[2],
      decoded[3],
    ]);
    return _CoseEnvelope(
      sanitizedBytes: tagged
          ? Uint8List.fromList([0xd2, ...sanitized])
          : sanitized,
      textHeaders: Map<String, Object?>.unmodifiable(textHeaders),
    );
  }
}

final class _DerSlice {
  const _DerSlice({
    required this.tag,
    required this.contentStart,
    required this.end,
  });

  final int tag;
  final int contentStart;
  final int end;
}

final class _CallbackVerificationBackend implements CoseVerificationBackend {
  const _CallbackVerificationBackend(this.verifier, this.publicKey);

  final C2paVerifier verifier;
  final Uint8List publicKey;

  @override
  Future<bool> verify(
    SigningAlgorithm algorithm,
    List<int> data,
    List<int> signature,
  ) => verifier.verify(
    algorithm: algorithm.name,
    data: Uint8List.fromList(data),
    signature: Uint8List.fromList(signature),
    publicKey: Uint8List.fromList(publicKey),
  );
}

const _manifestTypes = {
  JumbfUuid.c2paManifest,
  JumbfUuid.c2paLegacyManifest,
  JumbfUuid.c2paCompressedManifest,
  JumbfUuid.c2paUpdateManifest,
};

bool _isBmffMedia(String? mimeType, String? fileName) {
  final mime = mimeType?.toLowerCase();
  if (mime == 'video/mp4' ||
      mime == 'video/quicktime' ||
      mime == 'image/heif' ||
      mime == 'image/heic' ||
      mime == 'image/avif') {
    return true;
  }
  final name = fileName?.toLowerCase();
  final dot = name?.lastIndexOf('.') ?? -1;
  final extension = dot < 0 ? null : name!.substring(dot + 1);
  return const {'mp4', 'mov', 'heif', 'heic', 'avif'}.contains(extension);
}

extension<T> on Iterable<T> {
  T? get lastOrNull {
    T? result;
    for (final value in this) {
      result = value;
    }
    return result;
  }
}
