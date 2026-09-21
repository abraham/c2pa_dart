import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';

import 'actions.dart';
import 'bmff_hash.dart';
import 'box_hash.dart';
import 'claim.dart';
import 'collection_hash.dart';
import 'context.dart';
import 'data_hash.dart';
import 'dynamic_assertion.dart';
import 'exceptions.dart';
import 'ingredient.dart';
import 'intent.dart';
import 'json_utils.dart';
import 'reader.dart';
import 'resource_store.dart';
import 'signing.dart';
import 'standard_assertions.dart';
import 'timestamping.dart';
import 'validation.dart';
import 'validation_code.dart';
import 'working_archive.dart';

/// The wire encoding used for a custom assertion payload.
enum AssertionEncoding {
  /// JSON assertion payload encoded with canonical key ordering.
  json,

  /// CBOR assertion payload encoded deterministically.
  cbor,

  /// Opaque binary assertion payload with a required content type.
  binary,
}

/// Ordered phases of embedded DataHash manifest construction.
enum DataHashBuildState {
  /// No DataHash placeholder has been created yet.
  draft,

  /// A zero-valued DataHash placeholder manifest has been built.
  placeholderCreated,

  /// The placeholder manifest has been embedded in the asset.
  placeholderEmbedded,

  /// The final asset digest and exclusion ranges have been computed.
  bindingFinalized,

  /// The final manifest has been signed at the reserved size.
  signed,

  /// The signed manifest has replaced the embedded placeholder.
  patched,
}

/// Bytes produced by sidecar manifest generation.
final class C2paSidecarResult {
  /// Creates an immutable sidecar result from caller-owned bytes.
  C2paSidecarResult({
    required List<int> manifestBytes,
    List<int>? assetBytes,
    this.remoteManifestUrl,
  }) : manifestBytes = Uint8List.fromList(manifestBytes).asUnmodifiableView(),
       assetBytes = assetBytes == null
           ? null
           : Uint8List.fromList(assetBytes).asUnmodifiableView();

  /// Standalone manifest bytes suitable for a sidecar file.
  final Uint8List manifestBytes;

  /// Updated asset bytes, or `null` when the asset was unchanged.
  final Uint8List? assetBytes;

  /// Default remote manifest URL for sidecar builds, or `null`.
  final Uri? remoteManifestUrl;
}

/// Enforces the ordering required by an embedded DataHash build.
final class DataHashBuildStateMachine {
  DataHashBuildState _state = DataHashBuildState.draft;

  /// The current embedded DataHash build phase.
  DataHashBuildState get state => _state;

  /// Advances to the next DataHash build phase.
  ///
  /// Throws [C2paSigningException] if [next] is not the immediate next state.
  void advance(DataHashBuildState next) {
    if (next.index != _state.index + 1) {
      throw C2paSigningException(
        'Invalid DataHash build transition: ${_state.name} -> ${next.name}',
      );
    }
    _state = next;
  }
}

/// A custom assertion encoded deterministically as JSON or CBOR.
final class AssertionDefinition {
  /// Creates a custom assertion definition.
  ///
  /// Throws [C2paValidationException] when binary data lacks a content type.
  AssertionDefinition({
    required this.label,
    required Object? data,
    this.encoding = AssertionEncoding.cbor,
    this.contentType,
  }) : data = _freezeAssertionData(data) {
    if (encoding == AssertionEncoding.binary &&
        (contentType == null || contentType!.trim().isEmpty)) {
      throw const C2paValidationException(
        'Binary assertions require a content type',
      );
    }
  }

  /// Creates a JSON assertion with canonical JSON encoding.
  AssertionDefinition.json({required String label, required Object? data})
    : this(label: label, data: data, encoding: AssertionEncoding.json);

  /// Creates a CBOR assertion with deterministic CBOR encoding.
  AssertionDefinition.cbor({required String label, required Object? data})
    : this(label: label, data: data);

  /// Creates a binary assertion with an embedded-file content type.
  AssertionDefinition.binary({
    required String label,
    required String contentType,
    required Uint8List data,
  }) : this(
         label: label,
         data: data,
         encoding: AssertionEncoding.binary,
         contentType: contentType,
       );

  /// Assertion label used under `c2pa.assertions`.
  final String label;

  /// Frozen assertion payload data to encode.
  final Object? data;

  /// Encoding used when writing [data] into the manifest.
  final AssertionEncoding encoding;

  /// Media type for binary assertions, otherwise `null`.
  final String? contentType;

  @override
  bool operator ==(Object other) =>
      other is AssertionDefinition &&
      label == other.label &&
      encoding == other.encoding &&
      contentType == other.contentType &&
      deepEquals(data, other.data);

  @override
  int get hashCode => Object.hash(label, encoding, contentType, deepHash(data));
}

/// Caller-owned bytes placed in the manifest's data-box store.
final class ManifestResource {
  /// Creates an immutable data-box resource from caller-owned bytes.
  ManifestResource({
    /// Resource label used under `c2pa.databoxes`.
    ///
    /// Must be unique within a [ManifestDefinition].
    required this.label,
    required this.format,
    required Uint8List bytes,
    this.name,
    Iterable<String> dataTypes = const [],
    Map<String, Object?> extra = const {},
  }) : bytes = Uint8List.fromList(bytes).asUnmodifiableView(),
       dataTypes = List<String>.unmodifiable(dataTypes),
       extra = freezeJsonMap(extra);

  /// Resource label used under `c2pa.databoxes`.
  final String label;

  /// Resource media type; must be non-empty during signing.
  final String format;

  /// Optional display name stored with the resource.
  final String? name;

  /// C2PA data type hints associated with the resource.
  final List<String> dataTypes;

  /// Extra resource fields preserved in the data-box CBOR map.
  final Map<String, Object?> extra;

  /// Immutable resource payload bytes stored in the manifest.
  final Uint8List bytes;

  @override
  bool operator ==(Object other) =>
      other is ManifestResource &&
      label == other.label &&
      format == other.format &&
      name == other.name &&
      deepEquals(dataTypes, other.dataTypes) &&
      deepEquals(extra, other.extra) &&
      deepEquals(bytes, other.bytes);

  @override
  int get hashCode => Object.hash(
    label,
    format,
    name,
    deepHash(dataTypes),
    deepHash(extra),
    deepHash(bytes),
  );
}

/// An ingredient and, when available, its embedded manifest box.
final class BuilderIngredient {
  /// Creates an ingredient and freezes embedded manifest boxes.
  ///
  /// Throws [C2paValidationException] if [id] conflicts with the assertion ID.
  BuilderIngredient({
    required this.id,
    required this.assertion,
    Uint8List? manifestBoxBytes,
    Iterable<Uint8List> manifestBoxes = const [],
  }) : manifestBoxes = List<Uint8List>.unmodifiable([
         ...manifestBoxes.map(
           (bytes) => Uint8List.fromList(bytes).asUnmodifiableView(),
         ),
         if (manifestBoxBytes != null)
           Uint8List.fromList(manifestBoxBytes).asUnmodifiableView(),
       ]) {
    if (assertion.instanceId != null && assertion.instanceId != id) {
      throw const C2paValidationException(
        'Builder ingredient ID must match its assertion instanceID',
      );
    }
  }

  /// Builds an ingredient from a reader's active manifest.
  ///
  /// Throws [C2paValidationException] if no active manifest or signature exists.
  static Future<BuilderIngredient> fromReader({
    required C2paReader reader,
    required Relationship relationship,
    String? id,
    String? title,
    String? format,
  }) async {
    final entry = reader.activeManifest;
    final claim = reader.activeClaim;
    if (entry == null || claim == null) {
      throw const C2paValidationException(
        'An ingredient reader must contain an active manifest and claim',
      );
    }
    final manifestNode = parseJumbf(entry.bytes);
    final signatureNode = manifestNode.children
        .whereType<JumbfSuperBoxNode>()
        .where(
          (node) => node.description.contentTypeHex == JumbfUuid.c2paSignature,
        )
        .singleOrNull;
    if (signatureNode == null) {
      throw const C2paValidationException(
        'An ingredient manifest must contain exactly one claim signature',
      );
    }
    final algorithm = _ingredientHashAlgorithm(claim.algorithm ?? 'sha256');
    final hashName = algorithm.name.toLowerCase().replaceAll('-', '');
    final manifestHash = await algorithm.digest(_jumbfPayload(entry.bytes));
    final signatureHash = await algorithm.digest(
      _jumbfPayload(signatureNode.rawBytes),
    );
    final ingredientId = id ?? claim.instanceId;
    final root = parseJumbf(reader.manifestBytes);
    return BuilderIngredient(
      id: ingredientId,
      assertion: IngredientAssertion(
        version: IngredientAssertionVersion.v3,
        relationship: relationship,
        title: title ?? claim.title,
        format: format ?? claim.format,
        instanceId: claim.instanceId,
        validationResults: reader.validationResults,
        activeManifest: ClaimHashedUri(
          url: 'self#jumbf=/c2pa/${entry.label}',
          algorithm: hashName,
          hash: Uint8List.fromList(manifestHash),
        ),
        claimSignature: ClaimHashedUri(
          url:
              'self#jumbf=/c2pa/${entry.label}/'
              'c2pa.signature',
          algorithm: hashName,
          hash: Uint8List.fromList(signatureHash),
        ),
      ),
      manifestBoxes: root.children
          .whereType<JumbfSuperBoxNode>()
          .where(
            (node) =>
                node.description.contentTypeHex == JumbfUuid.c2paManifest ||
                node.description.contentTypeHex == JumbfUuid.c2paUpdateManifest,
          )
          .map((node) => node.rawBytes),
    );
  }

  /// Reads [source] and builds an ingredient from its active manifest.
  ///
  /// Performs asset I/O through [C2paReader].
  static Future<BuilderIngredient> fromSource({
    required RandomAccessByteSource source,
    required Relationship relationship,
    String? mimeType,
    String? fileName,
    C2paContext? context,
    String? id,
    String? title,
    String? format,
  }) async => fromReader(
    reader: await C2paReader.fromSource(
      source: source,
      mimeType: mimeType,
      fileName: fileName,
      context: context,
    ),
    relationship: relationship,
    id: id,
    title: title,
    format: format ?? mimeType,
  );

  /// Builder-local ingredient ID referenced by actions.
  final String id;

  /// Ingredient assertion embedded into the new manifest.
  final IngredientAssertion assertion;

  /// Embedded ingredient manifest boxes copied into the manifest store.
  final List<Uint8List> manifestBoxes;

  @override
  bool operator ==(Object other) =>
      other is BuilderIngredient &&
      id == other.id &&
      assertion == other.assertion &&
      deepEquals(manifestBoxes, other.manifestBoxes);

  @override
  int get hashCode => Object.hash(id, assertion, deepHash(manifestBoxes));
}

/// Immutable input used to construct one v2 C2PA manifest.
final class ManifestDefinition {
  /// Creates immutable manifest-building input.
  ManifestDefinition({
    required this.label,
    required this.intent,
    required this.generatorInfo,
    required this.format,
    required this.instanceId,
    this.title,
    this.hashAlgorithm = 'sha256',
    this.softBindingAlgorithm,
    Iterable<AssertionDefinition> assertions = const [],
    Iterable<ManifestResource> resources = const [],
    Iterable<String> redactions = const [],
    Iterable<BuilderIngredient> ingredients = const [],
    Iterable<C2paAction> actions = const [],
    Iterable<BmffHashExclusion> bmffExclusions = const [],
    this.bmffHashName,
  }) : assertions = List<AssertionDefinition>.unmodifiable(assertions),
       resources = List<ManifestResource>.unmodifiable(resources),
       redactions = List<String>.unmodifiable(redactions),
       ingredients = List<BuilderIngredient>.unmodifiable(ingredients),
       actions = List<C2paAction>.unmodifiable(actions),
       bmffExclusions = List<BmffHashExclusion>.unmodifiable(bmffExclusions);

  /// Manifest label used under the top-level `c2pa` manifest store.
  final String label;

  /// Creation, edit, or update intent that controls validation rules.
  final BuilderIntent intent;

  /// Claim-generator metadata written into the C2PA claim.
  final ClaimGeneratorInfo generatorInfo;

  /// Human-readable asset title, or `null` when omitted.
  final String? title;

  /// Asset media type claimed by the manifest.
  final String format;

  /// Claim instance ID; must be non-empty during signing.
  final String instanceId;

  /// Assertion hash algorithm name, such as `sha256`.
  final String hashAlgorithm;

  /// Optional `alg_soft` value for soft-binding assertion references.
  final String? softBindingAlgorithm;

  /// Custom assertions appended after generated assertions.
  final List<AssertionDefinition> assertions;

  /// Data-box resources embedded in the manifest store.
  final List<ManifestResource> resources;

  /// JUMBF URIs for ingredient assertions redacted by this claim.
  final List<String> redactions;

  /// Ingredients whose assertions and manifests feed this manifest.
  final List<BuilderIngredient> ingredients;

  /// Additional provenance actions after the generated inception action.
  final List<C2paAction> actions;

  /// Extra ISO BMFF hash exclusions merged with SDK defaults.
  final List<BmffHashExclusion> bmffExclusions;

  /// Optional named BMFF hash assertion variant.
  final String? bmffHashName;

  /// Returns a manifest definition with selected fields replaced.
  ManifestDefinition copyWith({
    String? label,
    BuilderIntent? intent,
    ClaimGeneratorInfo? generatorInfo,
    String? format,
    String? instanceId,
    String? title,
    String? hashAlgorithm,
    String? softBindingAlgorithm,
    Iterable<AssertionDefinition>? assertions,
    Iterable<ManifestResource>? resources,
    Iterable<String>? redactions,
    Iterable<BuilderIngredient>? ingredients,
    Iterable<C2paAction>? actions,
    Iterable<BmffHashExclusion>? bmffExclusions,
    String? bmffHashName,
  }) => ManifestDefinition(
    label: label ?? this.label,
    intent: intent ?? this.intent,
    generatorInfo: generatorInfo ?? this.generatorInfo,
    format: format ?? this.format,
    instanceId: instanceId ?? this.instanceId,
    title: title ?? this.title,
    hashAlgorithm: hashAlgorithm ?? this.hashAlgorithm,
    softBindingAlgorithm: softBindingAlgorithm ?? this.softBindingAlgorithm,
    assertions: assertions ?? this.assertions,
    resources: resources ?? this.resources,
    redactions: redactions ?? this.redactions,
    ingredients: ingredients ?? this.ingredients,
    actions: actions ?? this.actions,
    bmffExclusions: bmffExclusions ?? this.bmffExclusions,
    bmffHashName: bmffHashName ?? this.bmffHashName,
  );

  @override
  bool operator ==(Object other) =>
      other is ManifestDefinition &&
      label == other.label &&
      intent == other.intent &&
      generatorInfo == other.generatorInfo &&
      title == other.title &&
      format == other.format &&
      instanceId == other.instanceId &&
      hashAlgorithm == other.hashAlgorithm &&
      softBindingAlgorithm == other.softBindingAlgorithm &&
      deepEquals(assertions, other.assertions) &&
      deepEquals(resources, other.resources) &&
      deepEquals(redactions, other.redactions) &&
      deepEquals(ingredients, other.ingredients) &&
      deepEquals(actions, other.actions) &&
      deepEquals(bmffExclusions, other.bmffExclusions) &&
      bmffHashName == other.bmffHashName;

  @override
  int get hashCode => Object.hash(
    label,
    intent,
    generatorInfo,
    title,
    format,
    instanceId,
    hashAlgorithm,
    softBindingAlgorithm,
    deepHash(assertions),
    deepHash(resources),
    deepHash(redactions),
    deepHash(ingredients),
    deepHash(actions),
    deepHash(bmffExclusions),
    bmffHashName,
  );
}

/// Output of a fragmented BMFF signing operation.
/// Signed initialization segment and fragments for fragmented BMFF.
final class FragmentedBmffBuildResult {
  /// Creates immutable fragmented BMFF output bytes.
  FragmentedBmffBuildResult({
    required List<int> initializationSegment,
    required Iterable<List<int>> fragments,
  }) : initializationSegment = Uint8List.fromList(initializationSegment)
           .asUnmodifiableView(),
       fragments = List<Uint8List>.unmodifiable(
         fragments.map(
           (fragment) => Uint8List.fromList(fragment).asUnmodifiableView(),
         ),
       );

  /// Initialization segment containing the signed C2PA manifest.
  final Uint8List initializationSegment;

  /// Fragments containing patched Merkle proof UUID boxes.
  final List<Uint8List> fragments;
}

/// Builds deterministic, signed v2 manifest stores.
final class C2paBuilder {
  /// Creates a deterministic manifest builder.
  ///
  /// The builder is immutable; `with...` methods return new builders.
  C2paBuilder({
    required this.definition,
    required this.context,
    required this.signingAlgorithm,
    required Iterable<Uint8List> x5chain,
    this.archiveBasePath,
    this.remoteManifestUrl,
    this.noEmbed = false,
    Map<String, Object?> archiveExtensions = const {},
    Iterable<C2paDynamicAssertion> dynamicAssertions = const [],
    Iterable<Uint8List> cachedOcspResponses = const [],
    this.timestamp,
  }) : x5chain = List<Uint8List>.unmodifiable(
         x5chain.map(
           (certificate) =>
               Uint8List.fromList(certificate).asUnmodifiableView(),
         ),
       ),
       archiveExtensions = freezeJsonMap(archiveExtensions),
       dynamicAssertions = List<C2paDynamicAssertion>.unmodifiable(
         dynamicAssertions,
       ),
       cachedOcspResponses = List<Uint8List>.unmodifiable(
         cachedOcspResponses.map(
           (response) => Uint8List.fromList(response).asUnmodifiableView(),
         ),
       );

  /// Loads a builder from a serialized C2PA builder archive.
  static Future<C2paBuilder> fromArchive({
    required List<int> bytes,
    required C2paContext context,
    C2paArchiveLoadOptions options = const C2paArchiveLoadOptions(),
  }) =>
      loadC2paBuilderArchive(bytes: bytes, context: context, options: options);

  /// Creates a builder initialized from a reader's active manifest.
  static Future<C2paBuilder> fromReader({
    required C2paReader reader,
    C2paContext? context,
    String signingAlgorithm = 'es256',
    Iterable<Uint8List> x5chain = const [],
  }) => c2paBuilderFromReader(
    reader: reader,
    context: context,
    signingAlgorithm: signingAlgorithm,
    x5chain: x5chain,
  );

  /// Immutable manifest definition used by this builder.
  final ManifestDefinition definition;

  /// Context providing signer, settings, trust, and progress hooks.
  final C2paContext context;

  /// Base path stored in builder archives, or `null`.
  final String? archiveBasePath;

  /// Default remote manifest URL for sidecar builds, or `null`.
  final Uri? remoteManifestUrl;

  /// Whether [saveToSource] should prefer sidecar output over embedding.
  final bool noEmbed;

  /// Extension data preserved in builder archives.
  final Map<String, Object?> archiveExtensions;

  /// Dynamic assertions resolved during manifest signing.
  final List<C2paDynamicAssertion> dynamicAssertions;

  /// OCSP responses attached to the COSE signature.
  final List<Uint8List> cachedOcspResponses;

  /// Timestamp configuration, or `null` to sign without a timestamp.
  final C2paTimestampConfig? timestamp;

  /// A supported COSE algorithm name such as `ed25519`, `es256`, or `ps256`.
  final String signingAlgorithm;

  /// Caller-provided certificate chain or opaque verification key material.
  final List<Uint8List> x5chain;

  /// Returns a builder with a typed standard assertion appended.
  ///
  /// Repeated labels are assigned the standard `__N` instance suffix.
  C2paBuilder withStandardAssertion(C2paStandardAssertion assertion) {
    final base = assertion.label;
    final existingLabels = definition.assertions
        .map((item) => item.label)
        .toSet();
    var label = base;
    if (existingLabels.contains(label)) {
      var instance = 2;
      while (existingLabels.contains('${base}__$instance')) {
        instance++;
      }
      label = '${base}__$instance';
    }
    final encoded = switch (assertion.encoding) {
      C2paStandardAssertionEncoding.json => AssertionDefinition.json(
        label: label,
        data: assertion.toAssertionData(),
      ),
      C2paStandardAssertionEncoding.cbor => AssertionDefinition.cbor(
        label: label,
        data: assertion.toAssertionData(),
      ),
      C2paStandardAssertionEncoding.binary => AssertionDefinition.binary(
        label: label,
        contentType: assertion.contentType!,
        data: assertion.toAssertionData()! as Uint8List,
      ),
    };
    return C2paBuilder(
      definition: definition.copyWith(
        assertions: [...definition.assertions, encoded],
      ),
      context: context,
      signingAlgorithm: signingAlgorithm,
      x5chain: x5chain,
      archiveBasePath: archiveBasePath,
      remoteManifestUrl: remoteManifestUrl,
      noEmbed: noEmbed,
      archiveExtensions: archiveExtensions,
      dynamicAssertions: dynamicAssertions,
      cachedOcspResponses: cachedOcspResponses,
      timestamp: timestamp,
    );
  }

  /// Returns a builder with a data-box resource appended.
  C2paBuilder withResource(ManifestResource resource) => C2paBuilder(
    definition: definition.copyWith(
      resources: [...definition.resources, resource],
    ),
    context: context,
    signingAlgorithm: signingAlgorithm,
    x5chain: x5chain,
    archiveBasePath: archiveBasePath,
    remoteManifestUrl: remoteManifestUrl,
    noEmbed: noEmbed,
    archiveExtensions: archiveExtensions,
    dynamicAssertions: dynamicAssertions,
    cachedOcspResponses: cachedOcspResponses,
    timestamp: timestamp,
  );

  /// Returns a builder with a dynamic assertion appended.
  ///
  /// The callback runs during signing and must fill its reserved size exactly.
  C2paBuilder withDynamicAssertion(C2paDynamicAssertion assertion) =>
      C2paBuilder(
        definition: definition,
        context: context,
        signingAlgorithm: signingAlgorithm,
        x5chain: x5chain,
        archiveBasePath: archiveBasePath,
        remoteManifestUrl: remoteManifestUrl,
        noEmbed: noEmbed,
        archiveExtensions: archiveExtensions,
        dynamicAssertions: [...dynamicAssertions, assertion],
        cachedOcspResponses: cachedOcspResponses,
        timestamp: timestamp,
      );

  /// Returns a builder with archive and embedding options updated.
  C2paBuilder withArchiveConfiguration({
    String? basePath,
    Uri? remoteManifestUrl,
    bool? noEmbed,
    Map<String, Object?>? extensions,
  }) => C2paBuilder(
    definition: definition,
    context: context,
    signingAlgorithm: signingAlgorithm,
    x5chain: x5chain,
    archiveBasePath: basePath ?? archiveBasePath,
    remoteManifestUrl: remoteManifestUrl ?? this.remoteManifestUrl,
    noEmbed: noEmbed ?? this.noEmbed,
    archiveExtensions: extensions ?? archiveExtensions,
    dynamicAssertions: dynamicAssertions,
    cachedOcspResponses: cachedOcspResponses,
    timestamp: timestamp,
  );

  /// Returns a builder that timestamps the claim signature when signing.
  C2paBuilder withTimestamp(C2paTimestampConfig timestamp) => C2paBuilder(
    definition: definition,
    context: context,
    signingAlgorithm: signingAlgorithm,
    x5chain: x5chain,
    archiveBasePath: archiveBasePath,
    remoteManifestUrl: remoteManifestUrl,
    noEmbed: noEmbed,
    archiveExtensions: archiveExtensions,
    dynamicAssertions: dynamicAssertions,
    cachedOcspResponses: cachedOcspResponses,
    timestamp: timestamp,
  );

  /// Returns a builder with cached OCSP responses for the signature.
  C2paBuilder withCachedOcspResponses(Iterable<Uint8List> responses) =>
      C2paBuilder(
        definition: definition,
        context: context,
        signingAlgorithm: signingAlgorithm,
        x5chain: x5chain,
        archiveBasePath: archiveBasePath,
        remoteManifestUrl: remoteManifestUrl,
        noEmbed: noEmbed,
        archiveExtensions: archiveExtensions,
        dynamicAssertions: dynamicAssertions,
        cachedOcspResponses: responses,
        timestamp: timestamp,
      );

  /// Returns a builder with timestamping disabled.
  C2paBuilder withoutTimestamp() => C2paBuilder(
    definition: definition,
    context: context,
    signingAlgorithm: signingAlgorithm,
    x5chain: x5chain,
    archiveBasePath: archiveBasePath,
    remoteManifestUrl: remoteManifestUrl,
    noEmbed: noEmbed,
    archiveExtensions: archiveExtensions,
    dynamicAssertions: dynamicAssertions,
    cachedOcspResponses: cachedOcspResponses,
  );

  /// Serializes this builder into a C2PA builder archive.
  Uint8List toArchive() => encodeC2paBuilderArchive(this);

  /// Returns a builder with a C2PA metadata assertion appended.
  C2paBuilder withMetadata(C2paMetadataAssertion metadata) =>
      withStandardAssertion(metadata);

  /// Returns a builder with assertion metadata appended.
  C2paBuilder withAssertionMetadata(C2paAssertionMetadata metadata) =>
      withStandardAssertion(metadata);

  /// Returns a builder with a soft-binding assertion appended.
  C2paBuilder withSoftBinding(C2paSoftBindingAssertion softBinding) =>
      withStandardAssertion(softBinding);

  /// Returns a builder with embedded data appended as an assertion.
  C2paBuilder withEmbeddedData(C2paEmbeddedData embeddedData) =>
      withStandardAssertion(embeddedData);

  /// Returns a builder with a thumbnail assertion appended.
  C2paBuilder withThumbnail(C2paThumbnail thumbnail) =>
      withStandardAssertion(thumbnail);

  /// Returns a builder with asset-reference metadata appended.
  C2paBuilder withAssetReferences(C2paAssetReferenceAssertion references) =>
      withStandardAssertion(references);

  /// Returns a builder with asset type metadata appended.
  C2paBuilder withAssetTypes(C2paAssetTypesAssertion assetTypes) =>
      withStandardAssertion(assetTypes);

  /// Returns a builder with a timestamp assertion appended.
  C2paBuilder withTimestampAssertion(C2paTimestampAssertion timestamp) =>
      withStandardAssertion(timestamp);

  /// Returns a builder with certificate-status metadata appended.
  C2paBuilder withCertificateStatus(
    C2paCertificateStatusAssertion certificateStatus,
  ) => withStandardAssertion(certificateStatus);

  /// Returns a builder with a legacy JSON assertion appended.
  C2paBuilder withLegacyAssertion(C2paLegacyJsonAssertion assertion) =>
      withStandardAssertion(assertion);

  /// Builds a standalone C2PA manifest store.
  /// Builds a standalone signed C2PA manifest store.
  ///
  /// Throws [C2paSigningException] if signing fails or context lacks a signer.
  Future<Uint8List> build({bool requireValidClaim = false}) async {
    if (definition.intent is UpdateIntent) return _buildManifest(null);
    final boxHash = BoxHashAssertion(
      boxes: [
        BoxHashBox(names: const ['C2PA'], hash: const [0], excluded: true),
      ],
    );
    return _buildManifest(boxHash);
  }

  /// Builds a standalone manifest for a caller-supplied collection.
  /// Builds a standalone manifest bound to [collection].
  ///
  /// Throws [C2paValidationException] for update manifests or resource limits.
  Future<Uint8List> buildCollection(C2paCollectionSource collection) async {
    if (definition.intent is UpdateIntent) {
      throw _validationFailure(
        'Update manifests cannot contain a collection hard binding',
        ValidationCode.manifestUpdateInvalid,
      );
    }
    final assertion = await _generateCollectionHash(collection);
    return _buildManifest(assertion);
  }

  Future<Uint8List> _buildManifest(
    Object? hardBinding, {
    C2paSigner? signingOverride,
    bool reportSigning = true,
    bool finalizeDynamicAssertions = true,
  }) async {
    _validateDefinition();

    final signer = signingOverride ?? context.signer;
    if (signer == null) {
      throw const C2paSigningException(
        'C2paContext.signer is required to build a signed manifest',
      );
    }
    final algorithm = _parseSigningAlgorithm(signingAlgorithm);
    if (_normalizeAlgorithmName(signer.algorithm) != algorithm.name) {
      throw C2paSigningException(
        'Signer algorithm ${signer.algorithm} does not match '
        '${algorithm.name}',
      );
    }

    if (reportSigning) {
      await context.reportProgress(
        const C2paProgressEvent(phase: C2paProgressPhase.signing),
      );
    }

    final hashAlgorithm = _parseHashAlgorithm(definition.hashAlgorithm);
    var assertionNodes = <JumbfSuperBoxNode>[
      if (hardBinding != null) _hardBindingAssertion(hardBinding),
      for (var index = 0; index < definition.ingredients.length; index++)
        _ingredientAssertion(definition.ingredients[index].assertion, index),
      _actionsAssertion(),
      for (final assertion in definition.assertions) _assertionNode(assertion),
      for (final assertion in dynamicAssertions)
        _dynamicPlaceholderNode(assertion),
    ];
    final preliminaryReferences = await _assertionReferences(
      assertionNodes,
      hashAlgorithm,
    );
    if (finalizeDynamicAssertions && dynamicAssertions.isNotEmpty) {
      final claimContext = C2paDynamicClaimContext(
        manifestLabel: definition.label,
        instanceId: definition.instanceId,
        format: definition.format,
        hashAlgorithm: _hashName(hashAlgorithm),
        assertions: preliminaryReferences.map(ClaimHashedUri.fromCbor),
      );
      final firstDynamicIndex =
          assertionNodes.length - dynamicAssertions.length;
      final finalized = <JumbfSuperBoxNode>[];
      for (var index = 0; index < dynamicAssertions.length; index++) {
        finalized.add(
          await _resolveDynamicAssertion(
            dynamicAssertions[index],
            claimContext,
          ),
        );
      }
      assertionNodes = [
        ...assertionNodes.take(firstDynamicIndex),
        ...finalized,
      ];
    }
    final references = finalizeDynamicAssertions
        ? await _assertionReferences(assertionNodes, hashAlgorithm)
        : preliminaryReferences;

    final claimBytes = encodeCbor({
      'instanceID': definition.instanceId,
      'claim_generator_info': definition.generatorInfo.toCborMap(),
      'signature': 'self#jumbf=c2pa.signature',
      'created_assertions': references,
      'dc:title': ?definition.title,
      if (definition.redactions.isNotEmpty)
        'redacted_assertions': definition.redactions,
      'alg': hashAlgorithm.name.toLowerCase().replaceAll('-', ''),
    }, maxNestingDepth: context.settings.maxRecursionDepth);

    late Uint8List coseBytes;
    try {
      final backend = _CallbackSigningBackend(signer);
      coseBytes = await CoseSigner(backends: {algorithm: backend}).sign(
        algorithm: algorithm,
        payload: claimBytes,
        detached: true,
        unprotectedHeaders: CoseHeaders({
          CoseHeaderLabel.x509Chain: x5chain.length == 1
              ? x5chain.single
              : x5chain,
        }),
      );
    } catch (error, stackTrace) {
      throw C2paSigningException(
        'Failed to sign the v2 claim: $error',
        cause: error,
        stackTrace: stackTrace,
      );
    }
    if (cachedOcspResponses.isNotEmpty) {
      coseBytes = _attachUnprotectedHeader(coseBytes, 'rVals', {
        'ocspVals': cachedOcspResponses,
      });
    }
    if (timestamp != null) {
      coseBytes = await _timestampCose(
        coseBytes,
        timestamp!,
        createPlaceholder: !finalizeDynamicAssertions,
      );
    }

    final assertionStore = JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paAssertionStore,
        label: 'c2pa.assertions',
      ),
      children: assertionNodes,
    );
    final claimBox = JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paClaim,
        label: 'c2pa.claim.v2',
      ),
      children: [JumbfCborNode(claimBytes)],
    );
    final signatureBox = JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paSignature,
        label: 'c2pa.signature',
      ),
      children: [JumbfCborNode(coseBytes)],
    );
    final manifest = JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: definition.intent is UpdateIntent
            ? JumbfUuid.c2paUpdateManifest
            : JumbfUuid.c2paManifest,
        label: definition.label,
      ),
      children: [
        assertionStore,
        claimBox,
        signatureBox,
        if (definition.resources.isNotEmpty) _resourceStore(),
      ],
    );
    final store = JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifestStore,
        label: 'c2pa',
      ),
      children: [
        for (final ingredient in definition.ingredients)
          for (final bytes in ingredient.manifestBoxes) parseJumbf(bytes),
        manifest,
      ],
    ).encode();
    if (store.length > context.settings.maxManifestBytes) {
      throw C2paSigningException(
        'Manifest store size ${store.length} exceeds the configured limit '
        'of ${context.settings.maxManifestBytes} bytes',
      );
    }
    return store;
  }

  /// Writes standalone output when [source] is absent, otherwise embeds into
  /// a source format using the strongest supported hard-binding layout.
  /// Writes a standalone manifest or embeds one into [source].
  ///
  /// Mutates [output] only after validating it is empty.
  Future<void> saveToSource({
    RandomAccessByteSource? source,
    required WritableByteSink output,
    String? mimeType,
    String? fileName,
    bool requireValidClaim = false,
    bool? embedManifest,
  }) async {
    if (source == null) {
      final manifest = await build(requireValidClaim: requireValidClaim);
      if (await output.length != 0) {
        throw const C2paFormatException(
          'The standalone destination sink must be empty',
        );
      }
      await output.append(manifest);
      return;
    }
    await _saveEmbeddedSource(
      source,
      output,
      mimeType: mimeType,
      fileName: fileName,
      embedManifest: embedManifest ?? !noEmbed,
    );
  }

  /// Creates a standalone sidecar and optionally writes its URL into the asset.
  ///
  /// URL metadata is applied before hashing so the returned manifest binds the
  /// exact returned asset bytes.
  /// Builds a sidecar manifest and optional URL-updated asset.
  ///
  /// Reads [source] and returns updated asset bytes only when a URL is written.
  Future<C2paSidecarResult> buildSidecar({
    required RandomAccessByteSource source,
    Uri? remoteManifestUrl,
    String? mimeType,
    String? fileName,
  }) async {
    final effectiveRemoteManifestUrl =
        remoteManifestUrl ?? this.remoteManifestUrl;
    RandomAccessByteSource bindingSource = source;
    Uint8List? updatedAsset;
    if (effectiveRemoteManifestUrl != null) {
      _validateRemoteManifestUrl(effectiveRemoteManifestUrl);
      final sink = MemoryByteSink();
      try {
        await AssetHandlerRegistry().updateRemoteManifestReference(
          source,
          effectiveRemoteManifestUrl.toString(),
          sink,
          mimeType: mimeType,
          fileExtension: _fileExtension(fileName),
        );
      } on AssetFormatException catch (error, stackTrace) {
        throw C2paFormatException(
          error.message,
          cause: error,
          stackTrace: stackTrace,
        );
      }
      updatedAsset = sink.toBytes();
      bindingSource = MemoryByteSource(updatedAsset);
    }

    final sidecar = MemoryByteSink();
    await saveToSource(
      source: bindingSource,
      output: sidecar,
      mimeType: mimeType,
      fileName: fileName,
      embedManifest: false,
    );
    return C2paSidecarResult(
      manifestBytes: sidecar.toBytes(),
      assetBytes: updatedAsset,
      remoteManifestUrl: effectiveRemoteManifestUrl,
    );
  }

  /// Inserts or updates the asset's provenance URL metadata.
  /// Inserts or updates the asset's provenance URL metadata.
  ///
  /// Throws [C2paValidationException] if the URL is not absolute HTTP(S).
  static Future<Uint8List> updateRemoteManifestReference({
    required RandomAccessByteSource source,
    required Uri remoteManifestUrl,
    String? mimeType,
    String? fileName,
  }) async {
    _validateRemoteManifestUrl(remoteManifestUrl);
    final output = MemoryByteSink();
    try {
      await AssetHandlerRegistry().updateRemoteManifestReference(
        source,
        remoteManifestUrl.toString(),
        output,
        mimeType: mimeType,
        fileExtension: _fileExtension(fileName),
      );
      return output.toBytes();
    } on AssetFormatException catch (error, stackTrace) {
      throw C2paFormatException(
        error.message,
        cause: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Removes provenance URL metadata from a capable source format.
  /// Removes provenance URL metadata from a capable source format.
  ///
  /// Throws [C2paFormatException] when the asset handler rejects the format.
  static Future<Uint8List> removeRemoteManifestReference({
    required RandomAccessByteSource source,
    String? mimeType,
    String? fileName,
  }) async {
    final output = MemoryByteSink();
    try {
      await AssetHandlerRegistry().removeRemoteManifestReference(
        source,
        output,
        mimeType: mimeType,
        fileExtension: _fileExtension(fileName),
      );
      return output.toBytes();
    } on AssetFormatException catch (error, stackTrace) {
      throw C2paFormatException(
        error.message,
        cause: error,
        stackTrace: stackTrace,
      );
    }
  }

  static void _validateRemoteManifestUrl(Uri uri) {
    if (!uri.isAbsolute ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        (uri.scheme != 'https' && uri.scheme != 'http')) {
      throw const C2paValidationException(
        'Remote manifest URLs must be absolute HTTP(S) URLs without user info',
      );
    }
  }

  /// Signs an ordered fragmented ISO BMFF asset.
  ///
  /// A Merkle proof UUID box is inserted before each fragment's `moof`, while
  /// the signed manifest is inserted into the initialization segment.
  /// Signs an ordered fragmented ISO BMFF asset.
  ///
  /// Uses reserved-size signing and enforces Merkle placeholder ordering.
  Future<FragmentedBmffBuildResult> buildFragmentedBmff({
    required RandomAccessByteSource initializationSegment,
    required Iterable<RandomAccessByteSource> fragments,
    required int merkleReservationBytes,
    int uniqueId = 0,
    int localId = 0,
    int? fixedBlockSize,
    bool useVariableBlockSizes = false,
    String? mimeType,
    String? fileName,
  }) async {
    _validateDefinition();
    if (definition.intent is UpdateIntent) {
      throw _validationFailure(
        'Update manifests cannot contain a hard binding',
        ValidationCode.manifestUpdateInvalid,
      );
    }
    if (merkleReservationBytes <= 0 ||
        merkleReservationBytes > context.settings.maxManifestBytes) {
      throw C2paSigningException(
        'BMFF Merkle reservation $merkleReservationBytes exceeds the '
        'configured limit of ${context.settings.maxManifestBytes}',
      );
    }
    if (uniqueId < 0 || localId < 0) {
      throw const C2paValidationException(
        'BMFF Merkle IDs must be non-negative',
      );
    }
    if (fixedBlockSize != null && fixedBlockSize <= 0) {
      throw const C2paValidationException(
        'BMFF Merkle fixed block size must be positive',
      );
    }
    if (fixedBlockSize != null && useVariableBlockSizes) {
      throw const C2paValidationException(
        'Choose either fixed or variable BMFF Merkle block sizes',
      );
    }
    final fragmentList = List<RandomAccessByteSource>.unmodifiable(fragments);
    if (fragmentList.isEmpty) {
      throw const C2paValidationException(
        'Fragmented BMFF signing requires at least one fragment',
      );
    }
    final signer = context.signer;
    if (signer is! C2paReservedSizeSigner ||
        signer.reservedSignatureSize <= 0) {
      throw const C2paSigningException(
        'Fragmented BMFF Hash requires an explicit positive '
        'reservedSignatureSize',
      );
    }

    final registry = AssetHandlerRegistry();
    final exclusions = _bmffExclusions();
    final isoExclusions = _isoBmffExclusions(exclusions);
    final extension = _fileExtension(fileName);
    late FragmentedIsoBmffLayout originalLayout;
    try {
      originalLayout = await registry.getFragmentedBmffLayout(
        FragmentedIsoBmffSource(
          initializationSegment: initializationSegment,
          fragments: fragmentList,
        ),
        isoExclusions,
        mimeType: mimeType,
        fileExtension: extension,
        version: BmffHashAssertion.version,
      );
    } on AssetFormatException catch (error, stackTrace) {
      throw C2paFormatException(
        error.message,
        cause: error,
        stackTrace: stackTrace,
      );
    }

    final algorithm = _parseHashAlgorithm(definition.hashAlgorithm);
    final algorithmName = _hashName(algorithm);
    final proofBytes = List<int>.generate(
      fragmentList.length,
      (index) =>
          _merkleProofSiblingCount(fragmentList.length, index) *
          algorithm.digestLength,
    ).fold<int>(0, (total, length) => total + length);
    if (proofBytes > context.settings.maxTotalResourceBytes) {
      throw C2paSigningException(
        'BMFF Merkle proof reservation $proofBytes exceeds the configured '
        'limit of ${context.settings.maxTotalResourceBytes} bytes',
      );
    }
    final placeholderProofs = <BmffMerkleProof>[
      for (var index = 0; index < fragmentList.length; index++)
        BmffMerkleProof(
          uniqueId: uniqueId,
          localId: localId,
          location: index,
          hashes: List<List<int>>.generate(
            _merkleProofSiblingCount(fragmentList.length, index),
            (_) => List<int>.filled(algorithm.digestLength, 0),
          ),
        ),
    ];
    final stagedFragments = <Uint8List>[];
    for (var index = 0; index < fragmentList.length; index++) {
      final bytes = await _readAll(fragmentList[index]);
      final moof = originalLayout.segments[index + 1].hashLayout.boxes
          .where((box) => box.box.type == 'moof')
          .single;
      stagedFragments.add(
        _insertBytes(
          bytes,
          moof.box.offset,
          _encodeC2paUuidBox(
            'merkle',
            encodeCbor(placeholderProofs[index].toCborMap()),
          ),
        ),
      );
    }

    final stagedFragmentSources = stagedFragments
        .map<RandomAccessByteSource>(MemoryByteSource.new)
        .toList(growable: false);
    final preManifestLayout = await registry.getFragmentedBmffLayout(
      FragmentedIsoBmffSource(
        initializationSegment: initializationSegment,
        fragments: stagedFragmentSources,
      ),
      isoExclusions,
      mimeType: mimeType,
      fileExtension: extension,
      version: BmffHashAssertion.version,
    );
    final variableSizes = useVariableBlockSizes
        ? preManifestLayout.segments
              .skip(1)
              .map((segment) => _eventLength(segment.hashLayout.events))
              .toList(growable: false)
        : null;
    if (fixedBlockSize != null &&
        preManifestLayout.segments
            .skip(1)
            .any(
              (segment) =>
                  _eventLength(segment.hashLayout.events) > fixedBlockSize,
            )) {
      throw const C2paValidationException(
        'A BMFF fragment exceeds the configured fixed block size',
      );
    }
    final placeholderMap = MerkleMap(
      uniqueId: uniqueId,
      localId: localId,
      count: fragmentList.length,
      algorithm: algorithmName,
      initHash: List<int>.filled(algorithm.digestLength, 0),
      hashes: [List<int>.filled(algorithm.digestLength, 0)],
      fixedBlockSize: fixedBlockSize,
      variableBlockSizes: variableSizes,
    );
    final placeholderAssertion = BmffHashAssertion(
      exclusions: exclusions,
      algorithm: algorithmName,
      merkle: [placeholderMap],
      name: definition.bmffHashName,
    );
    if (encodeCbor(placeholderAssertion.toCborMap()).length >
        merkleReservationBytes) {
      throw C2paSigningException(
        'BMFF Merkle assertion exceeds its '
        '$merkleReservationBytes-byte reservation',
      );
    }
    final placeholderManifest = await _buildManifest(
      placeholderAssertion,
      signingOverride: _ReservedSignatureSigner(
        signingAlgorithm,
        signer.reservedSignatureSize,
      ),
      reportSigning: false,
      finalizeDynamicAssertions: false,
    );
    final initBytes = await _readAll(initializationSegment);
    final ftyp = originalLayout.segments.first.hashLayout.boxes.first;
    final stagedInit = _insertBytes(
      initBytes,
      ftyp.box.end,
      _encodeC2paUuidBox('manifest', placeholderManifest),
    );
    final stagedLayout = await registry.getFragmentedBmffLayout(
      FragmentedIsoBmffSource(
        initializationSegment: MemoryByteSource(stagedInit),
        fragments: stagedFragmentSources,
      ),
      isoExclusions,
      mimeType: mimeType,
      fileExtension: extension,
      version: BmffHashAssertion.version,
    );
    final initDigest = await _assetHashEngine().digestEvents(
      MemoryByteSource(stagedInit),
      algorithm,
      _bmffDigestEvents(stagedLayout.segments.first.hashLayout),
    );
    final leaves = <Uint8List>[];
    for (var index = 0; index < stagedFragmentSources.length; index++) {
      leaves.add(
        await _assetHashEngine().digestEvents(
          stagedFragmentSources[index],
          algorithm,
          _bmffDigestEvents(stagedLayout.segments[index + 1].hashLayout),
        ),
      );
    }
    final tree = await _buildMerkleTree(leaves, algorithm);
    final finalMap = MerkleMap(
      uniqueId: uniqueId,
      localId: localId,
      count: fragmentList.length,
      algorithm: algorithmName,
      initHash: initDigest,
      hashes: [tree.layers.last.single],
      fixedBlockSize: fixedBlockSize,
      variableBlockSizes: variableSizes,
    );
    final assertion = BmffHashAssertion(
      exclusions: exclusions,
      algorithm: algorithmName,
      merkle: [finalMap],
      name: definition.bmffHashName,
    );
    final assertionSize = encodeCbor(assertion.toCborMap()).length;
    if (assertionSize > merkleReservationBytes) {
      throw C2paSigningException(
        'BMFF Merkle assertion size $assertionSize exceeds its '
        '$merkleReservationBytes-byte reservation',
      );
    }
    final manifest = await _buildManifest(
      assertion,
      signingOverride: _ExactReservedSizeSigner(
        signer,
        signer.reservedSignatureSize,
      ),
    );
    if (manifest.length != placeholderManifest.length) {
      throw const C2paSigningException(
        'BMFF Merkle configuration changed after placeholder creation',
      );
    }
    final manifestMetadata = stagedLayout.segments.first.c2paMetadata
        .where((metadata) => metadata.purpose == 'manifest')
        .single;
    final finalInit = _replaceBytes(
      stagedInit,
      manifestMetadata.dataRange.start,
      manifestMetadata.dataRange.end,
      manifest,
    );
    final finalFragments = <Uint8List>[];
    for (var index = 0; index < stagedFragments.length; index++) {
      final metadata = stagedLayout.segments[index + 1].c2paMetadata
          .where((item) => item.purpose == 'merkle')
          .single;
      final proof = BmffMerkleProof(
        uniqueId: uniqueId,
        localId: localId,
        location: index,
        hashes: _merkleProof(tree.layers, index),
      );
      final encoded = encodeCbor(proof.toCborMap());
      if (encoded.length != metadata.dataRange.length) {
        throw const C2paSigningException(
          'BMFF Merkle proof changed after placeholder creation',
        );
      }
      finalFragments.add(
        _replaceBytes(
          stagedFragments[index],
          metadata.dataRange.start,
          metadata.dataRange.end,
          encoded,
        ),
      );
    }
    return FragmentedBmffBuildResult(
      initializationSegment: finalInit,
      fragments: finalFragments,
    );
  }

  Future<void> _saveEmbeddedSource(
    RandomAccessByteSource source,
    WritableByteSink output, {
    String? mimeType,
    String? fileName,
    required bool embedManifest,
  }) async {
    try {
      final registry = AssetHandlerRegistry();
      if (!embedManifest) {
        Object hardBinding;
        try {
          await registry.getCollectionHashLayout(
            source,
            mimeType: mimeType,
            fileExtension: _fileExtension(fileName),
          );
          hardBinding = await _generateZipCollectionHash(
            registry,
            source,
            _parseHashAlgorithm(definition.hashAlgorithm),
            mimeType: mimeType,
            fileName: fileName,
          );
        } on UnsupportedCollectionHashLayoutException {
          hardBinding = await _generateSidecarDataHash(source);
        }
        final manifest = await _buildManifest(hardBinding);
        await _requireEmptyOutput(output);
        await output.append(manifest);
        return;
      }
      try {
        final unsignedLayout = await registry.getBoxHashLayout(
          source,
          mimeType: mimeType,
          fileExtension: _fileExtension(fileName),
        );
        final provisionalManifest = await _buildManifest(
          _placeholderBoxHash(unsignedLayout),
          finalizeDynamicAssertions: false,
        );
        final provisionalOutput = MemoryByteSink();
        await registry.embedManifest(
          source,
          provisionalManifest,
          provisionalOutput,
          mimeType: mimeType,
          fileExtension: _fileExtension(fileName),
        );
        final provisionalSource = MemoryByteSource(provisionalOutput.toBytes());
        final layout = await registry.getBoxHashLayout(
          provisionalSource,
          mimeType: mimeType,
          fileExtension: _fileExtension(fileName),
        );
        final boxHash = await _generateBoxHash(provisionalSource, layout);
        final manifest = await _buildManifest(boxHash);
        await registry.embedManifest(
          source,
          manifest,
          output,
          mimeType: mimeType,
          fileExtension: _fileExtension(fileName),
        );
      } on UnsupportedHashLayoutException {
        try {
          await registry.getBmffHashLayout(
            source,
            _isoBmffExclusions(_bmffExclusions()),
            mimeType: mimeType,
            fileExtension: _fileExtension(fileName),
            version: BmffHashAssertion.version,
          );
          await _saveWithBmffHash(
            registry,
            source,
            output,
            mimeType: mimeType,
            fileName: fileName,
          );
        } on UnsupportedHashLayoutException {
          try {
            await registry.getCollectionHashLayout(
              source,
              mimeType: mimeType,
              fileExtension: _fileExtension(fileName),
            );
            await _saveWithZipCollectionHash(
              registry,
              source,
              output,
              mimeType: mimeType,
              fileName: fileName,
            );
          } on UnsupportedCollectionHashLayoutException {
            await _saveWithDataHash(
              registry,
              source,
              output,
              mimeType: mimeType,
              fileName: fileName,
            );
          }
        }
      }
    } on UnsupportedIsoBmffFeatureException catch (error, stackTrace) {
      throw C2paUnsupportedException(
        error.message,
        cause: error,
        stackTrace: stackTrace,
      );
    } on C2paException {
      rethrow;
    } on Exception catch (error, stackTrace) {
      throw C2paFormatException(
        'Failed to embed the C2PA manifest: $error',
        cause: error,
        stackTrace: stackTrace,
      );
    }
  }

  Future<void> _saveWithBmffHash(
    AssetHandlerRegistry registry,
    RandomAccessByteSource source,
    WritableByteSink output, {
    String? mimeType,
    String? fileName,
  }) async {
    final signer = context.signer;
    if (signer is! C2paReservedSizeSigner ||
        signer.reservedSignatureSize <= 0) {
      throw const C2paSigningException(
        'Embedded BMFF Hash requires an explicit positive '
        'reservedSignatureSize',
      );
    }
    final extension = _fileExtension(fileName);
    final algorithm = _parseHashAlgorithm(definition.hashAlgorithm);
    final hashName = _hashName(algorithm);
    final exclusions = _bmffExclusions();
    final placeholderAssertion = BmffHashAssertion(
      exclusions: exclusions,
      algorithm: hashName,
      hash: List<int>.filled(algorithm.digestLength, 0),
      name: definition.bmffHashName,
    );
    final reservedSigner = _ReservedSignatureSigner(
      signingAlgorithm,
      signer.reservedSignatureSize,
    );
    final placeholder = await _buildManifest(
      placeholderAssertion,
      signingOverride: reservedSigner,
      reportSigning: false,
      finalizeDynamicAssertions: false,
    );
    final staged = MemoryByteSink();
    await registry.embedManifest(
      source,
      placeholder,
      staged,
      mimeType: mimeType,
      fileExtension: extension,
    );
    final stagedSource = MemoryByteSource(staged.toBytes());
    final layout = await registry.getBmffHashLayout(
      stagedSource,
      _isoBmffExclusions(exclusions),
      mimeType: mimeType,
      fileExtension: extension,
      version: BmffHashAssertion.version,
    );
    final digest = await _assetHashEngine().digestEvents(
      stagedSource,
      algorithm,
      _bmffDigestEvents(layout),
    );
    final assertion = BmffHashAssertion(
      exclusions: exclusions,
      algorithm: hashName,
      hash: digest,
      name: definition.bmffHashName,
    );
    final manifest = await _buildManifest(
      assertion,
      signingOverride: _ExactReservedSizeSigner(
        signer,
        signer.reservedSignatureSize,
      ),
    );
    if (manifest.length != placeholder.length) {
      throw C2paSigningException(
        'Final BMFF manifest length ${manifest.length} differs from '
        'placeholder length ${placeholder.length}',
      );
    }
    final patched = MemoryByteSink();
    await registry.replaceManifest(
      stagedSource,
      manifest,
      patched,
      mimeType: mimeType,
      fileExtension: extension,
    );
    if (await patched.length != await staged.length) {
      throw const C2paSigningException(
        'BMFF replacement changed the composed asset length',
      );
    }
    await _requireEmptyOutput(output);
    await output.append(patched.toBytes());
  }

  Future<void> _saveWithZipCollectionHash(
    AssetHandlerRegistry registry,
    RandomAccessByteSource source,
    WritableByteSink output, {
    String? mimeType,
    String? fileName,
  }) async {
    final signer = context.signer;
    if (signer is! C2paReservedSizeSigner ||
        signer.reservedSignatureSize <= 0) {
      throw const C2paSigningException(
        'Embedded Collection Data Hash requires an explicit positive '
        'reservedSignatureSize',
      );
    }
    final extension = _fileExtension(fileName);
    final algorithm = _parseHashAlgorithm(definition.hashAlgorithm);
    final algorithmName = _hashName(algorithm);
    final unsignedLayout = await registry.getCollectionHashLayout(
      source,
      mimeType: mimeType,
      fileExtension: extension,
    );
    final placeholder = CollectionHashAssertion(
      uris: {
        for (final entry in unsignedLayout.entries)
          if (!entry.isDirectory)
            normalizeCollectionUri(entry.uri.path): CollectionHashEntry(
              hash: List<int>.filled(algorithm.digestLength, 0),
              size: entry.range.length,
              format: entry.mimeType,
            ),
      },
      algorithm: algorithmName,
      zipCentralDirectoryHash: List<int>.filled(algorithm.digestLength, 0),
    );
    final placeholderManifest = await _buildManifest(
      placeholder,
      signingOverride: _ReservedSignatureSigner(
        signingAlgorithm,
        signer.reservedSignatureSize,
      ),
      reportSigning: false,
      finalizeDynamicAssertions: false,
    );
    final stagedOutput = MemoryByteSink();
    await registry.embedManifest(
      source,
      placeholderManifest,
      stagedOutput,
      mimeType: mimeType,
      fileExtension: extension,
    );
    final stagedSource = MemoryByteSource(stagedOutput.toBytes());
    final assertion = await _generateZipCollectionHash(
      registry,
      stagedSource,
      algorithm,
      mimeType: mimeType,
      fileName: fileName,
    );
    final manifest = await _buildManifest(
      assertion,
      signingOverride: _ExactReservedSizeSigner(
        signer,
        signer.reservedSignatureSize,
      ),
    );
    if (manifest.length != placeholderManifest.length) {
      throw const C2paSigningException(
        'Collection hash configuration changed after placeholder creation',
      );
    }
    final patched = _patchStoredZipManifest(
      stagedOutput.toBytes(),
      placeholderManifest,
      manifest,
    );
    await _requireEmptyOutput(output);
    await output.append(patched);
  }

  Future<CollectionHashAssertion> _generateZipCollectionHash(
    AssetHandlerRegistry registry,
    RandomAccessByteSource source,
    HashAlgorithm algorithm, {
    String? mimeType,
    String? fileName,
  }) async {
    final layout = await registry.getCollectionHashLayout(
      source,
      mimeType: mimeType,
      fileExtension: _fileExtension(fileName),
    );
    final entries = <String, CollectionHashEntry>{};
    for (final entry in layout.entries) {
      if (entry.isDirectory) continue;
      final uri = normalizeCollectionUri(entry.uri.path);
      if (entries.containsKey(uri)) {
        throw C2paValidationException(
          'Duplicate normalized collection URI: $uri',
        );
      }
      entries[uri] = CollectionHashEntry(
        hash: await _assetHashEngine().digestRanges(source, algorithm, [
          entry.range,
        ]),
        size: entry.range.length,
        format: entry.mimeType,
      );
    }
    final centralDirectoryHash = await _assetHashEngine().digestRanges(
      source,
      algorithm,
      layout.centralDirectoryHashRanges,
    );
    return CollectionHashAssertion(
      uris: entries,
      algorithm: _hashName(algorithm),
      zipCentralDirectoryHash: centralDirectoryHash,
    );
  }

  Future<CollectionHashAssertion> _generateCollectionHash(
    C2paCollectionSource collection,
  ) async {
    final algorithm = _parseHashAlgorithm(definition.hashAlgorithm);
    final items = List<C2paCollectionItem>.from(await collection.entries());
    if (items.length > context.settings.maxResourceCount) {
      throw C2paValidationException(
        'Collection item count ${items.length} exceeds the configured limit '
        'of ${context.settings.maxResourceCount}',
      );
    }
    final entries = <String, CollectionHashEntry>{};
    var totalBytes = 0;
    for (final item in items) {
      final uri = normalizeCollectionUri(item.uri);
      if (entries.containsKey(uri)) {
        throw C2paValidationException(
          'Duplicate normalized collection URI: $uri',
        );
      }
      final length = await item.source.length;
      totalBytes += length;
      if (length > context.settings.maxResourceBytes ||
          totalBytes > context.settings.maxTotalResourceBytes) {
        throw C2paValidationException(
          'Collection content exceeds configured resource limits',
        );
      }
      entries[uri] = CollectionHashEntry(
        hash: await _assetHashEngine().digestSource(item.source, algorithm),
        size: length,
        format: item.format,
        dataTypes: item.dataTypes,
      );
    }
    return CollectionHashAssertion(
      uris: entries,
      algorithm: _hashName(algorithm),
    );
  }

  List<BmffHashExclusion> _bmffExclusions() {
    final exclusions = <BmffHashExclusion>[
      BmffHashExclusion(
        xpath: '/uuid',
        data: [
          BmffHashDataReplacement(
            offset: 8,
            value: const [
              0xd8,
              0xfe,
              0xc3,
              0xd6,
              0x1b,
              0x0e,
              0x48,
              0x3c,
              0x92,
              0x97,
              0x58,
              0x28,
              0x87,
              0x7e,
              0xc4,
              0x81,
            ],
          ),
        ],
      ),
      BmffHashExclusion(xpath: '/ftyp'),
      BmffHashExclusion(xpath: '/mfra'),
      BmffHashExclusion(xpath: '/free'),
      BmffHashExclusion(xpath: '/skip'),
    ];
    for (final custom in definition.bmffExclusions) {
      if (!exclusions.contains(custom)) exclusions.add(custom);
    }
    return List<BmffHashExclusion>.unmodifiable(exclusions);
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

  static List<AssetHashEvent> _bmffDigestEvents(IsoBmffHashLayout layout) =>
      layout.events
          .map<AssetHashEvent>(
            (event) => switch (event) {
              IsoBmffSourceDigestEvent(:final range) => AssetHashRangeEvent(
                range,
              ),
              IsoBmffOffsetDigestEvent(:final bytes) =>
                AssetHashInjectedBytesEvent(bytes),
            },
          )
          .toList(growable: false);

  static int _eventLength(Iterable<IsoBmffDigestEvent> events) => events.fold(
    0,
    (length, event) =>
        length +
        switch (event) {
          IsoBmffSourceDigestEvent(:final range) => range.length,
          IsoBmffOffsetDigestEvent(:final bytes) => bytes.length,
        },
  );

  static Future<Uint8List> _readAll(RandomAccessByteSource source) async {
    final length = await source.length;
    return source.read(ByteRange(0, length));
  }

  static Uint8List _insertBytes(List<int> source, int offset, List<int> value) {
    if (offset < 0 || offset > source.length) {
      throw const C2paFormatException('BMFF insertion offset is invalid');
    }
    return Uint8List.fromList([
      ...source.take(offset),
      ...value,
      ...source.skip(offset),
    ]);
  }

  static Uint8List _replaceBytes(
    List<int> source,
    int start,
    int end,
    List<int> value,
  ) {
    if (start < 0 ||
        end < start ||
        end > source.length ||
        value.length != end - start) {
      throw const C2paSigningException(
        'BMFF placeholder replacement size is invalid',
      );
    }
    final result = Uint8List.fromList(source);
    result.setRange(start, end, value);
    return result;
  }

  static Uint8List _encodeC2paUuidBox(String purpose, List<int> payload) {
    final purposeBytes = [...purpose.codeUnits, 0];
    final hasAuxiliaryOffset =
        purpose == 'manifest' || purpose == 'original' || purpose == 'update';
    final size =
        8 +
        16 +
        4 +
        purposeBytes.length +
        (hasAuxiliaryOffset ? 8 : 0) +
        payload.length;
    if (size > 0xffffffff) {
      throw C2paSigningException(
        'BMFF C2PA UUID box size $size exceeds the 32-bit limit',
      );
    }
    final bytes = Uint8List(size);
    ByteData.sublistView(bytes).setUint32(0, size, Endian.big);
    bytes.setRange(4, 8, 'uuid'.codeUnits);
    bytes.setRange(8, 24, IsoBmffAssetHandler.c2paUuid);
    bytes.setRange(28, 28 + purposeBytes.length, purposeBytes);
    final payloadOffset =
        28 + purposeBytes.length + (hasAuxiliaryOffset ? 8 : 0);
    bytes.setRange(payloadOffset, size, payload);
    return bytes;
  }

  static Uint8List _patchStoredZipManifest(
    List<int> archive,
    List<int> placeholder,
    List<int> manifest,
  ) {
    if (placeholder.length != manifest.length) {
      throw const C2paSigningException(
        'ZIP collection manifest changed its reserved size',
      );
    }
    final bytes = Uint8List.fromList(archive);
    final payloadOffset = _indexOfBytes(bytes, placeholder);
    if (payloadOffset < 0 ||
        _indexOfBytes(bytes, placeholder, payloadOffset + 1) >= 0) {
      throw const C2paSigningException(
        'ZIP collection manifest placeholder is missing or ambiguous',
      );
    }
    var localOffset = -1;
    for (var offset = payloadOffset - 30; offset >= 0; offset--) {
      if (_uint32Little(bytes, offset) != 0x04034b50) continue;
      final nameLength = _uint16Little(bytes, offset + 26);
      final extraLength = _uint16Little(bytes, offset + 28);
      if (offset + 30 + nameLength + extraLength == payloadOffset) {
        localOffset = offset;
        break;
      }
    }
    if (localOffset < 0 || _uint16Little(bytes, localOffset + 8) != 0) {
      throw const C2paSigningException(
        'ZIP collection manifest must be a stored local entry',
      );
    }
    bytes.setRange(payloadOffset, payloadOffset + manifest.length, manifest);
    final crc = _crc32(manifest);
    _setUint32Little(bytes, localOffset + 14, crc);

    final manifestName = utf8.encode(ZipAssetHandler.manifestPath);
    var centralOffset = 0;
    var patchedCentral = false;
    while (centralOffset <= bytes.length - 46) {
      centralOffset = _indexOfBytes(bytes, const [
        0x50,
        0x4b,
        0x01,
        0x02,
      ], centralOffset);
      if (centralOffset < 0) break;
      final nameLength = _uint16Little(bytes, centralOffset + 28);
      final extraLength = _uint16Little(bytes, centralOffset + 30);
      final commentLength = _uint16Little(bytes, centralOffset + 32);
      final nameStart = centralOffset + 46;
      if (nameStart + nameLength <= bytes.length &&
          _equalByteLists(
            bytes.sublist(nameStart, nameStart + nameLength),
            manifestName,
          )) {
        _setUint32Little(bytes, centralOffset + 16, crc);
        patchedCentral = true;
        break;
      }
      centralOffset = nameStart + nameLength + extraLength + commentLength;
    }
    if (!patchedCentral) {
      throw const C2paSigningException(
        'ZIP collection manifest central-directory entry is missing',
      );
    }
    return bytes;
  }

  static int _indexOfBytes(
    List<int> bytes,
    List<int> pattern, [
    int start = 0,
  ]) {
    for (
      var offset = start;
      offset <= bytes.length - pattern.length;
      offset++
    ) {
      var matches = true;
      for (var index = 0; index < pattern.length; index++) {
        if (bytes[offset + index] != pattern[index]) {
          matches = false;
          break;
        }
      }
      if (matches) return offset;
    }
    return -1;
  }

  static int _uint16Little(List<int> bytes, int offset) =>
      bytes[offset] | bytes[offset + 1] << 8;

  static int _uint32Little(List<int> bytes, int offset) =>
      bytes[offset] |
      bytes[offset + 1] << 8 |
      bytes[offset + 2] << 16 |
      bytes[offset + 3] << 24;

  static void _setUint32Little(Uint8List bytes, int offset, int value) {
    bytes[offset] = value;
    bytes[offset + 1] = value >> 8;
    bytes[offset + 2] = value >> 16;
    bytes[offset + 3] = value >> 24;
  }

  static bool _equalByteLists(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }

  static int _crc32(List<int> bytes) {
    var crc = 0xffffffff;
    for (final byte in bytes) {
      crc ^= byte;
      for (var bit = 0; bit < 8; bit++) {
        crc = crc & 1 == 0 ? crc >> 1 : (crc >> 1) ^ 0xedb88320;
      }
    }
    return (crc ^ 0xffffffff) & 0xffffffff;
  }

  static int _merkleProofSiblingCount(int count, int location) {
    var layerSize = count;
    var index = location;
    var result = 0;
    while (layerSize > 1) {
      if (index.isOdd || index + 1 < layerSize) result++;
      index ~/= 2;
      layerSize = (layerSize + 1) ~/ 2;
    }
    return result;
  }

  static Future<_MerkleTree> _buildMerkleTree(
    List<Uint8List> leaves,
    HashAlgorithm algorithm,
  ) async {
    if (leaves.isEmpty) {
      throw const C2paValidationException(
        'A BMFF Merkle tree requires at least one leaf',
      );
    }
    final layers = <List<Uint8List>>[List<Uint8List>.unmodifiable(leaves)];
    while (layers.last.length > 1) {
      final current = layers.last;
      final parent = <Uint8List>[];
      for (var index = 0; index < current.length; index += 2) {
        if (index + 1 == current.length) {
          parent.add(current[index]);
        } else {
          parent.add(
            Uint8List.fromList(
              await algorithm.digest([
                ...current[index],
                ...current[index + 1],
              ]),
            ),
          );
        }
      }
      layers.add(List<Uint8List>.unmodifiable(parent));
    }
    return _MerkleTree(List<List<Uint8List>>.unmodifiable(layers));
  }

  static List<Uint8List> _merkleProof(
    List<List<Uint8List>> layers,
    int location,
  ) {
    final result = <Uint8List>[];
    var index = location;
    for (final layer in layers.take(layers.length - 1)) {
      if (index.isOdd) {
        result.add(layer[index - 1]);
      } else if (index + 1 < layer.length) {
        result.add(layer[index + 1]);
      }
      index ~/= 2;
    }
    return List<Uint8List>.unmodifiable(result);
  }

  Future<void> _saveWithDataHash(
    AssetHandlerRegistry registry,
    RandomAccessByteSource source,
    WritableByteSink output, {
    String? mimeType,
    String? fileName,
  }) async {
    final signer = context.signer;
    if (signer is! C2paReservedSizeSigner ||
        signer.reservedSignatureSize <= 0) {
      throw const C2paSigningException(
        'Embedded DataHash requires an explicit positive '
        'reservedSignatureSize',
      );
    }
    final extension = _fileExtension(fileName);
    await registry.getDataHashLayout(
      source,
      mimeType: mimeType,
      fileExtension: extension,
    );
    final machine = DataHashBuildStateMachine();
    final hashAlgorithm = _parseHashAlgorithm(definition.hashAlgorithm);
    final hashName = _hashName(hashAlgorithm);
    const paddingReserve = 1024;
    final initial = DataHashAssertion(
      algorithm: hashName,
      hash: List<int>.filled(hashAlgorithm.digestLength, 0),
      pad: List<int>.filled(paddingReserve, 0),
    );
    final targetPayloadSize = encodeCbor(initial.toCborMap()).length;
    final reservedSigner = _ReservedSignatureSigner(
      signingAlgorithm,
      signer.reservedSignatureSize,
    );
    var placeholder = await _buildManifest(
      initial,
      signingOverride: reservedSigner,
      reportSigning: false,
      finalizeDynamicAssertions: false,
    );
    machine.advance(DataHashBuildState.placeholderCreated);

    var staged = MemoryByteSink();
    await registry.embedManifest(
      source,
      placeholder,
      staged,
      mimeType: mimeType,
      fileExtension: extension,
    );
    machine.advance(DataHashBuildState.placeholderEmbedded);

    var stagedSource = MemoryByteSource(staged.toBytes());
    var layout = await registry.getDataHashLayout(
      stagedSource,
      mimeType: mimeType,
      fileExtension: extension,
    );
    var binding = _padDataHash(
      DataHashAssertion(
        exclusions: _dataHashRanges(layout),
        algorithm: hashName,
        hash: List<int>.filled(hashAlgorithm.digestLength, 0),
      ),
      targetPayloadSize,
    );
    placeholder = await _buildManifest(
      binding,
      signingOverride: reservedSigner,
      reportSigning: false,
      finalizeDynamicAssertions: false,
    );
    staged = MemoryByteSink();
    await registry.embedManifest(
      source,
      placeholder,
      staged,
      mimeType: mimeType,
      fileExtension: extension,
    );
    stagedSource = MemoryByteSource(staged.toBytes());
    layout = await registry.getDataHashLayout(
      stagedSource,
      mimeType: mimeType,
      fileExtension: extension,
    );

    final digest = await _assetHashEngine().digestExcluding(
      stagedSource,
      hashAlgorithm,
      layout.exclusions.map((item) => item.range),
    );
    binding = _padDataHash(
      DataHashAssertion(
        exclusions: _dataHashRanges(layout),
        algorithm: hashName,
        hash: digest,
      ),
      targetPayloadSize,
    );
    machine.advance(DataHashBuildState.bindingFinalized);

    final finalSigner = _ExactReservedSizeSigner(
      signer,
      signer.reservedSignatureSize,
    );
    final manifest = await _buildManifest(
      binding,
      signingOverride: finalSigner,
    );
    machine.advance(DataHashBuildState.signed);
    if (manifest.length != placeholder.length) {
      throw C2paSigningException(
        'Final DataHash manifest length ${manifest.length} differs from '
        'reserved placeholder length ${placeholder.length}',
      );
    }

    final patched = MemoryByteSink();
    final manifestExclusions = layout.exclusions
        .where((item) => item.kind == DataHashExclusionKind.manifest)
        .toList(growable: false);
    if (manifestExclusions.length == 1 &&
        manifestExclusions.single.range.length == manifest.length) {
      await patched.append(staged.toBytes());
      await patched.writeAt(manifestExclusions.single.range.start, manifest);
    } else {
      await registry.replaceManifest(
        stagedSource,
        manifest,
        patched,
        mimeType: mimeType,
        fileExtension: extension,
      );
    }
    final patchedLength = await patched.length;
    final stagedLength = await staged.length;
    if (patchedLength != stagedLength) {
      throw C2paSigningException(
        'DataHash replacement changed the composed asset length '
        'from $stagedLength to $patchedLength',
      );
    }
    machine.advance(DataHashBuildState.patched);
    await _requireEmptyOutput(output);
    await output.append(patched.toBytes());
  }

  Future<DataHashAssertion> _generateSidecarDataHash(
    RandomAccessByteSource source,
  ) async {
    final algorithm = _parseHashAlgorithm(definition.hashAlgorithm);
    return DataHashAssertion(
      algorithm: _hashName(algorithm),
      hash: await _assetHashEngine().digestSource(source, algorithm),
    );
  }

  AssetHashEngine _assetHashEngine() => AssetHashEngine(
    isCancelled: context.isCancelled,
    onProgress: (progress) {
      unawaited(
        context.reportProgress(
          C2paProgressEvent(
            phase: C2paProgressPhase.signing,
            completed: progress.bytesProcessed,
            total: progress.totalBytes,
            message: 'Hashing asset',
          ),
        ),
      );
    },
  );

  static List<DataHashExclusionRange> _dataHashRanges(DataHashLayout layout) =>
      layout.exclusions
          .map(
            (item) => DataHashExclusionRange(
              start: item.range.start,
              length: item.range.length,
            ),
          )
          .toList(growable: false);

  static DataHashAssertion _padDataHash(
    DataHashAssertion assertion,
    int targetSize,
  ) {
    for (var padLength = targetSize; padLength >= 0; padLength--) {
      final candidate = DataHashAssertion(
        exclusions: assertion.exclusions,
        name: assertion.name,
        algorithm: assertion.algorithm,
        hash: assertion.hash,
        pad: List<int>.filled(padLength, 0),
      );
      final length = encodeCbor(candidate.toCborMap()).length;
      if (length == targetSize) return candidate;
      if (length < targetSize) break;
    }
    for (
      var firstPad = 0;
      firstPad <= 512 && firstPad <= targetSize;
      firstPad++
    ) {
      final withEmptySecondPad = DataHashAssertion(
        exclusions: assertion.exclusions,
        name: assertion.name,
        algorithm: assertion.algorithm,
        hash: assertion.hash,
        pad: List<int>.filled(firstPad, 0),
        pad2: const [],
      );
      final remaining =
          targetSize - encodeCbor(withEmptySecondPad.toCborMap()).length;
      for (var adjustment = -4; adjustment <= 4; adjustment++) {
        final secondPad = remaining + adjustment;
        if (secondPad < 0) continue;
        final candidate = DataHashAssertion(
          exclusions: assertion.exclusions,
          name: assertion.name,
          algorithm: assertion.algorithm,
          hash: assertion.hash,
          pad: List<int>.filled(firstPad, 0),
          pad2: List<int>.filled(secondPad, 0),
        );
        if (encodeCbor(candidate.toCborMap()).length == targetSize) {
          return candidate;
        }
      }
    }
    throw C2paSigningException(
      'DataHash assertion cannot fit the reserved $targetSize-byte payload',
    );
  }

  static Future<void> _requireEmptyOutput(WritableByteSink output) async {
    if (await output.length != 0) {
      throw const C2paFormatException('The destination sink must be empty');
    }
  }

  void _validateDefinition() {
    _validateLabel(definition.label, 'manifest label');
    if (definition.format.trim().isEmpty) {
      throw const C2paValidationException('Manifest format must not be empty');
    }
    if (definition.instanceId.trim().isEmpty) {
      throw const C2paValidationException(
        'Manifest instance ID must not be empty',
      );
    }
    if (x5chain.isEmpty || x5chain.any((certificate) => certificate.isEmpty)) {
      throw const C2paSigningException(
        'Caller-provided x5chain/key material must not be empty',
      );
    }

    final assertionLabels = <String>{ActionsAssertion.versionedLabel};
    for (var index = 0; index < definition.ingredients.length; index++) {
      assertionLabels.add(_ingredientLabel(index));
    }
    for (final assertion in definition.assertions) {
      _validateLabel(assertion.label, 'assertion label');
      if (assertion.label.startsWith('c2pa.hash.')) {
        throw const C2paValidationException(
          'The BoxHash hard-binding assertion is generated by C2paBuilder',
        );
      }
      if (!assertionLabels.add(assertion.label)) {
        throw C2paValidationException(
          'Duplicate or reserved assertion label: ${assertion.label}',
        );
      }

      _encodeAssertionPayload(assertion);
      if (assertion.label.split('__').first ==
              C2paSoftBindingAssertion.baseLabel &&
          assertion.data is Map &&
          !(assertion.data! as Map).containsKey('alg') &&
          definition.softBindingAlgorithm == null) {
        throw const C2paValidationException(
          'A soft binding requires alg or claim alg_soft',
        );
      }
    }
    for (final assertion in dynamicAssertions) {
      _validateLabel(assertion.label, 'dynamic assertion label');
      if (assertion.label.startsWith('c2pa.hash.')) {
        throw _validationFailure(
          'Dynamic assertions cannot provide a hard binding',
          ValidationCode.generalError,
        );
      }
      if (assertion.reservedSize < 1) {
        throw _validationFailure(
          'Dynamic assertion ${assertion.label} must reserve at least one byte',
          ValidationCode.generalError,
        );
      }
      if (assertion.encoding == C2paDynamicAssertionEncoding.binary &&
          (assertion.contentType == null ||
              assertion.contentType!.trim().isEmpty)) {
        throw _validationFailure(
          'Dynamic binary assertion ${assertion.label} requires a content type',
          ValidationCode.generalError,
        );
      }
      if (assertion.encoding != C2paDynamicAssertionEncoding.binary &&
          assertion.contentType != null) {
        throw _validationFailure(
          'Only dynamic binary assertions may declare a content type',
          ValidationCode.generalError,
        );
      }
      if (!assertionLabels.add(assertion.label)) {
        throw _validationFailure(
          'Duplicate or reserved assertion label: ${assertion.label}',
          ValidationCode.assertionUndeclared,
        );
      }
    }

    final resourceLabels = <String>{};
    final resourceLimits = ResourceStore(settings: context.settings);
    for (final resource in definition.resources) {
      _validateLabel(resource.label, 'resource label');
      if (resource.format.trim().isEmpty) {
        throw C2paValidationException(
          'Resource ${resource.label} must have a media type',
        );
      }
      if (!resourceLabels.add(resource.label)) {
        throw C2paValidationException(
          'Duplicate resource label: ${resource.label}',
        );
      }
      resourceLimits.add(
        'self#jumbf=c2pa.databoxes/${resource.label}',
        resource.bytes,
      );
    }

    final redactions = <String>{};
    for (final redaction in definition.redactions) {
      if (redaction.trim().isEmpty ||
          !redaction.contains('jumbf=') ||
          !redactions.add(redaction)) {
        throw C2paValidationException(
          'Invalid or duplicate redaction URI: $redaction',
        );
      }
    }

    final ingredientIds = <String>{};
    var parentCount = 0;
    final embeddedAssertions = <String, Set<String>>{};
    for (final ingredient in definition.ingredients) {
      if (ingredient.id.trim().isEmpty || !ingredientIds.add(ingredient.id)) {
        throw C2paValidationException(
          'Ingredient IDs must be non-empty and unique: ${ingredient.id}',
        );
      }
      if (ingredient.assertion.relationship == Relationship.parentOf) {
        parentCount++;
      }
      for (final bytes in ingredient.manifestBoxes) {
        final node = parseJumbf(bytes);
        final label = node.label;
        if (label == null || embeddedAssertions.containsKey(label)) {
          throw C2paValidationException(
            'Duplicate embedded ingredient manifest label: $label',
          );
        }
        final assertionStores = node.children
            .whereType<JumbfSuperBoxNode>()
            .where(
              (child) =>
                  child.description.contentTypeHex ==
                  JumbfUuid.c2paAssertionStore,
            );
        embeddedAssertions[label] = assertionStores.isEmpty
            ? const {}
            : assertionStores.single.children
                  .whereType<JumbfSuperBoxNode>()
                  .map((assertion) => assertion.label)
                  .whereType<String>()
                  .toSet();
      }
    }
    for (final action in definition.actions) {
      for (final id in action.parameters?.ingredientIds ?? const <String>[]) {
        if (!ingredientIds.contains(id)) {
          throw C2paValidationException(
            'Action ${action.action} references unknown ingredient ID: $id',
          );
        }
      }
    }

    switch (definition.intent) {
      case CreateIntent():
        if (parentCount != 0) {
          throw _validationFailure(
            'Create intent cannot contain a parent ingredient',
            ValidationCode.generalError,
          );
        }
      case EditIntent():
        if (parentCount != 1) {
          throw _validationFailure(
            'Edit intent requires exactly one parent ingredient',
            parentCount > 1
                ? ValidationCode.manifestMultipleParents
                : ValidationCode.generalError,
          );
        }
      case UpdateIntent():
        if (definition.ingredients.length != 1 || parentCount != 1) {
          throw _validationFailure(
            'Update intent requires exactly one parent ingredient',
            ValidationCode.manifestUpdateWrongParents,
          );
        }
        if (definition.redactions.isNotEmpty ||
            definition.resources.isNotEmpty ||
            definition.assertions.isNotEmpty ||
            dynamicAssertions.isNotEmpty ||
            definition.actions.isNotEmpty) {
          throw _validationFailure(
            'Update intent requires exactly one parent and cannot add custom '
            'assertions, dynamic assertions, actions, resources, redactions, '
            'or other ingredients',
            ValidationCode.manifestUpdateInvalid,
          );
        }
    }
    _validateRedactions(embeddedAssertions);
  }

  void _validateRedactions(Map<String, Set<String>> ingredientAssertions) {
    final actionRedactions = definition.actions
        .where((action) => action.action == C2paActionNames.redacted)
        .map((action) => action.parameters?.redacted)
        .whereType<String>()
        .toSet();
    for (final redaction in definition.redactions) {
      final marker = '/c2pa/';
      final markerIndex = redaction.indexOf(marker);
      final assertionMarker = '/c2pa.assertions/';
      final assertionIndex = redaction.indexOf(assertionMarker);
      if (markerIndex < 0 || assertionIndex <= markerIndex + marker.length) {
        throw _validationFailure(
          'Redaction URI does not identify an ingredient assertion: $redaction',
          ValidationCode.assertionNotRedacted,
        );
      }
      final manifestLabel = Uri.decodeComponent(
        redaction.substring(markerIndex + marker.length, assertionIndex),
      );
      final assertionLabel = Uri.decodeComponent(
        redaction.substring(assertionIndex + assertionMarker.length),
      );
      if (manifestLabel == definition.label) {
        throw _validationFailure(
          'A claim cannot redact one of its own assertions: $redaction',
          ValidationCode.assertionSelfRedacted,
        );
      }
      final baseLabel = assertionLabel.split('__').first;
      if (baseLabel == ActionsAssertion.label ||
          baseLabel == ActionsAssertion.versionedLabel) {
        throw _validationFailure(
          'Actions assertions cannot be redacted',
          ValidationCode.assertionActionRedacted,
        );
      }
      if (baseLabel.startsWith('c2pa.hash.')) {
        throw _validationFailure(
          'Hard-binding assertions cannot be redacted',
          ValidationCode.assertionDataHashRedacted,
        );
      }
      final availableAssertions = ingredientAssertions[manifestLabel];
      if (availableAssertions == null ||
          !availableAssertions.contains(assertionLabel)) {
        throw _validationFailure(
          'Redaction target is not present in an ingredient: $redaction',
          ValidationCode.assertionNotRedacted,
        );
      }
      if (!actionRedactions.contains(redaction)) {
        throw _validationFailure(
          'Redaction has no matching c2pa.redacted action: $redaction',
          ValidationCode.assertionActionRedactionMismatch,
        );
      }
    }
    for (final actionRedaction in actionRedactions) {
      if (!definition.redactions.contains(actionRedaction)) {
        throw _validationFailure(
          'c2pa.redacted action has no matching redaction: $actionRedaction',
          ValidationCode.assertionActionRedactionMismatch,
        );
      }
    }
  }

  C2paValidationException _validationFailure(
    String message,
    ValidationCode code,
  ) => C2paValidationException(
    message,
    results: ValidationResults.fromIssues([
      ValidationIssue.known(
        code: code,
        url: 'self#jumbf=/c2pa/${definition.label}',
        explanation: message,
      ),
    ]),
  );

  Future<BoxHashAssertion> _generateBoxHash(
    RandomAccessByteSource source,
    BoxHashLayout layout,
  ) async {
    final algorithm = _parseHashAlgorithm(definition.hashAlgorithm);
    final hashName = _hashName(algorithm);
    final included = layout.entries
        .where((entry) => !_isExcludedBox(entry))
        .map((entry) => entry.range)
        .toList(growable: false);
    final digests = await AssetHashEngine().digestRangesIndependently(
      source,
      algorithm,
      included,
    );
    var digestIndex = 0;
    return BoxHashAssertion(
      boxes: [
        for (final entry in layout.entries)
          if (_isExcludedBox(entry))
            BoxHashBox(
              names: entry.names,
              hash: entry.names.length == 1 && entry.names.single == 'C2PA'
                  ? const [0]
                  : const [],
              excluded: true,
            )
          else
            BoxHashBox(
              names: entry.names,
              algorithm: hashName,
              hash: digests[digestIndex++].digest,
            ),
      ],
    );
  }

  static BoxHashAssertion _placeholderBoxHash(BoxHashLayout layout) =>
      BoxHashAssertion(
        boxes: [
          for (final entry in layout.entries)
            BoxHashBox(
              names: entry.names,
              hash: entry.names.length == 1 && entry.names.single == 'C2PA'
                  ? const [0]
                  : const [],
              excluded: _isExcludedBox(entry),
            ),
        ],
      );

  static bool _isExcludedBox(BoxHashEntry entry) =>
      entry.excluded ||
      (entry.names.length == 1 && entry.names.single == 'C2PA');

  static JumbfSuperBoxNode _boxHashAssertion(BoxHashAssertion assertion) =>
      JumbfSuperBoxNode(
        description: JumbfDescription.fromUuidHex(
          contentType: JumbfUuid.cbor,
          label: BoxHashAssertion.label,
        ),
        children: [JumbfCborNode(encodeCbor(assertion.toCborMap()))],
      );

  static JumbfSuperBoxNode _dataHashAssertion(DataHashAssertion assertion) =>
      JumbfSuperBoxNode(
        description: JumbfDescription.fromUuidHex(
          contentType: JumbfUuid.cbor,
          label: DataHashAssertion.label,
        ),
        children: [JumbfCborNode(encodeCbor(assertion.toCborMap()))],
      );

  static JumbfSuperBoxNode _bmffHashAssertion(BmffHashAssertion assertion) =>
      JumbfSuperBoxNode(
        description: JumbfDescription.fromUuidHex(
          contentType: JumbfUuid.cbor,
          label: BmffHashAssertion.label,
        ),
        children: [JumbfCborNode(encodeCbor(assertion.toCborMap()))],
      );

  static JumbfSuperBoxNode _collectionHashAssertion(
    CollectionHashAssertion assertion,
  ) => JumbfSuperBoxNode(
    description: JumbfDescription.fromUuidHex(
      contentType: JumbfUuid.cbor,
      label: CollectionHashAssertion.label,
    ),
    children: [JumbfCborNode(encodeCbor(assertion.toCborMap()))],
  );

  static JumbfSuperBoxNode _hardBindingAssertion(Object assertion) {
    if (assertion is BoxHashAssertion) return _boxHashAssertion(assertion);
    if (assertion is DataHashAssertion) return _dataHashAssertion(assertion);
    if (assertion is BmffHashAssertion) return _bmffHashAssertion(assertion);
    if (assertion is CollectionHashAssertion) {
      return _collectionHashAssertion(assertion);
    }
    throw ArgumentError.value(assertion, 'hardBinding');
  }

  Future<List<Map<String, Object?>>> _assertionReferences(
    Iterable<JumbfSuperBoxNode> assertions,
    HashAlgorithm algorithm,
  ) async {
    final references = <Map<String, Object?>>[];
    for (final assertion in assertions) {
      references.add({
        'url':
            'self#jumbf=c2pa.assertions/'
            '${Uri.encodeComponent(assertion.label!)}',
        'alg': _hashName(algorithm),
        'alg_soft': ?definition.softBindingAlgorithm,
        'hash': Uint8List.fromList(
          await algorithm.digest(_boxPayload(assertion.rawBytes)),
        ),
      });
    }
    return references;
  }

  JumbfSuperBoxNode _dynamicPlaceholderNode(C2paDynamicAssertion assertion) {
    final payload = switch (assertion.encoding) {
      C2paDynamicAssertionEncoding.cbor => _cborPlaceholder(
        assertion.reservedSize,
      ),
      C2paDynamicAssertionEncoding.json => _jsonPlaceholder(
        assertion.reservedSize,
      ),
      C2paDynamicAssertionEncoding.binary => Uint8List(assertion.reservedSize),
    };
    return _dynamicNode(assertion, payload);
  }

  Future<JumbfSuperBoxNode> _resolveDynamicAssertion(
    C2paDynamicAssertion assertion,
    C2paDynamicClaimContext claim,
  ) async {
    late C2paDynamicAssertionOutput output;
    try {
      output = await assertion.callback(
        C2paDynamicAssertionRequest(
          label: assertion.label,
          reservedSize: assertion.reservedSize,
          claim: claim,
        ),
      );
    } catch (error, stackTrace) {
      throw C2paSigningException(
        'Dynamic assertion ${assertion.label} callback failed: $error',
        cause: error,
        stackTrace: stackTrace,
      );
    }
    if (output.label != assertion.label) {
      throw C2paSigningException(
        'Dynamic assertion returned label ${output.label}; '
        'expected ${assertion.label}',
      );
    }
    if (output.encoding != assertion.encoding ||
        output.contentType != assertion.contentType) {
      throw C2paSigningException(
        'Dynamic assertion ${assertion.label} changed its declared encoding',
      );
    }
    final definition = switch (output.encoding) {
      C2paDynamicAssertionEncoding.cbor => AssertionDefinition.cbor(
        label: output.label,
        data: output.data,
      ),
      C2paDynamicAssertionEncoding.json => AssertionDefinition.json(
        label: output.label,
        data: output.data,
      ),
      C2paDynamicAssertionEncoding.binary => AssertionDefinition.binary(
        label: output.label,
        contentType: output.contentType!,
        data: output.data! as Uint8List,
      ),
    };
    final payload = _encodeAssertionPayload(definition);
    if (payload.length != assertion.reservedSize) {
      throw C2paSigningException(
        'Dynamic assertion ${assertion.label} produced ${payload.length} '
        'bytes; expected exactly ${assertion.reservedSize}',
      );
    }
    return _assertionNode(definition);
  }

  static JumbfSuperBoxNode _dynamicNode(
    C2paDynamicAssertion assertion,
    Uint8List payload,
  ) {
    if (assertion.encoding == C2paDynamicAssertionEncoding.binary) {
      return JumbfSuperBoxNode(
        description: JumbfDescription.fromUuidHex(
          contentType: JumbfUuid.c2paEmbeddedFile,
          label: assertion.label,
        ),
        children: [
          JumbfEmbeddedFileDescriptionNode(mediaType: assertion.contentType!),
          JumbfEmbeddedFileNode(payload),
        ],
      );
    }
    return JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: assertion.encoding == C2paDynamicAssertionEncoding.json
            ? JumbfUuid.json
            : JumbfUuid.cbor,
        label: assertion.label,
      ),
      children: [
        if (assertion.encoding == C2paDynamicAssertionEncoding.json)
          JumbfJsonNode(payload)
        else
          JumbfCborNode(payload),
      ],
    );
  }

  static Uint8List _cborPlaceholder(int size) {
    for (var payloadSize = size; payloadSize >= 0; payloadSize--) {
      final encoded = encodeCbor(Uint8List(payloadSize));
      if (encoded.length == size) return encoded;
    }
    throw C2paValidationException(
      'Dynamic CBOR assertion reservation $size cannot hold one CBOR value',
    );
  }

  static Uint8List _jsonPlaceholder(int size) {
    final value = switch (size) {
      1 => '0',
      2 => '[]',
      3 => '[0]',
      _ when size >= 4 => 'null${List.filled(size - 4, ' ').join()}',
      _ => throw C2paValidationException(
        'Dynamic JSON assertion reservation must be positive',
      ),
    };
    return Uint8List.fromList(utf8.encode(value));
  }

  static String _hashName(HashAlgorithm algorithm) =>
      algorithm.name.toLowerCase().replaceAll('-', '');

  Future<Uint8List> _timestampCose(
    Uint8List cose,
    C2paTimestampConfig config, {
    required bool createPlaceholder,
  }) async {
    if (createPlaceholder) {
      return _attachSigTst2(
        cose,
        Uint8List(config.reservedSize),
        config.reservedSize,
      );
    }
    if (await context.isCancelled?.call() ?? false) {
      throw const C2paTimestampException('Timestamp request was cancelled');
    }
    final message = CoseSign1.parse(cose);
    final signedBytes = encodeCbor(<Object?>[
      'CounterSignature',
      message.protectedBytes,
      Uint8List(0),
      encodeCbor(message.signature),
    ]);
    Uint8List token;
    final supplied = config.token;
    if (supplied != null) {
      token = supplied;
    } else {
      final callback = config.callback!;
      final request = await createTimestampRequest(
        signedBytes: signedBytes,
        hashAlgorithm: _parseHashAlgorithm(config.hashAlgorithm),
        policyOid: config.policyOid,
        nonce: config.nonce,
      );
      try {
        final future = callback(
          Uint8List.fromList(request).asUnmodifiableView(),
        );
        final response = await future.timeout(
          config.timeout ?? context.settings.networkTimeout,
        );
        token = _timestampTokenFromResponse(response) ?? response;
      } on TimeoutException catch (error, stackTrace) {
        throw C2paTimestampException(
          'Timestamp authority request timed out',
          cause: error,
          stackTrace: stackTrace,
        );
      } on C2paTimestampException {
        rethrow;
      } on Object catch (error, stackTrace) {
        throw C2paTimestampException(
          'Timestamp authority request failed: $error',
          cause: error,
          stackTrace: stackTrace,
        );
      }
    }
    if (await context.isCancelled?.call() ?? false) {
      throw const C2paTimestampException('Timestamp request was cancelled');
    }
    if (token.length > config.reservedSize) {
      throw C2paTimestampLimitException(
        limit: config.reservedSize,
        actual: token.length,
      );
    }
    final trust = context.timestampTrust;
    final verification = await verifyTimestampToken(
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
    final onlyTrustFailure =
        verification.token != null &&
        verification.issues.every(
          (issue) => issue.code == TimestampIssueCode.untrustedCertificatePath,
        );
    if (!verification.isValid &&
        !(onlyTrustFailure && !context.timestampTrust.verifyTrust)) {
      throw C2paTimestampException(
        'Timestamp token does not bind the claim signature: '
        '${verification.issues.map((issue) => issue.message).join('; ')}',
      );
    }
    return _attachSigTst2(cose, token, config.reservedSize);
  }

  static Uint8List _attachSigTst2(
    Uint8List cose,
    Uint8List token,
    int reservedSize,
  ) {
    if (token.length > reservedSize) {
      throw C2paTimestampLimitException(
        limit: reservedSize,
        actual: token.length,
      );
    }
    Uint8List encodeWithPadding(Uint8List value, int padding) {
      final tagged = cose.isNotEmpty && cose.first == 0xd2;
      final decoded = decodeCbor(
        tagged ? Uint8List.sublistView(cose, 1) : cose,
      );
      if (decoded is! List || decoded.length != 4) {
        throw const C2paTimestampException(
          'Signer did not return a tagged COSE_Sign1 value',
        );
      }
      final values = List<Object?>.from(decoded);
      if (values[1] is! Map) {
        throw const C2paTimestampException(
          'COSE_Sign1 unprotected headers are malformed',
        );
      }
      final unprotected = Map<Object?, Object?>.from(values[1] as Map);
      if (unprotected.containsKey('sigTst') ||
          unprotected.containsKey('sigTst2')) {
        throw const C2paTimestampException(
          'Signer supplied conflicting timestamp headers',
        );
      }
      unprotected['sigTst2'] = {
        'tstTokens': [
          {'val': Uint8List.fromList(value)},
        ],
        'pad': Uint8List(padding),
      };
      values[1] = unprotected;
      final encoded = encodeCbor(values);
      return tagged ? Uint8List.fromList([0xd2, ...encoded]) : encoded;
    }

    final targetLength = encodeWithPadding(Uint8List(reservedSize), 0).length;
    if (token.length == reservedSize) return encodeWithPadding(token, 0);
    for (var padding = 0; padding <= reservedSize + 16; padding++) {
      final candidate = encodeWithPadding(token, padding);
      if (candidate.length == targetLength) return candidate;
    }
    throw const C2paTimestampException(
      'Unable to fit timestamp into its reserved COSE space',
    );
  }

  static Uint8List _attachUnprotectedHeader(
    Uint8List cose,
    Object key,
    Object? value,
  ) {
    final tagged = cose.isNotEmpty && cose.first == 0xd2;
    final decoded = decodeCbor(tagged ? Uint8List.sublistView(cose, 1) : cose);
    if (decoded is! List || decoded.length != 4 || decoded[1] is! Map) {
      throw const C2paSigningException(
        'Signer did not return a valid COSE_Sign1 value',
      );
    }
    final values = List<Object?>.from(decoded);
    final headers = Map<Object?, Object?>.from(decoded[1] as Map);
    if (headers.containsKey(key)) {
      throw C2paSigningException('Signer supplied conflicting $key header');
    }
    values[1] = <Object?, Object?>{...headers, key: value};
    final encoded = encodeCbor(values);
    return tagged ? Uint8List.fromList([0xd2, ...encoded]) : encoded;
  }

  static Uint8List? _timestampTokenFromResponse(Uint8List response) {
    try {
      final outer = _readDerValue(response, 0);
      if (outer.$1 != 0x30 || outer.$3 != response.length) return null;
      final status = _readDerValue(response, outer.$2);
      if (status.$1 != 0x30 || status.$3 >= outer.$3) return null;
      final token = _readDerValue(response, status.$3);
      if (token.$1 != 0x30 || token.$3 != outer.$3) return null;
      return Uint8List.sublistView(response, status.$3, token.$3);
    } on FormatException {
      return null;
    }
  }

  static (int, int, int) _readDerValue(Uint8List bytes, int offset) {
    if (offset + 2 > bytes.length) {
      throw const FormatException('Truncated DER value');
    }
    final tag = bytes[offset];
    var cursor = offset + 1;
    final first = bytes[cursor++];
    var length = first;
    if (first >= 0x80) {
      final width = first & 0x7f;
      if (width == 0 || width > 4 || cursor + width > bytes.length) {
        throw const FormatException('Malformed DER length');
      }
      length = 0;
      for (var index = 0; index < width; index++) {
        length = (length << 8) | bytes[cursor++];
      }
    }
    final end = cursor + length;
    if (end > bytes.length) throw const FormatException('Truncated DER value');
    return (tag, cursor, end);
  }

  JumbfSuperBoxNode _resourceStore() => JumbfSuperBoxNode(
    description: JumbfDescription.fromUuidHex(
      contentType: JumbfUuid.c2paDataBoxes,
      label: 'c2pa.databoxes',
    ),
    children: [
      for (final resource in definition.resources)
        JumbfSuperBoxNode(
          description: JumbfDescription.fromUuidHex(
            contentType: JumbfUuid.cbor,
            label: resource.label,
          ),
          children: [
            JumbfCborNode(
              encodeCbor({
                ...resource.extra,
                'format': resource.format,
                'name': ?resource.name,
                if (resource.dataTypes.isNotEmpty)
                  'data_types': resource.dataTypes,
                'data': Uint8List.fromList(resource.bytes),
              }, maxNestingDepth: context.settings.maxRecursionDepth),
            ),
          ],
        ),
    ],
  );

  JumbfSuperBoxNode _actionsAssertion() {
    final generatedAction = switch (definition.intent) {
      CreateIntent(:final sourceType) => C2paAction(
        action: C2paActionNames.created,
        sourceType: sourceType == DigitalSourceType.empty ? null : sourceType,
      ),
      EditIntent() || UpdateIntent() => C2paAction(
        action: C2paActionNames.opened,
        parameters: ActionParameters(
          ingredientIds: [
            definition.ingredients
                .singleWhere(
                  (item) =>
                      item.assertion.relationship == Relationship.parentOf,
                )
                .id,
          ],
        ),
      ),
    };
    final hasInceptionAction = definition.actions.any(
      (action) =>
          action.action == C2paActionNames.created ||
          action.action == C2paActionNames.opened,
    );
    final actions = ActionsAssertion(
      actions: [
        if (!hasInceptionAction) generatedAction,
        ...definition.actions,
      ],
    );
    return JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.cbor,
        label: ActionsAssertion.versionedLabel,
      ),
      children: [JumbfCborNode(encodeCbor(actions.toCborMap()))],
    );
  }

  static JumbfSuperBoxNode _ingredientAssertion(
    IngredientAssertion assertion,
    int index,
  ) => JumbfSuperBoxNode(
    description: JumbfDescription.fromUuidHex(
      contentType: JumbfUuid.cbor,
      label: _ingredientLabel(index),
    ),
    children: [JumbfCborNode(encodeCbor(assertion.toCborMap()))],
  );

  static String _ingredientLabel(int index) =>
      index == 0 ? 'c2pa.ingredient.v3' : 'c2pa.ingredient.v3__$index';

  JumbfSuperBoxNode _assertionNode(AssertionDefinition assertion) {
    final payload = _encodeAssertionPayload(assertion);
    if (assertion.encoding == AssertionEncoding.binary) {
      return JumbfSuperBoxNode(
        description: JumbfDescription.fromUuidHex(
          contentType: JumbfUuid.c2paEmbeddedFile,
          label: assertion.label,
        ),
        children: [
          JumbfEmbeddedFileDescriptionNode(mediaType: assertion.contentType!),
          JumbfEmbeddedFileNode(payload),
        ],
      );
    }
    return JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: assertion.encoding == AssertionEncoding.json
            ? JumbfUuid.json
            : JumbfUuid.cbor,
        label: assertion.label,
      ),
      children: [
        if (assertion.encoding == AssertionEncoding.json)
          JumbfJsonNode(payload)
        else
          JumbfCborNode(payload),
      ],
    );
  }

  Uint8List _encodeAssertionPayload(AssertionDefinition assertion) {
    try {
      return switch (assertion.encoding) {
        AssertionEncoding.json => Uint8List.fromList(
          utf8.encode(jsonEncode(_canonicalJson(assertion.data))),
        ),
        AssertionEncoding.cbor => encodeCbor(
          assertion.data,
          maxNestingDepth: context.settings.maxRecursionDepth,
        ),
        AssertionEncoding.binary => switch (assertion.data) {
          final Uint8List bytes => Uint8List.fromList(bytes),
          final List<int> bytes => Uint8List.fromList(bytes),
          _ => throw const FormatException(
            'Binary assertion data must be bytes',
          ),
        },
      };
    } on Exception catch (error, stackTrace) {
      throw C2paValidationException(
        'Assertion ${assertion.label} cannot be encoded: $error',
        cause: error,
        stackTrace: stackTrace,
      );
    }
  }

  static Object? _canonicalJson(Object? value) {
    if (value == null || value is bool || value is String) return value;
    if (value is num) {
      if (value is double && !value.isFinite) {
        throw const FormatException('JSON numbers must be finite');
      }
      return value;
    }
    if (value is List) {
      return List<Object?>.unmodifiable(value.map(_canonicalJson));
    }
    if (value is Map) {
      if (value.keys.any((key) => key is! String)) {
        throw const FormatException('JSON object keys must be strings');
      }
      final keys = value.keys.cast<String>().toList()..sort();
      return UnmodifiableMapView<String, Object?>({
        for (final key in keys) key: _canonicalJson(value[key]),
      });
    }
    throw FormatException('Unsupported JSON value: ${value.runtimeType}');
  }

  static void _validateLabel(String value, String name) {
    if (value.trim().isEmpty ||
        value.contains('/') ||
        value.contains('\\') ||
        value.contains('\u0000')) {
      throw C2paValidationException('Invalid $name: $value');
    }
  }

  static SigningAlgorithm _parseSigningAlgorithm(String value) {
    final normalized = _normalizeAlgorithmName(value);
    for (final algorithm in SigningAlgorithm.values) {
      if (algorithm.name == normalized) return algorithm;
    }
    throw C2paSigningException('Unsupported signing algorithm: $value');
  }

  static String _normalizeAlgorithmName(String value) =>
      value.trim().toLowerCase().replaceAll(RegExp(r'[-_]'), '');

  static HashAlgorithm _parseHashAlgorithm(String value) {
    final normalized = _normalizeAlgorithmName(value);
    return switch (normalized) {
      'sha256' => HashAlgorithm.sha256,
      'sha384' => HashAlgorithm.sha384,
      'sha512' => HashAlgorithm.sha512,
      _ => throw C2paValidationException(
        'Unsupported assertion hash algorithm: $value',
      ),
    };
  }

  static Uint8List _boxPayload(Uint8List bytes) {
    final size = ByteData.sublistView(bytes).getUint32(0, Endian.big);
    return Uint8List.sublistView(bytes, size == 1 ? 16 : 8);
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

Object? _freezeAssertionData(Object? value) {
  if (value is Uint8List) {
    return Uint8List.fromList(value).asUnmodifiableView();
  }
  if (value is List) {
    return List<Object?>.unmodifiable(value.map(_freezeAssertionData));
  }
  if (value is Map) {
    return UnmodifiableMapView<Object?, Object?>(
      value.map(
        (key, item) =>
            MapEntry(_freezeAssertionData(key), _freezeAssertionData(item)),
      ),
    );
  }
  return value;
}

final class _CallbackSigningBackend implements CoseSigningBackend {
  const _CallbackSigningBackend(this.signer);

  final C2paSigner signer;

  @override
  Future<List<int>> sign(SigningAlgorithm algorithm, List<int> data) =>
      signer.sign(Uint8List.fromList(data));
}

final class _ReservedSignatureSigner implements C2paSigner {
  const _ReservedSignatureSigner(this.algorithm, this.size);

  @override
  final String algorithm;
  final int size;

  @override
  Future<Uint8List> sign(Uint8List data) async =>
      Uint8List.fromList(List<int>.filled(size, 0));
}

final class _ExactReservedSizeSigner implements C2paSigner {
  const _ExactReservedSizeSigner(this.delegate, this.reservedSize);

  final C2paSigner delegate;
  final int reservedSize;

  @override
  String get algorithm => delegate.algorithm;

  @override
  Future<Uint8List> sign(Uint8List data) async {
    final signature = await delegate.sign(data);
    if (signature.length > reservedSize) {
      throw C2paSigningException(
        'Signature size ${signature.length} exceeds the explicit '
        '$reservedSize-byte reservation',
      );
    }
    if (signature.length != reservedSize) {
      throw C2paSigningException(
        'Signature size ${signature.length} does not fill the explicit '
        '$reservedSize-byte reservation',
      );
    }
    return signature;
  }
}

final class _MerkleTree {
  const _MerkleTree(this.layers);

  final List<List<Uint8List>> layers;
}

HashAlgorithm _ingredientHashAlgorithm(String value) {
  final normalized = value.toLowerCase().replaceAll(RegExp(r'[-_]'), '');
  return switch (normalized) {
    'sha256' => HashAlgorithm.sha256,
    'sha384' => HashAlgorithm.sha384,
    'sha512' => HashAlgorithm.sha512,
    _ => throw C2paValidationException(
      'Unsupported ingredient hash algorithm: $value',
    ),
  };
}

Uint8List _jumbfPayload(Uint8List bytes) {
  if (bytes.length < 8) {
    throw const C2paValidationException('Malformed ingredient JUMBF box');
  }
  final size = ByteData.sublistView(bytes).getUint32(0, Endian.big);
  final headerSize = size == 1 ? 16 : 8;
  if (bytes.length < headerSize) {
    throw const C2paValidationException('Malformed ingredient JUMBF box');
  }
  return Uint8List.sublistView(bytes, headerSize);
}
