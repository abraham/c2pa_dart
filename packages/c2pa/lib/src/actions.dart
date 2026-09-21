import 'claim.dart';
import 'intent.dart';
import 'json_utils.dart';

/// Canonical action names for the `c2pa.actions` assertion.
abstract final class C2paActionNames {
  /// Color or tone adjustments applied to asset content.
  static const colorAdjustments = 'c2pa.color_adjustments';

  /// Conversion from one format or representation to another.
  static const converted = 'c2pa.converted';

  /// Initial creation of the asset or manifest provenance chain.
  static const created = 'c2pa.created';

  /// Cropping that removed pixels or samples from an asset.
  static const cropped = 'c2pa.cropped';

  /// Drawing or brush-like edits added to visual content.
  static const drawing = 'c2pa.drawing';

  /// Generic editing when no more specific action applies.
  static const edited = 'c2pa.edited';

  /// Filter effects applied to asset content.
  static const filtered = 'c2pa.filtered';

  /// Opening an existing parent asset for edit or update provenance.
  static const opened = 'c2pa.opened';

  /// Orientation or rotation changes applied to the asset.
  static const orientation = 'c2pa.orientation';

  /// Placement of an ingredient into the asset composition.
  static const placed = 'c2pa.placed';

  /// Removal of content from the asset composition.
  static const removed = 'c2pa.removed';

  /// Redaction of a provenance assertion from an ingredient manifest.
  static const redacted = 'c2pa.redacted';

  /// Publication or export of the asset for distribution.
  static const published = 'c2pa.published';

  /// Packaging changes that preserve the underlying content.
  static const repackaged = 'c2pa.repackaged';

  /// Image, video, or canvas dimensions were changed.
  static const resized = 'c2pa.resized';

  /// Media encoding was changed without asserting semantic edits.
  static const transcoded = 'c2pa.transcoded';

  /// Human language content was translated.
  static const translated = 'c2pa.translated';

  /// Action with unknown or unspecified provenance semantics.
  static const unknown = 'c2pa.unknown';
}

/// Software identity attached to a provenance action.
sealed class ActionSoftwareAgent {
  /// Creates a software-agent value for an action.
  const ActionSoftwareAgent();

  /// Decodes a software agent from a CBOR string or info map.
  ///
  /// Throws [FormatException] if a non-string value is not generator info.
  factory ActionSoftwareAgent.fromCbor(Object? value) {
    if (value is String) return ActionSoftwareAgentName(value);
    return ActionSoftwareAgentInfo(ClaimGeneratorInfo.fromCbor(value));
  }

  /// Encodes this agent for a `softwareAgent` CBOR field.
  Object toCbor();
}

/// A software agent represented only by its display name.
final class ActionSoftwareAgentName extends ActionSoftwareAgent {
  /// Creates a string-valued software-agent reference.
  const ActionSoftwareAgentName(this.name);

  /// The software-agent name stored directly in CBOR.
  final String name;

  @override
  Object toCbor() => name;

  @override
  bool operator ==(Object other) =>
      other is ActionSoftwareAgentName && name == other.name;

  @override
  int get hashCode => name.hashCode;
}

/// A software agent represented by structured generator info.
final class ActionSoftwareAgentInfo extends ActionSoftwareAgent {
  /// Creates a structured software-agent reference.
  const ActionSoftwareAgentInfo(this.info);

  /// Structured claim-generator metadata for the software agent.
  final ClaimGeneratorInfo info;

  @override
  Object toCbor() => info.toCborMap();

  @override
  bool operator ==(Object other) =>
      other is ActionSoftwareAgentInfo && info == other.info;

  @override
  int get hashCode => info.hashCode;
}

/// A human or system actor associated with a C2PA action.
final class ActionActor {
  /// Creates an actor and freezes unrecognized extension fields.
  ActionActor({
    this.identifier,
    this.type,
    Map<String, Object?> extra = const {},
  }) : extra = freezeJsonMap(extra);

  /// Decodes an action actor from a string-keyed CBOR map.
  ///
  /// Throws [FormatException] if [value] is not a string-keyed map.
  factory ActionActor.fromCbor(Object? value) {
    final map = _stringMap(value, 'actor');
    return ActionActor(
      identifier: map['identifier'] as String?,
      type: map['type'] as String?,
      extra: unknownFields(map, const {'identifier', 'type'}),
    );
  }

  /// Actor identifier, or `null` when the actor is anonymous.
  final String? identifier;

  /// Actor type such as a role URI, or `null` when unspecified.
  final String? type;

  /// Unrecognized actor fields preserved for round-tripping.
  final Map<String, Object?> extra;

  /// Encodes this action as a CBOR map.
  Map<String, Object?> toCborMap() => {
    ...extra,
    if (identifier != null) 'identifier': identifier,
    if (type != null) 'type': type,
  };

  @override
  bool operator ==(Object other) =>
      other is ActionActor &&
      identifier == other.identifier &&
      type == other.type &&
      deepEquals(extra, other.extra);

  @override
  int get hashCode => Object.hash(identifier, type, deepHash(extra));
}

/// A region or segment affected by an action.
final class ActionRegion {
  /// Creates a region from a string-keyed map and freezes it.
  ActionRegion(Map<String, Object?> value) : value = freezeJsonMap(value);

  /// Region fields as defined by the producer or C2PA vocabulary.
  final Map<String, Object?> value;

  /// Encodes this region as a CBOR map.
  Map<String, Object?> toCborMap() => value;

  @override
  bool operator ==(Object other) =>
      other is ActionRegion && deepEquals(value, other.value);

  @override
  int get hashCode => deepHash(value);
}

/// Action-specific parameters for the `c2pa.actions` vocabulary.
final class ActionParameters {
  /// Creates parameters and freezes collection fields.
  ///
  /// A `null` property is omitted from the encoded assertion.
  ActionParameters({
    this.ingredient,
    Iterable<ClaimHashedUri>? ingredients,
    Iterable<String>? ingredientIds,
    this.description,
    this.redacted,
    this.sourceLanguage,
    this.targetLanguage,
    this.multipleInstances,
    Map<String, Object?> common = const {},
  }) : ingredients = ingredients == null
           ? null
           : List<ClaimHashedUri>.unmodifiable(ingredients),
       ingredientIds = ingredientIds == null
           ? null
           : List<String>.unmodifiable(ingredientIds),
       common = freezeJsonMap(common);

  /// Decodes action parameters from CBOR, including legacy IDs.
  ///
  /// Throws [FormatException] if [value] is not a string-keyed map.
  factory ActionParameters.fromCbor(
    Object? value, {
    Iterable<String>? legacyIngredientIds,
  }) {
    final map = value == null
        ? <String, Object?>{}
        : _stringMap(value, 'action parameters');
    final canonicalIds = _stringValues(map['ingredientIds']);
    final oldIds = canonicalIds.isNotEmpty
        ? canonicalIds
        : [
            ..._stringValues(map['org.cai.ingredientIds']),
            ..._stringValues(map['instanceId']),
            ...?legacyIngredientIds,
          ];
    return ActionParameters(
      ingredient: map['ingredient'] == null
          ? null
          : ClaimHashedUri.fromCbor(map['ingredient']),
      ingredients: _optionalList(map['ingredients'])
          ?.map(ClaimHashedUri.fromCbor),
      ingredientIds: oldIds.isEmpty ? null : oldIds,
      description: map['description'] as String?,
      redacted: map['redacted'] as String?,
      sourceLanguage: map['sourceLanguage'] as String?,
      targetLanguage: map['targetLanguage'] as String?,
      multipleInstances: map['multipleInstances'] as bool?,
      common: unknownFields(map, const {
        'ingredient',
        'ingredients',
        'ingredientIds',
        'org.cai.ingredientIds',
        'instanceId',
        'description',
        'redacted',
        'sourceLanguage',
        'targetLanguage',
        'multipleInstances',
      }),
    );
  }

  /// Single ingredient URI affected by the action, or `null`.
  final ClaimHashedUri? ingredient;

  /// Ingredient URIs affected by the action, or `null` when absent.
  final List<ClaimHashedUri>? ingredients;

  /// Builder ingredient IDs affected by the action, or `null`.
  final List<String>? ingredientIds;

  /// Human-readable action description, or `null` when omitted.
  final String? description;

  /// Redacted assertion URI for `c2pa.redacted`, or `null`.
  final String? redacted;

  /// BCP 47 source language for translation, or `null`.
  final String? sourceLanguage;

  /// BCP 47 target language for translation, or `null`.
  final String? targetLanguage;

  /// Whether the action applies to multiple instances, or `null`.
  final bool? multipleInstances;

  /// Common or extension parameters preserved for round-tripping.
  final Map<String, Object?> common;

  /// Encodes these parameters as a CBOR map.
  Map<String, Object?> toCborMap() => {
    ...common,
    if (ingredient != null) 'ingredient': ingredient!.toCborMap(),
    if (ingredients != null)
      'ingredients': ingredients!
          .map((item) => item.toCborMap())
          .toList(growable: false),
    if (ingredientIds != null) 'ingredientIds': ingredientIds,
    if (description != null) 'description': description,
    if (redacted != null) 'redacted': redacted,
    if (sourceLanguage != null) 'sourceLanguage': sourceLanguage,
    if (targetLanguage != null) 'targetLanguage': targetLanguage,
    if (multipleInstances != null) 'multipleInstances': multipleInstances,
  };

  @override
  bool operator ==(Object other) =>
      other is ActionParameters &&
      ingredient == other.ingredient &&
      deepEquals(ingredients, other.ingredients) &&
      deepEquals(ingredientIds, other.ingredientIds) &&
      description == other.description &&
      redacted == other.redacted &&
      sourceLanguage == other.sourceLanguage &&
      targetLanguage == other.targetLanguage &&
      multipleInstances == other.multipleInstances &&
      deepEquals(common, other.common);

  @override
  int get hashCode => Object.hash(
    ingredient,
    deepHash(ingredients),
    deepHash(ingredientIds),
    description,
    redacted,
    sourceLanguage,
    targetLanguage,
    multipleInstances,
    deepHash(common),
  );
}

/// One provenance action recorded in a `c2pa.actions` assertion.
final class C2paAction {
  /// Creates an action and freezes repeatable fields.
  ///
  /// The [action] name must be non-empty when encoded or decoded.
  C2paAction({
    required this.action,
    this.when,
    this.softwareAgent,
    this.softwareAgentIndex,
    this.changed,
    Iterable<ActionRegion>? regions,
    this.parameters,
    Iterable<ActionActor>? actors,
    this.sourceType,
    Iterable<C2paAction>? related,
    this.reason,
    this.description,
    Map<String, Object?> unknownFields = const {},
  }) : regions = regions == null
           ? null
           : List<ActionRegion>.unmodifiable(regions),
       actors = actors == null ? null : List<ActionActor>.unmodifiable(actors),
       related = related == null
           ? null
           : List<C2paAction>.unmodifiable(related),
       unknownFields = freezeJsonMap(unknownFields);

  /// Decodes a C2PA action from a CBOR map.
  ///
  /// Throws [FormatException] if required fields are missing or malformed.
  factory C2paAction.fromCbor(Object? value) {
    final map = _stringMap(value, 'action');
    final action = map['action'];
    if (action is! String || action.isEmpty) {
      throw const FormatException('An action requires a non-empty name');
    }
    final legacy = _stringValues(map['instanceId'] ?? map['instanceID']);
    final when = map['when'];
    final sourceType = _sourceType(map['digitalSourceType']);
    final extra = Map<String, Object?>.from(
      _unknown(map, const {
        'action',
        'when',
        'softwareAgent',
        'softwareAgentIndex',
        'changed',
        'changes',
        'instanceId',
        'instanceID',
        'parameters',
        'actors',
        'digitalSourceType',
        'related',
        'reason',
        'description',
      }),
    );
    if (map['digitalSourceType'] != null && sourceType == null) {
      extra['digitalSourceType'] = map['digitalSourceType'];
    }
    return C2paAction(
      action: action,
      when: when == null ? null : DateTime.parse(when as String).toUtc(),
      softwareAgent: map['softwareAgent'] == null
          ? null
          : ActionSoftwareAgent.fromCbor(map['softwareAgent']),
      softwareAgentIndex: map['softwareAgentIndex'] as int?,
      changed: map['changed'] as String?,
      regions: _optionalList(map['changes'])
          ?.map((item) => ActionRegion(_stringMap(item, 'region'))),
      parameters: map['parameters'] == null && legacy.isEmpty
          ? null
          : ActionParameters.fromCbor(
              map['parameters'],
              legacyIngredientIds: legacy,
            ),
      actors: _optionalList(map['actors'])?.map(ActionActor.fromCbor),
      sourceType: sourceType,
      related: _optionalList(map['related'])?.map(C2paAction.fromCbor),
      reason: map['reason'] as String?,
      description: map['description'] as String?,
      unknownFields: extra,
    );
  }

  /// Action name, usually one of [C2paActionNames].
  final String action;

  /// UTC action timestamp, or `null` when not recorded.
  final DateTime? when;

  /// Software agent that performed the action, or `null`.
  final ActionSoftwareAgent? softwareAgent;

  /// Index into assertion-level software agents, or `null`.
  final int? softwareAgentIndex;

  /// Legacy changed-region marker, or `null` when absent.
  final String? changed;

  /// Regions changed by the action, or `null` when unspecified.
  final List<ActionRegion>? regions;

  /// Action-specific parameters, or `null` when absent.
  final ActionParameters? parameters;

  /// Actors associated with the action, or `null` when omitted.
  final List<ActionActor>? actors;

  /// Digital source type URI value for creation actions, or `null`.
  final DigitalSourceType? sourceType;

  /// Nested related actions, or `null` when none are declared.
  final List<C2paAction>? related;

  /// Reason for the action, or `null` when not supplied.
  final String? reason;

  /// Human-readable action description, or `null` when omitted.
  final String? description;

  /// Unrecognized assertion fields preserved for round-tripping.
  final Map<String, Object?> unknownFields;

  /// Encodes this action as a CBOR map.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    'action': action,
    if (when != null) 'when': when!.toUtc().toIso8601String(),
    if (softwareAgent != null) 'softwareAgent': softwareAgent!.toCbor(),
    if (softwareAgentIndex != null) 'softwareAgentIndex': softwareAgentIndex,
    if (changed != null) 'changed': changed,
    if (regions != null)
      'changes': regions!
          .map((item) => item.toCborMap())
          .toList(growable: false),
    if (parameters != null) 'parameters': parameters!.toCborMap(),
    if (actors != null)
      'actors': actors!.map((item) => item.toCborMap()).toList(growable: false),
    if (sourceType != null) 'digitalSourceType': _sourceTypeUri(sourceType!),
    if (related != null)
      'related': related!
          .map((item) => item.toCborMap())
          .toList(growable: false),
    if (reason != null) 'reason': reason,
    if (description != null) 'description': description,
  };

  @override
  bool operator ==(Object other) =>
      other is C2paAction &&
      action == other.action &&
      when == other.when &&
      softwareAgent == other.softwareAgent &&
      softwareAgentIndex == other.softwareAgentIndex &&
      changed == other.changed &&
      deepEquals(regions, other.regions) &&
      parameters == other.parameters &&
      deepEquals(actors, other.actors) &&
      sourceType == other.sourceType &&
      deepEquals(related, other.related) &&
      reason == other.reason &&
      description == other.description &&
      deepEquals(unknownFields, other.unknownFields);

  @override
  int get hashCode => Object.hashAll([
    action,
    when,
    softwareAgent,
    softwareAgentIndex,
    changed,
    deepHash(regions),
    parameters,
    deepHash(actors),
    sourceType,
    deepHash(related),
    reason,
    description,
    deepHash(unknownFields),
  ]);
}

/// The C2PA `c2pa.actions` assertion.
final class ActionsAssertion {
  /// Creates an actions assertion with immutable action lists.
  ///
  /// At least one action is required when decoding from CBOR.
  ActionsAssertion({
    required Iterable<C2paAction> actions,
    this.version = 2,
    Iterable<ClaimGeneratorInfo>? softwareAgents,
    this.allActionsIncluded,
    Iterable<Map<String, Object?>>? templates,
    Map<String, Object?> metadata = const {},
    Map<String, Object?> unknownFields = const {},
  }) : actions = List<C2paAction>.unmodifiable(actions),
       softwareAgents = softwareAgents == null
           ? null
           : List<ClaimGeneratorInfo>.unmodifiable(softwareAgents),
       templates = templates == null
           ? null
           : List<Map<String, Object?>>.unmodifiable(
               templates.map(freezeJsonMap),
             ),
       metadata = freezeJsonMap(metadata),
       unknownFields = freezeJsonMap(unknownFields);

  /// Decodes an actions assertion of the given [version].
  ///
  /// Throws [FormatException] if the assertion lacks actions.
  factory ActionsAssertion.fromCbor(Object? value, {required int version}) {
    final map = _stringMap(value, 'actions assertion');
    final actions = _optionalList(map['actions']);
    if (actions == null || actions.isEmpty) {
      throw const FormatException('An actions assertion requires actions');
    }
    return ActionsAssertion(
      version: version,
      actions: actions.map(C2paAction.fromCbor),
      softwareAgents: _optionalList(map['softwareAgents'])
          ?.map(ClaimGeneratorInfo.fromCbor),
      allActionsIncluded: map['allActionsIncluded'] as bool?,
      templates: _optionalList(map['templates'])
          ?.map((item) => _stringMap(item, 'action template')),
      metadata: map['metadata'] == null
          ? const {}
          : _stringMap(map['metadata'], 'metadata'),
      unknownFields: _unknown(map, const {
        'actions',
        'softwareAgents',
        'allActionsIncluded',
        'templates',
        'metadata',
      }),
    );
  }

  /// Version 1 assertion label `c2pa.actions`.
  static const label = 'c2pa.actions';

  /// Version 2 assertion label `c2pa.actions.v2`.
  static const versionedLabel = 'c2pa.actions.v2';

  /// Actions assertion version used to choose the encoded label.
  final int version;

  /// Ordered provenance actions recorded by this assertion.
  final List<C2paAction> actions;

  /// Shared software-agent table, or `null` when not present.
  final List<ClaimGeneratorInfo>? softwareAgents;

  /// Whether the list is complete, or `null` when unspecified.
  final bool? allActionsIncluded;

  /// Action templates preserved from CBOR, or `null` when absent.
  final List<Map<String, Object?>>? templates;

  /// Assertion metadata map; empty when no metadata is present.
  final Map<String, Object?> metadata;

  /// Unrecognized assertion fields preserved for round-tripping.
  final Map<String, Object?> unknownFields;

  /// The label used when this assertion is embedded in JUMBF.
  String get assertionLabel => version == 1 ? label : versionedLabel;

  /// Encodes this actions assertion as a CBOR map.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    'actions': actions.map((item) => item.toCborMap()).toList(growable: false),
    if (softwareAgents != null)
      'softwareAgents': softwareAgents!
          .map((item) => item.toCborMap())
          .toList(growable: false),
    if (allActionsIncluded != null) 'allActionsIncluded': allActionsIncluded,
    if (templates != null) 'templates': templates,
    if (metadata.isNotEmpty) 'metadata': metadata,
  };

  @override
  bool operator ==(Object other) =>
      other is ActionsAssertion &&
      version == other.version &&
      deepEquals(actions, other.actions) &&
      deepEquals(softwareAgents, other.softwareAgents) &&
      allActionsIncluded == other.allActionsIncluded &&
      deepEquals(templates, other.templates) &&
      deepEquals(metadata, other.metadata) &&
      deepEquals(unknownFields, other.unknownFields);

  @override
  int get hashCode => Object.hash(
    version,
    deepHash(actions),
    deepHash(softwareAgents),
    allActionsIncluded,
    deepHash(templates),
    deepHash(metadata),
    deepHash(unknownFields),
  );
}

List<Object?>? _optionalList(Object? value) {
  if (value == null) return null;
  if (value is! List) throw const FormatException('Expected an array');
  return value.cast<Object?>();
}

List<String> _stringValues(Object? value) {
  if (value is String) return [value];
  if (value is List && value.every((item) => item is String)) {
    return value.cast<String>();
  }
  return const [];
}

DigitalSourceType? _sourceType(Object? value) {
  if (value == null) return null;
  if (value is! String) {
    throw const FormatException('digitalSourceType must be a string');
  }
  final name = value.split('/').last;
  for (final item in DigitalSourceType.values) {
    if (item.name == name) return item;
  }
  return null;
}

String _sourceTypeUri(DigitalSourceType type) => type == DigitalSourceType.empty
    ? 'http://c2pa.org/digitalsourcetype/empty'
    : 'http://cv.iptc.org/newscodes/digitalsourcetype/${type.name}';

Map<String, Object?> _stringMap(Object? value, String name) {
  if (value is! Map || value.keys.any((key) => key is! String)) {
    throw FormatException('$name must be a string-keyed map');
  }
  return value.cast<String, Object?>();
}

Map<String, Object?> _unknown(Map<String, Object?> map, Set<String> known) =>
    unknownFields(map, known);
