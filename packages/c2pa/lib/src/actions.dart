import 'claim.dart';
import 'intent.dart';
import 'json_utils.dart';

abstract final class C2paActionNames {
  static const colorAdjustments = 'c2pa.color_adjustments';
  static const converted = 'c2pa.converted';
  static const created = 'c2pa.created';
  static const cropped = 'c2pa.cropped';
  static const drawing = 'c2pa.drawing';
  static const edited = 'c2pa.edited';
  static const filtered = 'c2pa.filtered';
  static const opened = 'c2pa.opened';
  static const orientation = 'c2pa.orientation';
  static const placed = 'c2pa.placed';
  static const removed = 'c2pa.removed';
  static const redacted = 'c2pa.redacted';
  static const published = 'c2pa.published';
  static const repackaged = 'c2pa.repackaged';
  static const resized = 'c2pa.resized';
  static const transcoded = 'c2pa.transcoded';
  static const translated = 'c2pa.translated';
  static const unknown = 'c2pa.unknown';
}

sealed class ActionSoftwareAgent {
  const ActionSoftwareAgent();

  factory ActionSoftwareAgent.fromCbor(Object? value) {
    if (value is String) return ActionSoftwareAgentName(value);
    return ActionSoftwareAgentInfo(ClaimGeneratorInfo.fromCbor(value));
  }

  Object toCbor();
}

final class ActionSoftwareAgentName extends ActionSoftwareAgent {
  const ActionSoftwareAgentName(this.name);
  final String name;

  @override
  Object toCbor() => name;

  @override
  bool operator ==(Object other) =>
      other is ActionSoftwareAgentName && name == other.name;

  @override
  int get hashCode => name.hashCode;
}

final class ActionSoftwareAgentInfo extends ActionSoftwareAgent {
  const ActionSoftwareAgentInfo(this.info);
  final ClaimGeneratorInfo info;

  @override
  Object toCbor() => info.toCborMap();

  @override
  bool operator ==(Object other) =>
      other is ActionSoftwareAgentInfo && info == other.info;

  @override
  int get hashCode => info.hashCode;
}

final class ActionActor {
  ActionActor({
    this.identifier,
    this.type,
    Map<String, Object?> extra = const {},
  }) : extra = freezeJsonMap(extra);

  factory ActionActor.fromCbor(Object? value) {
    final map = _stringMap(value, 'actor');
    return ActionActor(
      identifier: map['identifier'] as String?,
      type: map['type'] as String?,
      extra: unknownFields(map, const {'identifier', 'type'}),
    );
  }

  final String? identifier;
  final String? type;
  final Map<String, Object?> extra;

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

final class ActionRegion {
  ActionRegion(Map<String, Object?> value) : value = freezeJsonMap(value);
  final Map<String, Object?> value;
  Map<String, Object?> toCborMap() => value;

  @override
  bool operator ==(Object other) =>
      other is ActionRegion && deepEquals(value, other.value);

  @override
  int get hashCode => deepHash(value);
}

final class ActionParameters {
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

  final ClaimHashedUri? ingredient;
  final List<ClaimHashedUri>? ingredients;
  final List<String>? ingredientIds;
  final String? description;
  final String? redacted;
  final String? sourceLanguage;
  final String? targetLanguage;
  final bool? multipleInstances;
  final Map<String, Object?> common;

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

final class C2paAction {
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

  final String action;
  final DateTime? when;
  final ActionSoftwareAgent? softwareAgent;
  final int? softwareAgentIndex;
  final String? changed;
  final List<ActionRegion>? regions;
  final ActionParameters? parameters;
  final List<ActionActor>? actors;
  final DigitalSourceType? sourceType;
  final List<C2paAction>? related;
  final String? reason;
  final String? description;
  final Map<String, Object?> unknownFields;

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

final class ActionsAssertion {
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

  static const label = 'c2pa.actions';
  static const versionedLabel = 'c2pa.actions.v2';

  final int version;
  final List<C2paAction> actions;
  final List<ClaimGeneratorInfo>? softwareAgents;
  final bool? allActionsIncluded;
  final List<Map<String, Object?>>? templates;
  final Map<String, Object?> metadata;
  final Map<String, Object?> unknownFields;

  String get assertionLabel => version == 1 ? label : versionedLabel;

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
