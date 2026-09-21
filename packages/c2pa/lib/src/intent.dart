import 'json_utils.dart';

enum DigitalSourceType {
  empty,
  trainedAlgorithmicData,
  digitalCapture,
  computationalCapture,
  negativeFilm,
  positiveFilm,
  print,
  minorHumanEdits,
  humanEdits,
  compositeWithTrainedAlgorithmicMedia,
  algorithmicallyEnhanced,
  softwareImage,
  digitalArt,
  digitalCreation,
  dataDrivenMedia,
  trainedAlgorithmicMedia,
  algorithmicMedia,
  screenCapture,
  virtualRecording,
  composite,
  compositeCapture,
  compositeSynthetic,
  other,
}

sealed class BuilderIntent {
  const BuilderIntent();

  const factory BuilderIntent.create(DigitalSourceType sourceType) =
      CreateIntent;
  const factory BuilderIntent.edit() = EditIntent;
  const factory BuilderIntent.update() = UpdateIntent;

  factory BuilderIntent.fromJson(Map<String, Object?> json) {
    return switch (json['type']) {
      'create' => CreateIntent(
        enumByName(DigitalSourceType.values, json['sourceType']) ??
            DigitalSourceType.other,
      ),
      'edit' => const EditIntent(),
      'update' => const UpdateIntent(),
      _ => throw FormatException('Unknown builder intent: ${json['type']}'),
    };
  }

  String get type;
  Map<String, Object?> toJson();
}

final class CreateIntent extends BuilderIntent {
  const CreateIntent(this.sourceType);

  final DigitalSourceType sourceType;

  @override
  String get type => 'create';

  @override
  Map<String, Object?> toJson() => {
    'type': type,
    'sourceType': sourceType.name,
  };

  @override
  bool operator ==(Object other) =>
      other is CreateIntent && sourceType == other.sourceType;

  @override
  int get hashCode => Object.hash(type, sourceType);
}

final class EditIntent extends BuilderIntent {
  const EditIntent();

  @override
  String get type => 'edit';

  @override
  Map<String, Object?> toJson() => {'type': type};

  @override
  bool operator ==(Object other) => other is EditIntent;

  @override
  int get hashCode => type.hashCode;
}

final class UpdateIntent extends BuilderIntent {
  const UpdateIntent();

  @override
  String get type => 'update';

  @override
  Map<String, Object?> toJson() => {'type': type};

  @override
  bool operator ==(Object other) => other is UpdateIntent;

  @override
  int get hashCode => type.hashCode;
}

enum Relationship { parentOf, componentOf, inputTo }

enum ClaimVersion {
  v1(1),
  v2(2);

  const ClaimVersion(this.number);
  final int number;

  static ClaimVersion? fromJson(Object? value) {
    for (final version in values) {
      if (value == version.number || value == version.name) return version;
    }
    return null;
  }
}
