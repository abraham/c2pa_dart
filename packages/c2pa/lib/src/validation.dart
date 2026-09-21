import 'dart:collection';

import 'json_utils.dart';
import 'validation_code.dart';

enum ValidationState { invalid, valid, trusted }

final class ValidationIssue {
  ValidationIssue({
    required this.code,
    this.url,
    this.explanation,
    this.ingredientUri,
  }) : severity = ValidationCode.classify(code);

  ValidationIssue.known({
    required ValidationCode code,
    this.url,
    this.explanation,
    this.ingredientUri,
  }) : code = code.value,
       severity = code.runtimeSeverity;

  factory ValidationIssue.fromJson(
    Map<String, Object?> json, {
    String? ingredientUri,
  }) => ValidationIssue(
    code: json['code'] as String,
    url: json['url'] as String?,
    explanation: json['explanation'] as String?,
    ingredientUri: ingredientUri,
  );

  final String code;
  final ValidationSeverity severity;
  final String? url;
  final String? explanation;

  /// Internal routing metadata. It is intentionally not serialized.
  final String? ingredientUri;

  bool get passed => severity != ValidationSeverity.failure;

  Map<String, Object?> toJson() => {
    'code': code,
    'url': ?url,
    'explanation': ?explanation,
  };

  @override
  bool operator ==(Object other) =>
      other is ValidationIssue &&
      code == other.code &&
      url == other.url &&
      explanation == other.explanation &&
      ingredientUri == other.ingredientUri;

  @override
  int get hashCode => Object.hash(code, url, explanation, ingredientUri);
}

final class StatusCodes {
  StatusCodes({Iterable<ValidationIssue> statuses = const []}) {
    final successful = <ValidationIssue>[];
    final informational = <ValidationIssue>[];
    final failed = <ValidationIssue>[];
    for (final status in statuses) {
      switch (status.severity) {
        case ValidationSeverity.success:
          successful.add(status);
        case ValidationSeverity.informational:
          informational.add(status);
        case ValidationSeverity.failure:
          failed.add(status);
      }
    }
    success = List<ValidationIssue>.unmodifiable(successful);
    this.informational = List<ValidationIssue>.unmodifiable(informational);
    failure = List<ValidationIssue>.unmodifiable(failed);
  }

  factory StatusCodes.fromJson(
    Map<String, Object?> json, {
    String? ingredientUri,
  }) {
    final statuses = <ValidationIssue>[];
    for (final key in const ['success', 'informational', 'failure']) {
      statuses.addAll(
        (json[key] as List<Object?>? ?? const [])
            .cast<Map<String, Object?>>()
            .map(
              (value) =>
                  ValidationIssue.fromJson(value, ingredientUri: ingredientUri),
            ),
      );
    }
    return StatusCodes(statuses: statuses);
  }

  late final List<ValidationIssue> success;
  late final List<ValidationIssue> informational;
  late final List<ValidationIssue> failure;

  List<ValidationIssue> get all => List<ValidationIssue>.unmodifiable([
    ...success,
    ...informational,
    ...failure,
  ]);

  Map<String, Object?> toJson() => {
    'success': success.map((status) => status.toJson()).toList(growable: false),
    'informational': informational
        .map((status) => status.toJson())
        .toList(growable: false),
    'failure': failure.map((status) => status.toJson()).toList(growable: false),
  };

  @override
  bool operator ==(Object other) =>
      other is StatusCodes &&
      deepEquals(success, other.success) &&
      deepEquals(informational, other.informational) &&
      deepEquals(failure, other.failure);

  @override
  int get hashCode => Object.hash(
    deepHash(success),
    deepHash(informational),
    deepHash(failure),
  );
}

final class IngredientDeltaValidationResult {
  IngredientDeltaValidationResult({
    required this.ingredientAssertionUri,
    required StatusCodes validationDeltas,
  }) : validationDeltas = StatusCodes(
         statuses: validationDeltas.all.map(
           (status) => ValidationIssue(
             code: status.code,
             url: status.url,
             explanation: status.explanation,
             ingredientUri: ingredientAssertionUri,
           ),
         ),
       );

  factory IngredientDeltaValidationResult.fromJson(Map<String, Object?> json) {
    final uri = json['ingredientAssertionURI'] as String;
    return IngredientDeltaValidationResult(
      ingredientAssertionUri: uri,
      validationDeltas: StatusCodes.fromJson(
        json['validationDeltas'] as Map<String, Object?>,
        ingredientUri: uri,
      ),
    );
  }

  final String ingredientAssertionUri;
  final StatusCodes validationDeltas;

  Map<String, Object?> toJson() => {
    'ingredientAssertionURI': ingredientAssertionUri,
    'validationDeltas': validationDeltas.toJson(),
  };

  @override
  bool operator ==(Object other) =>
      other is IngredientDeltaValidationResult &&
      ingredientAssertionUri == other.ingredientAssertionUri &&
      validationDeltas == other.validationDeltas;

  @override
  int get hashCode => Object.hash(ingredientAssertionUri, validationDeltas);
}

final class ValidationResults {
  ValidationResults({
    this.activeManifest,
    Iterable<IngredientDeltaValidationResult>? ingredientDeltas,
    this.validationTime,
  }) : ingredientDeltas = ingredientDeltas == null
           ? null
           : List<IngredientDeltaValidationResult>.unmodifiable(
               ingredientDeltas,
             );

  factory ValidationResults.fromIssues(
    Iterable<ValidationIssue> issues, {
    DateTime? validationTime,
  }) {
    final active = <ValidationIssue>[];
    final ingredients = <String, List<ValidationIssue>>{};
    for (final issue in issues) {
      final ingredientUri = issue.ingredientUri;
      if (ingredientUri == null) {
        active.add(issue);
      } else {
        ingredients.putIfAbsent(ingredientUri, () => []).add(issue);
      }
    }
    return ValidationResults(
      activeManifest: active.isEmpty ? null : StatusCodes(statuses: active),
      ingredientDeltas: ingredients.entries.map(
        (entry) => IngredientDeltaValidationResult(
          ingredientAssertionUri: entry.key,
          validationDeltas: StatusCodes(statuses: entry.value),
        ),
      ),
      validationTime: validationTime,
    );
  }

  factory ValidationResults.fromJson(Map<String, Object?> json) =>
      ValidationResults(
        activeManifest: switch (json['activeManifest']) {
          final Map<String, Object?> value => StatusCodes.fromJson(value),
          _ => null,
        },
        ingredientDeltas: switch (json['ingredientDeltas']) {
          final List<Object?> values => values.cast<Map<String, Object?>>().map(
            IngredientDeltaValidationResult.fromJson,
          ),
          _ => null,
        },
      );

  final StatusCodes? activeManifest;
  final List<IngredientDeltaValidationResult>? ingredientDeltas;

  /// Internal document-level metadata. It is intentionally not serialized.
  final DateTime? validationTime;

  ValidationState get state {
    final active = activeManifest;
    if (active == null) return ValidationState.invalid;

    final isValid =
        active.success.any(
          (status) =>
              status.code == ValidationCode.claimSignatureValidated.value,
        ) &&
        active.success.any(
          (status) =>
              status.code == ValidationCode.claimSignatureInsideValidity.value,
        ) &&
        active.failure.every(
          (status) =>
              status.code == ValidationCode.signingCredentialUntrusted.value,
        ) &&
        (ingredientDeltas ?? const <IngredientDeltaValidationResult>[]).every(
          (delta) => delta.validationDeltas.failure.every(
            (status) =>
                status.code == ValidationCode.signingCredentialUntrusted.value,
          ),
        );

    if (!isValid) return ValidationState.invalid;

    final isTrusted =
        active.success.any(
          (status) =>
              status.code == ValidationCode.signingCredentialTrusted.value,
        ) &&
        active.failure.isEmpty &&
        (ingredientDeltas ?? const <IngredientDeltaValidationResult>[]).every(
          (delta) => delta.validationDeltas.failure.isEmpty,
        );
    return isTrusted ? ValidationState.trusted : ValidationState.valid;
  }

  List<ValidationIssue> get issues => List<ValidationIssue>.unmodifiable([
    if (activeManifest case final active?) ...active.all,
    for (final delta
        in ingredientDeltas ?? const <IngredientDeltaValidationResult>[])
      ...delta.validationDeltas.all,
  ]);

  List<ValidationIssue> get errors => UnmodifiableListView(
    issues.where((issue) => issue.severity == ValidationSeverity.failure),
  );

  List<ValidationIssue> get warnings => UnmodifiableListView(
    issues.where((issue) => issue.severity == ValidationSeverity.informational),
  );

  Map<String, Object?> toJson() => {
    'activeManifest': ?activeManifest?.toJson(),
    'ingredientDeltas': ?ingredientDeltas
        ?.map((delta) => delta.toJson())
        .toList(growable: false),
  };

  @override
  bool operator ==(Object other) =>
      other is ValidationResults &&
      activeManifest == other.activeManifest &&
      deepEquals(ingredientDeltas, other.ingredientDeltas) &&
      validationTime == other.validationTime;

  @override
  int get hashCode =>
      Object.hash(activeManifest, deepHash(ingredientDeltas), validationTime);
}
