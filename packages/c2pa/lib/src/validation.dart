import 'dart:collection';

import 'json_utils.dart';
import 'validation_code.dart';

/// Overall validation state for an active manifest and its ingredients.
enum ValidationState {
  /// Required C2PA signature validation checks failed or are missing.
  invalid,

  /// Required C2PA signature checks passed, but trust was not established.
  valid,

  /// Required C2PA signature checks passed with trusted signing credentials.
  trusted,
}

/// One validation status code emitted while checking a C2PA manifest.
final class ValidationIssue {
  /// Creates an issue and derives [severity] from the code registry.
  ValidationIssue({
    required this.code,
    this.url,
    this.explanation,
    this.ingredientUri,
  }) : severity = ValidationCode.classify(code);

  /// Creates an issue from a known [ValidationCode].
  ValidationIssue.known({
    required ValidationCode code,
    this.url,
    this.explanation,
    this.ingredientUri,
  }) : code = code.value,
       severity = code.runtimeSeverity;

  /// Creates an issue whose severity was determined by the producing validator
  /// rather than by the static code registry.
  ///
  /// CAWG identity validation resolves some codes contextually (for example a
  /// credential is only untrusted when trust verification is enabled), so the
  /// severity it computed must be preserved instead of re-derived.
  ValidationIssue.withSeverity({
    required this.code,
    required this.severity,
    this.url,
    this.explanation,
    this.ingredientUri,
  });

  /// Creates an issue from a C2PA validation-status JSON object.
  factory ValidationIssue.fromJson(
    Map<String, Object?> json, {
    String? ingredientUri,
  }) => ValidationIssue(
    code: json['code'] as String,
    url: json['url'] as String?,
    explanation: json['explanation'] as String?,
    ingredientUri: ingredientUri,
  );

  /// C2PA validation code such as `claimSignature.validated`.
  final String code;

  /// Severity classified for [code], or supplied by the validator.
  final ValidationSeverity severity;

  /// Optional URL associated with the validation issue.
  final String? url;

  /// Optional human-readable detail supplied by the validator.
  final String? explanation;

  /// Internal routing metadata. It is intentionally not serialized.
  final String? ingredientUri;

  /// Whether this issue is not a validation failure.
  bool get passed => severity != ValidationSeverity.failure;

  /// Encodes this issue as C2PA validation-status JSON.
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

/// Validation issues grouped by success, informational, and failure severity.
final class StatusCodes {
  /// Creates grouped status lists from [statuses].
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

  /// Creates grouped status lists from C2PA validation-results JSON.
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

  /// Successful validation status entries.
  late final List<ValidationIssue> success;

  /// Informational validation status entries.
  late final List<ValidationIssue> informational;

  /// Failed validation status entries.
  late final List<ValidationIssue> failure;

  /// All status entries in success, informational, then failure order.
  List<ValidationIssue> get all => List<ValidationIssue>.unmodifiable([
    ...success,
    ...informational,
    ...failure,
  ]);

  /// Encodes the grouped status lists as validation-results JSON.
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

/// Validation delta associated with one ingredient assertion URI.
final class IngredientDeltaValidationResult {
  /// Creates an ingredient delta and stamps each issue with its URI.
  IngredientDeltaValidationResult({
    required this.ingredientAssertionUri,
    required StatusCodes validationDeltas,
  }) : validationDeltas = StatusCodes(
         statuses: validationDeltas.all.map(
           // Preserve the severity the producing validator computed. Rebuilding
           // through the default constructor would re-derive it from the code
           // registry, which silently discards contextual classifications such
           // as CAWG identity severities and c2pa-rs call-site kinds that
           // differ from `log_kind`.
           (status) => ValidationIssue.withSeverity(
             code: status.code,
             severity: status.severity,
             url: status.url,
             explanation: status.explanation,
             ingredientUri: ingredientAssertionUri,
           ),
         ),
       );

  /// Creates an ingredient delta from validation-results JSON.
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

  /// JUMBF URI of the ingredient assertion this delta describes.
  final String ingredientAssertionUri;

  /// Validation status changes attributed to [ingredientAssertionUri].
  final StatusCodes validationDeltas;

  /// Encodes this ingredient delta as validation-results JSON.
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

/// Validation results for the active manifest and ingredient deltas.
final class ValidationResults {
  /// Creates validation results from pre-grouped status lists.
  ValidationResults({
    this.activeManifest,
    Iterable<IngredientDeltaValidationResult>? ingredientDeltas,
    this.validationTime,
  }) : ingredientDeltas = ingredientDeltas == null
           ? null
           : List<IngredientDeltaValidationResult>.unmodifiable(
               ingredientDeltas,
             );

  /// Groups flat validation [issues] into active-manifest and ingredient results.
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

  /// Creates validation results from a C2PA validation-results object.
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

  /// Validation statuses for the active manifest, or `null` if absent.
  final StatusCodes? activeManifest;

  /// Per-ingredient validation deltas, or `null` when none were reported.
  final List<IngredientDeltaValidationResult>? ingredientDeltas;

  /// Internal document-level metadata. It is intentionally not serialized.
  final DateTime? validationTime;

  /// Overall state derived from signature and trust validation statuses.
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

  /// All active-manifest and ingredient validation issues.
  List<ValidationIssue> get issues => List<ValidationIssue>.unmodifiable([
    if (activeManifest case final active?) ...active.all,
    for (final delta
        in ingredientDeltas ?? const <IngredientDeltaValidationResult>[])
      ...delta.validationDeltas.all,
  ]);

  /// Validation issues whose severity is `ValidationSeverity.failure`.
  List<ValidationIssue> get errors => UnmodifiableListView(
    issues.where((issue) => issue.severity == ValidationSeverity.failure),
  );

  /// Validation issues whose severity is `ValidationSeverity.informational`.
  List<ValidationIssue> get warnings => UnmodifiableListView(
    issues.where((issue) => issue.severity == ValidationSeverity.informational),
  );

  /// Encodes these results as C2PA validation-results JSON.
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
