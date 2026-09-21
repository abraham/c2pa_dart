final class JsonSchemaValidation {
  const JsonSchemaValidation(this.errors);

  final List<String> errors;

  bool get isValid => errors.isEmpty;
}

final class JsonSchemaValidator {
  const JsonSchemaValidator(this.schema);

  final Map<String, Object?> schema;

  JsonSchemaValidation validate(Object? value) {
    final errors = <String>[];
    _validate(value, schema, r'$', errors);
    return JsonSchemaValidation(List.unmodifiable(errors));
  }

  void _validate(
    Object? value,
    Map<String, Object?> node,
    String path,
    List<String> errors,
  ) {
    final reference = node[r'$ref'];
    if (reference is String) {
      _validate(value, _resolve(reference), path, errors);
      return;
    }

    final oneOf = node['oneOf'];
    if (oneOf is List<Object?>) {
      final matches = oneOf.where((candidate) {
        final candidateErrors = <String>[];
        _validate(
          value,
          (candidate as Map<Object?, Object?>).cast<String, Object?>(),
          path,
          candidateErrors,
        );
        return candidateErrors.isEmpty;
      }).length;
      if (matches != 1) {
        errors.add(
          '$path must match exactly one oneOf branch; matched $matches',
        );
      }
      return;
    }

    final type = node['type'];
    if (type != null && !_matchesType(value, type)) {
      errors.add('$path must be ${_typeDescription(type)}');
      return;
    }

    final enumValues = node['enum'];
    if (enumValues is List<Object?> && !enumValues.contains(value)) {
      errors.add('$path must be one of $enumValues');
    }

    if (value is Map<Object?, Object?>) {
      _validateObject(value, node, path, errors);
    } else if (value is List<Object?>) {
      _validateArray(value, node, path, errors);
    } else if (value is String) {
      _validateString(value, node, path, errors);
    } else if (value is num) {
      _validateNumber(value, node, path, errors);
    }
  }

  void _validateObject(
    Map<Object?, Object?> value,
    Map<String, Object?> node,
    String path,
    List<String> errors,
  ) {
    final object = value.map((key, child) => MapEntry(key.toString(), child));
    final required = node['required'];
    if (required is List<Object?>) {
      for (final key in required.cast<String>()) {
        if (!object.containsKey(key)) errors.add('$path is missing "$key"');
      }
    }

    final properties =
        (node['properties'] as Map<Object?, Object?>?)
            ?.cast<String, Object?>() ??
        const <String, Object?>{};
    final patterns =
        (node['patternProperties'] as Map<Object?, Object?>?)
            ?.cast<String, Object?>() ??
        const <String, Object?>{};
    for (final entry in object.entries) {
      final propertySchema = properties[entry.key];
      if (propertySchema is Map<Object?, Object?>) {
        _validate(
          entry.value,
          propertySchema.cast<String, Object?>(),
          '$path.${entry.key}',
          errors,
        );
        continue;
      }
      final matchingPatterns = patterns.entries.where(
        (pattern) => RegExp(pattern.key).hasMatch(entry.key),
      );
      if (matchingPatterns.isNotEmpty) {
        for (final pattern in matchingPatterns) {
          _validate(
            entry.value,
            (pattern.value as Map<Object?, Object?>).cast<String, Object?>(),
            '$path.${entry.key}',
            errors,
          );
        }
        continue;
      }
      final additional = node['additionalProperties'];
      if (additional == false) {
        errors.add('$path does not allow "${entry.key}"');
      } else if (additional is Map<Object?, Object?>) {
        _validate(
          entry.value,
          additional.cast<String, Object?>(),
          '$path.${entry.key}',
          errors,
        );
      }
    }

    final dependent = node['dependentRequired'];
    if (dependent is Map<Object?, Object?>) {
      for (final entry in dependent.entries) {
        final key = entry.key.toString();
        if (!object.containsKey(key)) continue;
        for (final dependency
            in (entry.value as List<Object?>).cast<String>()) {
          if (!object.containsKey(dependency)) {
            errors.add('$path.$key requires "$dependency"');
          }
        }
      }
    }
  }

  void _validateArray(
    List<Object?> value,
    Map<String, Object?> node,
    String path,
    List<String> errors,
  ) {
    final minItems = node['minItems'];
    if (minItems is int && value.length < minItems) {
      errors.add('$path must contain at least $minItems items');
    }
    final items = node['items'];
    if (items is Map<Object?, Object?>) {
      for (var index = 0; index < value.length; index++) {
        _validate(
          value[index],
          items.cast<String, Object?>(),
          '$path[$index]',
          errors,
        );
      }
    }
  }

  void _validateString(
    String value,
    Map<String, Object?> node,
    String path,
    List<String> errors,
  ) {
    final minLength = node['minLength'];
    if (minLength is int && value.length < minLength) {
      errors.add('$path must have at least $minLength characters');
    }
    final maxLength = node['maxLength'];
    if (maxLength is int && value.length > maxLength) {
      errors.add('$path must have at most $maxLength characters');
    }
    final pattern = node['pattern'];
    if (pattern is String && !RegExp(pattern).hasMatch(value)) {
      errors.add('$path does not match $pattern');
    }
    switch (node['format']) {
      case 'uri':
        final uri = Uri.tryParse(value);
        if (uri == null || !uri.hasScheme) errors.add('$path is not a URI');
      case 'date-time':
        if (DateTime.tryParse(value) == null) {
          errors.add('$path is not an RFC 3339 date-time');
        }
      case 'date':
        if (!RegExp(r'^\d{4}-\d{2}-\d{2}$').hasMatch(value) ||
            DateTime.tryParse(value) == null) {
          errors.add('$path is not an RFC 3339 date');
        }
    }
  }

  void _validateNumber(
    num value,
    Map<String, Object?> node,
    String path,
    List<String> errors,
  ) {
    final minimum = node['minimum'];
    if (minimum is num && value < minimum) {
      errors.add('$path must be >= $minimum');
    }
    final maximum = node['maximum'];
    if (maximum is num && value > maximum) {
      errors.add('$path must be <= $maximum');
    }
  }

  Map<String, Object?> _resolve(String reference) {
    if (!reference.startsWith('#/')) {
      throw FormatException('Only local schema references are supported.');
    }
    Object? current = schema;
    for (final encoded in reference.substring(2).split('/')) {
      final key = encoded.replaceAll('~1', '/').replaceAll('~0', '~');
      current = (current as Map<Object?, Object?>)[key];
    }
    if (current is! Map<Object?, Object?>) {
      throw FormatException('Schema reference "$reference" is not an object.');
    }
    return current.cast<String, Object?>();
  }
}

bool _matchesType(Object? value, Object type) {
  final types = type is List<Object?> ? type.cast<String>() : [type as String];
  return types.any(
    (candidate) => switch (candidate) {
      'null' => value == null,
      'object' => value is Map,
      'array' => value is List,
      'string' => value is String,
      'integer' => value is int,
      'number' => value is num,
      'boolean' => value is bool,
      _ => throw FormatException('Unsupported JSON Schema type "$candidate".'),
    },
  );
}

String _typeDescription(Object type) =>
    type is List<Object?> ? type.join(' or ') : type.toString();
