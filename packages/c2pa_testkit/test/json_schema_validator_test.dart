import 'package:test/test.dart';

import 'support/json_schema_validator.dart';

void main() {
  final schema = <String, Object?>{
    r'$defs': {
      'identifier': {
        'type': 'string',
        'pattern': r'^[a-z][a-z0-9-]+$',
        'minLength': 2,
        'maxLength': 16,
      },
    },
    'type': 'object',
    'required': ['id', 'kind', 'entries', 'endpoint'],
    'properties': {
      'id': {r'$ref': r'#/$defs/identifier'},
      'kind': {
        'oneOf': [
          {
            'type': 'string',
            'enum': ['basic'],
          },
          {'type': 'integer', 'minimum': 2, 'maximum': 4},
        ],
      },
      'entries': {
        'type': 'array',
        'minItems': 1,
        'items': {'type': 'number', 'minimum': 0, 'maximum': 10},
      },
      'endpoint': {'type': 'string', 'format': 'uri'},
      'created': {'type': 'string', 'format': 'date-time'},
      'date': {'type': 'string', 'format': 'date'},
      'token': {'type': 'string'},
      'secret': {'type': 'string'},
    },
    'patternProperties': {
      r'^x-': {'type': 'boolean'},
    },
    'additionalProperties': false,
    'dependentRequired': {
      'token': ['secret'],
    },
  };

  test('accepts the schema constructs used by the vendored crJSON schema', () {
    final errors = JsonSchemaValidator(schema).validate({
      'id': 'fixture-1',
      'kind': 3,
      'entries': [0, 2.5, 10],
      'endpoint': 'https://example.test/report',
      'created': '2025-01-02T03:04:05Z',
      'date': '2025-01-02',
      'token': 'public',
      'secret': 'paired',
      'x-enabled': true,
    });

    expect(errors.errors, isEmpty);
  });

  test('reports refs, oneOf, bounds, formats, dependencies, and extras', () {
    final errors = JsonSchemaValidator(schema).validate({
      'id': '1',
      'kind': 8,
      'entries': [-1],
      'endpoint': 'not a URI',
      'created': 'not a timestamp',
      'date': '2025-99-99',
      'token': 'unpaired',
      'x-enabled': 'yes',
      'unexpected': true,
    });

    expect(errors.isValid, isFalse);
    expect(
      errors.errors.any((error) => error.contains('does not match')),
      isTrue,
    );
    expect(errors.errors.any((error) => error.contains('oneOf')), isTrue);
    expect(errors.errors.any((error) => error.contains('>=')), isTrue);
    expect(errors.errors.any((error) => error.contains('RFC 3339')), isTrue);
    expect(errors.errors.any((error) => error.contains('requires')), isTrue);
    expect(
      errors.errors.any((error) => error.contains('does not allow')),
      isTrue,
    );
  });
}
