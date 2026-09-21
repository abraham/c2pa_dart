import 'package:c2pa/c2pa.dart';
import 'package:test/test.dart';

void main() {
  group('manifest models', () {
    test('round-trip known and unknown JSON fields', () {
      final source = <String, Object?>{
        'label': 'urn:c2pa:manifest:1',
        'title': 'asset.jpg',
        'format': 'image/jpeg',
        'instance_id': 'xmp:iid:123',
        'claim_generator': 'c2pa-dart/0.1',
        'claim_version': 2,
        'vendor_extension': {
          'enabled': true,
          'values': [1, 2],
        },
        'thumbnail': {
          'identifier': 'self#jumbf=/thumb',
          'format': 'image/jpeg',
          'resource_extension': 'preserved',
        },
        'assertions': [
          {
            'label': 'c2pa.actions',
            'data': {
              'actions': [
                {'action': 'c2pa.created'},
              ],
            },
            'assertion_extension': 42,
          },
        ],
        'ingredients': [
          {
            'title': 'source.png',
            'relationship': 'parentOf',
            'format': 'image/png',
            'ingredient_extension': {
              'nested': ['kept'],
            },
          },
        ],
      };

      final manifest = Manifest.fromJson(source);

      expect(manifest.claimVersion, ClaimVersion.v2);
      expect(manifest.ingredients.single.relationship, Relationship.parentOf);
      expect(manifest.toJson(), source);
      expect(Manifest.fromJson(manifest.toJson()), manifest);
      expect(Manifest.fromJson(manifest.toJson()).hashCode, manifest.hashCode);
    });

    test('deeply freezes unknown fields and assertion data', () {
      final nested = <String, Object?>{
        'list': <Object?>[
          <String, Object?>{'value': 1},
        ],
      };
      final assertion = ManifestAssertion(
        label: 'example.assertion',
        data: nested,
        extra: {
          'vendor': <Object?>[1],
        },
      );

      (nested['list']! as List<Object?>).add(2);
      expect((assertion.data! as Map<String, Object?>)['list'], hasLength(1));
      expect(
        () => (assertion.extra['vendor']! as List<Object?>).add(2),
        throwsUnsupportedError,
      );
    });

    test('collections and grouped assertion views are immutable', () {
      final assertions = [
        ManifestAssertion(label: 'test', data: const {'a': 1}),
        ManifestAssertion(label: 'test', data: const {'a': 2}),
      ];
      final manifest = Manifest(label: 'label', assertions: assertions);
      assertions.clear();

      expect(manifest.assertions, hasLength(2));
      expect(manifest.assertionsByLabel['test'], hasLength(2));
      expect(
        () => manifest.assertionsByLabel['test']!.clear(),
        throwsUnsupportedError,
      );
      expect(
        () => manifest.assertionsByLabel['new'] = const [],
        throwsUnsupportedError,
      );
    });

    test('resource references and hashed URIs preserve extensions', () {
      final resource = ResourceReference.fromJson(const {
        'identifier': 'self#jumbf=/resource',
        'format': 'application/json',
        'data_types': ['c2pa.types.schema'],
        'future': true,
      });
      final hashed = HashedUri.fromJson(const {
        'url': 'self#jumbf=/assertion',
        'alg': 'sha256',
        'hash': 'AQID',
        'future': 2,
      });

      expect(resource.toJson()['future'], isTrue);
      expect(hashed.toJson()['future'], 2);
      expect(ResourceReference.fromJson(resource.toJson()), resource);
      expect(HashedUri.fromJson(hashed.toJson()), hashed);
    });
  });
}
