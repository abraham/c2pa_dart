import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:test/test.dart';

void main() {
  group('ResourceStore', () {
    test('normalizes JUMBF keys and protects against duplicates', () async {
      final store = ResourceStore();
      store.add(
        ' self#jumbf=c2pa/manifest/./thumbnail ',
        Uint8List.fromList([1, 2]),
      );

      expect(store.uris, {'self#jumbf=/c2pa/manifest/thumbnail'});
      expect(await store.lookup('#jumbf=/c2pa/manifest/thumbnail'), [1, 2]);
      expect(
        () => store.add('/c2pa/manifest/thumbnail', Uint8List.fromList([3])),
        throwsA(isA<C2paDuplicateResourceException>()),
      );
    });

    test('owns input bytes and returns immutable byte views', () async {
      final input = Uint8List.fromList([1, 2, 3]);
      final store = ResourceStore()..add('/c2pa/data', input);
      input[0] = 9;

      final result = await store.lookup('self#jumbf=/c2pa/data');

      expect(result, [1, 2, 3]);
      expect(() => result[0] = 4, throwsUnsupportedError);
    });

    test('enforces individual, aggregate, and count limits', () {
      final individual = ResourceStore(
        settings: const C2paSettings(
          maxResourceBytes: 2,
          maxTotalResourceBytes: 4,
        ),
      );
      expect(
        () => individual.add('/large', Uint8List(3)),
        throwsA(
          isA<C2paResourceLimitException>().having(
            (error) => error.kind,
            'kind',
            ResourceLimitKind.resourceBytes,
          ),
        ),
      );

      final aggregate = ResourceStore(
        settings: const C2paSettings(
          maxResourceBytes: 3,
          maxTotalResourceBytes: 4,
        ),
      )..add('/one', Uint8List(3));
      expect(
        () => aggregate.add('/two', Uint8List(2)),
        throwsA(
          isA<C2paResourceLimitException>().having(
            (error) => error.kind,
            'kind',
            ResourceLimitKind.totalBytes,
          ),
        ),
      );

      final count = ResourceStore(
        settings: const C2paSettings(
          maxResourceBytes: 1,
          maxTotalResourceBytes: 2,
          maxResourceCount: 1,
        ),
      )..add('/one', Uint8List(1));
      expect(
        () => count.add('/two', Uint8List(1)),
        throwsA(
          isA<C2paResourceLimitException>().having(
            (error) => error.kind,
            'kind',
            ResourceLimitKind.count,
          ),
        ),
      );
    });

    test('async lookup reports typed not-found errors', () async {
      final store = ResourceStore();

      await expectLater(
        store.lookup('/missing'),
        throwsA(
          isA<C2paResourceNotFoundException>().having(
            (error) => error.uri,
            'uri',
            'self#jumbf=/missing',
          ),
        ),
      );
    });

    test('rejects malformed resource identifiers', () {
      expect(
        () => ResourceStore.normalizeUri(''),
        throwsA(isA<C2paResourceUriException>()),
      );
      expect(
        () => ResourceStore.normalizeUri(r'c2pa\resource'),
        throwsA(isA<C2paResourceUriException>()),
      );
    });
  });
}
