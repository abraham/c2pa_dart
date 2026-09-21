import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:test/test.dart';

void main() {
  test('owns input and output bytes and metadata map', () {
    final source = [1, 2, 3];
    final metadata = <String, Object?>{'origin': 'test'};
    final fixture = FixtureAsset(
      name: 'tiny',
      bytes: source,
      mediaType: 'application/octet-stream',
      metadata: metadata,
    );

    source[0] = 9;
    metadata['origin'] = 'changed';
    final exposed = fixture.bytes;
    exposed[1] = 9;

    expect(fixture.bytes, [1, 2, 3]);
    expect(fixture.metadata, {'origin': 'test'});
    expect(() => fixture.metadata['new'] = true, throwsUnsupportedError);
    expect(fixture.length, 3);
  });

  test('deterministic fixtures are stable and seed-sensitive', () {
    final first = FixtureAsset.deterministic(
      name: 'fixture',
      length: 16,
      seed: 42,
    );
    final second = FixtureAsset.deterministic(
      name: 'fixture',
      length: 16,
      seed: 42,
    );
    final other = FixtureAsset.deterministic(
      name: 'fixture',
      length: 16,
      seed: 43,
    );

    expect(first.bytes, second.bytes);
    expect(first.bytes, isNot(other.bytes));
    expect(
      () => FixtureAsset.deterministic(name: 'bad', length: -1),
      throwsRangeError,
    );
    expect(
      () => FixtureAsset.deterministic(name: 'bad', length: 1, seed: -1),
      throwsRangeError,
    );
  });

  test('copyWith preserves fields and owns replacement bytes', () {
    final fixture = FixtureAsset(
      name: 'original',
      bytes: [1],
      mediaType: 'image/jpeg',
      metadata: {'a': 1},
    );
    final replacement = [2, 3];
    final copy = fixture.copyWith(name: 'copy', bytes: replacement);
    replacement[0] = 9;

    expect(copy.name, 'copy');
    expect(copy.bytes, [2, 3]);
    expect(copy.mediaType, 'image/jpeg');
    expect(copy.metadata, {'a': 1});
  });
}
