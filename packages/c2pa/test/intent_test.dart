import 'package:c2pa/c2pa.dart';
import 'package:test/test.dart';

void main() {
  test('builder intents round-trip with typed create source', () {
    const intents = <BuilderIntent>[
      BuilderIntent.create(DigitalSourceType.digitalCapture),
      BuilderIntent.edit(),
      BuilderIntent.update(),
    ];

    for (final intent in intents) {
      expect(BuilderIntent.fromJson(intent.toJson()), intent);
    }

    final create = intents.first as CreateIntent;
    expect(create.sourceType, DigitalSourceType.digitalCapture);
  });

  test('claim versions accept number and enum name', () {
    expect(ClaimVersion.fromJson(1), ClaimVersion.v1);
    expect(ClaimVersion.fromJson('v2'), ClaimVersion.v2);
    expect(ClaimVersion.fromJson(3), isNull);
  });
}
