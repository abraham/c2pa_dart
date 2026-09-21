import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:test/test.dart';

void main() {
  test('seeded generator and serialized replay are deterministic', () {
    final generator = MutationPlanGenerator(
      MutationGeneratorConfig(
        protectedRanges: [ByteRange(4, 8)],
        structuralRanges: [ByteRange(0, 4), ByteRange(8, 12)],
        lengthFields: [IntegerField(offset: 0, width: 4)],
        offsetFields: [IntegerField(offset: 8, width: 4)],
        maxOperationsPerPlan: 4,
      ),
    );
    final input = List<int>.generate(16, (index) => index);

    final first = generator.generate(input, seed: 0x12345678);
    final second = generator.generate(input, seed: 0x12345678);
    final replayed = MutationPlan.fromJson(first.toJson());

    expect(first.toJson(), second.toJson());
    expect(first.apply(input), second.apply(input));
    expect(replayed.toJson(), first.toJson());
    expect(replayed.apply(input), first.apply(input));
  });

  test('generates every requested mutation classification', () {
    final input = List<int>.generate(16, (index) => index);
    for (final classification in MutationClassification.values) {
      final generator = MutationPlanGenerator(
        MutationGeneratorConfig(
          classifications: [classification],
          protectedRanges: [ByteRange(4, 8)],
          structuralRanges: [ByteRange(0, 4), ByteRange(8, 12)],
          lengthFields: [IntegerField(offset: 0, width: 4)],
          offsetFields: [IntegerField(offset: 8, width: 4)],
        ),
      );

      final plan = generator.generate(input, seed: 7);

      expect(plan.steps, hasLength(1), reason: classification.name);
      expect(plan.steps.single.classification, classification);
      expect(plan.apply(input), isNot(input));
    }
  });

  test('protected and unprotected flips stay in their classifications', () {
    final input = List<int>.filled(8, 0);
    final protectedPlan = MutationPlanGenerator(
      MutationGeneratorConfig(
        classifications: [MutationClassification.protectedBitFlip],
        protectedRanges: [ByteRange(2, 5)],
      ),
    ).generate(input, seed: 1);
    final unprotectedPlan = MutationPlanGenerator(
      MutationGeneratorConfig(
        classifications: [MutationClassification.unprotectedBitFlip],
        protectedRanges: [ByteRange(2, 5)],
      ),
    ).generate(input, seed: 1);

    final protectedOffset = (protectedPlan.steps.single as BitFlipStep).offset;
    final unprotectedOffset =
        (unprotectedPlan.steps.single as BitFlipStep).offset;
    expect(protectedOffset, inInclusiveRange(2, 4));
    expect(unprotectedOffset, isNot(inInclusiveRange(2, 4)));
  });

  test('plans shrink deterministically to valid smaller candidates', () {
    final input = List<int>.generate(12, (index) => index);
    final plan = MutationPlan(
      seed: 9,
      steps: [
        NestingBombStep(offset: 0, depth: 8),
        DeleteRangeStep(ByteRange(4, 8)),
      ],
    );

    final shrunk = plan.shrink(input).toList();

    expect(shrunk, isNotEmpty);
    expect(shrunk.any((candidate) => candidate.steps.length < 2), isTrue);
    expect(
      shrunk.any(
        (candidate) => candidate.steps.whereType<NestingBombStep>().any(
          (step) => step.depth < 8,
        ),
      ),
      isTrue,
    );
    for (final candidate in shrunk) {
      expect(() => candidate.apply(input), returnsNormally);
    }
  });

  test('enforces operation and generated-output bounds', () {
    expect(() => ByteRange(-1, 1), throwsRangeError);
    expect(() => ByteRange(2, 1), throwsRangeError);
    expect(
      () => IntegerCorruptionStep(
        classification: MutationClassification.lengthCorruption,
        offset: 3,
        width: 4,
      ).apply([1, 2, 3, 4]),
      throwsRangeError,
    );
    expect(
      () => ReorderRangesStep(first: ByteRange(2, 4), second: ByteRange(3, 5)),
      throwsArgumentError,
    );
    final generator = MutationPlanGenerator(
      MutationGeneratorConfig(maxGeneratedBytes: 4),
    );
    expect(
      () => generator.generate([1, 2, 3, 4, 5], seed: 1),
      throwsArgumentError,
    );
    expect(
      () => MutationPlanGenerator(
        MutationGeneratorConfig(
          classifications: [MutationClassification.protectedBitFlip],
        ),
      ).generate([1], seed: 1),
      throwsStateError,
    );
  });
}
