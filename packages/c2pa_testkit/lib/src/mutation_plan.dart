import 'dart:typed_data';

import 'byte_mutation.dart';

/// A planned corruption category for negative C2PA validation tests.
enum MutationClassification {
  /// Shortens the asset so parsing should fail on incomplete data.
  truncation,

  /// Corrupts a declared length so validation should reject bad bounds.
  lengthCorruption,

  /// Corrupts a declared offset so validation should reject bad references.
  offsetCorruption,

  /// Duplicates a structural range so validation should reject extra data.
  duplicateStructure,

  /// Swaps structural ranges so validation should reject invalid ordering.
  reorderStructure,

  /// Removes a structural range so validation should reject missing data.
  deleteStructure,

  /// Flips signed bytes so validation should report protected data tampering.
  protectedBitFlip,

  /// Flips unsigned bytes so validation should catch unprotected corruption.
  unprotectedBitFlip,

  /// Inserts deep nesting so validation should reject excessive structure.
  nestingBomb,

  /// Rewrites a CBOR size marker so validation should reject malformed CBOR.
  malformedCborSize,

  /// Rewrites a DER size marker so validation should reject malformed DER.
  malformedDerSize,
}

/// A half-open byte range used to target fixture mutations.
final class ByteRange {
  /// Creates a range from inclusive [start] to exclusive [end].
  ///
  /// Throws a [RangeError] when [start] is negative or [end] is before
  /// [start]. Coordinates are bytes and must fit in JavaScript-safe integers.
  ByteRange(this.start, this.end) {
    RangeError.checkNotNegative(start, 'start');
    RangeError.checkValueInInterval(end, start, 0x1fffffffffffff, 'end');
  }

  /// The inclusive starting byte offset.
  final int start;

  /// The exclusive ending byte offset.
  final int end;

  /// The number of bytes in this range.
  int get length => end - start;

  /// Tests whether [offset] lies within this half-open byte range.
  bool contains(int offset) => offset >= start && offset < end;

  /// Verifies that this range fits inside [bytes].
  ///
  /// Throws a [RangeError] when the exclusive end exceeds the input length.
  void validateFor(List<int> bytes, [String name = 'range']) {
    if (end > bytes.length) {
      throw RangeError.range(end, start, bytes.length, '$name.end');
    }
  }

  /// Converts this byte range to a JSON-safe map.
  Map<String, Object?> toJson() => {'start': start, 'end': end};

  /// Parses a byte range from a JSON-safe [json] map.
  ///
  /// Throws a [FormatException] when required integer fields are missing.
  factory ByteRange.fromJson(Map<String, Object?> json) =>
      ByteRange(_integer(json, 'start'), _integer(json, 'end'));

  @override
  /// Tests whether [other] has the same byte coordinates.
  bool operator ==(Object other) =>
      other is ByteRange && start == other.start && end == other.end;

  @override
  /// A hash derived from the byte range coordinates.
  int get hashCode => Object.hash(start, end);
}

/// The byte order used when targeting an integer field.
enum ByteOrder {
  /// Most significant byte first.
  bigEndian,

  /// Least significant byte first.
  littleEndian,
}

/// A fixed-width integer field that can be corrupted in a fixture.
final class IntegerField {
  /// Creates a mutation target at byte [offset] with a byte [width].
  ///
  /// Throws when [offset] is negative or [width] is not 1, 2, 4, or 8 bytes.
  IntegerField({
    required this.offset,
    required this.width,
    this.byteOrder = ByteOrder.bigEndian,
  }) {
    RangeError.checkNotNegative(offset, 'offset');
    if (!const {1, 2, 4, 8}.contains(width)) {
      throw ArgumentError.value(width, 'width', 'must be 1, 2, 4, or 8');
    }
  }

  /// The first byte of the integer field in the fixture.
  final int offset;

  /// The integer width in bytes; valid values are 1, 2, 4, and 8.
  final int width;

  /// The byte order used to choose the least significant byte to flip.
  final ByteOrder byteOrder;

  /// Verifies that the full integer field fits inside [bytes].
  ///
  /// Throws a [RangeError] when `offset + width` exceeds the input length.
  void validateFor(List<int> bytes, [String name = 'field']) {
    if (offset + width > bytes.length) {
      throw RangeError.range(offset + width, 0, bytes.length, name);
    }
  }
}

/// A single deterministic byte mutation in a [MutationPlan].
sealed class ByteMutationStep {
  /// Creates a mutation step base instance.
  const ByteMutationStep();

  /// The validation-failure category this step is expected to exercise.
  MutationClassification get classification;

  /// Applies this mutation to [input] without modifying [input].
  Uint8List apply(List<int> input);

  /// Produces smaller valid alternatives for minimizing a failing test case.
  Iterable<ByteMutationStep> shrink(int inputLength);

  /// Converts this step to a JSON-safe map for campaign replay.
  Map<String, Object?> toJson();

  /// Parses a concrete mutation step from a JSON-safe [json] map.
  ///
  /// Throws a [FormatException] for malformed fields and an [ArgumentError] for
  /// classifications that do not match the concrete step requirements.
  static ByteMutationStep fromJson(Map<String, Object?> json) {
    final classification = MutationClassification.values.byName(
      _string(json, 'classification'),
    );
    return switch (classification) {
      MutationClassification.truncation => TruncateStep(
        _integer(json, 'length'),
      ),
      MutationClassification.lengthCorruption ||
      MutationClassification.offsetCorruption => IntegerCorruptionStep(
        classification: classification,
        offset: _integer(json, 'offset'),
        width: _integer(json, 'width'),
        xorMask: _integer(json, 'xorMask'),
        byteOrder: ByteOrder.values.byName(
          json['byteOrder']?.toString() ?? ByteOrder.bigEndian.name,
        ),
      ),
      MutationClassification.duplicateStructure => DuplicateRangeStep(
        range: ByteRange.fromJson(_map(json, 'range')),
        insertOffset: _integer(json, 'insertOffset'),
      ),
      MutationClassification.reorderStructure => ReorderRangesStep(
        first: ByteRange.fromJson(_map(json, 'first')),
        second: ByteRange.fromJson(_map(json, 'second')),
      ),
      MutationClassification.deleteStructure => DeleteRangeStep(
        ByteRange.fromJson(_map(json, 'range')),
      ),
      MutationClassification.protectedBitFlip ||
      MutationClassification.unprotectedBitFlip => BitFlipStep(
        classification: classification,
        offset: _integer(json, 'offset'),
        bit: _integer(json, 'bit'),
      ),
      MutationClassification.nestingBomb => NestingBombStep(
        offset: _integer(json, 'offset'),
        depth: _integer(json, 'depth'),
        openingByte: _integer(json, 'openingByte'),
        closingByte: _integer(json, 'closingByte'),
      ),
      MutationClassification.malformedCborSize ||
      MutationClassification.malformedDerSize => MalformedSizeStep(
        classification: classification,
        offset: _integer(json, 'offset'),
        declaredSize: _integer(json, 'declaredSize'),
      ),
    };
  }
}

/// A mutation that removes trailing bytes from an asset.
final class TruncateStep extends ByteMutationStep {
  /// Creates a truncation that keeps exactly [length] bytes.
  ///
  /// Throws a [RangeError] when [length] is negative. Applying the step also
  /// throws if [length] exceeds the current input length.
  TruncateStep(this.length) {
    RangeError.checkNotNegative(length, 'length');
  }

  /// The output length in bytes after truncation.
  final int length;

  @override
  /// The truncation failure category for incomplete byte streams.
  MutationClassification get classification =>
      MutationClassification.truncation;

  @override
  /// Shortens [input] to [length] bytes without modifying [input].
  Uint8List apply(List<int> input) => ByteMutation.truncate(input, length);

  @override
  /// Yields truncations closer to [inputLength] for failure minimization.
  Iterable<ByteMutationStep> shrink(int inputLength) sync* {
    if (length >= inputLength) return;
    final midpoint = length + ((inputLength - length) ~/ 2);
    if (midpoint > length && midpoint < inputLength) {
      yield TruncateStep(midpoint);
    }
    if (inputLength - 1 != midpoint) {
      yield TruncateStep(inputLength - 1);
    }
  }

  @override
  /// Converts this truncation step to a JSON-safe map.
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'length': length,
  };
}

/// A mutation that flips one byte of a length or offset integer.
final class IntegerCorruptionStep extends ByteMutationStep {
  /// Creates an integer-field corruption for a length or offset.
  ///
  /// [width] must be 1, 2, 4, or 8 bytes and [xorMask] must be between 1 and
  /// 255. The [classification] must be a length or offset corruption.
  IntegerCorruptionStep({
    required this.classification,
    required this.offset,
    required this.width,
    this.xorMask = 1,
    this.byteOrder = ByteOrder.bigEndian,
  }) {
    if (classification != MutationClassification.lengthCorruption &&
        classification != MutationClassification.offsetCorruption) {
      throw ArgumentError.value(classification, 'classification');
    }
    RangeError.checkNotNegative(offset, 'offset');
    if (!const {1, 2, 4, 8}.contains(width)) {
      throw ArgumentError.value(width, 'width', 'must be 1, 2, 4, or 8');
    }
    RangeError.checkValueInInterval(xorMask, 1, 0xff, 'xorMask');
  }

  @override
  /// The integer-field failure category this step should provoke.
  final MutationClassification classification;

  /// The first byte of the integer field to corrupt.
  final int offset;

  /// The integer field width in bytes; valid values are 1, 2, 4, and 8.
  final int width;

  /// The non-zero byte mask XORed into the targeted integer byte.
  final int xorMask;

  /// The byte order used to locate the least significant byte.
  final ByteOrder byteOrder;

  @override
  /// Flips the selected integer byte in [input] without modifying [input].
  ///
  /// Throws a [RangeError] when the configured field extends past [input].
  Uint8List apply(List<int> input) {
    if (offset + width > input.length) {
      throw RangeError.range(offset + width, 0, input.length, 'field end');
    }
    final result = Uint8List.fromList(input);
    final target = byteOrder == ByteOrder.bigEndian
        ? offset + width - 1
        : offset;
    result[target] ^= xorMask;
    return result;
  }

  @override
  /// Yields a one-bit corruption when this step uses a wider [xorMask].
  Iterable<ByteMutationStep> shrink(int inputLength) sync* {
    if (xorMask != 1) {
      yield IntegerCorruptionStep(
        classification: classification,
        offset: offset,
        width: width,
        byteOrder: byteOrder,
      );
    }
  }

  @override
  /// Converts this integer corruption step to a JSON-safe map.
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'offset': offset,
    'width': width,
    'xorMask': xorMask,
    'byteOrder': byteOrder.name,
  };
}

/// A mutation that inserts a duplicate copy of a structural byte range.
final class DuplicateRangeStep extends ByteMutationStep {
  /// Creates a structural duplication from [range] at [insertOffset].
  ///
  /// Applying the step throws if [range] is outside the input or
  /// [insertOffset] is not a valid insertion point.
  const DuplicateRangeStep({required this.range, required this.insertOffset});

  /// The structural byte range copied from the current input.
  final ByteRange range;

  /// The byte offset where the duplicated structure is inserted.
  final int insertOffset;

  @override
  /// The structural duplication category for extra-data failures.
  MutationClassification get classification =>
      MutationClassification.duplicateStructure;

  @override
  /// Inserts a copy of [range] into [input] without modifying [input].
  Uint8List apply(List<int> input) {
    range.validateFor(input);
    RangeError.checkValueInInterval(
      insertOffset,
      0,
      input.length,
      'insertOffset',
    );
    return ByteMutation.insert(
      input,
      insertOffset,
      input.sublist(range.start, range.end),
    );
  }

  @override
  /// Yields a one-byte duplication when [range] spans multiple bytes.
  Iterable<ByteMutationStep> shrink(int inputLength) sync* {
    if (range.length > 1) {
      yield DuplicateRangeStep(
        range: ByteRange(range.start, range.start + 1),
        insertOffset: insertOffset,
      );
    }
  }

  @override
  /// Converts this structural duplication step to a JSON-safe map.
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'range': range.toJson(),
    'insertOffset': insertOffset,
  };
}

/// A mutation that swaps two non-overlapping structural byte ranges.
final class ReorderRangesStep extends ByteMutationStep {
  /// Creates a structural reorder from [first] and [second].
  ///
  /// Throws an [ArgumentError] unless the ranges are sorted and
  /// non-overlapping. Applying the step throws if either range is outside the
  /// current input.
  ReorderRangesStep({required this.first, required this.second}) {
    if (first.end > second.start) {
      throw ArgumentError(
        'Reordered ranges must be non-overlapping and sorted.',
      );
    }
  }

  /// The earlier structural byte range moved after [second].
  final ByteRange first;

  /// The later structural byte range moved before [first].
  final ByteRange second;

  @override
  /// The structural reordering category for ordering failures.
  MutationClassification get classification =>
      MutationClassification.reorderStructure;

  @override
  /// Swaps [first] and [second] in [input] without modifying [input].
  Uint8List apply(List<int> input) {
    first.validateFor(input, 'first');
    second.validateFor(input, 'second');
    return Uint8List.fromList([
      ...input.take(first.start),
      ...input.sublist(second.start, second.end),
      ...input.sublist(first.end, second.start),
      ...input.sublist(first.start, first.end),
      ...input.skip(second.end),
    ]);
  }

  @override
  /// Produces no smaller reorder candidates.
  Iterable<ByteMutationStep> shrink(int inputLength) => const [];

  @override
  /// Converts this structural reorder step to a JSON-safe map.
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'first': first.toJson(),
    'second': second.toJson(),
  };
}

/// A mutation that removes a structural byte range from an asset.
final class DeleteRangeStep extends ByteMutationStep {
  /// Creates a structural deletion for [range].
  ///
  /// Applying the step throws when [range] is outside the current input.
  const DeleteRangeStep(this.range);

  /// The structural byte range removed from the current input.
  final ByteRange range;

  @override
  /// The structural deletion category for missing-data failures.
  MutationClassification get classification =>
      MutationClassification.deleteStructure;

  @override
  /// Removes [range] from [input] without modifying [input].
  Uint8List apply(List<int> input) {
    range.validateFor(input);
    return ByteMutation.replaceRange(input, range.start, range.end, const []);
  }

  @override
  /// Yields a one-byte deletion when [range] spans multiple bytes.
  Iterable<ByteMutationStep> shrink(int inputLength) sync* {
    if (range.length > 1) {
      yield DeleteRangeStep(ByteRange(range.start, range.start + 1));
    }
  }

  @override
  /// Converts this structural deletion step to a JSON-safe map.
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'range': range.toJson(),
  };
}

/// A mutation that flips one bit in protected or unprotected bytes.
final class BitFlipStep extends ByteMutationStep {
  /// Creates a bit flip at byte [offset] and bit index [bit].
  ///
  /// [bit] is zero-based and must be in the inclusive range 0 to 7. The
  /// [classification] must be a protected or unprotected bit flip.
  BitFlipStep({
    required this.classification,
    required this.offset,
    required this.bit,
  }) {
    if (classification != MutationClassification.protectedBitFlip &&
        classification != MutationClassification.unprotectedBitFlip) {
      throw ArgumentError.value(classification, 'classification');
    }
    RangeError.checkNotNegative(offset, 'offset');
    RangeError.checkValueInInterval(bit, 0, 7, 'bit');
  }

  @override
  /// The bit-flip category used to distinguish signed and unsigned bytes.
  final MutationClassification classification;

  /// The byte offset whose bit is flipped.
  final int offset;

  /// The zero-based bit index within the byte, from 0 to 7.
  final int bit;

  @override
  /// Flips [bit] at [offset] in [input] without modifying [input].
  Uint8List apply(List<int> input) =>
      ByteMutation.flip(input, offset, mask: 1 << bit);

  @override
  /// Yields a candidate that flips bit zero when [bit] is non-zero.
  Iterable<ByteMutationStep> shrink(int inputLength) sync* {
    if (bit != 0) {
      yield BitFlipStep(classification: classification, offset: offset, bit: 0);
    }
  }

  @override
  /// Converts this bit-flip step to a JSON-safe map.
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'offset': offset,
    'bit': bit,
  };
}

/// A mutation that inserts a deeply nested byte pattern.
final class NestingBombStep extends ByteMutationStep {
  /// Creates a nesting bomb insertion at [offset].
  ///
  /// [depth] controls the number of opening and closing bytes inserted and
  /// must be in the inclusive range 1 to 65535. Byte values must be 0 to 255.
  NestingBombStep({
    required this.offset,
    required this.depth,
    this.openingByte = 0x9f,
    this.closingByte = 0xff,
  }) {
    RangeError.checkNotNegative(offset, 'offset');
    RangeError.checkValueInInterval(depth, 1, 0xffff, 'depth');
    RangeError.checkValueInInterval(openingByte, 0, 0xff, 'openingByte');
    RangeError.checkValueInInterval(closingByte, 0, 0xff, 'closingByte');
  }

  /// The byte offset where the nested pattern is inserted.
  final int offset;

  /// The number of opening bytes and matching closing bytes to insert.
  final int depth;

  /// The byte repeated [depth] times before the closing bytes.
  final int openingByte;

  /// The byte repeated [depth] times after the opening bytes.
  final int closingByte;

  @override
  /// The nesting-bomb category for excessive-depth parser failures.
  MutationClassification get classification =>
      MutationClassification.nestingBomb;

  @override
  /// Inserts the nested byte pattern into [input] without modifying [input].
  Uint8List apply(List<int> input) {
    RangeError.checkValueInInterval(offset, 0, input.length, 'offset');
    return ByteMutation.insert(input, offset, [
      ...List.filled(depth, openingByte),
      ...List.filled(depth, closingByte),
    ]);
  }

  @override
  /// Yields a shallower nesting bomb when [depth] is greater than one.
  Iterable<ByteMutationStep> shrink(int inputLength) sync* {
    if (depth > 1) {
      yield NestingBombStep(
        offset: offset,
        depth: depth ~/ 2,
        openingByte: openingByte,
        closingByte: closingByte,
      );
    }
  }

  @override
  /// Converts this nesting-bomb step to a JSON-safe map.
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'offset': offset,
    'depth': depth,
    'openingByte': openingByte,
    'closingByte': closingByte,
  };
}

/// A mutation that replaces one byte with an invalid CBOR or DER size header.
final class MalformedSizeStep extends ByteMutationStep {
  /// Creates a malformed size marker at byte [offset].
  ///
  /// [declaredSize] is encoded as a four-byte unsigned size and must fit in
  /// 32 bits. The [classification] must target CBOR or DER size parsing.
  MalformedSizeStep({
    required this.classification,
    required this.offset,
    required this.declaredSize,
  }) {
    if (classification != MutationClassification.malformedCborSize &&
        classification != MutationClassification.malformedDerSize) {
      throw ArgumentError.value(classification, 'classification');
    }
    RangeError.checkNotNegative(offset, 'offset');
    RangeError.checkValueInInterval(
      declaredSize,
      0,
      0xffffffff,
      'declaredSize',
    );
  }

  @override
  /// The malformed-size category for CBOR or DER validation failures.
  final MutationClassification classification;

  /// The byte offset replaced by the malformed size marker.
  final int offset;

  /// The declared size in bytes written after the replacement marker.
  final int declaredSize;

  @override
  /// Replaces one byte in [input] with a marker and four size bytes.
  ///
  /// Throws a [RangeError] when [offset] is outside [input].
  Uint8List apply(List<int> input) {
    RangeError.checkValidIndex(offset, input, 'offset');
    final marker = classification == MutationClassification.malformedCborSize
        ? 0x5a
        : 0x84;
    return ByteMutation.replaceRange(
      input,
      offset,
      offset + 1,
      [
        marker,
        declaredSize >>> 24,
        declaredSize >>> 16,
        declaredSize >>> 8,
        declaredSize,
      ].map((byte) => byte & 0xff).toList(growable: false),
    );
  }

  @override
  /// Yields a smaller declared size when [declaredSize] is greater than one.
  Iterable<ByteMutationStep> shrink(int inputLength) sync* {
    if (declaredSize > 1) {
      yield MalformedSizeStep(
        classification: classification,
        offset: offset,
        declaredSize: declaredSize ~/ 2,
      );
    }
  }

  @override
  /// Converts this malformed-size step to a JSON-safe map.
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'offset': offset,
    'declaredSize': declaredSize,
  };
}

/// A deterministic sequence of byte mutations for a fixture.
final class MutationPlan {
  /// Creates a mutation plan from [steps] and the generator [seed].
  ///
  /// The step list is defensively copied and cannot be mutated afterward.
  MutationPlan({required this.seed, required Iterable<ByteMutationStep> steps})
    : steps = List.unmodifiable(steps);

  /// Parses a mutation plan from a JSON-safe [json] map.
  ///
  /// Throws a [FormatException] when the step array or any required field is
  /// malformed.
  factory MutationPlan.fromJson(Map<String, Object?> json) {
    final rawSteps = json['steps'];
    if (rawSteps is! List<Object?>) {
      throw const FormatException('Mutation plan steps must be an array.');
    }
    return MutationPlan(
      seed: _integer(json, 'seed'),
      steps: rawSteps.map(
        (step) => ByteMutationStep.fromJson(_objectMap(step, 'mutation step')),
      ),
    );
  }

  /// The seed that produced this plan, used for campaign replay.
  final int seed;

  /// The ordered mutation steps applied to an input fixture.
  final List<ByteMutationStep> steps;

  /// The distinct mutation categories present in [steps].
  Set<MutationClassification> get classifications =>
      Set.unmodifiable(steps.map((step) => step.classification));

  /// Applies every step to [input] in order without modifying [input].
  ///
  /// Throws any [RangeError] raised by a step whose target no longer fits after
  /// earlier mutations.
  Uint8List apply(List<int> input) {
    var result = Uint8List.fromList(input);
    for (final step in steps) {
      result = step.apply(result);
    }
    return result;
  }

  /// Produces smaller plans that still apply cleanly to [input].
  ///
  /// Used by campaign tests to minimize failing corruption cases while keeping
  /// only candidates that do not throw [RangeError] during application.
  Iterable<MutationPlan> shrink(List<int> input) sync* {
    for (var index = steps.length - 1; index >= 0; index--) {
      final candidate = [...steps]..removeAt(index);
      final plan = MutationPlan(seed: seed, steps: candidate);
      try {
        plan.apply(input);
      } on RangeError {
        continue;
      }
      yield plan;
    }
    for (var index = 0; index < steps.length; index++) {
      var length = input.length;
      for (var prior = 0; prior < index; prior++) {
        length = steps[prior].apply(Uint8List(length)).length;
      }
      for (final smaller in steps[index].shrink(length)) {
        final candidate = [...steps]..[index] = smaller;
        final plan = MutationPlan(seed: seed, steps: candidate);
        try {
          plan.apply(input);
        } on RangeError {
          continue;
        }
        yield plan;
      }
    }
  }

  /// Converts this mutation plan to a JSON-safe map.
  Map<String, Object?> toJson() => {
    'seed': seed,
    'steps': steps.map((step) => step.toJson()).toList(growable: false),
  };
}

/// A deterministic 32-bit byte generator for reproducible test cases.
final class SeededByteGenerator {
  /// Creates a generator initialized from [seed].
  ///
  /// The seed is truncated to the low 32 bits to match the generator state.
  SeededByteGenerator(int seed) : _state = seed & 0xffffffff;

  int _state;

  /// Advances the generator and returns an unsigned 32-bit integer.
  int nextUint32() {
    _state = (1664525 * _state + 1013904223) & 0xffffffff;
    return _state;
  }

  /// Returns a deterministic integer in the half-open range `0..maximum`.
  ///
  /// Throws a [RangeError] when [maximum] is less than one.
  int nextInt(int maximum) {
    RangeError.checkValueInInterval(maximum, 1, 0x7fffffff, 'maximum');
    return nextUint32() % maximum;
  }

  /// Returns a deterministic boolean derived from the next 32-bit value.
  bool nextBool() => nextUint32().isOdd;
}

/// Configuration for generating byte-level negative-test mutations.
final class MutationGeneratorConfig {
  /// Creates generator settings for a fixture corpus.
  ///
  /// [maxOperationsPerPlan] must be 1 to 1024, [maxNestingDepth] must be at
  /// least one, and [maxGeneratedBytes] limits mutated output size in bytes.
  /// At least one [classifications] entry is required.
  MutationGeneratorConfig({
    Iterable<MutationClassification> classifications =
        MutationClassification.values,
    Iterable<ByteRange> protectedRanges = const [],
    Iterable<ByteRange> structuralRanges = const [],
    Iterable<IntegerField> lengthFields = const [],
    Iterable<IntegerField> offsetFields = const [],
    this.maxOperationsPerPlan = 1,
    this.maxNestingDepth = 32,
    this.maxGeneratedBytes = 16 * 1024 * 1024,
  }) : classifications = Set.unmodifiable(classifications),
       protectedRanges = List.unmodifiable(protectedRanges),
       structuralRanges = List.unmodifiable(structuralRanges),
       lengthFields = List.unmodifiable(lengthFields),
       offsetFields = List.unmodifiable(offsetFields) {
    if (this.classifications.isEmpty) {
      throw ArgumentError('At least one mutation classification is required.');
    }
    RangeError.checkValueInInterval(
      maxOperationsPerPlan,
      1,
      1024,
      'maxOperationsPerPlan',
    );
    RangeError.checkValueInInterval(
      maxNestingDepth,
      1,
      0xffff,
      'maxNestingDepth',
    );
    RangeError.checkValueInInterval(
      maxGeneratedBytes,
      1,
      0x1fffffffffffff,
      'maxGeneratedBytes',
    );
  }

  /// The mutation categories eligible for generated plans.
  final Set<MutationClassification> classifications;

  /// Byte ranges treated as signed or hashed by the test fixture.
  final List<ByteRange> protectedRanges;

  /// Byte ranges representing structures that may be duplicated or removed.
  final List<ByteRange> structuralRanges;

  /// Integer fields whose length values may be corrupted.
  final List<IntegerField> lengthFields;

  /// Integer fields whose offset values may be corrupted.
  final List<IntegerField> offsetFields;

  /// The maximum number of mutation steps in one generated plan.
  final int maxOperationsPerPlan;

  /// The maximum nesting depth inserted by nesting-bomb mutations.
  final int maxNestingDepth;

  /// The maximum mutated output size in bytes.
  final int maxGeneratedBytes;
}

/// A deterministic mutation-plan generator for byte fixtures.
final class MutationPlanGenerator {
  /// Creates a generator that follows [config].
  const MutationPlanGenerator(this.config);

  /// The settings that bound generated mutation plans.
  final MutationGeneratorConfig config;

  /// Generates a deterministic mutation plan for [input] using [seed].
  ///
  /// Throws an [ArgumentError] when [input] exceeds the configured byte limit
  /// and a [StateError] when no configured mutation applies to [input].
  MutationPlan generate(List<int> input, {required int seed}) {
    if (input.length > config.maxGeneratedBytes) {
      throw ArgumentError.value(
        input.length,
        'input',
        'exceeds maxGeneratedBytes ${config.maxGeneratedBytes}',
      );
    }
    final random = SeededByteGenerator(seed);
    var current = Uint8List.fromList(input);
    final steps = <ByteMutationStep>[];
    final operationCount = 1 + random.nextInt(config.maxOperationsPerPlan);
    for (var index = 0; index < operationCount; index++) {
      final viable = _viableClassifications(current);
      if (viable.isEmpty) {
        if (steps.isEmpty) {
          throw StateError('No configured mutation applies to this input.');
        }
        break;
      }
      final classification = viable[random.nextInt(viable.length)];
      final step = _generateStep(classification, current, random);
      current = step.apply(current);
      steps.add(step);
    }
    return MutationPlan(seed: seed, steps: steps);
  }

  List<MutationClassification> _viableClassifications(List<int> input) {
    final ranges = config.structuralRanges
        .where((range) => range.length > 0 && range.end <= input.length)
        .toList();
    final reorderable = _reorderablePairs(ranges).isNotEmpty;
    return config.classifications.where((classification) {
      return switch (classification) {
        MutationClassification.truncation => input.isNotEmpty,
        MutationClassification.lengthCorruption =>
          _validFields(config.lengthFields, input).isNotEmpty ||
              input.isNotEmpty,
        MutationClassification.offsetCorruption =>
          _validFields(config.offsetFields, input).isNotEmpty ||
              input.isNotEmpty,
        MutationClassification.duplicateStructure => ranges.any(
          (range) => input.length + range.length <= config.maxGeneratedBytes,
        ),
        MutationClassification.deleteStructure => ranges.isNotEmpty,
        MutationClassification.reorderStructure => reorderable,
        MutationClassification.protectedBitFlip => _hasProtectedOffset(
          input.length,
        ),
        MutationClassification.unprotectedBitFlip => _hasUnprotectedOffset(
          input.length,
        ),
        MutationClassification.nestingBomb =>
          input.length + 2 <= config.maxGeneratedBytes,
        MutationClassification.malformedCborSize ||
        MutationClassification.malformedDerSize =>
          input.isNotEmpty && input.length + 4 <= config.maxGeneratedBytes,
      };
    }).toList();
  }

  ByteMutationStep _generateStep(
    MutationClassification classification,
    List<int> input,
    SeededByteGenerator random,
  ) {
    switch (classification) {
      case MutationClassification.truncation:
        return TruncateStep(random.nextInt(input.length));
      case MutationClassification.lengthCorruption:
      case MutationClassification.offsetCorruption:
        final configured =
            classification == MutationClassification.lengthCorruption
            ? config.lengthFields
            : config.offsetFields;
        final fields = _validFields(configured, input);
        final field = fields.isEmpty
            ? IntegerField(offset: random.nextInt(input.length), width: 1)
            : fields[random.nextInt(fields.length)];
        return IntegerCorruptionStep(
          classification: classification,
          offset: field.offset,
          width: field.width,
          xorMask: 1 << random.nextInt(8),
          byteOrder: field.byteOrder,
        );
      case MutationClassification.duplicateStructure:
        final ranges = config.structuralRanges
            .where(
              (range) =>
                  range.length > 0 &&
                  range.end <= input.length &&
                  input.length + range.length <= config.maxGeneratedBytes,
            )
            .toList();
        final range = ranges[random.nextInt(ranges.length)];
        return DuplicateRangeStep(
          range: range,
          insertOffset: random.nextInt(input.length + 1),
        );
      case MutationClassification.reorderStructure:
        final ranges =
            config.structuralRanges
                .where((range) => range.length > 0 && range.end <= input.length)
                .toList()
              ..sort((left, right) => left.start.compareTo(right.start));
        final pairs = _reorderablePairs(ranges);
        final pair = pairs[random.nextInt(pairs.length)];
        return ReorderRangesStep(first: pair.$1, second: pair.$2);
      case MutationClassification.deleteStructure:
        return DeleteRangeStep(_randomStructuralRange(input, random));
      case MutationClassification.protectedBitFlip:
        return BitFlipStep(
          classification: classification,
          offset: _randomOffset(input.length, random, protected: true),
          bit: random.nextInt(8),
        );
      case MutationClassification.unprotectedBitFlip:
        return BitFlipStep(
          classification: classification,
          offset: _randomOffset(input.length, random, protected: false),
          bit: random.nextInt(8),
        );
      case MutationClassification.nestingBomb:
        final maximumDepth =
            (config.maxGeneratedBytes - input.length) ~/ 2 <
                config.maxNestingDepth
            ? (config.maxGeneratedBytes - input.length) ~/ 2
            : config.maxNestingDepth;
        return NestingBombStep(
          offset: random.nextInt(input.length + 1),
          depth: 1 + random.nextInt(maximumDepth),
        );
      case MutationClassification.malformedCborSize:
      case MutationClassification.malformedDerSize:
        return MalformedSizeStep(
          classification: classification,
          offset: random.nextInt(input.length),
          declaredSize: input.length + 1 + random.nextInt(0x10000),
        );
    }
  }

  List<IntegerField> _validFields(List<IntegerField> fields, List<int> input) =>
      fields
          .where((field) => field.offset + field.width <= input.length)
          .toList();

  ByteRange _randomStructuralRange(
    List<int> input,
    SeededByteGenerator random,
  ) {
    final ranges = config.structuralRanges
        .where((range) => range.length > 0 && range.end <= input.length)
        .toList();
    return ranges[random.nextInt(ranges.length)];
  }

  bool _hasProtectedOffset(int length) => config.protectedRanges.any(
    (range) => range.start < length && range.length > 0,
  );

  bool _hasUnprotectedOffset(int length) {
    for (var offset = 0; offset < length; offset++) {
      if (!_isProtected(offset)) return true;
    }
    return false;
  }

  bool _isProtected(int offset) =>
      config.protectedRanges.any((range) => range.contains(offset));

  int _randomOffset(
    int length,
    SeededByteGenerator random, {
    required bool protected,
  }) {
    final candidates = <int>[];
    for (var offset = 0; offset < length; offset++) {
      if (_isProtected(offset) == protected) candidates.add(offset);
    }
    return candidates[random.nextInt(candidates.length)];
  }

  List<(ByteRange, ByteRange)> _reorderablePairs(List<ByteRange> ranges) {
    final sorted = [...ranges]
      ..sort((left, right) => left.start.compareTo(right.start));
    final pairs = <(ByteRange, ByteRange)>[];
    for (var first = 0; first < sorted.length; first++) {
      for (var second = first + 1; second < sorted.length; second++) {
        if (sorted[first].end <= sorted[second].start) {
          pairs.add((sorted[first], sorted[second]));
        }
      }
    }
    return pairs;
  }
}

Map<String, Object?> _map(Map<String, Object?> json, String key) =>
    _objectMap(json[key], key);

Map<String, Object?> _objectMap(Object? value, String name) {
  if (value is! Map<Object?, Object?>) {
    throw FormatException('$name must be a JSON object.');
  }
  return value.map((key, value) => MapEntry(key.toString(), value));
}

int _integer(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! int) throw FormatException('$key must be an integer.');
  return value;
}

String _string(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! String) throw FormatException('$key must be a string.');
  return value;
}
