import 'dart:typed_data';

import 'byte_mutation.dart';

enum MutationClassification {
  truncation,
  lengthCorruption,
  offsetCorruption,
  duplicateStructure,
  reorderStructure,
  deleteStructure,
  protectedBitFlip,
  unprotectedBitFlip,
  nestingBomb,
  malformedCborSize,
  malformedDerSize,
}

final class ByteRange {
  ByteRange(this.start, this.end) {
    RangeError.checkNotNegative(start, 'start');
    RangeError.checkValueInInterval(end, start, 0x1fffffffffffff, 'end');
  }

  final int start;
  final int end;

  int get length => end - start;
  bool contains(int offset) => offset >= start && offset < end;

  void validateFor(List<int> bytes, [String name = 'range']) {
    if (end > bytes.length) {
      throw RangeError.range(end, start, bytes.length, '$name.end');
    }
  }

  Map<String, Object?> toJson() => {'start': start, 'end': end};

  factory ByteRange.fromJson(Map<String, Object?> json) =>
      ByteRange(_integer(json, 'start'), _integer(json, 'end'));

  @override
  bool operator ==(Object other) =>
      other is ByteRange && start == other.start && end == other.end;

  @override
  int get hashCode => Object.hash(start, end);
}

enum ByteOrder { bigEndian, littleEndian }

final class IntegerField {
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

  final int offset;
  final int width;
  final ByteOrder byteOrder;

  void validateFor(List<int> bytes, [String name = 'field']) {
    if (offset + width > bytes.length) {
      throw RangeError.range(offset + width, 0, bytes.length, name);
    }
  }
}

sealed class ByteMutationStep {
  const ByteMutationStep();

  MutationClassification get classification;
  Uint8List apply(List<int> input);
  Iterable<ByteMutationStep> shrink(int inputLength);
  Map<String, Object?> toJson();

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

final class TruncateStep extends ByteMutationStep {
  TruncateStep(this.length) {
    RangeError.checkNotNegative(length, 'length');
  }

  final int length;

  @override
  MutationClassification get classification =>
      MutationClassification.truncation;

  @override
  Uint8List apply(List<int> input) => ByteMutation.truncate(input, length);

  @override
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
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'length': length,
  };
}

final class IntegerCorruptionStep extends ByteMutationStep {
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
  final MutationClassification classification;
  final int offset;
  final int width;
  final int xorMask;
  final ByteOrder byteOrder;

  @override
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
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'offset': offset,
    'width': width,
    'xorMask': xorMask,
    'byteOrder': byteOrder.name,
  };
}

final class DuplicateRangeStep extends ByteMutationStep {
  const DuplicateRangeStep({required this.range, required this.insertOffset});

  final ByteRange range;
  final int insertOffset;

  @override
  MutationClassification get classification =>
      MutationClassification.duplicateStructure;

  @override
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
  Iterable<ByteMutationStep> shrink(int inputLength) sync* {
    if (range.length > 1) {
      yield DuplicateRangeStep(
        range: ByteRange(range.start, range.start + 1),
        insertOffset: insertOffset,
      );
    }
  }

  @override
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'range': range.toJson(),
    'insertOffset': insertOffset,
  };
}

final class ReorderRangesStep extends ByteMutationStep {
  ReorderRangesStep({required this.first, required this.second}) {
    if (first.end > second.start) {
      throw ArgumentError(
        'Reordered ranges must be non-overlapping and sorted.',
      );
    }
  }

  final ByteRange first;
  final ByteRange second;

  @override
  MutationClassification get classification =>
      MutationClassification.reorderStructure;

  @override
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
  Iterable<ByteMutationStep> shrink(int inputLength) => const [];

  @override
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'first': first.toJson(),
    'second': second.toJson(),
  };
}

final class DeleteRangeStep extends ByteMutationStep {
  const DeleteRangeStep(this.range);

  final ByteRange range;

  @override
  MutationClassification get classification =>
      MutationClassification.deleteStructure;

  @override
  Uint8List apply(List<int> input) {
    range.validateFor(input);
    return ByteMutation.replaceRange(input, range.start, range.end, const []);
  }

  @override
  Iterable<ByteMutationStep> shrink(int inputLength) sync* {
    if (range.length > 1) {
      yield DeleteRangeStep(ByteRange(range.start, range.start + 1));
    }
  }

  @override
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'range': range.toJson(),
  };
}

final class BitFlipStep extends ByteMutationStep {
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
  final MutationClassification classification;
  final int offset;
  final int bit;

  @override
  Uint8List apply(List<int> input) =>
      ByteMutation.flip(input, offset, mask: 1 << bit);

  @override
  Iterable<ByteMutationStep> shrink(int inputLength) sync* {
    if (bit != 0) {
      yield BitFlipStep(classification: classification, offset: offset, bit: 0);
    }
  }

  @override
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'offset': offset,
    'bit': bit,
  };
}

final class NestingBombStep extends ByteMutationStep {
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

  final int offset;
  final int depth;
  final int openingByte;
  final int closingByte;

  @override
  MutationClassification get classification =>
      MutationClassification.nestingBomb;

  @override
  Uint8List apply(List<int> input) {
    RangeError.checkValueInInterval(offset, 0, input.length, 'offset');
    return ByteMutation.insert(input, offset, [
      ...List.filled(depth, openingByte),
      ...List.filled(depth, closingByte),
    ]);
  }

  @override
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
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'offset': offset,
    'depth': depth,
    'openingByte': openingByte,
    'closingByte': closingByte,
  };
}

final class MalformedSizeStep extends ByteMutationStep {
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
  final MutationClassification classification;
  final int offset;
  final int declaredSize;

  @override
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
  Map<String, Object?> toJson() => {
    'classification': classification.name,
    'offset': offset,
    'declaredSize': declaredSize,
  };
}

final class MutationPlan {
  MutationPlan({required this.seed, required Iterable<ByteMutationStep> steps})
    : steps = List.unmodifiable(steps);

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

  final int seed;
  final List<ByteMutationStep> steps;

  Set<MutationClassification> get classifications =>
      Set.unmodifiable(steps.map((step) => step.classification));

  Uint8List apply(List<int> input) {
    var result = Uint8List.fromList(input);
    for (final step in steps) {
      result = step.apply(result);
    }
    return result;
  }

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

  Map<String, Object?> toJson() => {
    'seed': seed,
    'steps': steps.map((step) => step.toJson()).toList(growable: false),
  };
}

final class SeededByteGenerator {
  SeededByteGenerator(int seed) : _state = seed & 0xffffffff;

  int _state;

  int nextUint32() {
    _state = (1664525 * _state + 1013904223) & 0xffffffff;
    return _state;
  }

  int nextInt(int maximum) {
    RangeError.checkValueInInterval(maximum, 1, 0x7fffffff, 'maximum');
    return nextUint32() % maximum;
  }

  bool nextBool() => nextUint32().isOdd;
}

final class MutationGeneratorConfig {
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

  final Set<MutationClassification> classifications;
  final List<ByteRange> protectedRanges;
  final List<ByteRange> structuralRanges;
  final List<IntegerField> lengthFields;
  final List<IntegerField> offsetFields;
  final int maxOperationsPerPlan;
  final int maxNestingDepth;
  final int maxGeneratedBytes;
}

final class MutationPlanGenerator {
  const MutationPlanGenerator(this.config);

  final MutationGeneratorConfig config;

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
