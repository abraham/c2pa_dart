import 'dart:typed_data';

/// Default cap on how deeply [DerReader.reader] descents may nest.
///
/// DER is self-describing, so a structure can nest as deeply as its encoder
/// chose to. Parsing is driven by callers opening a reader over the content of
/// a value they just read, which means a hostile certificate can drive
/// unbounded recursion in the calling parser. The cap bounds that chain.
///
/// Real X.509, CMS, OCSP, and CRL structures nest far below this; the value is
/// chosen to reject runaway input without rejecting legitimate documents.
const int defaultMaxDerDepth = 32;

/// A single DER tag-length-value triple.
///
/// [encoded] covers the whole triple including its tag and length bytes, which
/// is what signature verification hashes. [content] covers only the value
/// bytes, which is what further parsing consumes.
final class DerValue {
  /// Creates a value at the root of a new nesting budget.
  ///
  /// Parsers use this to reinterpret bytes under a different [tag] without
  /// re-encoding them. A value built this way starts a fresh depth budget, so
  /// prefer [DerReader.read] for values that come from an existing parse.
  factory DerValue({
    required int tag,
    required Uint8List encoded,
    required Uint8List content,
  }) => DerValue._nested(tag, encoded, content, 0, defaultMaxDerDepth);

  DerValue._nested(
    this.tag,
    this.encoded,
    this.content,
    this._depth,
    this._maxDepth,
  );

  /// Identifier octet, limited to low-tag-number form.
  final int tag;

  /// The complete triple, including the tag and length octets.
  final Uint8List encoded;

  /// The value octets, excluding the tag and length octets.
  final Uint8List content;

  final int _depth;
  final int _maxDepth;

  /// Opens a reader over [content], one level deeper than this value.
  ///
  /// Throws FormatException when the nesting budget is exhausted.
  DerReader reader() => DerReader._(content, _depth + 1, _maxDepth);
}

/// Strict DER reader shared by the X.509, CMS, OCSP, and CRL parsers.
///
/// Every certificate-path input reaches this class, so it rejects the encoding
/// variants that let two parsers disagree about the same bytes: high-tag-number
/// form, indefinite lengths, non-minimal lengths, and lengths that overrun
/// their container. BER accepts several of those; DER does not, and accepting
/// them here would let a signature cover one interpretation while a relying
/// party acts on another.
///
/// The reader is flat. Reading a constructed value yields its [DerValue], and
/// descending into it means calling [DerValue.reader], which is where the
/// nesting budget is spent.
final class DerReader {
  /// Reads [bytes] as the root of a new nesting budget.
  ///
  /// [maxDepth] bounds how many times [DerValue.reader] may descend from
  /// values produced by this reader.
  factory DerReader(List<int> bytes, {int maxDepth = defaultMaxDerDepth}) =>
      DerReader._(
        bytes is Uint8List ? bytes : Uint8List.fromList(bytes),
        0,
        maxDepth,
      );

  DerReader._(this._bytes, this._depth, this._maxDepth) {
    if (_depth > _maxDepth) {
      throw const FormatException('DER nesting is too deep');
    }
  }

  final Uint8List _bytes;
  final int _depth;
  final int _maxDepth;
  int _offset = 0;

  /// Whether every byte has been consumed.
  bool get isAtEnd => _offset == _bytes.length;

  /// The next identifier octet, or `null` when no bytes remain.
  int? peekTag() => isAtEnd ? null : _bytes[_offset];

  /// Reads the next triple, optionally requiring it to carry [expectedTag].
  ///
  /// Throws FormatException for any non-DER encoding or a tag mismatch.
  DerValue read([int? expectedTag]) {
    final start = _offset;
    final tag = _readByte();
    if (tag & 0x1f == 0x1f) {
      throw const FormatException('High-tag-number DER is unsupported');
    }
    if (expectedTag != null && tag != expectedTag) {
      throw FormatException(
        'Expected DER tag 0x${expectedTag.toRadixString(16)}, '
        'found 0x${tag.toRadixString(16)}',
      );
    }

    final length = _readLength();
    if (length > _bytes.length - _offset) {
      throw const FormatException('DER value exceeds its container');
    }

    final contentStart = _offset;
    _offset += length;
    return DerValue._nested(
      tag,
      _bytes.sublist(start, _offset),
      _bytes.sublist(contentStart, _offset),
      _depth,
      _maxDepth,
    );
  }

  /// Reads one triple carrying [tag] and requires it to span every byte.
  ///
  /// Throws FormatException when anything follows the value.
  Uint8List single(int tag) {
    final value = read(tag);
    requireEnd();
    return value.content;
  }

  /// Requires that every byte has been consumed.
  ///
  /// Throws FormatException when unread bytes remain.
  void requireEnd() {
    if (!isAtEnd) {
      throw const FormatException('Trailing DER data');
    }
  }

  /// Decodes a definite, minimally encoded length octet run.
  int _readLength() {
    final first = _readByte();
    if (first < 0x80) {
      return first;
    }

    final count = first & 0x7f;
    if (count == 0) {
      throw const FormatException('Indefinite DER length is forbidden');
    }
    if (count > 4 || count > _bytes.length - _offset || _bytes[_offset] == 0) {
      throw const FormatException('Invalid DER length');
    }

    var length = 0;
    for (var index = 0; index < count; index++) {
      length = length << 8 | _readByte();
    }
    if (length < 0x80) {
      throw const FormatException('Non-minimal DER length');
    }
    return length;
  }

  int _readByte() {
    if (_offset >= _bytes.length) {
      throw const FormatException('Truncated DER');
    }
    return _bytes[_offset++];
  }
}
