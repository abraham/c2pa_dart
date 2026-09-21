import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import 'byte_reader.dart';
import 'errors.dart';
import 'handlers/isobmff_handler.dart';
import 'isobmff.dart';

/// A byte pattern that an ISO BMFF exclusion rule must match.
final class IsoBmffDataMatch {
  /// Creates a match at a box-relative byte [offset].
  IsoBmffDataMatch({required this.offset, required Iterable<int> value})
    : value = Uint8List.fromList(value.toList(growable: false));

  /// Byte offset from the start of the matched box, including its header.
  final int offset;

  /// The exact bytes that must appear at [offset].
  final Uint8List value;
}

/// A box-relative byte range excluded by an ISO BMFF hash rule.
final class IsoBmffSubset {
  /// Creates a subset at a box-relative byte [offset].
  const IsoBmffSubset({required this.offset, this.length = 0});

  /// Byte offset from the start of the matched box, including its header.
  final int offset;

  /// Zero means through the end of the matched box.
  final int length;
}

/// A C2PA BMFF hash exclusion rule matched against parsed boxes.
final class IsoBmffExclusion {
  /// Creates a rule for boxes at absolute XPath-like [xpath].
  ///
  /// Matching can be narrowed by box [length], FullBox [version], [flags], and
  /// [data]. If [subset] is empty the entire box is excluded; otherwise only
  /// each box-relative subset is excluded from source-byte hashing.
  IsoBmffExclusion({
    required this.xpath,
    this.length,
    Iterable<IsoBmffDataMatch> data = const <IsoBmffDataMatch>[],
    Iterable<IsoBmffSubset> subset = const <IsoBmffSubset>[],
    this.version,
    Iterable<int>? flags,
    this.exact = true,
  }) : data = List<IsoBmffDataMatch>.unmodifiable(data),
       subset = List<IsoBmffSubset>.unmodifiable(subset),
       flags = flags == null
           ? null
           : Uint8List.fromList(flags.toList(growable: false));

  /// Absolute box path such as `/moov/uuid`; `//` and trailing `/` are invalid.
  final String xpath;

  /// Required total box length in bytes, or `null` to ignore length.
  final int? length;

  /// Box-relative byte patterns that all must match before exclusion.
  final List<IsoBmffDataMatch> data;

  /// Ordered, non-overlapping box-relative byte ranges to exclude.
  final List<IsoBmffSubset> subset;

  /// Required ISO BMFF FullBox version byte, or `null` to ignore it.
  final int? version;

  /// Required three-byte FullBox flags value, or `null` to ignore flags.
  final Uint8List? flags;

  /// Whether [flags] must equal the box flags instead of acting as a mask.
  final bool exact;
}

/// A parsed ISO BMFF box with tree position and FullBox metadata.
final class IsoBmffBoxNode {
  /// Creates a parsed node with immutable [children].
  IsoBmffBoxNode({
    required this.box,
    required this.path,
    required this.version,
    required this.flags,
    required Iterable<IsoBmffBoxNode> children,
  }) : children = List<IsoBmffBoxNode>.unmodifiable(children);

  /// The box byte range and header metadata from the source segment.
  final IsoBmffBox box;

  /// Absolute slash-separated box path used by exclusion rules.
  final String path;

  /// FullBox version byte, or `null` when the box is not a FullBox.
  final int? version;

  /// FullBox flags as a 24-bit integer, or `null` when absent.
  final int? flags;

  /// Nested child boxes parsed from recognized container boxes.
  final List<IsoBmffBoxNode> children;

  /// Depth-first descendants, excluding this node.
  Iterable<IsoBmffBoxNode> get descendants sync* {
    for (final child in children) {
      yield child;
      yield* child.descendants;
    }
  }
}

/// A kind of input fed into the BMFF hash digest stream.
///
/// [sourceBytes] contributes bytes from the asset, while [offset] contributes
/// an eight-byte logical box offset marker.
enum IsoBmffDigestEventKind {
  /// Source bytes copied from a non-excluded range of the asset.
  sourceBytes,

  /// Eight-byte logical box offset marker inserted into the digest stream.
  offset,
}

/// One ordered contribution to an ISO BMFF hash digest stream.
sealed class IsoBmffDigestEvent {
  /// Creates a digest event at a stable [logicalOffset].
  const IsoBmffDigestEvent({
    required this.kind,
    required this.segmentIndex,
    required this.logicalOffset,
  });

  /// The type of digest input represented by this event.
  final IsoBmffDigestEventKind kind;

  /// Zero-based segment index; zero is the initialization segment.
  final int segmentIndex;

  /// Byte offset in the stable logical stream used for event ordering.
  final int logicalOffset;
}

/// A digest event that contributes a contiguous source byte range.
final class IsoBmffSourceDigestEvent extends IsoBmffDigestEvent {
  /// Creates a source-byte event for [range].
  const IsoBmffSourceDigestEvent({
    required super.segmentIndex,
    required super.logicalOffset,
    required this.range,
  }) : super(kind: IsoBmffDigestEventKind.sourceBytes);

  /// Segment-relative byte range included in the digest.
  final ByteRange range;
}

/// A digest event that contributes an encoded BMFF box offset marker.
final class IsoBmffOffsetDigestEvent extends IsoBmffDigestEvent {
  /// Creates an offset event for a segment-relative [boxOffset].
  ///
  /// Throws [MalformedBmffHashLayoutException] if [boxOffset] cannot be
  /// represented in the supported unsigned 64-bit range.
  IsoBmffOffsetDigestEvent({
    required super.segmentIndex,
    required super.logicalOffset,
    required this.boxOffset,
    required this.logicalBoxOffset,
  }) : bytes = _uint64Bytes(boxOffset),
       super(kind: IsoBmffDigestEventKind.offset);

  /// Offset within the physical segment.
  final int boxOffset;

  /// Offset in the stable logical stream formed by initialization then
  /// fragments.
  final int logicalBoxOffset;

  /// The big-endian eight-byte encoding of [boxOffset].
  final Uint8List bytes;
}

/// The resolved exclusions and digest events for one BMFF segment.
final class IsoBmffHashLayout {
  /// Creates a segment hash layout with immutable [boxes] and [events].
  IsoBmffHashLayout({
    required this.sourceLength,
    required this.logicalOffset,
    required this.segmentIndex,
    required Iterable<IsoBmffBoxNode> boxes,
    required Iterable<ByteRange> exclusions,
    required Iterable<IsoBmffDigestEvent> events,
  }) : boxes = List<IsoBmffBoxNode>.unmodifiable(boxes),
       exclusions = List<ByteRange>.unmodifiable(exclusions),
       events = List<IsoBmffDigestEvent>.unmodifiable(events);

  /// Segment length in bytes.
  final int sourceLength;

  /// Absolute byte offset of this segment in the logical fragmented stream.
  final int logicalOffset;

  /// Zero-based segment index in the fragmented source.
  final int segmentIndex;

  /// Top-level boxes parsed from this segment.
  final List<IsoBmffBoxNode> boxes;

  /// Segment-relative byte ranges excluded from source-byte hashing.
  final List<ByteRange> exclusions;

  /// Ordered digest inputs after applying exclusions and offset markers.
  final List<IsoBmffDigestEvent> events;
}

/// Metadata discovered in a C2PA ISO BMFF UUID box.
final class IsoBmffC2paMetadata {
  /// Creates metadata for one C2PA UUID box.
  IsoBmffC2paMetadata({
    required this.purpose,
    required this.boxRange,
    required this.dataRange,
    required this.logicalBoxOffset,
    required this.version,
    required this.flags,
    this.auxiliaryOffset,
  });

  /// C2PA purpose string, such as `manifest`, `update`, or `merkle`.
  final String purpose;

  /// Segment-relative byte range covering the full UUID box.
  final ByteRange boxRange;

  /// Segment-relative byte range of C2PA payload bytes to hash or extract.
  final ByteRange dataRange;

  /// Absolute logical byte offset of the UUID box in fragmented order.
  final int logicalBoxOffset;

  /// FullBox version byte from the C2PA UUID box; currently zero.
  final int version;

  /// FullBox flags from the C2PA UUID box; currently zero.
  final int flags;

  /// Auxiliary offset field for manifest-like boxes, or `null` for merkle.
  final int? auxiliaryOffset;

  /// Whether [purpose] identifies a merkle data box.
  bool get isMerkle => purpose == 'merkle';

  /// Whether [purpose] identifies a C2PA manifest-store box.
  bool get isManifest =>
      purpose == 'manifest' || purpose == 'original' || purpose == 'update';
}

/// An ISO BMFF initialization segment plus media fragments.
final class FragmentedIsoBmffSource {
  /// Creates a fragmented source with immutable [fragments].
  FragmentedIsoBmffSource({
    required this.initializationSegment,
    required Iterable<RandomAccessByteSource> fragments,
  }) : fragments = List<RandomAccessByteSource>.unmodifiable(fragments);

  /// The first segment, which must begin with an `ftyp` box.
  final RandomAccessByteSource initializationSegment;

  /// Media fragments ordered by `mfhd` sequence number.
  final List<RandomAccessByteSource> fragments;
}

/// Hash layout and C2PA metadata for one fragmented BMFF segment.
final class FragmentedIsoBmffSegment {
  /// Creates metadata for a logical segment.
  FragmentedIsoBmffSegment({
    required this.index,
    required this.isInitialization,
    required this.logicalOffset,
    required this.length,
    required this.sequenceNumber,
    required this.hashLayout,
    required Iterable<IsoBmffC2paMetadata> c2paMetadata,
  }) : c2paMetadata = List<IsoBmffC2paMetadata>.unmodifiable(c2paMetadata);

  /// Zero-based segment index; zero is the initialization segment.
  final int index;

  /// Whether this segment is the initialization segment.
  final bool isInitialization;

  /// Absolute byte offset of the segment in the logical concatenation.
  final int logicalOffset;

  /// Segment length in bytes.
  final int length;

  /// `mfhd` sequence number, or `null` for the initialization segment.
  final int? sequenceNumber;

  /// Resolved BMFF hash layout for this segment.
  final IsoBmffHashLayout hashLayout;

  /// C2PA UUID boxes discovered in this segment.
  final List<IsoBmffC2paMetadata> c2paMetadata;
}

/// The logical BMFF layout across initialization and fragment segments.
final class FragmentedIsoBmffLayout {
  /// Creates a fragmented layout with immutable [segments].
  FragmentedIsoBmffLayout({
    required this.logicalLength,
    required Iterable<FragmentedIsoBmffSegment> segments,
  }) : segments = List<FragmentedIsoBmffSegment>.unmodifiable(segments);

  /// Total logical length in bytes across all segments.
  final int logicalLength;

  /// Segment layouts in logical order.
  final List<FragmentedIsoBmffSegment> segments;
}

/// Interface for handlers that resolve C2PA BMFF hash layouts.
abstract interface class IsoBmffHashLayoutProvider {
  /// Resolves exclusions and digest events for a single BMFF [source].
  ///
  /// [logicalOffset] and [segmentIndex] identify this source within a
  /// fragmented logical stream. Throws [MalformedBmffHashLayoutException] for
  /// invalid exclusion rules and [MalformedAssetFormatException] for invalid
  /// BMFF structure.
  Future<IsoBmffHashLayout> getBmffHashLayout(
    RandomAccessByteSource source,
    List<IsoBmffExclusion> exclusions, {
    int version = 2,
    int logicalOffset = 0,
    int segmentIndex = 0,
  });

  /// Resolves BMFF hash layouts across initialization and media fragments.
  ///
  /// Fragments must be ordered by increasing `mfhd` sequence number, and the
  /// initialization segment must begin with `ftyp`.
  Future<FragmentedIsoBmffLayout> getFragmentedBmffLayout(
    FragmentedIsoBmffSource source,
    List<IsoBmffExclusion> exclusions, {
    int version = 2,
  });
}

/// Reader for C2PA BMFF hash layouts defined over ISO BMFF boxes.
final class IsoBmffHashLayoutReader {
  /// Creates a reader with safety limits for untrusted BMFF input.
  const IsoBmffHashLayoutReader({
    this.maxSourceSize = 512 * 1024 * 1024,
    this.maxTotalFragmentedSize = 2 * 1024 * 1024 * 1024,
    this.maxBoxCount = 1024 * 1024,
    this.maxDepth = 32,
    this.maxFragments = 1024 * 1024,
    this.maxRules = 4096,
    this.maxMatches = 1024 * 1024,
  });

  /// Maximum bytes accepted for one BMFF segment.
  final int maxSourceSize;

  /// Maximum combined logical bytes accepted across fragments.
  final int maxTotalFragmentedSize;

  /// Maximum number of boxes parsed from one segment tree.
  final int maxBoxCount;

  /// Maximum nested container depth while parsing boxes.
  final int maxDepth;

  /// Maximum number of media fragments after the initialization segment.
  final int maxFragments;

  /// Maximum number of exclusion rules accepted per layout request.
  final int maxRules;

  /// Maximum number of boxes matched by exclusion rules.
  final int maxMatches;

  /// Reads one BMFF segment and resolves its C2PA hash layout.
  ///
  /// Offsets in [exclusions] are relative to matched boxes; returned
  /// layout's `exclusions` are absolute within [source]. Version 1 emits only
  /// source-byte events, while later versions also emit box-offset events for
  /// boxes that are not fully excluded.
  Future<IsoBmffHashLayout> read(
    RandomAccessByteSource source,
    List<IsoBmffExclusion> exclusions, {
    int version = 2,
    int logicalOffset = 0,
    int segmentIndex = 0,
  }) async {
    if (version < 1 || version > 3) {
      throw UnsupportedIsoBmffFeatureException(
        'BMFF hash assertion version $version',
      );
    }
    if (logicalOffset < 0 || BigInt.from(logicalOffset) > _maxSupportedUint64) {
      throw const MalformedBmffHashLayoutException(
        'The logical BMFF offset is outside the unsigned 64-bit range.',
      );
    }
    if (exclusions.length > maxRules) {
      throw SegmentLimitExceededException(
        limit: maxRules,
        actual: exclusions.length,
      );
    }
    final parsed = await _parse(source);
    if (_sumExceedsSupportedUint64(parsed.length, logicalOffset)) {
      throw const MalformedBmffHashLayoutException(
        'The BMFF logical range exceeds unsigned 64-bit.',
      );
    }
    final ranges = await _resolveExclusions(source, parsed, exclusions);
    final markers = version > 1
        ? parsed.boxes
              .where((box) => !_fullyExcluded(box.box.range, ranges))
              .map((box) => box.box.offset)
              .toList(growable: false)
        : const <int>[];
    final events = _buildEvents(
      parsed.length,
      ranges,
      markers,
      logicalOffset: logicalOffset,
      segmentIndex: segmentIndex,
    );
    return IsoBmffHashLayout(
      sourceLength: parsed.length,
      logicalOffset: logicalOffset,
      segmentIndex: segmentIndex,
      boxes: parsed.boxes,
      exclusions: ranges,
      events: events,
    );
  }

  /// Reads an initialization segment and fragments as one logical BMFF stream.
  ///
  /// The first segment must begin with `ftyp`; each later segment must contain
  /// one top-level `moof` with one `mfhd` FullBox, ordered by sequence number.
  Future<FragmentedIsoBmffLayout> readFragmented(
    FragmentedIsoBmffSource source,
    List<IsoBmffExclusion> exclusions, {
    int version = 2,
  }) async {
    if (source.fragments.length > maxFragments) {
      throw SegmentLimitExceededException(
        limit: maxFragments,
        actual: source.fragments.length,
      );
    }
    final sources = <RandomAccessByteSource>[
      source.initializationSegment,
      ...source.fragments,
    ];
    final segments = <FragmentedIsoBmffSegment>[];
    var logicalOffset = 0;
    int? previousSequence;
    for (var index = 0; index < sources.length; index++) {
      final current = sources[index];
      final parsed = await _parse(current);
      if (index == 0) {
        if (parsed.boxes.isEmpty || parsed.boxes.first.box.type != 'ftyp') {
          throw const MalformedAssetFormatException(
            'A fragmented BMFF initialization segment must begin with ftyp.',
          );
        }
      }
      int? sequenceNumber;
      if (index > 0) {
        sequenceNumber = await _fragmentSequence(current, parsed.boxes);
        if (previousSequence != null && sequenceNumber <= previousSequence) {
          throw const MalformedAssetFormatException(
            'BMFF fragments are not ordered by mfhd sequence number.',
          );
        }
        previousSequence = sequenceNumber;
      }
      if (_sumExceedsSupportedUint64(parsed.length, logicalOffset)) {
        throw const MalformedBmffHashLayoutException(
          'The fragmented BMFF logical length exceeds unsigned 64-bit.',
        );
      }
      final layout = await read(
        current,
        exclusions,
        version: version,
        logicalOffset: logicalOffset,
        segmentIndex: index,
      );
      final metadata = await _discoverMetadata(
        current,
        parsed.boxes,
        logicalOffset,
      );
      segments.add(
        FragmentedIsoBmffSegment(
          index: index,
          isInitialization: index == 0,
          logicalOffset: logicalOffset,
          length: parsed.length,
          sequenceNumber: sequenceNumber,
          hashLayout: layout,
          c2paMetadata: metadata,
        ),
      );
      logicalOffset += parsed.length;
      if (logicalOffset > maxTotalFragmentedSize) {
        throw AssetLimitExceededException(
          limit: maxTotalFragmentedSize,
          actual: logicalOffset,
        );
      }
    }
    return FragmentedIsoBmffLayout(
      logicalLength: logicalOffset,
      segments: segments,
    );
  }

  Future<_ParsedBmff> _parse(RandomAccessByteSource source) async {
    final length = await source.length;
    if (length > maxSourceSize) {
      throw AssetLimitExceededException(limit: maxSourceSize, actual: length);
    }
    if (length < 8) {
      throw TruncatedAssetException(expectedLength: 8, actualLength: length);
    }
    final state = _TreeState(maxBoxCount);
    final boxes = await _readRange(source, 0, length, '', 0, state);
    return _ParsedBmff(length, boxes);
  }

  Future<List<IsoBmffBoxNode>> _readRange(
    RandomAccessByteSource source,
    int start,
    int end,
    String parentPath,
    int depth,
    _TreeState state,
  ) async {
    if (depth > maxDepth) {
      throw SegmentLimitExceededException(limit: maxDepth, actual: depth);
    }
    final result = <IsoBmffBoxNode>[];
    var offset = start;
    while (offset < end) {
      if (end - offset < 8) {
        throw TruncatedAssetException(
          expectedLength: offset + 8,
          actualLength: end,
        );
      }
      final header = await source.read(ByteRange(offset, offset + 8));
      final size32 = readUint32Be(header, 0);
      final type = String.fromCharCodes(header.sublist(4, 8));
      var headerSize = 8;
      var extended = false;
      var extendsToEnd = false;
      late int size;
      if (size32 == 0) {
        size = end - offset;
        extendsToEnd = true;
      } else if (size32 == 1) {
        if (end - offset < 16) {
          throw TruncatedAssetException(
            expectedLength: offset + 16,
            actualLength: end,
          );
        }
        size = _uint64(await source.read(ByteRange(offset + 8, offset + 16)));
        headerSize = 16;
        extended = true;
      } else {
        size = size32;
      }
      if (size < headerSize || size > ByteRange.maxCoordinate - offset) {
        throw const MalformedAssetFormatException(
          'An ISO BMFF box has an invalid or overflowing size.',
        );
      }
      final boxEnd = offset + size;
      if (boxEnd > end) {
        throw TruncatedAssetException(
          expectedLength: boxEnd,
          actualLength: end,
        );
      }
      List<int>? userType;
      var contentOffset = offset + headerSize;
      if (type == 'uuid') {
        if (boxEnd - contentOffset < 16) {
          throw const MalformedAssetFormatException(
            'An ISO BMFF UUID box is missing its user type.',
          );
        }
        userType = await source.read(
          ByteRange(contentOffset, contentOffset + 16),
        );
        contentOffset += 16;
      }
      int? version;
      int? flags;
      final isC2pa =
          type == 'uuid' && _equal(userType, IsoBmffAssetHandler.c2paUuid);
      final isFullBox = _fullBoxTypes.contains(type) || isC2pa;
      var childStart = contentOffset;
      if (isFullBox) {
        var hasFullHeader = true;
        if (type == 'meta' && boxEnd - contentOffset >= 8) {
          final peek = await source.read(
            ByteRange(contentOffset, contentOffset + 8),
          );
          hasFullHeader = String.fromCharCodes(peek.sublist(4, 8)) != 'hdlr';
        }
        if (hasFullHeader) {
          if (boxEnd - contentOffset < 4) {
            throw const MalformedAssetFormatException(
              'An ISO BMFF FullBox is missing version and flags.',
            );
          }
          final full = await source.read(
            ByteRange(contentOffset, contentOffset + 4),
          );
          version = full[0];
          flags = (full[1] << 16) | (full[2] << 8) | full[3];
          childStart += 4;
        }
      }
      state.add();
      final box = IsoBmffBox(
        type: type,
        offset: offset,
        size: size,
        headerSize: headerSize,
        usesExtendedSize: extended,
        extendsToEnd: extendsToEnd,
        userType: userType,
      );
      final path = '$parentPath/$type';
      final children = _containerTypes.contains(type) && childStart < boxEnd
          ? await _readRange(source, childStart, boxEnd, path, depth + 1, state)
          : const <IsoBmffBoxNode>[];
      result.add(
        IsoBmffBoxNode(
          box: box,
          path: path,
          version: version,
          flags: flags,
          children: children,
        ),
      );
      offset = boxEnd;
      if (extendsToEnd && offset != end) {
        throw const MalformedAssetFormatException(
          'A size-to-EOF ISO BMFF box must be last in its parent.',
        );
      }
    }
    return result;
  }

  Future<List<ByteRange>> _resolveExclusions(
    RandomAccessByteSource source,
    _ParsedBmff parsed,
    List<IsoBmffExclusion> rules,
  ) async {
    final byPath = <String, List<IsoBmffBoxNode>>{};
    for (final box in parsed.allBoxes) {
      byPath.putIfAbsent(box.path, () => <IsoBmffBoxNode>[]).add(box);
    }
    final ranges = <ByteRange>[];
    var matchCount = 0;
    for (final rule in rules) {
      _validateRule(rule);
      for (final node in byPath[rule.xpath] ?? const <IsoBmffBoxNode>[]) {
        if (rule.length != null && rule.length != node.box.size) continue;
        if (rule.version != null && rule.version != node.version) continue;
        if (rule.flags != null) {
          if (node.flags == null) continue;
          final desired =
              (rule.flags![0] << 16) | (rule.flags![1] << 8) | rule.flags![2];
          if (rule.exact
              ? desired != node.flags
              : (desired | node.flags!) != desired) {
            continue;
          }
        }
        var dataMatches = true;
        for (final match in rule.data) {
          if (match.offset > node.box.size ||
              match.value.length > node.box.size - match.offset) {
            throw const MalformedBmffHashLayoutException(
              'A BMFF data match extends outside its target box.',
            );
          }
          final bytes = await source.read(
            ByteRange(
              node.box.offset + match.offset,
              node.box.offset + match.offset + match.value.length,
            ),
          );
          if (!_equal(bytes, match.value)) {
            dataMatches = false;
            break;
          }
        }
        if (!dataMatches) continue;
        matchCount++;
        if (matchCount > maxMatches) {
          throw SegmentLimitExceededException(
            limit: maxMatches,
            actual: matchCount,
          );
        }
        if (rule.subset.isEmpty) {
          ranges.add(node.box.range);
        } else {
          for (final subset in rule.subset) {
            if (subset.offset > node.box.size) {
              throw const MalformedBmffHashLayoutException(
                'A BMFF subset starts outside its target box.',
              );
            }
            final available = node.box.size - subset.offset;
            final length = subset.length == 0
                ? available
                : subset.length < available
                ? subset.length
                : available;
            ranges.add(
              ByteRange(
                node.box.offset + subset.offset,
                node.box.offset + subset.offset + length,
              ),
            );
          }
        }
      }
    }
    ranges.sort((left, right) => left.start.compareTo(right.start));
    for (var i = 1; i < ranges.length; i++) {
      if (ranges[i].start < ranges[i - 1].end) {
        throw const MalformedBmffHashLayoutException(
          'Resolved BMFF exclusion ranges overlap.',
        );
      }
    }
    return ranges;
  }

  void _validateRule(IsoBmffExclusion rule) {
    if (!rule.xpath.startsWith('/') ||
        rule.xpath.length == 1 ||
        rule.xpath.endsWith('/') ||
        rule.xpath.contains('//')) {
      throw const MalformedBmffHashLayoutException(
        'A BMFF exclusion xpath must be an absolute box path.',
      );
    }
    if (rule.length != null && rule.length! < 0) {
      throw const MalformedBmffHashLayoutException(
        'A BMFF exclusion length cannot be negative.',
      );
    }
    if (rule.version != null && (rule.version! < 0 || rule.version! > 0xff)) {
      throw const MalformedBmffHashLayoutException(
        'A BMFF FullBox version must fit in one byte.',
      );
    }
    if (rule.flags != null && rule.flags!.length != 3) {
      throw const MalformedBmffHashLayoutException(
        'BMFF FullBox flags must contain exactly three bytes.',
      );
    }
    var previousEnd = BigInt.from(-1);
    for (var index = 0; index < rule.subset.length; index++) {
      final subset = rule.subset[index];
      if (subset.offset < 0 || subset.length < 0) {
        throw const MalformedBmffHashLayoutException(
          'A BMFF subset offset and length must be non-negative.',
        );
      }
      final offset = BigInt.from(subset.offset);
      final length = BigInt.from(subset.length);
      if (offset < previousEnd) {
        throw const MalformedBmffHashLayoutException(
          'BMFF subsets must be ordered and non-overlapping.',
        );
      }
      if (subset.length == 0 && index != rule.subset.length - 1) {
        throw const MalformedBmffHashLayoutException(
          'A through-end BMFF subset must be the final subset.',
        );
      }
      final end = subset.length == 0 ? _maxSupportedUint64 : offset + length;
      if (end > _maxSupportedUint64) {
        throw const MalformedBmffHashLayoutException(
          'A BMFF subset range exceeds the supported unsigned 64-bit range.',
        );
      }
      previousEnd = end;
    }
    for (final match in rule.data) {
      if (match.offset < 0) {
        throw const MalformedBmffHashLayoutException(
          'A BMFF data match offset cannot be negative.',
        );
      }
    }
  }

  List<IsoBmffDigestEvent> _buildEvents(
    int sourceLength,
    List<ByteRange> exclusions,
    List<int> markerOffsets, {
    required int logicalOffset,
    required int segmentIndex,
  }) {
    final included = <ByteRange>[];
    var cursor = 0;
    for (final exclusion in exclusions) {
      if (exclusion.start > cursor) {
        included.add(ByteRange(cursor, exclusion.start));
      }
      cursor = exclusion.end;
    }
    if (cursor < sourceLength) included.add(ByteRange(cursor, sourceLength));

    final events = <IsoBmffDigestEvent>[];
    for (final range in included) {
      var start = range.start;
      for (final marker in markerOffsets) {
        if (marker < start || marker >= range.end) continue;
        if (marker > start) {
          events.add(
            IsoBmffSourceDigestEvent(
              segmentIndex: segmentIndex,
              logicalOffset: logicalOffset + start,
              range: ByteRange(start, marker),
            ),
          );
        }
        events.add(
          IsoBmffOffsetDigestEvent(
            segmentIndex: segmentIndex,
            logicalOffset: logicalOffset + marker,
            boxOffset: marker,
            logicalBoxOffset: logicalOffset + marker,
          ),
        );
        start = marker;
      }
      if (start < range.end) {
        events.add(
          IsoBmffSourceDigestEvent(
            segmentIndex: segmentIndex,
            logicalOffset: logicalOffset + start,
            range: ByteRange(start, range.end),
          ),
        );
      }
    }
    for (final marker in markerOffsets) {
      if (events.any(
        (event) =>
            event is IsoBmffOffsetDigestEvent && event.boxOffset == marker,
      )) {
        continue;
      }
      events.add(
        IsoBmffOffsetDigestEvent(
          segmentIndex: segmentIndex,
          logicalOffset: logicalOffset + marker,
          boxOffset: marker,
          logicalBoxOffset: logicalOffset + marker,
        ),
      );
    }
    events.sort((left, right) {
      final compare = left.logicalOffset.compareTo(right.logicalOffset);
      if (compare != 0) return compare;
      if (left.kind == right.kind) return 0;
      return left.kind == IsoBmffDigestEventKind.offset ? -1 : 1;
    });
    return events;
  }

  Future<List<IsoBmffC2paMetadata>> _discoverMetadata(
    RandomAccessByteSource source,
    List<IsoBmffBoxNode> boxes,
    int logicalOffset,
  ) async {
    final result = <IsoBmffC2paMetadata>[];
    final purposeCounts = <String, int>{};
    for (final node in boxes) {
      if (node.box.type != 'uuid' ||
          !_equal(node.box.userType, IsoBmffAssetHandler.c2paUuid)) {
        continue;
      }
      if (node.version != 0 || node.flags != 0) {
        throw const MalformedAssetFormatException(
          'A C2PA BMFF UUID box has unsupported version or flags.',
        );
      }
      var cursor = node.box.payloadOffset + 20;
      final purposeBytes = <int>[];
      var terminated = false;
      while (cursor < node.box.end && purposeBytes.length <= 64) {
        final byte = (await source.read(ByteRange(cursor, cursor + 1))).single;
        cursor++;
        if (byte == 0) {
          terminated = true;
          break;
        }
        purposeBytes.add(byte);
      }
      if (!terminated || purposeBytes.length > 64) {
        throw const MalformedAssetFormatException(
          'A C2PA BMFF UUID purpose is unterminated.',
        );
      }
      final purpose = String.fromCharCodes(purposeBytes);
      int? auxiliaryOffset;
      if (purpose == 'manifest' ||
          purpose == 'original' ||
          purpose == 'update') {
        if (node.box.end - cursor < 8) {
          throw const MalformedAssetFormatException(
            'A C2PA BMFF manifest box lacks its auxiliary offset.',
          );
        }
        auxiliaryOffset = _uint64(
          await source.read(ByteRange(cursor, cursor + 8)),
        );
        cursor += 8;
      } else if (purpose != 'merkle') {
        continue;
      }
      purposeCounts[purpose] = (purposeCounts[purpose] ?? 0) + 1;
      if (purpose != 'merkle' && purposeCounts[purpose]! > 1) {
        throw MalformedAssetFormatException(
          'A BMFF segment contains duplicate C2PA "$purpose" boxes.',
        );
      }
      result.add(
        IsoBmffC2paMetadata(
          purpose: purpose,
          boxRange: node.box.range,
          dataRange: ByteRange(cursor, node.box.end),
          logicalBoxOffset: logicalOffset + node.box.offset,
          version: node.version!,
          flags: node.flags!,
          auxiliaryOffset: auxiliaryOffset,
        ),
      );
    }
    return result;
  }

  Future<int> _fragmentSequence(
    RandomAccessByteSource source,
    List<IsoBmffBoxNode> boxes,
  ) async {
    final moofs = boxes.where((box) => box.box.type == 'moof').toList();
    if (moofs.length != 1) {
      throw const MalformedAssetFormatException(
        'Each BMFF media fragment must contain exactly one top-level moof box.',
      );
    }
    final headers = moofs.single.children
        .where((box) => box.box.type == 'mfhd')
        .toList();
    if (headers.length != 1 || headers.single.version == null) {
      throw const MalformedAssetFormatException(
        'Each BMFF media fragment must contain exactly one mfhd FullBox.',
      );
    }
    final header = headers.single;
    final sequenceOffset = header.box.payloadOffset + 4;
    if (header.box.end - sequenceOffset < 4) {
      throw const MalformedAssetFormatException(
        'A BMFF mfhd box is missing its sequence number.',
      );
    }
    return readUint32Be(
      await source.read(ByteRange(sequenceOffset, sequenceOffset + 4)),
      0,
    );
  }

  static const Set<String> _containerTypes = <String>{
    'moov',
    'trak',
    'mdia',
    'minf',
    'stbl',
    'moof',
    'traf',
    'edts',
    'udta',
    'dinf',
    'tref',
    'treg',
    'mvex',
    'mfra',
    'meta',
    'schi',
  };

  static const Set<String> _fullBoxTypes = <String>{
    'pdin',
    'mvhd',
    'tkhd',
    'mdhd',
    'hdlr',
    'nmhd',
    'elng',
    'stsd',
    'stdp',
    'stts',
    'ctts',
    'cslg',
    'stss',
    'stsh',
    'elst',
    'dref',
    'stsz',
    'stz2',
    'stsc',
    'stco',
    'co64',
    'padb',
    'subs',
    'saiz',
    'saio',
    'mehd',
    'trex',
    'mfhd',
    'tfhd',
    'trun',
    'tfra',
    'mfro',
    'tfdt',
    'leva',
    'trep',
    'assp',
    'sbgp',
    'sgpd',
    'csgp',
    'cprt',
    'tsel',
    'kind',
    'meta',
    'xml ',
    'bxml',
    'iloc',
    'pitm',
    'ipro',
    'infe',
    'iinf',
    'iref',
    'ipma',
    'schm',
    'fiin',
    'fpar',
    'fecr',
    'gitn',
    'fire',
    'stri',
    'stsg',
    'stvi',
    'csch',
    'sidx',
    'ssix',
    'prft',
    'srpp',
    'vmhd',
    'smhd',
    'srat',
    'chnl',
    'dmix',
    'txtC',
    'mime',
    'uri ',
    'uriI',
    'hmhd',
    'sthd',
    'vvhd',
    'medc',
  };
}

final class _ParsedBmff {
  const _ParsedBmff(this.length, this.boxes);

  final int length;
  final List<IsoBmffBoxNode> boxes;

  Iterable<IsoBmffBoxNode> get allBoxes sync* {
    for (final box in boxes) {
      yield box;
      yield* box.descendants;
    }
  }
}

final class _TreeState {
  _TreeState(this.limit);

  final int limit;
  int count = 0;

  void add() {
    count++;
    if (count > limit) {
      throw SegmentLimitExceededException(limit: limit, actual: count);
    }
  }
}

final BigInt _maxSupportedUint64 = BigInt.parse('9223372036854775807');

bool _sumExceedsSupportedUint64(int left, int right) =>
    BigInt.from(left) + BigInt.from(right) > _maxSupportedUint64;

Uint8List _uint64Bytes(int value) {
  var remaining = BigInt.from(value);
  if (remaining < BigInt.zero || remaining > _maxSupportedUint64) {
    throw const MalformedBmffHashLayoutException(
      'A BMFF offset is outside the unsigned 64-bit range.',
    );
  }
  final bytes = Uint8List(8);
  for (var index = 7; index >= 0; index--) {
    bytes[index] = (remaining & BigInt.from(0xff)).toInt();
    remaining >>= 8;
  }
  return bytes;
}

int _uint64(Uint8List bytes) =>
    tryReadUint64Be(bytes, 0) ??
    (throw const MalformedAssetFormatException(
      'An ISO BMFF 64-bit value exceeds the supported address range.',
    ));

bool _equal(List<int>? left, List<int> right) {
  if (left == null || left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) return false;
  }
  return true;
}

bool _fullyExcluded(ByteRange box, List<ByteRange> exclusions) {
  var cursor = box.start;
  for (final range in exclusions) {
    if (range.end <= cursor) continue;
    if (range.start > cursor || range.start >= box.end) return false;
    if (range.end > cursor) cursor = range.end;
    if (cursor >= box.end) return true;
  }
  return false;
}
