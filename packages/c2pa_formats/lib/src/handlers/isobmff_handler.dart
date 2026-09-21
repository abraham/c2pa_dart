import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../byte_reader.dart';
import '../errors.dart';
import '../hash_layout.dart';
import '../isobmff.dart';
import '../isobmff_hash_layout.dart';
import '../manifest_mutation.dart';
import '../xmp.dart';
import '../xmp_remote_reference.dart';

/// An ISO BMFF handler for C2PA `uuid` boxes.
///
/// Handles MP4, QuickTime, M4A, AVIF, HEIF, and HEIC assets. The C2PA
/// manifest is stored in a top-level `uuid` box with [c2paUuid]; XMP is stored
/// in a `uuid` box with [xmpUuid].
final class IsoBmffAssetHandler
    with ManifestRewrite
    implements
        AssetHandler,
        DataHashLayoutProvider,
        IsoBmffBoxProvider,
        IsoBmffHashLayoutProvider,
        XmpMetadataProvider,
        RemoteManifestReferenceProvider {
  /// Creates a handler for one supported ISO BMFF [format].
  const IsoBmffAssetHandler({
    required this.format,
    this.maxManifestSize = 64 * 1024 * 1024,
    this.maxSourceSize = 512 * 1024 * 1024,
    this.maxOutputSize = 576 * 1024 * 1024,
    this.maxBoxCount = 1024 * 1024,
    this.maxDepth = 32,
    this.copyChunkSize = 64 * 1024,
    this.maxXmpSize = 4 * 1024 * 1024,
    this.maxRemoteReferenceLength = 64 * 1024,
  }) : assert(
         format == AssetFormat.mp4 ||
             format == AssetFormat.mov ||
             format == AssetFormat.m4a ||
             format == AssetFormat.avif ||
             format == AssetFormat.heif ||
             format == AssetFormat.heic,
       ),
       assert(maxManifestSize > 0),
       assert(maxSourceSize > 0),
       assert(maxOutputSize > 0),
       assert(maxBoxCount > 0),
       assert(maxDepth > 0),
       assert(copyChunkSize > 0),
       assert(maxXmpSize > 0),
       assert(maxRemoteReferenceLength > 0);

  /// UUID user type for top-level C2PA manifest boxes.
  static const List<int> c2paUuid = <int>[
    0xd8,
    0xfe,
    0xc3,
    0xd6,
    0x1b,
    0x0e,
    0x48,
    0x3c,
    0x92,
    0x97,
    0x58,
    0x28,
    0x87,
    0x7e,
    0xc4,
    0x81,
  ];

  /// UUID user type for top-level XMP metadata boxes.
  static const List<int> xmpUuid = <int>[
    0xbe,
    0x7a,
    0xcf,
    0xcb,
    0x97,
    0xa9,
    0x42,
    0xe8,
    0x9c,
    0x71,
    0x99,
    0x94,
    0x91,
    0xe3,
    0xaf,
    0xac,
  ];

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

  @override
  /// The specific ISO BMFF-derived format handled by this instance.
  final AssetFormat format;

  /// Maximum embedded C2PA manifest size in bytes.
  final int maxManifestSize;

  /// Maximum source asset size in bytes.
  final int maxSourceSize;

  /// Maximum rewritten asset size in bytes.
  final int maxOutputSize;

  /// Maximum number of boxes parsed from the asset.
  final int maxBoxCount;

  /// Maximum nested ISO BMFF container-box depth.
  final int maxDepth;

  /// Number of bytes copied per streaming write operation.
  final int copyChunkSize;

  /// Maximum XMP packet size in bytes.
  final int maxXmpSize;

  /// Maximum UTF-8 length of a remote reference in bytes.
  final int maxRemoteReferenceLength;

  @override
  String get name => switch (format) {
    AssetFormat.mp4 => 'MP4',
    AssetFormat.mov => 'QuickTime',
    AssetFormat.m4a => 'M4A',
    AssetFormat.avif => 'AVIF',
    AssetFormat.heif => 'HEIF',
    AssetFormat.heic => 'HEIC',
    _ => 'ISO BMFF',
  };

  @override
  AssetHandlerCapabilities get capabilities => AssetHandlerCapabilities(
    canDetect: true,
    canExtractManifest: true,
    canEmbedManifest: true,
    canReplaceManifest: true,
    canRemoveManifest: true,
    canProvideDataHashLayout: true,
    canProvideBmffHashLayout: true,
    canListTopLevelBoxes: true,
    canReadXmp: true,
    canEmbedRemoteReference: true,
    canReadRemoteReference: true,
    canRemoveRemoteReference: true,
    mimeTypes: switch (format) {
      AssetFormat.mp4 => const <String>['video/mp4', 'application/mp4'],
      AssetFormat.mov => const <String>['video/quicktime'],
      AssetFormat.m4a => const <String>['audio/mp4', 'audio/x-m4a'],
      AssetFormat.avif => const <String>['image/avif'],
      AssetFormat.heif => const <String>['image/heif'],
      AssetFormat.heic => const <String>['image/heic', 'image/heic-sequence'],
      _ => const <String>[],
    },
    fileExtensions: switch (format) {
      AssetFormat.mp4 => const <String>['mp4', 'm4v'],
      AssetFormat.mov => const <String>['mov', 'qt'],
      AssetFormat.m4a => const <String>['m4a', 'm4b', 'm4p'],
      AssetFormat.avif => const <String>['avif'],
      AssetFormat.heif => const <String>['heif', 'hif'],
      AssetFormat.heic => const <String>['heic'],
      _ => const <String>[],
    },
  );

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    try {
      return (await _inspect(source, requireFormat: false)).detectedFormat ==
          format;
    } on AssetFormatException {
      return false;
    }
  }

  @override
  Future<List<IsoBmffBox>> getTopLevelBoxes(
    RandomAccessByteSource source,
  ) async => (await _inspect(source)).boxes;

  @override
  Future<Uint8List> extractManifest(RandomAccessByteSource source) async {
    final inspection = await _inspect(source);
    final manifest = inspection.manifest;
    if (manifest == null) throw ManifestNotFoundException(format);
    return source.read(
      ByteRange.fromStartAndLength(
        manifest.manifestOffset,
        manifest.manifestLength,
      ),
    );
  }

  @override
  Future<DataHashLayout> getDataHashLayout(
    RandomAccessByteSource source,
  ) async {
    final inspection = await _inspect(source);
    final manifest = inspection.manifest;
    return DataHashLayout(
      sourceLength: inspection.sourceLength,
      insertionOffset: manifest?.box.offset ?? inspection.ftyp.end,
      exclusions: manifest == null
          ? const <DataHashExclusion>[]
          : <DataHashExclusion>[
              DataHashExclusion(
                range: manifest.box.range,
                kind: DataHashExclusionKind.manifest,
                name: 'uuid[c2pa]',
              ),
            ],
    );
  }

  @override
  Future<IsoBmffHashLayout> getBmffHashLayout(
    RandomAccessByteSource source,
    List<IsoBmffExclusion> exclusions, {
    int version = 2,
    int logicalOffset = 0,
    int segmentIndex = 0,
  }) =>
      IsoBmffHashLayoutReader(
        maxSourceSize: maxSourceSize,
        maxBoxCount: maxBoxCount,
        maxDepth: maxDepth,
      ).read(
        source,
        exclusions,
        version: version,
        logicalOffset: logicalOffset,
        segmentIndex: segmentIndex,
      );

  @override
  Future<FragmentedIsoBmffLayout> getFragmentedBmffLayout(
    FragmentedIsoBmffSource source,
    List<IsoBmffExclusion> exclusions, {
    int version = 2,
  }) => IsoBmffHashLayoutReader(
    maxSourceSize: maxSourceSize,
    maxBoxCount: maxBoxCount,
    maxDepth: maxDepth,
  ).readFragmented(source, exclusions, version: version);

  @override
  Future<String?> readXmp(RandomAccessByteSource source) async {
    final inspection = await _inspect(source);
    final xmp = inspection.xmp;
    if (xmp == null) return null;
    final bytes = await source.read(
      ByteRange.fromStartAndLength(xmp.dataOffset, xmp.dataLength),
    );
    try {
      return utf8.decode(bytes, allowMalformed: false);
    } on FormatException {
      throw const MalformedAssetFormatException(
        'ISO BMFF XMP metadata is not valid UTF-8.',
      );
    }
  }

  @override
  Future<String?> readRemoteManifestReference(
    RandomAccessByteSource source,
  ) async {
    final inspection = await _inspect(source);
    final xmp = inspection.xmp;
    if (xmp == null) return null;
    final bytes = await source.read(
      ByteRange.fromStartAndLength(xmp.dataOffset, xmp.dataLength),
    );
    return XmpRemoteReferenceEditor.parse(bytes, maxLength: maxXmpSize).value;
  }

  @override
  Future<void> embedRemoteReference(
    RandomAccessByteSource source,
    String reference,
    WritableByteSink output,
  ) => updateRemoteManifestReference(source, reference, output);

  @override
  Future<void> updateRemoteManifestReference(
    RandomAccessByteSource source,
    String reference,
    WritableByteSink output,
  ) async {
    final referenceLength = utf8.encode(reference).length;
    if (referenceLength > maxRemoteReferenceLength) {
      throw AssetLimitExceededException(
        limit: maxRemoteReferenceLength,
        actual: referenceLength,
      );
    }
    final inspection = await _inspect(source);
    final existing = inspection.xmp;
    final original = existing == null
        ? Uint8List.fromList(
            utf8.encode(XmpRemoteReferenceEditor.minimalPacket),
          )
        : await source.read(
            ByteRange.fromStartAndLength(
              existing.dataOffset,
              existing.dataLength,
            ),
          );
    final updated = XmpRemoteReferenceEditor.parse(
      original,
      maxLength: maxXmpSize,
    ).update(reference, maxLength: maxXmpSize);
    await _rewriteXmp(source, output, inspection, existing, updated);
  }

  @override
  Future<void> removeRemoteManifestReference(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) async {
    final inspection = await _inspect(source);
    final existing = inspection.xmp;
    if (existing == null) {
      throw RemoteManifestReferenceNotFoundException(format);
    }
    final bytes = await source.read(
      ByteRange.fromStartAndLength(existing.dataOffset, existing.dataLength),
    );
    final editor = XmpRemoteReferenceEditor.parse(bytes, maxLength: maxXmpSize);
    if (editor.value == null) {
      throw RemoteManifestReferenceNotFoundException(format);
    }
    await _rewriteXmp(
      source,
      output,
      inspection,
      existing,
      editor.remove(maxLength: maxXmpSize),
    );
  }

  Future<void> _rewriteXmp(
    RandomAccessByteSource source,
    WritableByteSink output,
    _IsoBmffInspection inspection,
    _XmpBox? existing,
    Uint8List xmp,
  ) async {
    if (await output.length != 0) {
      throw const MalformedAssetFormatException(
        'The destination sink must be empty.',
      );
    }
    if (inspection.fragmented) {
      throw const UnsupportedIsoBmffFeatureException('fragmented streams');
    }
    if (xmp.length > maxXmpSize) {
      throw AssetLimitExceededException(limit: maxXmpSize, actual: xmp.length);
    }
    final encoded = _encodeUuidBox(xmpUuid, xmp);
    final removedLength = existing?.box.size ?? 0;
    final outputLength =
        inspection.sourceLength - removedLength + encoded.length;
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }
    final staged = MemoryByteSink();
    if (existing == null) {
      await _copy(source, staged, 0, inspection.ftyp.end);
      await staged.append(encoded);
      await _copy(source, staged, inspection.ftyp.end, inspection.sourceLength);
    } else {
      await _copy(source, staged, 0, existing.box.offset);
      await staged.append(encoded);
      await _copy(source, staged, existing.box.end, inspection.sourceLength);
    }
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'ISO BMFF XMP rewrite produced an unexpected output length.',
      );
    }
    await _adjustKnownOffsets(staged, encoded.length - removedLength);
    await output.append(staged.toBytes());
  }

  Future<void> _adjustKnownOffsets(
    MemoryByteSink staged,
    int adjustment,
  ) async {
    if (adjustment == 0) return;
    final source = MemoryByteSource(staged.toBytes());
    final layout = await IsoBmffHashLayoutReader(
      maxSourceSize: maxOutputSize,
      maxBoxCount: maxBoxCount,
      maxDepth: maxDepth,
    ).read(source, const <IsoBmffExclusion>[]);
    final nodes = <IsoBmffBoxNode>[
      for (final root in layout.boxes) root,
      for (final root in layout.boxes) ...root.descendants,
    ];
    for (final node in nodes) {
      if (node.box.type == 'stco' || node.box.type == 'co64') {
        await _adjustChunkOffsets(staged, node, adjustment);
      } else if (node.box.type == 'iloc') {
        await _adjustItemLocations(staged, node, adjustment);
      }
    }
  }

  Future<void> _adjustChunkOffsets(
    MemoryByteSink staged,
    IsoBmffBoxNode node,
    int adjustment,
  ) async {
    final width = node.box.type == 'stco' ? 4 : 8;
    final start = node.box.payloadOffset + 4;
    if (start + 4 > node.box.end) {
      throw const MalformedAssetFormatException(
        'A BMFF chunk-offset box is truncated.',
      );
    }
    final bytes = staged.toBytes();
    final count = readUint32Be(bytes, start);
    if (count > (node.box.end - start - 4) ~/ width ||
        start + 4 + count * width != node.box.end) {
      throw const MalformedAssetFormatException(
        'A BMFF chunk-offset table is malformed.',
      );
    }
    for (var index = 0; index < count; index++) {
      final offset = start + 4 + index * width;
      final value = _readSizedBigUint(bytes, offset, width);
      await staged.writeAt(
        offset,
        _adjustedSizedUintBytes(value, adjustment, width),
      );
    }
  }

  Future<void> _adjustItemLocations(
    MemoryByteSink staged,
    IsoBmffBoxNode node,
    int adjustment,
  ) async {
    final bytes = staged.toBytes();
    var cursor = node.box.payloadOffset;
    if (cursor + 6 > node.box.end) {
      throw const MalformedAssetFormatException(
        'A BMFF iloc box is truncated.',
      );
    }
    final version = bytes[cursor];
    cursor += 4;
    final offsetSize = bytes[cursor] >> 4;
    final lengthSize = bytes[cursor] & 0x0f;
    cursor++;
    final baseOffsetSize = bytes[cursor] >> 4;
    final indexSize = version == 1 || version == 2 ? bytes[cursor] & 0x0f : 0;
    cursor++;
    for (final size in [offsetSize, lengthSize, baseOffsetSize, indexSize]) {
      if (size != 0 && size != 4 && size != 8) {
        throw const UnsupportedIsoBmffFeatureException(
          'iloc fields other than 0, 4, or 8 bytes',
        );
      }
    }
    if (version > 2) {
      throw const UnsupportedIsoBmffFeatureException('iloc version above 2');
    }
    final countWidth = version < 2 ? 2 : 4;
    _requireBoxBytes(cursor, countWidth, node.box.end);
    final itemCount = _readSizedUint(bytes, cursor, countWidth);
    cursor += countWidth;
    for (var item = 0; item < itemCount; item++) {
      final idWidth = version < 2 ? 2 : 4;
      _requireBoxBytes(cursor, idWidth, node.box.end);
      cursor += idWidth;
      var constructionMethod = 0;
      if (version == 1 || version == 2) {
        _requireBoxBytes(cursor, 2, node.box.end);
        constructionMethod = _readSizedUint(bytes, cursor, 2) & 0x0f;
        cursor += 2;
      }
      _requireBoxBytes(cursor, 2 + baseOffsetSize + 2, node.box.end);
      cursor += 2;
      final basePosition = cursor;
      final baseOffset = _readSizedBigUint(bytes, cursor, baseOffsetSize);
      cursor += baseOffsetSize;
      if (constructionMethod == 0 && baseOffsetSize != 0) {
        await staged.writeAt(
          basePosition,
          _adjustedSizedUintBytes(baseOffset, adjustment, baseOffsetSize),
        );
      }
      final extentCount = _readSizedUint(bytes, cursor, 2);
      cursor += 2;
      for (var extent = 0; extent < extentCount; extent++) {
        _requireBoxBytes(
          cursor,
          indexSize + offsetSize + lengthSize,
          node.box.end,
        );
        cursor += indexSize;
        final extentPosition = cursor;
        final extentOffset = _readSizedBigUint(bytes, cursor, offsetSize);
        cursor += offsetSize + lengthSize;
        if (constructionMethod == 0 &&
            baseOffset == BigInt.zero &&
            extentOffset != BigInt.zero &&
            offsetSize != 0) {
          await staged.writeAt(
            extentPosition,
            _adjustedSizedUintBytes(extentOffset, adjustment, offsetSize),
          );
        }
      }
    }
    if (cursor != node.box.end) {
      throw const MalformedAssetFormatException(
        'A BMFF iloc box contains trailing or missing fields.',
      );
    }
  }

  static Uint8List _adjustedSizedUintBytes(
    BigInt value,
    int adjustment,
    int width,
  ) {
    var adjusted = value + BigInt.from(adjustment);
    final maximum = width == 4
        ? BigInt.from(0xffffffff)
        : BigInt.parse('9223372036854775807');
    if (adjusted < BigInt.zero || adjusted > maximum) {
      throw const MalformedAssetFormatException(
        'A BMFF absolute offset overflows during XMP rewrite.',
      );
    }
    final bytes = Uint8List(width);
    for (var index = width - 1; index >= 0; index--) {
      bytes[index] = (adjusted & BigInt.from(0xff)).toInt();
      adjusted >>= 8;
    }
    return bytes;
  }

  static int _readSizedUint(List<int> bytes, int offset, int width) {
    if (width == 0) return 0;
    final data = ByteData.sublistView(
      bytes is Uint8List ? bytes : Uint8List.fromList(bytes),
    );
    if (width == 2) return data.getUint16(offset, Endian.big);
    if (width == 4) return data.getUint32(offset, Endian.big);
    throw const UnsupportedIsoBmffFeatureException(
      'integer fields other than 0, 2, or 4 bytes',
    );
  }

  static BigInt _readSizedBigUint(List<int> bytes, int offset, int width) {
    var value = BigInt.zero;
    for (var index = 0; index < width; index++) {
      value = (value << 8) | BigInt.from(bytes[offset + index]);
    }
    return value;
  }

  static void _requireBoxBytes(int offset, int length, int end) {
    if (offset < 0 || length < 0 || offset > end - length) {
      throw const MalformedAssetFormatException(
        'A BMFF offset table exceeds its box bounds.',
      );
    }
  }

  @override
  Future<void> rewriteManifest(
    RandomAccessByteSource source,
    WritableByteSink output, {
    required ManifestMutation operation,
    Uint8List? manifest,
  }) async {
    if (await output.length != 0) {
      throw const MalformedAssetFormatException(
        'The destination sink must be empty.',
      );
    }
    if (manifest != null && manifest.length > maxManifestSize) {
      throw AssetLimitExceededException(
        limit: maxManifestSize,
        actual: manifest.length,
      );
    }

    final inspection = await _inspect(source);
    if (inspection.fragmented) {
      throw const UnsupportedIsoBmffFeatureException('fragmented streams');
    }
    final existing = inspection.manifest;
    if (operation == ManifestMutation.embed && existing != null) {
      throw ManifestAlreadyExistsException(format);
    }
    if (operation != ManifestMutation.embed && existing == null) {
      throw ManifestNotFoundException(format);
    }

    final encoded = manifest == null ? null : _encodeManifestBox(manifest);
    final removedLength = existing?.box.size ?? 0;
    final insertedLength = encoded?.length ?? 0;
    final outputLength =
        inspection.sourceLength - removedLength + insertedLength;
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }

    final staged = MemoryByteSink();
    if (existing == null) {
      await _copy(source, staged, 0, inspection.ftyp.end);
      await staged.append(encoded!);
      await _copy(source, staged, inspection.ftyp.end, inspection.sourceLength);
    } else {
      await _copy(source, staged, 0, existing.box.offset);
      if (encoded != null) await staged.append(encoded);
      await _copy(source, staged, existing.box.end, inspection.sourceLength);
    }
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'ISO BMFF rewrite produced an unexpected output length.',
      );
    }
    await output.append(staged.toBytes());
  }

  Future<_IsoBmffInspection> _inspect(
    RandomAccessByteSource source, {
    bool requireFormat = true,
  }) async {
    final sourceLength = await source.length;
    if (sourceLength > maxSourceSize) {
      throw AssetLimitExceededException(
        limit: maxSourceSize,
        actual: sourceLength,
      );
    }
    if (sourceLength < 16) {
      throw TruncatedAssetException(
        expectedLength: 16,
        actualLength: sourceLength,
      );
    }

    final state = _ScanState(maxBoxCount);
    final boxes = await _scanRange(
      source,
      0,
      sourceLength,
      state,
      topLevel: true,
      depth: 0,
    );
    if (boxes.isEmpty || boxes.first.type != 'ftyp') {
      throw const MalformedAssetFormatException(
        'ISO BMFF must begin with an ftyp box.',
      );
    }
    if (boxes.where((box) => box.type == 'ftyp').length != 1) {
      throw const MalformedAssetFormatException(
        'ISO BMFF must contain exactly one top-level ftyp box.',
      );
    }
    final ftyp = boxes.first;
    final detectedFormat = await _readFormat(source, ftyp);
    if (requireFormat && detectedFormat != format) {
      throw MalformedAssetFormatException(
        'ISO BMFF brands identify ${detectedFormat.name}, not ${format.name}.',
      );
    }

    _ManifestBox? manifest;
    _XmpBox? xmp;
    for (final box in boxes.where((box) => box.type == 'uuid')) {
      if (_equal(box.userType, c2paUuid)) {
        final parsed = await _readManifestBox(source, box);
        if (manifest != null) {
          throw const MalformedAssetFormatException(
            'ISO BMFF contains duplicate C2PA UUID boxes.',
          );
        }
        manifest = parsed;
      } else if (_equal(box.userType, xmpUuid)) {
        if (xmp != null) {
          throw const MalformedAssetFormatException(
            'ISO BMFF contains duplicate XMP UUID boxes.',
          );
        }
        final dataLength = box.size - box.headerSize - 16;
        if (dataLength > maxXmpSize) {
          throw AssetLimitExceededException(
            limit: maxXmpSize,
            actual: dataLength,
          );
        }
        xmp = _XmpBox(box, box.offset + box.headerSize + 16, dataLength);
      }
    }
    return _IsoBmffInspection(
      sourceLength: sourceLength,
      ftyp: ftyp,
      boxes: List<IsoBmffBox>.unmodifiable(boxes),
      detectedFormat: detectedFormat,
      manifest: manifest,
      xmp: xmp,
      fragmented: state.fragmented,
    );
  }

  Future<List<IsoBmffBox>> _scanRange(
    RandomAccessByteSource source,
    int start,
    int end,
    _ScanState state, {
    required bool topLevel,
    required int depth,
  }) async {
    if (depth > maxDepth) {
      throw SegmentLimitExceededException(limit: maxDepth, actual: depth);
    }
    final boxes = <IsoBmffBox>[];
    var offset = start;
    while (offset < end) {
      final remaining = end - offset;
      if (remaining < 8) {
        throw TruncatedAssetException(
          expectedLength: offset + 8,
          actualLength: end,
        );
      }
      final basic = await source.read(ByteRange(offset, offset + 8));
      final size32 = readUint32Be(basic, 0);
      final type = String.fromCharCodes(basic.sublist(4, 8));
      var headerSize = 8;
      var extended = false;
      var toEnd = false;
      late int size;
      if (size32 == 0) {
        size = remaining;
        toEnd = true;
      } else if (size32 == 1) {
        if (remaining < 16) {
          throw TruncatedAssetException(
            expectedLength: offset + 16,
            actualLength: end,
          );
        }
        final large = await source.read(ByteRange(offset + 8, offset + 16));
        size = _uint64(large);
        headerSize = 16;
        extended = true;
      } else {
        size = size32;
      }
      if (size < headerSize) {
        throw const MalformedAssetFormatException(
          'ISO BMFF box size is smaller than its header.',
        );
      }
      if (size > ByteRange.maxCoordinate - offset) {
        throw const MalformedAssetFormatException(
          'ISO BMFF box size overflows the supported address range.',
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
      if (type == 'uuid') {
        if (size < headerSize + 16) {
          throw const MalformedAssetFormatException(
            'ISO BMFF UUID box is too small for its user type.',
          );
        }
        userType = await source.read(
          ByteRange(offset + headerSize, offset + headerSize + 16),
        );
        if (!topLevel && _equal(userType, c2paUuid)) {
          throw const MalformedAssetFormatException(
            'A C2PA UUID box must be a top-level ISO BMFF box.',
          );
        }
        if (!topLevel && _equal(userType, xmpUuid)) {
          throw const UnsupportedIsoBmffFeatureException(
            'nested XMP UUID boxes',
          );
        }
      }
      state.addBox();
      if (type == 'moof' || type == 'mvex') state.fragmented = true;
      final box = IsoBmffBox(
        type: type,
        offset: offset,
        size: size,
        headerSize: headerSize,
        usesExtendedSize: extended,
        extendsToEnd: toEnd,
        userType: userType,
      );
      boxes.add(box);

      if (_containerTypes.contains(type)) {
        var childStart = box.payloadOffset;
        if (type == 'meta') {
          final payloadLength = box.end - childStart;
          if (payloadLength < 4) {
            throw const MalformedAssetFormatException(
              'ISO BMFF meta box is missing its FullBox header.',
            );
          }
          if (payloadLength < 8 ||
              String.fromCharCodes(
                    await source.read(
                      ByteRange(childStart + 4, childStart + 8),
                    ),
                  ) !=
                  'hdlr') {
            childStart += 4;
          }
        }
        if (childStart < box.end) {
          await _scanRange(
            source,
            childStart,
            box.end,
            state,
            topLevel: false,
            depth: depth + 1,
          );
        }
      }
      offset = boxEnd;
      if (toEnd && offset != end) {
        throw const MalformedAssetFormatException(
          'A size-to-EOF ISO BMFF box must be last.',
        );
      }
    }
    return boxes;
  }

  Future<AssetFormat> _readFormat(
    RandomAccessByteSource source,
    IsoBmffBox ftyp,
  ) async {
    if (ftyp.payloadLength < 8 || (ftyp.payloadLength - 8) % 4 != 0) {
      throw const MalformedAssetFormatException(
        'The ISO BMFF ftyp payload is malformed.',
      );
    }
    final payload = await source.read(ByteRange(ftyp.payloadOffset, ftyp.end));
    final brands = <String>{String.fromCharCodes(payload.sublist(0, 4))};
    for (var offset = 8; offset < payload.length; offset += 4) {
      brands.add(String.fromCharCodes(payload.sublist(offset, offset + 4)));
    }
    if (brands.any(_isAvifBrand)) return AssetFormat.avif;
    if (brands.any(_isHeicBrand)) return AssetFormat.heic;
    if (brands.any(_isHeifBrand)) return AssetFormat.heif;
    if (brands.contains('qt  ')) return AssetFormat.mov;
    if (brands.any(_isM4aBrand)) return AssetFormat.m4a;
    if (brands.any(_isMp4Brand)) return AssetFormat.mp4;
    throw const MalformedAssetFormatException(
      'The ISO BMFF ftyp box has no supported brand.',
    );
  }

  Future<_ManifestBox> _readManifestBox(
    RandomAccessByteSource source,
    IsoBmffBox box,
  ) async {
    final dataOffset = box.payloadOffset + 16;
    if (box.end - dataOffset < 13) {
      throw const MalformedAssetFormatException(
        'The C2PA UUID box is too small.',
      );
    }
    final fixed = await source.read(ByteRange(dataOffset, dataOffset + 4));
    if (fixed.any((byte) => byte != 0)) {
      throw const MalformedAssetFormatException(
        'The C2PA UUID FullBox version and flags are unsupported.',
      );
    }
    var cursor = dataOffset + 4;
    final purposeBytes = <int>[];
    while (cursor < box.end && purposeBytes.length <= 64) {
      final byte = (await source.read(ByteRange(cursor, cursor + 1))).single;
      cursor++;
      if (byte == 0) break;
      purposeBytes.add(byte);
    }
    if (cursor > box.end ||
        purposeBytes.length > 64 ||
        cursor == box.end && purposeBytes.isNotEmpty) {
      throw const MalformedAssetFormatException(
        'The C2PA UUID purpose is missing its terminator.',
      );
    }
    final purpose = String.fromCharCodes(purposeBytes);
    if (purpose != 'manifest') {
      throw MalformedAssetFormatException(
        'Unsupported C2PA UUID purpose "$purpose".',
      );
    }
    if (box.end - cursor < 8) {
      throw const MalformedAssetFormatException(
        'The C2PA UUID box is missing its auxiliary offset.',
      );
    }
    final merkleOffset = await source.read(ByteRange(cursor, cursor + 8));
    if (merkleOffset.any((byte) => byte != 0)) {
      throw const MalformedAssetFormatException(
        'C2PA BMFF auxiliary and Merkle boxes are not supported.',
      );
    }
    cursor += 8;
    final manifestLength = box.end - cursor;
    if (manifestLength > maxManifestSize) {
      throw AssetLimitExceededException(
        limit: maxManifestSize,
        actual: manifestLength,
      );
    }
    return _ManifestBox(
      box: box,
      manifestOffset: cursor,
      manifestLength: manifestLength,
    );
  }

  Uint8List _encodeManifestBox(Uint8List manifest) {
    const purpose = <int>[0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0];
    final size = 8 + 16 + 4 + purpose.length + 8 + manifest.length;
    if (size > 0xffffffff) {
      throw AssetLimitExceededException(limit: 0xffffffff, actual: size);
    }
    final bytes = Uint8List(size);
    final data = ByteData.sublistView(bytes);
    data.setUint32(0, size, Endian.big);
    bytes.setRange(4, 8, 'uuid'.codeUnits);
    bytes.setRange(8, 24, c2paUuid);
    bytes.setRange(28, 28 + purpose.length, purpose);
    bytes.setRange(45, size, manifest);
    return bytes;
  }

  static Uint8List _encodeUuidBox(List<int> uuid, Uint8List payload) {
    final size = 8 + 16 + payload.length;
    if (size > 0xffffffff) {
      throw AssetLimitExceededException(limit: 0xffffffff, actual: size);
    }
    final bytes = Uint8List(size);
    ByteData.sublistView(bytes).setUint32(0, size, Endian.big);
    bytes.setRange(4, 8, 'uuid'.codeUnits);
    bytes.setRange(8, 24, uuid);
    bytes.setRange(24, size, payload);
    return bytes;
  }

  Future<void> _copy(
    RandomAccessByteSource source,
    WritableByteSink output,
    int start,
    int end,
  ) async {
    var offset = start;
    while (offset < end) {
      final next =
          offset +
          (end - offset > copyChunkSize ? copyChunkSize : end - offset);
      await output.append(await source.read(ByteRange(offset, next)));
      offset = next;
    }
  }

  static int _uint64(Uint8List bytes) =>
      tryReadUint64Be(bytes, 0) ??
      (throw const MalformedAssetFormatException(
        'ISO BMFF 64-bit size exceeds the supported address range.',
      ));

  static bool _equal(List<int>? left, List<int> right) {
    if (left == null || left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }

  static bool _isAvifBrand(String brand) => brand == 'avif' || brand == 'avis';

  static bool _isHeicBrand(String brand) => const <String>{
    'heic',
    'heix',
    'hevc',
    'hevx',
    'heim',
    'heis',
    'hevm',
    'hevs',
  }.contains(brand);

  static bool _isHeifBrand(String brand) =>
      brand == 'mif1' || brand == 'msf1' || brand == 'heif';

  static bool _isM4aBrand(String brand) =>
      brand == 'M4A ' || brand == 'M4B ' || brand == 'M4P ';

  static bool _isMp4Brand(String brand) =>
      brand == 'isom' ||
      brand == 'avc1' ||
      brand == 'dash' ||
      brand == 'MSNV' ||
      brand == 'M4V ' ||
      brand == 'mp41' ||
      brand == 'mp42' ||
      brand == 'cmfc' ||
      brand == 'cmfs' ||
      brand.startsWith('iso') ||
      brand.startsWith('3g');
}

final class _ScanState {
  _ScanState(this.limit);

  final int limit;
  int count = 0;
  bool fragmented = false;

  void addBox() {
    count++;
    if (count > limit) {
      throw SegmentLimitExceededException(limit: limit, actual: count);
    }
  }
}

final class _ManifestBox {
  const _ManifestBox({
    required this.box,
    required this.manifestOffset,
    required this.manifestLength,
  });

  final IsoBmffBox box;
  final int manifestOffset;
  final int manifestLength;
}

final class _XmpBox {
  const _XmpBox(this.box, this.dataOffset, this.dataLength);

  final IsoBmffBox box;
  final int dataOffset;
  final int dataLength;
}

final class _IsoBmffInspection {
  const _IsoBmffInspection({
    required this.sourceLength,
    required this.ftyp,
    required this.boxes,
    required this.detectedFormat,
    required this.manifest,
    required this.xmp,
    required this.fragmented,
  });

  final int sourceLength;
  final IsoBmffBox ftyp;
  final List<IsoBmffBox> boxes;
  final AssetFormat detectedFormat;
  final _ManifestBox? manifest;
  final _XmpBox? xmp;
  final bool fragmented;
}
