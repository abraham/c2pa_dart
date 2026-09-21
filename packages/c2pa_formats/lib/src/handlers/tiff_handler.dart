import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../errors.dart';
import '../hash_layout.dart';
import '../manifest_mutation.dart';
import '../xmp.dart';
import '../xmp_remote_reference.dart';

/// A TIFF and DNG handler for C2PA IFD entries.
///
/// The manifest is stored in TIFF tag `0xCD41` as offset data. XMP is stored in
/// tag `0x02BC`; BigTIFF is rejected by this handler.
final class TiffAssetHandler
    with ManifestRewrite
    implements
        AssetHandler,
        DataHashLayoutProvider,
        BoxHashLayoutProvider,
        XmpMetadataProvider,
        RemoteManifestReferenceProvider {
  /// Creates a TIFF/DNG handler with IFD and byte limits.
  const TiffAssetHandler({
    this.maxManifestSize = 64 * 1024 * 1024,
    this.maxSourceSize = 256 * 1024 * 1024,
    this.maxOutputSize = 256 * 1024 * 1024,
    this.maxIfdCount = 2000,
    this.maxEntriesPerIfd = 4096,
    this.maxReferencedIfds = 1000,
    this.maxXmpSize = 4 * 1024 * 1024,
    this.maxRemoteReferenceLength = 64 * 1024,
  }) : assert(maxManifestSize > 0),
       assert(maxSourceSize > 0),
       assert(maxOutputSize > 0),
       assert(maxIfdCount > 0),
       assert(maxEntriesPerIfd > 0),
       assert(maxReferencedIfds > 0),
       assert(maxXmpSize > 0),
       assert(maxRemoteReferenceLength > 0);

  static const int _c2paTag = 0xcd41;
  static const int _undefinedType = 7;
  static const int _xmpTag = 0x02bc;
  static const int _byteType = 1;
  static const Set<int> _ifdReferenceTags = <int>{
    0x014a,
    0x8769,
    0x8825,
    40965,
  };
  static const int _maximumClassicOffset = 0xffffffff;

  /// Maximum embedded C2PA manifest size in bytes.
  final int maxManifestSize;

  /// Maximum source asset size in bytes.
  final int maxSourceSize;

  /// Maximum rewritten asset size in bytes.
  final int maxOutputSize;

  /// Maximum number of IFDs parsed from the asset.
  final int maxIfdCount;

  /// Maximum number of entries allowed in one IFD.
  final int maxEntriesPerIfd;

  /// Maximum number of referenced IFDs followed while scanning.
  final int maxReferencedIfds;

  /// Maximum XMP packet size in bytes.
  final int maxXmpSize;

  /// Maximum UTF-8 length of a remote reference in bytes.
  final int maxRemoteReferenceLength;

  @override
  String get name => 'TIFF/DNG';

  @override
  AssetFormat get format => AssetFormat.tiff;

  @override
  AssetHandlerCapabilities get capabilities => const AssetHandlerCapabilities(
    canDetect: true,
    canExtractManifest: true,
    canEmbedManifest: true,
    canReplaceManifest: true,
    canRemoveManifest: true,
    canProvideDataHashLayout: true,
    canReadXmp: true,
    canEmbedRemoteReference: true,
    canReadRemoteReference: true,
    canRemoveRemoteReference: true,
    mimeTypes: <String>['image/tiff', 'image/dng', 'image/x-adobe-dng'],
    fileExtensions: <String>['tif', 'tiff', 'dng'],
  );

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    if (await source.length < 4) return false;
    final header = await source.read(ByteRange(0, 4));
    final order = _byteOrder(header);
    if (order == null) return false;
    final magic = _readUint16(header, 2, order);
    return magic == 42 || magic == 43;
  }

  @override
  Future<Uint8List> extractManifest(RandomAccessByteSource source) async {
    final structure = await _inspect(source);
    final manifest = structure.manifestEntry;
    if (manifest == null) {
      throw const ManifestNotFoundException(AssetFormat.tiff);
    }

    return source.read(
      ByteRange.fromStartAndLength(manifest.valueOffset, manifest.count),
    );
  }

  @override
  Future<DataHashLayout> getDataHashLayout(
    RandomAccessByteSource source,
  ) async {
    final structure = await _inspect(source);
    final manifest = structure.manifestEntry;
    if (manifest == null) {
      return DataHashLayout(
        sourceLength: structure.sourceLength,
        insertionOffset: _align(structure.sourceLength, 4),
      );
    }
    final exclusions = <DataHashExclusion>[
      DataHashExclusion(
        range: ByteRange(manifest.entryOffset! + 4, manifest.entryOffset! + 8),
        kind: DataHashExclusionKind.mutableMetadata,
        name: 'C2PA tag count',
      ),
      DataHashExclusion(
        range: ByteRange.fromStartAndLength(
          manifest.valueOffset,
          manifest.count,
        ),
        kind: DataHashExclusionKind.manifest,
        name: 'C2PA tag value',
      ),
    ]..sort((left, right) => left.range.start.compareTo(right.range.start));
    return DataHashLayout(
      sourceLength: structure.sourceLength,
      insertionOffset: manifest.valueOffset,
      exclusions: exclusions,
    );
  }

  @override
  Future<BoxHashLayout> getBoxHashLayout(RandomAccessByteSource source) async {
    throw const UnsupportedHashLayoutException(
      AssetFormat.tiff,
      HashLayoutKind.boxHash,
    );
  }

  @override
  Future<String?> readXmp(RandomAccessByteSource source) async {
    final found = await _findXmp(source);
    if (found == null) return null;
    try {
      return utf8.decode(found.bytes, allowMalformed: false);
    } on FormatException {
      throw const MalformedAssetFormatException(
        'TIFF XMP metadata is not valid UTF-8.',
      );
    }
  }

  @override
  Future<String?> readRemoteManifestReference(
    RandomAccessByteSource source,
  ) async {
    final found = await _findXmp(source);
    if (found == null) return null;
    return XmpRemoteReferenceEditor.parse(
      found.bytes,
      maxLength: maxXmpSize,
    ).value;
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
    final found = await _findXmp(source);
    final original =
        found?.bytes ??
        Uint8List.fromList(utf8.encode(XmpRemoteReferenceEditor.minimalPacket));
    final updated = XmpRemoteReferenceEditor.parse(
      original,
      maxLength: maxXmpSize,
    ).update(reference, maxLength: maxXmpSize);
    await _rewriteXmp(source, output, updated);
  }

  @override
  Future<void> removeRemoteManifestReference(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) async {
    final found = await _findXmp(source);
    if (found == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.tiff);
    }
    final editor = XmpRemoteReferenceEditor.parse(
      found.bytes,
      maxLength: maxXmpSize,
    );
    if (editor.value == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.tiff);
    }
    await _rewriteXmp(source, output, editor.remove(maxLength: maxXmpSize));
  }

  Future<_TiffXmp?> _findXmp(RandomAccessByteSource source) async {
    final structure = await _inspect(source);
    _IfdEntry? found;
    for (final ifd in structure.allIfds) {
      final entry = ifd.entryFor(_xmpTag);
      if (entry == null) continue;
      if (found != null) {
        throw const MalformedAssetFormatException(
          'The TIFF contains more than one XMP tag.',
        );
      }
      if (entry.type != _byteType || entry.count <= 4) {
        throw const MalformedAssetFormatException(
          'The TIFF XMP tag must contain offset-stored BYTE data.',
        );
      }
      if (ifd != structure.pages.first) {
        throw const MalformedAssetFormatException(
          'The TIFF XMP tag must be in the first page IFD.',
        );
      }
      if (entry.count > maxXmpSize) {
        throw AssetLimitExceededException(
          limit: maxXmpSize,
          actual: entry.count,
        );
      }
      found = entry;
    }
    if (found == null) return null;
    return _TiffXmp(
      found,
      await source.read(
        ByteRange.fromStartAndLength(found.valueOffset, found.count),
      ),
    );
  }

  Future<void> _rewriteXmp(
    RandomAccessByteSource source,
    WritableByteSink output,
    Uint8List xmp,
  ) async {
    if (await output.length != 0) {
      throw const MalformedAssetFormatException(
        'The destination sink must be empty.',
      );
    }
    if (xmp.length > maxXmpSize) {
      throw AssetLimitExceededException(limit: maxXmpSize, actual: xmp.length);
    }
    final structure = await _inspect(source);
    await _findXmp(source);
    final first = structure.pages.first;
    final entryCount =
        first.entries.where((entry) => entry.tag != _xmpTag).length + 1;
    var expectedLength = _align(structure.sourceLength, 4) + xmp.length;
    expectedLength = _align(expectedLength, 2) + 2 + entryCount * 12 + 4;
    if (expectedLength > maxOutputSize ||
        expectedLength > _maximumClassicOffset) {
      throw AssetLimitExceededException(
        limit: maxOutputSize < _maximumClassicOffset
            ? maxOutputSize
            : _maximumClassicOffset,
        actual: expectedLength,
      );
    }
    final staged = MemoryByteSink();
    await copyByteRange(source, staged, ByteRange(0, structure.sourceLength));
    final xmpOffset = _align(await staged.length, 4);
    await _appendPadding(staged, xmpOffset - await staged.length);
    await staged.append(xmp);
    final ifdOffset = _align(await staged.length, 2);
    await _appendPadding(staged, ifdOffset - await staged.length);
    final entries = <_IfdEntry>[
      for (final entry in first.entries)
        if (entry.tag != _xmpTag) entry,
      _IfdEntry.created(
        tag: _xmpTag,
        type: _byteType,
        count: xmp.length,
        valueOffset: xmpOffset,
        order: structure.order,
      ),
    ]..sort((left, right) => left.tag.compareTo(right.tag));
    await staged.append(
      _encodeIfd(entries, first.nextIfdOffset, structure.order),
    );
    await staged.writeAt(4, _uint32Bytes(ifdOffset, structure.order));
    if (await staged.length != expectedLength) {
      throw const MalformedAssetFormatException(
        'TIFF XMP rewrite produced an unexpected output length.',
      );
    }
    await output.append(staged.toBytes());
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

    final structure = await _inspect(source);
    final existing = structure.manifestEntry;
    if (operation == ManifestMutation.embed && existing != null) {
      throw const ManifestAlreadyExistsException(AssetFormat.tiff);
    }
    if (operation != ManifestMutation.embed && existing == null) {
      throw const ManifestNotFoundException(AssetFormat.tiff);
    }

    final pages = structure.pages;
    late _Ifd target;
    late int pointerLocation;
    var removeStandaloneIfd = false;
    if (operation == ManifestMutation.embed) {
      if (pages.length == 1) {
        target = pages.first;
        pointerLocation = 4;
      } else {
        target = _Ifd.synthetic();
        pointerLocation = pages.last.nextPointerOffset;
      }
    } else {
      target = structure.manifestIfd!;
      final targetIndex = pages.indexOf(target);
      if (targetIndex < 0) {
        throw const MalformedAssetFormatException(
          'The TIFF C2PA tag must be in a page IFD.',
        );
      }
      pointerLocation = targetIndex == 0
          ? 4
          : pages[targetIndex - 1].nextPointerOffset;
      removeStandaloneIfd =
          operation == ManifestMutation.remove &&
          target.entries.length == 1 &&
          targetIndex > 0;
    }

    final resultingEntryCount =
        target.entries.where((entry) => entry.tag != _c2paTag).length +
        (manifest == null ? 0 : 1);
    var expectedLength = structure.sourceLength;
    if (!removeStandaloneIfd) {
      expectedLength = _align(expectedLength, 4);
      if (manifest != null) expectedLength += manifest.length;
      expectedLength = _align(expectedLength, 2);
      expectedLength += 2 + resultingEntryCount * 12 + 4;
    }
    if (expectedLength > maxOutputSize ||
        expectedLength > _maximumClassicOffset) {
      throw AssetLimitExceededException(
        limit: maxOutputSize < _maximumClassicOffset
            ? maxOutputSize
            : _maximumClassicOffset,
        actual: expectedLength,
      );
    }

    final staged = MemoryByteSink();
    await copyByteRange(
      source,
      staged,
      ByteRange(0, structure.sourceLength),
      chunkSize: 64 * 1024,
    );

    if (removeStandaloneIfd) {
      final next = _uint32Bytes(target.nextIfdOffset, structure.order);
      await staged.writeAt(pointerLocation, next);
    } else {
      var writeOffset = _align(await staged.length, 4);
      await _appendPadding(staged, writeOffset - await staged.length);
      int? manifestOffset;
      if (manifest != null) {
        manifestOffset = writeOffset;
        await staged.append(manifest);
        writeOffset += manifest.length;
      }
      final ifdOffset = _align(writeOffset, 2);
      await _appendPadding(staged, ifdOffset - await staged.length);

      final entries = <_IfdEntry>[
        for (final entry in target.entries)
          if (entry.tag != _c2paTag) entry,
        if (manifest != null)
          _IfdEntry.created(
            tag: _c2paTag,
            type: _undefinedType,
            count: manifest.length,
            valueOffset: manifestOffset!,
            order: structure.order,
          ),
      ]..sort((left, right) => left.tag.compareTo(right.tag));
      if (entries.length > 0xffff) {
        throw AssetLimitExceededException(
          limit: 0xffff,
          actual: entries.length,
        );
      }
      final ifdBytes = _encodeIfd(
        entries,
        target.nextIfdOffset,
        structure.order,
      );
      await staged.append(ifdBytes);
      await staged.writeAt(
        pointerLocation,
        _uint32Bytes(ifdOffset, structure.order),
      );
    }

    final outputLength = await staged.length;
    if (outputLength != expectedLength) {
      throw const MalformedAssetFormatException(
        'TIFF rewrite produced an unexpected output length.',
      );
    }
    await output.append(staged.toBytes());
  }

  Future<_TiffStructure> _inspect(RandomAccessByteSource source) async {
    final sourceLength = await source.length;
    if (sourceLength > maxSourceSize) {
      throw AssetLimitExceededException(
        limit: maxSourceSize,
        actual: sourceLength,
      );
    }
    if (sourceLength > _maximumClassicOffset) {
      throw AssetLimitExceededException(
        limit: _maximumClassicOffset,
        actual: sourceLength,
      );
    }
    if (sourceLength < 8) {
      throw TruncatedAssetException(
        expectedLength: 8,
        actualLength: sourceLength,
      );
    }
    final header = await source.read(ByteRange(0, 8));
    final order = _byteOrder(header);
    if (order == null) {
      throw const MalformedAssetFormatException(
        'TIFF byte order must be II or MM.',
      );
    }
    final magic = _readUint16(header, 2, order);
    if (magic == 43) throw const UnsupportedTiffVariantException();
    if (magic != 42) {
      throw const MalformedAssetFormatException(
        'Classic TIFF magic must be 42.',
      );
    }
    final firstIfdOffset = _readUint32(header, 4, order);
    if (firstIfdOffset == 0) {
      throw const MalformedAssetFormatException(
        'TIFF must reference a first IFD.',
      );
    }

    final pages = <_Ifd>[];
    final allIfds = <int, _Ifd>{};
    final pendingReferences = <int>[];
    final visitedPages = <int>{};
    var pageOffset = firstIfdOffset;
    while (pageOffset != 0) {
      if (!visitedPages.add(pageOffset)) {
        throw const MalformedAssetFormatException(
          'The TIFF page IFD chain contains a cycle.',
        );
      }
      if (pages.length >= maxIfdCount) {
        throw SegmentLimitExceededException(
          limit: maxIfdCount,
          actual: pages.length + 1,
        );
      }
      final ifd = await _readIfd(source, sourceLength, pageOffset, order);
      pages.add(ifd);
      allIfds[pageOffset] = ifd;
      pendingReferences.addAll(
        await _referencedIfdOffsets(source, sourceLength, ifd, order),
      );
      pageOffset = ifd.nextIfdOffset;
    }

    final visitedReferences = <int>{...visitedPages};
    var referenceIndex = 0;
    while (referenceIndex < pendingReferences.length) {
      if (referenceIndex >= maxReferencedIfds) {
        throw SegmentLimitExceededException(
          limit: maxReferencedIfds,
          actual: referenceIndex + 1,
        );
      }
      final offset = pendingReferences[referenceIndex++];
      if (offset == 0) continue;
      if (!visitedReferences.add(offset)) {
        throw const MalformedAssetFormatException(
          'The TIFF IFD references contain a cycle or duplicate offset.',
        );
      }
      final ifd = await _readIfd(source, sourceLength, offset, order);
      allIfds[offset] = ifd;
      pendingReferences.addAll(
        await _referencedIfdOffsets(source, sourceLength, ifd, order),
      );
    }

    _Ifd? manifestIfd;
    _IfdEntry? manifestEntry;
    for (final ifd in allIfds.values) {
      final entry = ifd.entryFor(_c2paTag);
      if (entry == null) continue;
      if (manifestEntry != null) {
        throw const MalformedAssetFormatException(
          'The TIFF contains more than one C2PA tag.',
        );
      }
      if (entry.type != _undefinedType) {
        throw const MalformedAssetFormatException(
          'The TIFF C2PA tag must have field type UNDEFINED (7).',
        );
      }
      if (entry.count <= 4) {
        throw const MalformedAssetFormatException(
          'The TIFF C2PA manifest must use offset storage.',
        );
      }
      if (entry.count > maxManifestSize) {
        throw AssetLimitExceededException(
          limit: maxManifestSize,
          actual: entry.count,
        );
      }
      _checkRange(entry.valueOffset, entry.count, sourceLength);
      manifestIfd = ifd;
      manifestEntry = entry;
    }
    if (manifestIfd != null &&
        manifestIfd != pages.first &&
        manifestIfd != pages.last) {
      throw const MalformedAssetFormatException(
        'The TIFF C2PA tag must be in the first or last page IFD.',
      );
    }
    return _TiffStructure(
      sourceLength: sourceLength,
      order: order,
      pages: pages,
      manifestIfd: manifestIfd,
      manifestEntry: manifestEntry,
      allIfds: allIfds.values.toList(growable: false),
    );
  }

  Future<_Ifd> _readIfd(
    RandomAccessByteSource source,
    int sourceLength,
    int offset,
    Endian order,
  ) async {
    if (offset.isOdd) {
      throw MalformedAssetFormatException(
        'TIFF IFD offset $offset is not word-aligned.',
      );
    }
    _checkRange(offset, 2, sourceLength);
    final countBytes = await source.read(ByteRange(offset, offset + 2));
    final count = _readUint16(countBytes, 0, order);
    if (count > maxEntriesPerIfd) {
      throw SegmentLimitExceededException(
        limit: maxEntriesPerIfd,
        actual: count,
      );
    }
    final tableLength = 2 + count * 12 + 4;
    _checkRange(offset, tableLength, sourceLength);
    final table = await source.read(
      ByteRange.fromStartAndLength(offset, tableLength),
    );
    final entries = <_IfdEntry>[];
    final tags = <int>{};
    for (var index = 0; index < count; index++) {
      final entryOffset = 2 + index * 12;
      final tag = _readUint16(table, entryOffset, order);
      if (!tags.add(tag)) {
        throw MalformedAssetFormatException(
          'TIFF IFD at $offset contains duplicate tag $tag.',
        );
      }
      final type = _readUint16(table, entryOffset + 2, order);
      final typeSize = _typeSize(type);
      final valueCount = _readUint32(table, entryOffset + 4, order);
      if (valueCount > sourceLength ~/ typeSize) {
        throw const MalformedAssetFormatException(
          'A TIFF entry count exceeds the source bounds.',
        );
      }
      final dataLength = valueCount * typeSize;
      final valueOffset = _readUint32(table, entryOffset + 8, order);
      if (dataLength > 4) {
        _checkRange(valueOffset, dataLength, sourceLength);
      }
      entries.add(
        _IfdEntry(
          tag: tag,
          type: type,
          count: valueCount,
          valueOffset: valueOffset,
          entryOffset: offset + entryOffset,
          raw: Uint8List.fromList(table.sublist(entryOffset, entryOffset + 12)),
        ),
      );
    }
    return _Ifd(
      offset: offset,
      entries: entries,
      nextPointerOffset: offset + 2 + count * 12,
      nextIfdOffset: _readUint32(table, 2 + count * 12, order),
    );
  }

  Future<List<int>> _referencedIfdOffsets(
    RandomAccessByteSource source,
    int sourceLength,
    _Ifd ifd,
    Endian order,
  ) async {
    final offsets = <int>[];
    for (final entry in ifd.entries) {
      if (!_ifdReferenceTags.contains(entry.tag)) continue;
      if (entry.type != 4 && entry.type != 13) {
        throw const MalformedAssetFormatException(
          'A referenced TIFF IFD tag must contain LONG offsets.',
        );
      }
      if (entry.count > maxReferencedIfds) {
        throw SegmentLimitExceededException(
          limit: maxReferencedIfds,
          actual: entry.count,
        );
      }
      if (entry.count == 1) {
        offsets.add(entry.valueOffset);
      } else {
        final byteLength = entry.count * 4;
        _checkRange(entry.valueOffset, byteLength, sourceLength);
        final bytes = await source.read(
          ByteRange.fromStartAndLength(entry.valueOffset, byteLength),
        );
        for (var index = 0; index < entry.count; index++) {
          offsets.add(_readUint32(bytes, index * 4, order));
        }
      }
    }
    return offsets;
  }

  static Uint8List _encodeIfd(
    List<_IfdEntry> entries,
    int nextIfdOffset,
    Endian order,
  ) {
    final output = Uint8List(2 + entries.length * 12 + 4);
    final data = ByteData.sublistView(output)
      ..setUint16(0, entries.length, order);
    for (var index = 0; index < entries.length; index++) {
      output.setRange(2 + index * 12, 14 + index * 12, entries[index].raw);
    }
    data.setUint32(2 + entries.length * 12, nextIfdOffset, order);
    return output;
  }

  static int _typeSize(int type) => switch (type) {
    1 || 2 || 6 || 7 => 1,
    3 || 8 => 2,
    4 || 9 || 11 || 13 => 4,
    5 || 10 || 12 || 16 || 17 || 18 => 8,
    _ => throw MalformedAssetFormatException(
      'Unsupported TIFF field type $type.',
    ),
  };

  static Endian? _byteOrder(List<int> bytes) {
    if (bytes.length < 2) return null;
    if (bytes[0] == 0x49 && bytes[1] == 0x49) return Endian.little;
    if (bytes[0] == 0x4d && bytes[1] == 0x4d) return Endian.big;
    return null;
  }

  static int _readUint16(List<int> bytes, int offset, Endian order) =>
      ByteData.sublistView(
        bytes is Uint8List ? bytes : Uint8List.fromList(bytes),
      ).getUint16(offset, order);

  static int _readUint32(List<int> bytes, int offset, Endian order) =>
      ByteData.sublistView(
        bytes is Uint8List ? bytes : Uint8List.fromList(bytes),
      ).getUint32(offset, order);

  static Uint8List _uint32Bytes(int value, Endian order) {
    if (value < 0 || value > _maximumClassicOffset) {
      throw AssetLimitExceededException(
        limit: _maximumClassicOffset,
        actual: value,
      );
    }
    final data = ByteData(4)..setUint32(0, value, order);
    return data.buffer.asUint8List();
  }

  static int _align(int value, int alignment) =>
      (value + alignment - 1) & -alignment;

  static Future<void> _appendPadding(WritableByteSink sink, int count) async {
    if (count > 0) await sink.append(Uint8List(count));
  }

  static void _checkRange(int offset, int length, int sourceLength) {
    if (offset < 0 || length < 0 || offset > sourceLength - length) {
      throw TruncatedAssetException(
        expectedLength: offset + length,
        actualLength: sourceLength,
      );
    }
  }
}

final class _IfdEntry {
  const _IfdEntry({
    required this.tag,
    required this.type,
    required this.count,
    required this.valueOffset,
    required this.entryOffset,
    required this.raw,
  });

  factory _IfdEntry.created({
    required int tag,
    required int type,
    required int count,
    required int valueOffset,
    required Endian order,
  }) {
    final raw = Uint8List(12);
    final data = ByteData.sublistView(raw)
      ..setUint16(0, tag, order)
      ..setUint16(2, type, order)
      ..setUint32(4, count, order)
      ..setUint32(8, valueOffset, order);
    return _IfdEntry(
      tag: tag,
      type: type,
      count: count,
      valueOffset: valueOffset,
      entryOffset: null,
      raw: data.buffer.asUint8List(),
    );
  }

  final int tag;
  final int type;
  final int count;
  final int valueOffset;
  final int? entryOffset;
  final Uint8List raw;
}

final class _Ifd {
  const _Ifd({
    required this.offset,
    required this.entries,
    required this.nextPointerOffset,
    required this.nextIfdOffset,
  });

  factory _Ifd.synthetic() => const _Ifd(
    offset: 0,
    entries: <_IfdEntry>[],
    nextPointerOffset: 0,
    nextIfdOffset: 0,
  );

  final int offset;
  final List<_IfdEntry> entries;
  final int nextPointerOffset;
  final int nextIfdOffset;

  _IfdEntry? entryFor(int tag) {
    for (final entry in entries) {
      if (entry.tag == tag) return entry;
    }
    return null;
  }
}

final class _TiffStructure {
  const _TiffStructure({
    required this.sourceLength,
    required this.order,
    required this.pages,
    required this.manifestIfd,
    required this.manifestEntry,
    required this.allIfds,
  });

  final int sourceLength;
  final Endian order;
  final List<_Ifd> pages;
  final _Ifd? manifestIfd;
  final _IfdEntry? manifestEntry;
  final List<_Ifd> allIfds;
}

final class _TiffXmp {
  const _TiffXmp(this.entry, this.bytes);

  final _IfdEntry entry;
  final Uint8List bytes;
}
