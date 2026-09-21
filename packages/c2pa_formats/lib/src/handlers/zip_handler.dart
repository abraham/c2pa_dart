import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../errors.dart';
import '../zip_collection.dart';

/// A ZIP-like archive handler for C2PA manifest entries.
///
/// Handles ZIP, EPUB, OOXML, OpenDocument, and OpenXPS containers. The
/// manifest is stored as the uncompressed entry [manifestPath].
final class ZipAssetHandler
    implements AssetHandler, ZipCollectionLayoutProvider {
  /// Creates a ZIP handler for one supported archive [format].
  const ZipAssetHandler({
    required this.format,
    this.maxManifestSize = 64 * 1024 * 1024,
    this.maxSourceSize = 512 * 1024 * 1024,
    this.maxOutputSize = 576 * 1024 * 1024,
    this.maxEntryCount = 100000,
    this.maxNameLength = 65535,
    this.copyChunkSize = 64 * 1024,
  }) : assert(
         format == AssetFormat.zip ||
             format == AssetFormat.epub ||
             format == AssetFormat.ooxml ||
             format == AssetFormat.openDocument ||
             format == AssetFormat.openXps,
       ),
       assert(maxManifestSize > 0),
       assert(maxSourceSize > 0),
       assert(maxOutputSize > 0),
       assert(maxEntryCount > 0),
       assert(maxNameLength > 0),
       assert(copyChunkSize > 0);

  /// Archive path of the embedded C2PA manifest entry.
  static const String manifestPath = 'META-INF/content_credential.c2pa';

  static const int _localSignature = 0x04034b50;
  static const int _centralSignature = 0x02014b50;
  static const int _descriptorSignature = 0x08074b50;
  static const int _eocdSignature = 0x06054b50;
  static const int _zip64EocdSignature = 0x06064b50;
  static const int _zip64LocatorSignature = 0x07064b50;
  static const int _uint16Max = 0xffff;
  static const int _uint32Max = 0xffffffff;

  @override
  /// The ZIP-like archive format handled by this instance.
  final AssetFormat format;

  /// Maximum embedded C2PA manifest size in bytes.
  final int maxManifestSize;

  /// Maximum source archive size in bytes.
  final int maxSourceSize;

  /// Maximum rewritten archive size in bytes.
  final int maxOutputSize;

  /// Maximum number of ZIP entries parsed from the central directory.
  final int maxEntryCount;

  /// Maximum entry name length in bytes.
  final int maxNameLength;

  /// Number of bytes copied per streaming write operation.
  final int copyChunkSize;

  @override
  String get name => switch (format) {
    AssetFormat.zip => 'ZIP',
    AssetFormat.epub => 'EPUB',
    AssetFormat.ooxml => 'Office Open XML',
    AssetFormat.openDocument => 'OpenDocument',
    AssetFormat.openXps => 'OpenXPS',
    _ => 'ZIP',
  };

  @override
  AssetHandlerCapabilities get capabilities => AssetHandlerCapabilities(
    canDetect: true,
    canExtractManifest: true,
    canEmbedManifest: true,
    canReplaceManifest: true,
    canRemoveManifest: true,
    canProvideCollectionHashLayout: true,
    mimeTypes: switch (format) {
      AssetFormat.zip => const <String>[
        'application/zip',
        'application/x-zip',
        'application/x-zip-compressed',
      ],
      AssetFormat.epub => const <String>['application/epub+zip'],
      AssetFormat.ooxml => const <String>[
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/vnd.ms-word.document.macroenabled.12',
        'application/vnd.ms-excel.sheet.macroenabled.12',
        'application/vnd.ms-powerpoint.presentation.macroenabled.12',
      ],
      AssetFormat.openDocument => const <String>[
        'application/vnd.oasis.opendocument.text',
        'application/vnd.oasis.opendocument.spreadsheet',
        'application/vnd.oasis.opendocument.presentation',
        'application/vnd.oasis.opendocument.graphics',
        'application/vnd.oasis.opendocument.text-template',
        'application/vnd.oasis.opendocument.spreadsheet-template',
        'application/vnd.oasis.opendocument.presentation-template',
        'application/vnd.oasis.opendocument.graphics-template',
      ],
      AssetFormat.openXps => const <String>['application/oxps'],
      _ => const <String>[],
    },
    fileExtensions: switch (format) {
      AssetFormat.zip => const <String>['zip'],
      AssetFormat.epub => const <String>['epub'],
      AssetFormat.ooxml => const <String>[
        'docx',
        'xlsx',
        'pptx',
        'docm',
        'xlsm',
        'pptm',
      ],
      AssetFormat.openDocument => const <String>[
        'odt',
        'ods',
        'odp',
        'odg',
        'ott',
        'ots',
        'otp',
        'otg',
      ],
      AssetFormat.openXps => const <String>['oxps'],
      _ => const <String>[],
    },
  );

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    try {
      return (await _inspect(source)).detectedFormat == format;
    } on AssetFormatException {
      return false;
    } on FormatException {
      return false;
    }
  }

  @override
  Future<Uint8List> extractManifest(RandomAccessByteSource source) async {
    final inspection = await _inspect(source);
    final manifest = inspection.manifest;
    if (manifest == null) throw ManifestNotFoundException(format);
    if (manifest.compressionMethod != 0) {
      throw const UnsupportedZipFeatureException(
        'compressed C2PA manifest entries',
      );
    }
    final bytes = await source.read(
      ByteRange.fromStartAndLength(
        manifest.dataOffset,
        manifest.compressedSize,
      ),
    );
    if (bytes.length != manifest.uncompressedSize ||
        _crc32(bytes) != manifest.crc32) {
      throw const MalformedAssetFormatException(
        'The ZIP C2PA manifest has inconsistent size or CRC metadata.',
      );
    }
    if (bytes.length > maxManifestSize) {
      throw AssetLimitExceededException(
        limit: maxManifestSize,
        actual: bytes.length,
      );
    }
    return bytes;
  }

  @override
  Future<ZipCollectionLayout> getCollectionHashLayout(
    RandomAccessByteSource source,
  ) async {
    final inspection = await _inspect(source);
    final entries = <ZipCollectionEntry>[
      for (final entry in inspection.entries)
        if (entry.normalizedPath != manifestPath)
          ZipCollectionEntry(
            uri: Uri(path: entry.normalizedPath),
            range: ByteRange(entry.localOffset, entry.localEnd),
            compressedSize: entry.compressedSize,
            uncompressedSize: entry.uncompressedSize,
            compressionMethod: entry.compressionMethod,
            isDirectory: entry.normalizedPath.endsWith('/'),
            mimeType: _mimeTypeForPath(entry.normalizedPath),
          ),
    ];
    final ranges = <ByteRange>[];
    final manifest = inspection.manifest;
    if (manifest == null) {
      ranges.add(
        ByteRange(inspection.centralDirectoryOffset, inspection.sourceLength),
      );
    } else {
      final crcStart = manifest.centralOffset + 16;
      if (inspection.centralDirectoryOffset < crcStart) {
        ranges.add(ByteRange(inspection.centralDirectoryOffset, crcStart));
      }
      if (crcStart + 4 < inspection.sourceLength) {
        ranges.add(ByteRange(crcStart + 4, inspection.sourceLength));
      }
    }
    return ZipCollectionLayout(
      entries: entries,
      centralDirectoryHashRanges: ranges,
    );
  }

  @override
  Future<Uint8List> readCentralDirectoryHashMaterial(
    RandomAccessByteSource source,
  ) async {
    final layout = await getCollectionHashLayout(source);
    final output = BytesBuilder(copy: false);
    for (final range in layout.centralDirectoryHashRanges) {
      output.add(await source.read(range));
    }
    return output.takeBytes();
  }

  @override
  Future<void> embedManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) => _rewrite(
    source,
    output,
    operation: _ZipMutation.embed,
    manifest: manifest,
  );

  @override
  Future<void> replaceManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) => _rewrite(
    source,
    output,
    operation: _ZipMutation.replace,
    manifest: manifest,
  );

  @override
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) => _rewrite(source, output, operation: _ZipMutation.remove);

  Future<void> _rewrite(
    RandomAccessByteSource source,
    WritableByteSink output, {
    required _ZipMutation operation,
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
    final existing = inspection.manifest;
    if (operation == _ZipMutation.embed && existing != null) {
      throw ManifestAlreadyExistsException(format);
    }
    if (operation != _ZipMutation.embed && existing == null) {
      throw ManifestNotFoundException(format);
    }

    final newEntries = <_NewZipEntry>[];
    var nextLocalOffset = inspection.centralDirectoryOffset;
    if (manifest != null) {
      if (!inspection.entries.any(
        (entry) => entry.normalizedPath == 'META-INF/',
      )) {
        final directory = _buildNewEntry(
          'META-INF/',
          Uint8List(0),
          nextLocalOffset,
          directory: true,
        );
        newEntries.add(directory);
        nextLocalOffset += directory.local.length;
      }
      final manifestEntry = _buildNewEntry(
        manifestPath,
        manifest,
        nextLocalOffset,
      );
      newEntries.add(manifestEntry);
      nextLocalOffset += manifestEntry.local.length;
    }

    final preservedEntries = inspection.entries
        .where((entry) => entry.normalizedPath != manifestPath)
        .toList();
    final entryCount = preservedEntries.length + newEntries.length;
    if (entryCount > maxEntryCount) {
      throw SegmentLimitExceededException(
        limit: maxEntryCount,
        actual: entryCount,
      );
    }
    final centralDirectoryOffset = nextLocalOffset;
    final centralDirectorySize =
        preservedEntries.fold<int>(
          0,
          (size, entry) => size + entry.centralEnd - entry.centralOffset,
        ) +
        newEntries.fold<int>(0, (size, entry) => size + entry.central.length);
    final needsZip64 =
        inspection.zip64 ||
        entryCount >= _uint16Max ||
        centralDirectoryOffset > _uint32Max ||
        centralDirectorySize > _uint32Max;
    final expectedOutputLength =
        centralDirectoryOffset +
        centralDirectorySize +
        22 +
        inspection.comment.length +
        (needsZip64 ? 76 + inspection.zip64ExtensibleData.length : 0);
    if (expectedOutputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: expectedOutputLength,
      );
    }

    final staged = MemoryByteSink();
    await _copy(source, staged, 0, inspection.centralDirectoryOffset);
    for (final entry in newEntries) {
      await staged.append(entry.local);
    }
    for (final entry in preservedEntries) {
      await staged.append(
        await source.read(ByteRange(entry.centralOffset, entry.centralEnd)),
      );
    }
    for (final entry in newEntries) {
      await staged.append(entry.central);
    }
    if (needsZip64) {
      final zip64Offset = await staged.length;
      await staged.append(
        _buildZip64End(
          entryCount,
          centralDirectorySize,
          centralDirectoryOffset,
          inspection.zip64ExtensibleData,
        ),
      );
      await staged.append(_buildZip64Locator(zip64Offset));
    }
    await staged.append(
      _buildEndRecord(
        entryCount,
        centralDirectorySize,
        centralDirectoryOffset,
        inspection.comment,
        zip64: needsZip64,
      ),
    );
    final outputLength = await staged.length;
    if (outputLength != expectedOutputLength) {
      throw const MalformedAssetFormatException(
        'ZIP rewrite produced an unexpected output length.',
      );
    }
    await output.append(staged.toBytes());
  }

  Future<_ZipInspection> _inspect(RandomAccessByteSource source) async {
    final sourceLength = await source.length;
    if (sourceLength > maxSourceSize) {
      throw AssetLimitExceededException(
        limit: maxSourceSize,
        actual: sourceLength,
      );
    }
    if (sourceLength < 22) {
      throw TruncatedAssetException(
        expectedLength: 22,
        actualLength: sourceLength,
      );
    }
    final end = await _readEndRecords(source, sourceLength);
    if (end.entryCount > maxEntryCount) {
      throw SegmentLimitExceededException(
        limit: maxEntryCount,
        actual: end.entryCount,
      );
    }
    if (end.centralDirectoryOffset > sourceLength ||
        end.centralDirectorySize > sourceLength - end.centralDirectoryOffset) {
      throw const MalformedAssetFormatException(
        'The ZIP central directory exceeds the source bounds.',
      );
    }
    if (end.centralDirectoryOffset + end.centralDirectorySize !=
        end.centralDirectoryEnd) {
      throw const MalformedAssetFormatException(
        'Unsupported records occur between the ZIP central directory and end records.',
      );
    }

    final entries = <_ZipEntry>[];
    final paths = <String>{};
    var offset = end.centralDirectoryOffset;
    for (var index = 0; index < end.entryCount; index++) {
      final entry = await _readCentralEntry(
        source,
        offset,
        end.centralDirectoryEnd,
      );
      if (!paths.add(entry.normalizedPath)) {
        throw MalformedAssetFormatException(
          'The ZIP contains duplicate entry path "${entry.normalizedPath}".',
        );
      }
      await _readLocalEntry(
        source,
        entry,
        centralDirectoryOffset: end.centralDirectoryOffset,
      );
      entries.add(entry);
      offset = entry.centralEnd;
    }
    if (offset != end.centralDirectoryEnd) {
      throw const MalformedAssetFormatException(
        'The ZIP central directory entry count or size is inconsistent.',
      );
    }
    final ordered = [...entries]
      ..sort((left, right) => left.localOffset.compareTo(right.localOffset));
    var previousEnd = 0;
    for (final entry in ordered) {
      if (entry.localOffset < previousEnd) {
        throw const MalformedAssetFormatException(
          'ZIP local entry ranges overlap.',
        );
      }
      previousEnd = entry.localEnd;
    }

    final manifestEntries = entries
        .where((entry) => entry.normalizedPath == manifestPath)
        .toList();
    if (manifestEntries.length > 1) {
      throw const MalformedAssetFormatException(
        'The ZIP contains duplicate C2PA manifest entries.',
      );
    }
    final detectedFormat = await _detectFamily(source, entries);
    return _ZipInspection(
      sourceLength: sourceLength,
      entries: List<_ZipEntry>.unmodifiable(entries),
      manifest: manifestEntries.firstOrNull,
      centralDirectoryOffset: end.centralDirectoryOffset,
      centralDirectorySize: end.centralDirectorySize,
      comment: end.comment,
      zip64: end.zip64,
      zip64ExtensibleData: end.zip64ExtensibleData,
      detectedFormat: detectedFormat,
    );
  }

  Future<_ZipEnd> _readEndRecords(
    RandomAccessByteSource source,
    int sourceLength,
  ) async {
    final tailLength = sourceLength < 65557 ? sourceLength : 65557;
    final tailStart = sourceLength - tailLength;
    final tail = await source.read(ByteRange(tailStart, sourceLength));
    var relative = tail.length - 22;
    while (relative >= 0) {
      if (_uint32(tail, relative) == _eocdSignature) {
        final commentLength = _uint16(tail, relative + 20);
        if (relative + 22 + commentLength == tail.length) break;
      }
      relative--;
    }
    if (relative < 0) {
      throw const MalformedAssetFormatException(
        'The ZIP end-of-central-directory record was not found.',
      );
    }
    final eocdOffset = tailStart + relative;
    final eocd = Uint8List.sublistView(tail, relative);
    final disk = _uint16(eocd, 4);
    final centralDisk = _uint16(eocd, 6);
    final entriesOnDisk = _uint16(eocd, 8);
    final totalEntries = _uint16(eocd, 10);
    final size32 = _uint32(eocd, 12);
    final offset32 = _uint32(eocd, 16);
    if (disk != 0 || centralDisk != 0 || entriesOnDisk != totalEntries) {
      throw const UnsupportedZipFeatureException('multi-disk archives');
    }
    final comment = Uint8List.fromList(
      eocd.sublist(22, 22 + _uint16(eocd, 20)),
    );
    final usesZip64 =
        totalEntries == _uint16Max ||
        size32 == _uint32Max ||
        offset32 == _uint32Max;
    if (!usesZip64) {
      return _ZipEnd(
        entryCount: totalEntries,
        centralDirectorySize: size32,
        centralDirectoryOffset: offset32,
        centralDirectoryEnd: eocdOffset,
        comment: comment,
        zip64: false,
        zip64ExtensibleData: Uint8List(0),
      );
    }
    if (eocdOffset < 20) {
      throw const MalformedAssetFormatException(
        'The ZIP64 locator is missing.',
      );
    }
    final locator = await source.read(ByteRange(eocdOffset - 20, eocdOffset));
    if (_uint32(locator, 0) != _zip64LocatorSignature ||
        _uint32(locator, 4) != 0 ||
        _uint32(locator, 16) != 1) {
      throw const UnsupportedZipFeatureException(
        'multi-disk or malformed ZIP64 archives',
      );
    }
    final zip64Offset = _uint64(locator, 8);
    if (zip64Offset > eocdOffset - 20 || eocdOffset - 20 - zip64Offset < 56) {
      throw const MalformedAssetFormatException(
        'The ZIP64 end record has invalid bounds.',
      );
    }
    final fixed = await source.read(ByteRange(zip64Offset, zip64Offset + 56));
    if (_uint32(fixed, 0) != _zip64EocdSignature) {
      throw const MalformedAssetFormatException(
        'The ZIP64 end record signature is invalid.',
      );
    }
    final recordDataSize = _uint64(fixed, 4);
    if (recordDataSize < 44 ||
        recordDataSize > ByteRange.maxCoordinate - 12 ||
        zip64Offset + 12 + recordDataSize != eocdOffset - 20) {
      throw const MalformedAssetFormatException(
        'The ZIP64 end record size is invalid.',
      );
    }
    if (_uint32(fixed, 16) != 0 ||
        _uint32(fixed, 20) != 0 ||
        _uint64(fixed, 24) != _uint64(fixed, 32)) {
      throw const UnsupportedZipFeatureException('multi-disk ZIP64 archives');
    }
    final count = _uint64(fixed, 32);
    final centralSize = _uint64(fixed, 40);
    final centralOffset = _uint64(fixed, 48);
    final extensionLength = recordDataSize - 44;
    final extension = extensionLength == 0
        ? Uint8List(0)
        : await source.read(
            ByteRange(zip64Offset + 56, zip64Offset + 56 + extensionLength),
          );
    return _ZipEnd(
      entryCount: count,
      centralDirectorySize: centralSize,
      centralDirectoryOffset: centralOffset,
      centralDirectoryEnd: zip64Offset,
      comment: comment,
      zip64: true,
      zip64ExtensibleData: extension,
    );
  }

  Future<_ZipEntry> _readCentralEntry(
    RandomAccessByteSource source,
    int offset,
    int centralDirectoryEnd,
  ) async {
    if (centralDirectoryEnd - offset < 46) {
      throw const MalformedAssetFormatException(
        'A ZIP central directory header is truncated.',
      );
    }
    final fixed = await source.read(ByteRange(offset, offset + 46));
    if (_uint32(fixed, 0) != _centralSignature) {
      throw const MalformedAssetFormatException(
        'A ZIP central directory header signature is invalid.',
      );
    }
    final flags = _uint16(fixed, 8);
    _validateFlags(flags);
    final compression = _uint16(fixed, 10);
    _validateCompression(compression);
    final nameLength = _uint16(fixed, 28);
    final extraLength = _uint16(fixed, 30);
    final commentLength = _uint16(fixed, 32);
    if (nameLength == 0 || nameLength > maxNameLength) {
      throw AssetLimitExceededException(
        limit: maxNameLength,
        actual: nameLength,
      );
    }
    final end = offset + 46 + nameLength + extraLength + commentLength;
    if (end > centralDirectoryEnd) {
      throw const MalformedAssetFormatException(
        'A ZIP central directory entry exceeds its bounds.',
      );
    }
    final variable = await source.read(ByteRange(offset + 46, end));
    final nameBytes = Uint8List.sublistView(variable, 0, nameLength);
    final extra = Uint8List.sublistView(
      variable,
      nameLength,
      nameLength + extraLength,
    );
    final name = _decodeName(nameBytes, flags);
    final normalized = _normalizePath(name);
    var uncompressedSize = _uint32(fixed, 24);
    var compressedSize = _uint32(fixed, 20);
    var localOffset = _uint32(fixed, 42);
    var diskStart = _uint16(fixed, 34);
    final zip64 = _readZip64Extra(
      extra,
      uncompressed: uncompressedSize == _uint32Max,
      compressed: compressedSize == _uint32Max,
      localOffset: localOffset == _uint32Max,
      diskStart: diskStart == _uint16Max,
    );
    if (uncompressedSize == _uint32Max) {
      uncompressedSize = zip64.uncompressedSize!;
    }
    if (compressedSize == _uint32Max) {
      compressedSize = zip64.compressedSize!;
    }
    if (localOffset == _uint32Max) localOffset = zip64.localOffset!;
    if (diskStart == _uint16Max) diskStart = zip64.diskStart!;
    if (diskStart != 0) {
      throw const UnsupportedZipFeatureException('multi-disk archives');
    }
    return _ZipEntry(
      nameBytes: Uint8List.fromList(nameBytes),
      normalizedPath: normalized,
      flags: flags,
      compressionMethod: compression,
      crc32: _uint32(fixed, 16),
      compressedSize: compressedSize,
      uncompressedSize: uncompressedSize,
      localOffset: localOffset,
      centralOffset: offset,
      centralEnd: end,
      usesZip64Sizes:
          _uint32(fixed, 20) == _uint32Max || _uint32(fixed, 24) == _uint32Max,
    );
  }

  Future<void> _readLocalEntry(
    RandomAccessByteSource source,
    _ZipEntry entry, {
    required int centralDirectoryOffset,
  }) async {
    if (entry.localOffset > centralDirectoryOffset - 30) {
      throw const MalformedAssetFormatException(
        'A ZIP local header offset is outside the local-entry area.',
      );
    }
    final fixed = await source.read(
      ByteRange(entry.localOffset, entry.localOffset + 30),
    );
    if (_uint32(fixed, 0) != _localSignature) {
      throw const MalformedAssetFormatException(
        'A ZIP local header signature is invalid.',
      );
    }
    final flags = _uint16(fixed, 6);
    _validateFlags(flags);
    final compression = _uint16(fixed, 8);
    _validateCompression(compression);
    if (flags != entry.flags || compression != entry.compressionMethod) {
      throw const MalformedAssetFormatException(
        'ZIP local and central header metadata disagree.',
      );
    }
    final nameLength = _uint16(fixed, 26);
    final extraLength = _uint16(fixed, 28);
    final variableEnd = entry.localOffset + 30 + nameLength + extraLength;
    if (variableEnd > centralDirectoryOffset) {
      throw const MalformedAssetFormatException(
        'A ZIP local header exceeds the local-entry area.',
      );
    }
    final variable = await source.read(
      ByteRange(entry.localOffset + 30, variableEnd),
    );
    final localName = variable.sublist(0, nameLength);
    final localExtra = Uint8List.sublistView(variable, nameLength);
    _validateExtraFields(localExtra);
    if (!_equal(localName, entry.nameBytes)) {
      throw const MalformedAssetFormatException(
        'ZIP local and central entry names disagree.',
      );
    }
    final dataOffset = variableEnd;
    if (entry.compressedSize > centralDirectoryOffset - dataOffset) {
      throw const MalformedAssetFormatException(
        'ZIP compressed data exceeds the local-entry area.',
      );
    }
    final dataEnd = dataOffset + entry.compressedSize;
    var localEnd = dataEnd;
    if (flags & 0x0008 != 0) {
      localEnd = await _readDescriptor(
        source,
        entry,
        dataEnd,
        centralDirectoryOffset,
      );
    } else {
      final localCrc = _uint32(fixed, 14);
      var localCompressed = _uint32(fixed, 18);
      var localUncompressed = _uint32(fixed, 22);
      if (localCompressed == _uint32Max || localUncompressed == _uint32Max) {
        final zip64 = _readZip64Extra(
          localExtra,
          uncompressed: localUncompressed == _uint32Max,
          compressed: localCompressed == _uint32Max,
          localOffset: false,
          diskStart: false,
        );
        if (localUncompressed == _uint32Max) {
          localUncompressed = zip64.uncompressedSize!;
        }
        if (localCompressed == _uint32Max) {
          localCompressed = zip64.compressedSize!;
        }
      }
      if (localCrc != entry.crc32 ||
          localCompressed != entry.compressedSize ||
          localUncompressed != entry.uncompressedSize) {
        throw const MalformedAssetFormatException(
          'ZIP local and central size or CRC metadata disagree.',
        );
      }
    }
    if (localEnd > centralDirectoryOffset) {
      throw const MalformedAssetFormatException(
        'A ZIP local entry overlaps its central directory.',
      );
    }
    entry
      ..dataOffset = dataOffset
      ..localEnd = localEnd;
  }

  Future<int> _readDescriptor(
    RandomAccessByteSource source,
    _ZipEntry entry,
    int offset,
    int centralDirectoryOffset,
  ) async {
    if (offset == centralDirectoryOffset) return offset;
    if (centralDirectoryOffset - offset < 4) {
      throw const MalformedAssetFormatException(
        'A ZIP data descriptor is truncated.',
      );
    }
    final first = await source.read(ByteRange(offset, offset + 4));
    final marker = _uint32(first, 0);
    if ((marker == _localSignature || marker == _centralSignature) &&
        entry.compressedSize == 0 &&
        entry.uncompressedSize == 0) {
      return offset;
    }
    final hasSignature = marker == _descriptorSignature;
    final sizeFieldLength = entry.usesZip64Sizes ? 8 : 4;
    final length = (hasSignature ? 4 : 0) + 4 + sizeFieldLength * 2;
    if (length > centralDirectoryOffset - offset) {
      throw const MalformedAssetFormatException(
        'A ZIP data descriptor is truncated.',
      );
    }
    final descriptor = await source.read(ByteRange(offset, offset + length));
    var cursor = hasSignature ? 4 : 0;
    final crc = _uint32(descriptor, cursor);
    cursor += 4;
    final compressed = sizeFieldLength == 8
        ? _uint64(descriptor, cursor)
        : _uint32(descriptor, cursor);
    cursor += sizeFieldLength;
    final uncompressed = sizeFieldLength == 8
        ? _uint64(descriptor, cursor)
        : _uint32(descriptor, cursor);
    if (crc != entry.crc32 ||
        compressed != entry.compressedSize ||
        uncompressed != entry.uncompressedSize) {
      throw const MalformedAssetFormatException(
        'A ZIP data descriptor disagrees with its central header.',
      );
    }
    return offset + length;
  }

  Future<AssetFormat> _detectFamily(
    RandomAccessByteSource source,
    List<_ZipEntry> entries,
  ) async {
    final paths = {for (final entry in entries) entry.normalizedPath};
    final mimetype = entries
        .where((entry) => entry.normalizedPath == 'mimetype')
        .firstOrNull;
    if (mimetype != null &&
        mimetype.compressionMethod == 0 &&
        mimetype.uncompressedSize <= 256) {
      if (mimetype.compressedSize != mimetype.uncompressedSize) {
        throw const MalformedAssetFormatException(
          'The stored ZIP mimetype entry has inconsistent sizes.',
        );
      }
      final bytes = await source.read(
        ByteRange.fromStartAndLength(
          mimetype.dataOffset,
          mimetype.compressedSize,
        ),
      );
      if (_crc32(bytes) != mimetype.crc32) {
        throw const MalformedAssetFormatException(
          'The ZIP mimetype entry has an invalid CRC.',
        );
      }
      late String value;
      try {
        value = utf8.decode(bytes);
      } on FormatException {
        throw const MalformedAssetFormatException(
          'The ZIP mimetype entry is not valid UTF-8.',
        );
      }
      if (value == 'application/epub+zip') return AssetFormat.epub;
      if (value.startsWith('application/vnd.oasis.opendocument.')) {
        return AssetFormat.openDocument;
      }
    }
    if (paths.contains('[Content_Types].xml')) {
      if (paths.contains('FixedDocumentSequence.fdseq') ||
          paths.any((path) => path.endsWith('.fpage'))) {
        return AssetFormat.openXps;
      }
      return AssetFormat.ooxml;
    }
    return AssetFormat.zip;
  }

  _NewZipEntry _buildNewEntry(
    String path,
    Uint8List data,
    int localOffset, {
    bool directory = false,
  }) {
    final name = utf8.encode(path);
    final crc = _crc32(data);
    final local = BytesBuilder(copy: false)
      ..add(_little32(_localSignature))
      ..add(_little16(20))
      ..add(_little16(0x0800))
      ..add(_little16(0))
      ..add(_little16(0))
      ..add(_little16(0))
      ..add(_little32(crc))
      ..add(_little32(data.length))
      ..add(_little32(data.length))
      ..add(_little16(name.length))
      ..add(_little16(0))
      ..add(name)
      ..add(data);
    final central = BytesBuilder(copy: false)
      ..add(_little32(_centralSignature))
      ..add(_little16(0x0314))
      ..add(_little16(20))
      ..add(_little16(0x0800))
      ..add(_little16(0))
      ..add(_little16(0))
      ..add(_little16(0))
      ..add(_little32(crc))
      ..add(_little32(data.length))
      ..add(_little32(data.length))
      ..add(_little16(name.length))
      ..add(_little16(0))
      ..add(_little16(0))
      ..add(_little16(0))
      ..add(_little16(0))
      ..add(_little32(directory ? 0x41ed0010 : 0x81a40000))
      ..add(_little32(localOffset))
      ..add(name);
    return _NewZipEntry(local.takeBytes(), central.takeBytes());
  }

  Uint8List _buildZip64End(
    int entryCount,
    int centralSize,
    int centralOffset,
    Uint8List extension,
  ) {
    final output = BytesBuilder(copy: false)
      ..add(_little32(_zip64EocdSignature))
      ..add(_little64(44 + extension.length))
      ..add(_little16(45))
      ..add(_little16(45))
      ..add(_little32(0))
      ..add(_little32(0))
      ..add(_little64(entryCount))
      ..add(_little64(entryCount))
      ..add(_little64(centralSize))
      ..add(_little64(centralOffset))
      ..add(extension);
    return output.takeBytes();
  }

  Uint8List _buildZip64Locator(int zip64Offset) {
    final output = BytesBuilder(copy: false)
      ..add(_little32(_zip64LocatorSignature))
      ..add(_little32(0))
      ..add(_little64(zip64Offset))
      ..add(_little32(1));
    return output.takeBytes();
  }

  Uint8List _buildEndRecord(
    int entryCount,
    int centralSize,
    int centralOffset,
    Uint8List comment, {
    required bool zip64,
  }) {
    final output = BytesBuilder(copy: false)
      ..add(_little32(_eocdSignature))
      ..add(_little16(0))
      ..add(_little16(0))
      ..add(_little16(zip64 ? _uint16Max : entryCount))
      ..add(_little16(zip64 ? _uint16Max : entryCount))
      ..add(_little32(zip64 ? _uint32Max : centralSize))
      ..add(_little32(zip64 ? _uint32Max : centralOffset))
      ..add(_little16(comment.length))
      ..add(comment);
    return output.takeBytes();
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

  static void _validateFlags(int flags) {
    if (flags & 0x0001 != 0 || flags & 0x0040 != 0) {
      throw const UnsupportedZipFeatureException('encrypted entries');
    }
  }

  static void _validateCompression(int method) {
    if (method != 0 && method != 8) {
      throw UnsupportedZipFeatureException('compression method $method');
    }
  }

  static String _decodeName(Uint8List bytes, int flags) {
    if (bytes.contains(0)) {
      throw const MalformedAssetFormatException(
        'A ZIP entry path contains a NUL byte.',
      );
    }
    if (flags & 0x0800 != 0) return utf8.decode(bytes);
    if (bytes.any((byte) => byte > 0x7f)) {
      throw const UnsupportedZipFeatureException(
        'non-UTF-8 legacy entry names',
      );
    }
    return ascii.decode(bytes);
  }

  static String _normalizePath(String path) {
    final normalized = path.replaceAll('\\', '/');
    if (normalized.isEmpty ||
        normalized.startsWith('/') ||
        RegExp(r'^[A-Za-z]:').hasMatch(normalized) ||
        normalized.codeUnits.any((unit) => unit < 0x20 || unit == 0x7f)) {
      throw MalformedAssetFormatException(
        'The ZIP entry path "$path" is unsafe.',
      );
    }
    final parts = normalized.split('/');
    for (var index = 0; index < parts.length; index++) {
      final part = parts[index];
      if (part == '..' ||
          part == '.' ||
          (part.isEmpty && index != parts.length - 1)) {
        throw MalformedAssetFormatException(
          'The ZIP entry path "$path" is unsafe.',
        );
      }
    }
    return normalized;
  }

  static _Zip64Extra _readZip64Extra(
    Uint8List extra, {
    required bool uncompressed,
    required bool compressed,
    required bool localOffset,
    required bool diskStart,
  }) {
    if (!uncompressed && !compressed && !localOffset && !diskStart) {
      _validateExtraFields(extra);
      return const _Zip64Extra();
    }
    var offset = 0;
    while (offset < extra.length) {
      if (extra.length - offset < 4) {
        throw const MalformedAssetFormatException(
          'A ZIP extra field is truncated.',
        );
      }
      final id = _uint16(extra, offset);
      final length = _uint16(extra, offset + 2);
      offset += 4;
      if (length > extra.length - offset) {
        throw const MalformedAssetFormatException(
          'A ZIP extra field exceeds its bounds.',
        );
      }
      if (id == 0x0001) {
        var cursor = offset;
        int read64() {
          if (cursor + 8 > offset + length) {
            throw const MalformedAssetFormatException(
              'The ZIP64 extra field is truncated.',
            );
          }
          final value = _uint64(extra, cursor);
          cursor += 8;
          return value;
        }

        int read32() {
          if (cursor + 4 > offset + length) {
            throw const MalformedAssetFormatException(
              'The ZIP64 extra field is truncated.',
            );
          }
          final value = _uint32(extra, cursor);
          cursor += 4;
          return value;
        }

        return _Zip64Extra(
          uncompressedSize: uncompressed ? read64() : null,
          compressedSize: compressed ? read64() : null,
          localOffset: localOffset ? read64() : null,
          diskStart: diskStart ? read32() : null,
        );
      }
      offset += length;
    }
    throw const MalformedAssetFormatException(
      'A required ZIP64 extra field is missing.',
    );
  }

  static void _validateExtraFields(Uint8List extra) {
    var offset = 0;
    while (offset < extra.length) {
      if (extra.length - offset < 4) {
        throw const MalformedAssetFormatException(
          'A ZIP extra field is truncated.',
        );
      }
      final length = _uint16(extra, offset + 2);
      offset += 4;
      if (length > extra.length - offset) {
        throw const MalformedAssetFormatException(
          'A ZIP extra field exceeds its bounds.',
        );
      }
      offset += length;
    }
  }

  static String? _mimeTypeForPath(String path) {
    final lower = path.toLowerCase();
    final dot = lower.lastIndexOf('.');
    final extension = dot < 0 ? '' : lower.substring(dot + 1);
    return switch (extension) {
      'c2pa' => 'application/c2pa',
      'xml' => 'application/xml',
      'html' || 'htm' => 'text/html',
      'css' => 'text/css',
      'json' => 'application/json',
      'txt' => 'text/plain',
      'jpg' || 'jpeg' => 'image/jpeg',
      'png' => 'image/png',
      'gif' => 'image/gif',
      'svg' => 'image/svg+xml',
      'webp' => 'image/webp',
      _ => null,
    };
  }

  static int _uint16(Uint8List bytes, int offset) =>
      ByteData.sublistView(bytes).getUint16(offset, Endian.little);

  static int _uint32(Uint8List bytes, int offset) =>
      ByteData.sublistView(bytes).getUint32(offset, Endian.little);

  static int _uint64(Uint8List bytes, int offset) {
    final data = ByteData.sublistView(bytes);
    final low = data.getUint32(offset, Endian.little);
    final high = data.getUint32(offset + 4, Endian.little);
    if (high > 0x1fffff) {
      throw const MalformedAssetFormatException(
        'A ZIP64 value exceeds the supported address range.',
      );
    }
    return high * 0x100000000 + low;
  }

  static Uint8List _little16(int value) {
    final bytes = Uint8List(2);
    ByteData.sublistView(bytes).setUint16(0, value, Endian.little);
    return bytes;
  }

  static Uint8List _little32(int value) {
    final bytes = Uint8List(4);
    ByteData.sublistView(bytes).setUint32(0, value, Endian.little);
    return bytes;
  }

  static Uint8List _little64(int value) {
    final bytes = Uint8List(8);
    final data = ByteData.sublistView(bytes);
    data
      ..setUint32(0, value & _uint32Max, Endian.little)
      ..setUint32(4, value ~/ 0x100000000, Endian.little);
    return bytes;
  }

  static bool _equal(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }

  static int _crc32(List<int> bytes) {
    var crc = 0xffffffff;
    for (final byte in bytes) {
      crc ^= byte;
      for (var bit = 0; bit < 8; bit++) {
        crc = crc & 1 == 0 ? crc >> 1 : (crc >> 1) ^ 0xedb88320;
      }
    }
    return (crc ^ 0xffffffff) & _uint32Max;
  }
}

enum _ZipMutation { embed, replace, remove }

final class _ZipEntry {
  _ZipEntry({
    required this.nameBytes,
    required this.normalizedPath,
    required this.flags,
    required this.compressionMethod,
    required this.crc32,
    required this.compressedSize,
    required this.uncompressedSize,
    required this.localOffset,
    required this.centralOffset,
    required this.centralEnd,
    required this.usesZip64Sizes,
  });

  final Uint8List nameBytes;
  final String normalizedPath;
  final int flags;
  final int compressionMethod;
  final int crc32;
  final int compressedSize;
  final int uncompressedSize;
  final int localOffset;
  final int centralOffset;
  final int centralEnd;
  final bool usesZip64Sizes;
  int dataOffset = 0;
  int localEnd = 0;
}

final class _ZipEnd {
  const _ZipEnd({
    required this.entryCount,
    required this.centralDirectorySize,
    required this.centralDirectoryOffset,
    required this.centralDirectoryEnd,
    required this.comment,
    required this.zip64,
    required this.zip64ExtensibleData,
  });

  final int entryCount;
  final int centralDirectorySize;
  final int centralDirectoryOffset;
  final int centralDirectoryEnd;
  final Uint8List comment;
  final bool zip64;
  final Uint8List zip64ExtensibleData;
}

final class _ZipInspection {
  const _ZipInspection({
    required this.sourceLength,
    required this.entries,
    required this.manifest,
    required this.centralDirectoryOffset,
    required this.centralDirectorySize,
    required this.comment,
    required this.zip64,
    required this.zip64ExtensibleData,
    required this.detectedFormat,
  });

  final int sourceLength;
  final List<_ZipEntry> entries;
  final _ZipEntry? manifest;
  final int centralDirectoryOffset;
  final int centralDirectorySize;
  final Uint8List comment;
  final bool zip64;
  final Uint8List zip64ExtensibleData;
  final AssetFormat detectedFormat;
}

final class _Zip64Extra {
  const _Zip64Extra({
    this.uncompressedSize,
    this.compressedSize,
    this.localOffset,
    this.diskStart,
  });

  final int? uncompressedSize;
  final int? compressedSize;
  final int? localOffset;
  final int? diskStart;
}

final class _NewZipEntry {
  const _NewZipEntry(this.local, this.central);

  final Uint8List local;
  final Uint8List central;
}
