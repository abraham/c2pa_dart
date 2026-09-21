import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../byte_reader.dart';
import '../errors.dart';
import '../hash_layout.dart';
import '../isobmff.dart';
import '../manifest_mutation.dart';
import '../xmp.dart';
import '../xmp_remote_reference.dart';

/// A JPEG XL container handler for C2PA JUMBF boxes.
///
/// The manifest is a top-level `jumb` box in the JPEG XL container. Raw JPEG
/// XL codestreams are detected as unsupported because they cannot carry boxes.
final class JpegXlAssetHandler
    with ManifestRewrite
    implements
        AssetHandler,
        BoxHashLayoutProvider,
        IsoBmffBoxProvider,
        XmpMetadataProvider,
        RemoteManifestReferenceProvider {
  /// Creates a JPEG XL handler with byte and box-count limits.
  const JpegXlAssetHandler({
    this.maxManifestSize = 64 * 1024 * 1024,
    this.maxSourceSize = 512 * 1024 * 1024,
    this.maxOutputSize = 576 * 1024 * 1024,
    this.maxBoxCount = 1024,
    this.copyChunkSize = 64 * 1024,
    this.maxXmpSize = 4 * 1024 * 1024,
    this.maxRemoteReferenceLength = 64 * 1024,
  }) : assert(maxManifestSize > 0),
       assert(maxSourceSize > 0),
       assert(maxOutputSize > 0),
       assert(maxBoxCount > 0),
       assert(copyChunkSize > 0),
       assert(maxXmpSize > 0),
       assert(maxRemoteReferenceLength > 0);

  /// JPEG XL container signature bytes required before any boxes.
  static const List<int> containerSignature = <int>[
    0x00,
    0x00,
    0x00,
    0x0c,
    0x4a,
    0x58,
    0x4c,
    0x20,
    0x0d,
    0x0a,
    0x87,
    0x0a,
  ];

  /// Signature bytes for unsupported raw JPEG XL codestreams.
  static const List<int> rawCodestreamSignature = <int>[0xff, 0x0a];

  /// Maximum embedded C2PA manifest size in bytes.
  final int maxManifestSize;

  /// Maximum source asset size in bytes.
  final int maxSourceSize;

  /// Maximum rewritten asset size in bytes.
  final int maxOutputSize;

  /// Maximum number of top-level JPEG XL boxes parsed from the asset.
  final int maxBoxCount;

  /// Number of bytes copied per streaming write operation.
  final int copyChunkSize;

  /// Maximum XMP packet size in bytes.
  final int maxXmpSize;

  /// Maximum UTF-8 length of a remote reference in bytes.
  final int maxRemoteReferenceLength;

  @override
  String get name => 'JPEG XL';

  @override
  AssetFormat get format => AssetFormat.jpegXl;

  @override
  AssetHandlerCapabilities get capabilities => const AssetHandlerCapabilities(
    canDetect: true,
    canExtractManifest: true,
    canEmbedManifest: true,
    canReplaceManifest: true,
    canRemoveManifest: true,
    canProvideBoxHashLayout: true,
    canListTopLevelBoxes: true,
    canReadXmp: true,
    canEmbedRemoteReference: true,
    canReadRemoteReference: true,
    canRemoveRemoteReference: true,
    mimeTypes: <String>['image/jxl'],
    fileExtensions: <String>['jxl'],
  );

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    final length = await source.length;
    if (length < containerSignature.length) return false;
    final signature = await source.read(
      ByteRange(0, containerSignature.length),
    );
    if (!_equal(signature, containerSignature)) return false;
    try {
      await _inspect(source);
      return true;
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
    if (manifest == null) {
      throw const ManifestNotFoundException(AssetFormat.jpegXl);
    }
    return source.read(manifest.range);
  }

  @override
  Future<BoxHashLayout> getBoxHashLayout(RandomAccessByteSource source) async {
    final inspection = await _inspect(source);
    final entries = <BoxHashEntry>[];
    for (final box in inspection.boxes) {
      entries.add(
        BoxHashEntry(
          names: <String>[box.type == 'jumb' ? 'C2PA' : box.type],
          range: box.range,
        ),
      );
      if (inspection.manifest == null && box.offset == inspection.ftyp.offset) {
        entries.add(
          BoxHashEntry(
            names: const <String>['C2PA'],
            range: ByteRange(
              inspection.insertionOffset,
              inspection.insertionOffset,
            ),
            excluded: true,
            synthetic: true,
          ),
        );
      }
    }
    return BoxHashLayout(
      sourceLength: inspection.sourceLength,
      entries: entries,
    );
  }

  @override
  Future<String?> readXmp(RandomAccessByteSource source) async {
    final inspection = await _inspect(source);
    final xmp = inspection.xmp;
    if (xmp == null) return null;
    if (xmp.compressed) {
      throw const UnsupportedJpegXlFeatureException(
        'Brotli-compressed XMP brob boxes',
      );
    }
    final bytes = await source.read(xmp.dataRange);
    try {
      return utf8.decode(bytes, allowMalformed: false);
    } on FormatException {
      throw const MalformedAssetFormatException(
        'JPEG XL XMP metadata is not valid UTF-8.',
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
    if (xmp.compressed) {
      throw const UnsupportedJpegXlFeatureException(
        'Brotli-compressed XMP brob boxes',
      );
    }
    return XmpRemoteReferenceEditor.parse(
      await source.read(xmp.dataRange),
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
    final inspection = await _inspect(source);
    final existing = inspection.xmp;
    if (existing?.compressed ?? false) {
      throw const UnsupportedJpegXlFeatureException(
        'Brotli-compressed XMP brob boxes',
      );
    }
    final original = existing == null
        ? Uint8List.fromList(
            utf8.encode(XmpRemoteReferenceEditor.minimalPacket),
          )
        : await source.read(existing.dataRange);
    final updated = XmpRemoteReferenceEditor.parse(
      original,
      maxLength: maxXmpSize,
    ).update(reference, maxLength: maxXmpSize);
    await _rewriteXmp(source, output, inspection, updated);
  }

  @override
  Future<void> removeRemoteManifestReference(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) async {
    final inspection = await _inspect(source);
    final existing = inspection.xmp;
    if (existing == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.jpegXl);
    }
    if (existing.compressed) {
      throw const UnsupportedJpegXlFeatureException(
        'Brotli-compressed XMP brob boxes',
      );
    }
    final editor = XmpRemoteReferenceEditor.parse(
      await source.read(existing.dataRange),
      maxLength: maxXmpSize,
    );
    if (editor.value == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.jpegXl);
    }
    await _rewriteXmp(
      source,
      output,
      inspection,
      editor.remove(maxLength: maxXmpSize),
    );
  }

  Future<void> _rewriteXmp(
    RandomAccessByteSource source,
    WritableByteSink output,
    _JpegXlInspection inspection,
    Uint8List xmp,
  ) async {
    if (await output.length != 0) {
      throw const MalformedAssetFormatException(
        'The destination sink must be empty.',
      );
    }
    final encoded = _encodeBox('xml ', xmp);
    final existing = inspection.xmp;
    final outputLength =
        inspection.sourceLength - (existing?.box.size ?? 0) + encoded.length;
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }
    final start = existing?.box.offset ?? inspection.insertionOffset;
    final end = existing?.box.end ?? start;
    final staged = MemoryByteSink();
    await _copy(source, staged, 0, start);
    await staged.append(encoded);
    await _copy(source, staged, end, inspection.sourceLength);
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'JPEG XL XMP rewrite produced an unexpected output length.',
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
    if (manifest != null) {
      if (manifest.length > maxManifestSize) {
        throw AssetLimitExceededException(
          limit: maxManifestSize,
          actual: manifest.length,
        );
      }
      _validateManifestBytes(manifest);
    }

    final inspection = await _inspect(source);
    final existing = inspection.manifest;
    if (operation == ManifestMutation.embed && existing != null) {
      throw const ManifestAlreadyExistsException(AssetFormat.jpegXl);
    }
    if (operation != ManifestMutation.embed && existing == null) {
      throw const ManifestNotFoundException(AssetFormat.jpegXl);
    }

    final removedLength = existing?.size ?? 0;
    final insertedLength = manifest?.length ?? 0;
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
      await _copy(source, staged, 0, inspection.insertionOffset);
      await staged.append(manifest!);
      await _copy(
        source,
        staged,
        inspection.insertionOffset,
        inspection.sourceLength,
      );
    } else {
      await _copy(source, staged, 0, existing.offset);
      if (manifest != null) await staged.append(manifest);
      await _copy(source, staged, existing.end, inspection.sourceLength);
    }
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'JPEG XL rewrite produced an unexpected output length.',
      );
    }
    await output.append(staged.toBytes());
  }

  Future<_JpegXlInspection> _inspect(RandomAccessByteSource source) async {
    final sourceLength = await source.length;
    if (sourceLength > maxSourceSize) {
      throw AssetLimitExceededException(
        limit: maxSourceSize,
        actual: sourceLength,
      );
    }
    if (sourceLength >= 2) {
      final first = await source.read(ByteRange(0, 2));
      if (_equal(first, rawCodestreamSignature)) {
        throw const UnsupportedJpegXlCodestreamException();
      }
    }
    if (sourceLength < containerSignature.length) {
      throw TruncatedAssetException(
        expectedLength: containerSignature.length,
        actualLength: sourceLength,
      );
    }
    final signature = await source.read(
      ByteRange(0, containerSignature.length),
    );
    if (!_equal(signature, containerSignature)) {
      throw const MalformedAssetFormatException(
        'The JPEG XL container signature is invalid.',
      );
    }

    final boxes = await _parseBoxes(source, sourceLength);
    if (boxes.length < 3 ||
        boxes.first.type != 'JXL ' ||
        boxes.first.size != 12 ||
        boxes[1].type != 'ftyp') {
      throw const MalformedAssetFormatException(
        'A JPEG XL container must begin with its signature and ftyp boxes.',
      );
    }
    final ftyp = boxes[1];
    await _validateFtyp(source, ftyp);
    if (!boxes.any((box) => box.type == 'jxlc' || box.type == 'jxlp')) {
      throw const MalformedAssetFormatException(
        'The JPEG XL container has no codestream box.',
      );
    }

    IsoBmffBox? manifest;
    for (final box in boxes.where((box) => box.type == 'jumb')) {
      if (!await _isC2paJumb(source, box)) continue;
      if (manifest != null) {
        throw const MalformedAssetFormatException(
          'The JPEG XL container has duplicate C2PA manifest boxes.',
        );
      }
      manifest = box;
    }
    if (manifest != null && manifest.size > maxManifestSize) {
      throw AssetLimitExceededException(
        limit: maxManifestSize,
        actual: manifest.size,
      );
    }
    _JpegXlXmp? xmp;
    for (final box in boxes.where(
      (candidate) => candidate.type == 'xml ' || candidate.type == 'brob',
    )) {
      var compressed = false;
      var dataOffset = box.payloadOffset;
      if (box.type == 'brob') {
        if (box.payloadLength < 4) {
          throw const MalformedAssetFormatException(
            'A JPEG XL brob box is missing its original box type.',
          );
        }
        final originalType = await source.read(
          ByteRange(box.payloadOffset, box.payloadOffset + 4),
        );
        if (String.fromCharCodes(originalType) != 'xml ') continue;
        compressed = true;
        dataOffset += 4;
      }
      if (xmp != null) {
        throw const MalformedAssetFormatException(
          'The JPEG XL container contains duplicate XMP boxes.',
        );
      }
      final dataLength = box.end - dataOffset;
      if (dataLength > maxXmpSize) {
        throw AssetLimitExceededException(
          limit: maxXmpSize,
          actual: dataLength,
        );
      }
      xmp = _JpegXlXmp(
        box: box,
        dataRange: ByteRange(dataOffset, box.end),
        compressed: compressed,
      );
    }
    return _JpegXlInspection(
      sourceLength: sourceLength,
      boxes: List<IsoBmffBox>.unmodifiable(boxes),
      ftyp: ftyp,
      insertionOffset: ftyp.end,
      manifest: manifest,
      xmp: xmp,
    );
  }

  static Uint8List _encodeBox(String type, Uint8List payload) {
    final size = 8 + payload.length;
    if (size > 0xffffffff) {
      throw AssetLimitExceededException(limit: 0xffffffff, actual: size);
    }
    final bytes = Uint8List(size);
    ByteData.sublistView(bytes).setUint32(0, size, Endian.big);
    bytes.setRange(4, 8, type.codeUnits);
    bytes.setRange(8, size, payload);
    return bytes;
  }

  Future<List<IsoBmffBox>> _parseBoxes(
    RandomAccessByteSource source,
    int sourceLength,
  ) async {
    final boxes = <IsoBmffBox>[];
    var offset = 0;
    while (offset < sourceLength) {
      if (sourceLength - offset < 8) {
        throw TruncatedAssetException(
          expectedLength: offset + 8,
          actualLength: sourceLength,
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
        size = sourceLength - offset;
        toEnd = true;
      } else if (size32 == 1) {
        if (sourceLength - offset < 16) {
          throw TruncatedAssetException(
            expectedLength: offset + 16,
            actualLength: sourceLength,
          );
        }
        size = _uint64(await source.read(ByteRange(offset + 8, offset + 16)));
        headerSize = 16;
        extended = true;
      } else {
        size = size32;
      }
      if (size < headerSize) {
        throw const MalformedAssetFormatException(
          'A JPEG XL box size is smaller than its header.',
        );
      }
      if (size > ByteRange.maxCoordinate - offset) {
        throw const MalformedAssetFormatException(
          'A JPEG XL box size overflows the supported address range.',
        );
      }
      final end = offset + size;
      if (end > sourceLength) {
        throw TruncatedAssetException(
          expectedLength: end,
          actualLength: sourceLength,
        );
      }
      boxes.add(
        IsoBmffBox(
          type: type,
          offset: offset,
          size: size,
          headerSize: headerSize,
          usesExtendedSize: extended,
          extendsToEnd: toEnd,
        ),
      );
      if (boxes.length > maxBoxCount) {
        throw SegmentLimitExceededException(
          limit: maxBoxCount,
          actual: boxes.length,
        );
      }
      offset = end;
    }
    return boxes;
  }

  Future<void> _validateFtyp(
    RandomAccessByteSource source,
    IsoBmffBox ftyp,
  ) async {
    if (ftyp.payloadLength < 8 || (ftyp.payloadLength - 8) % 4 != 0) {
      throw const MalformedAssetFormatException(
        'The JPEG XL ftyp box is malformed.',
      );
    }
    final payload = await source.read(ByteRange(ftyp.payloadOffset, ftyp.end));
    var hasJxlBrand = String.fromCharCodes(payload.sublist(0, 4)) == 'jxl ';
    for (var offset = 8; !hasJxlBrand && offset < payload.length; offset += 4) {
      hasJxlBrand =
          String.fromCharCodes(payload.sublist(offset, offset + 4)) == 'jxl ';
    }
    if (!hasJxlBrand) {
      throw const MalformedAssetFormatException(
        'The JPEG XL ftyp box does not declare the jxl brand.',
      );
    }
  }

  Future<bool> _isC2paJumb(
    RandomAccessByteSource source,
    IsoBmffBox box,
  ) async {
    if (box.payloadLength < 30) return false;
    final peek = await source.read(
      ByteRange(box.payloadOffset, box.payloadOffset + 30),
    );
    if (String.fromCharCodes(peek.sublist(4, 8)) != 'jumd') return false;
    final innerSize = readUint32Be(peek, 0);
    if (innerSize < 30 || innerSize > box.payloadLength) {
      throw const MalformedAssetFormatException(
        'The JPEG XL JUMBF description box has invalid bounds.',
      );
    }
    if (peek[24] & 0x03 != 0x03) return false;
    final labelEnd = peek.indexOf(0, 25);
    if (labelEnd < 0) {
      throw const MalformedAssetFormatException(
        'The JPEG XL JUMBF label is unterminated.',
      );
    }
    return String.fromCharCodes(peek.sublist(25, labelEnd)) == 'c2pa';
  }

  void _validateManifestBytes(Uint8List manifest) {
    if (manifest.length < 38) {
      throw const MalformedAssetFormatException(
        'A JPEG XL manifest must be a complete C2PA jumb box.',
      );
    }
    final size32 = readUint32Be(manifest, 0);
    if (String.fromCharCodes(manifest.sublist(4, 8)) != 'jumb') {
      throw const MalformedAssetFormatException(
        'A JPEG XL manifest must use a top-level jumb box.',
      );
    }
    var headerSize = 8;
    late int size;
    if (size32 == 0) {
      size = manifest.length;
    } else if (size32 == 1) {
      if (manifest.length < 16) {
        throw const MalformedAssetFormatException(
          'The JPEG XL manifest extended header is truncated.',
        );
      }
      size = _uint64(Uint8List.sublistView(manifest, 8, 16));
      headerSize = 16;
    } else {
      size = size32;
    }
    if (size != manifest.length || size < headerSize + 30) {
      throw const MalformedAssetFormatException(
        'The JPEG XL manifest jumb box has invalid bounds.',
      );
    }
    final payload = Uint8List.sublistView(manifest, headerSize);
    if (String.fromCharCodes(payload.sublist(4, 8)) != 'jumd' ||
        readUint32Be(payload, 0) < 30 ||
        readUint32Be(payload, 0) > payload.length ||
        payload[24] & 0x03 != 0x03) {
      throw const MalformedAssetFormatException(
        'The JPEG XL manifest lacks a valid JUMBF description.',
      );
    }
    final labelEnd = payload.indexOf(0, 25);
    if (labelEnd < 0 ||
        String.fromCharCodes(payload.sublist(25, labelEnd)) != 'c2pa') {
      throw const MalformedAssetFormatException(
        'The JPEG XL JUMBF description is not labelled c2pa.',
      );
    }
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
        'A JPEG XL 64-bit box size exceeds the supported address range.',
      ));

  static bool _equal(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }
}

final class _JpegXlInspection {
  const _JpegXlInspection({
    required this.sourceLength,
    required this.boxes,
    required this.ftyp,
    required this.insertionOffset,
    required this.manifest,
    required this.xmp,
  });

  final int sourceLength;
  final List<IsoBmffBox> boxes;
  final IsoBmffBox ftyp;
  final int insertionOffset;
  final IsoBmffBox? manifest;
  final _JpegXlXmp? xmp;
}

final class _JpegXlXmp {
  const _JpegXlXmp({
    required this.box,
    required this.dataRange,
    required this.compressed,
  });

  final IsoBmffBox box;
  final ByteRange dataRange;
  final bool compressed;
}
