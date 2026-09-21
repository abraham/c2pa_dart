import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../errors.dart';
import '../xmp.dart';
import 'mp3_handler.dart';

final class FlacAssetHandler
    implements
        AssetHandler,
        XmpMetadataProvider,
        RemoteManifestReferenceProvider {
  const FlacAssetHandler({
    this.maxManifestSize = 64 * 1024 * 1024,
    this.maxSourceSize = 256 * 1024 * 1024,
    this.maxOutputSize = 256 * 1024 * 1024,
    this.maxMetadataBlocks = 65536,
    this.maxMetadataBlockSize = 0xffffff,
    this.maxId3Frames = 65536,
    this.maxXmpSize = 4 * 1024 * 1024,
    this.maxRemoteReferenceLength = 64 * 1024,
  });

  static const List<int> _signature = <int>[0x66, 0x4c, 0x61, 0x43];

  final int maxManifestSize;
  final int maxSourceSize;
  final int maxOutputSize;
  final int maxMetadataBlocks;
  final int maxMetadataBlockSize;
  final int maxId3Frames;
  final int maxXmpSize;
  final int maxRemoteReferenceLength;

  Mp3AssetHandler get _id3 => Mp3AssetHandler(
    maxManifestSize: maxManifestSize,
    maxSourceSize: maxSourceSize,
    maxOutputSize: maxOutputSize,
    maxFrameCount: maxId3Frames,
    allowNonMpegPayload: true,
    maxXmpSize: maxXmpSize,
    maxRemoteReferenceLength: maxRemoteReferenceLength,
  );

  @override
  String get name => 'FLAC';

  @override
  AssetFormat get format => AssetFormat.flac;

  @override
  AssetHandlerCapabilities get capabilities => const AssetHandlerCapabilities(
    canDetect: true,
    canExtractManifest: true,
    canEmbedManifest: true,
    canReplaceManifest: true,
    canRemoveManifest: true,
    canReadXmp: true,
    canEmbedRemoteReference: true,
    canReadRemoteReference: true,
    canRemoveRemoteReference: true,
    mimeTypes: <String>['audio/flac'],
    fileExtensions: <String>['flac'],
  );

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    final length = await source.length;
    if (length < 4 || length > maxSourceSize) return false;
    final prefix = await source.read(ByteRange(0, length < 10 ? length : 10));
    if (_startsWith(prefix, _signature)) return true;
    if (prefix.length < 10 || !_startsWith(prefix, const [0x49, 0x44, 0x33])) {
      return false;
    }
    final tagSize = _decodeSyncSafe(prefix, 6);
    if (tagSize == null) return false;
    final flacOffset = 10 + tagSize;
    if (flacOffset + 4 > length) return false;
    return _equalBytes(
      await source.read(ByteRange(flacOffset, flacOffset + 4)),
      _signature,
    );
  }

  @override
  Future<Uint8List> extractManifest(RandomAccessByteSource source) async {
    await _inspectFlac(source);
    try {
      return await _id3.extractManifest(source);
    } on ManifestNotFoundException {
      throw const ManifestNotFoundException(AssetFormat.flac);
    }
  }

  @override
  Future<void> embedManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) async {
    await _inspectFlac(source);
    try {
      await _id3.embedManifest(source, manifest, output);
    } on ManifestAlreadyExistsException {
      throw const ManifestAlreadyExistsException(AssetFormat.flac);
    }
  }

  @override
  Future<void> replaceManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) async {
    await _inspectFlac(source);
    try {
      await _id3.replaceManifest(source, manifest, output);
    } on ManifestNotFoundException {
      throw const ManifestNotFoundException(AssetFormat.flac);
    }
  }

  @override
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) async {
    await _inspectFlac(source);
    try {
      await _id3.removeManifest(source, output);
    } on ManifestNotFoundException {
      throw const ManifestNotFoundException(AssetFormat.flac);
    }
  }

  @override
  Future<String?> readXmp(RandomAccessByteSource source) async {
    await _inspectFlac(source);
    return _id3.readXmp(source);
  }

  @override
  Future<String?> readRemoteManifestReference(
    RandomAccessByteSource source,
  ) async {
    await _inspectFlac(source);
    return _id3.readRemoteManifestReference(source);
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
    await _inspectFlac(source);
    await _id3.updateRemoteManifestReference(source, reference, output);
  }

  @override
  Future<void> removeRemoteManifestReference(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) async {
    await _inspectFlac(source);
    try {
      await _id3.removeRemoteManifestReference(source, output);
    } on RemoteManifestReferenceNotFoundException {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.flac);
    }
  }

  Future<void> _inspectFlac(RandomAccessByteSource source) async {
    final sourceLength = await source.length;
    if (sourceLength > maxSourceSize) {
      throw AssetLimitExceededException(
        limit: maxSourceSize,
        actual: sourceLength,
      );
    }
    if (sourceLength < 4) {
      throw TruncatedAssetException(
        expectedLength: 4,
        actualLength: sourceLength,
      );
    }

    var flacOffset = 0;
    final prefixLength = sourceLength < 10 ? sourceLength : 10;
    final prefix = await source.read(ByteRange(0, prefixLength));
    if (_startsWith(prefix, const [0x49, 0x44, 0x33])) {
      if (prefix.length < 10) {
        throw TruncatedAssetException(
          expectedLength: 10,
          actualLength: sourceLength,
        );
      }
      if (prefix[3] != 3 && prefix[3] != 4) {
        throw const MalformedAssetFormatException(
          'Only ID3v2.3 and ID3v2.4 tags are supported.',
        );
      }
      final tagSize = _decodeSyncSafe(prefix, 6);
      if (tagSize == null) {
        throw const MalformedAssetFormatException(
          'The ID3 tag size is not sync-safe.',
        );
      }
      flacOffset = 10 + tagSize;
      if (flacOffset > sourceLength) {
        throw TruncatedAssetException(
          expectedLength: flacOffset,
          actualLength: sourceLength,
        );
      }
    }

    if (flacOffset + 8 > sourceLength) {
      throw TruncatedAssetException(
        expectedLength: flacOffset + 8,
        actualLength: sourceLength,
      );
    }
    if (!_equalBytes(
      await source.read(ByteRange(flacOffset, flacOffset + 4)),
      _signature,
    )) {
      throw const MalformedAssetFormatException(
        'FLAC data is missing the fLaC marker.',
      );
    }

    var offset = flacOffset + 4;
    var blockCount = 0;
    var foundLast = false;
    while (!foundLast) {
      blockCount++;
      if (blockCount > maxMetadataBlocks) {
        throw SegmentLimitExceededException(
          limit: maxMetadataBlocks,
          actual: blockCount,
        );
      }
      if (sourceLength - offset < 4) {
        throw TruncatedAssetException(
          expectedLength: offset + 4,
          actualLength: sourceLength,
        );
      }
      final header = await source.read(ByteRange(offset, offset + 4));
      final type = header[0] & 0x7f;
      if (type == 0x7f) {
        throw const MalformedAssetFormatException(
          'FLAC metadata block type 127 is invalid.',
        );
      }
      final dataLength = (header[1] << 16) | (header[2] << 8) | header[3];
      if (dataLength > maxMetadataBlockSize) {
        throw AssetLimitExceededException(
          limit: maxMetadataBlockSize,
          actual: dataLength,
        );
      }
      final end = offset + 4 + dataLength;
      if (end > sourceLength) {
        throw TruncatedAssetException(
          expectedLength: end,
          actualLength: sourceLength,
        );
      }
      if (blockCount == 1 && (type != 0 || dataLength != 34)) {
        throw const MalformedAssetFormatException(
          'The first FLAC metadata block must be 34-byte STREAMINFO.',
        );
      }
      foundLast = (header[0] & 0x80) != 0;
      offset = end;
    }
  }

  static int? _decodeSyncSafe(List<int> bytes, int offset) {
    if (bytes.length < offset + 4) return null;
    var result = 0;
    for (var index = offset; index < offset + 4; index++) {
      final value = bytes[index];
      if ((value & 0x80) != 0) return null;
      result = (result << 7) | value;
    }
    return result;
  }

  static bool _startsWith(List<int> bytes, List<int> prefix) {
    if (bytes.length < prefix.length) return false;
    for (var index = 0; index < prefix.length; index++) {
      if (bytes[index] != prefix[index]) return false;
    }
    return true;
  }

  static bool _equalBytes(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }
}
