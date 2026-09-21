import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../errors.dart';
import '../hash_layout.dart';
import '../xmp.dart';
import '../xmp_remote_reference.dart';

final class RiffAssetHandler
    implements
        AssetHandler,
        DataHashLayoutProvider,
        BoxHashLayoutProvider,
        XmpMetadataProvider,
        RemoteManifestReferenceProvider {
  const RiffAssetHandler({
    required this.format,
    this.maxManifestSize = 64 * 1024 * 1024,
    this.maxSourceSize = 256 * 1024 * 1024,
    this.maxOutputSize = 256 * 1024 * 1024,
    this.maxChunkCount = 1024 * 1024,
    this.maxXmpSize = 4 * 1024 * 1024,
    this.maxRemoteReferenceLength = 64 * 1024,
  }) : assert(
         format == AssetFormat.webp ||
             format == AssetFormat.wav ||
             format == AssetFormat.avi,
       ),
       assert(maxManifestSize > 0),
       assert(maxSourceSize > 0),
       assert(maxOutputSize > 0),
       assert(maxChunkCount > 0),
       assert(maxXmpSize > 0),
       assert(maxRemoteReferenceLength > 0);

  static const List<int> _riff = <int>[0x52, 0x49, 0x46, 0x46];
  static const List<int> _c2pa = <int>[0x43, 0x32, 0x50, 0x41];
  static const List<int> _xmp = <int>[0x58, 0x4d, 0x50, 0x20];
  static const List<int> _vp8x = <int>[0x56, 0x50, 0x38, 0x58];
  static const List<int> _vp8 = <int>[0x56, 0x50, 0x38, 0x20];
  static const List<int> _vp8l = <int>[0x56, 0x50, 0x38, 0x4c];
  static const List<int> _webp = <int>[0x57, 0x45, 0x42, 0x50];
  static const List<int> _wave = <int>[0x57, 0x41, 0x56, 0x45];
  static const List<int> _avi = <int>[0x41, 0x56, 0x49, 0x20];
  static const List<int> _avix = <int>[0x41, 0x56, 0x49, 0x58];
  static const int _maximumChunkSize = 0xffffffff;

  @override
  final AssetFormat format;
  final int maxManifestSize;
  final int maxSourceSize;
  final int maxOutputSize;
  final int maxChunkCount;
  final int maxXmpSize;
  final int maxRemoteReferenceLength;

  @override
  String get name => switch (format) {
    AssetFormat.webp => 'WebP',
    AssetFormat.wav => 'WAV',
    AssetFormat.avi => 'AVI',
    _ => 'RIFF',
  };

  @override
  AssetHandlerCapabilities get capabilities => switch (format) {
    AssetFormat.webp => const AssetHandlerCapabilities(
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
      mimeTypes: <String>['image/webp', 'image/x-webp'],
      fileExtensions: <String>['webp'],
    ),
    AssetFormat.wav => const AssetHandlerCapabilities(
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
      mimeTypes: <String>[
        'audio/wav',
        'audio/wave',
        'audio/x-wav',
        'audio/vnd.wave',
      ],
      fileExtensions: <String>['wav'],
    ),
    AssetFormat.avi => const AssetHandlerCapabilities(
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
      mimeTypes: <String>[
        'application/x-troff-msvideo',
        'video/avi',
        'video/msvideo',
        'video/x-msvideo',
      ],
      fileExtensions: <String>['avi'],
    ),
    _ => throw StateError('Unsupported RIFF format'),
  };

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    if (await source.length < 12) return false;
    final header = await source.read(ByteRange(0, 12));
    return _equalRange(header, 0, _riff) && _equalRange(header, 8, _formType);
  }

  @override
  Future<Uint8List> extractManifest(RandomAccessByteSource source) async {
    final inspection = await _inspect(source);
    final manifest = inspection.manifestChunk;
    if (manifest == null) {
      throw ManifestNotFoundException(format);
    }

    return source.read(
      ByteRange.fromStartAndLength(manifest.dataOffset, manifest.dataLength),
    );
  }

  @override
  Future<DataHashLayout> getDataHashLayout(
    RandomAccessByteSource source,
  ) async {
    final inspection = await _inspect(source);
    final manifest = inspection.manifestChunk;
    return DataHashLayout(
      sourceLength: inspection.sourceLength,
      insertionOffset: manifest?.offset ?? inspection.firstRiff.end,
      exclusions: manifest == null
          ? const []
          : [
              DataHashExclusion(
                range: ByteRange(manifest.offset, manifest.end),
                kind: DataHashExclusionKind.manifest,
                name: 'C2PA',
              ),
            ],
    );
  }

  @override
  Future<BoxHashLayout> getBoxHashLayout(RandomAccessByteSource source) async {
    throw UnsupportedHashLayoutException(format, HashLayoutKind.boxHash);
  }

  @override
  Future<void> embedManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) => _rewrite(
    source,
    output,
    manifest: manifest,
    operation: _RiffMutation.embed,
  );

  @override
  Future<void> replaceManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) => _rewrite(
    source,
    output,
    manifest: manifest,
    operation: _RiffMutation.replace,
  );

  @override
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) => _rewrite(source, output, operation: _RiffMutation.remove);

  @override
  Future<String?> readXmp(RandomAccessByteSource source) async {
    final inspection = await _inspect(source);
    final chunk = inspection.xmpChunk;
    if (chunk == null) return null;
    final bytes = await source.read(
      ByteRange.fromStartAndLength(chunk.dataOffset, chunk.dataLength),
    );
    try {
      return utf8.decode(bytes, allowMalformed: false).trimRight();
    } on FormatException {
      throw MalformedAssetFormatException(
        '${format.name} XMP metadata is not valid UTF-8.',
      );
    }
  }

  @override
  Future<String?> readRemoteManifestReference(
    RandomAccessByteSource source,
  ) async {
    final xmp = await readXmp(source);
    if (xmp == null) return null;
    return XmpRemoteReferenceEditor.parse(
      Uint8List.fromList(utf8.encode(xmp)),
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
    final existing = inspection.xmpChunk;
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
      _normalizeXmpPayload(original),
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
    final existing = inspection.xmpChunk;
    if (existing == null) {
      throw RemoteManifestReferenceNotFoundException(format);
    }
    final bytes = await source.read(
      ByteRange.fromStartAndLength(existing.dataOffset, existing.dataLength),
    );
    final editor = XmpRemoteReferenceEditor.parse(
      _normalizeXmpPayload(bytes),
      maxLength: maxXmpSize,
    );
    if (editor.value == null) {
      throw RemoteManifestReferenceNotFoundException(format);
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
    _RiffInspection inspection,
    Uint8List xmp,
  ) async {
    if (await output.length != 0) {
      throw const MalformedAssetFormatException(
        'The destination sink must be empty.',
      );
    }
    final paddedXmp = xmp.length.isEven
        ? xmp
        : Uint8List.fromList(<int>[...xmp, 0x20]);
    if (paddedXmp.length > maxXmpSize) {
      throw AssetLimitExceededException(
        limit: maxXmpSize,
        actual: paddedXmp.length,
      );
    }
    final encoded = _encodeNamedChunk(_xmp, paddedXmp);
    final existing = inspection.xmpChunk;
    final patches = <_RiffPatch>[
      _RiffPatch(
        existing?.offset ??
            inspection.manifestChunk?.offset ??
            inspection.firstRiff.end,
        existing?.end ??
            inspection.manifestChunk?.offset ??
            inspection.firstRiff.end,
        encoded,
      ),
    ];
    if (format == AssetFormat.webp) {
      final vp8x = inspection.vp8xChunk;
      if (vp8x != null) {
        final flags = await source.read(
          ByteRange(vp8x.dataOffset, vp8x.dataOffset + 1),
        );
        patches.add(
          _RiffPatch(
            vp8x.dataOffset,
            vp8x.dataOffset + 1,
            Uint8List.fromList(<int>[flags.single | 0x04]),
          ),
        );
      } else {
        patches.add(
          _RiffPatch(12, 12, await _createVp8xChunk(source, inspection)),
        );
      }
    }
    patches.sort((left, right) => left.start.compareTo(right.start));
    var delta = 0;
    for (final patch in patches) {
      delta += patch.bytes.length - (patch.end - patch.start);
    }
    final outputLength = inspection.sourceLength + delta;
    final newRiffSize = inspection.firstRiff.declaredSize + delta;
    if (outputLength > maxOutputSize || newRiffSize > _maximumChunkSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize < _maximumChunkSize
            ? maxOutputSize
            : _maximumChunkSize,
        actual: outputLength,
      );
    }
    final staged = MemoryByteSink();
    var cursor = 0;
    for (final patch in patches) {
      if (patch.start < cursor) {
        throw const MalformedAssetFormatException(
          'RIFF XMP rewrite patches overlap.',
        );
      }
      await _copy(source, staged, cursor, patch.start);
      await staged.append(patch.bytes);
      cursor = patch.end;
    }
    await _copy(source, staged, cursor, inspection.sourceLength);
    final sizeBytes = ByteData(4)..setUint32(0, newRiffSize, Endian.little);
    await staged.writeAt(4, sizeBytes.buffer.asUint8List());
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'RIFF XMP rewrite produced an unexpected output length.',
      );
    }
    await output.append(staged.toBytes());
  }

  Future<Uint8List> _createVp8xChunk(
    RandomAccessByteSource source,
    _RiffInspection inspection,
  ) async {
    final image = inspection.imageChunk;
    if (image == null) {
      throw const MalformedAssetFormatException(
        'WebP requires VP8, VP8L, or VP8X image metadata.',
      );
    }
    final bytes = await source.read(
      ByteRange.fromStartAndLength(image.dataOffset, image.dataLength),
    );
    late int width;
    late int height;
    if (_equalBytes(image.id, _vp8l)) {
      if (bytes.length < 5 || bytes[0] != 0x2f) {
        throw const MalformedAssetFormatException(
          'The WebP VP8L dimensions are malformed.',
        );
      }
      final packed = ByteData.sublistView(bytes).getUint32(1, Endian.little);
      width = (packed & 0x3fff) + 1;
      height = ((packed >> 14) & 0x3fff) + 1;
    } else {
      if (bytes.length < 10 ||
          bytes[3] != 0x9d ||
          bytes[4] != 0x01 ||
          bytes[5] != 0x2a) {
        throw const MalformedAssetFormatException(
          'The WebP VP8 dimensions are malformed.',
        );
      }
      width = (bytes[6] | bytes[7] << 8) & 0x3fff;
      height = (bytes[8] | bytes[9] << 8) & 0x3fff;
    }
    final payload = Uint8List(10);
    payload[0] = 0x04;
    payload[4] = (width - 1) & 0xff;
    payload[5] = ((width - 1) >> 8) & 0xff;
    payload[6] = ((width - 1) >> 16) & 0xff;
    payload[7] = (height - 1) & 0xff;
    payload[8] = ((height - 1) >> 8) & 0xff;
    payload[9] = ((height - 1) >> 16) & 0xff;
    return _encodeNamedChunk(_vp8x, payload);
  }

  List<int> get _formType => switch (format) {
    AssetFormat.webp => _webp,
    AssetFormat.wav => _wave,
    AssetFormat.avi => _avi,
    _ => throw StateError('Unsupported RIFF format'),
  };

  Future<void> _rewrite(
    RandomAccessByteSource source,
    WritableByteSink output, {
    required _RiffMutation operation,
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
      if (manifest.length > _maximumChunkSize) {
        throw AssetLimitExceededException(
          limit: _maximumChunkSize,
          actual: manifest.length,
        );
      }
    }

    final inspection = await _inspect(source);
    final existing = inspection.manifestChunk;
    if (operation == _RiffMutation.embed && existing != null) {
      throw ManifestAlreadyExistsException(format);
    }
    if (operation != _RiffMutation.embed && existing == null) {
      throw ManifestNotFoundException(format);
    }

    final encoded = manifest == null ? null : _encodeChunk(manifest);
    final removedLength = existing?.totalLength ?? 0;
    final insertedLength = encoded?.length ?? 0;
    final newRiffSize =
        inspection.firstRiff.declaredSize - removedLength + insertedLength;
    if (newRiffSize > _maximumChunkSize) {
      throw AssetLimitExceededException(
        limit: _maximumChunkSize,
        actual: newRiffSize,
      );
    }
    final outputLength =
        inspection.sourceLength - removedLength + insertedLength;
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }

    final staged = MemoryByteSink();
    final insertionOffset = inspection.firstRiff.end;
    if (existing == null) {
      await _copy(source, staged, 0, insertionOffset);
      await staged.append(encoded!);
      await _copy(source, staged, insertionOffset, inspection.sourceLength);
    } else {
      await _copy(source, staged, 0, existing.offset);
      await _copy(source, staged, existing.end, insertionOffset);
      if (encoded != null) await staged.append(encoded);
      await _copy(source, staged, insertionOffset, inspection.sourceLength);
    }
    final sizeBytes = ByteData(4)..setUint32(0, newRiffSize, Endian.little);
    await staged.writeAt(4, sizeBytes.buffer.asUint8List());
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'RIFF rewrite produced an unexpected output length.',
      );
    }
    await output.append(staged.toBytes());
  }

  Future<_RiffInspection> _inspect(RandomAccessByteSource source) async {
    final sourceLength = await source.length;
    if (sourceLength > maxSourceSize) {
      throw AssetLimitExceededException(
        limit: maxSourceSize,
        actual: sourceLength,
      );
    }
    final firstRiff = await _parseRiff(
      source,
      sourceLength,
      0,
      expectedForm: _formType,
      collectManifest: true,
    );
    var offset = firstRiff.end;
    if (format == AssetFormat.avi) {
      while (offset < sourceLength) {
        final additional = await _parseRiff(
          source,
          sourceLength,
          offset,
          expectedForm: _avix,
        );
        offset = additional.end;
      }
    } else if (offset != sourceLength) {
      throw const MalformedAssetFormatException(
        'The RIFF asset contains trailing data outside its root chunk.',
      );
    }
    if (offset != sourceLength) {
      throw const MalformedAssetFormatException(
        'The AVI contains malformed trailing RIFF data.',
      );
    }
    if (firstRiff.manifestChunks.length > 1) {
      throw const MalformedAssetFormatException(
        'The RIFF asset contains more than one C2PA chunk.',
      );
    }
    if (firstRiff.xmpChunks.length > 1) {
      throw const MalformedAssetFormatException(
        'The RIFF asset contains more than one XMP chunk.',
      );
    }
    return _RiffInspection(
      sourceLength: sourceLength,
      firstRiff: firstRiff,
      manifestChunk: firstRiff.manifestChunks.firstOrNull,
      xmpChunk: firstRiff.xmpChunks.firstOrNull,
      vp8xChunk: firstRiff.vp8xChunk,
      imageChunk: firstRiff.imageChunk,
    );
  }

  Future<_RiffContainer> _parseRiff(
    RandomAccessByteSource source,
    int sourceLength,
    int offset, {
    required List<int> expectedForm,
    bool collectManifest = false,
  }) async {
    if (sourceLength - offset < 12) {
      throw TruncatedAssetException(
        expectedLength: offset + 12,
        actualLength: sourceLength,
      );
    }
    final header = await source.read(ByteRange(offset, offset + 12));
    if (!_equalRange(header, 0, _riff)) {
      throw MalformedAssetFormatException('Expected RIFF at offset $offset.');
    }
    final declaredSize = _uint32Little(header, 4);
    if (declaredSize < 4) {
      throw const MalformedAssetFormatException(
        'A RIFF chunk must include a four-byte form type.',
      );
    }
    if (!_equalRange(header, 8, expectedForm)) {
      throw const MalformedAssetFormatException(
        'The RIFF asset has an unexpected form type.',
      );
    }
    final end = offset + 8 + declaredSize;
    if (end > sourceLength) {
      throw TruncatedAssetException(
        expectedLength: end,
        actualLength: sourceLength,
      );
    }
    if (declaredSize.isOdd) {
      throw const MalformedAssetFormatException(
        'A RIFF container must have an even declared size.',
      );
    }

    final manifests = <_RiffChunk>[];
    final xmpChunks = <_RiffChunk>[];
    _RiffChunk? vp8xChunk;
    _RiffChunk? imageChunk;
    var chunkOffset = offset + 12;
    var chunkCount = 0;
    while (chunkOffset < end) {
      chunkCount++;
      if (chunkCount > maxChunkCount) {
        throw SegmentLimitExceededException(
          limit: maxChunkCount,
          actual: chunkCount,
        );
      }
      if (end - chunkOffset < 8) {
        throw TruncatedAssetException(
          expectedLength: chunkOffset + 8,
          actualLength: end,
        );
      }
      final chunkHeader = await source.read(
        ByteRange(chunkOffset, chunkOffset + 8),
      );
      final dataLength = _uint32Little(chunkHeader, 4);
      final paddedLength = dataLength + (dataLength & 1);
      final chunkEnd = chunkOffset + 8 + paddedLength;
      if (chunkEnd > end) {
        throw TruncatedAssetException(
          expectedLength: chunkEnd,
          actualLength: end,
        );
      }
      if (collectManifest && _equalRange(chunkHeader, 0, _c2pa)) {
        if (dataLength > maxManifestSize) {
          throw AssetLimitExceededException(
            limit: maxManifestSize,
            actual: dataLength,
          );
        }
        manifests.add(
          _RiffChunk(
            id: _c2pa,
            offset: chunkOffset,
            end: chunkEnd,
            dataOffset: chunkOffset + 8,
            dataLength: dataLength,
          ),
        );
      } else if (collectManifest && _equalRange(chunkHeader, 0, _xmp)) {
        if (dataLength > maxXmpSize) {
          throw AssetLimitExceededException(
            limit: maxXmpSize,
            actual: dataLength,
          );
        }
        xmpChunks.add(
          _RiffChunk(
            id: _xmp,
            offset: chunkOffset,
            end: chunkEnd,
            dataOffset: chunkOffset + 8,
            dataLength: dataLength,
          ),
        );
      } else if (collectManifest && _equalRange(chunkHeader, 0, _vp8x)) {
        vp8xChunk ??= _RiffChunk(
          id: _vp8x,
          offset: chunkOffset,
          end: chunkEnd,
          dataOffset: chunkOffset + 8,
          dataLength: dataLength,
        );
      } else if (collectManifest &&
          imageChunk == null &&
          (_equalRange(chunkHeader, 0, _vp8) ||
              _equalRange(chunkHeader, 0, _vp8l))) {
        imageChunk = _RiffChunk(
          id: Uint8List.fromList(chunkHeader.sublist(0, 4)),
          offset: chunkOffset,
          end: chunkEnd,
          dataOffset: chunkOffset + 8,
          dataLength: dataLength,
        );
      }
      chunkOffset = chunkEnd;
    }
    if (chunkOffset != end) {
      throw const MalformedAssetFormatException(
        'RIFF child chunks do not fill the declared container size.',
      );
    }
    return _RiffContainer(
      offset: offset,
      end: end,
      declaredSize: declaredSize,
      manifestChunks: manifests,
      xmpChunks: xmpChunks,
      vp8xChunk: vp8xChunk,
      imageChunk: imageChunk,
    );
  }

  static Uint8List _encodeChunk(Uint8List manifest) {
    return _encodeNamedChunk(_c2pa, manifest);
  }

  static Uint8List _encodeNamedChunk(List<int> id, Uint8List payload) {
    final paddedLength = payload.length + (payload.length & 1);
    final output = Uint8List(8 + paddedLength);
    output.setRange(0, 4, id);
    final data = ByteData.sublistView(output)
      ..setUint32(4, payload.length, Endian.little);
    output.setRange(8, 8 + payload.length, payload);
    return data.buffer.asUint8List();
  }

  static Future<void> _copy(
    RandomAccessByteSource source,
    WritableByteSink output,
    int start,
    int end,
  ) async {
    if (start == end) return;
    await copyByteRange(
      source,
      output,
      ByteRange(start, end),
      chunkSize: 64 * 1024,
    );
  }

  static int _uint32Little(List<int> bytes, int offset) =>
      bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24);

  static bool _equalRange(List<int> bytes, int offset, List<int> expected) {
    if (offset + expected.length > bytes.length) return false;
    for (var index = 0; index < expected.length; index++) {
      if (bytes[offset + index] != expected[index]) return false;
    }
    return true;
  }

  static bool _equalBytes(List<int> left, List<int> right) =>
      left.length == right.length && _equalRange(left, 0, right);

  Uint8List _normalizeXmpPayload(Uint8List bytes) {
    try {
      return Uint8List.fromList(utf8.encode(utf8.decode(bytes).trimRight()));
    } on FormatException {
      throw MalformedAssetFormatException(
        '${format.name} XMP metadata is not valid UTF-8.',
      );
    }
  }
}

enum _RiffMutation { embed, replace, remove }

final class _RiffChunk {
  const _RiffChunk({
    required this.id,
    required this.offset,
    required this.end,
    required this.dataOffset,
    required this.dataLength,
  });

  final List<int> id;
  final int offset;
  final int end;
  final int dataOffset;
  final int dataLength;

  int get totalLength => end - offset;
}

final class _RiffContainer {
  const _RiffContainer({
    required this.offset,
    required this.end,
    required this.declaredSize,
    required this.manifestChunks,
    required this.xmpChunks,
    required this.vp8xChunk,
    required this.imageChunk,
  });

  final int offset;
  final int end;
  final int declaredSize;
  final List<_RiffChunk> manifestChunks;
  final List<_RiffChunk> xmpChunks;
  final _RiffChunk? vp8xChunk;
  final _RiffChunk? imageChunk;
}

final class _RiffInspection {
  const _RiffInspection({
    required this.sourceLength,
    required this.firstRiff,
    required this.manifestChunk,
    required this.xmpChunk,
    required this.vp8xChunk,
    required this.imageChunk,
  });

  final int sourceLength;
  final _RiffContainer firstRiff;
  final _RiffChunk? manifestChunk;
  final _RiffChunk? xmpChunk;
  final _RiffChunk? vp8xChunk;
  final _RiffChunk? imageChunk;
}

final class _RiffPatch {
  const _RiffPatch(this.start, this.end, this.bytes);

  final int start;
  final int end;
  final Uint8List bytes;
}
