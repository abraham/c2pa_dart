import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../byte_reader.dart';
import '../errors.dart';
import '../manifest_mutation.dart';
import '../xmp.dart';
import '../xmp_remote_reference.dart';

/// An MP3 handler for C2PA data stored in ID3v2 frames.
///
/// The manifest is stored in a GEOB frame with MIME type `application/c2pa`.
/// XMP metadata is stored in a PRIV frame owned by `XMP`.
final class Mp3AssetHandler
    with ManifestRewrite
    implements
        AssetHandler,
        XmpMetadataProvider,
        RemoteManifestReferenceProvider {
  /// Creates an MP3 handler with ID3 frame and byte limits.
  const Mp3AssetHandler({
    this.maxManifestSize = 64 * 1024 * 1024,
    this.maxSourceSize = 256 * 1024 * 1024,
    this.maxOutputSize = 256 * 1024 * 1024,
    this.maxFrameCount = 65536,
    this.allowNonMpegPayload = false,
    this.maxXmpSize = 4 * 1024 * 1024,
    this.maxRemoteReferenceLength = 64 * 1024,
  });

  static const String _mimeType = 'application/c2pa';
  static const String _deprecatedMimeType = 'application/x-c2pa-manifest-store';
  static const String _fileName = 'c2pa';
  static const String _description = 'c2pa manifest store';
  static const String _xmpOwner = 'XMP';

  /// Maximum embedded C2PA manifest size in bytes.
  final int maxManifestSize;

  /// Maximum source asset size in bytes.
  final int maxSourceSize;

  /// Maximum rewritten asset size in bytes.
  final int maxOutputSize;

  /// Maximum number of ID3 frames parsed from the leading tag.
  final int maxFrameCount;

  /// Whether non-MPEG payloads after ID3 are accepted, as for FLAC.
  final bool allowNonMpegPayload;

  /// Maximum XMP packet size in bytes.
  final int maxXmpSize;

  /// Maximum UTF-8 length of a remote reference in bytes.
  final int maxRemoteReferenceLength;

  @override
  String get name => 'MP3';

  @override
  AssetFormat get format => AssetFormat.mp3;

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
    mimeTypes: <String>[
      'audio/mpeg',
      'audio/mp3',
      'audio/x-mp3',
      'audio/mpeg3',
    ],
    fileExtensions: <String>['mp3'],
  );

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    final length = await source.length;
    if (length < 2) return false;
    final prefix = await source.read(ByteRange(0, length < 3 ? 2 : 3));
    return (prefix.length >= 3 &&
            prefix[0] == 0x49 &&
            prefix[1] == 0x44 &&
            prefix[2] == 0x33) ||
        (prefix[0] == 0xff && (prefix[1] & 0xe0) == 0xe0);
  }

  @override
  Future<Uint8List> extractManifest(RandomAccessByteSource source) async {
    final tag = await _inspect(source);
    final frame = tag.manifestFrame;
    if (frame == null) throw const ManifestNotFoundException(AssetFormat.mp3);
    return frame.data!;
  }

  @override
  Future<String?> readXmp(RandomAccessByteSource source) async {
    final frame = (await _inspect(source)).xmpFrame;
    if (frame == null) return null;
    try {
      return utf8.decode(frame.data!, allowMalformed: false);
    } on FormatException {
      throw const MalformedAssetFormatException(
        'ID3 XMP metadata is not valid UTF-8.',
      );
    }
  }

  @override
  Future<String?> readRemoteManifestReference(
    RandomAccessByteSource source,
  ) async {
    final frame = (await _inspect(source)).xmpFrame;
    if (frame == null) return null;
    return XmpRemoteReferenceEditor.parse(
      frame.data!,
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
    final tag = await _inspect(source);
    final original =
        tag.xmpFrame?.data ??
        Uint8List.fromList(utf8.encode(XmpRemoteReferenceEditor.minimalPacket));
    final updated = XmpRemoteReferenceEditor.parse(
      original,
      maxLength: maxXmpSize,
    ).update(reference, maxLength: maxXmpSize);
    await _rewriteXmp(source, output, tag, updated);
  }

  @override
  Future<void> removeRemoteManifestReference(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) async {
    final tag = await _inspect(source);
    final frame = tag.xmpFrame;
    if (frame == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.mp3);
    }
    final editor = XmpRemoteReferenceEditor.parse(
      frame.data!,
      maxLength: maxXmpSize,
    );
    if (editor.value == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.mp3);
    }
    await _rewriteXmp(
      source,
      output,
      tag,
      editor.remove(maxLength: maxXmpSize),
    );
  }

  Future<void> _rewriteXmp(
    RandomAccessByteSource source,
    WritableByteSink output,
    _Id3Tag tag,
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
    final version = tag.hasId3 ? tag.version : 4;
    final globalUnsync = tag.hasId3 && (tag.flags & 0x80) != 0;
    final frame = _encodePrivFrame(xmp, version, globalUnsync);
    final existing = tag.xmpFrame;
    final originalBodyLength = tag.hasId3 ? tag.tagEnd - 10 : 0;
    final bodyLength =
        originalBodyLength - (existing?.length ?? 0) + frame.length;
    if (bodyLength > 0x0fffffff) {
      throw AssetLimitExceededException(limit: 0x0fffffff, actual: bodyLength);
    }
    final outputLength = tag.sourceLength - tag.tagEnd + 10 + bodyLength;
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }
    final staged = MemoryByteSink();
    await staged.append(
      _id3Header(version, tag.hasId3 ? tag.flags : 0, bodyLength),
    );
    final bodyStart = tag.hasId3 ? 10 : 0;
    if (existing == null) {
      await _copy(source, staged, bodyStart, tag.paddingStart);
    } else {
      await _copy(source, staged, bodyStart, existing.offset);
      await _copy(source, staged, existing.end, tag.paddingStart);
    }
    await staged.append(frame);
    if (tag.hasId3) {
      await _copy(source, staged, tag.paddingStart, tag.tagEnd);
    }
    await _copy(source, staged, tag.tagEnd, tag.sourceLength);
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'ID3 XMP rewrite produced an unexpected output length.',
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
    final tag = await _inspect(source);
    final existing = tag.manifestFrame;
    if (operation == ManifestMutation.embed && existing != null) {
      throw const ManifestAlreadyExistsException(AssetFormat.mp3);
    }
    if (operation != ManifestMutation.embed && existing == null) {
      throw const ManifestNotFoundException(AssetFormat.mp3);
    }

    final version = tag.hasId3 ? tag.version : 4;
    final globalUnsync = tag.hasId3 && (tag.flags & 0x80) != 0;
    final newFrame = manifest == null
        ? null
        : _encodeGeobFrame(manifest, version, globalUnsync);
    final removedLength = existing?.length ?? 0;
    final originalBodyLength = tag.hasId3 ? tag.tagEnd - 10 : 0;
    final newBodyLength =
        originalBodyLength - removedLength + (newFrame?.length ?? 0);
    final omitEmptyTag =
        manifest == null && newBodyLength == 0 && tag.extendedHeaderEnd == 10;
    if (newBodyLength > 0x0fffffff) {
      throw AssetLimitExceededException(
        limit: 0x0fffffff,
        actual: newBodyLength,
      );
    }
    final outputLength =
        tag.sourceLength - tag.tagEnd + (omitEmptyTag ? 0 : 10 + newBodyLength);
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }

    final staged = MemoryByteSink();
    if (!omitEmptyTag) {
      await staged.append(
        _id3Header(version, tag.hasId3 ? tag.flags : 0, newBodyLength),
      );
      final bodyStart = tag.hasId3 ? 10 : 0;
      final paddingStart = tag.hasId3 ? tag.paddingStart : 0;
      if (existing == null) {
        await _copy(source, staged, bodyStart, paddingStart);
      } else {
        await _copy(source, staged, bodyStart, existing.offset);
        await _copy(source, staged, existing.end, paddingStart);
      }
      if (newFrame != null) await staged.append(newFrame);
      if (tag.hasId3) {
        await _copy(source, staged, paddingStart, tag.tagEnd);
      }
    }
    await _copy(source, staged, tag.tagEnd, tag.sourceLength);
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'ID3 rewrite produced an unexpected output length.',
      );
    }
    await output.append(staged.toBytes());
  }

  Future<_Id3Tag> _inspect(RandomAccessByteSource source) async {
    final sourceLength = await source.length;
    if (sourceLength > maxSourceSize) {
      throw AssetLimitExceededException(
        limit: maxSourceSize,
        actual: sourceLength,
      );
    }
    if (sourceLength < 2) {
      throw TruncatedAssetException(
        expectedLength: 2,
        actualLength: sourceLength,
      );
    }
    final prefixLength = sourceLength < 10 ? sourceLength : 10;
    final header = await source.read(ByteRange(0, prefixLength));
    final hasId3 =
        header.length >= 3 &&
        header[0] == 0x49 &&
        header[1] == 0x44 &&
        header[2] == 0x33;
    if (!hasId3) {
      if (!allowNonMpegPayload &&
          (header[0] != 0xff || (header[1] & 0xe0) != 0xe0)) {
        throw const MalformedAssetFormatException(
          'MP3 data has neither an ID3 tag nor an MPEG frame sync.',
        );
      }
      return _Id3Tag.bare(sourceLength);
    }
    if (header.length < 10) {
      throw TruncatedAssetException(
        expectedLength: 10,
        actualLength: header.length,
      );
    }

    final version = header[3];
    if (version != 3 && version != 4) {
      throw MalformedAssetFormatException(
        'Only ID3v2.3 and ID3v2.4 are supported, found v2.$version.',
      );
    }
    final flags = header[5];
    final allowedFlags = version == 3 ? 0xe0 : 0xf0;
    if ((flags & ~allowedFlags) != 0 || (version == 4 && (flags & 0x10) != 0)) {
      throw const MalformedAssetFormatException(
        'The ID3 header contains unsupported flags.',
      );
    }
    final bodySize = _decodeSyncSafe(header, 6);
    final tagEnd = 10 + bodySize;
    if (tagEnd > sourceLength) {
      throw TruncatedAssetException(
        expectedLength: tagEnd,
        actualLength: sourceLength,
      );
    }

    var position = 10;
    if ((flags & 0x40) != 0) {
      if (tagEnd - position < 4) {
        throw const MalformedAssetFormatException(
          'The ID3 extended header is truncated.',
        );
      }
      final sizeBytes = await source.read(ByteRange(position, position + 4));
      final extensionSize = version == 4
          ? _decodeSyncSafe(sizeBytes, 0)
          : readUint32Be(sizeBytes, 0) + 4;
      if (extensionSize < 6 || extensionSize > tagEnd - position) {
        throw const MalformedAssetFormatException(
          'The ID3 extended header has an invalid size.',
        );
      }
      position += extensionSize;
    }
    final extendedHeaderEnd = position;

    _Id3Frame? manifestFrame;
    _Id3Frame? xmpFrame;
    var frameCount = 0;
    var paddingStart = tagEnd;
    while (position < tagEnd) {
      final remaining = tagEnd - position;
      if (remaining < 10) {
        final tail = await source.read(ByteRange(position, tagEnd));
        if (tail.any((byte) => byte != 0)) {
          throw const MalformedAssetFormatException(
            'The ID3 tag has a truncated frame header.',
          );
        }
        paddingStart = position;
        break;
      }
      final frameHeader = await source.read(ByteRange(position, position + 10));
      if (frameHeader[0] == 0) {
        final padding = await source.read(ByteRange(position, tagEnd));
        if (padding.any((byte) => byte != 0)) {
          throw const MalformedAssetFormatException(
            'ID3 padding contains non-zero bytes.',
          );
        }
        paddingStart = position;
        break;
      }
      if (!_validFrameId(frameHeader)) {
        throw MalformedAssetFormatException(
          'Invalid ID3 frame identifier at offset $position.',
        );
      }
      final statusFlags = frameHeader[8];
      final formatFlags = frameHeader[9];
      if ((version == 3 &&
              ((statusFlags & 0x1f) != 0 || (formatFlags & 0x1f) != 0)) ||
          (version == 4 &&
              ((statusFlags & 0x8f) != 0 || (formatFlags & 0xb0) != 0))) {
        throw const MalformedAssetFormatException(
          'An ID3 frame contains reserved flags.',
        );
      }
      frameCount++;
      if (frameCount > maxFrameCount) {
        throw SegmentLimitExceededException(
          limit: maxFrameCount,
          actual: frameCount,
        );
      }
      final frameSize = version == 4
          ? _decodeSyncSafe(frameHeader, 4)
          : readUint32Be(frameHeader, 4);
      final globallyUnsynchronizedV23 = version == 3 && (flags & 0x80) != 0;
      final decodedV23Body = globallyUnsynchronizedV23
          ? await _readV23UnsynchronizedBody(
              source,
              position + 10,
              tagEnd,
              frameSize,
            )
          : null;
      final frameEnd = decodedV23Body?.physicalEnd ?? position + 10 + frameSize;
      if (frameEnd > tagEnd) {
        throw TruncatedAssetException(
          expectedLength: frameEnd,
          actualLength: tagEnd,
        );
      }
      if (_equalAscii(frameHeader, 0, 'GEOB')) {
        final unsupportedTransforms = version == 3
            ? formatFlags & 0xe0
            : formatFlags & 0x4d;
        if (unsupportedTransforms != 0) {
          throw const MalformedAssetFormatException(
            'A C2PA GEOB frame uses unsupported transforms.',
          );
        }
        final rawBody =
            decodedV23Body?.bytes ??
            await source.read(ByteRange(position + 10, frameEnd));
        final unsynchronized =
            version == 4 &&
            ((flags & 0x80) != 0 || (frameHeader[9] & 0x02) != 0);
        final body = unsynchronized
            ? _decodeUnsynchronization(rawBody)
            : rawBody;
        final parsed = _parseGeob(body);
        if (parsed != null) {
          if (manifestFrame != null) {
            throw const MalformedAssetFormatException(
              'The ID3 tag contains more than one C2PA GEOB frame.',
            );
          }
          if (parsed.length > maxManifestSize) {
            throw AssetLimitExceededException(
              limit: maxManifestSize,
              actual: parsed.length,
            );
          }
          manifestFrame = _Id3Frame(
            offset: position,
            end: frameEnd,
            data: parsed,
          );
        }
      } else if (_equalAscii(frameHeader, 0, 'PRIV')) {
        final unsupportedTransforms = version == 3
            ? formatFlags & 0xe0
            : formatFlags & 0x4d;
        if (unsupportedTransforms != 0) {
          throw const MalformedAssetFormatException(
            'An ID3 PRIV frame uses unsupported transforms.',
          );
        }
        final rawBody =
            decodedV23Body?.bytes ??
            await source.read(ByteRange(position + 10, frameEnd));
        final unsynchronized =
            version == 4 &&
            ((flags & 0x80) != 0 || (frameHeader[9] & 0x02) != 0);
        final body = unsynchronized
            ? _decodeUnsynchronization(rawBody)
            : rawBody;
        final parsed = _parseXmpPriv(body);
        if (parsed != null) {
          if (xmpFrame != null) {
            throw const MalformedAssetFormatException(
              'The ID3 tag contains more than one XMP PRIV frame.',
            );
          }
          if (parsed.length > maxXmpSize) {
            throw AssetLimitExceededException(
              limit: maxXmpSize,
              actual: parsed.length,
            );
          }
          xmpFrame = _Id3Frame(offset: position, end: frameEnd, data: parsed);
        }
      }
      position = frameEnd;
    }
    return _Id3Tag(
      sourceLength: sourceLength,
      hasId3: true,
      version: version,
      flags: flags,
      tagEnd: tagEnd,
      extendedHeaderEnd: extendedHeaderEnd,
      paddingStart: paddingStart,
      manifestFrame: manifestFrame,
      xmpFrame: xmpFrame,
    );
  }

  static Uint8List? _parseGeob(Uint8List body) {
    if (body.isEmpty) {
      throw const MalformedAssetFormatException('A GEOB frame is empty.');
    }
    final encoding = body[0];
    if (encoding != 0 && encoding != 3) {
      throw const MalformedAssetFormatException(
        'C2PA GEOB text must use Latin-1 or UTF-8 encoding.',
      );
    }
    var position = 1;
    final mimeEnd = _findZero(body, position);
    final mime = latin1.decode(body.sublist(position, mimeEnd));
    position = mimeEnd + 1;
    final fileEnd = _findZero(body, position);
    position = fileEnd + 1;
    final descriptionEnd = _findZero(body, position);
    position = descriptionEnd + 1;
    if (mime != _mimeType && mime != _deprecatedMimeType) return null;
    return Uint8List.fromList(body.sublist(position));
  }

  static Uint8List _encodeGeobFrame(
    Uint8List manifest,
    int version,
    bool unsynchronized,
  ) {
    final rawBody = Uint8List.fromList([
      0,
      ...latin1.encode(_mimeType),
      0,
      ...latin1.encode(_fileName),
      0,
      ...latin1.encode(_description),
      0,
      ...manifest,
    ]);
    final body = unsynchronized ? _encodeUnsynchronization(rawBody) : rawBody;
    final output = Uint8List(10 + body.length);
    output.setRange(0, 4, 'GEOB'.codeUnits);
    final size = version == 4
        ? _encodeSyncSafe(body.length)
        : _uint32Bytes(rawBody.length);
    output.setRange(4, 8, size);
    output.setRange(10, output.length, body);
    return output;
  }

  static Uint8List? _parseXmpPriv(Uint8List body) {
    final ownerEnd = _findZero(body, 0);
    if (latin1.decode(body.sublist(0, ownerEnd)) != _xmpOwner) return null;
    return Uint8List.fromList(body.sublist(ownerEnd + 1));
  }

  static Uint8List _encodePrivFrame(
    Uint8List xmp,
    int version,
    bool unsynchronized,
  ) {
    final rawBody = Uint8List.fromList([
      ...latin1.encode(_xmpOwner),
      0,
      ...xmp,
    ]);
    final body = unsynchronized ? _encodeUnsynchronization(rawBody) : rawBody;
    final output = Uint8List(10 + body.length);
    output.setRange(0, 4, 'PRIV'.codeUnits);
    output.setRange(
      4,
      8,
      version == 4
          ? _encodeSyncSafe(body.length)
          : _uint32Bytes(rawBody.length),
    );
    output.setRange(10, output.length, body);
    return output;
  }

  static Uint8List _id3Header(int version, int flags, int bodyLength) =>
      Uint8List.fromList([
        0x49,
        0x44,
        0x33,
        version,
        0,
        flags,
        ..._encodeSyncSafe(bodyLength),
      ]);

  static Uint8List _decodeUnsynchronization(Uint8List bytes) {
    final output = BytesBuilder(copy: false);
    for (var index = 0; index < bytes.length; index++) {
      output.addByte(bytes[index]);
      if (bytes[index] == 0xff &&
          index + 1 < bytes.length &&
          bytes[index + 1] == 0x00) {
        index++;
      }
    }
    return output.takeBytes();
  }

  static Future<_UnsynchronizedBody> _readV23UnsynchronizedBody(
    RandomAccessByteSource source,
    int start,
    int tagEnd,
    int decodedLength,
  ) async {
    final physical = await source.read(ByteRange(start, tagEnd));
    final output = BytesBuilder(copy: false);
    var offset = 0;
    var decoded = 0;
    while (decoded < decodedLength && offset < physical.length) {
      final byte = physical[offset++];
      output.addByte(byte);
      decoded++;
      if (byte == 0xff &&
          offset < physical.length &&
          physical[offset] == 0x00) {
        offset++;
      }
    }
    if (decoded != decodedLength) {
      throw TruncatedAssetException(
        expectedLength: decodedLength,
        actualLength: decoded,
      );
    }
    return _UnsynchronizedBody(
      bytes: output.takeBytes(),
      physicalEnd: start + offset,
    );
  }

  static Uint8List _encodeUnsynchronization(Uint8List bytes) {
    final output = BytesBuilder(copy: false);
    for (var index = 0; index < bytes.length; index++) {
      final byte = bytes[index];
      output.addByte(byte);
      if (byte == 0xff &&
          (index + 1 == bytes.length ||
              bytes[index + 1] == 0x00 ||
              bytes[index + 1] >= 0xe0)) {
        output.addByte(0);
      }
    }
    return output.takeBytes();
  }

  static int _findZero(List<int> bytes, int start) {
    for (var index = start; index < bytes.length; index++) {
      if (bytes[index] == 0) return index;
    }
    throw const MalformedAssetFormatException(
      'A GEOB text field is not terminated.',
    );
  }

  static int _decodeSyncSafe(List<int> bytes, int offset) {
    var value = 0;
    for (var index = 0; index < 4; index++) {
      final byte = bytes[offset + index];
      if ((byte & 0x80) != 0) {
        throw const MalformedAssetFormatException(
          'An ID3 sync-safe integer contains a high bit.',
        );
      }
      value = (value << 7) | byte;
    }
    return value;
  }

  static Uint8List _encodeSyncSafe(int value) {
    if (value < 0 || value > 0x0fffffff) {
      throw AssetLimitExceededException(limit: 0x0fffffff, actual: value);
    }
    return Uint8List.fromList([
      (value >> 21) & 0x7f,
      (value >> 14) & 0x7f,
      (value >> 7) & 0x7f,
      value & 0x7f,
    ]);
  }

  static Uint8List _uint32Bytes(int value) {
    final data = ByteData(4)..setUint32(0, value, Endian.big);
    return data.buffer.asUint8List();
  }

  static bool _validFrameId(List<int> bytes) {
    for (var index = 0; index < 4; index++) {
      final byte = bytes[index];
      if (!((byte >= 0x41 && byte <= 0x5a) || (byte >= 0x30 && byte <= 0x39))) {
        return false;
      }
    }
    return true;
  }

  static bool _equalAscii(List<int> bytes, int offset, String value) {
    final expected = value.codeUnits;
    if (offset + expected.length > bytes.length) return false;
    for (var index = 0; index < expected.length; index++) {
      if (bytes[offset + index] != expected[index]) return false;
    }
    return true;
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
}

final class _Id3Frame {
  const _Id3Frame({
    required this.offset,
    required this.end,
    required this.data,
  });

  final int offset;
  final int end;
  final Uint8List? data;

  int get length => end - offset;
}

final class _UnsynchronizedBody {
  const _UnsynchronizedBody({required this.bytes, required this.physicalEnd});

  final Uint8List bytes;
  final int physicalEnd;
}

final class _Id3Tag {
  const _Id3Tag({
    required this.sourceLength,
    required this.hasId3,
    required this.version,
    required this.flags,
    required this.tagEnd,
    required this.extendedHeaderEnd,
    required this.paddingStart,
    required this.manifestFrame,
    required this.xmpFrame,
  });

  factory _Id3Tag.bare(int sourceLength) => _Id3Tag(
    sourceLength: sourceLength,
    hasId3: false,
    version: 4,
    flags: 0,
    tagEnd: 0,
    extendedHeaderEnd: 0,
    paddingStart: 0,
    manifestFrame: null,
    xmpFrame: null,
  );

  final int sourceLength;
  final bool hasId3;
  final int version;
  final int flags;
  final int tagEnd;
  final int extendedHeaderEnd;
  final int paddingStart;
  final _Id3Frame? manifestFrame;
  final _Id3Frame? xmpFrame;
}
