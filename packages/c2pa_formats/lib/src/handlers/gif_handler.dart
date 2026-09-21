import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../errors.dart';
import '../hash_layout.dart';
import '../xmp.dart';
import '../xmp_remote_reference.dart';

final class GifAssetHandler
    implements
        AssetHandler,
        DataHashLayoutProvider,
        BoxHashLayoutProvider,
        XmpMetadataProvider,
        RemoteManifestReferenceProvider {
  const GifAssetHandler({
    this.maxManifestSize = 64 * 1024 * 1024,
    this.maxSourceSize = 256 * 1024 * 1024,
    this.maxOutputSize = 256 * 1024 * 1024,
    this.maxSubBlockCount = 1024 * 1024,
    this.maxXmpSize = 4 * 1024 * 1024,
    this.maxRemoteReferenceLength = 64 * 1024,
  }) : assert(maxManifestSize > 0),
       assert(maxSourceSize > 0),
       assert(maxOutputSize > 0),
       assert(maxSubBlockCount > 0),
       assert(maxXmpSize > 0),
       assert(maxRemoteReferenceLength > 0);

  static const List<int> _signature = <int>[0x47, 0x49, 0x46];
  static const List<int> _version87a = <int>[0x38, 0x37, 0x61];
  static const List<int> _version89a = <int>[0x38, 0x39, 0x61];
  static const List<int> _applicationIdentifier = <int>[
    0x43,
    0x32,
    0x50,
    0x41,
    0x5f,
    0x47,
    0x49,
    0x46,
  ];
  static const List<int> _authenticationCode = <int>[0x01, 0x00, 0x00];
  static const List<int> _xmpIdentifier = <int>[
    0x58,
    0x4d,
    0x50,
    0x20,
    0x44,
    0x61,
    0x74,
    0x61,
  ];
  static const List<int> _xmpAuthenticationCode = <int>[0x58, 0x4d, 0x50];
  static const int _xmpTrailerLength = 257;

  final int maxManifestSize;
  final int maxSourceSize;
  final int maxOutputSize;
  final int maxSubBlockCount;
  final int maxXmpSize;
  final int maxRemoteReferenceLength;

  @override
  String get name => 'GIF';

  @override
  AssetFormat get format => AssetFormat.gif;

  @override
  AssetHandlerCapabilities get capabilities => const AssetHandlerCapabilities(
    canDetect: true,
    canExtractManifest: true,
    canEmbedManifest: true,
    canReplaceManifest: true,
    canRemoveManifest: true,
    canProvideDataHashLayout: true,
    canProvideBoxHashLayout: true,
    canReadXmp: true,
    canEmbedRemoteReference: true,
    canReadRemoteReference: true,
    canRemoveRemoteReference: true,
    mimeTypes: <String>['image/gif'],
    fileExtensions: <String>['gif'],
  );

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    if (await source.length < 6) return false;
    final header = await source.read(ByteRange(0, 6));
    return _equalRange(header, 0, _signature) &&
        (_equalRange(header, 3, _version87a) ||
            _equalRange(header, 3, _version89a));
  }

  @override
  Future<Uint8List> extractManifest(RandomAccessByteSource source) async {
    final inspection = await _inspect(source, captureManifest: true);
    final manifest = inspection.manifest;
    if (manifest == null) {
      throw const ManifestNotFoundException(AssetFormat.gif);
    }

    return manifest;
  }

  @override
  Future<DataHashLayout> getDataHashLayout(
    RandomAccessByteSource source,
  ) async {
    final inspection = await _inspect(source);
    final manifest = inspection.manifestBlock;
    return DataHashLayout(
      sourceLength: inspection.sourceLength,
      insertionOffset: manifest?.offset ?? inspection.preambleEnd,
      exclusions: manifest == null
          ? const []
          : [
              DataHashExclusion(
                range: ByteRange(manifest.offset, manifest.end),
                kind: DataHashExclusionKind.manifest,
                name: 'C2PA_GIF',
              ),
            ],
    );
  }

  @override
  Future<BoxHashLayout> getBoxHashLayout(RandomAccessByteSource source) async {
    final inspection = await _inspect(source);
    final entries = <BoxHashEntry>[];
    for (final box in inspection.boxes) {
      entries.add(
        BoxHashEntry(names: box.names, range: ByteRange(box.offset, box.end)),
      );
      if (inspection.manifestBlock == null &&
          box.end == inspection.preambleEnd) {
        entries.add(
          BoxHashEntry(
            names: const ['C2PA'],
            range: ByteRange(box.end, box.end),
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
  Future<void> embedManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) => _rewrite(
    source,
    output,
    manifest: manifest,
    operation: _GifMutation.embed,
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
    operation: _GifMutation.replace,
  );

  @override
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) => _rewrite(source, output, operation: _GifMutation.remove);

  @override
  Future<String?> readXmp(RandomAccessByteSource source) async {
    final inspection = await _inspect(source, captureXmp: true);
    final xmp = inspection.xmp;
    if (xmp == null) return null;
    try {
      return utf8.decode(xmp, allowMalformed: false);
    } on FormatException {
      throw const MalformedAssetFormatException(
        'GIF XMP metadata is not valid UTF-8.',
      );
    }
  }

  @override
  Future<String?> readRemoteManifestReference(
    RandomAccessByteSource source,
  ) async {
    final inspection = await _inspect(source, captureXmp: true);
    final xmp = inspection.xmp;
    if (xmp == null) return null;
    return XmpRemoteReferenceEditor.parse(xmp, maxLength: maxXmpSize).value;
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
    final inspection = await _inspect(source, captureXmp: true);
    final original =
        inspection.xmp ??
        Uint8List.fromList(utf8.encode(XmpRemoteReferenceEditor.minimalPacket));
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
    final inspection = await _inspect(source, captureXmp: true);
    final xmp = inspection.xmp;
    if (xmp == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.gif);
    }
    final editor = XmpRemoteReferenceEditor.parse(xmp, maxLength: maxXmpSize);
    if (editor.value == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.gif);
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
    _GifInspection inspection,
    Uint8List xmp,
  ) async {
    if (await output.length != 0) {
      throw const MalformedAssetFormatException(
        'The destination sink must be empty.',
      );
    }
    final encoded = _encodeXmpApplicationExtension(xmp);
    final existing = inspection.xmpBlock;
    final outputLength =
        inspection.sourceLength - (existing?.length ?? 0) + encoded.length;
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }
    final staged = MemoryByteSink();
    final start = existing?.offset ?? inspection.preambleEnd;
    final end = existing?.end ?? start;
    await _copy(source, staged, 0, start);
    await staged.append(encoded);
    await _copy(source, staged, end, inspection.sourceLength);
    await staged.writeAt(3, _version89a);
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'GIF XMP rewrite produced an unexpected output length.',
      );
    }
    await output.append(staged.toBytes());
  }

  Future<void> _rewrite(
    RandomAccessByteSource source,
    WritableByteSink output, {
    required _GifMutation operation,
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
    final existing = inspection.manifestBlock;
    if (operation == _GifMutation.embed && existing != null) {
      throw const ManifestAlreadyExistsException(AssetFormat.gif);
    }
    if (operation != _GifMutation.embed && existing == null) {
      throw const ManifestNotFoundException(AssetFormat.gif);
    }

    final encoded = manifest == null
        ? null
        : _encodeApplicationExtension(manifest);
    final removedLength = existing?.length ?? 0;
    final insertedLength = encoded?.length ?? 0;
    final outputLength =
        inspection.sourceLength - removedLength + insertedLength;
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }

    final insertionOffset = operation == _GifMutation.replace
        ? existing!.offset
        : inspection.preambleEnd;
    final staged = MemoryByteSink();
    if (existing == null) {
      await _copy(source, staged, 0, insertionOffset);
      await staged.append(encoded!);
      await _copy(source, staged, insertionOffset, inspection.sourceLength);
    } else {
      await _copy(source, staged, 0, existing.offset);
      if (encoded != null) await staged.append(encoded);
      await _copy(source, staged, existing.end, inspection.sourceLength);
    }
    if (manifest != null) {
      await staged.writeAt(3, _version89a);
    }
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'GIF rewrite produced an unexpected output length.',
      );
    }
    await output.append(staged.toBytes());
  }

  Future<_GifInspection> _inspect(
    RandomAccessByteSource source, {
    bool captureManifest = false,
    bool captureXmp = false,
  }) async {
    final sourceLength = await source.length;
    if (sourceLength > maxSourceSize) {
      throw AssetLimitExceededException(
        limit: maxSourceSize,
        actual: sourceLength,
      );
    }
    if (sourceLength < 13) {
      throw TruncatedAssetException(
        expectedLength: 13,
        actualLength: sourceLength,
      );
    }

    final cursor = _GifCursor(source, sourceLength);
    final header = await cursor.readBytes(6);
    if (!_equalRange(header, 0, _signature) ||
        (!_equalRange(header, 3, _version87a) &&
            !_equalRange(header, 3, _version89a))) {
      throw const MalformedAssetFormatException(
        'GIF data has an invalid header or version.',
      );
    }
    final boxes = <_GifBox>[
      _GifBox(0, 6, [String.fromCharCodes(header)]),
    ];
    final descriptor = await cursor.readBytes(7);
    boxes.add(const _GifBox(6, 13, ['LSD']));
    final packed = descriptor[4];
    if ((packed & 0x80) != 0) {
      final tableStart = cursor.position;
      final tableSize = 3 * (1 << ((packed & 0x07) + 1));
      await cursor.skip(tableSize);
      boxes.add(_GifBox(tableStart, cursor.position, const []));
    }
    final preambleEnd = cursor.position;

    _GifBlock? manifestBlock;
    Uint8List? manifest;
    _GifBlock? xmpBlock;
    Uint8List? xmp;
    var encounteredImage = false;
    var foundTrailer = false;
    while (cursor.position < sourceLength) {
      final blockStart = cursor.position;
      final introducer = await cursor.readByte();
      switch (introducer) {
        case 0x21:
          final label = await cursor.readByte();
          switch (label) {
            case 0xff:
              final blockSize = await cursor.readByte();
              if (blockSize != 0x0b) {
                throw MalformedAssetFormatException(
                  'GIF application extension at offset $blockStart '
                  'has block size $blockSize instead of 11.',
                );
              }
              final identifier = await cursor.readBytes(8);
              final authentication = await cursor.readBytes(3);
              final isC2pa =
                  _equalBytes(identifier, _applicationIdentifier) &&
                  _equalBytes(authentication, _authenticationCode);
              final isXmp =
                  _equalBytes(identifier, _xmpIdentifier) &&
                  _equalBytes(authentication, _xmpAuthenticationCode);
              if ((isC2pa || isXmp) && encounteredImage) {
                throw const MalformedAssetFormatException(
                  'C2PA and XMP GIF application extensions must precede image data.',
                );
              }
              final decoded = await _readSubBlocks(
                cursor,
                capture: (isC2pa && captureManifest) || (isXmp && captureXmp),
                maxDecodedLength: isC2pa
                    ? maxManifestSize
                    : isXmp
                    ? maxXmpSize + _xmpTrailerLength
                    : null,
              );
              if (isC2pa) {
                if (manifestBlock != null) {
                  throw const MalformedAssetFormatException(
                    'The GIF contains more than one C2PA application extension.',
                  );
                }
                manifestBlock = _GifBlock(blockStart, cursor.position);
                manifest = decoded;
              } else if (isXmp) {
                if (xmpBlock != null) {
                  throw const MalformedAssetFormatException(
                    'The GIF contains more than one XMP application extension.',
                  );
                }
                xmpBlock = _GifBlock(blockStart, cursor.position);
                if (captureXmp) xmp = _decodeGifXmp(decoded!);
              }
              boxes.add(
                _GifBox(blockStart, cursor.position, [
                  isC2pa
                      ? 'C2PA'
                      : isXmp
                      ? 'XMP'
                      : '21FF',
                ]),
              );
            case 0xfe:
              await _readSubBlocks(cursor);
              boxes.add(_GifBox(blockStart, cursor.position, const ['21FE']));
            case 0xf9:
              final blockSize = await cursor.readByte();
              if (blockSize != 4) {
                throw const MalformedAssetFormatException(
                  'A GIF graphic control extension must have size 4.',
                );
              }
              await cursor.skip(4);
              if (await cursor.readByte() != 0) {
                throw const MalformedAssetFormatException(
                  'A GIF graphic control extension is not terminated.',
                );
              }
              boxes.add(_GifBox(blockStart, cursor.position, const ['21F9']));
            case 0x01:
              final blockSize = await cursor.readByte();
              if (blockSize != 12) {
                throw const MalformedAssetFormatException(
                  'A GIF plain text extension must have size 12.',
                );
              }
              await cursor.skip(12);
              await _readSubBlocks(cursor);
              boxes.add(_GifBox(blockStart, cursor.position, const ['2101']));
            default:
              throw MalformedAssetFormatException(
                'Unsupported GIF extension label 0x'
                '${label.toRadixString(16)} at offset $blockStart.',
              );
          }
        case 0x2c:
          encounteredImage = true;
          final imageDescriptor = await cursor.readBytes(9);
          boxes.add(_GifBox(blockStart, cursor.position, const ['2C']));
          final imagePacked = imageDescriptor[8];
          if ((imagePacked & 0x80) != 0) {
            final tableStart = cursor.position;
            final tableSize = 3 * (1 << ((imagePacked & 0x07) + 1));
            await cursor.skip(tableSize);
            boxes.add(_GifBox(tableStart, cursor.position, const []));
          }
          final imageDataStart = cursor.position;
          await cursor.readByte();
          await _readSubBlocks(cursor);
          boxes.add(_GifBox(imageDataStart, cursor.position, const ['TBID']));
        case 0x3b:
          foundTrailer = true;
          boxes.add(_GifBox(blockStart, cursor.position, const ['3B']));
          if (cursor.position != sourceLength) {
            throw const MalformedAssetFormatException(
              'GIF data contains trailing bytes after the trailer.',
            );
          }
        default:
          throw MalformedAssetFormatException(
            'Invalid GIF block introducer 0x'
            '${introducer.toRadixString(16)} at offset $blockStart.',
          );
      }
      if (foundTrailer) break;
    }

    if (!foundTrailer) {
      throw const MalformedAssetFormatException(
        'GIF data is missing the required trailer.',
      );
    }
    return _GifInspection(
      sourceLength: sourceLength,
      preambleEnd: preambleEnd,
      manifestBlock: manifestBlock,
      manifest: manifest,
      xmpBlock: xmpBlock,
      xmp: xmp,
      boxes: boxes,
    );
  }

  Future<Uint8List?> _readSubBlocks(
    _GifCursor cursor, {
    bool capture = false,
    int? maxDecodedLength,
  }) async {
    final builder = capture ? BytesBuilder(copy: false) : null;
    var decodedLength = 0;
    var count = 0;
    while (true) {
      final size = await cursor.readByte();
      if (size == 0) break;
      count++;
      if (count > maxSubBlockCount) {
        throw SegmentLimitExceededException(
          limit: maxSubBlockCount,
          actual: count,
        );
      }
      decodedLength += size;
      if (maxDecodedLength != null && decodedLength > maxDecodedLength) {
        throw AssetLimitExceededException(
          limit: maxDecodedLength,
          actual: decodedLength,
        );
      }
      final bytes = await cursor.readBytes(size);
      builder?.add(bytes);
    }
    return builder?.takeBytes();
  }

  Uint8List _encodeApplicationExtension(Uint8List manifest) {
    return _encodeApplicationData(
      _applicationIdentifier,
      _authenticationCode,
      manifest,
    );
  }

  Uint8List _encodeXmpApplicationExtension(Uint8List xmp) {
    if (xmp.length > maxXmpSize) {
      throw AssetLimitExceededException(limit: maxXmpSize, actual: xmp.length);
    }
    final data = BytesBuilder(copy: false)
      ..add(xmp)
      ..addByte(1);
    for (var value = 255; value >= 0; value--) {
      data.addByte(value);
    }
    return _encodeApplicationData(
      _xmpIdentifier,
      _xmpAuthenticationCode,
      data.takeBytes(),
    );
  }

  Uint8List _encodeApplicationData(
    List<int> identifier,
    List<int> authenticationCode,
    Uint8List data,
  ) {
    final subBlockCount = (data.length + 254) ~/ 255;
    if (subBlockCount > maxSubBlockCount) {
      throw SegmentLimitExceededException(
        limit: maxSubBlockCount,
        actual: subBlockCount,
      );
    }
    final output = BytesBuilder(copy: false)
      ..add(const <int>[0x21, 0xff, 0x0b])
      ..add(identifier)
      ..add(authenticationCode);
    for (var offset = 0; offset < data.length; offset += 255) {
      final remaining = data.length - offset;
      final size = remaining < 255 ? remaining : 255;
      output
        ..addByte(size)
        ..add(data.sublist(offset, offset + size));
    }
    output.addByte(0);
    return output.takeBytes();
  }

  static Uint8List _decodeGifXmp(Uint8List bytes) {
    if (bytes.length < _xmpTrailerLength) {
      throw const MalformedAssetFormatException(
        'The GIF XMP application extension is missing its magic trailer.',
      );
    }
    final trailerStart = bytes.length - _xmpTrailerLength;
    if (bytes[trailerStart] != 1) {
      throw const MalformedAssetFormatException(
        'The GIF XMP magic trailer is invalid.',
      );
    }
    for (var index = 0; index < 256; index++) {
      if (bytes[trailerStart + 1 + index] != 255 - index) {
        throw const MalformedAssetFormatException(
          'The GIF XMP magic trailer is invalid.',
        );
      }
    }
    return Uint8List.fromList(bytes.sublist(0, trailerStart));
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

  static bool _equalBytes(List<int> left, List<int> right) =>
      left.length == right.length && _equalRange(left, 0, right);

  static bool _equalRange(List<int> bytes, int offset, List<int> expected) {
    if (offset + expected.length > bytes.length) return false;
    for (var index = 0; index < expected.length; index++) {
      if (bytes[offset + index] != expected[index]) return false;
    }
    return true;
  }
}

typedef GifHandler = GifAssetHandler;

enum _GifMutation { embed, replace, remove }

final class _GifBlock {
  const _GifBlock(this.offset, this.end);

  final int offset;
  final int end;

  int get length => end - offset;
}

final class _GifInspection {
  const _GifInspection({
    required this.sourceLength,
    required this.preambleEnd,
    required this.manifestBlock,
    required this.manifest,
    required this.xmpBlock,
    required this.xmp,
    required this.boxes,
  });

  final int sourceLength;
  final int preambleEnd;
  final _GifBlock? manifestBlock;
  final Uint8List? manifest;
  final _GifBlock? xmpBlock;
  final Uint8List? xmp;
  final List<_GifBox> boxes;
}

final class _GifBox {
  const _GifBox(this.offset, this.end, this.names);

  final int offset;
  final int end;
  final List<String> names;
}

final class _GifCursor {
  _GifCursor(this.source, this.length);

  static const int _bufferSize = 64 * 1024;

  final RandomAccessByteSource source;
  final int length;
  int position = 0;
  Uint8List _buffer = Uint8List(0);
  int _bufferStart = 0;

  Future<int> readByte() async {
    if (position >= length) {
      throw TruncatedAssetException(
        expectedLength: position + 1,
        actualLength: length,
      );
    }
    if (position < _bufferStart || position >= _bufferStart + _buffer.length) {
      _bufferStart = position;
      final remaining = length - position;
      final readLength = remaining < _bufferSize ? remaining : _bufferSize;
      _buffer = await source.read(
        ByteRange.fromStartAndLength(position, readLength),
      );
    }
    return _buffer[position++ - _bufferStart];
  }

  Future<Uint8List> readBytes(int count) async {
    if (count < 0 || count > length - position) {
      throw TruncatedAssetException(
        expectedLength: position + count,
        actualLength: length,
      );
    }
    final output = Uint8List(count);
    for (var index = 0; index < count; index++) {
      output[index] = await readByte();
    }
    return output;
  }

  Future<void> skip(int count) async {
    if (count < 0 || count > length - position) {
      throw TruncatedAssetException(
        expectedLength: position + count,
        actualLength: length,
      );
    }
    position += count;
  }
}
