import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../byte_compare.dart';
import '../errors.dart';
import '../hash_layout.dart';
import '../xmp.dart';
import '../xmp_remote_reference.dart';

/// A PNG handler for C2PA `caBX` chunks.
///
/// The manifest is stored in a `caBX` ancillary chunk. XMP metadata is read
/// from `iTXt` chunks whose keyword is `XML:com.adobe.xmp`.
final class PngAssetHandler
    implements
        AssetHandler,
        DataHashLayoutProvider,
        BoxHashLayoutProvider,
        XmpMetadataProvider,
        RemoteManifestReferenceProvider {
  /// Creates a PNG handler with chunk and byte limits.
  const PngAssetHandler({
    this.maxManifestSize = 64 * 1024 * 1024,
    this.maxSourceSize = 256 * 1024 * 1024,
    this.maxOutputSize = 256 * 1024 * 1024,
    this.maxXmpSize = 4 * 1024 * 1024,
    this.maxRemoteReferenceLength = 64 * 1024,
  }) : assert(maxManifestSize > 0),
       assert(maxSourceSize > 0),
       assert(maxOutputSize > 0),
       assert(maxXmpSize > 0),
       assert(maxRemoteReferenceLength > 0);

  static const int _streamReadSize = 64 * 1024;
  static const int _maximumPngChunkSize = 0xffffffff;
  static const List<int> _signature = <int>[
    0x89,
    0x50,
    0x4e,
    0x47,
    0x0d,
    0x0a,
    0x1a,
    0x0a,
  ];
  static const List<int> _c2paChunkType = <int>[0x63, 0x61, 0x42, 0x58];
  static const List<int> _headerChunkType = <int>[0x49, 0x48, 0x44, 0x52];
  static const List<int> _endChunkType = <int>[0x49, 0x45, 0x4e, 0x44];
  static const List<int> _textChunkType = <int>[0x69, 0x54, 0x58, 0x74];
  static const String _xmpKeyword = 'XML:com.adobe.xmp';

  /// Maximum embedded C2PA manifest size in bytes.
  final int maxManifestSize;

  /// Maximum source PNG size in bytes.
  final int maxSourceSize;

  /// Maximum rewritten PNG size in bytes.
  final int maxOutputSize;

  /// Maximum XMP packet size in bytes.
  final int maxXmpSize;

  /// Maximum UTF-8 length of a remote reference in bytes.
  final int maxRemoteReferenceLength;

  @override
  String get name => 'PNG';

  @override
  AssetFormat get format => AssetFormat.png;

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
    mimeTypes: <String>['image/png'],
    fileExtensions: <String>['png'],
  );

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    if (await source.length < _signature.length) return false;
    final signature = await source.read(ByteRange(0, _signature.length));
    return bytesEqual(signature, _signature);
  }

  @override
  Future<Uint8List> extractManifest(RandomAccessByteSource source) async {
    final inspection = await _inspect(source, captureManifest: true);
    final manifest = inspection.manifest;
    if (manifest == null) {
      throw const ManifestNotFoundException(AssetFormat.png);
    }
    return manifest;
  }

  @override
  Future<DataHashLayout> getDataHashLayout(
    RandomAccessByteSource source,
  ) async {
    final inspection = await _inspect(source);
    final manifest = inspection.manifestChunk;
    return DataHashLayout(
      sourceLength: inspection.sourceLength,
      insertionOffset: manifest?.offset ?? inspection.chunks.first.end,
      exclusions: manifest == null
          ? const []
          : [
              DataHashExclusion(
                range: ByteRange(manifest.offset, manifest.end),
                kind: DataHashExclusionKind.manifest,
                name: 'caBX',
              ),
            ],
    );
  }

  @override
  Future<BoxHashLayout> getBoxHashLayout(RandomAccessByteSource source) async {
    final inspection = await _inspect(source);
    final entries = <BoxHashEntry>[
      BoxHashEntry(names: const ['PNGh'], range: ByteRange(0, 8)),
    ];
    final hasManifest = inspection.manifestChunk != null;
    for (final chunk in inspection.chunks) {
      final name = ascii.decode(chunk.type);
      entries.add(
        BoxHashEntry(
          names: [name == 'caBX' ? 'C2PA' : name],
          range: ByteRange(chunk.offset, chunk.end),
        ),
      );
      if (!hasManifest && name == 'IHDR') {
        entries.add(
          BoxHashEntry(
            names: const ['C2PA'],
            range: ByteRange(chunk.end, chunk.end),
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
    final xmp = await _findXmp(source);
    if (xmp == null) return null;
    try {
      return utf8.decode(xmp.bytes, allowMalformed: false);
    } on FormatException {
      throw const MalformedAssetFormatException(
        'PNG XMP metadata is not valid UTF-8.',
      );
    }
  }

  @override
  Future<String?> readRemoteManifestReference(
    RandomAccessByteSource source,
  ) async {
    final xmp = await _findXmp(source);
    if (xmp == null) return null;
    return XmpRemoteReferenceEditor.parse(
      xmp.bytes,
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
    final xmp = await _findXmp(source);
    final original =
        xmp?.bytes ??
        Uint8List.fromList(utf8.encode(XmpRemoteReferenceEditor.minimalPacket));
    final updated = XmpRemoteReferenceEditor.parse(
      original,
      maxLength: maxXmpSize,
    ).update(reference, maxLength: maxXmpSize);
    await _rewriteXmp(source, output, xmp?.chunk, updated);
  }

  @override
  Future<void> removeRemoteManifestReference(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) async {
    final xmp = await _findXmp(source);
    if (xmp == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.png);
    }
    final editor = XmpRemoteReferenceEditor.parse(
      xmp.bytes,
      maxLength: maxXmpSize,
    );
    if (editor.value == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.png);
    }
    await _rewriteXmp(
      source,
      output,
      xmp.chunk,
      editor.remove(maxLength: maxXmpSize),
    );
  }

  Future<_PngXmp?> _findXmp(RandomAccessByteSource source) async {
    final inspection = await _inspect(source);
    _PngXmp? found;
    for (final chunk in inspection.chunks) {
      if (!bytesEqual(chunk.type, _textChunkType)) continue;
      final data = await source.read(
        ByteRange(chunk.offset + 8, chunk.end - 4),
      );
      final keywordEnd = data.indexOf(0);
      if (keywordEnd < 0) {
        throw const MalformedAssetFormatException(
          'A PNG iTXt keyword is unterminated.',
        );
      }
      if (latin1.decode(data.sublist(0, keywordEnd)) != _xmpKeyword) continue;
      if (found != null) {
        throw const MalformedAssetFormatException(
          'The PNG contains duplicate XMP iTXt chunks.',
        );
      }
      var cursor = keywordEnd + 1;
      if (data.length - cursor < 2) {
        throw const MalformedAssetFormatException(
          'The PNG XMP iTXt fields are truncated.',
        );
      }
      final compressed = data[cursor++];
      final method = data[cursor++];
      if (compressed != 0 || method != 0) {
        throw const UnsupportedXmpFeatureException(
          'compressed PNG XMP metadata',
        );
      }
      for (var field = 0; field < 2; field++) {
        final end = data.indexOf(0, cursor);
        if (end < 0) {
          throw const MalformedAssetFormatException(
            'A PNG XMP iTXt field is unterminated.',
          );
        }
        cursor = end + 1;
      }
      final bytes = Uint8List.fromList(data.sublist(cursor));
      if (bytes.length > maxXmpSize) {
        throw AssetLimitExceededException(
          limit: maxXmpSize,
          actual: bytes.length,
        );
      }
      found = _PngXmp(chunk, bytes);
    }
    return found;
  }

  Future<void> _rewriteXmp(
    RandomAccessByteSource source,
    WritableByteSink output,
    _PngChunk? existing,
    Uint8List xmp,
  ) async {
    if (await output.length != 0) {
      throw const MalformedAssetFormatException(
        'The destination sink must be empty.',
      );
    }
    final payload = Uint8List.fromList(<int>[
      ...ascii.encode(_xmpKeyword),
      0,
      0,
      0,
      0,
      0,
      ...xmp,
    ]);
    final encoded = _encodeNamedChunk(_textChunkType, payload);
    final inspection = await _inspect(source);
    final removed = existing?.totalLength ?? 0;
    final outputLength = inspection.sourceLength - removed + encoded.length;
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }
    final staged = MemoryByteSink();
    await staged.append(await source.read(ByteRange(0, _signature.length)));
    for (final chunk in inspection.chunks) {
      if (existing != null && chunk.offset == existing.offset) {
        await staged.append(encoded);
        continue;
      }
      await copyByteRange(source, staged, ByteRange(chunk.offset, chunk.end));
      if (existing == null && bytesEqual(chunk.type, _headerChunkType)) {
        await staged.append(encoded);
      }
    }
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'PNG XMP rewrite produced an unexpected output length.',
      );
    }
    await output.append(staged.toBytes());
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
    operation: _PngMutation.embed,
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
    operation: _PngMutation.replace,
  );

  @override
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) => _rewrite(source, output, operation: _PngMutation.remove);

  Future<void> _rewrite(
    RandomAccessByteSource source,
    WritableByteSink output, {
    required _PngMutation operation,
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
      if (manifest.length > _maximumPngChunkSize) {
        throw AssetLimitExceededException(
          limit: _maximumPngChunkSize,
          actual: manifest.length,
        );
      }
    }

    final inspection = await _inspect(source);
    final existing = inspection.manifestChunk;
    if (operation == _PngMutation.embed && existing != null) {
      throw const ManifestAlreadyExistsException(AssetFormat.png);
    }
    if (operation != _PngMutation.embed && existing == null) {
      throw const ManifestNotFoundException(AssetFormat.png);
    }

    final replacement = manifest == null ? null : _encodeChunk(manifest);
    final removedLength = existing?.totalLength ?? 0;
    final insertedLength = replacement?.length ?? 0;
    final outputLength =
        inspection.sourceLength - removedLength + insertedLength;
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }

    // Validate the complete source before staging any output. Staging keeps
    // malformed input from partially mutating an arbitrary destination sink.
    final staged = MemoryByteSink();
    await copyByteRange(
      source,
      staged,
      ByteRange(0, _signature.length),
      chunkSize: _streamReadSize,
    );
    for (final chunk in inspection.chunks) {
      if (!bytesEqual(chunk.type, _c2paChunkType)) {
        await copyByteRange(
          source,
          staged,
          ByteRange(chunk.offset, chunk.end),
          chunkSize: _streamReadSize,
        );
      }
      if (bytesEqual(chunk.type, _headerChunkType) && replacement != null) {
        await staged.append(replacement);
      }
    }
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'PNG rewrite produced an unexpected output length.',
      );
    }

    await output.append(staged.toBytes());
  }

  Future<_PngInspection> _inspect(
    RandomAccessByteSource source, {
    bool captureManifest = false,
  }) async {
    final sourceLength = await source.length;
    if (sourceLength > maxSourceSize) {
      throw AssetLimitExceededException(
        limit: maxSourceSize,
        actual: sourceLength,
      );
    }
    if (sourceLength < _signature.length) {
      throw TruncatedAssetException(
        expectedLength: _signature.length,
        actualLength: sourceLength,
      );
    }
    final signature = await source.read(ByteRange(0, _signature.length));
    if (!bytesEqual(signature, _signature)) {
      throw const MalformedAssetFormatException(
        'PNG data has an invalid signature.',
      );
    }

    final chunks = <_PngChunk>[];
    _PngChunk? manifestChunk;
    Uint8List? manifest;
    var offset = _signature.length;
    var foundEnd = false;
    while (offset < sourceLength) {
      if (sourceLength - offset < 12) {
        throw TruncatedAssetException(
          expectedLength: offset + 12,
          actualLength: sourceLength,
        );
      }

      final header = await source.read(ByteRange(offset, offset + 8));
      final dataLength = _uint32(header, 0);
      final type = Uint8List.fromList(header.sublist(4, 8));
      if (!_isValidChunkType(type)) {
        throw MalformedAssetFormatException(
          'PNG chunk at offset $offset has an invalid type code.',
        );
      }
      final typeName = ascii.decode(type);
      final dataOffset = offset + 8;
      final availableForData = sourceLength - dataOffset - 4;
      if (dataLength > availableForData) {
        throw TruncatedAssetException(
          expectedLength: dataOffset + dataLength + 4,
          actualLength: sourceLength,
        );
      }
      final crcOffset = dataOffset + dataLength;
      final chunkEnd = crcOffset + 4;
      final isManifest = bytesEqual(type, _c2paChunkType);
      final isHeader = bytesEqual(type, _headerChunkType);
      final isEnd = bytesEqual(type, _endChunkType);

      if (chunks.isEmpty && (!isHeader || dataLength != 13)) {
        throw const MalformedAssetFormatException(
          'The first PNG chunk must be a 13-byte IHDR.',
        );
      }
      if (isHeader && chunks.isNotEmpty) {
        throw const MalformedAssetFormatException(
          'The PNG contains more than one IHDR chunk.',
        );
      }
      if (isEnd && dataLength != 0) {
        throw const MalformedAssetFormatException(
          'The PNG IEND chunk must have an empty payload.',
        );
      }
      if (isManifest) {
        if (manifestChunk != null) {
          throw const MalformedAssetFormatException(
            'The PNG contains more than one caBX manifest store.',
          );
        }
        if (dataLength > maxManifestSize) {
          throw AssetLimitExceededException(
            limit: maxManifestSize,
            actual: dataLength,
          );
        }
      }

      var crc = _updateCrc(0xffffffff, type);
      final builder = isManifest && captureManifest
          ? BytesBuilder(copy: false)
          : null;
      var dataPosition = dataOffset;
      while (dataPosition < crcOffset) {
        final remaining = crcOffset - dataPosition;
        final readLength = remaining < _streamReadSize
            ? remaining
            : _streamReadSize;
        final bytes = await source.read(
          ByteRange.fromStartAndLength(dataPosition, readLength),
        );
        crc = _updateCrc(crc, bytes);
        builder?.add(bytes);
        dataPosition += readLength;
      }
      final calculatedCrc = crc ^ 0xffffffff;
      final storedCrcBytes = await source.read(ByteRange(crcOffset, chunkEnd));
      final storedCrc = _uint32(storedCrcBytes, 0);
      if (calculatedCrc != storedCrc) {
        throw InvalidChunkCrcException(
          chunkType: typeName,
          expected: calculatedCrc,
          actual: storedCrc,
        );
      }

      final chunk = _PngChunk(offset: offset, end: chunkEnd, type: type);
      chunks.add(chunk);
      if (isManifest) {
        manifestChunk = chunk;
        manifest = builder?.takeBytes();
      }
      offset = chunkEnd;
      if (isEnd) {
        foundEnd = true;
        if (offset != sourceLength) {
          throw const MalformedAssetFormatException(
            'PNG data contains trailing bytes after IEND.',
          );
        }
        break;
      }
    }

    if (!foundEnd) {
      throw const MalformedAssetFormatException(
        'PNG data is missing the required IEND chunk.',
      );
    }
    return _PngInspection(
      sourceLength: sourceLength,
      chunks: chunks,
      manifestChunk: manifestChunk,
      manifest: manifest,
    );
  }

  static Uint8List _encodeChunk(Uint8List manifest) {
    return _encodeNamedChunk(_c2paChunkType, manifest);
  }

  static Uint8List _encodeNamedChunk(List<int> type, Uint8List payload) {
    final output = Uint8List(12 + payload.length);
    final data = ByteData.sublistView(output);
    data.setUint32(0, payload.length, Endian.big);
    output.setRange(4, 8, type);
    output.setRange(8, 8 + payload.length, payload);
    var crc = _updateCrc(0xffffffff, type);
    crc = _updateCrc(crc, payload) ^ 0xffffffff;
    data.setUint32(8 + payload.length, crc, Endian.big);
    return output;
  }

  static bool _isValidChunkType(List<int> type) =>
      type.length == 4 &&
      type.every(
        (byte) =>
            (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a),
      );

  static int _uint32(List<int> bytes, int offset) =>
      (bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3];

  static int _updateCrc(int crc, List<int> bytes) {
    var value = crc;
    for (final byte in bytes) {
      value ^= byte;
      for (var bit = 0; bit < 8; bit++) {
        value = (value & 1) != 0 ? (value >> 1) ^ 0xedb88320 : value >> 1;
      }
    }
    return value;
  }
}

/// Backward-compatible alias for [PngAssetHandler].
typedef PngHandler = PngAssetHandler;

enum _PngMutation { embed, replace, remove }

final class _PngChunk {
  const _PngChunk({
    required this.offset,
    required this.end,
    required this.type,
  });

  final int offset;
  final int end;
  final Uint8List type;

  int get totalLength => end - offset;
}

final class _PngInspection {
  const _PngInspection({
    required this.sourceLength,
    required this.chunks,
    required this.manifestChunk,
    required this.manifest,
  });

  final int sourceLength;
  final List<_PngChunk> chunks;
  final _PngChunk? manifestChunk;
  final Uint8List? manifest;
}

final class _PngXmp {
  const _PngXmp(this.chunk, this.bytes);

  final _PngChunk chunk;
  final Uint8List bytes;
}
