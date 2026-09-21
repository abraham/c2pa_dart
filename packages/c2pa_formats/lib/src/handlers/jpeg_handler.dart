import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../errors.dart';
import '../hash_layout.dart';
import '../xmp.dart';
import '../xmp_remote_reference.dart';

final class JpegAssetHandler
    implements
        AssetHandler,
        DataHashLayoutProvider,
        BoxHashLayoutProvider,
        XmpMetadataProvider,
        RemoteManifestReferenceProvider {
  const JpegAssetHandler({
    this.maxManifestSize = 64 * 1024 * 1024,
    this.maxSegmentCount = 4096,
    this.maxSourceSize = 256 * 1024 * 1024,
    this.maxOutputSize = 256 * 1024 * 1024,
    this.maxXmpSize = 60 * 1024,
    this.maxRemoteReferenceLength = 16 * 1024,
  }) : assert(maxManifestSize > 0),
       assert(maxSegmentCount > 0),
       assert(maxSourceSize > 0),
       assert(maxOutputSize > 0),
       assert(maxXmpSize > 0),
       assert(maxRemoteReferenceLength > 0);

  static const int _app11 = 0xeb;
  static const int _endOfImage = 0xd9;
  static const int _startOfScan = 0xda;
  static const int _startOfImage = 0xd8;
  static const int _temporary = 0x01;
  static const int _restartFirst = 0xd0;
  static const int _restartLast = 0xd7;
  static const int _jpegXtPrefixLength = 8;
  static const int _continuationPrefixLength = 16;
  static const int _segmentDataSize = 64000;
  static const int _app0 = 0xe0;
  static const int _entityId = 0x0211;
  static const List<int> _commonIdentifier = <int>[0x4a, 0x50];
  static const List<int> _c2paMarker = <int>[0x63, 0x32, 0x70, 0x61];
  static const String _xmpSignature = 'http://ns.adobe.com/xap/1.0/\u0000';

  final int maxManifestSize;
  final int maxSegmentCount;
  final int maxSourceSize;
  final int maxOutputSize;
  final int maxXmpSize;
  final int maxRemoteReferenceLength;

  @override
  String get name => 'JPEG';

  @override
  AssetFormat get format => AssetFormat.jpeg;

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
    mimeTypes: <String>['image/jpeg', 'image/jpg'],
    fileExtensions: <String>['jpg', 'jpeg', 'jpe'],
  );

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    if (await source.length < 3) return false;
    final signature = await source.read(ByteRange(0, 3));
    return signature.length == 3 &&
        signature[0] == 0xff &&
        signature[1] == _startOfImage &&
        signature[2] == 0xff;
  }

  @override
  Future<Uint8List> extractManifest(RandomAccessByteSource source) async {
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
    final signature = await source.read(ByteRange(0, 2));
    if (signature[0] != 0xff || signature[1] != _startOfImage) {
      throw const MalformedAssetFormatException(
        'JPEG data must begin with an SOI marker.',
      );
    }

    final packets = await _scanApp11Packets(source, sourceLength);
    final c2paHeaders = packets.where(_hasC2paStartData).toList();
    if (c2paHeaders.any((packet) => packet.sequence != 1)) {
      throw const MalformedAssetFormatException(
        'A C2PA JPEG XT packet must begin with sequence 1.',
      );
    }
    final starts = c2paHeaders.where(_isC2paStart).toList();
    if (starts.isEmpty) {
      throw const ManifestNotFoundException(AssetFormat.jpeg);
    }
    if (starts.length > 1) {
      throw const MalformedAssetFormatException(
        'The JPEG contains more than one C2PA manifest store.',
      );
    }

    final start = starts.single;
    final group = packets
        .where((packet) => packet.entity == start.entity)
        .toList();
    final startIndex = group.indexOf(start);
    if (startIndex != 0) {
      throw const MalformedAssetFormatException(
        'A C2PA continuation segment appears before sequence 1.',
      );
    }
    if (group.length > maxSegmentCount) {
      throw SegmentLimitExceededException(
        limit: maxSegmentCount,
        actual: group.length,
      );
    }

    final firstPayload = await _readPacket(source, start);
    final boxLength = _declaredBoxLength(firstPayload);
    if (boxLength > maxManifestSize) {
      throw AssetLimitExceededException(
        limit: maxManifestSize,
        actual: boxLength,
      );
    }

    final output = BytesBuilder(copy: false);
    var reconstructedLength = 0;
    for (var index = 0; index < group.length; index++) {
      final packet = group[index];
      final expectedSequence = index + 1;
      if (packet.sequence != expectedSequence) {
        throw MalformedAssetFormatException(
          'Expected JPEG XT sequence $expectedSequence, '
          'found ${packet.sequence}.',
        );
      }

      final payload = index == 0
          ? firstPayload
          : await _readPacket(source, packet);
      final dataOffset = index == 0
          ? _jpegXtPrefixLength
          : _continuationPrefixLength;
      if (payload.length < dataOffset) {
        throw const MalformedAssetFormatException(
          'A C2PA APP11 segment is shorter than its JPEG XT prefix.',
        );
      }
      if (index > 0 &&
          !_equalRange(
            payload,
            _jpegXtPrefixLength,
            firstPayload,
            _jpegXtPrefixLength,
            8,
          )) {
        throw const MalformedAssetFormatException(
          'A continuation segment repeats a different LBox or TBox.',
        );
      }

      final chunkLength = payload.length - dataOffset;
      if (chunkLength == 0 && reconstructedLength < boxLength) {
        throw const MalformedAssetFormatException(
          'A C2PA continuation segment contains no box data.',
        );
      }
      if (chunkLength > boxLength - reconstructedLength) {
        throw const MalformedAssetFormatException(
          'C2PA APP11 segments contain data beyond the declared box size.',
        );
      }
      output.add(payload.sublist(dataOffset));
      reconstructedLength += chunkLength;
    }

    if (reconstructedLength != boxLength) {
      throw TruncatedAssetException(
        expectedLength: boxLength,
        actualLength: reconstructedLength,
      );
    }

    final manifest = output.takeBytes();
    _validateManifestBox(manifest);
    return manifest;
  }

  @override
  Future<DataHashLayout> getDataHashLayout(
    RandomAccessByteSource source,
  ) async {
    final layout = await _inspectForWrite(source);
    final group = await _manifestPackets(source, layout);
    return DataHashLayout(
      sourceLength: layout.sourceLength,
      insertionOffset: group.isEmpty
          ? layout.insertionOffset
          : group.first.markerOffset,
      exclusions: _packetExclusions(group),
    );
  }

  @override
  Future<BoxHashLayout> getBoxHashLayout(RandomAccessByteSource source) async {
    final layout = await _inspectForWrite(source);
    final group = await _manifestPackets(source, layout);
    final manifestOffsets = {for (final packet in group) packet.markerOffset};
    final entries = <BoxHashEntry>[];
    var insertedSynthetic = false;
    for (final box in layout.boxes) {
      if (group.isEmpty &&
          !insertedSynthetic &&
          box.offset >= layout.insertionOffset) {
        entries.add(_syntheticC2paBox(layout.insertionOffset));
        insertedSynthetic = true;
      }

      final isManifest = manifestOffsets.contains(box.offset);
      if (isManifest &&
          entries.isNotEmpty &&
          entries.last.names.contains('C2PA') &&
          entries.last.range.end == box.offset) {
        final previous = entries.removeLast();
        entries.add(
          BoxHashEntry(
            names: const ['C2PA'],
            range: ByteRange(previous.range.start, box.end),
          ),
        );
        continue;
      }
      entries.add(
        BoxHashEntry(
          names: [isManifest ? 'C2PA' : box.name],
          range: ByteRange(box.offset, box.end),
        ),
      );
    }
    if (group.isEmpty && !insertedSynthetic) {
      entries.add(_syntheticC2paBox(layout.insertionOffset));
    }
    return BoxHashLayout(sourceLength: layout.sourceLength, entries: entries);
  }

  Future<List<_JpegXtPacket>> _manifestPackets(
    RandomAccessByteSource source,
    _JpegLayout layout,
  ) async {
    final c2paHeaders = layout.packets.where(_hasC2paStartData).toList();
    if (c2paHeaders.any((packet) => packet.sequence != 1)) {
      throw const MalformedAssetFormatException(
        'A C2PA JPEG XT packet must begin with sequence 1.',
      );
    }
    final starts = c2paHeaders.where(_isC2paStart).toList();
    if (starts.length > 1) {
      throw const MalformedAssetFormatException(
        'The JPEG contains more than one C2PA manifest store.',
      );
    }
    if (starts.isEmpty) return const [];
    await extractManifest(source);
    final entity = starts.single.entity;
    return layout.packets
        .where((packet) => packet.entity == entity)
        .toList(growable: false);
  }

  static BoxHashEntry _syntheticC2paBox(int offset) => BoxHashEntry(
    names: const ['C2PA'],
    range: ByteRange(offset, offset),
    excluded: true,
    synthetic: true,
  );

  static List<DataHashExclusion> _packetExclusions(
    List<_JpegXtPacket> packets,
  ) {
    final exclusions = <DataHashExclusion>[];
    for (final packet in packets) {
      if (exclusions.isNotEmpty &&
          exclusions.last.range.end == packet.markerOffset) {
        final previous = exclusions.removeLast();
        exclusions.add(
          DataHashExclusion(
            range: ByteRange(previous.range.start, packet.markerEnd),
            kind: DataHashExclusionKind.manifest,
            name: 'C2PA APP11',
          ),
        );
      } else {
        exclusions.add(
          DataHashExclusion(
            range: ByteRange(packet.markerOffset, packet.markerEnd),
            kind: DataHashExclusionKind.manifest,
            name: 'C2PA APP11',
          ),
        );
      }
    }
    return exclusions;
  }

  @override
  Future<String?> readXmp(RandomAccessByteSource source) async {
    final found = await _findXmp(source);
    if (found == null) return null;
    try {
      return utf8.decode(found.bytes, allowMalformed: false);
    } on FormatException {
      throw const MalformedAssetFormatException(
        'JPEG XMP metadata is not valid UTF-8.',
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
    if (utf8.encode(reference).length > maxRemoteReferenceLength) {
      throw AssetLimitExceededException(
        limit: maxRemoteReferenceLength,
        actual: utf8.encode(reference).length,
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
    await _rewriteXmp(source, output, found, updated);
  }

  @override
  Future<void> removeRemoteManifestReference(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) async {
    final found = await _findXmp(source);
    if (found == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.jpeg);
    }
    final editor = XmpRemoteReferenceEditor.parse(
      found.bytes,
      maxLength: maxXmpSize,
    );
    if (editor.value == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.jpeg);
    }
    await _rewriteXmp(
      source,
      output,
      found,
      editor.remove(maxLength: maxXmpSize),
    );
  }

  Future<_JpegXmp?> _findXmp(RandomAccessByteSource source) async {
    final layout = await _inspectForWrite(source);
    _JpegXmp? found;
    final signature = ascii.encode(_xmpSignature);
    for (final box in layout.boxes.where((box) => box.name == 'APP1')) {
      if (box.end - box.offset < 4 + signature.length) continue;
      final prefix = await source.read(
        ByteRange(box.offset + 4, box.offset + 4 + signature.length),
      );
      if (!_startsWith(prefix, signature)) continue;
      if (found != null) {
        throw const MalformedAssetFormatException(
          'The JPEG contains duplicate standard XMP APP1 segments.',
        );
      }
      final bytes = await source.read(
        ByteRange(box.offset + 4 + signature.length, box.end),
      );
      if (bytes.length > maxXmpSize) {
        throw AssetLimitExceededException(
          limit: maxXmpSize,
          actual: bytes.length,
        );
      }
      found = _JpegXmp(box: box, bytes: bytes);
    }
    return found;
  }

  Future<void> _rewriteXmp(
    RandomAccessByteSource source,
    WritableByteSink output,
    _JpegXmp? existing,
    Uint8List xmp,
  ) async {
    if (await output.length != 0) {
      throw const MalformedAssetFormatException(
        'The destination sink must be empty.',
      );
    }
    final signature = ascii.encode(_xmpSignature);
    final payloadLength = signature.length + xmp.length;
    if (payloadLength + 2 > 0xffff) {
      throw AssetLimitExceededException(
        limit: 0xffff - 2 - signature.length,
        actual: xmp.length,
      );
    }
    final segment = Uint8List(payloadLength + 4);
    ByteData.sublistView(segment)
      ..setUint8(0, 0xff)
      ..setUint8(1, 0xe1)
      ..setUint16(2, payloadLength + 2, Endian.big);
    segment.setRange(4, 4 + signature.length, signature);
    segment.setRange(4 + signature.length, segment.length, xmp);
    final layout = await _inspectForWrite(source);
    final start = existing?.box.offset ?? layout.insertionOffset;
    final end = existing?.box.end ?? start;
    final outputLength = layout.sourceLength - (end - start) + segment.length;
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }
    final staged = MemoryByteSink();
    await _copyIfNonEmpty(source, staged, 0, start);
    await staged.append(segment);
    await _copyIfNonEmpty(source, staged, end, layout.sourceLength);
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'JPEG XMP rewrite produced an unexpected output length.',
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
    operation: _JpegMutation.embed,
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
    operation: _JpegMutation.replace,
  );

  @override
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) => _rewrite(source, output, operation: _JpegMutation.remove);

  Future<void> _rewrite(
    RandomAccessByteSource source,
    WritableByteSink output, {
    required _JpegMutation operation,
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
      _validateManifestBox(manifest);
    }

    final layout = await _inspectForWrite(source);
    final c2paHeaders = layout.packets.where(_hasC2paStartData).toList();
    if (c2paHeaders.any((packet) => packet.sequence != 1)) {
      throw const MalformedAssetFormatException(
        'A C2PA JPEG XT packet must begin with sequence 1.',
      );
    }
    final starts = c2paHeaders.where(_isC2paStart).toList();
    if (starts.length > 1) {
      throw const MalformedAssetFormatException(
        'The JPEG contains more than one C2PA manifest store.',
      );
    }
    final hasManifest = starts.isNotEmpty;
    if (operation == _JpegMutation.embed && hasManifest) {
      throw const ManifestAlreadyExistsException(AssetFormat.jpeg);
    }
    if (operation != _JpegMutation.embed && !hasManifest) {
      throw const ManifestNotFoundException(AssetFormat.jpeg);
    }

    var removals = const <ByteRange>[];
    if (hasManifest) {
      // Reconstructing first ensures malformed, missing, or reordered packet
      // groups are rejected before any output is staged.
      await extractManifest(source);
      final entity = starts.single.entity;
      removals =
          layout.packets
              .where((packet) => packet.entity == entity)
              .map((packet) => ByteRange(packet.markerOffset, packet.markerEnd))
              .toList()
            ..sort();
    }

    final encodedManifest = manifest == null
        ? null
        : _encodeManifestSegments(manifest);
    final removedLength = removals.fold<int>(
      0,
      (sum, range) => sum + range.length,
    );
    final insertedLength = encodedManifest?.length ?? 0;
    final outputLength = layout.sourceLength - removedLength + insertedLength;
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }

    final staged = MemoryByteSink();
    var position = 0;
    var inserted = encodedManifest == null;
    for (final removal in removals) {
      if (!inserted && layout.insertionOffset <= removal.start) {
        await _copyIfNonEmpty(source, staged, position, layout.insertionOffset);
        await staged.append(encodedManifest!);
        position = layout.insertionOffset;
        inserted = true;
      }
      await _copyIfNonEmpty(source, staged, position, removal.start);
      position = removal.end;
    }
    if (!inserted) {
      await _copyIfNonEmpty(source, staged, position, layout.insertionOffset);
      await staged.append(encodedManifest!);
      position = layout.insertionOffset;
    }
    await _copyIfNonEmpty(source, staged, position, layout.sourceLength);
    if (await staged.length != outputLength) {
      throw const MalformedAssetFormatException(
        'JPEG rewrite produced an unexpected output length.',
      );
    }
    await output.append(staged.toBytes());
  }

  Future<_JpegLayout> _inspectForWrite(RandomAccessByteSource source) async {
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
    final signature = await source.read(ByteRange(0, 2));
    if (signature[0] != 0xff || signature[1] != _startOfImage) {
      throw const MalformedAssetFormatException(
        'JPEG data must begin with an SOI marker.',
      );
    }

    final cursor = _JpegCursor(source, sourceLength, 2);
    final packets = <_JpegXtPacket>[];
    final boxes = <_JpegPhysicalBox>[
      const _JpegPhysicalBox(name: 'SOI', offset: 0, end: 2),
    ];
    var insertionOffset = 2;
    var beforeFirstScan = true;
    var inEntropyData = false;
    int? scanBoxIndex;
    var foundEnd = false;

    while (cursor.position < sourceLength) {
      if (inEntropyData) {
        final byte = await cursor.readByte();
        if (byte != 0xff) continue;
        final markerStart = cursor.position - 1;
        int marker;
        do {
          marker = await cursor.readByte();
        } while (marker == 0xff);
        if (marker == 0x00 ||
            (marker >= _restartFirst && marker <= _restartLast)) {
          continue;
        }
        final index = scanBoxIndex;
        if (index != null) {
          boxes[index] = boxes[index].withEnd(markerStart);
          scanBoxIndex = null;
        }
        cursor.seek(markerStart);
        inEntropyData = false;
        continue;
      }

      final markerStart = cursor.position;
      if (await cursor.readByte() != 0xff) {
        throw MalformedAssetFormatException(
          'Expected a JPEG marker at offset $markerStart.',
        );
      }
      int marker;
      do {
        marker = await cursor.readByte();
      } while (marker == 0xff);
      if (marker == 0x00) {
        throw MalformedAssetFormatException(
          'Unexpected stuffed marker byte at offset $markerStart.',
        );
      }
      if (marker == _endOfImage) {
        boxes.add(
          _JpegPhysicalBox(
            name: 'EOI',
            offset: markerStart,
            end: cursor.position,
          ),
        );
        foundEnd = true;
        if (cursor.position != sourceLength) {
          throw const MalformedAssetFormatException(
            'JPEG data contains trailing bytes after EOI.',
          );
        }
        break;
      }
      if (marker == _startOfImage) {
        throw MalformedAssetFormatException(
          'Unexpected SOI marker at offset $markerStart.',
        );
      }
      if (marker == _temporary ||
          (marker >= _restartFirst && marker <= _restartLast)) {
        if (beforeFirstScan) {
          throw MalformedAssetFormatException(
            'Unexpected standalone marker before scan data at '
            'offset $markerStart.',
          );
        }
        boxes.add(
          _JpegPhysicalBox(
            name: _jpegMarkerName(marker),
            offset: markerStart,
            end: cursor.position,
          ),
        );
        continue;
      }

      final segmentLength = await cursor.readUint16();
      if (segmentLength < 2) {
        throw MalformedAssetFormatException(
          'JPEG segment at offset $markerStart has invalid length '
          '$segmentLength.',
        );
      }
      final payloadOffset = cursor.position;
      final payloadLength = segmentLength - 2;
      final segmentEnd = payloadOffset + payloadLength;
      if (segmentEnd > sourceLength) {
        throw TruncatedAssetException(
          expectedLength: segmentEnd,
          actualLength: sourceLength,
        );
      }

      if (beforeFirstScan && marker == _app0) {
        insertionOffset = segmentEnd;
      }
      if (beforeFirstScan &&
          marker == _app11 &&
          payloadLength >= _jpegXtPrefixLength) {
        final prefixLength = payloadLength < 40 ? payloadLength : 40;
        final payloadPrefix = await source.read(
          ByteRange(payloadOffset, payloadOffset + prefixLength),
        );
        if (_startsWith(payloadPrefix, _commonIdentifier)) {
          packets.add(
            _JpegXtPacket(
              markerOffset: markerStart,
              markerEnd: segmentEnd,
              payloadOffset: payloadOffset,
              payloadLength: payloadLength,
              entity: _uint16(payloadPrefix, 2),
              sequence: _uint32(payloadPrefix, 4),
              prefix: payloadPrefix,
            ),
          );
        }
      }

      cursor.seek(segmentEnd);
      boxes.add(
        _JpegPhysicalBox(
          name: _jpegMarkerName(marker),
          offset: markerStart,
          end: segmentEnd,
        ),
      );
      if (marker == _startOfScan) {
        beforeFirstScan = false;
        inEntropyData = true;
        scanBoxIndex = boxes.length - 1;
      }
    }

    if (!foundEnd) {
      throw const MalformedAssetFormatException(
        'JPEG data is missing the required EOI marker.',
      );
    }
    return _JpegLayout(
      sourceLength: sourceLength,
      insertionOffset: insertionOffset,
      packets: packets,
      boxes: boxes,
    );
  }

  static String _jpegMarkerName(int marker) {
    if (marker >= 0xe0 && marker <= 0xef) return 'APP${marker - 0xe0}';
    if (marker >= 0xd0 && marker <= 0xd7) return 'RST${marker - 0xd0}';
    if (marker >= 0xf0 && marker <= 0xfd) return 'JPG${marker - 0xef}';
    return switch (marker) {
      0x01 => 'TEM',
      0xc0 => 'SOF0',
      0xc1 => 'SOF1',
      0xc2 => 'SOF2',
      0xc4 => 'DHT',
      0xcc => 'DAC',
      0xd8 => 'SOI',
      0xd9 => 'EOI',
      0xda => 'SOS',
      0xdb => 'DQT',
      0xdd => 'DRI',
      0xfe => 'COM',
      _ => '0x${marker.toRadixString(16).padLeft(2, '0').toUpperCase()}',
    };
  }

  Uint8List _encodeManifestSegments(Uint8List manifest) {
    final segmentCount =
        (manifest.length + _segmentDataSize - 1) ~/ _segmentDataSize;
    if (segmentCount > maxSegmentCount) {
      throw SegmentLimitExceededException(
        limit: maxSegmentCount,
        actual: segmentCount,
      );
    }
    final output = BytesBuilder(copy: false);
    var offset = 0;
    for (var index = 0; index < segmentCount; index++) {
      final remaining = manifest.length - offset;
      final chunkLength = remaining < _segmentDataSize
          ? remaining
          : _segmentDataSize;
      final payloadLength =
          _jpegXtPrefixLength + (index == 0 ? 0 : 8) + chunkLength;
      final segmentLength = payloadLength + 2;
      final header = ByteData(12 + (index == 0 ? 0 : 8))
        ..setUint8(0, 0xff)
        ..setUint8(1, _app11)
        ..setUint16(2, segmentLength, Endian.big)
        ..setUint8(4, _commonIdentifier[0])
        ..setUint8(5, _commonIdentifier[1])
        ..setUint16(6, _entityId, Endian.big)
        ..setUint32(8, index + 1, Endian.big);
      if (index > 0) {
        header.buffer.asUint8List().setRange(12, 20, manifest, 0);
      }
      output
        ..add(header.buffer.asUint8List())
        ..add(manifest.sublist(offset, offset + chunkLength));
      offset += chunkLength;
    }
    return output.takeBytes();
  }

  static Future<void> _copyIfNonEmpty(
    RandomAccessByteSource source,
    WritableByteSink output,
    int start,
    int end,
  ) async {
    if (end < start) {
      throw const MalformedAssetFormatException(
        'JPEG rewrite ranges overlap or are out of order.',
      );
    }
    if (start == end) return;
    await copyByteRange(
      source,
      output,
      ByteRange(start, end),
      chunkSize: 64 * 1024,
    );
  }

  Future<List<_JpegXtPacket>> _scanApp11Packets(
    RandomAccessByteSource source,
    int sourceLength,
  ) async {
    final packets = <_JpegXtPacket>[];
    var offset = 2;
    while (offset < sourceLength) {
      final markerStart = offset;
      final prefix = await _readByte(source, offset, sourceLength);
      if (prefix != 0xff) {
        throw MalformedAssetFormatException(
          'Expected a JPEG marker at offset $offset.',
        );
      }
      do {
        offset++;
        if (offset >= sourceLength) {
          throw TruncatedAssetException(
            expectedLength: offset + 1,
            actualLength: sourceLength,
          );
        }
      } while (await _readByte(source, offset, sourceLength) == 0xff);

      final marker = await _readByte(source, offset, sourceLength);
      offset++;
      if (marker == 0x00) {
        throw MalformedAssetFormatException(
          'Unexpected stuffed marker byte at offset $markerStart.',
        );
      }
      if (marker == _endOfImage) break;
      if (marker == _startOfImage) {
        throw MalformedAssetFormatException(
          'Unexpected SOI marker at offset $markerStart.',
        );
      }
      if (marker == _temporary ||
          (marker >= _restartFirst && marker <= _restartLast)) {
        continue;
      }

      if (sourceLength - offset < 2) {
        throw TruncatedAssetException(
          expectedLength: offset + 2,
          actualLength: sourceLength,
        );
      }
      final lengthBytes = await source.read(ByteRange(offset, offset + 2));
      final segmentLength = _uint16(lengthBytes, 0);
      if (segmentLength < 2) {
        throw MalformedAssetFormatException(
          'JPEG segment at offset $markerStart has invalid length '
          '$segmentLength.',
        );
      }
      final segmentEnd = offset + segmentLength;
      if (segmentEnd > sourceLength) {
        throw TruncatedAssetException(
          expectedLength: segmentEnd,
          actualLength: sourceLength,
        );
      }
      final payloadOffset = offset + 2;
      final payloadLength = segmentLength - 2;

      if (marker == _app11 && payloadLength >= _jpegXtPrefixLength) {
        final prefixLength = payloadLength < 40 ? payloadLength : 40;
        final payloadPrefix = await source.read(
          ByteRange(payloadOffset, payloadOffset + prefixLength),
        );
        if (_startsWith(payloadPrefix, _commonIdentifier)) {
          packets.add(
            _JpegXtPacket(
              markerOffset: markerStart,
              markerEnd: segmentEnd,
              payloadOffset: payloadOffset,
              payloadLength: payloadLength,
              entity: _uint16(payloadPrefix, 2),
              sequence: _uint32(payloadPrefix, 4),
              prefix: payloadPrefix,
            ),
          );
        }
      }

      offset = segmentEnd;
      if (marker == _startOfScan) break;
    }
    return packets;
  }

  Future<Uint8List> _readPacket(
    RandomAccessByteSource source,
    _JpegXtPacket packet,
  ) => source.read(
    ByteRange.fromStartAndLength(packet.payloadOffset, packet.payloadLength),
  );

  static bool _isC2paStart(_JpegXtPacket packet) =>
      packet.sequence == 1 && _hasC2paStartData(packet);

  static bool _hasC2paStartData(_JpegXtPacket packet) {
    final prefix = packet.prefix;
    if (prefix.length < 33) return false;
    final boxHeaderSize = _uint32(prefix, 8) == 1 ? 16 : 8;
    final descriptionOffset = _jpegXtPrefixLength + boxHeaderSize;
    if (prefix.length < descriptionOffset + 12) return false;
    return _equalRange(
      prefix,
      descriptionOffset + 8,
      Uint8List.fromList(_c2paMarker),
      0,
      _c2paMarker.length,
    );
  }

  int _declaredBoxLength(Uint8List payload) {
    if (payload.length < _continuationPrefixLength) {
      throw const MalformedAssetFormatException(
        'The first C2PA APP11 segment has no complete ISO box header.',
      );
    }
    final size32 = _uint32(payload, _jpegXtPrefixLength);
    if (size32 == 0) {
      throw const MalformedAssetFormatException(
        'A segmented C2PA box must declare its total size.',
      );
    }
    if (size32 == 1) {
      if (payload.length < 24) {
        throw const MalformedAssetFormatException(
          'The first C2PA APP11 segment has a truncated large-size box.',
        );
      }
      return _uint64(payload, 16);
    }
    if (size32 < 8) {
      throw const MalformedAssetFormatException(
        'The C2PA box size is smaller than its header.',
      );
    }
    return size32;
  }

  static void _validateManifestBox(Uint8List manifest) {
    try {
      final outer = parseIsoBoxHeader(manifest);
      if (outer.type != JumbfFourcc.superBox ||
          outer.size != manifest.length ||
          outer.extendsToEnd) {
        throw const MalformedAssetFormatException(
          'The reconstructed C2PA data is not one complete JUMBF superbox.',
        );
      }
      final description = parseIsoBoxHeader(
        manifest,
        offset: outer.headerSize,
        end: manifest.length,
      );
      if (description.type != JumbfFourcc.description ||
          description.payloadSize < 16 ||
          !_equalRange(
            manifest,
            description.offset + description.headerSize,
            Uint8List.fromList(_c2paMarker),
            0,
            _c2paMarker.length,
          )) {
        throw const MalformedAssetFormatException(
          'The JUMBF superbox is not a C2PA manifest store.',
        );
      }
    } on IsoBoxException catch (error) {
      throw MalformedAssetFormatException(
        'The reconstructed C2PA box is malformed: ${error.message}',
      );
    }
  }

  static Future<int> _readByte(
    RandomAccessByteSource source,
    int offset,
    int sourceLength,
  ) async {
    if (offset >= sourceLength) {
      throw TruncatedAssetException(
        expectedLength: offset + 1,
        actualLength: sourceLength,
      );
    }
    return (await source.read(ByteRange(offset, offset + 1)))[0];
  }

  static bool _startsWith(List<int> bytes, List<int> prefix) =>
      bytes.length >= prefix.length &&
      _equalRange(bytes, 0, Uint8List.fromList(prefix), 0, prefix.length);

  static bool _equalRange(
    List<int> left,
    int leftOffset,
    List<int> right,
    int rightOffset,
    int length,
  ) {
    if (leftOffset + length > left.length ||
        rightOffset + length > right.length) {
      return false;
    }
    for (var index = 0; index < length; index++) {
      if (left[leftOffset + index] != right[rightOffset + index]) return false;
    }
    return true;
  }

  static int _uint16(List<int> bytes, int offset) =>
      (bytes[offset] << 8) | bytes[offset + 1];

  static int _uint32(List<int> bytes, int offset) =>
      (bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3];

  static int _uint64(List<int> bytes, int offset) {
    var value = 0;
    for (var index = 0; index < 8; index++) {
      value = (value << 8) | bytes[offset + index];
    }
    if (value < 0 || value > ByteRange.maxCoordinate) {
      throw AssetLimitExceededException(
        limit: ByteRange.maxCoordinate,
        actual: value,
      );
    }
    return value;
  }
}

typedef JpegHandler = JpegAssetHandler;

enum _JpegMutation { embed, replace, remove }

final class _JpegXtPacket {
  const _JpegXtPacket({
    required this.markerOffset,
    required this.markerEnd,
    required this.payloadOffset,
    required this.payloadLength,
    required this.entity,
    required this.sequence,
    required this.prefix,
  });

  final int markerOffset;
  final int markerEnd;
  final int payloadOffset;
  final int payloadLength;
  final int entity;
  final int sequence;
  final Uint8List prefix;
}

final class _JpegLayout {
  const _JpegLayout({
    required this.sourceLength,
    required this.insertionOffset,
    required this.packets,
    required this.boxes,
  });

  final int sourceLength;
  final int insertionOffset;
  final List<_JpegXtPacket> packets;
  final List<_JpegPhysicalBox> boxes;
}

final class _JpegXmp {
  const _JpegXmp({required this.box, required this.bytes});

  final _JpegPhysicalBox box;
  final Uint8List bytes;
}

final class _JpegPhysicalBox {
  const _JpegPhysicalBox({
    required this.name,
    required this.offset,
    required this.end,
  });

  final String name;
  final int offset;
  final int end;

  _JpegPhysicalBox withEnd(int value) =>
      _JpegPhysicalBox(name: name, offset: offset, end: value);
}

final class _JpegCursor {
  _JpegCursor(this.source, this.length, this.position);

  static const int _bufferSize = 64 * 1024;

  final RandomAccessByteSource source;
  final int length;
  int position;
  Uint8List _buffer = Uint8List(0);
  int _bufferStart = 0;

  void seek(int offset) {
    if (offset < 0 || offset > length) {
      throw TruncatedAssetException(
        expectedLength: offset,
        actualLength: length,
      );
    }
    position = offset;
  }

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

  Future<int> readUint16() async =>
      ((await readByte()) << 8) | await readByte();
}
