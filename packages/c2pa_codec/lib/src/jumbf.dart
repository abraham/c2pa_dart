import 'dart:convert';
import 'dart:typed_data';

import 'brotli.dart';
import 'errors.dart';
import 'iso_box.dart';

// Positional leaf constructors intentionally adapt named base parameters.
// ignore_for_file: use_super_parameters

/// Four-character box types used by the JUMBF and C2PA profiles.
abstract final class JumbfFourcc {
  /// The `jumb` JUMBF superbox type.
  static const superBox = 'jumb';

  /// The `jumd` JUMBF description box type.
  static const description = 'jumd';

  /// The `cbor` CBOR content box type.
  static const cbor = 'cbor';

  /// The `json` JSON content box type.
  static const json = 'json';

  /// The `xml ` XML content box type, including its trailing space.
  static const xml = 'xml ';

  /// The `jp2c` JPEG 2000 codestream content box type.
  static const codestream = 'jp2c';

  /// The `uuid` ISO extension box type.
  static const uuid = 'uuid';

  /// The `bfdb` embedded-file description box type.
  static const embeddedFileDescription = 'bfdb';

  /// The `bidb` embedded-file data box type.
  static const embeddedFileData = 'bidb';

  /// The `free` padding box type.
  static const padding = 'free';

  /// The `brob` Brotli-compressed content box type.
  static const brotli = 'brob';

  /// The `c2sh` C2PA salt box type used in `jumd` private data.
  static const salt = 'c2sh';
}

/// Hexadecimal UUID identifiers registered by JUMBF and C2PA.
abstract final class JumbfUuid {
  /// The JUMBF content-type UUID for JPEG 2000 codestream content.
  static const codestream = '6579d6fbdba2446bb2ac1b82feeb89d1';

  /// The JUMBF content-type UUID for JSON content.
  static const json = '6a736f6e00110010800000aa00389b71';

  /// The JUMBF content-type UUID for CBOR content.
  static const cbor = '63626f7200110010800000aa00389b71';

  /// The JUMBF content-type UUID for XML content.
  static const xml = '786d6c2000110010800000aa00389b71';

  /// The JUMBF content-type UUID for UUID content boxes.
  static const uuid = '7575696400110010800000aa00389b71';

  /// The JUMBF content-type UUID for embedded-file superboxes.
  static const embeddedFile = '40cb0c32bb8a489da70b2ad6f47f4369';

  /// The JUMBF content-type UUID for Brotli-compressed content.
  static const brotli = '62726f6200110010800000aa00389b71';

  /// The C2PA manifest-store superbox content-type UUID.
  static const c2paManifestStore = '6332706100110010800000aa00389b71';

  /// The C2PA manifest superbox content-type UUID.
  static const c2paManifest = '63326d6100110010800000aa00389b71';

  /// The legacy C2PA manifest superbox content-type UUID.
  static const c2paLegacyManifest = '63326d6400110010800000aa00389b71';

  /// The C2PA compressed-manifest superbox content-type UUID.
  static const c2paCompressedManifest = '6332636d00110010800000aa00389b71';

  /// The C2PA update-manifest superbox content-type UUID.
  static const c2paUpdateManifest = '6332756d00110010800000aa00389b71';

  /// The C2PA assertion-store superbox content-type UUID.
  static const c2paAssertionStore = '6332617300110010800000aa00389b71';

  /// The C2PA ingredient-store superbox content-type UUID.
  static const c2paIngredientStore = '6361697300110010800000aa00389b71';

  /// The C2PA ingredient superbox content-type UUID.
  static const c2paIngredient = '6361696e00110010800000aa00389b71';

  /// The C2PA claim superbox content-type UUID.
  static const c2paClaim = '6332636c00110010800000aa00389b71';

  /// The C2PA signature superbox content-type UUID.
  static const c2paSignature = '6332637300110010800000aa00389b71';

  /// The C2PA verifiable-credentials superbox content-type UUID.
  static const c2paCredentials = '6332766300110010800000aa00389b71';

  /// The C2PA data-boxes superbox content-type UUID.
  static const c2paDataBoxes = '6332646200110010800000aa00389b71';

  /// The C2PA redaction superbox content-type UUID.
  static const c2paRedaction = 'caa98eee9d4df80e86ad4dffca263973';

  /// The JUMBF content-type UUID for `bfdb` embedded-file descriptions.
  static const embeddedFileDescription = '6266646200110010800000aa00389b71';

  /// The JUMBF content-type UUID for `bidb` embedded-file data.
  static const embeddedFileData = '6269646200110010800000aa00389b71';

  /// The C2PA JSON assertion content-type UUID.
  static const c2paJsonAssertion = json;

  /// The C2PA CBOR assertion content-type UUID.
  static const c2paCborAssertion = cbor;

  /// The C2PA UUID assertion content-type UUID.
  static const c2paUuidAssertion = uuid;

  /// The C2PA embedded-file assertion content-type UUID.
  static const c2paEmbeddedFile = embeddedFile;

  /// Converts a 32-character hexadecimal UUID to 16 bytes.
  static Uint8List bytes(String uuid) {
    if (uuid.length != 32) {
      throw const JumbfException(
        JumbfErrorCode.invalidDescription,
        'A JUMBF UUID must contain exactly 32 hexadecimal characters',
      );
    }
    final result = Uint8List(16);
    for (var index = 0; index < result.length; index++) {
      final value = int.tryParse(
        uuid.substring(index * 2, index * 2 + 2),
        radix: 16,
      );
      if (value == null) {
        throw const JumbfException(
          JumbfErrorCode.invalidDescription,
          'A JUMBF UUID contains a non-hexadecimal character',
        );
      }
      result[index] = value;
    }
    return result;
  }

  /// Returns a lower-case hexadecimal UUID.
  static String hex(List<int> uuid) {
    if (uuid.length != 16) {
      throw const JumbfException(
        JumbfErrorCode.invalidDescription,
        'A JUMBF UUID must contain exactly 16 bytes',
      );
    }
    return uuid.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  }
}

/// A JUMBF description (`jumd`) box.
final class JumbfDescription {
  /// Creates a `jumd` box description with a 16-byte [contentType] UUID.
  JumbfDescription({
    required Uint8List contentType,
    this.requestable = true,
    this.label,
    this.id,
    Uint8List? hash,
    Uint8List? salt,
  }) : _contentType = _copyExact(contentType, 16, 'content type UUID'),
       _hash = hash == null ? null : _copyExact(hash, 32, 'SHA-256 hash'),
       _salt = salt == null ? null : _copySalt(salt),
       _rawBytes = null {
    final value = label;
    if (value != null && value.contains('\u0000')) {
      throw const JumbfException(
        JumbfErrorCode.invalidDescription,
        'A JUMBF label must not contain a NUL character',
      );
    }
    if (id != null && (id! < 0 || id! > 0xffffffff)) {
      throw const JumbfException(
        JumbfErrorCode.invalidDescription,
        'A JUMBF description id must be an unsigned 32-bit integer',
      );
    }
  }

  /// Creates a `jumd` box description from a hexadecimal content-type UUID.
  factory JumbfDescription.fromUuidHex({
    required String contentType,
    bool requestable = true,
    String? label,
    int? id,
    Uint8List? hash,
    Uint8List? salt,
  }) => JumbfDescription(
    contentType: JumbfUuid.bytes(contentType),
    requestable: requestable,
    label: label,
    id: id,
    hash: hash,
    salt: salt,
  );

  final Uint8List _contentType;

  /// Whether the JUMBF requestable bit is set in the toggles byte.
  final bool requestable;

  /// The NUL-terminated JUMBF label, or `null` when absent.
  final String? label;

  /// The unsigned 32-bit JUMBF description id, or `null` when absent.
  final int? id;
  final Uint8List? _hash;
  final Uint8List? _salt;
  final Uint8List? _rawBytes;

  JumbfDescription._parsed({
    required Uint8List contentType,
    required this.requestable,
    required this.label,
    required this.id,
    required Uint8List? hash,
    required Uint8List? salt,
    required Uint8List rawBytes,
  }) : _contentType = Uint8List.fromList(contentType),
       _hash = hash == null ? null : Uint8List.fromList(hash),
       _salt = salt == null ? null : Uint8List.fromList(salt),
       _rawBytes = Uint8List.fromList(rawBytes);

  /// A copy of the 16-byte content-type UUID.
  Uint8List get contentType => Uint8List.fromList(_contentType);

  /// The lower-case hexadecimal content-type UUID.
  String get contentTypeHex => JumbfUuid.hex(_contentType);

  /// The 32-byte SHA-256 hash field, or `null` when absent.
  Uint8List? get hash => _hash == null ? null : Uint8List.fromList(_hash);

  /// The C2PA salt bytes, or `null` when absent.
  Uint8List? get salt => _salt == null ? null : Uint8List.fromList(_salt);

  /// Encodes this description as a `jumd` ISO box.
  Uint8List encode() {
    final original = _rawBytes;
    if (original != null) return Uint8List.fromList(original);
    final payload = BytesBuilder(copy: false)..add(_contentType);
    var toggles = requestable ? 0x01 : 0;
    if (label != null) toggles |= 0x02;
    if (id != null) toggles |= 0x04;
    if (_hash != null) toggles |= 0x08;
    if (_salt != null) toggles |= 0x10;
    payload.addByte(toggles);
    final labelValue = label;
    if (labelValue != null) {
      payload
        ..add(utf8.encode(labelValue))
        ..addByte(0);
    }
    final idValue = id;
    if (idValue != null) {
      final bytes = ByteData(4)..setUint32(0, idValue, Endian.big);
      payload.add(bytes.buffer.asUint8List());
    }
    final hashValue = _hash;
    if (hashValue != null) payload.add(hashValue);
    final saltValue = _salt;
    if (saltValue != null) {
      payload.add(_encodeBox(JumbfFourcc.salt, saltValue));
    }
    return _encodeBox(JumbfFourcc.description, payload.takeBytes());
  }

  /// Parses a single `jumd` box from [boxBytes].
  static JumbfDescription parse(
    List<int> boxBytes, {
    int offset = 0,
    int? end,
  }) {
    final input = _toBytes(boxBytes);
    final header = _parseHeader(input, offset: offset, end: end);
    if (header.type != JumbfFourcc.description) {
      throw JumbfException(
        JumbfErrorCode.expectedDescriptionBox,
        'Expected a jumd box, found ${header.type}',
        offset: offset,
      );
    }
    return _parseDescriptionPayload(
      input,
      header.offset + header.headerSize,
      header.endOffset,
      rawBytes: Uint8List.fromList(
        input.sublist(header.offset, header.endOffset),
      ),
    );
  }
}

/// Base type for immutable JUMBF tree nodes.
sealed class JumbfNode {
  /// Creates a JUMBF node that preserves [rawBytes] when parsed.
  JumbfNode(Uint8List? rawBytes)
    : _rawBytes = rawBytes == null ? null : Uint8List.fromList(rawBytes);

  final Uint8List? _rawBytes;

  /// The four-character ISO box type encoded for this node.
  String get boxType;

  /// Returns the exact parsed bytes, or the deterministic encoding for a new node.
  Uint8List get rawBytes => encode();

  /// Encodes this node as one complete ISO box.
  Uint8List encode();
}

/// A JUMBF superbox containing a description and child boxes.
final class JumbfSuperBoxNode extends JumbfNode {
  /// Creates a `jumb` superbox from [description] and child boxes.
  JumbfSuperBoxNode({
    required this.description,
    Iterable<JumbfNode> children = const [],
  }) : children = List<JumbfNode>.unmodifiable(children),
       super(null) {
    _checkDuplicateLabels(this.children);
  }

  JumbfSuperBoxNode._({
    required this.description,
    required this.children,
    required Uint8List rawBytes,
  }) : super(rawBytes);

  /// The first child `jumd` description box for this superbox.
  final JumbfDescription description;

  /// The content boxes or nested superboxes contained after [description].
  final List<JumbfNode> children;

  /// The description label used by C2PA JUMBF URI path segments.
  String? get label => description.label;

  /// Whether [description] marks this superbox as a C2PA `c2cm` box.
  bool get isCompressedManifest =>
      description.contentTypeHex == JumbfUuid.c2paCompressedManifest;

  @override
  String get boxType => JumbfFourcc.superBox;

  @override
  Uint8List encode() {
    final original = _rawBytes;
    if (original != null) return Uint8List.fromList(original);
    final payload = BytesBuilder(copy: false)..add(description.encode());
    for (final child in children) {
      payload.add(child.encode());
    }
    return _encodeBox(boxType, payload.takeBytes());
  }

  /// Finds a superbox by slash-separated labels or a `self#jumbf=` URI.
  JumbfSuperBoxNode? find(String pathOrUri) {
    var path = pathOrUri.trim();
    final marker = path.indexOf('jumbf=');
    if (marker >= 0) path = path.substring(marker + 6);
    final query = path.indexOf('?');
    if (query >= 0) path = path.substring(0, query);
    final fragment = path.indexOf('#');
    if (fragment >= 0) path = path.substring(0, fragment);

    final segments = path
        .split('/')
        .where((part) => part.isNotEmpty)
        .map((part) {
          try {
            return Uri.decodeComponent(part);
          } on FormatException {
            return part;
          }
        })
        .toList(growable: false);
    if (segments.isEmpty) return this;

    var current = this;
    var index = 0;
    if (segments.first == current.label) index = 1;
    for (; index < segments.length; index++) {
      JumbfSuperBoxNode? next;
      for (final child in current.children) {
        if (child is JumbfSuperBoxNode && child.label == segments[index]) {
          next = child;
          break;
        }
      }
      if (next == null) return null;
      current = next;
    }
    return current;
  }
}

/// Base type for leaf payload boxes.
sealed class JumbfPayloadNode extends JumbfNode {
  /// Creates a leaf content box with [boxType] and payload bytes.
  JumbfPayloadNode({
    required this.boxType,
    required Uint8List payload,
    Uint8List? rawBytes,
  }) : _payload = Uint8List.fromList(payload),
       super(rawBytes);

  @override
  /// The four-character ISO box type encoded for this content box.
  final String boxType;
  final Uint8List _payload;

  /// A copy of this content box payload without its ISO box header.
  Uint8List get payload => Uint8List.fromList(_payload);

  @override
  Uint8List encode() {
    final original = _rawBytes;
    return original == null
        ? _encodeBox(boxType, _payload)
        : Uint8List.fromList(original);
  }
}

/// A CBOR (`cbor`) content box.
final class JumbfCborNode extends JumbfPayloadNode {
  /// Creates a `cbor` content box with [payload].
  JumbfCborNode(Uint8List payload, {Uint8List? rawBytes})
    : super(boxType: JumbfFourcc.cbor, payload: payload, rawBytes: rawBytes);
}

/// A JSON (`json`) content box.
final class JumbfJsonNode extends JumbfPayloadNode {
  /// Creates a `json` content box with [payload].
  JumbfJsonNode(Uint8List payload, {Uint8List? rawBytes})
    : super(boxType: JumbfFourcc.json, payload: payload, rawBytes: rawBytes);
}

/// A Brotli-compressed (`brob`) content box.
final class JumbfBrotliNode extends JumbfPayloadNode {
  /// Creates a `brob` content box with Brotli-compressed [payload].
  JumbfBrotliNode(Uint8List payload, {Uint8List? rawBytes})
    : super(boxType: JumbfFourcc.brotli, payload: payload, rawBytes: rawBytes);
}

/// An embedded-file media type (`bfdb`) box.
final class JumbfEmbeddedFileDescriptionNode extends JumbfNode {
  /// Creates a `bfdb` box with a media type and optional file name.
  JumbfEmbeddedFileDescriptionNode({required this.mediaType, this.fileName})
    : super(null) {
    _validateCString(mediaType, 'media type');
    if (fileName != null) _validateCString(fileName!, 'file name');
  }

  JumbfEmbeddedFileDescriptionNode._({
    required this.mediaType,
    required this.fileName,
    required Uint8List rawBytes,
  }) : super(rawBytes);

  /// The NUL-terminated embedded-file media type.
  final String mediaType;

  /// The optional NUL-terminated embedded-file name.
  final String? fileName;

  @override
  String get boxType => JumbfFourcc.embeddedFileDescription;

  @override
  Uint8List encode() {
    final original = _rawBytes;
    if (original != null) return Uint8List.fromList(original);
    final payload = BytesBuilder(copy: false)
      ..addByte(fileName == null ? 0 : 1)
      ..add(utf8.encode(mediaType))
      ..addByte(0);
    final name = fileName;
    if (name != null) {
      payload
        ..add(utf8.encode(name))
        ..addByte(0);
    }
    return _encodeBox(boxType, payload.takeBytes());
  }
}

/// An embedded-file data (`bidb`) box.
final class JumbfEmbeddedFileNode extends JumbfPayloadNode {
  /// Creates a `bidb` content box with embedded file [payload].
  JumbfEmbeddedFileNode(Uint8List payload, {Uint8List? rawBytes})
    : super(
        boxType: JumbfFourcc.embeddedFileData,
        payload: payload,
        rawBytes: rawBytes,
      );
}

/// A UUID payload box. [payload] excludes the 16-byte ISO UUID field.
final class JumbfUuidNode extends JumbfPayloadNode {
  /// Creates a `uuid` box with a 16-byte [userType] and payload bytes.
  JumbfUuidNode({
    required Uint8List userType,
    required Uint8List payload,
    Uint8List? rawBytes,
  }) : _userType = _copyExact(userType, 16, 'UUID box user type'),
       super(boxType: JumbfFourcc.uuid, payload: payload, rawBytes: rawBytes);

  final Uint8List _userType;

  /// A copy of the 16-byte ISO UUID user type.
  Uint8List get userType => Uint8List.fromList(_userType);

  @override
  Uint8List encode() {
    final original = _rawBytes;
    if (original != null) return Uint8List.fromList(original);
    return _encodeBox(boxType, _payload, userType: _userType);
  }
}

/// A box whose type is not interpreted by this package.
final class JumbfUnknownNode extends JumbfPayloadNode {
  /// Creates an uninterpreted content box with [boxType] and [payload].
  JumbfUnknownNode({
    required String boxType,
    required Uint8List payload,
    Uint8List? rawBytes,
  }) : super(boxType: boxType, payload: payload, rawBytes: rawBytes);
}

/// Strictly parses one standalone JUMBF superbox.
/// Parses a JUMBF superbox from [bytes].
///
/// Set [allowTrailingData] when the caller received a container payload that
/// may be padded after the superbox — c2pa-rs reads the store with
/// `BoxReader::read_super_box` over a cursor and never requires the buffer to
/// be exhausted, and BMFF producers do emit such padding.
JumbfSuperBoxNode parseJumbf(
  List<int> bytes, {
  int maxNestingDepth = 64,
  int maxBoxCount = 10000,
  bool allowTrailingData = false,
}) {
  if (maxNestingDepth < 0 || maxBoxCount < 1) {
    throw const JumbfException(
      JumbfErrorCode.invalidBounds,
      'JUMBF limits must be non-negative and permit at least one box',
    );
  }
  final input = _toBytes(bytes);
  final state = _ParseState(
    input,
    maxNestingDepth: maxNestingDepth,
    maxBoxCount: maxBoxCount,
  );
  final result = state.parseSuperBox(0, input.length, 0);
  if (!allowTrailingData && result.$2 != input.length) {
    throw JumbfException(
      JumbfErrorCode.trailingData,
      'Trailing data follows the JUMBF superbox',
      offset: result.$2,
    );
  }
  return result.$1;
}

final class _ParseState {
  _ParseState(
    this.input, {
    required this.maxNestingDepth,
    required this.maxBoxCount,
  });

  final Uint8List input;
  final int maxNestingDepth;
  final int maxBoxCount;
  int boxCount = 0;

  (JumbfSuperBoxNode, int) parseSuperBox(int offset, int end, int depth) {
    if (depth > maxNestingDepth) {
      throw JumbfException(
        JumbfErrorCode.excessiveNesting,
        'JUMBF nesting exceeds the configured limit of $maxNestingDepth',
        offset: offset,
      );
    }
    final header = _countedHeader(offset, end);
    if (header.type != JumbfFourcc.superBox) {
      throw JumbfException(
        JumbfErrorCode.expectedSuperBox,
        'Expected a jumb box, found ${header.type}',
        offset: offset,
      );
    }
    final boxEnd = header.endOffset;
    var cursor = offset + header.headerSize;
    if (cursor >= boxEnd) {
      throw JumbfException(
        JumbfErrorCode.expectedDescriptionBox,
        'A JUMBF superbox must begin with a jumd box',
        offset: cursor,
      );
    }

    final descriptionHeader = _countedHeader(cursor, boxEnd);
    if (descriptionHeader.type != JumbfFourcc.description) {
      throw JumbfException(
        JumbfErrorCode.expectedDescriptionBox,
        'A JUMBF superbox must begin with a jumd box',
        offset: cursor,
      );
    }
    final description = _parseDescriptionPayload(
      input,
      cursor + descriptionHeader.headerSize,
      descriptionHeader.endOffset,
      rawBytes: Uint8List.fromList(
        input.sublist(cursor, descriptionHeader.endOffset),
      ),
    );
    cursor = descriptionHeader.endOffset;

    final children = <JumbfNode>[];
    final childLabels = <String>{};
    while (cursor < boxEnd) {
      final childHeader = _parseHeader(input, offset: cursor, end: boxEnd);
      late JumbfNode child;
      if (childHeader.type == JumbfFourcc.superBox) {
        final parsed = parseSuperBox(cursor, boxEnd, depth + 1);
        child = parsed.$1;
        final label = parsed.$1.label;
        if (label != null && !childLabels.add(label)) {
          throw JumbfException(
            JumbfErrorCode.duplicateLabel,
            'Duplicate sibling JUMBF label: $label',
            offset: cursor,
          );
        }
      } else {
        _countBox(cursor);
        child = _parsePayload(childHeader);
      }
      children.add(child);
      cursor = childHeader.endOffset;
    }
    if (cursor != boxEnd) {
      throw JumbfException(
        JumbfErrorCode.invalidBounds,
        'A child box crosses its parent superbox boundary',
        offset: cursor,
      );
    }

    return (
      JumbfSuperBoxNode._(
        description: description,
        children: List<JumbfNode>.unmodifiable(children),
        rawBytes: Uint8List.fromList(input.sublist(offset, boxEnd)),
      ),
      boxEnd,
    );
  }

  JumbfNode _parsePayload(IsoBoxHeader header) {
    final start = header.offset;
    final payloadStart = start + header.headerSize;
    final raw = Uint8List.fromList(input.sublist(start, header.endOffset));
    final payload = Uint8List.fromList(
      input.sublist(payloadStart, header.endOffset),
    );
    switch (header.type) {
      case JumbfFourcc.cbor:
        return JumbfCborNode(payload, rawBytes: raw);
      case JumbfFourcc.json:
        return JumbfJsonNode(payload, rawBytes: raw);
      case JumbfFourcc.brotli:
        return JumbfBrotliNode(payload, rawBytes: raw);
      case JumbfFourcc.embeddedFileDescription:
        return _parseEmbeddedFileDescription(payload, raw, payloadStart);
      case JumbfFourcc.embeddedFileData:
        return JumbfEmbeddedFileNode(payload, rawBytes: raw);
      case JumbfFourcc.uuid:
        return JumbfUuidNode(
          userType: header.userType!,
          payload: payload,
          rawBytes: raw,
        );
      case JumbfFourcc.description:
        throw JumbfException(
          JumbfErrorCode.invalidBox,
          'A jumd box is only valid as the first child of a superbox',
          offset: start,
        );
      default:
        return JumbfUnknownNode(
          boxType: header.type,
          payload: payload,
          rawBytes: raw,
        );
    }
  }

  IsoBoxHeader _countedHeader(int offset, int end) {
    _countBox(offset);
    return _parseHeader(input, offset: offset, end: end);
  }

  void _countBox(int offset) {
    boxCount++;
    if (boxCount > maxBoxCount) {
      throw JumbfException(
        JumbfErrorCode.excessiveBoxCount,
        'JUMBF box count exceeds the configured limit of $maxBoxCount',
        offset: offset,
      );
    }
  }
}

/// A validated compressed C2PA manifest and its expanded inner superbox.
final class JumbfCompressedManifest {
  JumbfCompressedManifest._({
    required this.outer,
    required this.manifest,
    required JumbfBrotliNode brotliBox,
  }) : _originalBytes = outer.rawBytes,
       _outerDescriptionBytes = outer.description.encode(),
       _brotliBoxBytes = brotliBox.rawBytes,
       _compressedPayload = brotliBox.payload;

  /// The outer `c2cm` compressed-manifest superbox.
  final JumbfSuperBoxNode outer;

  /// The expanded inner `c2ma` or `c2um` manifest superbox.
  final JumbfSuperBoxNode manifest;
  final Uint8List _originalBytes;
  final Uint8List _outerDescriptionBytes;
  final Uint8List _brotliBoxBytes;
  final Uint8List _compressedPayload;

  /// The exact outer compressed-manifest superbox bytes.
  Uint8List get originalBytes => Uint8List.fromList(_originalBytes);

  /// The exact outer `jumd` bytes covered by compressed ingredient hashes.
  Uint8List get outerDescriptionBytes =>
      Uint8List.fromList(_outerDescriptionBytes);

  /// The exact original `brob` box, including its ISO box header.
  Uint8List get brotliBoxBytes => Uint8List.fromList(_brotliBoxBytes);

  /// The compressed Brotli payload without its ISO box header.
  Uint8List get compressedPayload => Uint8List.fromList(_compressedPayload);
}

/// Decodes and validates one C2PA compressed-manifest JUMBF superbox.
JumbfCompressedManifest decodeCompressedJumbf(
  List<int> bytes, {
  required int maxOutputBytes,
  int maxNestingDepth = 64,
  int maxBoxCount = 10000,
}) {
  final outer = parseJumbf(
    bytes,
    maxNestingDepth: maxNestingDepth,
    maxBoxCount: maxBoxCount,
  );
  if (!outer.isCompressedManifest) {
    throw const JumbfException(
      JumbfErrorCode.invalidCompressedManifest,
      'Outer JUMBF description is not a c2cm compressed manifest',
    );
  }
  if (outer.children.length != 1 || outer.children.single is! JumbfBrotliNode) {
    throw const JumbfException(
      JumbfErrorCode.invalidCompressedManifest,
      'A c2cm superbox must contain exactly one brob content box',
    );
  }
  final brotliBox = outer.children.single as JumbfBrotliNode;
  final expanded = decodeBrotli(
    brotliBox.payload,
    maxOutputBytes: maxOutputBytes,
  );
  final manifest = parseJumbf(
    expanded,
    maxNestingDepth: maxNestingDepth,
    maxBoxCount: maxBoxCount,
  );
  final innerType = manifest.description.contentTypeHex;
  if (innerType != JumbfUuid.c2paManifest &&
      innerType != JumbfUuid.c2paUpdateManifest) {
    throw const JumbfException(
      JumbfErrorCode.invalidCompressedManifest,
      'Expanded content must be one c2ma or c2um manifest superbox',
    );
  }
  if (outer.label == null ||
      manifest.label == null ||
      outer.label != manifest.label) {
    throw JumbfException(
      JumbfErrorCode.compressedManifestLabelMismatch,
      'Compressed outer and expanded inner labels must match',
    );
  }
  return JumbfCompressedManifest._(
    outer: outer,
    manifest: manifest,
    brotliBox: brotliBox,
  );
}

JumbfDescription _parseDescriptionPayload(
  Uint8List input,
  int start,
  int end, {
  Uint8List? rawBytes,
}) {
  if (end - start < 17) {
    throw JumbfException(
      JumbfErrorCode.invalidDescription,
      'A jumd payload requires a UUID and toggles byte',
      offset: start,
    );
  }
  var cursor = start;
  final contentType = Uint8List.fromList(input.sublist(cursor, cursor + 16));
  cursor += 16;
  final toggles = input[cursor++];
  if ((toggles & 0xe0) != 0) {
    throw JumbfException(
      JumbfErrorCode.unsupportedDescriptionFeature,
      'Unsupported JUMBF description toggle bits: 0x${toggles.toRadixString(16)}',
      offset: cursor - 1,
    );
  }

  String? label;
  if ((toggles & 0x02) != 0) {
    final parsed = _readCString(input, cursor, end, 'JUMBF label');
    label = parsed.$1;
    cursor = parsed.$2;
  }

  int? id;
  if ((toggles & 0x04) != 0) {
    if (end - cursor < 4) {
      throw JumbfException(
        JumbfErrorCode.invalidDescription,
        'JUMBF description id is truncated',
        offset: cursor,
      );
    }
    id = ByteData.sublistView(
      input,
      cursor,
      cursor + 4,
    ).getUint32(0, Endian.big);
    cursor += 4;
  }

  Uint8List? hash;
  if ((toggles & 0x08) != 0) {
    if (end - cursor < 32) {
      throw JumbfException(
        JumbfErrorCode.invalidDescription,
        'JUMBF description hash is truncated',
        offset: cursor,
      );
    }
    hash = Uint8List.fromList(input.sublist(cursor, cursor + 32));
    cursor += 32;
  }

  Uint8List? salt;
  if ((toggles & 0x10) != 0) {
    final header = _parseHeader(input, offset: cursor, end: end);
    if (header.type != JumbfFourcc.salt || header.endOffset != end) {
      throw JumbfException(
        JumbfErrorCode.invalidDescription,
        'JUMBF private description data must be one c2sh box',
        offset: cursor,
      );
    }
    final payloadStart = cursor + header.headerSize;
    if (header.endOffset - payloadStart < 16) {
      throw JumbfException(
        JumbfErrorCode.invalidDescription,
        'A JUMBF salt must contain at least 16 bytes',
        offset: payloadStart,
      );
    }
    salt = Uint8List.fromList(input.sublist(payloadStart, header.endOffset));
    cursor = header.endOffset;
  }
  if (cursor != end) {
    throw JumbfException(
      JumbfErrorCode.invalidDescription,
      'Unexpected trailing bytes in JUMBF description',
      offset: cursor,
    );
  }

  if (rawBytes != null) {
    return JumbfDescription._parsed(
      contentType: contentType,
      requestable: (toggles & 0x01) != 0,
      label: label,
      id: id,
      hash: hash,
      salt: salt,
      rawBytes: rawBytes,
    );
  }
  return JumbfDescription(
    contentType: contentType,
    requestable: (toggles & 0x01) != 0,
    label: label,
    id: id,
    hash: hash,
    salt: salt,
  );
}

Uint8List _copySalt(Uint8List value) {
  if (value.length < 16) {
    throw const JumbfException(
      JumbfErrorCode.invalidDescription,
      'A JUMBF salt must contain at least 16 bytes',
    );
  }
  return Uint8List.fromList(value);
}

JumbfEmbeddedFileDescriptionNode _parseEmbeddedFileDescription(
  Uint8List payload,
  Uint8List raw,
  int payloadOffset,
) {
  if (payload.isEmpty || (payload[0] & 0xfe) != 0) {
    throw JumbfException(
      JumbfErrorCode.invalidEmbeddedFileDescription,
      'Invalid embedded-file description toggles',
      offset: payloadOffset,
    );
  }
  var cursor = 1;
  final media = _readCString(
    payload,
    cursor,
    payload.length,
    'embedded-file media type',
    baseOffset: payloadOffset,
    errorCode: JumbfErrorCode.invalidEmbeddedFileDescription,
  );
  cursor = media.$2;
  String? fileName;
  if ((payload[0] & 1) != 0) {
    final name = _readCString(
      payload,
      cursor,
      payload.length,
      'embedded-file name',
      baseOffset: payloadOffset,
      errorCode: JumbfErrorCode.invalidEmbeddedFileDescription,
    );
    fileName = name.$1;
    cursor = name.$2;
  }
  if (cursor != payload.length) {
    throw JumbfException(
      JumbfErrorCode.invalidEmbeddedFileDescription,
      'Unexpected trailing bytes in embedded-file description',
      offset: payloadOffset + cursor,
    );
  }
  return JumbfEmbeddedFileDescriptionNode._(
    mediaType: media.$1,
    fileName: fileName,
    rawBytes: raw,
  );
}

(String, int) _readCString(
  Uint8List input,
  int start,
  int end,
  String name, {
  int baseOffset = 0,
  JumbfErrorCode errorCode = JumbfErrorCode.invalidDescription,
}) {
  var terminator = start;
  while (terminator < end && input[terminator] != 0) {
    terminator++;
  }
  if (terminator == end) {
    throw JumbfException(
      errorCode,
      '$name is not NUL-terminated',
      offset: baseOffset + start,
    );
  }
  try {
    return (
      utf8.decode(input.sublist(start, terminator), allowMalformed: false),
      terminator + 1,
    );
  } on FormatException {
    throw JumbfException(
      JumbfErrorCode.invalidUtf8,
      '$name contains invalid UTF-8',
      offset: baseOffset + start,
    );
  }
}

void _checkDuplicateLabels(List<JumbfNode> children) {
  final labels = <String>{};
  for (final child in children) {
    if (child is JumbfSuperBoxNode) {
      final label = child.label;
      if (label != null && !labels.add(label)) {
        throw JumbfException(
          JumbfErrorCode.duplicateLabel,
          'Duplicate sibling JUMBF label: $label',
        );
      }
    }
  }
}

void _validateCString(String value, String name) {
  if (value.contains('\u0000')) {
    throw JumbfException(
      JumbfErrorCode.invalidEmbeddedFileDescription,
      'The embedded-file $name must not contain a NUL character',
    );
  }
}

Uint8List _copyExact(Uint8List value, int length, String name) {
  if (value.length != length) {
    throw JumbfException(
      JumbfErrorCode.invalidDescription,
      'A JUMBF $name must contain exactly $length bytes',
    );
  }
  return Uint8List.fromList(value);
}

Uint8List _encodeBox(String type, Uint8List payload, {Uint8List? userType}) {
  final header = IsoBoxHeader.create(
    type: type,
    payloadSize: payload.length,
    userType: userType,
  ).encode();
  return Uint8List.fromList([...header, ...payload]);
}

Uint8List _toBytes(List<int> bytes) {
  try {
    return bytes is Uint8List ? bytes : Uint8List.fromList(bytes);
  } on RangeError {
    throw const JumbfException(
      JumbfErrorCode.invalidBox,
      'JUMBF input contains a value outside the byte range',
    );
  }
}

IsoBoxHeader _parseHeader(Uint8List bytes, {required int offset, int? end}) {
  try {
    return IsoBoxHeader.parse(bytes, offset: offset, end: end);
  } on IsoBoxException catch (error) {
    throw JumbfException(
      JumbfErrorCode.invalidBox,
      error.message,
      offset: error.offset ?? offset,
    );
  }
}
