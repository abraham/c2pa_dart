import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../errors.dart';
import '../hash_layout.dart';
import '../xmp.dart';
import '../xmp_remote_reference.dart';

/// An SVG handler for C2PA manifest elements.
///
/// The manifest is base64 text in a `c2pa:manifest` element that must be a
/// direct child of SVG `metadata`.
final class SvgAssetHandler
    implements
        AssetHandler,
        DataHashLayoutProvider,
        BoxHashLayoutProvider,
        XmpMetadataProvider,
        RemoteManifestReferenceProvider {
  /// Creates an SVG handler with XML element and byte limits.
  const SvgAssetHandler({
    this.maxManifestSize = 64 * 1024 * 1024,
    this.maxSourceSize = 64 * 1024 * 1024,
    this.maxOutputSize = 128 * 1024 * 1024,
    this.maxElementCount = 1024 * 1024,
    this.maxDepth = 4096,
    this.maxXmpSize = 4 * 1024 * 1024,
    this.maxRemoteReferenceLength = 64 * 1024,
  });

  static const String _svgNamespace = 'http://www.w3.org/2000/svg';
  static const String _c2paNamespace = 'http://c2pa.org/manifest';
  static const String _rdfNamespace =
      'http://www.w3.org/1999/02/22-rdf-syntax-ns#';
  static const String _dctermsNamespace = 'http://purl.org/dc/terms/';
  static const String _xpacketId = 'W5M0MpCehiHzreSzNTczkc9d';

  /// Maximum decoded C2PA manifest size in bytes.
  final int maxManifestSize;

  /// Maximum source SVG size in bytes.
  final int maxSourceSize;

  /// Maximum rewritten SVG size in bytes.
  final int maxOutputSize;

  /// Maximum number of XML tokens parsed from the SVG.
  final int maxElementCount;

  /// Maximum XML nesting depth accepted while parsing.
  final int maxDepth;

  /// Maximum XMP packet size in bytes.
  final int maxXmpSize;

  /// Maximum UTF-8 length of a remote reference in bytes.
  final int maxRemoteReferenceLength;

  @override
  String get name => 'SVG';

  @override
  AssetFormat get format => AssetFormat.svg;

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
    mimeTypes: <String>['image/svg+xml', 'application/svg+xml'],
    fileExtensions: <String>['svg'],
  );

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    try {
      await _inspect(source);
      return true;
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
    if (manifest == null) {
      throw const ManifestNotFoundException(AssetFormat.svg);
    }
    final encoded = StringBuffer();
    for (final range in manifest.contentRanges) {
      encoded.write(
        utf8.decode(inspection.bytes.sublist(range.start, range.end)),
      );
    }
    final normalized = encoded.toString().replaceAll(
      RegExp(r'[\u0009\u000a\u000d\u0020]'),
      '',
    );
    if (normalized.isEmpty) {
      throw const ManifestNotFoundException(AssetFormat.svg);
    }
    final maximumDecodedLength = (normalized.length * 3 + 3) ~/ 4;
    if (maximumDecodedLength > maxManifestSize + 2) {
      throw AssetLimitExceededException(
        limit: maxManifestSize,
        actual: maximumDecodedLength,
      );
    }
    late Uint8List decoded;
    try {
      decoded = base64.decode(normalized);
    } on FormatException {
      throw const MalformedAssetFormatException(
        'The SVG C2PA manifest contains invalid base64.',
      );
    }
    if (decoded.length > maxManifestSize) {
      throw AssetLimitExceededException(
        limit: maxManifestSize,
        actual: decoded.length,
      );
    }
    return decoded;
  }

  @override
  Future<void> embedManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) => _mutateManifest(
    source,
    output,
    operation: _SvgMutation.embed,
    manifest: manifest,
  );

  @override
  Future<void> replaceManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) => _mutateManifest(
    source,
    output,
    operation: _SvgMutation.replace,
    manifest: manifest,
  );

  @override
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) => _mutateManifest(source, output, operation: _SvgMutation.remove);

  @override
  Future<DataHashLayout> getDataHashLayout(
    RandomAccessByteSource source,
  ) async {
    final inspection = await _inspect(source);
    final manifest = inspection.manifest;
    final insertionParent = inspection.metadata ?? inspection.root;
    return DataHashLayout(
      sourceLength: inspection.bytes.length,
      insertionOffset:
          manifest?.contentStart ??
          (insertionParent.selfClosing
              ? insertionParent.closeStart
              : insertionParent.openEnd),
      exclusions: manifest == null
          ? const []
          : [
              DataHashExclusion(
                range: ByteRange(manifest.contentStart, manifest.contentEnd),
                kind: DataHashExclusionKind.manifest,
                name: 'c2pa:manifest base64',
              ),
            ],
    );
  }

  @override
  Future<BoxHashLayout> getBoxHashLayout(RandomAccessByteSource source) async {
    throw const UnsupportedHashLayoutException(
      AssetFormat.svg,
      HashLayoutKind.boxHash,
    );
  }

  @override
  Future<String?> readXmp(RandomAccessByteSource source) async {
    final inspection = await _inspect(source);
    final range = inspection.xmpRange;
    if (range == null) return null;
    if (range.length > maxXmpSize) {
      throw AssetLimitExceededException(
        limit: maxXmpSize,
        actual: range.length,
      );
    }
    return utf8.decode(inspection.bytes.sublist(range.start, range.end));
  }

  @override
  Future<void> embedRemoteReference(
    RandomAccessByteSource source,
    String reference,
    WritableByteSink output,
  ) async {
    await _requireEmptySink(output);
    final referenceBytes = utf8.encode(reference);
    if (!_isValidXmlString(reference)) {
      throw const MalformedAssetFormatException(
        'The remote reference contains characters that are invalid in XML.',
      );
    }
    if (referenceBytes.length > maxRemoteReferenceLength) {
      throw AssetLimitExceededException(
        limit: maxRemoteReferenceLength,
        actual: referenceBytes.length,
      );
    }
    final inspection = await _inspect(source);
    final escaped = _escapeAttribute(reference);
    final patches = <_SvgPatch>[];
    final xmpRange = inspection.xmpRange;
    if (xmpRange == null) {
      final xmp = _minimalXmp(escaped);
      if (utf8.encode(xmp).length > maxXmpSize) {
        throw AssetLimitExceededException(
          limit: maxXmpSize,
          actual: utf8.encode(xmp).length,
        );
      }
      final metadataName = inspection.root.prefix.isEmpty
          ? 'metadata'
          : '${inspection.root.prefix}:metadata';
      _addChildInsertion(
        inspection,
        inspection.metadata == null
            ? '<$metadataName>$xmp</$metadataName>'
            : xmp,
        patches,
        requireC2paNamespace: false,
      );
    } else {
      final original = Uint8List.fromList(
        inspection.bytes.sublist(xmpRange.start, xmpRange.end),
      );
      final updated = XmpRemoteReferenceEditor.parse(
        original,
        maxLength: maxXmpSize,
      ).update(reference, maxLength: maxXmpSize);
      patches.add(
        _SvgPatch(xmpRange.start, xmpRange.end, utf8.decode(updated)),
      );
    }
    await _writePatched(inspection.bytes, patches, output);
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
  Future<void> updateRemoteManifestReference(
    RandomAccessByteSource source,
    String reference,
    WritableByteSink output,
  ) => embedRemoteReference(source, reference, output);

  @override
  Future<void> removeRemoteManifestReference(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) async {
    await _requireEmptySink(output);
    final inspection = await _inspect(source);
    final range = inspection.xmpRange;
    if (range == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.svg);
    }
    final editor = XmpRemoteReferenceEditor.parse(
      Uint8List.fromList(inspection.bytes.sublist(range.start, range.end)),
      maxLength: maxXmpSize,
    );
    if (editor.value == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.svg);
    }
    final updated = editor.remove(maxLength: maxXmpSize);
    await _writePatched(inspection.bytes, <_SvgPatch>[
      _SvgPatch(range.start, range.end, utf8.decode(updated)),
    ], output);
  }

  Future<void> _mutateManifest(
    RandomAccessByteSource source,
    WritableByteSink output, {
    required _SvgMutation operation,
    Uint8List? manifest,
  }) async {
    await _requireEmptySink(output);
    if (manifest != null && manifest.length > maxManifestSize) {
      throw AssetLimitExceededException(
        limit: maxManifestSize,
        actual: manifest.length,
      );
    }
    final inspection = await _inspect(source);
    final existing = inspection.manifest;
    if (operation == _SvgMutation.embed && existing != null) {
      throw const ManifestAlreadyExistsException(AssetFormat.svg);
    }
    if (operation != _SvgMutation.embed && existing == null) {
      throw const ManifestNotFoundException(AssetFormat.svg);
    }

    final patches = <_SvgPatch>[];
    if (operation == _SvgMutation.remove) {
      patches.add(_SvgPatch(existing!.start, existing.end, ''));
    } else if (operation == _SvgMutation.replace) {
      final encoded = base64.encode(manifest!);
      if (existing!.contentStart == existing.contentEnd &&
          inspection.bytes[existing.contentStart] == 0x2f) {
        final startToken = inspection.tokens.firstWhere(
          (token) =>
              token.kind == _XmlTokenKind.start &&
              token.start == existing.start,
        );
        patches.add(
          _SvgPatch(
            existing.start,
            existing.end,
            '${utf8.decode(inspection.bytes.sublist(existing.start, existing.contentStart))}'
            '>$encoded</${startToken.name}>',
          ),
        );
      } else {
        patches.add(
          _SvgPatch(existing.contentStart, existing.contentEnd, encoded),
        );
      }
    } else {
      final element =
          '<c2pa:manifest>${base64.encode(manifest!)}</c2pa:manifest>';
      final metadataName = inspection.root.prefix.isEmpty
          ? 'metadata'
          : '${inspection.root.prefix}:metadata';
      _addChildInsertion(
        inspection,
        inspection.metadata == null
            ? '<$metadataName>$element</$metadataName>'
            : element,
        patches,
        requireC2paNamespace: true,
      );
    }
    await _writePatched(inspection.bytes, patches, output);
  }

  void _addChildInsertion(
    _SvgInspection inspection,
    String content,
    List<_SvgPatch> patches, {
    required bool requireC2paNamespace,
  }) {
    final parent = inspection.metadata ?? inspection.root;
    final root = inspection.root;
    final effectiveNamespace = parent.namespaces['c2pa'];
    if (requireC2paNamespace &&
        effectiveNamespace != null &&
        effectiveNamespace != _c2paNamespace) {
      throw const MalformedAssetFormatException(
        'The c2pa prefix is bound to an unexpected namespace.',
      );
    }
    final namespaceText = requireC2paNamespace && effectiveNamespace == null
        ? ' xmlns:c2pa="$_c2paNamespace"'
        : '';

    if (parent.selfClosing) {
      if (parent != root && namespaceText.isNotEmpty) {
        patches.add(_SvgPatch(root.closeStart, root.closeStart, namespaceText));
      }
      final replacement =
          '${utf8.decode(inspection.bytes.sublist(parent.start, parent.closeStart))}'
          '${parent == root ? namespaceText : ''}>$content'
          '</${parent.name}>';
      patches.add(_SvgPatch(parent.start, parent.end, replacement));
      return;
    }
    if (namespaceText.isNotEmpty) {
      patches.add(_SvgPatch(root.closeStart, root.closeStart, namespaceText));
    }
    patches.add(_SvgPatch(parent.openEnd, parent.openEnd, content));
  }

  Future<void> _writePatched(
    Uint8List source,
    List<_SvgPatch> patches,
    WritableByteSink output,
  ) async {
    patches.sort((left, right) => left.start.compareTo(right.start));
    var previousEnd = 0;
    var outputLength = source.length;
    for (final patch in patches) {
      if (patch.start < previousEnd ||
          patch.end < patch.start ||
          patch.end > source.length) {
        throw const MalformedAssetFormatException(
          'SVG rewrite patches overlap or exceed the source.',
        );
      }
      previousEnd = patch.end;
      outputLength +=
          utf8.encode(patch.replacement).length - (patch.end - patch.start);
    }
    if (outputLength > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: outputLength,
      );
    }
    final staged = BytesBuilder(copy: false);
    var position = 0;
    for (final patch in patches) {
      staged
        ..add(source.sublist(position, patch.start))
        ..add(utf8.encode(patch.replacement));
      position = patch.end;
    }
    staged.add(source.sublist(position));
    final bytes = staged.takeBytes();
    if (bytes.length != outputLength) {
      throw const MalformedAssetFormatException(
        'SVG rewrite produced an unexpected output length.',
      );
    }
    await output.append(bytes);
  }

  Future<_SvgInspection> _inspect(RandomAccessByteSource source) async {
    final sourceLength = await source.length;
    if (sourceLength > maxSourceSize) {
      throw AssetLimitExceededException(
        limit: maxSourceSize,
        actual: sourceLength,
      );
    }
    if (sourceLength == 0) {
      throw const TruncatedAssetException(expectedLength: 1, actualLength: 0);
    }
    final bytes = await source.read(ByteRange(0, sourceLength));
    try {
      final text = utf8.decode(bytes);
      if (!_isValidXmlString(text)) {
        throw const MalformedAssetFormatException(
          'SVG data contains characters that are invalid in XML.',
        );
      }
    } on FormatException {
      throw const MalformedAssetFormatException(
        'SVG data must be valid UTF-8 XML.',
      );
    }
    return _SvgParser(
      bytes,
      maxElementCount: maxElementCount,
      maxDepth: maxDepth,
    ).parse();
  }

  Future<void> _requireEmptySink(WritableByteSink output) async {
    if (await output.length != 0) {
      throw const MalformedAssetFormatException(
        'The destination sink must be empty.',
      );
    }
  }

  static String _minimalXmp(String escapedReference) =>
      '<?xpacket begin="" id="$_xpacketId"?>'
      '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
      '<rdf:RDF xmlns:rdf="$_rdfNamespace">'
      '<rdf:Description rdf:about="" xmlns:dcterms="$_dctermsNamespace" '
      'dcterms:provenance="$escapedReference"></rdf:Description>'
      '</rdf:RDF></x:xmpmeta><?xpacket end="w"?>';

  static String _escapeAttribute(String value) => value
      .replaceAll('&', '&amp;')
      .replaceAll('"', '&quot;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;');

  static bool _isValidXmlString(String value) {
    for (final rune in value.runes) {
      if (rune != 0x09 &&
          rune != 0x0a &&
          rune != 0x0d &&
          (rune < 0x20 ||
              rune == 0xfffe ||
              rune == 0xffff ||
              rune > 0x10ffff)) {
        return false;
      }
    }
    return true;
  }
}

/// Backward-compatible alias for [SvgAssetHandler].
typedef SvgHandler = SvgAssetHandler;

enum _SvgMutation { embed, replace, remove }

enum _XmlTokenKind { start, end, text, comment, cdata, processingInstruction }

final class _SvgPatch {
  const _SvgPatch(this.start, this.end, this.replacement);

  final int start;
  final int end;
  final String replacement;
}

final class _XmlAttribute {
  const _XmlAttribute({
    required this.name,
    required this.localName,
    required this.value,
    required this.valueStart,
    required this.valueEnd,
    required this.namespaceUri,
  });

  final String name;
  final String localName;
  final String value;
  final int valueStart;
  final int valueEnd;
  final String? namespaceUri;
}

final class _XmlToken {
  const _XmlToken({
    required this.kind,
    required this.start,
    required this.end,
    this.openEnd = 0,
    this.closeStart = 0,
    this.name = '',
    this.localName = '',
    this.prefix = '',
    this.namespaceUri,
    this.selfClosing = false,
    this.depth = 0,
    this.parentStart,
    this.attributes = const [],
    this.namespaces = const {},
  });

  final _XmlTokenKind kind;
  final int start;
  final int end;
  final int openEnd;
  final int closeStart;
  final String name;
  final String localName;
  final String prefix;
  final String? namespaceUri;
  final bool selfClosing;
  final int depth;
  final int? parentStart;
  final List<_XmlAttribute> attributes;
  final Map<String, String> namespaces;
}

final class _SvgManifest {
  const _SvgManifest({
    required this.start,
    required this.end,
    required this.contentStart,
    required this.contentEnd,
    required this.contentRanges,
  });

  final int start;
  final int end;
  final int contentStart;
  final int contentEnd;
  final List<ByteRange> contentRanges;
}

final class _SvgInspection {
  const _SvgInspection({
    required this.bytes,
    required this.root,
    required this.metadata,
    required this.manifest,
    required this.xmpRange,
    required this.tokens,
  });

  final Uint8List bytes;
  final _XmlToken root;
  final _XmlToken? metadata;
  final _SvgManifest? manifest;
  final ByteRange? xmpRange;
  final List<_XmlToken> tokens;
}

final class _OpenElement {
  const _OpenElement(this.token);

  final _XmlToken token;
}

final class _SvgParser {
  const _SvgParser(
    this.bytes, {
    required this.maxElementCount,
    required this.maxDepth,
  });

  final Uint8List bytes;
  final int maxElementCount;
  final int maxDepth;

  _SvgInspection parse() {
    var position = _hasBom ? 3 : 0;
    final stack = <_OpenElement>[];
    final tokens = <_XmlToken>[];
    _XmlToken? root;
    _XmlToken? metadata;
    _XmlToken? manifestStart;
    _SvgManifest? manifest;
    final manifestContent = <ByteRange>[];
    int? xmpStart;
    ByteRange? xmpRange;
    var rootClosed = false;
    var elementCount = 0;
    var sawXmlDeclaration = false;

    while (position < bytes.length) {
      if (bytes[position] != 0x3c) {
        final start = position;
        while (position < bytes.length && bytes[position] != 0x3c) {
          position++;
        }
        _validateEntities(start, position);
        if (_containsSequence(start, position, ']]>')) {
          throw const MalformedAssetFormatException(
            'SVG text contains an invalid CDATA terminator.',
          );
        }
        if (stack.isEmpty &&
            bytes
                .sublist(start, position)
                .any((byte) => !_isXmlWhitespace(byte))) {
          throw const MalformedAssetFormatException(
            'SVG contains text outside its root element.',
          );
        }
        if (manifestStart != null) {
          manifestContent.add(ByteRange(start, position));
        }
        tokens.add(
          _XmlToken(kind: _XmlTokenKind.text, start: start, end: position),
        );
        continue;
      }

      if (_matches(position, '<!--')) {
        final end = _findSequence(position + 4, '-->');
        for (var index = position + 4; index < end - 4; index++) {
          if (bytes[index] == 0x2d && bytes[index + 1] == 0x2d) {
            throw const MalformedAssetFormatException(
              'An SVG comment contains an invalid double hyphen.',
            );
          }
        }
        tokens.add(
          _XmlToken(kind: _XmlTokenKind.comment, start: position, end: end),
        );
        position = end;
        continue;
      }
      if (_matches(position, '<![CDATA[')) {
        if (stack.isEmpty) {
          throw const MalformedAssetFormatException(
            'CDATA is not allowed outside the SVG root.',
          );
        }
        final end = _findSequence(position + 9, ']]>');
        if (manifestStart != null) {
          manifestContent.add(ByteRange(position + 9, end - 3));
        }
        tokens.add(
          _XmlToken(kind: _XmlTokenKind.cdata, start: position, end: end),
        );
        position = end;
        continue;
      }
      if (_matches(position, '<?')) {
        final end = _findSequence(position + 2, '?>');
        final content = utf8.decode(bytes.sublist(position + 2, end - 2));
        final target = content.trimLeft().split(RegExp(r'\s')).first;
        if (target.toLowerCase() == 'xml') {
          if (root != null || sawXmlDeclaration) {
            throw const MalformedAssetFormatException(
              'The XML declaration must occur once before the root element.',
            );
          }
          sawXmlDeclaration = true;
        }
        if (target == 'xpacket') {
          final isStart = content.contains(SvgAssetHandler._xpacketId);
          if (isStart) {
            if (xmpStart != null || xmpRange != null) {
              throw const MalformedAssetFormatException(
                'The SVG contains duplicate XMP packets.',
              );
            }
            xmpStart = position;
          } else {
            if (xmpStart == null) {
              throw const MalformedAssetFormatException(
                'The SVG contains an unmatched XMP packet terminator.',
              );
            }
            xmpRange = ByteRange(xmpStart, end);
            xmpStart = null;
          }
        }
        tokens.add(
          _XmlToken(
            kind: _XmlTokenKind.processingInstruction,
            start: position,
            end: end,
          ),
        );
        position = end;
        continue;
      }
      if (_matchesCaseInsensitive(position, '<!DOCTYPE')) {
        if (root != null) {
          throw const MalformedAssetFormatException(
            'The SVG document type must precede the root element.',
          );
        }
        position = _scanDeclarationEnd(position + 2);
        continue;
      }
      if (_matches(position, '<!')) {
        throw const MalformedAssetFormatException(
          'Unsupported XML declaration.',
        );
      }
      if (_matches(position, '</')) {
        final end = _scanTagEnd(position);
        final name = _readName(position + 2, end - 1);
        for (var index = name.end; index < end - 1; index++) {
          if (!_isXmlWhitespace(bytes[index])) {
            throw const MalformedAssetFormatException(
              'An SVG closing tag contains unexpected content.',
            );
          }
        }
        if (stack.isEmpty || stack.last.token.name != name.value) {
          throw const MalformedAssetFormatException(
            'SVG contains mismatched element tags.',
          );
        }
        final open = stack.removeLast().token;
        final token = _XmlToken(
          kind: _XmlTokenKind.end,
          start: position,
          end: end,
          name: name.value,
          localName: _localName(name.value),
          depth: stack.length,
          parentStart: stack.isEmpty ? null : stack.last.token.start,
        );
        tokens.add(token);
        if (manifestStart?.start == open.start) {
          manifest = _SvgManifest(
            start: open.start,
            end: end,
            contentStart: open.openEnd,
            contentEnd: position,
            contentRanges: List<ByteRange>.unmodifiable(manifestContent),
          );
          manifestStart = null;
        }
        if (open.start == root?.start) rootClosed = true;
        position = end;
        continue;
      }

      final parsed = _parseStartTag(position, stack);
      final token = parsed.token;
      elementCount++;
      if (elementCount > maxElementCount) {
        throw SegmentLimitExceededException(
          limit: maxElementCount,
          actual: elementCount,
        );
      }
      if (stack.length + 1 > maxDepth) {
        throw SegmentLimitExceededException(
          limit: maxDepth,
          actual: stack.length + 1,
        );
      }
      if (manifestStart != null) {
        throw const MalformedAssetFormatException(
          'The C2PA manifest element may contain only base64 text.',
        );
      }
      if (root == null) {
        if (token.localName != 'svg' ||
            (token.namespaceUri != null &&
                token.namespaceUri!.isNotEmpty &&
                token.namespaceUri != SvgAssetHandler._svgNamespace)) {
          throw const MalformedAssetFormatException(
            'The XML root element is not SVG.',
          );
        }
        root = token;
      } else if (stack.isEmpty || rootClosed) {
        throw const MalformedAssetFormatException(
          'SVG must contain exactly one root element.',
        );
      }
      final isDirectMetadata =
          stack.length == 1 &&
          stack.first.token.start == root.start &&
          token.localName == 'metadata' &&
          token.namespaceUri == root.namespaceUri;
      if (isDirectMetadata && metadata == null) metadata = token;

      final isManifest =
          stack.length == 2 &&
          stack[1].token.localName == 'metadata' &&
          token.name == 'c2pa:manifest' &&
          token.namespaceUri == SvgAssetHandler._c2paNamespace;
      if (token.localName == 'manifest' &&
          token.namespaceUri == SvgAssetHandler._c2paNamespace &&
          !isManifest) {
        throw const MalformedAssetFormatException(
          'The C2PA manifest must be a direct child of SVG metadata.',
        );
      }
      if (isManifest) {
        if (manifest != null || manifestStart != null) {
          throw const MalformedAssetFormatException(
            'The SVG contains more than one C2PA manifest element.',
          );
        }
        if (token.selfClosing) {
          manifest = _SvgManifest(
            start: token.start,
            end: token.end,
            contentStart: token.closeStart,
            contentEnd: token.closeStart,
            contentRanges: const [],
          );
        } else {
          manifestStart = token;
          manifestContent.clear();
        }
      }
      tokens.add(token);
      if (!token.selfClosing) stack.add(_OpenElement(token));
      if (token.selfClosing && token.start == root.start) rootClosed = true;
      position = token.end;
    }

    if (root == null || stack.isNotEmpty || !rootClosed) {
      throw const MalformedAssetFormatException(
        'SVG XML is incomplete or unbalanced.',
      );
    }
    if (xmpStart != null) {
      throw const MalformedAssetFormatException(
        'The SVG contains an unterminated XMP packet.',
      );
    }
    return _SvgInspection(
      bytes: bytes,
      root: root,
      metadata: metadata,
      manifest: manifest,
      xmpRange: xmpRange,
      tokens: List<_XmlToken>.unmodifiable(tokens),
    );
  }

  bool get _hasBom =>
      bytes.length >= 3 &&
      bytes[0] == 0xef &&
      bytes[1] == 0xbb &&
      bytes[2] == 0xbf;

  _ParsedStart _parseStartTag(int start, List<_OpenElement> stack) {
    final end = _scanTagEnd(start);
    final name = _readName(start + 1, end - 1);
    var closeStart = end - 1;
    while (closeStart > name.end && _isXmlWhitespace(bytes[closeStart - 1])) {
      closeStart--;
    }
    final selfClosing = closeStart > name.end && bytes[closeStart - 1] == 0x2f;
    if (selfClosing) closeStart--;
    final rawAttributes = _parseAttributes(name.end, closeStart);
    final namespaces = <String, String>{
      'xml': 'http://www.w3.org/XML/1998/namespace',
      if (stack.isNotEmpty) ...stack.last.token.namespaces,
    };
    for (final attribute in rawAttributes) {
      if (attribute.name == 'xmlns') {
        namespaces[''] = attribute.value;
      } else if (attribute.name.startsWith('xmlns:')) {
        namespaces[attribute.name.substring(6)] = attribute.value;
      }
    }
    final parts = _splitName(name.value);
    if (parts.$1.isNotEmpty && !namespaces.containsKey(parts.$1)) {
      throw MalformedAssetFormatException(
        'The XML prefix ${parts.$1} is not bound to a namespace.',
      );
    }
    final resolvedAttributes = <_XmlAttribute>[
      for (final attribute in rawAttributes)
        _XmlAttribute(
          name: attribute.name,
          localName: _localName(attribute.name),
          value: attribute.value,
          valueStart: attribute.valueStart,
          valueEnd: attribute.valueEnd,
          namespaceUri:
              (attribute.name == 'xmlns' || attribute.name.startsWith('xmlns:'))
              ? null
              : _attributeNamespace(attribute.name, namespaces),
        ),
    ];
    return _ParsedStart(
      _XmlToken(
        kind: _XmlTokenKind.start,
        start: start,
        end: end,
        openEnd: end,
        closeStart: closeStart,
        name: name.value,
        localName: parts.$2,
        prefix: parts.$1,
        namespaceUri: namespaces[parts.$1],
        selfClosing: selfClosing,
        depth: stack.length,
        parentStart: stack.isEmpty ? null : stack.last.token.start,
        attributes: List<_XmlAttribute>.unmodifiable(resolvedAttributes),
        namespaces: Map<String, String>.unmodifiable(namespaces),
      ),
    );
  }

  List<_XmlAttribute> _parseAttributes(int start, int end) {
    final attributes = <_XmlAttribute>[];
    final names = <String>{};
    var position = start;
    while (position < end) {
      while (position < end && _isXmlWhitespace(bytes[position])) {
        position++;
      }
      if (position == end) break;
      final name = _readName(position, end);
      if (!names.add(name.value)) {
        throw const MalformedAssetFormatException(
          'An SVG element contains duplicate attributes.',
        );
      }
      position = name.end;
      while (position < end && _isXmlWhitespace(bytes[position])) {
        position++;
      }
      if (position >= end || bytes[position++] != 0x3d) {
        throw const MalformedAssetFormatException(
          'An SVG attribute is missing an equals sign.',
        );
      }
      while (position < end && _isXmlWhitespace(bytes[position])) {
        position++;
      }
      if (position >= end ||
          (bytes[position] != 0x22 && bytes[position] != 0x27)) {
        throw const MalformedAssetFormatException(
          'An SVG attribute value must be quoted.',
        );
      }
      final quote = bytes[position++];
      final valueStart = position;
      while (position < end && bytes[position] != quote) {
        if (bytes[position] == 0x3c) {
          throw const MalformedAssetFormatException(
            'An SVG attribute contains an invalid less-than sign.',
          );
        }
        position++;
      }
      if (position >= end) {
        throw const MalformedAssetFormatException(
          'An SVG attribute value is unterminated.',
        );
      }
      final valueEnd = position++;
      _validateEntities(valueStart, valueEnd);
      attributes.add(
        _XmlAttribute(
          name: name.value,
          localName: _localName(name.value),
          value: utf8.decode(bytes.sublist(valueStart, valueEnd)),
          valueStart: valueStart,
          valueEnd: valueEnd,
          namespaceUri: null,
        ),
      );
    }
    return attributes;
  }

  _XmlName _readName(int start, int limit) {
    var end = start;
    while (end < limit &&
        !_isXmlWhitespace(bytes[end]) &&
        bytes[end] != 0x2f &&
        bytes[end] != 0x3e &&
        bytes[end] != 0x3d) {
      end++;
    }
    if (end == start) {
      throw const MalformedAssetFormatException(
        'An SVG element or attribute name is missing.',
      );
    }
    final value = utf8.decode(bytes.sublist(start, end));
    if (!_isValidName(value)) {
      throw const MalformedAssetFormatException(
        'An SVG element or attribute has an invalid XML name.',
      );
    }
    return _XmlName(value, end);
  }

  int _scanTagEnd(int start) {
    int? quote;
    for (var position = start + 1; position < bytes.length; position++) {
      final byte = bytes[position];
      if (quote != null) {
        if (byte == quote) quote = null;
      } else if (byte == 0x22 || byte == 0x27) {
        quote = byte;
      } else if (byte == 0x3e) {
        return position + 1;
      } else if (byte == 0x3c) {
        throw const MalformedAssetFormatException(
          'An SVG start tag is malformed.',
        );
      }
    }
    throw const MalformedAssetFormatException('An SVG tag is unterminated.');
  }

  int _scanDeclarationEnd(int start) {
    int? quote;
    var bracketDepth = 0;
    for (var position = start; position < bytes.length; position++) {
      final byte = bytes[position];
      if (quote != null) {
        if (byte == quote) quote = null;
      } else if (byte == 0x22 || byte == 0x27) {
        quote = byte;
      } else if (byte == 0x5b) {
        bracketDepth++;
      } else if (byte == 0x5d && bracketDepth > 0) {
        bracketDepth--;
      } else if (byte == 0x3e && bracketDepth == 0) {
        return position + 1;
      }
    }
    throw const MalformedAssetFormatException(
      'The SVG document type is unterminated.',
    );
  }

  int _findSequence(int start, String sequence) {
    final target = sequence.codeUnits;
    for (
      var position = start;
      position <= bytes.length - target.length;
      position++
    ) {
      var matches = true;
      for (var index = 0; index < target.length; index++) {
        if (bytes[position + index] != target[index]) {
          matches = false;
          break;
        }
      }
      if (matches) return position + target.length;
    }
    throw const MalformedAssetFormatException(
      'An SVG XML construct is unterminated.',
    );
  }

  void _validateEntities(int start, int end) {
    var position = start;
    while (position < end) {
      if (bytes[position++] != 0x26) continue;
      final entityStart = position;
      while (position < end && bytes[position] != 0x3b) {
        position++;
      }
      if (position >= end) {
        throw const MalformedAssetFormatException(
          'An SVG entity reference is unterminated.',
        );
      }
      final entity = ascii.decode(bytes.sublist(entityStart, position));
      final validNamed =
          entity == 'amp' ||
          entity == 'lt' ||
          entity == 'gt' ||
          entity == 'apos' ||
          entity == 'quot';
      final validNumeric = _validNumericEntity(entity);
      if (!validNamed && !validNumeric) {
        throw const MalformedAssetFormatException(
          'An SVG entity reference is invalid or unsupported.',
        );
      }
      position++;
    }
  }

  static bool _validNumericEntity(String entity) {
    if (!entity.startsWith('#')) return false;
    final hexadecimal = entity.startsWith('#x') || entity.startsWith('#X');
    final digits = entity.substring(hexadecimal ? 2 : 1);
    if (digits.isEmpty) return false;
    final value = int.tryParse(digits, radix: hexadecimal ? 16 : 10);
    return value != null &&
        value <= 0x10ffff &&
        (value < 0xd800 || value > 0xdfff) &&
        value != 0xfffe &&
        value != 0xffff &&
        (value == 0x09 || value == 0x0a || value == 0x0d || value >= 0x20);
  }

  bool _containsSequence(int start, int end, String sequence) {
    final target = sequence.codeUnits;
    for (var position = start; position <= end - target.length; position++) {
      var matches = true;
      for (var index = 0; index < target.length; index++) {
        if (bytes[position + index] != target[index]) {
          matches = false;
          break;
        }
      }
      if (matches) return true;
    }
    return false;
  }

  bool _matches(int offset, String value) {
    final expected = value.codeUnits;
    if (offset + expected.length > bytes.length) return false;
    for (var index = 0; index < expected.length; index++) {
      if (bytes[offset + index] != expected[index]) return false;
    }
    return true;
  }

  bool _matchesCaseInsensitive(int offset, String value) {
    if (offset + value.length > bytes.length) return false;
    final expected = value.codeUnits;
    for (var index = 0; index < expected.length; index++) {
      var actualByte = bytes[offset + index];
      var expectedByte = expected[index];
      if (actualByte >= 0x61 && actualByte <= 0x7a) actualByte -= 0x20;
      if (expectedByte >= 0x61 && expectedByte <= 0x7a) expectedByte -= 0x20;
      if (actualByte != expectedByte) return false;
    }
    return true;
  }

  static bool _isXmlWhitespace(int byte) =>
      byte == 0x20 || byte == 0x09 || byte == 0x0a || byte == 0x0d;

  static (String, String) _splitName(String name) {
    final separator = name.indexOf(':');
    return separator < 0
        ? ('', name)
        : (name.substring(0, separator), name.substring(separator + 1));
  }

  static String _localName(String name) => _splitName(name).$2;

  static String? _attributeNamespace(
    String name,
    Map<String, String> namespaces,
  ) {
    final parts = _splitName(name);
    if (parts.$1.isEmpty) return null;
    final namespace = namespaces[parts.$1];
    if (namespace == null) {
      throw MalformedAssetFormatException(
        'The XML prefix ${parts.$1} is not bound to a namespace.',
      );
    }
    return namespace;
  }

  static bool _isValidName(String name) {
    final nameParts = name.split(':');
    if (name.isEmpty ||
        nameParts.length > 2 ||
        nameParts.any((part) => part.isEmpty)) {
      return false;
    }
    final runes = name.runes.toList(growable: false);
    bool validStart(int rune) =>
        rune == 0x3a ||
        rune == 0x5f ||
        (rune >= 0x41 && rune <= 0x5a) ||
        (rune >= 0x61 && rune <= 0x7a) ||
        rune >= 0x80;
    bool validRest(int rune) =>
        validStart(rune) ||
        rune == 0x2d ||
        rune == 0x2e ||
        (rune >= 0x30 && rune <= 0x39);
    return validStart(runes.first) && runes.skip(1).every(validRest);
  }
}

final class _ParsedStart {
  const _ParsedStart(this.token);

  final _XmlToken token;
}

final class _XmlName {
  const _XmlName(this.value, this.end);

  final String value;
  final int end;
}
