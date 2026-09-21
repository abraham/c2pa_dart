import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import 'asset_format.dart';
import 'errors.dart';

/// An editor for the XMP `dcterms:provenance` remote manifest reference.
final class XmpRemoteReferenceEditor {
  XmpRemoteReferenceEditor._(this._bytes, this._document, this._reference);

  /// Minimal UTF-8 XMP packet containing one editable `rdf:Description`.
  static const String minimalPacket =
      '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
      '<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="XMP Core 6.0.0">'
      '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
      '<rdf:Description rdf:about="" '
      'xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
      'xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" '
      'xmlns:dc="http://purl.org/dc/elements/1.1/" '
      'xmlns:dcterms="http://purl.org/dc/terms/" '
      'xmpMM:DocumentID="xmp.did:cb9f5498-bb58-4572-8043-8c369e6bfb9b" '
      'xmpMM:InstanceID="xmp.iid:cb9f5498-bb58-4572-8043-8c369e6bfb9b">'
      ' </rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>';

  /// Parses [bytes] as an XMP packet whose length is limited by [maxLength].
  ///
  /// The editor accepts `dcterms:provenance` either as an attribute on
  /// `rdf:Description` or as a direct child element. Throws
  /// [MalformedAssetFormatException] for invalid UTF-8, malformed XML, nested
  /// provenance content, or multiple provenance values.
  factory XmpRemoteReferenceEditor.parse(
    Uint8List bytes, {
    required int maxLength,
  }) {
    if (bytes.length > maxLength) {
      throw AssetLimitExceededException(limit: maxLength, actual: bytes.length);
    }
    try {
      utf8.decode(bytes, allowMalformed: false);
    } on FormatException {
      throw const MalformedAssetFormatException(
        'XMP metadata is not valid UTF-8.',
      );
    }
    final document = _XmpParser(bytes).parse();
    final values = <_XmpValue>[];
    for (final element in document.elements) {
      if (element.namespaceUri != _rdfNamespace ||
          element.localName != 'Description') {
        continue;
      }
      for (final attribute in element.attributes) {
        if (attribute.namespaceUri == _dctermsNamespace &&
            attribute.localName == 'provenance') {
          values.add(
            _XmpValue.attribute(
              value: attribute.value,
              range: attribute.range,
              valueRange: attribute.valueRange,
              description: element,
            ),
          );
        }
      }
      for (final child in document.elements) {
        if (child.parentStart != element.start ||
            child.namespaceUri != _dctermsNamespace ||
            child.localName != 'provenance') {
          continue;
        }
        if (child.selfClosing) {
          values.add(
            _XmpValue.element(
              value: '',
              range: ByteRange(child.start, child.end),
              valueRange: ByteRange(child.end, child.end),
              description: element,
              element: child,
            ),
          );
          continue;
        }
        final closing = document.closingByStart[child.start];
        if (closing == null) {
          throw const MalformedAssetFormatException(
            'The XMP provenance element is unterminated.',
          );
        }
        if (document.elements.any(
          (candidate) =>
              candidate.parentStart == child.start &&
              candidate.start < closing.start,
        )) {
          throw const MalformedAssetFormatException(
            'The XMP provenance element must contain only text.',
          );
        }
        final raw = bytes.sublist(child.end, closing.start);
        values.add(
          _XmpValue.element(
            value: _decodeEntities(utf8.decode(raw)),
            range: ByteRange(child.start, closing.end),
            valueRange: ByteRange(child.end, closing.start),
            description: element,
            element: child,
          ),
        );
      }
    }
    if (values.length > 1) {
      throw const MalformedAssetFormatException(
        'XMP metadata contains duplicate or conflicting provenance values.',
      );
    }
    return XmpRemoteReferenceEditor._(
      Uint8List.fromList(bytes),
      document,
      values.firstOrNull,
    );
  }

  final Uint8List _bytes;
  final _XmpDocument _document;
  final _XmpValue? _reference;

  /// Current `dcterms:provenance` value, or `null` when absent.
  String? get value => _reference?.value;

  /// Returns XMP bytes with `dcterms:provenance` set to [value].
  ///
  /// Throws [MalformedAssetFormatException] when [value] is not valid XML text
  /// or the packet has no `rdf:Description`. Throws
  /// [AssetLimitExceededException] if the edited packet exceeds [maxLength].
  Uint8List update(String value, {required int maxLength}) {
    if (!_validXmlString(value)) {
      throw const MalformedAssetFormatException(
        'The remote reference contains characters invalid in XML.',
      );
    }
    final encodedValue = utf8.encode(_escapeAttribute(value));
    final existing = _reference;
    late Uint8List edited;
    if (existing != null) {
      if (existing.attribute) {
        edited = _patch(_bytes, existing.valueRange, encodedValue);
      } else {
        final element = existing.element!;
        if (element.selfClosing) {
          final replacement = utf8.encode(
            '<${element.name}>${_escapeText(value)}</${element.name}>',
          );
          edited = _patch(_bytes, existing.range, replacement);
        } else {
          edited = _patch(
            _bytes,
            existing.valueRange,
            utf8.encode(_escapeText(value)),
          );
        }
      }
    } else {
      final descriptions = _document.elements
          .where(
            (element) =>
                element.namespaceUri == _rdfNamespace &&
                element.localName == 'Description',
          )
          .toList();
      if (descriptions.isEmpty) {
        throw const MalformedAssetFormatException(
          'XMP metadata has no rdf:Description element.',
        );
      }
      final description = descriptions.first;
      final existingPrefix = _prefixForNamespace(
        description,
        _dctermsNamespace,
      );
      final prefix = existingPrefix ?? _availablePrefix(description, 'dcterms');
      final namespacePatch = existingPrefix == null
          ? ' xmlns:$prefix="$_dctermsNamespace"'
          : '';
      final name = '$prefix:provenance';
      edited = _patch(
        _bytes,
        ByteRange(description.closeStart, description.closeStart),
        utf8.encode('$namespacePatch $name="${_escapeAttribute(value)}"'),
      );
    }
    edited = _preservePacketLength(_bytes, edited);
    if (edited.length > maxLength) {
      throw AssetLimitExceededException(
        limit: maxLength,
        actual: edited.length,
      );
    }
    return edited;
  }

  /// Returns XMP bytes with the `dcterms:provenance` value removed.
  ///
  /// Throws [RemoteManifestReferenceNotFoundException] when no provenance value
  /// exists and [AssetLimitExceededException] if padding preservation exceeds
  /// [maxLength].
  Uint8List remove({required int maxLength}) {
    final existing = _reference;
    if (existing == null) {
      throw const RemoteManifestReferenceNotFoundException(AssetFormat.unknown);
    }
    final edited = _preservePacketLength(
      _bytes,
      _patch(_bytes, existing.range, const <int>[]),
    );
    if (edited.length > maxLength) {
      throw AssetLimitExceededException(
        limit: maxLength,
        actual: edited.length,
      );
    }
    return edited;
  }
}

const String _rdfNamespace = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';
const String _dctermsNamespace = 'http://purl.org/dc/terms/';

final class _XmpDocument {
  const _XmpDocument(this.elements, this.closingByStart);

  final List<_XmpElement> elements;
  final Map<int, _XmpClosing> closingByStart;
}

final class _XmpElement {
  const _XmpElement({
    required this.start,
    required this.end,
    required this.closeStart,
    required this.name,
    required this.localName,
    required this.namespaceUri,
    required this.namespaces,
    required this.attributes,
    required this.selfClosing,
    required this.parentStart,
  });

  final int start;
  final int end;
  final int closeStart;
  final String name;
  final String localName;
  final String? namespaceUri;
  final Map<String, String> namespaces;
  final List<_XmpAttribute> attributes;
  final bool selfClosing;
  final int? parentStart;
}

final class _XmpClosing {
  const _XmpClosing(this.start, this.end);

  final int start;
  final int end;
}

final class _XmpAttribute {
  const _XmpAttribute({
    required this.localName,
    required this.namespaceUri,
    required this.value,
    required this.range,
    required this.valueRange,
  });

  final String localName;
  final String? namespaceUri;
  final String value;
  final ByteRange range;
  final ByteRange valueRange;
}

final class _XmpValue {
  const _XmpValue._({
    required this.value,
    required this.range,
    required this.valueRange,
    required this.description,
    required this.attribute,
    this.element,
  });

  factory _XmpValue.attribute({
    required String value,
    required ByteRange range,
    required ByteRange valueRange,
    required _XmpElement description,
  }) => _XmpValue._(
    value: value,
    range: range,
    valueRange: valueRange,
    description: description,
    attribute: true,
  );

  factory _XmpValue.element({
    required String value,
    required ByteRange range,
    required ByteRange valueRange,
    required _XmpElement description,
    required _XmpElement element,
  }) => _XmpValue._(
    value: value,
    range: range,
    valueRange: valueRange,
    description: description,
    attribute: false,
    element: element,
  );

  final String value;
  final ByteRange range;
  final ByteRange valueRange;
  final _XmpElement description;
  final bool attribute;
  final _XmpElement? element;
}

final class _XmpParser {
  const _XmpParser(this.bytes);

  final Uint8List bytes;

  _XmpDocument parse() {
    final elements = <_XmpElement>[];
    final closing = <int, _XmpClosing>{};
    final stack = <_XmpElement>[];
    var cursor = _hasBom ? 3 : 0;
    while (cursor < bytes.length) {
      if (bytes[cursor] != 0x3c) {
        cursor++;
        continue;
      }
      if (_matches(cursor, '<!--')) {
        cursor = _find(cursor + 4, '-->');
        continue;
      }
      if (_matches(cursor, '<![CDATA[')) {
        cursor = _find(cursor + 9, ']]>');
        continue;
      }
      if (_matches(cursor, '<?')) {
        cursor = _find(cursor + 2, '?>');
        continue;
      }
      if (_matches(cursor, '<!')) {
        cursor = _scanDeclaration(cursor + 2);
        continue;
      }
      final end = _tagEnd(cursor);
      if (_matches(cursor, '</')) {
        final name = _name(cursor + 2, end - 1).$1;
        if (stack.isEmpty || stack.last.name != name) {
          throw const MalformedAssetFormatException(
            'XMP metadata contains mismatched element tags.',
          );
        }
        final opened = stack.removeLast();
        closing[opened.start] = _XmpClosing(cursor, end);
        cursor = end;
        continue;
      }
      final nameResult = _name(cursor + 1, end - 1);
      final name = nameResult.$1;
      var position = nameResult.$2;
      final selfClosing = _selfClosing(cursor, end);
      final inherited = stack.isEmpty
          ? const <String, String>{
              'xml': 'http://www.w3.org/XML/1998/namespace',
            }
          : stack.last.namespaces;
      final namespaces = <String, String>{...inherited};
      final rawAttributes = <(int, int, String, int, int, String)>[];
      final attributeNames = <String>{};
      while (position < end - 1) {
        final whitespaceStart = position;
        while (position < end - 1 && _space(bytes[position])) {
          position++;
        }
        if (position >= end - 1 ||
            bytes[position] == 0x2f ||
            bytes[position] == 0x3e) {
          break;
        }
        final attributeName = _name(position, end - 1);
        if (!attributeNames.add(attributeName.$1)) {
          throw const MalformedAssetFormatException(
            'XMP metadata contains duplicate attributes.',
          );
        }
        position = attributeName.$2;
        while (position < end - 1 && _space(bytes[position])) {
          position++;
        }
        if (position >= end - 1 || bytes[position++] != 0x3d) {
          throw const MalformedAssetFormatException(
            'An XMP attribute is missing "=".',
          );
        }
        while (position < end - 1 && _space(bytes[position])) {
          position++;
        }
        if (position >= end - 1 ||
            (bytes[position] != 0x22 && bytes[position] != 0x27)) {
          throw const MalformedAssetFormatException(
            'An XMP attribute value is not quoted.',
          );
        }
        final quote = bytes[position++];
        final valueStart = position;
        while (position < end - 1 && bytes[position] != quote) {
          position++;
        }
        if (position >= end - 1) {
          throw const MalformedAssetFormatException(
            'An XMP attribute value is unterminated.',
          );
        }
        final valueEnd = position++;
        final value = utf8.decode(bytes.sublist(valueStart, valueEnd));
        rawAttributes.add((
          whitespaceStart,
          position,
          attributeName.$1,
          valueStart,
          valueEnd,
          value,
        ));
        if (attributeName.$1 == 'xmlns') {
          namespaces[''] = _decodeEntities(value);
        } else if (attributeName.$1.startsWith('xmlns:')) {
          namespaces[attributeName.$1.substring(6)] = _decodeEntities(value);
        }
      }
      final attributes = <_XmpAttribute>[];
      for (final raw in rawAttributes) {
        if (raw.$3 == 'xmlns' || raw.$3.startsWith('xmlns:')) continue;
        final split = raw.$3.indexOf(':');
        final prefix = split < 0 ? '' : raw.$3.substring(0, split);
        if (prefix.isNotEmpty && !namespaces.containsKey(prefix)) {
          throw const MalformedAssetFormatException(
            'XMP metadata contains an unbound attribute prefix.',
          );
        }
        attributes.add(
          _XmpAttribute(
            localName: split < 0 ? raw.$3 : raw.$3.substring(split + 1),
            namespaceUri: namespaces[prefix],
            value: _decodeEntities(raw.$6),
            range: ByteRange(raw.$1, raw.$2),
            valueRange: ByteRange(raw.$4, raw.$5),
          ),
        );
      }
      final split = name.indexOf(':');
      final prefix = split < 0 ? '' : name.substring(0, split);
      if (prefix.isNotEmpty && !namespaces.containsKey(prefix)) {
        throw const MalformedAssetFormatException(
          'XMP metadata contains an unbound element prefix.',
        );
      }
      final element = _XmpElement(
        start: cursor,
        end: end,
        closeStart: selfClosing ? end - 2 : end - 1,
        name: name,
        localName: split < 0 ? name : name.substring(split + 1),
        namespaceUri: namespaces[prefix],
        namespaces: Map<String, String>.unmodifiable(namespaces),
        attributes: List<_XmpAttribute>.unmodifiable(attributes),
        selfClosing: selfClosing,
        parentStart: stack.isEmpty ? null : stack.last.start,
      );
      elements.add(element);
      if (!selfClosing) stack.add(element);
      cursor = end;
    }
    if (stack.isNotEmpty) {
      throw const MalformedAssetFormatException(
        'XMP metadata contains unterminated elements.',
      );
    }
    return _XmpDocument(elements, closing);
  }

  bool get _hasBom =>
      bytes.length >= 3 &&
      bytes[0] == 0xef &&
      bytes[1] == 0xbb &&
      bytes[2] == 0xbf;

  bool _matches(int offset, String value) {
    final pattern = ascii.encode(value);
    if (offset + pattern.length > bytes.length) return false;
    for (var index = 0; index < pattern.length; index++) {
      if (bytes[offset + index] != pattern[index]) return false;
    }
    return true;
  }

  int _find(int start, String value) {
    for (var offset = start; offset < bytes.length; offset++) {
      if (_matches(offset, value)) return offset + value.length;
    }
    throw const MalformedAssetFormatException(
      'XMP metadata contains an unterminated declaration.',
    );
  }

  int _tagEnd(int start) {
    int? quote;
    for (var position = start + 1; position < bytes.length; position++) {
      final byte = bytes[position];
      if (quote != null) {
        if (byte == quote) quote = null;
      } else if (byte == 0x22 || byte == 0x27) {
        quote = byte;
      } else if (byte == 0x3e) {
        return position + 1;
      }
    }
    throw const MalformedAssetFormatException(
      'XMP metadata contains an unterminated tag.',
    );
  }

  int _scanDeclaration(int start) {
    var depth = 0;
    int? quote;
    for (var position = start; position < bytes.length; position++) {
      final byte = bytes[position];
      if (quote != null) {
        if (byte == quote) quote = null;
      } else if (byte == 0x22 || byte == 0x27) {
        quote = byte;
      } else if (byte == 0x5b) {
        depth++;
      } else if (byte == 0x5d && depth > 0) {
        depth--;
      } else if (byte == 0x3e && depth == 0) {
        return position + 1;
      }
    }
    throw const MalformedAssetFormatException(
      'XMP metadata contains an unterminated declaration.',
    );
  }

  int _tagEndOffset(int end) => end - 1;

  bool _selfClosing(int start, int end) {
    var position = _tagEndOffset(end) - 1;
    while (position > start && _space(bytes[position])) {
      position--;
    }
    return bytes[position] == 0x2f;
  }

  (String, int) _name(int start, int limit) {
    var position = start;
    if (position >= limit || !_nameStart(bytes[position])) {
      throw const MalformedAssetFormatException(
        'XMP metadata contains an invalid XML name.',
      );
    }
    position++;
    while (position < limit && _namePart(bytes[position])) {
      position++;
    }
    return (utf8.decode(bytes.sublist(start, position)), position);
  }
}

Uint8List _patch(Uint8List source, ByteRange range, List<int> replacement) {
  final builder = BytesBuilder(copy: false)
    ..add(source.sublist(0, range.start))
    ..add(replacement)
    ..add(source.sublist(range.end));
  return builder.takeBytes();
}

Uint8List _preservePacketLength(Uint8List original, Uint8List edited) {
  const marker = '<?xpacket end=';
  final originalMarker = _lastSequence(original, ascii.encode(marker));
  final editedMarker = _lastSequence(edited, ascii.encode(marker));
  if (originalMarker < 0 || editedMarker < 0) return edited;
  final difference = edited.length - original.length;
  if (difference == 0) return edited;
  if (difference < 0) {
    return _patch(
      edited,
      ByteRange(editedMarker, editedMarker),
      List<int>.filled(-difference, 0x20),
    );
  }
  var removableStart = editedMarker;
  while (removableStart > 0 &&
      _space(edited[removableStart - 1]) &&
      editedMarker - removableStart < difference) {
    removableStart--;
  }
  if (editedMarker - removableStart == difference) {
    return _patch(edited, ByteRange(removableStart, editedMarker), const []);
  }
  return edited;
}

int _lastSequence(List<int> bytes, List<int> pattern) {
  for (var offset = bytes.length - pattern.length; offset >= 0; offset--) {
    var equal = true;
    for (var index = 0; index < pattern.length; index++) {
      if (bytes[offset + index] != pattern[index]) {
        equal = false;
        break;
      }
    }
    if (equal) return offset;
  }
  return -1;
}

String? _prefixForNamespace(_XmpElement element, String namespace) {
  for (final entry in element.namespaces.entries) {
    if (entry.value == namespace) return entry.key;
  }
  return null;
}

String _availablePrefix(_XmpElement element, String preferred) {
  if (!element.namespaces.containsKey(preferred)) return preferred;
  var suffix = 1;
  while (element.namespaces.containsKey('$preferred$suffix')) {
    suffix++;
  }
  return '$preferred$suffix';
}

String _escapeAttribute(String value) => value
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');

String _escapeText(String value) => value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');

String _decodeEntities(String value) {
  final output = StringBuffer();
  var cursor = 0;
  while (cursor < value.length) {
    final ampersand = value.indexOf('&', cursor);
    if (ampersand < 0) {
      output.write(value.substring(cursor));
      break;
    }
    output.write(value.substring(cursor, ampersand));
    final semicolon = value.indexOf(';', ampersand + 1);
    if (semicolon < 0) {
      throw const MalformedAssetFormatException(
        'XMP metadata contains an unterminated entity.',
      );
    }
    final entity = value.substring(ampersand + 1, semicolon);
    final decoded = switch (entity) {
      'quot' => '"',
      'apos' => "'",
      'lt' => '<',
      'gt' => '>',
      'amp' => '&',
      _ when entity.startsWith('#x') => _numericEntity(entity.substring(2), 16),
      _ when entity.startsWith('#') => _numericEntity(entity.substring(1), 10),
      _ => throw const MalformedAssetFormatException(
        'XMP metadata contains an unsupported entity.',
      ),
    };
    output.write(decoded);
    cursor = semicolon + 1;
  }
  return output.toString();
}

String _numericEntity(String digits, int radix) {
  final value = int.tryParse(digits, radix: radix);
  if (value == null || !_validXmlCodePoint(value)) {
    throw const MalformedAssetFormatException(
      'XMP metadata contains an invalid numeric entity.',
    );
  }
  return String.fromCharCode(value);
}

bool _validXmlString(String value) {
  for (final rune in value.runes) {
    if (!_validXmlCodePoint(rune)) return false;
  }
  return true;
}

bool _validXmlCodePoint(int rune) =>
    rune == 0x9 ||
    rune == 0xa ||
    rune == 0xd ||
    (rune >= 0x20 && rune <= 0xd7ff) ||
    (rune >= 0xe000 && rune <= 0xfffd) ||
    (rune >= 0x10000 && rune <= 0x10ffff);

bool _space(int byte) =>
    byte == 0x20 || byte == 0x09 || byte == 0x0a || byte == 0x0d;

bool _nameStart(int byte) =>
    byte == 0x3a ||
    byte == 0x5f ||
    (byte >= 0x41 && byte <= 0x5a) ||
    (byte >= 0x61 && byte <= 0x7a);

bool _namePart(int byte) =>
    _nameStart(byte) ||
    byte == 0x2d ||
    byte == 0x2e ||
    (byte >= 0x30 && byte <= 0x39);

extension<T> on List<T> {
  T? get firstOrNull => isEmpty ? null : first;
}
