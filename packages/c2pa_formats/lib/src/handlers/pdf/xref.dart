part of '../pdf_handler.dart';

enum _XrefEntryKind { free, uncompressed, compressed }

final class _XrefEntry {
  const _XrefEntry(this.kind, this.field1, this.field2);

  final _XrefEntryKind kind;
  final int field1;
  final int field2;
}

final class _XrefSection {
  const _XrefSection(this.entries, this.trailer);

  final Map<int, _XrefEntry> entries;
  final Map<String, Object?> trailer;
}

_XrefSection _readXrefSection(
  Uint8List bytes,
  int offset, {
  required int maxObjectCount,
  required int maxDepth,
  required int maxDecodedStreamSize,
}) {
  final parser = _PdfParser(bytes, offset, maxDepth: maxDepth);
  parser.skipWhitespaceAndComments();
  if (parser.consumeKeyword('xref')) {
    final entries = <int, _XrefEntry>{};
    while (true) {
      parser.skipWhitespaceAndComments();
      if (parser.consumeKeyword('trailer')) break;
      final first = parser.readRequiredInteger('xref subsection start');
      final count = parser.readRequiredInteger('xref subsection count');
      if (first < 0 || count < 0 || first > maxObjectCount - count) {
        throw AssetLimitExceededException(
          limit: maxObjectCount,
          actual: first + count,
        );
      }
      for (var i = 0; i < count; i++) {
        final field1 = parser.readRequiredInteger('xref object offset');
        final generation = parser.readRequiredInteger('xref generation');
        final status = parser.readRequiredKeyword('xref entry status');
        if (status != 'n' && status != 'f') {
          throw const MalformedAssetFormatException(
            'A PDF xref entry has an invalid status.',
          );
        }
        if (status == 'n' && (field1 < 0 || field1 >= bytes.length)) {
          throw const MalformedAssetFormatException(
            'A PDF xref object offset is outside the asset.',
          );
        }
        entries[first + i] = _XrefEntry(
          status == 'n' ? _XrefEntryKind.uncompressed : _XrefEntryKind.free,
          field1,
          generation,
        );
      }
    }
    final trailer = parser.parseValue();
    if (trailer is! Map<String, Object?>) {
      throw const MalformedAssetFormatException(
        'The PDF trailer is not a dictionary.',
      );
    }
    return _XrefSection(entries, trailer);
  }
  return _readXrefStream(
    bytes,
    offset,
    maxObjectCount: maxObjectCount,
    maxDepth: maxDepth,
    maxDecodedStreamSize: maxDecodedStreamSize,
  );
}

_XrefSection _readXrefStream(
  Uint8List bytes,
  int offset, {
  required int maxObjectCount,
  required int maxDepth,
  required int maxDecodedStreamSize,
}) {
  final indirect = _parseIndirectObject(bytes, offset, maxDepth: maxDepth);
  final stream = indirect.value;
  if (stream is! _PdfStream) {
    throw const MalformedAssetFormatException(
      'The PDF startxref target is neither an xref table nor stream.',
    );
  }
  final type = stream.dictionary['Type'];
  if (type is! _PdfName || type.value != 'XRef') {
    throw const MalformedAssetFormatException(
      'The PDF cross-reference stream has no XRef type.',
    );
  }
  final temporary = _PdfDocument._(
    bytes: bytes,
    entries: const <int, _XrefEntry>{},
    root: const _PdfReference(0, 0),
    latestTrailer: const <String, Object?>{},
    latestXrefOffset: 0,
    maxObjectDepth: maxDepth,
    maxDecodedStreamSize: maxDecodedStreamSize,
  );
  final data = temporary.decodeStream(
    stream,
    limit: maxDecodedStreamSize,
    purpose: 'cross-reference',
  );
  final widthsValue = stream.dictionary['W'];
  if (widthsValue is! List<Object?> ||
      widthsValue.length != 3 ||
      widthsValue.any((value) => value is! int || value < 0 || value > 8)) {
    throw const MalformedAssetFormatException(
      'The PDF cross-reference stream W array is invalid.',
    );
  }
  final widths = widthsValue.cast<int>();
  final rowWidth = widths[0] + widths[1] + widths[2];
  if (rowWidth <= 0) {
    throw const MalformedAssetFormatException(
      'The PDF cross-reference stream row width is zero.',
    );
  }
  final size = stream.dictionary['Size'];
  if (size is! int || size < 0 || size > maxObjectCount) {
    throw AssetLimitExceededException(
      limit: maxObjectCount,
      actual: size is int ? size : maxObjectCount + 1,
    );
  }
  final indexValue = stream.dictionary['Index'];
  final sections = indexValue == null
      ? <int>[0, size]
      : _integerArray(indexValue, 'cross-reference stream Index');
  if (sections.length.isOdd) {
    throw const MalformedAssetFormatException(
      'The PDF cross-reference stream Index array is invalid.',
    );
  }
  var totalRows = 0;
  for (var i = 0; i < sections.length; i += 2) {
    final first = sections[i];
    final count = sections[i + 1];
    if (first < 0 || count < 0 || first > maxObjectCount - count) {
      throw AssetLimitExceededException(
        limit: maxObjectCount,
        actual: first + count,
      );
    }
    totalRows += count;
    if (totalRows > maxObjectCount) {
      throw AssetLimitExceededException(
        limit: maxObjectCount,
        actual: totalRows,
      );
    }
  }
  if (data.length != totalRows * rowWidth) {
    throw const MalformedAssetFormatException(
      'The PDF cross-reference stream length does not match its Index and W.',
    );
  }
  final entries = <int, _XrefEntry>{};
  var cursor = 0;
  for (var section = 0; section < sections.length; section += 2) {
    final first = sections[section];
    final count = sections[section + 1];
    for (var i = 0; i < count; i++) {
      final kind = widths[0] == 0 ? 1 : _readBigEndian(data, cursor, widths[0]);
      cursor += widths[0];
      final field1 = _readBigEndian(data, cursor, widths[1]);
      cursor += widths[1];
      final field2 = _readBigEndian(data, cursor, widths[2]);
      cursor += widths[2];
      final entryKind = switch (kind) {
        0 => _XrefEntryKind.free,
        1 => _XrefEntryKind.uncompressed,
        2 => _XrefEntryKind.compressed,
        _ => throw const MalformedAssetFormatException(
          'The PDF cross-reference stream contains an unknown entry type.',
        ),
      };
      if (entryKind == _XrefEntryKind.uncompressed &&
          (field1 < 0 || field1 >= bytes.length)) {
        throw const MalformedAssetFormatException(
          'A PDF xref stream object offset is outside the asset.',
        );
      }
      entries[first + i] = _XrefEntry(entryKind, field1, field2);
    }
  }
  entries.putIfAbsent(
    indirect.reference.objectNumber,
    () => _XrefEntry(
      _XrefEntryKind.uncompressed,
      offset,
      indirect.reference.generation,
    ),
  );
  return _XrefSection(entries, stream.dictionary);
}

final class _IndirectObject {
  const _IndirectObject(this.reference, this.value);

  final _PdfReference reference;
  final Object? value;
}

_IndirectObject _parseIndirectObject(
  Uint8List bytes,
  int offset, {
  required int maxDepth,
}) {
  if (offset < 0 || offset >= bytes.length) {
    throw const MalformedAssetFormatException(
      'A PDF object offset is outside the asset.',
    );
  }
  final parser = _PdfParser(bytes, offset, maxDepth: maxDepth);
  final number = parser.readRequiredInteger('object number');
  final generation = parser.readRequiredInteger('object generation');
  if (number < 0 || generation < 0 || !parser.consumeKeyword('obj')) {
    throw const MalformedAssetFormatException(
      'A PDF indirect object header is invalid.',
    );
  }
  var value = parser.parseValue();
  if (value is Map<String, Object?>) {
    final saved = parser.index;
    parser.skipWhitespaceAndComments();
    if (parser.consumeKeyword('stream')) {
      if (parser.index >= parser.end) {
        throw const MalformedAssetFormatException(
          'A PDF stream is missing its line ending.',
        );
      }
      if (bytes[parser.index] == 0x0d) {
        parser.index++;
        if (parser.index < parser.end && bytes[parser.index] == 0x0a) {
          parser.index++;
        }
      } else if (bytes[parser.index] == 0x0a) {
        parser.index++;
      } else {
        throw const MalformedAssetFormatException(
          'A PDF stream keyword is not followed by a line ending.',
        );
      }
      final length = value['Length'];
      if (length is! int || length < 0) {
        throw const UnsupportedPdfFeatureException(
          'streams with indirect or invalid Length values',
        );
      }
      if (length > parser.end - parser.index) {
        throw TruncatedAssetException(
          expectedLength: parser.index + length,
          actualLength: parser.end,
        );
      }
      final content = Uint8List.fromList(
        bytes.sublist(parser.index, parser.index + length),
      );
      parser.index += length;
      if (parser.index < parser.end && bytes[parser.index] == 0x0d) {
        parser.index++;
        if (parser.index < parser.end && bytes[parser.index] == 0x0a) {
          parser.index++;
        }
      } else if (parser.index < parser.end && bytes[parser.index] == 0x0a) {
        parser.index++;
      }
      if (!parser.consumeKeyword('endstream')) {
        throw const MalformedAssetFormatException(
          'A PDF stream does not end at its declared Length.',
        );
      }
      value = _PdfStream(value, content);
    } else {
      parser.index = saved;
    }
  }
  parser.skipWhitespaceAndComments();
  if (!parser.consumeKeyword('endobj')) {
    throw const MalformedAssetFormatException(
      'A PDF indirect object is missing endobj.',
    );
  }
  return _IndirectObject(_PdfReference(number, generation), value);
}
