part of '../pdf_handler.dart';

final class _ManifestAssociation {
  const _ManifestAssociation(this.reference, this.fileSpec);

  final _PdfReference reference;
  final Map<String, Object?> fileSpec;
}

final class _PdfNamePair {
  const _PdfNamePair(this.name, this.reference);

  final Uint8List name;
  final _PdfReference reference;
}

final class _EmbeddedFileNames {
  _EmbeddedFileNames(
    this.namesDictionary,
    this.embeddedDictionary,
    this.entries,
    this.changed,
  );

  final Map<String, Object?> namesDictionary;
  final Map<String, Object?> embeddedDictionary;
  final List<_PdfNamePair> entries;
  bool changed;
}

int _compareNamePairs(_PdfNamePair left, _PdfNamePair right) {
  final length = left.name.length < right.name.length
      ? left.name.length
      : right.name.length;
  for (var i = 0; i < length; i++) {
    final comparison = left.name[i].compareTo(right.name[i]);
    if (comparison != 0) return comparison;
  }
  return left.name.length.compareTo(right.name.length);
}

Uint8List _serializeStream(Map<String, Object?> dictionary, Uint8List content) {
  final values = Map<String, Object?>.from(dictionary)
    ..['Length'] = content.length;
  return Uint8List.fromList(<int>[
    ..._serializePdfValue(values),
    ...ascii.encode('\nstream\n'),
    ...content,
    ...ascii.encode('\nendstream'),
  ]);
}

Uint8List _serializePdfValue(Object? value) {
  final output = BytesBuilder(copy: false);

  void write(Object? current) {
    switch (current) {
      case null:
        output.add(ascii.encode('null'));
      case final bool boolean:
        output.add(ascii.encode(boolean ? 'true' : 'false'));
      case final int integer:
        output.add(ascii.encode(integer.toString()));
      case final double number:
        if (!number.isFinite) {
          throw const MalformedAssetFormatException(
            'A PDF numeric value is not finite.',
          );
        }
        output.add(ascii.encode(number.toString()));
      case final _PdfName name:
        output.addByte(0x2f);
        output.add(_encodePdfName(name.value));
      case final _PdfReference reference:
        output.add(
          ascii.encode('${reference.objectNumber} ${reference.generation} R'),
        );
      case final Uint8List string:
        output.addByte(0x3c);
        const digits = '0123456789ABCDEF';
        for (final byte in string) {
          output
            ..addByte(digits.codeUnitAt(byte >> 4))
            ..addByte(digits.codeUnitAt(byte & 0x0f));
        }
        output.addByte(0x3e);
      case final List<Object?> array:
        output.addByte(0x5b);
        for (var i = 0; i < array.length; i++) {
          if (i != 0) output.addByte(0x20);
          write(array[i]);
        }
        output.addByte(0x5d);
      case final Map<String, Object?> dictionary:
        output.add(ascii.encode('<<'));
        final keys = dictionary.keys.toList()..sort();
        for (final key in keys) {
          output.addByte(0x20);
          write(_PdfName(key));
          output.addByte(0x20);
          write(dictionary[key]);
        }
        output.add(ascii.encode(' >>'));
      default:
        throw UnsupportedPdfFeatureException(
          'serialization of ${current.runtimeType} values',
        );
    }
  }

  write(value);
  return output.takeBytes();
}

Uint8List _encodePdfName(String value) {
  final bytes = latin1.encode(value);
  final output = BytesBuilder(copy: false);
  const digits = '0123456789ABCDEF';
  for (final byte in bytes) {
    if (byte >= 0x21 && byte <= 0x7e && !_isDelimiter(byte) && byte != 0x23) {
      output.addByte(byte);
    } else {
      output
        ..addByte(0x23)
        ..addByte(digits.codeUnitAt(byte >> 4))
        ..addByte(digits.codeUnitAt(byte & 0x0f));
    }
  }
  return output.takeBytes();
}
