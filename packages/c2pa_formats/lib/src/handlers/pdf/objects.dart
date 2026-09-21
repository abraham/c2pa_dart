part of '../pdf_handler.dart';

final class _PdfName {
  const _PdfName(this.value);

  final String value;
}

final class _PdfReference {
  const _PdfReference(this.objectNumber, this.generation);

  final int objectNumber;
  final int generation;

  @override
  bool operator ==(Object other) =>
      other is _PdfReference &&
      other.objectNumber == objectNumber &&
      other.generation == generation;

  @override
  int get hashCode => Object.hash(objectNumber, generation);
}

final class _PdfStream {
  const _PdfStream(this.dictionary, this.content);

  final Map<String, Object?> dictionary;
  final Uint8List content;
}

final class _CompressedObject {
  const _CompressedObject(this.objectNumber, this.value);

  final int objectNumber;
  final Object? value;
}

List<int> _integerArray(Object? value, String description) {
  if (value is! List<Object?> || value.any((item) => item is! int)) {
    throw MalformedAssetFormatException(
      'The PDF $description is not an integer array.',
    );
  }
  return value.cast<int>();
}

int _readBigEndian(Uint8List bytes, int offset, int length) {
  var value = 0;
  for (var i = 0; i < length; i++) {
    if (value > 0x1fffffffffffff ~/ 256) {
      throw const MalformedAssetFormatException(
        'A PDF cross-reference field exceeds the supported integer range.',
      );
    }
    value = value * 256 + bytes[offset + i];
  }
  return value;
}
