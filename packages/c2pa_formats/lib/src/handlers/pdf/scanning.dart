part of '../pdf_handler.dart';

int _hex(int byte) {
  if (byte >= 0x30 && byte <= 0x39) return byte - 0x30;
  if (byte >= 0x41 && byte <= 0x46) return byte - 0x41 + 10;
  if (byte >= 0x61 && byte <= 0x66) return byte - 0x61 + 10;
  return -1;
}

bool _isWhitespace(int byte) =>
    byte == 0 ||
    byte == 9 ||
    byte == 10 ||
    byte == 12 ||
    byte == 13 ||
    byte == 32;

bool _isDelimiter(int byte) =>
    _isWhitespace(byte) ||
    byte == 0x28 ||
    byte == 0x29 ||
    byte == 0x3c ||
    byte == 0x3e ||
    byte == 0x5b ||
    byte == 0x5d ||
    byte == 0x7b ||
    byte == 0x7d ||
    byte == 0x2f ||
    byte == 0x25;

bool _hasPdfHeader(List<int> bytes) =>
    bytes.length >= 8 &&
    bytes[0] == 0x25 &&
    bytes[1] == 0x50 &&
    bytes[2] == 0x44 &&
    bytes[3] == 0x46 &&
    bytes[4] == 0x2d &&
    bytes[5] >= 0x31 &&
    bytes[5] <= 0x39 &&
    bytes[6] == 0x2e &&
    bytes[7] >= 0x30 &&
    bytes[7] <= 0x39;

int _lastIndexOf(List<int> bytes, List<int> pattern, {int? end}) {
  final boundary = (end ?? bytes.length) - pattern.length;
  for (var i = boundary; i >= 0; i--) {
    if (bytesEqualAt(bytes, i, pattern)) return i;
  }
  return -1;
}
