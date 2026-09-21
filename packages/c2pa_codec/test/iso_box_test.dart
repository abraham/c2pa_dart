import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  group('ISO box headers', () {
    test('writes and parses a 32-bit box header', () {
      final created = IsoBoxHeader.create(type: 'test', payloadSize: 4);
      expect(created.encode(), [0, 0, 0, 12, 0x74, 0x65, 0x73, 0x74]);

      final parsed = IsoBoxHeader.parse([...created.encode(), 1, 2, 3, 4]);
      expect(parsed.type, 'test');
      expect(parsed.size, 12);
      expect(parsed.headerSize, 8);
      expect(parsed.payloadSize, 4);
      expect(parsed.endOffset, 12);
      expect(parsed.isLargeSize, isFalse);
    });

    test('writes and parses a forced large-size header', () {
      final created = IsoBoxHeader.create(
        type: 'wide',
        payloadSize: 3,
        forceLargeSize: true,
      );
      expect(created.size, 19);
      expect(created.headerSize, 16);
      expect(created.encode(), [
        0,
        0,
        0,
        1,
        0x77,
        0x69,
        0x64,
        0x65,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        19,
      ]);

      final parsed = IsoBoxHeader.parse([...created.encode(), 1, 2, 3]);
      expect(parsed.size, 19);
      expect(parsed.isLargeSize, isTrue);
    });

    test('automatically selects large size and writes into a buffer', () {
      final created = IsoBoxHeader.create(
        type: 'wide',
        payloadSize: 0xfffffff8,
      );
      expect(created.isLargeSize, isTrue);
      expect(created.size, 0x100000008);

      final destination = Uint8List(20);
      created.writeTo(destination, offset: 2);
      expect(destination.sublist(2, 6), [0, 0, 0, 1]);
      expect(
        () => created.writeTo(Uint8List(15)),
        _isoError(IsoBoxErrorCode.invalidOffset),
      );
    });

    test('writes and parses UUID headers with immutable user type', () {
      final uuid = Uint8List.fromList(List<int>.generate(16, (index) => index));
      final created = IsoBoxHeader.create(
        type: 'uuid',
        payloadSize: 2,
        userType: uuid,
      );
      uuid[0] = 99;
      expect(created.headerSize, 24);
      expect(created.size, 26);
      expect(created.userType, List<int>.generate(16, (index) => index));

      final returned = created.userType!;
      returned[0] = 88;
      expect(created.userType![0], 0);

      final parsed = IsoBoxHeader.parse([...created.encode(), 7, 8]);
      expect(parsed.isUuid, isTrue);
      expect(parsed.userType, List<int>.generate(16, (index) => index));
    });

    test('resolves zero size against the supplied parent bound', () {
      final bytes = <int>[0, 0, 0, 0, 0x66, 0x72, 0x65, 0x65, 1, 2, 3, 4, 5];
      final parsed = IsoBoxHeader.parse(bytes, end: 12);
      expect(parsed.extendsToEnd, isTrue);
      expect(parsed.size, 12);
      expect(parsed.payloadSize, 4);
      expect(parsed.encode().sublist(0, 4), [0, 0, 0, 0]);
    });

    test('honors nonzero offsets and checked bounds', () {
      final header = IsoBoxHeader.create(type: 'skip', payloadSize: 1).encode();
      final parsed = IsoBoxHeader.parse([9, 9, ...header, 7], offset: 2);
      expect(parsed.offset, 2);
      expect(parsed.endOffset, 11);

      expect(
        () => IsoBoxHeader.parse([0, 0, 0]),
        _isoError(IsoBoxErrorCode.truncated),
      );
      expect(
        () => IsoBoxHeader.parse([...header]),
        _isoError(IsoBoxErrorCode.truncated),
      );
      expect(
        () => IsoBoxHeader.parse([0, 0, 0, 4, 0x74, 0x65, 0x73, 0x74]),
        _isoError(IsoBoxErrorCode.invalidSize),
      );
      expect(
        () => IsoBoxHeader.parse([0, 0, 0, 8, 0, 0x65, 0x73, 0x74]),
        _isoError(IsoBoxErrorCode.invalidType),
      );
    });

    test('validates UUID and type construction', () {
      expect(
        () => IsoBoxHeader.create(type: 'uuid', payloadSize: 0),
        _isoError(IsoBoxErrorCode.missingUserType),
      );
      expect(
        () => IsoBoxHeader.create(
          type: 'test',
          payloadSize: 0,
          userType: Uint8List(16),
        ),
        _isoError(IsoBoxErrorCode.unexpectedUserType),
      );
      expect(
        () => IsoBoxHeader.create(type: 'bad', payloadSize: 0),
        _isoError(IsoBoxErrorCode.invalidType),
      );
    });

    test('checks 64-bit declared sizes before converting to int', () {
      expect(
        () => IsoBoxHeader.parse(_largeSizeBox(BigInt.parse('4294967296'))),
        _isoError(IsoBoxErrorCode.truncated),
      );
      expect(
        () =>
            IsoBoxHeader.parse(_largeSizeBox(BigInt.parse('9007199254740991'))),
        _isoError(IsoBoxErrorCode.truncated),
      );
      expect(
        () =>
            IsoBoxHeader.parse(_largeSizeBox(BigInt.parse('9007199254740992'))),
        _isoError(IsoBoxErrorCode.sizeOutOfRange),
      );
      expect(
        () => IsoBoxHeader.parse(
          _largeSizeBox(BigInt.parse('18446744073709551615')),
        ),
        _isoError(IsoBoxErrorCode.sizeOutOfRange),
      );
      expect(
        () => IsoBoxHeader.create(type: 'test', payloadSize: 9007199254740991),
        _isoError(IsoBoxErrorCode.sizeOutOfRange),
      );
    });
  });
}

Matcher _isoError(IsoBoxErrorCode code) =>
    throwsA(isA<IsoBoxException>().having((error) => error.code, 'code', code));

Uint8List _largeSizeBox(BigInt size) {
  final bytes = Uint8List.fromList([
    0,
    0,
    0,
    1,
    ...'test'.codeUnits,
    ...List<int>.filled(8, 0),
  ]);
  var remaining = size;
  for (var index = 15; index >= 8; index--) {
    bytes[index] = (remaining & BigInt.from(0xff)).toInt();
    remaining >>= 8;
  }
  return bytes;
}
