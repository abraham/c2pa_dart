import 'package:c2pa_io/c2pa_io.dart';

Future<void> main() async {
  final source = MemoryByteSource([0x10, 0x20, 0x30, 0x40]);
  final reader = BoundedByteReader(source, ByteRange(1, 4));

  assert(await reader.readUint16() == 0x2030);
}
