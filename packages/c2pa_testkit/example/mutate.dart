import 'package:c2pa_testkit/c2pa_testkit.dart';

void main() {
  final original = [0x43, 0x32, 0x50, 0x41];
  final mutated = ByteMutation.flip(original, 0, mask: 0x01);
  assert(mutated[0] == 0x42);
  assert(original[0] == 0x43);
}
