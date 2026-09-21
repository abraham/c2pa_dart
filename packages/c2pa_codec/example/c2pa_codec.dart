import 'package:c2pa_codec/c2pa_codec.dart';

void main() {
  final encoded = encodeCbor({
    'name': 'c2pa',
    'versions': [1, 2],
  });
  final decoded = decodeCbor(encoded) as Map<Object?, Object?>;
  assert(decoded['name'] == 'c2pa');
}
