import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';

Future<void> main() async {
  final result = await AssetHandlerRegistry().detect(
    MemoryByteSource(const []),
    fileExtension: 'jpg',
  );
  assert(result.format == AssetFormat.jpeg);
  assert(result.method == AssetDetectionMethod.fileExtension);
}
