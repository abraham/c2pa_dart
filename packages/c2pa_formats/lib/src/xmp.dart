import 'package:c2pa_io/c2pa_io.dart';

abstract interface class XmpMetadataProvider {
  Future<String?> readXmp(RandomAccessByteSource source);

  Future<void> embedRemoteReference(
    RandomAccessByteSource source,
    String reference,
    WritableByteSink output,
  );
}

abstract interface class RemoteManifestReferenceProvider {
  Future<String?> readRemoteManifestReference(RandomAccessByteSource source);

  Future<void> updateRemoteManifestReference(
    RandomAccessByteSource source,
    String reference,
    WritableByteSink output,
  );

  Future<void> removeRemoteManifestReference(
    RandomAccessByteSource source,
    WritableByteSink output,
  );
}
