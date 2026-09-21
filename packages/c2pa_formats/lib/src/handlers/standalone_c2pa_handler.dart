import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../byte_compare.dart';
import '../errors.dart';
import '../hash_layout.dart';

/// A handler for standalone C2PA JUMBF manifest stores.
final class StandaloneC2paHandler
    implements AssetHandler, BoxHashLayoutProvider {
  /// Creates a handler for `.c2pa` manifest-store files.
  const StandaloneC2paHandler();

  static const int _basicHeaderLength = 8;
  static const int _extendedHeaderLength = 16;
  static const List<int> _jumbType = <int>[0x6a, 0x75, 0x6d, 0x62];
  static const List<int> _c2paType = <int>[0x63, 0x32, 0x70, 0x61];

  @override
  String get name => 'Standalone C2PA';

  @override
  AssetFormat get format => AssetFormat.standaloneC2pa;

  @override
  AssetHandlerCapabilities get capabilities => const AssetHandlerCapabilities(
    canDetect: true,
    canExtractManifest: true,
    canProvideBoxHashLayout: true,
    mimeTypes: <String>['application/c2pa'],
    fileExtensions: <String>['c2pa'],
  );

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    if (await source.length < _basicHeaderLength) return false;
    final header = await source.read(ByteRange(0, _basicHeaderLength));
    return header.length == _basicHeaderLength && _hasSupportedType(header);
  }

  @override
  Future<Uint8List> extractManifest(RandomAccessByteSource source) async {
    final sourceLength = await source.length;
    if (sourceLength < _basicHeaderLength) {
      throw TruncatedAssetException(
        expectedLength: _basicHeaderLength,
        actualLength: sourceLength,
      );
    }

    final header = await source.read(ByteRange(0, _basicHeaderLength));
    if (header.length != _basicHeaderLength) {
      throw TruncatedAssetException(
        expectedLength: _basicHeaderLength,
        actualLength: header.length,
      );
    }
    if (!_hasSupportedType(header)) {
      throw const MalformedAssetFormatException(
        'The top-level ISO box is not a JUMBF or C2PA box.',
      );
    }

    final size32 = _readUint32(header, 0);
    final int boxLength;
    if (size32 == 0) {
      boxLength = sourceLength;
    } else if (size32 == 1) {
      if (sourceLength < _extendedHeaderLength) {
        throw TruncatedAssetException(
          expectedLength: _extendedHeaderLength,
          actualLength: sourceLength,
        );
      }
      final extendedHeader = await source.read(
        ByteRange(0, _extendedHeaderLength),
      );
      if (extendedHeader.length != _extendedHeaderLength) {
        throw TruncatedAssetException(
          expectedLength: _extendedHeaderLength,
          actualLength: extendedHeader.length,
        );
      }
      boxLength = _readUint64(extendedHeader, _basicHeaderLength);
      if (boxLength < _extendedHeaderLength) {
        throw const MalformedAssetFormatException(
          'The extended ISO box size is smaller than its header.',
        );
      }
    } else {
      boxLength = size32;
      if (boxLength < _basicHeaderLength) {
        throw const MalformedAssetFormatException(
          'The ISO box size is smaller than its header.',
        );
      }
    }

    if (boxLength > sourceLength) {
      throw TruncatedAssetException(
        expectedLength: boxLength,
        actualLength: sourceLength,
      );
    }
    if (boxLength != sourceLength) {
      throw MalformedAssetFormatException(
        'The standalone box declares $boxLength bytes, '
        'but the source contains $sourceLength bytes.',
      );
    }

    final manifest = await source.read(ByteRange(0, boxLength));
    if (manifest.length != boxLength) {
      throw TruncatedAssetException(
        expectedLength: boxLength,
        actualLength: manifest.length,
      );
    }
    return manifest;
  }

  @override
  Future<BoxHashLayout> getBoxHashLayout(RandomAccessByteSource source) async {
    final manifest = await extractManifest(source);
    return BoxHashLayout(
      sourceLength: manifest.length,
      entries: [
        BoxHashEntry(
          names: const ['C2PA'],
          range: ByteRange(0, manifest.length),
        ),
      ],
    );
  }

  @override
  Future<void> embedManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) {
    throw const UnsupportedManifestMutationException(
      AssetFormat.standaloneC2pa,
      ManifestMutationOperation.embed,
    );
  }

  @override
  Future<void> replaceManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) {
    throw const UnsupportedManifestMutationException(
      AssetFormat.standaloneC2pa,
      ManifestMutationOperation.replace,
    );
  }

  @override
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) {
    throw const UnsupportedManifestMutationException(
      AssetFormat.standaloneC2pa,
      ManifestMutationOperation.remove,
    );
  }

  static bool _hasSupportedType(Uint8List header) =>
      bytesEqualAt(header, 4, _jumbType) || bytesEqualAt(header, 4, _c2paType);

  static int _readUint32(Uint8List bytes, int offset) =>
      ByteData.sublistView(bytes).getUint32(offset);

  static int _readUint64(Uint8List bytes, int offset) =>
      ByteData.sublistView(bytes).getUint64(offset);
}
