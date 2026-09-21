import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../byte_compare.dart';
import '../errors.dart';
import '../xmp.dart';

part 'pdf/document.dart';
part 'pdf/inflate.dart';
part 'pdf/objects.dart';
part 'pdf/parser.dart';
part 'pdf/scanning.dart';
part 'pdf/serialization.dart';
part 'pdf/xref.dart';

/// PDF handler using append-only incremental updates for C2PA associated files.
final class PdfAssetHandler implements AssetHandler, XmpMetadataProvider {
  /// Creates a PDF handler with object graph and byte limits.
  const PdfAssetHandler({
    this.maxSourceSize = 256 * 1024 * 1024,
    this.maxOutputSize = 320 * 1024 * 1024,
    this.maxManifestSize = 64 * 1024 * 1024,
    this.maxXmpSize = 4 * 1024 * 1024,
    this.maxObjectCount = 1024 * 1024,
    this.maxXrefSections = 128,
    this.maxObjectDepth = 128,
  }) : assert(maxSourceSize > 0),
       assert(maxOutputSize > 0),
       assert(maxManifestSize > 0),
       assert(maxXmpSize > 0),
       assert(maxObjectCount > 0),
       assert(maxXrefSections > 0),
       assert(maxObjectDepth > 0);

  /// Maximum source PDF size in bytes.
  final int maxSourceSize;

  /// Maximum rewritten PDF size in bytes.
  final int maxOutputSize;

  /// Maximum embedded C2PA manifest size in bytes.
  final int maxManifestSize;

  /// Maximum decoded XMP metadata stream size in bytes.
  final int maxXmpSize;

  /// Maximum number of indirect objects parsed from the PDF.
  final int maxObjectCount;

  /// Maximum number of cross-reference sections followed.
  final int maxXrefSections;

  /// Maximum nested object depth while resolving PDF objects.
  final int maxObjectDepth;

  @override
  String get name => 'PDF';

  @override
  AssetFormat get format => AssetFormat.pdf;

  @override
  AssetHandlerCapabilities get capabilities => const AssetHandlerCapabilities(
    canDetect: true,
    canExtractManifest: true,
    canEmbedManifest: true,
    canReplaceManifest: true,
    canRemoveManifest: true,
    canReadXmp: true,
    mimeTypes: <String>['application/pdf'],
    fileExtensions: <String>['pdf'],
  );

  @override
  Future<bool> detect(RandomAccessByteSource source) async {
    final length = await source.length;
    if (length < 8 || length > maxSourceSize) return false;
    final header = await source.read(ByteRange(0, 8));
    return _hasPdfHeader(header);
  }

  @override
  Future<Uint8List> extractManifest(RandomAccessByteSource source) async {
    final document = await _readDocument(source);
    final association = document.findManifestAssociation();
    if (association == null) {
      throw const ManifestNotFoundException(AssetFormat.pdf);
    }
    return _readAssociatedManifest(document, association);
  }

  Uint8List _readAssociatedManifest(
    _PdfDocument document,
    _ManifestAssociation association,
  ) {
    final embeddedFiles = document.dereference(association.fileSpec['EF']);
    if (embeddedFiles is! Map<String, Object?>) {
      throw const MalformedAssetFormatException(
        'The PDF C2PA file specification has no valid EF dictionary.',
      );
    }
    final stream = document.dereference(embeddedFiles['F']);
    if (stream is! _PdfStream) {
      throw const MalformedAssetFormatException(
        'The PDF C2PA file specification does not reference a stream.',
      );
    }
    final manifest = document.decodeStream(
      stream,
      limit: maxManifestSize,
      purpose: 'C2PA manifest',
    );
    if (manifest.length > maxManifestSize) {
      throw AssetLimitExceededException(
        limit: maxManifestSize,
        actual: manifest.length,
      );
    }
    return manifest;
  }

  @override
  Future<String?> readXmp(RandomAccessByteSource source) async {
    final document = await _readDocument(source);
    final metadata = document.dereference(document.catalog['Metadata']);
    if (metadata == null) return null;
    if (metadata is! _PdfStream) {
      throw const MalformedAssetFormatException(
        'The PDF catalog Metadata value is not a stream.',
      );
    }
    final subtype = document.dereference(metadata.dictionary['Subtype']);
    if (subtype is! _PdfName || subtype.value.toLowerCase() != 'xml') {
      return null;
    }
    final bytes = document.decodeStream(
      metadata,
      limit: maxXmpSize,
      purpose: 'XMP metadata',
    );
    try {
      return utf8.decode(bytes, allowMalformed: false);
    } on FormatException {
      throw const MalformedAssetFormatException(
        'The PDF XMP metadata is not valid UTF-8.',
      );
    }
  }

  Future<_PdfDocument> _readDocument(RandomAccessByteSource source) async {
    final length = await source.length;
    if (length > maxSourceSize) {
      throw AssetLimitExceededException(limit: maxSourceSize, actual: length);
    }
    if (length < 8) {
      throw TruncatedAssetException(expectedLength: 8, actualLength: length);
    }
    final bytes = await source.read(ByteRange(0, length));
    return _PdfDocument.parse(
      bytes,
      maxObjectCount: maxObjectCount,
      maxXrefSections: maxXrefSections,
      maxObjectDepth: maxObjectDepth,
      maxDecodedStreamSize: maxSourceSize,
    );
  }

  @override
  Future<void> embedManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) async {
    await _mutateManifest(
      source,
      manifest,
      output,
      operation: ManifestMutationOperation.embed,
    );
  }

  @override
  Future<void> replaceManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) async {
    await _mutateManifest(
      source,
      manifest,
      output,
      operation: ManifestMutationOperation.replace,
    );
  }

  @override
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) async {
    await _mutateManifest(
      source,
      null,
      output,
      operation: ManifestMutationOperation.remove,
    );
  }

  Future<void> _mutateManifest(
    RandomAccessByteSource source,
    Uint8List? manifest,
    WritableByteSink output, {
    required ManifestMutationOperation operation,
  }) async {
    if (manifest != null && manifest.length > maxManifestSize) {
      throw AssetLimitExceededException(
        limit: maxManifestSize,
        actual: manifest.length,
      );
    }
    final document = await _readDocument(source);
    document.validateMutationAllowed();
    final existing = document.findManifestAssociation();
    if (existing != null) {
      _readAssociatedManifest(document, existing);
    }
    if (operation == ManifestMutationOperation.embed && existing != null) {
      throw const ManifestAlreadyExistsException(AssetFormat.pdf);
    }
    if (operation != ManifestMutationOperation.embed && existing == null) {
      throw const ManifestNotFoundException(AssetFormat.pdf);
    }
    final result = document.appendManifestUpdate(
      manifest,
      existing: existing,
      maxObjectCount: maxObjectCount,
      maxOutputSize: maxOutputSize,
    );
    final staged = MemoryByteSink();
    await staged.append(result);
    await output.append(staged.toBytes());
  }

  @override
  Future<void> embedRemoteReference(
    RandomAccessByteSource source,
    String reference,
    WritableByteSink output,
  ) async {
    throw const UnsupportedXmpOperationException(
      AssetFormat.pdf,
      XmpOperation.embedRemoteReference,
    );
  }
}
