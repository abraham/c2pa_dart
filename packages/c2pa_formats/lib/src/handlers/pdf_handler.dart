import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import '../asset_format.dart';
import '../asset_handler.dart';
import '../errors.dart';
import '../xmp.dart';

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

final class _PdfDocument {
  _PdfDocument._({
    required this.bytes,
    required this.entries,
    required this.root,
    required this.latestTrailer,
    required this.latestXrefOffset,
    required this.maxObjectDepth,
    required this.maxDecodedStreamSize,
  });

  factory _PdfDocument.parse(
    Uint8List bytes, {
    required int maxObjectCount,
    required int maxXrefSections,
    required int maxObjectDepth,
    required int maxDecodedStreamSize,
  }) {
    if (bytes.length < 8 || !_hasPdfHeader(bytes)) {
      throw const MalformedAssetFormatException(
        'The PDF header signature is invalid.',
      );
    }
    final eof = _lastIndexOf(bytes, const <int>[0x25, 0x25, 0x45, 0x4f, 0x46]);
    if (eof < 0) {
      throw const MalformedAssetFormatException(
        'The PDF is missing its final %%EOF marker.',
      );
    }
    for (var i = eof + 5; i < bytes.length; i++) {
      if (!_isWhitespace(bytes[i])) {
        throw const MalformedAssetFormatException(
          'The PDF has non-whitespace data after its final %%EOF marker.',
        );
      }
    }
    final startxref = _lastIndexOf(bytes, const <int>[
      0x73,
      0x74,
      0x61,
      0x72,
      0x74,
      0x78,
      0x72,
      0x65,
      0x66,
    ], end: eof);
    if (startxref < 0) {
      throw const MalformedAssetFormatException(
        'The PDF is missing startxref.',
      );
    }
    final startParser = _PdfParser(
      bytes,
      startxref + 9,
      maxDepth: maxObjectDepth,
    );
    final xrefOffset = startParser.readRequiredInteger('startxref offset');
    if (xrefOffset < 0 || xrefOffset >= bytes.length) {
      throw const MalformedAssetFormatException(
        'The PDF startxref offset is outside the asset.',
      );
    }

    final entries = <int, _XrefEntry>{};
    Object? root;
    Map<String, Object?>? latestTrailer;
    var offset = xrefOffset;
    final visited = <int>{};
    var sectionCount = 0;
    while (true) {
      if (!visited.add(offset)) {
        throw const MalformedAssetFormatException(
          'The PDF cross-reference chain contains a cycle.',
        );
      }
      sectionCount++;
      if (sectionCount > maxXrefSections) {
        throw AssetLimitExceededException(
          limit: maxXrefSections,
          actual: sectionCount,
        );
      }
      final section = _readXrefSection(
        bytes,
        offset,
        maxObjectCount: maxObjectCount,
        maxDepth: maxObjectDepth,
        maxDecodedStreamSize: maxDecodedStreamSize,
      );
      latestTrailer ??= section.trailer;
      for (final entry in section.entries.entries) {
        entries.putIfAbsent(entry.key, () => entry.value);
      }
      root ??= section.trailer['Root'];
      if (section.trailer.containsKey('Encrypt')) {
        throw const UnsupportedPdfFeatureException('encrypted documents');
      }
      final hybrid = section.trailer['XRefStm'];
      if (hybrid != null) {
        if (hybrid is! int || hybrid < 0 || hybrid >= bytes.length) {
          throw const MalformedAssetFormatException(
            'The PDF XRefStm offset is invalid.',
          );
        }
        final supplement = _readXrefStream(
          bytes,
          hybrid,
          maxObjectCount: maxObjectCount,
          maxDepth: maxObjectDepth,
          maxDecodedStreamSize: maxDecodedStreamSize,
        );
        for (final entry in supplement.entries.entries) {
          entries.putIfAbsent(entry.key, () => entry.value);
        }
      }
      final previous = section.trailer['Prev'];
      if (previous == null) break;
      if (previous is! int || previous < 0 || previous >= bytes.length) {
        throw const MalformedAssetFormatException(
          'The PDF Prev cross-reference offset is invalid.',
        );
      }
      offset = previous;
    }
    if (entries.length > maxObjectCount) {
      throw AssetLimitExceededException(
        limit: maxObjectCount,
        actual: entries.length,
      );
    }
    if (root is! _PdfReference) {
      throw const MalformedAssetFormatException(
        'The PDF trailer has no valid Root reference.',
      );
    }
    return _PdfDocument._(
      bytes: bytes,
      entries: entries,
      root: root,
      latestTrailer: latestTrailer,
      latestXrefOffset: xrefOffset,
      maxObjectDepth: maxObjectDepth,
      maxDecodedStreamSize: maxDecodedStreamSize,
    );
  }

  final Uint8List bytes;
  final Map<int, _XrefEntry> entries;
  final _PdfReference root;
  final Map<String, Object?> latestTrailer;
  final int latestXrefOffset;
  final int maxObjectDepth;
  final int maxDecodedStreamSize;
  final Map<_PdfReference, Object?> _cache = <_PdfReference, Object?>{};
  final Set<_PdfReference> _resolving = <_PdfReference>{};
  final Map<int, List<_CompressedObject>> _objectStreamCache =
      <int, List<_CompressedObject>>{};

  Map<String, Object?> get catalog {
    final value = dereference(root);
    if (value is! Map<String, Object?>) {
      throw const MalformedAssetFormatException(
        'The PDF Root does not resolve to a catalog dictionary.',
      );
    }
    final type = dereference(value['Type']);
    if (type is! _PdfName || type.value != 'Catalog') {
      throw const MalformedAssetFormatException(
        'The PDF Root object is not a catalog.',
      );
    }
    return value;
  }

  _ManifestAssociation? findManifestAssociation() {
    final associated = dereference(catalog['AF']);
    if (associated == null) return null;
    if (associated is! List<Object?>) {
      throw const MalformedAssetFormatException(
        'The PDF catalog AF value is not an array.',
      );
    }
    _ManifestAssociation? match;
    for (final value in associated) {
      final fileSpec = dereference(value);
      if (fileSpec is! Map<String, Object?>) {
        throw const MalformedAssetFormatException(
          'A PDF associated-file entry does not resolve to a dictionary.',
        );
      }
      final relationship = dereference(fileSpec['AFRelationship']);
      if (relationship is _PdfName && relationship.value == 'C2PA_Manifest') {
        if (value is! _PdfReference) {
          throw const MalformedAssetFormatException(
            'The PDF C2PA file specification must be an indirect object.',
          );
        }
        if (match != null) {
          throw const MalformedAssetFormatException(
            'The PDF contains multiple C2PA associated files.',
          );
        }
        match = _ManifestAssociation(value, fileSpec);
      }
    }
    return match;
  }

  void validateMutationAllowed() {
    final permissions = dereference(catalog['Perms']);
    if (permissions != null) {
      if (permissions is! Map<String, Object?>) {
        throw const MalformedAssetFormatException(
          'The PDF catalog Perms value is not a dictionary.',
        );
      }
      if (permissions.containsKey('DocMDP')) {
        throw const UnsupportedPdfFeatureException(
          'DocMDP-restricted documents',
        );
      }
    }
    for (final entry in entries.entries) {
      if (entry.value.kind == _XrefEntryKind.free) continue;
      final generation = entry.value.kind == _XrefEntryKind.compressed
          ? 0
          : entry.value.field2;
      final value = dereference(_PdfReference(entry.key, generation));
      final dictionary = switch (value) {
        final Map<String, Object?> map => map,
        final _PdfStream stream => stream.dictionary,
        _ => null,
      };
      if (dictionary == null) continue;
      final type = dereference(dictionary['Type']);
      final fieldType = dereference(dictionary['FT']);
      if ((type is _PdfName && type.value == 'Sig') ||
          (fieldType is _PdfName && fieldType.value == 'Sig') ||
          (dictionary.containsKey('ByteRange') &&
              dictionary.containsKey('Contents'))) {
        throw const UnsupportedPdfFeatureException('signed documents');
      }
    }
  }

  Uint8List appendManifestUpdate(
    Uint8List? manifest, {
    required _ManifestAssociation? existing,
    required int maxObjectCount,
    required int maxOutputSize,
  }) {
    final catalogValue = Map<String, Object?>.from(catalog);
    final associatedValue = dereference(catalogValue['AF']);
    final associated = associatedValue == null
        ? <Object?>[]
        : List<Object?>.from(associatedValue as List<Object?>);
    if (existing != null) {
      associated.removeWhere((value) => value == existing.reference);
    }

    final names = _readEmbeddedFileNames(existing);
    final currentSize = latestTrailer['Size'];
    if (currentSize is! int || currentSize < 1) {
      throw const MalformedAssetFormatException(
        'The latest PDF trailer has an invalid Size.',
      );
    }
    var nextObject =
        entries.keys.fold<int>(
          currentSize - 1,
          (maximum, value) => value > maximum ? value : maximum,
        ) +
        1;
    final updates = <_PdfReference, Uint8List>{};

    _PdfReference allocate(Uint8List value) {
      if (nextObject >= maxObjectCount) {
        throw AssetLimitExceededException(
          limit: maxObjectCount,
          actual: nextObject + 1,
        );
      }
      final reference = _PdfReference(nextObject++, 0);
      updates[reference] = value;
      return reference;
    }

    if (manifest != null) {
      final streamReference = allocate(
        _serializeStream(<String, Object?>{
          'Type': const _PdfName('EmbeddedFile'),
          'Subtype': const _PdfName('application/x-c2pa-manifest-store'),
          'Params': <String, Object?>{'Size': manifest.length},
        }, manifest),
      );
      final fileSpecReference = allocate(
        _serializePdfValue(<String, Object?>{
          'Type': const _PdfName('Filespec'),
          'F': Uint8List.fromList(utf8.encode('Content Credentials')),
          'UF': Uint8List.fromList(utf8.encode('Content Credentials')),
          'Desc': Uint8List.fromList(utf8.encode('Content Credentials')),
          'AFRelationship': const _PdfName('C2PA_Manifest'),
          'EF': <String, Object?>{'F': streamReference},
        }),
      );
      associated.add(fileSpecReference);
      names.entries.add(
        _PdfNamePair(
          Uint8List.fromList(utf8.encode('Content Credentials')),
          fileSpecReference,
        ),
      );
      names.changed = true;
    }

    if (associated.isEmpty) {
      catalogValue.remove('AF');
    } else {
      catalogValue['AF'] = associated;
    }

    if (names.changed) {
      final namesDictionary = Map<String, Object?>.from(names.namesDictionary);
      if (names.entries.isEmpty) {
        namesDictionary.remove('EmbeddedFiles');
      } else {
        names.entries.sort(_compareNamePairs);
        final flattened = <Object?>[];
        for (final pair in names.entries) {
          flattened
            ..add(pair.name)
            ..add(pair.reference);
        }
        final embeddedDictionary =
            Map<String, Object?>.from(names.embeddedDictionary)
              ..remove('Kids')
              ..remove('Limits')
              ..['Names'] = flattened;
        final embeddedReference = allocate(
          _serializePdfValue(embeddedDictionary),
        );
        namesDictionary['EmbeddedFiles'] = embeddedReference;
      }
      if (namesDictionary.isEmpty) {
        catalogValue.remove('Names');
      } else {
        final namesReference = allocate(_serializePdfValue(namesDictionary));
        catalogValue['Names'] = namesReference;
      }
    }

    updates[root] = _serializePdfValue(catalogValue);
    return _writeIncrementalUpdate(
      updates,
      nextSize: nextObject > currentSize ? nextObject : currentSize,
      maxOutputSize: maxOutputSize,
    );
  }

  _EmbeddedFileNames _readEmbeddedFileNames(_ManifestAssociation? existing) {
    final namesValue = dereference(catalog['Names']);
    if (namesValue == null) {
      return _EmbeddedFileNames(
        <String, Object?>{},
        <String, Object?>{},
        <_PdfNamePair>[],
        false,
      );
    }
    if (namesValue is! Map<String, Object?>) {
      throw const MalformedAssetFormatException(
        'The PDF catalog Names value is not a dictionary.',
      );
    }
    final namesDictionary = Map<String, Object?>.from(namesValue);
    final embeddedValue = dereference(namesDictionary['EmbeddedFiles']);
    if (embeddedValue == null) {
      return _EmbeddedFileNames(
        namesDictionary,
        <String, Object?>{},
        <_PdfNamePair>[],
        false,
      );
    }
    if (embeddedValue is! Map<String, Object?>) {
      throw const MalformedAssetFormatException(
        'The PDF EmbeddedFiles name tree is not a dictionary.',
      );
    }
    if (embeddedValue.containsKey('Kids')) {
      throw const UnsupportedPdfFeatureException(
        'multi-level EmbeddedFiles name trees',
      );
    }
    final embeddedDictionary = Map<String, Object?>.from(embeddedValue);
    final values = dereference(embeddedDictionary['Names']);
    if (values == null) {
      return _EmbeddedFileNames(
        namesDictionary,
        embeddedDictionary,
        <_PdfNamePair>[],
        false,
      );
    }
    if (values is! List<Object?> || values.length.isOdd) {
      throw const MalformedAssetFormatException(
        'The PDF EmbeddedFiles Names value is not a valid name array.',
      );
    }
    final entries = <_PdfNamePair>[];
    var changed = false;
    for (var i = 0; i < values.length; i += 2) {
      final name = values[i];
      final reference = values[i + 1];
      if (name is! Uint8List || reference is! _PdfReference) {
        throw const MalformedAssetFormatException(
          'The PDF EmbeddedFiles name array contains an invalid pair.',
        );
      }
      if (existing != null && reference == existing.reference) {
        changed = true;
        continue;
      }
      if (_equalBytes(name, utf8.encode('Content Credentials'))) {
        throw const UnsupportedPdfFeatureException(
          'a conflicting Content Credentials embedded-file name',
        );
      }
      entries.add(_PdfNamePair(name, reference));
    }
    return _EmbeddedFileNames(
      namesDictionary,
      embeddedDictionary,
      entries,
      changed,
    );
  }

  Uint8List _writeIncrementalUpdate(
    Map<_PdfReference, Uint8List> updates, {
    required int nextSize,
    required int maxOutputSize,
  }) {
    final output = BytesBuilder(copy: false)..add(bytes);
    if (bytes.isNotEmpty && bytes.last != 0x0a && bytes.last != 0x0d) {
      output.addByte(0x0a);
    }
    final offsets = <_PdfReference, int>{};
    final references = updates.keys.toList()
      ..sort((left, right) {
        final byNumber = left.objectNumber.compareTo(right.objectNumber);
        return byNumber != 0
            ? byNumber
            : left.generation.compareTo(right.generation);
      });
    for (final reference in references) {
      if (reference.generation > 99999) {
        throw const UnsupportedPdfFeatureException(
          'object generations above 99999',
        );
      }
      offsets[reference] = output.length;
      output
        ..add(
          ascii.encode(
            '${reference.objectNumber} ${reference.generation} obj\n',
          ),
        )
        ..add(updates[reference]!)
        ..add(ascii.encode('\nendobj\n'));
    }
    final xrefOffset = output.length;
    if (xrefOffset > 9999999999) {
      throw const UnsupportedPdfFeatureException(
        'classic cross-reference offsets above 9999999999',
      );
    }
    output.add(ascii.encode('xref\n'));
    var first = 0;
    while (first < references.length) {
      var last = first + 1;
      while (last < references.length &&
          references[last].objectNumber ==
              references[last - 1].objectNumber + 1) {
        last++;
      }
      output.add(
        ascii.encode('${references[first].objectNumber} ${last - first}\n'),
      );
      for (var i = first; i < last; i++) {
        final reference = references[i];
        final offset = offsets[reference]!;
        if (offset > 9999999999) {
          throw const UnsupportedPdfFeatureException(
            'classic cross-reference offsets above 9999999999',
          );
        }
        output.add(
          ascii.encode(
            '${offset.toString().padLeft(10, '0')} '
            '${reference.generation.toString().padLeft(5, '0')} n \n',
          ),
        );
      }
      first = last;
    }
    final trailer = Map<String, Object?>.from(latestTrailer)
      ..remove('Type')
      ..remove('W')
      ..remove('Index')
      ..remove('Length')
      ..remove('Filter')
      ..remove('DecodeParms')
      ..remove('XRefStm')
      ..remove('Encrypt')
      ..['Size'] = nextSize
      ..['Root'] = root
      ..['Prev'] = latestXrefOffset;
    output
      ..add(ascii.encode('trailer\n'))
      ..add(_serializePdfValue(trailer))
      ..add(ascii.encode('\nstartxref\n$xrefOffset\n%%EOF\n'));
    if (output.length > maxOutputSize) {
      throw AssetLimitExceededException(
        limit: maxOutputSize,
        actual: output.length,
      );
    }
    return output.takeBytes();
  }

  Object? dereference(Object? value, [int depth = 0]) {
    if (depth > maxObjectDepth) {
      throw AssetLimitExceededException(limit: maxObjectDepth, actual: depth);
    }
    if (value is! _PdfReference) return value;
    final cached = _cache[value];
    if (_cache.containsKey(value)) return cached;
    if (!_resolving.add(value)) {
      throw const MalformedAssetFormatException(
        'The PDF object graph contains a reference cycle.',
      );
    }
    try {
      final entry = entries[value.objectNumber];
      if (entry == null || entry.kind == _XrefEntryKind.free) {
        throw MalformedAssetFormatException(
          'PDF object ${value.objectNumber} is not defined.',
        );
      }
      late Object? object;
      if (entry.kind == _XrefEntryKind.uncompressed) {
        final parsed = _parseIndirectObject(
          bytes,
          entry.field1,
          maxDepth: maxObjectDepth,
        );
        if (parsed.reference != value) {
          throw MalformedAssetFormatException(
            'PDF object ${value.objectNumber} has a mismatched object header.',
          );
        }
        object = parsed.value;
      } else {
        if (value.generation != 0) {
          throw const MalformedAssetFormatException(
            'A compressed PDF object has a non-zero generation.',
          );
        }
        final objects = _readObjectStream(entry.field1, depth + 1);
        if (entry.field2 < 0 || entry.field2 >= objects.length) {
          throw const MalformedAssetFormatException(
            'A compressed PDF object index is out of bounds.',
          );
        }
        final compressed = objects[entry.field2];
        if (compressed.objectNumber != value.objectNumber) {
          throw const MalformedAssetFormatException(
            'A compressed PDF object number does not match its xref entry.',
          );
        }
        object = compressed.value;
      }
      _cache[value] = object;
      return object;
    } finally {
      _resolving.remove(value);
    }
  }

  Uint8List decodeStream(
    _PdfStream stream, {
    required int limit,
    required String purpose,
  }) {
    final filters = _streamFilters(stream.dictionary['Filter']);
    var data = Uint8List.fromList(stream.content);
    if (filters.isEmpty) {
      if (data.length > limit) {
        throw AssetLimitExceededException(limit: limit, actual: data.length);
      }
      return data;
    }
    if (filters.length != 1 || filters.single != 'FlateDecode') {
      throw UnsupportedPdfFeatureException(
        '$purpose stream filter ${filters.join(', ')}',
      );
    }
    data = _inflateZlib(data, limit);
    final parameters = dereference(stream.dictionary['DecodeParms']);
    if (parameters != null) {
      if (parameters is! Map<String, Object?>) {
        throw const MalformedAssetFormatException(
          'PDF stream DecodeParms is not a dictionary.',
        );
      }
      data = _applyPredictor(data, parameters, limit);
    }
    return data;
  }

  List<_CompressedObject> _readObjectStream(int objectStreamNumber, int depth) {
    final cached = _objectStreamCache[objectStreamNumber];
    if (cached != null) return cached;
    final stream = dereference(_PdfReference(objectStreamNumber, 0), depth);
    if (stream is! _PdfStream) {
      throw const MalformedAssetFormatException(
        'A PDF object-stream xref entry does not reference a stream.',
      );
    }
    final type = dereference(stream.dictionary['Type'], depth);
    if (type is! _PdfName || type.value != 'ObjStm') {
      throw const MalformedAssetFormatException(
        'A compressed PDF object is not stored in an ObjStm.',
      );
    }
    final count = stream.dictionary['N'];
    final first = stream.dictionary['First'];
    if (count is! int || count < 0 || first is! int || first < 0) {
      throw const MalformedAssetFormatException(
        'The PDF object stream has invalid N or First values.',
      );
    }
    if (count > entries.length || count > 1024 * 1024) {
      throw AssetLimitExceededException(limit: entries.length, actual: count);
    }
    final decoded = decodeStream(
      stream,
      limit: maxDecodedStreamSize,
      purpose: 'object',
    );
    if (first > decoded.length) {
      throw const MalformedAssetFormatException(
        'The PDF object stream First offset is out of bounds.',
      );
    }
    final header = _PdfParser(decoded, 0, end: first, maxDepth: maxObjectDepth);
    final numbers = <int>[];
    final offsets = <int>[];
    for (var i = 0; i < count; i++) {
      numbers.add(header.readRequiredInteger('object stream object number'));
      offsets.add(header.readRequiredInteger('object stream object offset'));
    }
    header.skipWhitespaceAndComments();
    if (header.index != first) {
      throw const MalformedAssetFormatException(
        'The PDF object stream header has trailing data.',
      );
    }
    final objects = <_CompressedObject>[];
    for (var i = 0; i < count; i++) {
      final start = first + offsets[i];
      final end = i + 1 == count ? decoded.length : first + offsets[i + 1];
      if (start < first || end < start || end > decoded.length) {
        throw const MalformedAssetFormatException(
          'A PDF object stream object range is invalid.',
        );
      }
      final parser = _PdfParser(
        decoded,
        start,
        end: end,
        maxDepth: maxObjectDepth,
      );
      final value = parser.parseValue();
      parser.skipWhitespaceAndComments();
      if (parser.index != end) {
        throw const MalformedAssetFormatException(
          'A PDF object stream object has trailing data.',
        );
      }
      objects.add(_CompressedObject(numbers[i], value));
    }
    _objectStreamCache[objectStreamNumber] = objects;
    return objects;
  }

  List<String> _streamFilters(Object? value) {
    value = dereference(value);
    if (value == null) return const <String>[];
    if (value is _PdfName) return <String>[value.value];
    if (value is List<Object?>) {
      return value
          .map((item) {
            final resolved = dereference(item);
            if (resolved is! _PdfName) {
              throw const MalformedAssetFormatException(
                'A PDF stream filter is not a name.',
              );
            }
            return resolved.value;
          })
          .toList(growable: false);
    }
    throw const MalformedAssetFormatException(
      'The PDF stream Filter value is invalid.',
    );
  }
}

final class _ManifestAssociation {
  const _ManifestAssociation(this.reference, this.fileSpec);

  final _PdfReference reference;
  final Map<String, Object?> fileSpec;
}

final class _PdfNamePair {
  const _PdfNamePair(this.name, this.reference);

  final Uint8List name;
  final _PdfReference reference;
}

final class _EmbeddedFileNames {
  _EmbeddedFileNames(
    this.namesDictionary,
    this.embeddedDictionary,
    this.entries,
    this.changed,
  );

  final Map<String, Object?> namesDictionary;
  final Map<String, Object?> embeddedDictionary;
  final List<_PdfNamePair> entries;
  bool changed;
}

int _compareNamePairs(_PdfNamePair left, _PdfNamePair right) {
  final length = left.name.length < right.name.length
      ? left.name.length
      : right.name.length;
  for (var i = 0; i < length; i++) {
    final comparison = left.name[i].compareTo(right.name[i]);
    if (comparison != 0) return comparison;
  }
  return left.name.length.compareTo(right.name.length);
}

bool _equalBytes(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  for (var i = 0; i < left.length; i++) {
    if (left[i] != right[i]) return false;
  }
  return true;
}

Uint8List _serializeStream(Map<String, Object?> dictionary, Uint8List content) {
  final values = Map<String, Object?>.from(dictionary)
    ..['Length'] = content.length;
  return Uint8List.fromList(<int>[
    ..._serializePdfValue(values),
    ...ascii.encode('\nstream\n'),
    ...content,
    ...ascii.encode('\nendstream'),
  ]);
}

Uint8List _serializePdfValue(Object? value) {
  final output = BytesBuilder(copy: false);

  void write(Object? current) {
    switch (current) {
      case null:
        output.add(ascii.encode('null'));
      case final bool boolean:
        output.add(ascii.encode(boolean ? 'true' : 'false'));
      case final int integer:
        output.add(ascii.encode(integer.toString()));
      case final double number:
        if (!number.isFinite) {
          throw const MalformedAssetFormatException(
            'A PDF numeric value is not finite.',
          );
        }
        output.add(ascii.encode(number.toString()));
      case final _PdfName name:
        output.addByte(0x2f);
        output.add(_encodePdfName(name.value));
      case final _PdfReference reference:
        output.add(
          ascii.encode('${reference.objectNumber} ${reference.generation} R'),
        );
      case final Uint8List string:
        output.addByte(0x3c);
        const digits = '0123456789ABCDEF';
        for (final byte in string) {
          output
            ..addByte(digits.codeUnitAt(byte >> 4))
            ..addByte(digits.codeUnitAt(byte & 0x0f));
        }
        output.addByte(0x3e);
      case final List<Object?> array:
        output.addByte(0x5b);
        for (var i = 0; i < array.length; i++) {
          if (i != 0) output.addByte(0x20);
          write(array[i]);
        }
        output.addByte(0x5d);
      case final Map<String, Object?> dictionary:
        output.add(ascii.encode('<<'));
        final keys = dictionary.keys.toList()..sort();
        for (final key in keys) {
          output.addByte(0x20);
          write(_PdfName(key));
          output.addByte(0x20);
          write(dictionary[key]);
        }
        output.add(ascii.encode(' >>'));
      default:
        throw UnsupportedPdfFeatureException(
          'serialization of ${current.runtimeType} values',
        );
    }
  }

  write(value);
  return output.takeBytes();
}

Uint8List _encodePdfName(String value) {
  final bytes = latin1.encode(value);
  final output = BytesBuilder(copy: false);
  const digits = '0123456789ABCDEF';
  for (final byte in bytes) {
    if (byte >= 0x21 && byte <= 0x7e && !_isDelimiter(byte) && byte != 0x23) {
      output.addByte(byte);
    } else {
      output
        ..addByte(0x23)
        ..addByte(digits.codeUnitAt(byte >> 4))
        ..addByte(digits.codeUnitAt(byte & 0x0f));
    }
  }
  return output.takeBytes();
}

enum _XrefEntryKind { free, uncompressed, compressed }

final class _XrefEntry {
  const _XrefEntry(this.kind, this.field1, this.field2);

  final _XrefEntryKind kind;
  final int field1;
  final int field2;
}

final class _XrefSection {
  const _XrefSection(this.entries, this.trailer);

  final Map<int, _XrefEntry> entries;
  final Map<String, Object?> trailer;
}

_XrefSection _readXrefSection(
  Uint8List bytes,
  int offset, {
  required int maxObjectCount,
  required int maxDepth,
  required int maxDecodedStreamSize,
}) {
  final parser = _PdfParser(bytes, offset, maxDepth: maxDepth);
  parser.skipWhitespaceAndComments();
  if (parser.consumeKeyword('xref')) {
    final entries = <int, _XrefEntry>{};
    while (true) {
      parser.skipWhitespaceAndComments();
      if (parser.consumeKeyword('trailer')) break;
      final first = parser.readRequiredInteger('xref subsection start');
      final count = parser.readRequiredInteger('xref subsection count');
      if (first < 0 || count < 0 || first > maxObjectCount - count) {
        throw AssetLimitExceededException(
          limit: maxObjectCount,
          actual: first + count,
        );
      }
      for (var i = 0; i < count; i++) {
        final field1 = parser.readRequiredInteger('xref object offset');
        final generation = parser.readRequiredInteger('xref generation');
        final status = parser.readRequiredKeyword('xref entry status');
        if (status != 'n' && status != 'f') {
          throw const MalformedAssetFormatException(
            'A PDF xref entry has an invalid status.',
          );
        }
        if (status == 'n' && (field1 < 0 || field1 >= bytes.length)) {
          throw const MalformedAssetFormatException(
            'A PDF xref object offset is outside the asset.',
          );
        }
        entries[first + i] = _XrefEntry(
          status == 'n' ? _XrefEntryKind.uncompressed : _XrefEntryKind.free,
          field1,
          generation,
        );
      }
    }
    final trailer = parser.parseValue();
    if (trailer is! Map<String, Object?>) {
      throw const MalformedAssetFormatException(
        'The PDF trailer is not a dictionary.',
      );
    }
    return _XrefSection(entries, trailer);
  }
  return _readXrefStream(
    bytes,
    offset,
    maxObjectCount: maxObjectCount,
    maxDepth: maxDepth,
    maxDecodedStreamSize: maxDecodedStreamSize,
  );
}

_XrefSection _readXrefStream(
  Uint8List bytes,
  int offset, {
  required int maxObjectCount,
  required int maxDepth,
  required int maxDecodedStreamSize,
}) {
  final indirect = _parseIndirectObject(bytes, offset, maxDepth: maxDepth);
  final stream = indirect.value;
  if (stream is! _PdfStream) {
    throw const MalformedAssetFormatException(
      'The PDF startxref target is neither an xref table nor stream.',
    );
  }
  final type = stream.dictionary['Type'];
  if (type is! _PdfName || type.value != 'XRef') {
    throw const MalformedAssetFormatException(
      'The PDF cross-reference stream has no XRef type.',
    );
  }
  final temporary = _PdfDocument._(
    bytes: bytes,
    entries: const <int, _XrefEntry>{},
    root: const _PdfReference(0, 0),
    latestTrailer: const <String, Object?>{},
    latestXrefOffset: 0,
    maxObjectDepth: maxDepth,
    maxDecodedStreamSize: maxDecodedStreamSize,
  );
  final data = temporary.decodeStream(
    stream,
    limit: maxDecodedStreamSize,
    purpose: 'cross-reference',
  );
  final widthsValue = stream.dictionary['W'];
  if (widthsValue is! List<Object?> ||
      widthsValue.length != 3 ||
      widthsValue.any((value) => value is! int || value < 0 || value > 8)) {
    throw const MalformedAssetFormatException(
      'The PDF cross-reference stream W array is invalid.',
    );
  }
  final widths = widthsValue.cast<int>();
  final rowWidth = widths[0] + widths[1] + widths[2];
  if (rowWidth <= 0) {
    throw const MalformedAssetFormatException(
      'The PDF cross-reference stream row width is zero.',
    );
  }
  final size = stream.dictionary['Size'];
  if (size is! int || size < 0 || size > maxObjectCount) {
    throw AssetLimitExceededException(
      limit: maxObjectCount,
      actual: size is int ? size : maxObjectCount + 1,
    );
  }
  final indexValue = stream.dictionary['Index'];
  final sections = indexValue == null
      ? <int>[0, size]
      : _integerArray(indexValue, 'cross-reference stream Index');
  if (sections.length.isOdd) {
    throw const MalformedAssetFormatException(
      'The PDF cross-reference stream Index array is invalid.',
    );
  }
  var totalRows = 0;
  for (var i = 0; i < sections.length; i += 2) {
    final first = sections[i];
    final count = sections[i + 1];
    if (first < 0 || count < 0 || first > maxObjectCount - count) {
      throw AssetLimitExceededException(
        limit: maxObjectCount,
        actual: first + count,
      );
    }
    totalRows += count;
    if (totalRows > maxObjectCount) {
      throw AssetLimitExceededException(
        limit: maxObjectCount,
        actual: totalRows,
      );
    }
  }
  if (data.length != totalRows * rowWidth) {
    throw const MalformedAssetFormatException(
      'The PDF cross-reference stream length does not match its Index and W.',
    );
  }
  final entries = <int, _XrefEntry>{};
  var cursor = 0;
  for (var section = 0; section < sections.length; section += 2) {
    final first = sections[section];
    final count = sections[section + 1];
    for (var i = 0; i < count; i++) {
      final kind = widths[0] == 0 ? 1 : _readBigEndian(data, cursor, widths[0]);
      cursor += widths[0];
      final field1 = _readBigEndian(data, cursor, widths[1]);
      cursor += widths[1];
      final field2 = _readBigEndian(data, cursor, widths[2]);
      cursor += widths[2];
      final entryKind = switch (kind) {
        0 => _XrefEntryKind.free,
        1 => _XrefEntryKind.uncompressed,
        2 => _XrefEntryKind.compressed,
        _ => throw const MalformedAssetFormatException(
          'The PDF cross-reference stream contains an unknown entry type.',
        ),
      };
      if (entryKind == _XrefEntryKind.uncompressed &&
          (field1 < 0 || field1 >= bytes.length)) {
        throw const MalformedAssetFormatException(
          'A PDF xref stream object offset is outside the asset.',
        );
      }
      entries[first + i] = _XrefEntry(entryKind, field1, field2);
    }
  }
  entries.putIfAbsent(
    indirect.reference.objectNumber,
    () => _XrefEntry(
      _XrefEntryKind.uncompressed,
      offset,
      indirect.reference.generation,
    ),
  );
  return _XrefSection(entries, stream.dictionary);
}

final class _IndirectObject {
  const _IndirectObject(this.reference, this.value);

  final _PdfReference reference;
  final Object? value;
}

_IndirectObject _parseIndirectObject(
  Uint8List bytes,
  int offset, {
  required int maxDepth,
}) {
  if (offset < 0 || offset >= bytes.length) {
    throw const MalformedAssetFormatException(
      'A PDF object offset is outside the asset.',
    );
  }
  final parser = _PdfParser(bytes, offset, maxDepth: maxDepth);
  final number = parser.readRequiredInteger('object number');
  final generation = parser.readRequiredInteger('object generation');
  if (number < 0 || generation < 0 || !parser.consumeKeyword('obj')) {
    throw const MalformedAssetFormatException(
      'A PDF indirect object header is invalid.',
    );
  }
  var value = parser.parseValue();
  if (value is Map<String, Object?>) {
    final saved = parser.index;
    parser.skipWhitespaceAndComments();
    if (parser.consumeKeyword('stream')) {
      if (parser.index >= parser.end) {
        throw const MalformedAssetFormatException(
          'A PDF stream is missing its line ending.',
        );
      }
      if (bytes[parser.index] == 0x0d) {
        parser.index++;
        if (parser.index < parser.end && bytes[parser.index] == 0x0a) {
          parser.index++;
        }
      } else if (bytes[parser.index] == 0x0a) {
        parser.index++;
      } else {
        throw const MalformedAssetFormatException(
          'A PDF stream keyword is not followed by a line ending.',
        );
      }
      final length = value['Length'];
      if (length is! int || length < 0) {
        throw const UnsupportedPdfFeatureException(
          'streams with indirect or invalid Length values',
        );
      }
      if (length > parser.end - parser.index) {
        throw TruncatedAssetException(
          expectedLength: parser.index + length,
          actualLength: parser.end,
        );
      }
      final content = Uint8List.fromList(
        bytes.sublist(parser.index, parser.index + length),
      );
      parser.index += length;
      if (parser.index < parser.end && bytes[parser.index] == 0x0d) {
        parser.index++;
        if (parser.index < parser.end && bytes[parser.index] == 0x0a) {
          parser.index++;
        }
      } else if (parser.index < parser.end && bytes[parser.index] == 0x0a) {
        parser.index++;
      }
      if (!parser.consumeKeyword('endstream')) {
        throw const MalformedAssetFormatException(
          'A PDF stream does not end at its declared Length.',
        );
      }
      value = _PdfStream(value, content);
    } else {
      parser.index = saved;
    }
  }
  parser.skipWhitespaceAndComments();
  if (!parser.consumeKeyword('endobj')) {
    throw const MalformedAssetFormatException(
      'A PDF indirect object is missing endobj.',
    );
  }
  return _IndirectObject(_PdfReference(number, generation), value);
}

final class _PdfParser {
  _PdfParser(this.bytes, this.index, {int? end, required this.maxDepth})
    : end = end ?? bytes.length;

  final Uint8List bytes;
  int index;
  final int end;
  final int maxDepth;

  void skipWhitespaceAndComments() {
    while (index < end) {
      if (_isWhitespace(bytes[index])) {
        index++;
        continue;
      }
      if (bytes[index] == 0x25) {
        index++;
        while (index < end && bytes[index] != 0x0a && bytes[index] != 0x0d) {
          index++;
        }
        continue;
      }
      break;
    }
  }

  Object? parseValue([int depth = 0]) {
    if (depth > maxDepth) {
      throw AssetLimitExceededException(limit: maxDepth, actual: depth);
    }
    skipWhitespaceAndComments();
    if (index >= end) {
      throw const MalformedAssetFormatException(
        'Unexpected end of PDF object.',
      );
    }
    final byte = bytes[index];
    if (byte == 0x2f) return _parseName();
    if (byte == 0x28) return _parseLiteralString();
    if (byte == 0x5b) return _parseArray(depth + 1);
    if (byte == 0x3c) {
      if (index + 1 < end && bytes[index + 1] == 0x3c) {
        return _parseDictionary(depth + 1);
      }
      return _parseHexString();
    }
    if (byte == 0x2b ||
        byte == 0x2d ||
        byte == 0x2e ||
        (byte >= 0x30 && byte <= 0x39)) {
      return _parseNumberOrReference();
    }
    final keyword = readRequiredKeyword('PDF value');
    return switch (keyword) {
      'true' => true,
      'false' => false,
      'null' => null,
      _ => throw MalformedAssetFormatException(
        'Unexpected PDF keyword "$keyword".',
      ),
    };
  }

  int readRequiredInteger(String description) {
    skipWhitespaceAndComments();
    final value = _parseNumber();
    if (value is! int) {
      throw MalformedAssetFormatException(
        'The PDF $description is not an integer.',
      );
    }
    return value;
  }

  String readRequiredKeyword(String description) {
    skipWhitespaceAndComments();
    final start = index;
    while (index < end && !_isDelimiter(bytes[index])) {
      index++;
    }
    if (start == index) {
      throw MalformedAssetFormatException('The PDF $description is missing.');
    }
    return ascii.decode(bytes.sublist(start, index), allowInvalid: false);
  }

  bool consumeKeyword(String keyword) {
    skipWhitespaceAndComments();
    final encoded = ascii.encode(keyword);
    if (!_startsWith(bytes, index, encoded) ||
        (index + encoded.length < end &&
            !_isDelimiter(bytes[index + encoded.length]))) {
      return false;
    }
    index += encoded.length;
    return true;
  }

  Object _parseNumberOrReference() {
    final first = _parseNumber();
    if (first is! int) return first;
    final saved = index;
    try {
      final second = readRequiredInteger('reference generation');
      if (consumeKeyword('R')) return _PdfReference(first, second);
    } on AssetFormatException {
      // It was a single number.
    }
    index = saved;
    return first;
  }

  num _parseNumber() {
    skipWhitespaceAndComments();
    final start = index;
    if (index < end && (bytes[index] == 0x2b || bytes[index] == 0x2d)) {
      index++;
    }
    var hasDigit = false;
    var hasDot = false;
    while (index < end) {
      final byte = bytes[index];
      if (byte >= 0x30 && byte <= 0x39) {
        hasDigit = true;
        index++;
      } else if (byte == 0x2e && !hasDot) {
        hasDot = true;
        index++;
      } else {
        break;
      }
    }
    if (!hasDigit) {
      throw const MalformedAssetFormatException(
        'A PDF numeric value is invalid.',
      );
    }
    final text = ascii.decode(bytes.sublist(start, index));
    final value = hasDot ? double.tryParse(text) : int.tryParse(text);
    if (value == null) {
      throw const MalformedAssetFormatException(
        'A PDF numeric value is out of range.',
      );
    }
    return value;
  }

  _PdfName _parseName() {
    index++;
    final result = <int>[];
    while (index < end && !_isDelimiter(bytes[index])) {
      if (bytes[index] == 0x23) {
        if (index + 2 >= end) {
          throw const MalformedAssetFormatException(
            'A PDF name has an incomplete escape.',
          );
        }
        final high = _hex(bytes[index + 1]);
        final low = _hex(bytes[index + 2]);
        if (high < 0 || low < 0) {
          throw const MalformedAssetFormatException(
            'A PDF name has an invalid escape.',
          );
        }
        result.add((high << 4) | low);
        index += 3;
      } else {
        result.add(bytes[index++]);
      }
    }
    return _PdfName(latin1.decode(result));
  }

  Uint8List _parseLiteralString() {
    index++;
    var nesting = 1;
    final result = <int>[];
    while (index < end && nesting > 0) {
      var byte = bytes[index++];
      if (byte == 0x5c) {
        if (index >= end) break;
        byte = bytes[index++];
        switch (byte) {
          case 0x6e:
            result.add(0x0a);
          case 0x72:
            result.add(0x0d);
          case 0x74:
            result.add(0x09);
          case 0x62:
            result.add(0x08);
          case 0x66:
            result.add(0x0c);
          case 0x0d:
            if (index < end && bytes[index] == 0x0a) index++;
          case 0x0a:
            break;
          case >= 0x30 && <= 0x37:
            var value = byte - 0x30;
            var count = 1;
            while (count < 3 &&
                index < end &&
                bytes[index] >= 0x30 &&
                bytes[index] <= 0x37) {
              value = (value << 3) | (bytes[index++] - 0x30);
              count++;
            }
            result.add(value & 0xff);
          default:
            result.add(byte);
        }
      } else if (byte == 0x28) {
        nesting++;
        result.add(byte);
      } else if (byte == 0x29) {
        nesting--;
        if (nesting > 0) result.add(byte);
      } else {
        result.add(byte);
      }
    }
    if (nesting != 0) {
      throw const MalformedAssetFormatException(
        'A PDF literal string is unterminated.',
      );
    }
    return Uint8List.fromList(result);
  }

  Uint8List _parseHexString() {
    index++;
    final digits = <int>[];
    while (index < end && bytes[index] != 0x3e) {
      if (!_isWhitespace(bytes[index])) digits.add(bytes[index]);
      index++;
    }
    if (index >= end) {
      throw const MalformedAssetFormatException(
        'A PDF hexadecimal string is unterminated.',
      );
    }
    index++;
    final result = Uint8List((digits.length + 1) ~/ 2);
    for (var i = 0; i < digits.length; i += 2) {
      final high = _hex(digits[i]);
      final low = i + 1 < digits.length ? _hex(digits[i + 1]) : 0;
      if (high < 0 || low < 0) {
        throw const MalformedAssetFormatException(
          'A PDF hexadecimal string contains a non-hexadecimal digit.',
        );
      }
      result[i ~/ 2] = (high << 4) | low;
    }
    return result;
  }

  List<Object?> _parseArray(int depth) {
    index++;
    final result = <Object?>[];
    while (true) {
      skipWhitespaceAndComments();
      if (index >= end) {
        throw const MalformedAssetFormatException(
          'A PDF array is unterminated.',
        );
      }
      if (bytes[index] == 0x5d) {
        index++;
        return result;
      }
      result.add(parseValue(depth));
    }
  }

  Map<String, Object?> _parseDictionary(int depth) {
    index += 2;
    final result = <String, Object?>{};
    while (true) {
      skipWhitespaceAndComments();
      if (index + 1 < end && bytes[index] == 0x3e && bytes[index + 1] == 0x3e) {
        index += 2;
        return result;
      }
      if (index >= end || bytes[index] != 0x2f) {
        throw const MalformedAssetFormatException(
          'A PDF dictionary key is not a name.',
        );
      }
      final name = _parseName().value;
      if (result.containsKey(name)) {
        throw MalformedAssetFormatException(
          'The PDF dictionary contains duplicate key /$name.',
        );
      }
      result[name] = parseValue(depth);
    }
  }
}

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

Uint8List _applyPredictor(
  Uint8List bytes,
  Map<String, Object?> parameters,
  int limit,
) {
  final predictor = parameters['Predictor'] ?? 1;
  if (predictor is! int) {
    throw const MalformedAssetFormatException(
      'The PDF stream Predictor is not an integer.',
    );
  }
  if (predictor == 1) return bytes;
  final colors = parameters['Colors'] ?? 1;
  final bits = parameters['BitsPerComponent'] ?? 8;
  final columns = parameters['Columns'] ?? 1;
  if (colors is! int ||
      colors <= 0 ||
      bits != 8 ||
      columns is! int ||
      columns <= 0) {
    throw const UnsupportedPdfFeatureException(
      'stream predictor parameters other than 8-bit components',
    );
  }
  final rowBytes = colors * columns;
  if (rowBytes <= 0 || rowBytes > limit) {
    throw AssetLimitExceededException(limit: limit, actual: rowBytes);
  }
  if (predictor == 2) {
    if (bytes.length % rowBytes != 0) {
      throw const MalformedAssetFormatException(
        'A TIFF-predicted PDF stream has a partial row.',
      );
    }
    final output = Uint8List.fromList(bytes);
    for (var row = 0; row < output.length; row += rowBytes) {
      for (var i = colors; i < rowBytes; i++) {
        output[row + i] = (output[row + i] + output[row + i - colors]) & 0xff;
      }
    }
    return output;
  }
  if (predictor < 10 || predictor > 15) {
    throw UnsupportedPdfFeatureException('stream predictor $predictor');
  }
  final encodedRow = rowBytes + 1;
  if (bytes.length % encodedRow != 0) {
    throw const MalformedAssetFormatException(
      'A PNG-predicted PDF stream has a partial row.',
    );
  }
  final rows = bytes.length ~/ encodedRow;
  if (rows > limit ~/ rowBytes) {
    throw AssetLimitExceededException(limit: limit, actual: rows * rowBytes);
  }
  final output = Uint8List(rows * rowBytes);
  for (var row = 0; row < rows; row++) {
    final filter = bytes[row * encodedRow];
    if (filter > 4) {
      throw const MalformedAssetFormatException(
        'A PNG-predicted PDF stream has an invalid filter.',
      );
    }
    for (var column = 0; column < rowBytes; column++) {
      final raw = bytes[row * encodedRow + 1 + column];
      final left = column >= colors
          ? output[row * rowBytes + column - colors]
          : 0;
      final above = row > 0 ? output[(row - 1) * rowBytes + column] : 0;
      final upperLeft = row > 0 && column >= colors
          ? output[(row - 1) * rowBytes + column - colors]
          : 0;
      final value = switch (filter) {
        0 => raw,
        1 => raw + left,
        2 => raw + above,
        3 => raw + ((left + above) >> 1),
        4 => raw + _paeth(left, above, upperLeft),
        _ => raw,
      };
      output[row * rowBytes + column] = value & 0xff;
    }
  }
  return output;
}

int _paeth(int left, int above, int upperLeft) {
  final estimate = left + above - upperLeft;
  final leftDistance = (estimate - left).abs();
  final aboveDistance = (estimate - above).abs();
  final diagonalDistance = (estimate - upperLeft).abs();
  if (leftDistance <= aboveDistance && leftDistance <= diagonalDistance) {
    return left;
  }
  return aboveDistance <= diagonalDistance ? above : upperLeft;
}

Uint8List _inflateZlib(Uint8List input, int limit) {
  if (input.length < 6) {
    throw const MalformedAssetFormatException(
      'A FlateDecode stream has a truncated zlib wrapper.',
    );
  }
  final cmf = input[0];
  final flg = input[1];
  if ((cmf & 0x0f) != 8 || ((cmf << 8) + flg) % 31 != 0) {
    throw const MalformedAssetFormatException(
      'A FlateDecode stream has an invalid zlib header.',
    );
  }
  if ((flg & 0x20) != 0) {
    throw const UnsupportedPdfFeatureException(
      'FlateDecode streams with preset dictionaries',
    );
  }
  final reader = _BitReader(input, 2, input.length - 4);
  final output = <int>[];
  var finalBlock = false;
  while (!finalBlock) {
    finalBlock = reader.readBits(1) == 1;
    final type = reader.readBits(2);
    if (type == 0) {
      reader.align();
      final length = reader.readByte() | (reader.readByte() << 8);
      final inverse = reader.readByte() | (reader.readByte() << 8);
      if ((length ^ 0xffff) != inverse) {
        throw const MalformedAssetFormatException(
          'A FlateDecode stored block has an invalid length.',
        );
      }
      if (length > limit - output.length) {
        throw AssetLimitExceededException(
          limit: limit,
          actual: output.length + length,
        );
      }
      for (var i = 0; i < length; i++) {
        output.add(reader.readByte());
      }
    } else if (type == 1 || type == 2) {
      final tables = type == 1
          ? _fixedHuffmanTables()
          : _dynamicHuffmanTables(reader);
      _inflateHuffmanBlock(reader, output, tables.$1, tables.$2, limit);
    } else {
      throw const MalformedAssetFormatException(
        'A FlateDecode stream uses a reserved block type.',
      );
    }
  }
  if (!reader.onlyPaddingBitsRemain) {
    throw const MalformedAssetFormatException(
      'A FlateDecode stream has trailing compressed data.',
    );
  }
  final expected =
      input[input.length - 4] * 0x1000000 +
      input[input.length - 3] * 0x10000 +
      input[input.length - 2] * 0x100 +
      input[input.length - 1];
  if (_adler32(output) != expected) {
    throw const MalformedAssetFormatException(
      'A FlateDecode stream has an invalid Adler-32 checksum.',
    );
  }
  return Uint8List.fromList(output);
}

void _inflateHuffmanBlock(
  _BitReader reader,
  List<int> output,
  _Huffman literals,
  _Huffman distances,
  int limit,
) {
  const lengthBases = <int>[
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    13,
    15,
    17,
    19,
    23,
    27,
    31,
    35,
    43,
    51,
    59,
    67,
    83,
    99,
    115,
    131,
    163,
    195,
    227,
    258,
  ];
  const lengthExtras = <int>[
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    1,
    1,
    1,
    2,
    2,
    2,
    2,
    3,
    3,
    3,
    3,
    4,
    4,
    4,
    4,
    5,
    5,
    5,
    5,
    0,
  ];
  const distanceBases = <int>[
    1,
    2,
    3,
    4,
    5,
    7,
    9,
    13,
    17,
    25,
    33,
    49,
    65,
    97,
    129,
    193,
    257,
    385,
    513,
    769,
    1025,
    1537,
    2049,
    3073,
    4097,
    6145,
    8193,
    12289,
    16385,
    24577,
  ];
  const distanceExtras = <int>[
    0,
    0,
    0,
    0,
    1,
    1,
    2,
    2,
    3,
    3,
    4,
    4,
    5,
    5,
    6,
    6,
    7,
    7,
    8,
    8,
    9,
    9,
    10,
    10,
    11,
    11,
    12,
    12,
    13,
    13,
  ];
  while (true) {
    final symbol = literals.read(reader);
    if (symbol < 256) {
      if (output.length >= limit) {
        throw AssetLimitExceededException(
          limit: limit,
          actual: output.length + 1,
        );
      }
      output.add(symbol);
    } else if (symbol == 256) {
      return;
    } else {
      final index = symbol - 257;
      if (index < 0 || index >= lengthBases.length) {
        throw const MalformedAssetFormatException(
          'A FlateDecode stream has an invalid length symbol.',
        );
      }
      final length = lengthBases[index] + reader.readBits(lengthExtras[index]);
      final distanceSymbol = distances.read(reader);
      if (distanceSymbol >= distanceBases.length) {
        throw const MalformedAssetFormatException(
          'A FlateDecode stream has an invalid distance symbol.',
        );
      }
      final distance =
          distanceBases[distanceSymbol] +
          reader.readBits(distanceExtras[distanceSymbol]);
      if (distance <= 0 || distance > output.length) {
        throw const MalformedAssetFormatException(
          'A FlateDecode stream has an invalid back-reference.',
        );
      }
      if (length > limit - output.length) {
        throw AssetLimitExceededException(
          limit: limit,
          actual: output.length + length,
        );
      }
      for (var i = 0; i < length; i++) {
        output.add(output[output.length - distance]);
      }
    }
  }
}

(_Huffman, _Huffman) _fixedHuffmanTables() {
  final literalLengths = List<int>.filled(288, 8);
  for (var i = 144; i <= 255; i++) {
    literalLengths[i] = 9;
  }
  for (var i = 256; i <= 279; i++) {
    literalLengths[i] = 7;
  }
  final distanceLengths = List<int>.filled(32, 5);
  return (_Huffman(literalLengths), _Huffman(distanceLengths));
}

(_Huffman, _Huffman) _dynamicHuffmanTables(_BitReader reader) {
  final literalCount = reader.readBits(5) + 257;
  final distanceCount = reader.readBits(5) + 1;
  final codeCount = reader.readBits(4) + 4;
  const order = <int>[
    16,
    17,
    18,
    0,
    8,
    7,
    9,
    6,
    10,
    5,
    11,
    4,
    12,
    3,
    13,
    2,
    14,
    1,
    15,
  ];
  final codeLengths = List<int>.filled(19, 0);
  for (var i = 0; i < codeCount; i++) {
    codeLengths[order[i]] = reader.readBits(3);
  }
  final codeTable = _Huffman(codeLengths);
  final lengths = <int>[];
  final required = literalCount + distanceCount;
  while (lengths.length < required) {
    final symbol = codeTable.read(reader);
    if (symbol <= 15) {
      lengths.add(symbol);
    } else if (symbol == 16) {
      if (lengths.isEmpty) {
        throw const MalformedAssetFormatException(
          'A FlateDecode repeat code has no previous length.',
        );
      }
      final count = reader.readBits(2) + 3;
      if (count > required - lengths.length) {
        throw const MalformedAssetFormatException(
          'A FlateDecode code-length repeat exceeds its table.',
        );
      }
      lengths.addAll(List<int>.filled(count, lengths.last));
    } else if (symbol == 17 || symbol == 18) {
      final count =
          reader.readBits(symbol == 17 ? 3 : 7) + (symbol == 17 ? 3 : 11);
      if (count > required - lengths.length) {
        throw const MalformedAssetFormatException(
          'A FlateDecode zero repeat exceeds its table.',
        );
      }
      lengths.addAll(List<int>.filled(count, 0));
    } else {
      throw const MalformedAssetFormatException(
        'A FlateDecode code-length symbol is invalid.',
      );
    }
  }
  final literals = _Huffman(lengths.sublist(0, literalCount));
  final distances = _Huffman(lengths.sublist(literalCount));
  return (literals, distances);
}

final class _Huffman {
  _Huffman(List<int> lengths) {
    var maximum = 0;
    for (final length in lengths) {
      if (length > maximum) maximum = length;
    }
    if (maximum == 0) {
      throw const MalformedAssetFormatException(
        'A FlateDecode Huffman table is empty.',
      );
    }
    maxLength = maximum;
    final counts = List<int>.filled(maximum + 1, 0);
    for (final length in lengths) {
      if (length < 0 || length > 15) {
        throw const MalformedAssetFormatException(
          'A FlateDecode Huffman code length is invalid.',
        );
      }
      if (length > 0) counts[length]++;
    }
    var remaining = 1;
    for (var bits = 1; bits <= maximum; bits++) {
      remaining = (remaining << 1) - counts[bits];
      if (remaining < 0) {
        throw const MalformedAssetFormatException(
          'A FlateDecode Huffman table is oversubscribed.',
        );
      }
    }
    final next = List<int>.filled(maximum + 1, 0);
    var code = 0;
    for (var bits = 1; bits <= maximum; bits++) {
      code = (code + counts[bits - 1]) << 1;
      next[bits] = code;
    }
    for (var symbol = 0; symbol < lengths.length; symbol++) {
      final length = lengths[symbol];
      if (length == 0) continue;
      final reversed = _reverseBits(next[length]++, length);
      table[(length << 16) | reversed] = symbol;
    }
  }

  late final int maxLength;
  final Map<int, int> table = <int, int>{};

  int read(_BitReader reader) {
    var code = 0;
    for (var length = 1; length <= maxLength; length++) {
      code |= reader.readBits(1) << (length - 1);
      final symbol = table[(length << 16) | code];
      if (symbol != null) return symbol;
    }
    throw const MalformedAssetFormatException(
      'A FlateDecode Huffman code is invalid.',
    );
  }
}

final class _BitReader {
  _BitReader(this.bytes, this.index, this.end);

  final Uint8List bytes;
  int index;
  final int end;
  int _bits = 0;
  int _available = 0;

  int readBits(int count) {
    while (_available < count) {
      if (index >= end) {
        throw const MalformedAssetFormatException(
          'A FlateDecode stream is truncated.',
        );
      }
      _bits |= bytes[index++] << _available;
      _available += 8;
    }
    final mask = count == 0 ? 0 : (1 << count) - 1;
    final value = _bits & mask;
    _bits >>= count;
    _available -= count;
    return value;
  }

  void align() {
    _bits = 0;
    _available = 0;
  }

  int readByte() {
    if (_available != 0) {
      throw const MalformedAssetFormatException(
        'A FlateDecode stored block is not byte-aligned.',
      );
    }
    if (index >= end) {
      throw const MalformedAssetFormatException(
        'A FlateDecode stream is truncated.',
      );
    }
    return bytes[index++];
  }

  bool get onlyPaddingBitsRemain => index == end;
}

int _reverseBits(int value, int count) {
  var result = 0;
  for (var i = 0; i < count; i++) {
    result = (result << 1) | ((value >> i) & 1);
  }
  return result;
}

int _adler32(List<int> bytes) {
  var a = 1;
  var b = 0;
  for (final byte in bytes) {
    a = (a + byte) % 65521;
    b = (b + a) % 65521;
  }
  return (b << 16) | a;
}

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

bool _startsWith(List<int> bytes, int offset, List<int> pattern) {
  if (offset < 0 || offset + pattern.length > bytes.length) return false;
  for (var i = 0; i < pattern.length; i++) {
    if (bytes[offset + i] != pattern[i]) return false;
  }
  return true;
}

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
    if (_startsWith(bytes, i, pattern)) return i;
  }
  return -1;
}
