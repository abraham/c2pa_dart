part of '../pdf_handler.dart';

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
      if (bytesEqual(name, utf8.encode('Content Credentials'))) {
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
