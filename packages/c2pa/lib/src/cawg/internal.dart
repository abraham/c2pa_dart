part of '../cawg_identity.dart';

CawgIdentityAssertion _fitIdentityAssertion({
  required CawgSignerPayload payload,
  required Uint8List signature,
  required int size,
}) {
  final empty = CawgIdentityAssertion(
    signerPayload: payload,
    signature: signature,
  );
  final minimum = empty.encode().length;
  if (minimum > size) {
    throw StateError(
      'CAWG identity assertion requires $minimum bytes, reservation is $size',
    );
  }
  final estimate = size - minimum;
  for (var adjustment = 0; adjustment <= 16; adjustment++) {
    final padding = estimate - adjustment;
    if (padding < 0) continue;
    final assertion = CawgIdentityAssertion(
      signerPayload: payload,
      signature: signature,
      pad1: Uint8List(padding),
    );
    if (assertion.encode().length == size) return assertion;
  }
  for (var pad1Length = 0; pad1Length <= 32; pad1Length++) {
    final base = CawgIdentityAssertion(
      signerPayload: payload,
      signature: signature,
      pad1: Uint8List(pad1Length),
      pad2: Uint8List(0),
    ).encode().length;
    final pad2Estimate = size - base;
    for (var offset = -8; offset <= 8; offset++) {
      final pad2Length = pad2Estimate + offset;
      if (pad2Length < 0) continue;
      final assertion = CawgIdentityAssertion(
        signerPayload: payload,
        signature: signature,
        pad1: Uint8List(pad1Length),
        pad2: Uint8List(pad2Length),
      );
      if (assertion.encode().length == size) return assertion;
    }
  }
  throw StateError('Unable to fit CAWG identity assertion reservation');
}

final class _CallbackSigningBackend implements CoseSigningBackend {
  const _CallbackSigningBackend(this.signer);

  /// Signer callback used to produce COSE signatures.
  final C2paSigner signer;

  @override
  Future<List<int>> sign(SigningAlgorithm algorithm, List<int> data) =>
      signer.sign(Uint8List.fromList(data));
}

final class _CallbackVerificationBackend implements CoseVerificationBackend {
  const _CallbackVerificationBackend(this.verifier, this.publicKey);
  final C2paVerifier verifier;
  final Uint8List publicKey;

  @override
  Future<bool> verify(
    SigningAlgorithm algorithm,
    List<int> data,
    List<int> signature,
  ) => verifier.verify(
    algorithm: algorithm.name,
    data: Uint8List.fromList(data),
    signature: Uint8List.fromList(signature),
    publicKey: publicKey,
  );
}

Future<CoseVerificationBackend> _verificationBackend(
  SigningAlgorithm algorithm,
  X509Certificate certificate,
  C2paVerifier? callback,
) async {
  if (callback != null) {
    return _CallbackVerificationBackend(
      callback,
      certificate.subjectPublicKeyInfoDer,
    );
  }
  switch (algorithm) {
    case SigningAlgorithm.es256:
    case SigningAlgorithm.es384:
    case SigningAlgorithm.es512:
      return EcdsaVerificationBackend(
        algorithm,
        await importEcdsaPublicKeySpki(
          algorithm,
          certificate.subjectPublicKeyInfoDer,
        ),
      );
    case SigningAlgorithm.ps256:
    case SigningAlgorithm.ps384:
    case SigningAlgorithm.ps512:
      return RsaPssVerificationBackend(
        algorithm,
        await importRsaPssPublicKeySpki(
          algorithm,
          certificate.subjectPublicKeyInfoDer,
        ),
      );
    case SigningAlgorithm.ed25519:
      return Ed25519VerificationBackend(
        SimplePublicKey(
          certificate.subjectPublicKey,
          type: KeyPairType.ed25519,
        ),
      );
  }
}

List<Uint8List> _x5chain(CoseSign1 message) {
  final value =
      message.protectedHeaders[CoseHeaderLabel.x509Chain] ??
      message.unprotectedHeaders[CoseHeaderLabel.x509Chain];
  if (value is Uint8List) return [value];
  if (value is List && value.isNotEmpty && value.every((v) => v is Uint8List)) {
    return value.cast<Uint8List>();
  }
  throw const FormatException('CAWG X.509 signature requires x5chain');
}

final class _CawgCoseEnvelope {
  _CawgCoseEnvelope(this.sanitizedBytes, this.textHeaders, this.protectedBytes);
  final Uint8List sanitizedBytes;
  final Map<String, Object?> textHeaders;
  final Uint8List protectedBytes;

  factory _CawgCoseEnvelope.parse(Uint8List bytes) {
    final tagged = bytes.isNotEmpty && bytes.first == 0xd2;
    final decoded = decodeCbor(
      tagged ? Uint8List.sublistView(bytes, 1) : bytes,
      requireCanonicalMapOrder: false,
      allowIndefiniteLength: true,
    );
    if (decoded is! List || decoded.length != 4 || decoded[1] is! Map) {
      throw const FormatException('Malformed COSE_Sign1');
    }
    final protectedBytes = decoded[0];
    if (protectedBytes is! Uint8List) {
      throw const FormatException('Malformed COSE protected headers');
    }
    late Object? protectedHeaders;
    try {
      protectedHeaders = protectedBytes.isEmpty
          ? <Object?, Object?>{}
          : decodeCbor(
              protectedBytes,
              requireCanonicalMapOrder: false,
              allowIndefiniteLength: true,
            );
    } on Object catch (error) {
      throw _CawgInvalidProtectedHeaders(error.toString());
    }
    if (protectedHeaders is! Map) {
      throw const _CawgInvalidProtectedHeaders(
        'Malformed COSE protected headers',
      );
    }
    final numeric = <Object?, Object?>{};
    final text = <String, Object?>{};
    for (final entry in (decoded[1] as Map).entries) {
      if (entry.key is String) {
        text[entry.key as String] = entry.value;
      } else {
        numeric[entry.key] = entry.value;
      }
    }
    final sanitized = encodeCbor([
      encodeCbor(protectedHeaders),
      numeric,
      decoded[2],
      decoded[3],
    ]);
    return _CawgCoseEnvelope(
      tagged ? Uint8List.fromList([0xd2, ...sanitized]) : sanitized,
      Map.unmodifiable(text),
      protectedBytes,
    );
  }
}

Future<bool> _verifyCoseWithProtectedBytes(
  CoseVerificationBackend backend,
  SigningAlgorithm algorithm,
  Uint8List protectedBytes,
  Uint8List payload,
  Uint8List signature,
) => backend.verify(
  algorithm,
  encodeCbor(['Signature1', protectedBytes, Uint8List(0), payload]),
  signature,
);

bool _isAlgorithmCoseError(CoseErrorCode code) =>
    code == CoseErrorCode.missingProtectedAlgorithm ||
    code == CoseErrorCode.invalidHeaderLabel ||
    code == CoseErrorCode.invalidHeaderValue ||
    code == CoseErrorCode.duplicateHeader;

Uint8List? _timestampToken(Object? value) {
  if (value is Uint8List) return value;
  if (value is Map) {
    final tokens = value['tstTokens'];
    if (tokens is List && tokens.isNotEmpty) {
      final first = tokens.first;
      if (first is Uint8List) return first;
      if (first is Map && first['val'] is Uint8List) {
        return first['val'] as Uint8List;
      }
    }
    if (value['val'] is Uint8List) return value['val'] as Uint8List;
  }
  return null;
}

Uint8List? _firstByteString(Object? value, String key) {
  if (value is! Map) return null;
  final values = value[key];
  if (values is Uint8List) return values;
  if (values is List && values.isNotEmpty && values.first is Uint8List) {
    return values.first as Uint8List;
  }
  return null;
}

SimplePublicKey _didJwkKey(String did) {
  final encoded = did.substring('did:jwk:'.length);
  final decoded = utf8.decode(base64Url.decode(base64Url.normalize(encoded)));
  return _publicJwkKey(_stringMap(jsonDecode(decoded), 'did:jwk'));
}

SimplePublicKey _publicJwkKey(Map<String, Object?> jwk) {
  if (jwk['kty'] != 'OKP' ||
      jwk['crv'] != 'Ed25519' ||
      jwk['x'] is! String ||
      jwk.containsKey('d')) {
    throw const FormatException('Expected a public Ed25519 OKP JWK');
  }
  final bytes = base64Url.decode(base64Url.normalize(jwk['x']! as String));
  if (bytes.length != 32) {
    throw const FormatException('Ed25519 JWK x must contain 32 bytes');
  }
  return SimplePublicKey(bytes, type: KeyPairType.ed25519);
}

/// Renders a distinguished name for display, preferring the organization then
/// the common name, matching how signer names are surfaced elsewhere.
String _distinguishedNameText(X509DistinguishedName name) {
  String? attribute(String oid) {
    for (final entry in name.attributes.reversed) {
      if (entry.oid == oid) return entry.value;
    }
    return null;
  }

  return attribute('2.5.4.10') ??
      attribute('2.5.4.3') ??
      name.attributes.lastOrNull?.value ??
      '';
}

Uri _didWebUri(String did) {
  final segments = did.substring('did:web:'.length).split(':');
  if (segments.isEmpty || segments.first.isEmpty) {
    throw const FormatException('Malformed did:web identifier');
  }
  final authority = Uri.decodeComponent(segments.first);
  final authorityUri = Uri.tryParse('https://$authority');
  if (authorityUri == null || authorityUri.host.isEmpty) {
    throw const FormatException('Malformed did:web authority');
  }
  final decodedSegments = segments.skip(1).map(Uri.decodeComponent).toList();
  if (decodedSegments.any(
    (segment) =>
        segment.isEmpty ||
        segment == '.' ||
        segment == '..' ||
        segment.contains('/') ||
        segment.contains(r'\'),
  )) {
    throw const FormatException('Malformed did:web path');
  }
  final path = segments.length == 1
      ? '/.well-known/did.json'
      : '/${decodedSegments.join('/')}/did.json';
  return Uri(
    scheme: 'https',
    host: authorityUri.host,
    port: authorityUri.hasPort ? authorityUri.port : null,
    path: path,
  );
}

Map<String, Object?> _verifiedIdentitySummary(CawgVerifiedIdentity identity) =>
    {
      'type': identity.type,
      'name': ?identity.name,
      'username': ?identity.username,
      'address': ?identity.address,
      'uri': ?identity.uri?.toString(),
      'verifiedAt': identity.verifiedAt.toIso8601String(),
      'provider': {
        'id': identity.provider.id.toString(),
        'name': identity.provider.name,
      },
    };

bool _icaAssetMatches(
  Map<String, Object?> credentialAsset,
  CawgSignerPayload signerPayload, {
  required CawgIcaCompatibility compatibility,
}) {
  final actual = _mutableJsonMap(credentialAsset);
  final expected = _mutableJsonMap(signerPayload.toJson());
  final actualReferences = actual['referenced_assertions'];
  final expectedReferences = expected['referenced_assertions'];
  if (actualReferences is List && expectedReferences is List) {
    for (
      var index = 0;
      index < actualReferences.length && index < expectedReferences.length;
      index++
    ) {
      final actualReference = actualReferences[index];
      final expectedReference = expectedReferences[index];
      if (actualReference is! Map || expectedReference is! Map) {
        continue;
      }
      final actualMap = actualReference.cast<String, Object?>();
      final expectedMap = expectedReference.cast<String, Object?>();
      final hash = actualMap['hash'];
      if (hash is List && hash.every((value) => value is int)) {
        try {
          actualMap['hash'] = utf8.decode(hash.cast<int>());
        } on FormatException {
          return false;
        }
      }
      final actualAlgorithm = actualMap['alg'];
      if (compatibility == CawgIcaCompatibility.c2paRs09022 &&
          !expectedMap.containsKey('alg') &&
          actualAlgorithm is String) {
        expectedMap['alg'] = actualMap['alg'];
      }
    }
  }
  return deepEquals(actual, expected);
}

Map<String, Object?> _mutableJsonMap(Map<String, Object?> value) =>
    value.map((key, child) => MapEntry(key, _mutableJsonValue(child)));

Object? _mutableJsonValue(Object? value) {
  if (value is Map) {
    return value.map(
      (key, child) => MapEntry(key.toString(), _mutableJsonValue(child)),
    );
  }
  if (value is List) {
    return value.map(_mutableJsonValue).toList();
  }
  return value;
}

Uint8List? _sortCmsCertificateSet(Uint8List bytes) {
  try {
    final contentInfo = _DerSlice.read(bytes, 0);
    if (contentInfo.tag != 0x30 || contentInfo.end != bytes.length) return null;
    final contentChildren = contentInfo.children();
    if (contentChildren.length < 2 || contentChildren[1].tag != 0xa0) {
      return null;
    }
    final wrapperChildren = contentChildren[1].children();
    if (wrapperChildren.length != 1 || wrapperChildren.single.tag != 0x30) {
      return null;
    }
    final signedData = wrapperChildren.single;
    final signedChildren = signedData.children();
    final certificateIndex = signedChildren.indexWhere(
      (child) => child.tag == 0xa0,
      3,
    );
    if (certificateIndex < 0) return null;
    final certificates = signedChildren[certificateIndex].children()
      ..sort((left, right) => _compareByteLists(left.encoded, right.encoded));
    final normalizedCertificateSet = _encodeDer(
      0xa0,
      certificates.expand((child) => child.encoded).toList(growable: false),
    );
    final normalizedSignedData = _encodeDer(0x30, [
      for (var index = 0; index < signedChildren.length; index++)
        ...(index == certificateIndex
            ? normalizedCertificateSet
            : signedChildren[index].encoded),
    ]);
    final normalizedWrapper = _encodeDer(0xa0, normalizedSignedData);
    return Uint8List.fromList(
      _encodeDer(0x30, [
        ...contentChildren.first.encoded,
        ...normalizedWrapper,
        for (final child in contentChildren.skip(2)) ...child.encoded,
      ]),
    );
  } on FormatException {
    return null;
  }
}

int _compareByteLists(List<int> left, List<int> right) {
  final length = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < length; index++) {
    final comparison = left[index].compareTo(right[index]);
    if (comparison != 0) return comparison;
  }
  return left.length.compareTo(right.length);
}

List<int> _encodeDer(int tag, List<int> content) => [
  tag,
  ..._encodeDerLength(content.length),
  ...content,
];

List<int> _encodeDerLength(int length) {
  if (length < 0x80) return [length];
  final bytes = <int>[];
  for (var value = length; value > 0; value >>= 8) {
    bytes.insert(0, value & 0xff);
  }
  return [0x80 | bytes.length, ...bytes];
}

final class _DerSlice {
  const _DerSlice(
    this.source,
    this.start,
    this.tag,
    this.contentStart,
    this.end,
  );

  factory _DerSlice.read(Uint8List source, int offset) {
    if (offset < 0 || offset + 2 > source.length) {
      throw const FormatException('Truncated DER value');
    }
    final tag = source[offset];
    var cursor = offset + 1;
    final firstLength = source[cursor++];
    late int length;
    if (firstLength < 0x80) {
      length = firstLength;
    } else {
      final count = firstLength & 0x7f;
      if (count == 0 || count > 4 || cursor + count > source.length) {
        throw const FormatException('Malformed DER length');
      }
      length = 0;
      for (var index = 0; index < count; index++) {
        length = (length << 8) | source[cursor++];
      }
    }
    final end = cursor + length;
    if (end > source.length) {
      throw const FormatException('Truncated DER value');
    }
    return _DerSlice(source, offset, tag, cursor, end);
  }

  final Uint8List source;
  final int start;
  final int tag;
  final int contentStart;
  final int end;

  Uint8List get encoded => Uint8List.sublistView(source, start, end);

  List<_DerSlice> children() {
    final result = <_DerSlice>[];
    var cursor = contentStart;
    while (cursor < end) {
      final child = _DerSlice.read(source, cursor);
      result.add(child);
      cursor = child.end;
    }
    if (cursor != end) throw const FormatException('Malformed DER container');
    return result;
  }
}

final class _CawgUnsupportedIssuer implements Exception {
  const _CawgUnsupportedIssuer(this.message);
  final String message;
}

final class _CawgInvalidProtectedHeaders implements Exception {
  const _CawgInvalidProtectedHeaders(this.message);
  final String message;
}

final class _CawgDidResolutionFailure implements Exception {
  const _CawgDidResolutionFailure(this.message);
  final String message;
}

final class _CawgInvalidDidDocument implements Exception {
  const _CawgInvalidDidDocument(this.message);
  final String message;
}

SigningAlgorithm _algorithmByName(String name) {
  final normalized = name.toLowerCase().replaceAll('-', '');
  return SigningAlgorithm.values.firstWhere(
    (value) => value.name == normalized,
    orElse: () =>
        throw ArgumentError.value(name, 'algorithm', 'Unsupported algorithm'),
  );
}

Map<String, Object?> _stringMap(Object? value, String name) {
  if (value is! Map) throw FormatException('$name must be a map');
  final result = <String, Object?>{};
  for (final entry in value.entries) {
    if (entry.key is! String) {
      throw FormatException('$name keys must be strings');
    }
    result[entry.key as String] = entry.value;
  }
  return result;
}

/// Collects entries whose keys are not part of the known field set.
Map<String, Object?> unknownFieldsOf(
  Map<String, Object?> map,
  Set<String> known,
) => {
  for (final entry in map.entries)
    if (!known.contains(entry.key)) entry.key: entry.value,
};

List<String> _strings(Object? value, String name) {
  if (value is String) return [value];
  if (value is List && value.every((item) => item is String)) {
    return value.cast<String>();
  }
  throw FormatException('$name must be a string or string array');
}

DateTime? _optionalDate(Object? value, String name) {
  if (value == null) return null;
  if (value is! String || DateTime.tryParse(value) == null) {
    throw FormatException('$name must be an RFC 3339 timestamp');
  }
  return DateTime.parse(value).toUtc();
}

Object? _bytesToBase64(Object? value) {
  if (value is Uint8List) return base64.encode(value);
  if (value is List) return value.map(_bytesToBase64).toList(growable: false);
  if (value is Map) {
    return {
      for (final entry in value.entries)
        entry.key.toString(): _bytesToBase64(entry.value),
    };
  }
  return value;
}

String _relativeAssertionUrl(String url) {
  final marker = '/c2pa.assertions/';
  final index = url.indexOf(marker);
  if (index >= 0) return url.substring(index + 1);
  return url.startsWith('self#jumbf=/') ? url.substring(12) : url;
}

String _identityLabel(String value) =>
    Uri.decodeComponent(_relativeAssertionUrl(value).split('/').last);

bool _hasIdentityReferenceCycle(
  String start,
  Map<String, CawgIdentityAssertion> assertions,
) {
  final visiting = <String>{};
  final visited = <String>{};

  bool visit(String label) {
    if (!visiting.add(label)) return true;
    if (visited.contains(label)) {
      visiting.remove(label);
      return false;
    }
    final assertion = assertions[label];
    if (assertion != null) {
      for (final reference in assertion.signerPayload.referencedAssertions) {
        final target = _identityLabel(reference.url);
        if (_isIdentityReference(target) &&
            assertions.containsKey(target) &&
            visit(target)) {
          return true;
        }
      }
    }
    visiting.remove(label);
    visited.add(label);
    return false;
  }

  return visit(start);
}

bool _isIdentityReference(String url) {
  final label = url.split('/').last;
  return CawgIdentityLabels.isIdentity(Uri.decodeComponent(label));
}

bool _isHardBinding(String url) {
  final label = Uri.decodeComponent(url.split('/').last);
  return label == 'c2pa.hash.data' ||
      label == 'c2pa.hash.boxes' ||
      label == 'c2pa.hash.bmff.v3' ||
      label == 'c2pa.hash.collection.data';
}

Uint8List _cborMapValueBytes(Uint8List bytes, String wantedKey) {
  final cursor = _CborSliceCursor(bytes);
  final header = cursor.readHeader();
  if (header.major != 5) {
    throw const FormatException('CAWG identity assertion must be a CBOR map');
  }
  var remaining = header.indefinite ? null : header.value;
  while (remaining == null || remaining > 0) {
    if (remaining == null && cursor.isBreak) {
      cursor.offset++;
      break;
    }
    final keyStart = cursor.offset;
    final keyEnd = cursor.skipItem();
    final key = decodeCbor(
      Uint8List.sublistView(bytes, keyStart, keyEnd),
      requireCanonicalMapOrder: false,
      allowIndefiniteLength: true,
    );
    final valueStart = cursor.offset;
    final valueEnd = cursor.skipItem();
    if (key == wantedKey) {
      return Uint8List.fromList(bytes.sublist(valueStart, valueEnd));
    }
    if (remaining != null) remaining--;
  }
  throw FormatException('CAWG identity assertion is missing $wantedKey');
}

final class _CborSliceCursor {
  _CborSliceCursor(this.bytes);

  final Uint8List bytes;
  int offset = 0;

  bool get isBreak => offset < bytes.length && bytes[offset] == 0xff;

  ({int major, int value, bool indefinite}) readHeader() {
    if (offset >= bytes.length) {
      throw const FormatException('Truncated CBOR');
    }
    final initial = bytes[offset++];
    final major = initial >> 5;
    final additional = initial & 0x1f;
    if (additional == 31) {
      return (major: major, value: 0, indefinite: true);
    }
    if (additional < 24) {
      return (major: major, value: additional, indefinite: false);
    }
    final width = switch (additional) {
      24 => 1,
      25 => 2,
      26 => 4,
      27 => 8,
      _ => throw const FormatException('Invalid CBOR additional information'),
    };
    if (offset + width > bytes.length) {
      throw const FormatException('Truncated CBOR argument');
    }
    var value = 0;
    for (var index = 0; index < width; index++) {
      value = (value << 8) | bytes[offset++];
    }
    return (major: major, value: value, indefinite: false);
  }

  int skipItem([int depth = 0]) {
    if (depth > 128) throw const FormatException('Excessive CBOR nesting');
    final header = readHeader();
    switch (header.major) {
      case 0:
      case 1:
        break;
      case 2:
      case 3:
        if (header.indefinite) {
          while (!isBreak) {
            final chunk = readHeader();
            if (chunk.major != header.major || chunk.indefinite) {
              throw const FormatException('Invalid indefinite CBOR string');
            }
            _skipBytes(chunk.value);
          }
          offset++;
        } else {
          _skipBytes(header.value);
        }
      case 4:
        if (header.indefinite) {
          while (!isBreak) {
            skipItem(depth + 1);
          }
          offset++;
        } else {
          for (var index = 0; index < header.value; index++) {
            skipItem(depth + 1);
          }
        }
      case 5:
        if (header.indefinite) {
          while (!isBreak) {
            skipItem(depth + 1);
            skipItem(depth + 1);
          }
          offset++;
        } else {
          for (var index = 0; index < header.value; index++) {
            skipItem(depth + 1);
            skipItem(depth + 1);
          }
        }
      case 6:
        if (header.indefinite) {
          throw const FormatException('Indefinite CBOR tag');
        }
        skipItem(depth + 1);
      case 7:
        if (header.indefinite) {
          throw const FormatException('Unexpected CBOR break');
        }
    }
    return offset;
  }

  void _skipBytes(int length) {
    if (length < 0 || offset + length > bytes.length) {
      throw const FormatException('Truncated CBOR value');
    }
    offset += length;
  }
}
