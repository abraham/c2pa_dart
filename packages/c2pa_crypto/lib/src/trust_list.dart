import 'dart:convert';
import 'dart:typed_data';

import 'certificate_profile.dart';
import 'path_validation.dart';
import 'x509_certificate.dart';

enum PemDuplicateCertificateHandling { reject, ignore }

final class PemCertificateLimits {
  const PemCertificateLimits({
    this.maxCertificateBytes = 1024 * 1024,
    this.maxCertificates = 1024,
    this.maxBundleBytes = 16 * 1024 * 1024,
  });

  final int maxCertificateBytes;
  final int maxCertificates;
  final int maxBundleBytes;

  void validate() {
    if (maxCertificateBytes < 1 || maxCertificates < 1 || maxBundleBytes < 1) {
      throw const FormatException('PEM limits must be positive');
    }
  }
}

/// Parses a strict PEM certificate bundle without platform-specific APIs.
List<Uint8List> parsePemCertificateBundle(
  String pem, {
  PemCertificateLimits limits = const PemCertificateLimits(),
  PemDuplicateCertificateHandling duplicateHandling =
      PemDuplicateCertificateHandling.reject,
}) {
  limits.validate();
  if (utf8.encode(pem).length > limits.maxBundleBytes) {
    throw const FormatException('PEM certificate bundle exceeds byte limit');
  }
  final normalized = pem.replaceAll('\r\n', '\n');
  if (normalized.contains('\r')) {
    throw const FormatException('PEM bundle contains a lone carriage return');
  }
  const begin = '-----BEGIN CERTIFICATE-----';
  const end = '-----END CERTIFICATE-----';
  final certificates = <Uint8List>[];
  final seen = <String>{};
  var parsedCount = 0;
  var offset = 0;

  while (true) {
    final start = normalized.indexOf(begin, offset);
    if (start < 0) {
      if (normalized.substring(offset).trim().isNotEmpty) {
        throw const FormatException('Unexpected text outside PEM certificate');
      }
      break;
    }
    if (normalized.substring(offset, start).trim().isNotEmpty) {
      throw const FormatException('Unexpected text outside PEM certificate');
    }
    final bodyStart = start + begin.length;
    if (bodyStart >= normalized.length || normalized[bodyStart] != '\n') {
      throw const FormatException('PEM begin marker must end its line');
    }
    final finish = normalized.indexOf(end, bodyStart + 1);
    if (finish < 0) {
      throw const FormatException('Missing PEM certificate end marker');
    }
    final body = normalized.substring(bodyStart + 1, finish);
    if (body.contains(begin)) {
      throw const FormatException('Nested PEM certificate begin marker');
    }
    final compact = _strictBase64Body(body);
    late Uint8List der;
    try {
      der = Uint8List.fromList(base64.decode(compact));
    } on FormatException {
      throw const FormatException('Invalid PEM certificate base64');
    }
    if (base64.encode(der) != compact) {
      throw const FormatException('Non-canonical PEM certificate base64');
    }
    if (der.length > limits.maxCertificateBytes) {
      throw const FormatException('PEM certificate exceeds byte limit');
    }
    parsedCount++;
    if (parsedCount > limits.maxCertificates) {
      throw const FormatException('PEM certificate count exceeds limit');
    }
    X509Certificate.parse(der, allowUnknownCriticalExtensions: true);
    final identity = base64.encode(der);
    if (!seen.add(identity)) {
      if (duplicateHandling == PemDuplicateCertificateHandling.reject) {
        throw const FormatException('Duplicate certificate in PEM bundle');
      }
    } else {
      certificates.add(der);
    }
    offset = finish + end.length;
    if (offset < normalized.length && normalized[offset] != '\n') {
      throw const FormatException('PEM end marker must end its line');
    }
  }
  if (certificates.isEmpty) {
    throw const FormatException('PEM certificate bundle is empty');
  }
  return List.unmodifiable(certificates);
}

/// Encodes DER certificates as a deterministic 64-column PEM bundle.
String encodePemCertificateBundle(
  Iterable<List<int>> certificates, {
  PemCertificateLimits limits = const PemCertificateLimits(),
  PemDuplicateCertificateHandling duplicateHandling =
      PemDuplicateCertificateHandling.reject,
}) {
  limits.validate();
  final output = StringBuffer();
  final seen = <String>{};
  var count = 0;
  var inputCount = 0;
  for (final source in certificates) {
    inputCount++;
    if (inputCount > limits.maxCertificates) {
      throw const FormatException('PEM certificate count exceeds limit');
    }
    final der = Uint8List.fromList(source);
    if (der.length > limits.maxCertificateBytes) {
      throw const FormatException('Certificate exceeds PEM byte limit');
    }
    X509Certificate.parse(der, allowUnknownCriticalExtensions: true);
    final encoded = base64.encode(der);
    if (!seen.add(encoded)) {
      if (duplicateHandling == PemDuplicateCertificateHandling.reject) {
        throw const FormatException('Duplicate certificate in PEM bundle');
      }
      continue;
    }
    if (output.isNotEmpty) {
      output.writeln();
    }
    output.writeln('-----BEGIN CERTIFICATE-----');
    for (var offset = 0; offset < encoded.length; offset += 64) {
      final end = (offset + 64).clamp(0, encoded.length);
      output.writeln(encoded.substring(offset, end));
    }
    output.writeln('-----END CERTIFICATE-----');
    count++;
  }
  if (count == 0) {
    throw const FormatException('Cannot encode an empty certificate bundle');
  }
  final pem = output.toString();
  if (utf8.encode(pem).length > limits.maxBundleBytes) {
    throw const FormatException('PEM certificate bundle exceeds byte limit');
  }
  return pem;
}

abstract interface class PlatformTrustAnchorProvider {
  Future<Iterable<List<int>>> loadTrustAnchors();
}

enum TrustAnchorMergePrecedence { pemThenPlatform, platformThenPem }

final class TrustAnchorProviderException implements Exception {
  const TrustAnchorProviderException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() => 'TrustAnchorProviderException: $message';
}

final class C2paTrustPolicies {
  const C2paTrustPolicies({required this.signer, required this.tsa});

  final TrustPolicy signer;
  final TrustPolicy tsa;
}

/// Builds separate immutable signer and TSA policies from explicit PEM lists.
Future<C2paTrustPolicies> buildC2paTrustPolicies({
  required Iterable<String> signerPemBundles,
  required Iterable<String> tsaPemBundles,
  Iterable<List<int>> intermediates = const [],
  Iterable<List<int>> allowedEndEntitySha256Hashes = const [],
  Set<String> allowedSignerEkuOids = const {
    ExtendedKeyUsageOids.codeSigning,
    ExtendedKeyUsageOids.emailProtection,
    ExtendedKeyUsageOids.documentSigning,
  },
  Set<String> requiredCertificatePolicyOids = const {},
  DateTime? evaluationTime,
  int maxDepth = 8,
  PemCertificateLimits limits = const PemCertificateLimits(),
  PlatformTrustAnchorProvider? signerPlatformProvider,
  PlatformTrustAnchorProvider? tsaPlatformProvider,
  TrustAnchorMergePrecedence? platformMergePrecedence,
}) async {
  if ((signerPlatformProvider != null || tsaPlatformProvider != null) &&
      platformMergePrecedence == null) {
    throw ArgumentError(
      'platformMergePrecedence is required when a platform provider is used',
    );
  }
  if (signerPlatformProvider == null &&
      tsaPlatformProvider == null &&
      platformMergePrecedence != null) {
    throw ArgumentError('platformMergePrecedence requires a platform provider');
  }

  final signerPem = _parsePemLists(signerPemBundles, limits);
  final tsaPem = _parsePemLists(tsaPemBundles, limits);
  final signerPlatform = await _loadPlatformAnchors(
    signerPlatformProvider,
    limits,
    'signer',
  );
  final tsaPlatform = await _loadPlatformAnchors(
    tsaPlatformProvider,
    limits,
    'TSA',
  );
  final signerAnchors = _mergeAnchors(
    signerPem,
    signerPlatform,
    platformMergePrecedence,
  );
  final tsaAnchors = _mergeAnchors(
    tsaPem,
    tsaPlatform,
    platformMergePrecedence,
  );
  if (signerAnchors.isEmpty || tsaAnchors.isEmpty) {
    throw const FormatException(
      'Signer and TSA trust lists must each contain a certificate',
    );
  }

  return C2paTrustPolicies(
    signer: TrustPolicy(
      trustAnchors: signerAnchors,
      intermediates: intermediates,
      allowedEndEntitySha256Hashes: allowedEndEntitySha256Hashes,
      allowedEkuOids: allowedSignerEkuOids,
      requiredCertificatePolicyOids: requiredCertificatePolicyOids,
      evaluationTime: evaluationTime,
      maxDepth: maxDepth,
    ),
    tsa: TrustPolicy(
      trustAnchors: tsaAnchors,
      intermediates: intermediates,
      evaluationTime: evaluationTime,
      maxDepth: maxDepth,
    ),
  );
}

List<Uint8List> _parsePemLists(
  Iterable<String> bundles,
  PemCertificateLimits limits,
) {
  final result = <Uint8List>[];
  final seen = <String>{};
  var totalBytes = 0;
  var totalCertificates = 0;
  for (final bundle in bundles) {
    totalBytes += utf8.encode(bundle).length;
    if (totalBytes > limits.maxBundleBytes) {
      throw const FormatException('Combined PEM lists exceed byte limit');
    }
    final parsed = parsePemCertificateBundle(
      bundle,
      limits: limits,
      duplicateHandling: PemDuplicateCertificateHandling.ignore,
    );
    totalCertificates += parsed.length;
    if (totalCertificates > limits.maxCertificates) {
      throw const FormatException('Combined PEM lists exceed count limit');
    }
    for (final certificate in parsed) {
      if (seen.add(base64.encode(certificate))) {
        result.add(certificate);
      }
    }
  }
  return result;
}

Future<List<Uint8List>> _loadPlatformAnchors(
  PlatformTrustAnchorProvider? provider,
  PemCertificateLimits limits,
  String purpose,
) async {
  if (provider == null) {
    return const [];
  }
  try {
    final anchors = await provider.loadTrustAnchors();
    final result = <Uint8List>[];
    var totalBytes = 0;
    for (final source in anchors) {
      if (result.length >= limits.maxCertificates) {
        throw const FormatException(
          'Platform trust-anchor count exceeds limit',
        );
      }
      final der = Uint8List.fromList(source);
      totalBytes += der.length;
      if (der.length > limits.maxCertificateBytes ||
          totalBytes > limits.maxBundleBytes) {
        throw const FormatException('Platform trust-anchor bytes exceed limit');
      }
      X509Certificate.parse(der, allowUnknownCriticalExtensions: true);
      result.add(der);
    }
    return result;
  } catch (error) {
    throw TrustAnchorProviderException(
      'Failed to load $purpose platform trust anchors',
      cause: error,
    );
  }
}

List<Uint8List> _mergeAnchors(
  List<Uint8List> pem,
  List<Uint8List> platform,
  TrustAnchorMergePrecedence? precedence,
) {
  final ordered = switch (precedence) {
    TrustAnchorMergePrecedence.platformThenPem => [...platform, ...pem],
    _ => [...pem, ...platform],
  };
  final result = <Uint8List>[];
  final seen = <String>{};
  for (final certificate in ordered) {
    if (seen.add(base64.encode(certificate))) {
      result.add(certificate);
    }
  }
  return result;
}

String _strictBase64Body(String body) {
  final lines = body.split('\n');
  final compact = StringBuffer();
  for (final line in lines) {
    if (line.isEmpty) {
      continue;
    }
    if (line.trim() != line ||
        !RegExp(r'^[A-Za-z0-9+/]+={0,2}$').hasMatch(line)) {
      throw const FormatException('Invalid PEM certificate base64 line');
    }
    compact.write(line);
  }
  final value = compact.toString();
  if (value.isEmpty || value.length % 4 != 0) {
    throw const FormatException('Invalid PEM certificate base64 length');
  }
  return value;
}
