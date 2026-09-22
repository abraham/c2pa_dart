import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:pointycastle/export.dart' as pc;

import 'byte_compare.dart';
import 'certificate_profile.dart';
import 'der_reader.dart';
import 'der_writer.dart';
import 'ecdsa_signature.dart';
import 'hash_algorithm.dart';
import 'key_encoding.dart' as keyenc;
import 'signing_algorithm.dart';
import 'x509_certificate.dart';

/// Immutable inputs controlling certificate path construction and validation.
final class TrustPolicy {
  /// Creates an immutable RFC 5280 path-validation policy.
  ///
  /// Throws [ArgumentError] if DER inputs are empty, hashes are not 32
  /// bytes, byte values are outside `0..255`, or [maxDepth] is less than 1.
  TrustPolicy({
    required Iterable<List<int>> trustAnchors,
    Iterable<List<int>> intermediates = const [],
    Iterable<List<int>> allowedEndEntitySha256Hashes = const [],
    Set<String> allowedEkuOids = const {
      ExtendedKeyUsageOids.codeSigning,
      ExtendedKeyUsageOids.emailProtection,
      ExtendedKeyUsageOids.documentSigning,
    },
    Set<String> requiredCertificatePolicyOids = const {},
    DateTime? evaluationTime,
    this.maxDepth = 8,
  }) : _trustAnchors = _copyDerList(trustAnchors, 'trustAnchors'),
       _intermediates = _copyDerList(intermediates, 'intermediates'),
       _allowedEndEntitySha256Hashes = _copyHashes(
         allowedEndEntitySha256Hashes,
       ),
       allowedEkuOids = Set.unmodifiable(allowedEkuOids),
       requiredCertificatePolicyOids = Set.unmodifiable(
         requiredCertificatePolicyOids,
       ),
       evaluationTime = (evaluationTime ?? DateTime.now()).toUtc() {
    if (maxDepth < 1) {
      throw ArgumentError.value(maxDepth, 'maxDepth', 'Must be positive');
    }
  }

  final List<Uint8List> _trustAnchors;
  final List<Uint8List> _intermediates;
  final List<Uint8List> _allowedEndEntitySha256Hashes;

  /// The signer EKU OIDs accepted for C2PA leaf certificates.
  final Set<String> allowedEkuOids;

  /// The certificate policy OIDs required along the completed path.
  final Set<String> requiredCertificatePolicyOids;

  /// The UTC instant used for certificate validity checks.
  final DateTime evaluationTime;

  /// The maximum number of certificates allowed in a candidate path.
  final int maxDepth;

  /// Defensive copies of DER-encoded trust anchors.
  List<Uint8List> get trustAnchors =>
      _trustAnchors.map(Uint8List.fromList).toList(growable: false);

  /// Defensive copies of DER-encoded intermediate certificates.
  List<Uint8List> get intermediates =>
      _intermediates.map(Uint8List.fromList).toList(growable: false);

  /// Defensive copies of directly trusted leaf SHA-256 hashes.
  List<Uint8List> get allowedEndEntitySha256Hashes =>
      _allowedEndEntitySha256Hashes
          .map(Uint8List.fromList)
          .toList(growable: false);
}

/// The trust state produced by certificate path validation.
enum CertificatePathStatus {
  /// A single valid path reached a configured trust anchor or direct hash.
  trusted,

  /// The leaf or a candidate path failed validation checks.
  invalid,

  /// No valid path reached a configured trust anchor.
  untrusted,

  /// More than one valid path reached configured trust anchors.
  ambiguous,
}

/// Machine-readable RFC 5280 certificate path validation issue codes.
enum CertificatePathIssueCode {
  /// A certificate DER input could not be parsed.
  malformedCertificate,

  /// The leaf certificate failed its required C2PA or TSA profile.
  leafProfile,

  /// A certificate is not valid at the policy evaluation time.
  certificateNotYetValid,

  /// A certificate has expired at the policy evaluation time.
  certificateExpired,

  /// A critical extension is present but unsupported.
  unsupportedCriticalExtension,

  /// No candidate issuer matched the certificate issuer name and AKI.
  issuerNotFound,

  /// An issuer candidate is not marked as a CA certificate.
  issuerNotCa,

  /// An issuer KeyUsage extension does not permit `keyCertSign`.
  issuerMissingKeyCertSign,

  /// A BasicConstraints path length constraint is exceeded.
  pathLengthExceeded,

  /// A subject name falls within an excluded name subtree.
  nameConstraintExcluded,

  /// A subject name is outside all permitted name subtrees.
  nameConstraintNotPermitted,

  /// RFC 5280 policy processing requires an explicit policy.
  explicitPolicyRequired,

  /// The path does not satisfy the active certificate policy set.
  certificatePolicyViolation,

  /// Policy mappings appear after policy mapping has been inhibited.
  policyMappingInhibited,

  /// The only matching policy is `anyPolicy` after it was inhibited.
  anyPolicyInhibited,

  /// A certificate signature failed verification or was malformed.
  badCertificateSignature,

  /// A certificate signature algorithm is not supported.
  unsupportedSignatureAlgorithm,

  /// Path construction encountered a repeated certificate.
  loopDetected,

  /// Path construction exceeded [TrustPolicy.maxDepth].
  maxDepthExceeded,

  /// More than one valid path reached a trust anchor.
  ambiguousPath,
}

/// One issue found while constructing or validating a certificate path.
final class CertificatePathIssue {
  /// Creates a path-validation issue with optional path depth.
  const CertificatePathIssue(this.code, this.message, {this.certificateDepth});

  /// The machine-readable path-validation failure code.
  final CertificatePathIssueCode code;

  /// The human-readable path-validation failure detail.
  final String message;

  /// The zero-based leaf-to-anchor path depth, or `null` if not specific.
  final int? certificateDepth;
}

/// Structured result of certificate path construction and validation.
final class CertificatePathValidationResult {
  /// Creates a certificate path validation result.
  CertificatePathValidationResult({
    required this.status,
    required List<X509Certificate> path,
    required List<CertificatePathIssue> issues,
    required this.directlyAllowedEndEntity,
  }) : path = List.unmodifiable(path),
       issues = List.unmodifiable(issues);

  /// The overall trust status for the attempted path validation.
  final CertificatePathStatus status;

  /// The validated leaf-to-anchor path, or partial leaf-only path on failure.
  final List<X509Certificate> path;

  /// The immutable path-validation issues collected during evaluation.
  final List<CertificatePathIssue> issues;

  /// Whether trust came from an allowed leaf SHA-256 hash instead of a path.
  final bool directlyAllowedEndEntity;

  /// Whether [status] is [CertificatePathStatus.trusted].
  bool get isTrusted => status == CertificatePathStatus.trusted;
}

/// Builds and validates a C2PA signer certificate path.
Future<CertificatePathValidationResult> validateCertificatePath(
  List<int> leafDer, {
  required SigningAlgorithm algorithm,
  required TrustPolicy policy,
}) => _validateCertificatePath(
  leafDer,
  policy: policy,
  validateLeaf: (leaf) => validateC2paSignerCertificate(
    leaf,
    algorithm: algorithm,
    atTime: policy.evaluationTime,
    allowedExtendedKeyUsageOids: policy.allowedEkuOids,
  ),
);

/// Builds and validates an RFC 3161 TSA certificate path.
Future<CertificatePathValidationResult> validateTsaCertificatePath(
  List<int> leafDer, {
  required SigningAlgorithm algorithm,
  required TrustPolicy policy,
}) => _validateCertificatePath(
  leafDer,
  policy: policy,
  validateLeaf: (leaf) => validateTsaCertificate(
    leaf,
    algorithm: algorithm,
    atTime: policy.evaluationTime,
  ),
);

/// Builds and validates a delegated OCSP responder certificate path.
Future<CertificatePathValidationResult> validateOcspResponderCertificatePath(
  List<int> leafDer, {
  required SigningAlgorithm algorithm,
  required TrustPolicy policy,
}) => _validateCertificatePath(
  leafDer,
  policy: policy,
  validateLeaf: (leaf) => validateOcspResponderCertificate(
    leaf,
    algorithm: algorithm,
    atTime: policy.evaluationTime,
  ),
);

/// Builds and validates a CA certificate path without applying a leaf profile.
Future<CertificatePathValidationResult> validateCertificateAuthorityPath(
  List<int> certificateDer, {
  required TrustPolicy policy,
}) => _validateCertificatePath(
  certificateDer,
  policy: policy,
  validateLeaf: (certificate) {
    final issues = <CertificateProfileIssue>[];
    if (policy.evaluationTime.isBefore(certificate.notBefore)) {
      issues.add(
        const CertificateProfileIssue(
          CertificateProfileIssueCode.notYetValid,
          'Certificate authority is not yet valid',
        ),
      );
    }
    if (policy.evaluationTime.isAfter(certificate.notAfter)) {
      issues.add(
        const CertificateProfileIssue(
          CertificateProfileIssueCode.expired,
          'Certificate authority has expired',
        ),
      );
    }
    if (certificate.basicConstraints?.isCa != true) {
      issues.add(
        const CertificateProfileIssue(
          CertificateProfileIssueCode.caCertificate,
          'Certificate is not a certificate authority',
        ),
      );
    }
    if (certificate.keyUsage != null &&
        !certificate.keyUsage!.contains(X509KeyUsage.keyCertSign)) {
      issues.add(
        const CertificateProfileIssue(
          CertificateProfileIssueCode.missingKeyUsage,
          'Certificate authority KeyUsage must permit keyCertSign',
        ),
      );
    }
    if (certificate.criticalUnknownExtensions.isNotEmpty) {
      issues.add(
        const CertificateProfileIssue(
          CertificateProfileIssueCode.unsupportedCriticalExtension,
          'Certificate authority contains an unsupported critical extension',
        ),
      );
    }
    return issues;
  },
);

Future<CertificatePathValidationResult> _validateCertificatePath(
  List<int> leafDer, {
  required TrustPolicy policy,
  required List<CertificateProfileIssue> Function(X509Certificate) validateLeaf,
}) async {
  late X509Certificate leaf;
  try {
    leaf = X509Certificate.parse(leafDer, allowUnknownCriticalExtensions: true);
  } on FormatException catch (error) {
    return CertificatePathValidationResult(
      status: CertificatePathStatus.invalid,
      path: const [],
      issues: [
        CertificatePathIssue(
          CertificatePathIssueCode.malformedCertificate,
          error.message,
          certificateDepth: 0,
        ),
      ],
      directlyAllowedEndEntity: false,
    );
  }

  final leafIssues = validateLeaf(leaf);
  if (leafIssues.isNotEmpty) {
    return CertificatePathValidationResult(
      status: CertificatePathStatus.invalid,
      path: [leaf],
      issues: leafIssues
          .map(
            (issue) => CertificatePathIssue(
              switch (issue.code) {
                CertificateProfileIssueCode.notYetValid =>
                  CertificatePathIssueCode.certificateNotYetValid,
                CertificateProfileIssueCode.expired =>
                  CertificatePathIssueCode.certificateExpired,
                CertificateProfileIssueCode.unsupportedCriticalExtension =>
                  CertificatePathIssueCode.unsupportedCriticalExtension,
                _ => CertificatePathIssueCode.leafProfile,
              },
              issue.message,
              certificateDepth: 0,
            ),
          )
          .toList(),
      directlyAllowedEndEntity: false,
    );
  }

  final leafHash = await HashAlgorithm.sha256.digest(leaf.der);
  if (policy._allowedEndEntitySha256Hashes.any(
    (allowed) => constantTimeBytesEqual(allowed, leafHash),
  )) {
    if (policy.requiredCertificatePolicyOids.isNotEmpty &&
        !_certificatePoliciesMatch(
          leaf.certificatePolicies,
          policy.requiredCertificatePolicyOids,
          allowAnyPolicy: true,
        )) {
      return CertificatePathValidationResult(
        status: CertificatePathStatus.invalid,
        path: [leaf],
        issues: const [
          CertificatePathIssue(
            CertificatePathIssueCode.certificatePolicyViolation,
            'Leaf certificate does not satisfy the required policy set',
            certificateDepth: 0,
          ),
        ],
        directlyAllowedEndEntity: false,
      );
    }
    return CertificatePathValidationResult(
      status: CertificatePathStatus.trusted,
      path: [leaf],
      issues: const [],
      directlyAllowedEndEntity: true,
    );
  }

  final anchors = <X509Certificate>[];
  final candidates = <X509Certificate>[];
  try {
    for (final der in policy._trustAnchors) {
      anchors.add(
        X509Certificate.parse(der, allowUnknownCriticalExtensions: true),
      );
    }
    for (final der in policy._intermediates) {
      candidates.add(
        X509Certificate.parse(der, allowUnknownCriticalExtensions: true),
      );
    }
  } on FormatException catch (error) {
    return CertificatePathValidationResult(
      status: CertificatePathStatus.invalid,
      path: [leaf],
      issues: [
        CertificatePathIssue(
          CertificatePathIssueCode.malformedCertificate,
          'Malformed trust-policy certificate: ${error.message}',
        ),
      ],
      directlyAllowedEndEntity: false,
    );
  }
  candidates.addAll(anchors);
  final uniqueCandidates = <String, X509Certificate>{};
  for (final candidate in candidates) {
    uniqueCandidates.putIfAbsent(candidate.der.join(','), () => candidate);
  }

  final builder = _PathBuilder(
    anchors: anchors,
    candidates: uniqueCandidates.values.toList(growable: false),
    evaluationTime: policy.evaluationTime,
    maxDepth: policy.maxDepth,
    requiredCertificatePolicyOids: policy.requiredCertificatePolicyOids,
  );
  final paths = await builder.build(leaf);
  if (paths.length == 1) {
    return CertificatePathValidationResult(
      status: CertificatePathStatus.trusted,
      path: paths.single,
      issues: const [],
      directlyAllowedEndEntity: false,
    );
  }
  if (paths.length > 1) {
    return CertificatePathValidationResult(
      status: CertificatePathStatus.ambiguous,
      path: const [],
      issues: const [
        CertificatePathIssue(
          CertificatePathIssueCode.ambiguousPath,
          'More than one valid path reaches a trust anchor',
        ),
      ],
      directlyAllowedEndEntity: false,
    );
  }
  return CertificatePathValidationResult(
    status: builder.sawInvalidPath
        ? CertificatePathStatus.invalid
        : CertificatePathStatus.untrusted,
    path: [leaf],
    issues: builder.issues.isEmpty
        ? const [
            CertificatePathIssue(
              CertificatePathIssueCode.issuerNotFound,
              'No path reaches a configured trust anchor',
            ),
          ]
        : builder.issues,
    directlyAllowedEndEntity: false,
  );
}

final class _PathBuilder {
  _PathBuilder({
    required this.anchors,
    required this.candidates,
    required this.evaluationTime,
    required this.maxDepth,
    required this.requiredCertificatePolicyOids,
  });

  final List<X509Certificate> anchors;
  final List<X509Certificate> candidates;
  final DateTime evaluationTime;
  final int maxDepth;
  final Set<String> requiredCertificatePolicyOids;
  final List<CertificatePathIssue> issues = [];
  bool sawInvalidPath = false;

  Future<List<List<X509Certificate>>> build(X509Certificate leaf) async {
    final results = <List<X509Certificate>>[];
    await _walk([leaf], results);
    return results;
  }

  Future<void> _walk(
    List<X509Certificate> path,
    List<List<X509Certificate>> results,
  ) async {
    final current = path.last;
    if (_isAnchor(current)) {
      if (bytesEqual(current.subject.der, current.issuer.der)) {
        try {
          if (!await _verifyCertificateSignature(current, current)) {
            issues.add(
              CertificatePathIssue(
                CertificatePathIssueCode.badCertificateSignature,
                'Self-signed trust-anchor signature verification failed',
                certificateDepth: path.length - 1,
              ),
            );
            sawInvalidPath = true;
            return;
          }
        } on UnsupportedError catch (error) {
          issues.add(
            CertificatePathIssue(
              CertificatePathIssueCode.unsupportedSignatureAlgorithm,
              error.message ?? error.toString(),
              certificateDepth: path.length - 1,
            ),
          );
          sawInvalidPath = true;
          return;
        } on FormatException catch (error) {
          issues.add(
            CertificatePathIssue(
              CertificatePathIssueCode.badCertificateSignature,
              'Unable to verify self-signed trust anchor: $error',
              certificateDepth: path.length - 1,
            ),
          );
          sawInvalidPath = true;
          return;
        }
      }
      final completedIssue = _validateCompletedPath(path);
      if (completedIssue != null) {
        issues.add(completedIssue);
        sawInvalidPath = true;
        return;
      }
      results.add(List.unmodifiable(path));
      return;
    }
    if (path.length >= maxDepth) {
      issues.add(
        CertificatePathIssue(
          CertificatePathIssueCode.maxDepthExceeded,
          'Certificate path exceeds maximum depth $maxDepth',
          certificateDepth: path.length - 1,
        ),
      );
      sawInvalidPath = true;
      return;
    }

    var issuers = candidates
        .where(
          (candidate) => bytesEqual(candidate.subject.der, current.issuer.der),
        )
        .toList();
    final authorityKeyIdentifier = current.authorityKeyIdentifier;
    if (authorityKeyIdentifier != null) {
      issuers = issuers.where((candidate) {
        final subjectKeyIdentifier = candidate.subjectKeyIdentifier;
        return subjectKeyIdentifier == null ||
            bytesEqual(subjectKeyIdentifier, authorityKeyIdentifier);
      }).toList();
    }
    issuers.sort((left, right) => compareBytes(left.der, right.der));
    // A self-issued certificate is its own issuer candidate. It terminates the
    // path rather than extending it: if it were a configured trust anchor the
    // walk would already have stopped above, so reaching here means the chain
    // ends at an anchor this policy does not trust. Treating that as a cycle
    // reported `loopDetected`, which marks the whole path invalid instead of
    // merely untrusted — enough to make callers discard an otherwise valid
    // RFC 3161 timestamp whose TSA ships its own root in the CMS certificate
    // set. Genuine multi-certificate cycles are still caught below.
    issuers = issuers
        .where((candidate) => !bytesEqual(candidate.der, current.der))
        .toList();
    if (issuers.isEmpty) {
      issues.add(
        CertificatePathIssue(
          CertificatePathIssueCode.issuerNotFound,
          'No issuer candidate matches the certificate issuer',
          certificateDepth: path.length - 1,
        ),
      );
      return;
    }

    for (final issuer in issuers) {
      if (path.any((certificate) => bytesEqual(certificate.der, issuer.der))) {
        issues.add(
          CertificatePathIssue(
            CertificatePathIssueCode.loopDetected,
            'Certificate path contains a loop',
            certificateDepth: path.length,
          ),
        );
        sawInvalidPath = true;
        continue;
      }
      final issuerIssue = _validateIssuer(issuer, path);
      if (issuerIssue != null) {
        issues.add(issuerIssue);
        sawInvalidPath = true;
        continue;
      }
      late bool validSignature;
      try {
        validSignature = await _verifyCertificateSignature(current, issuer);
      } on UnsupportedError catch (error) {
        issues.add(
          CertificatePathIssue(
            CertificatePathIssueCode.unsupportedSignatureAlgorithm,
            error.message ?? error.toString(),
            certificateDepth: path.length - 1,
          ),
        );
        sawInvalidPath = true;
        continue;
      } on FormatException catch (error) {
        issues.add(
          CertificatePathIssue(
            CertificatePathIssueCode.badCertificateSignature,
            error.message,
            certificateDepth: path.length - 1,
          ),
        );
        sawInvalidPath = true;
        continue;
      }
      if (!validSignature) {
        issues.add(
          CertificatePathIssue(
            CertificatePathIssueCode.badCertificateSignature,
            'Certificate signature verification failed',
            certificateDepth: path.length - 1,
          ),
        );
        sawInvalidPath = true;
        continue;
      }
      await _walk([...path, issuer], results);
    }
  }

  CertificatePathIssue? _validateIssuer(
    X509Certificate issuer,
    List<X509Certificate> path,
  ) {
    final depth = path.length;
    if (evaluationTime.isBefore(issuer.notBefore)) {
      return CertificatePathIssue(
        CertificatePathIssueCode.certificateNotYetValid,
        'Issuer certificate is not yet valid',
        certificateDepth: depth,
      );
    }
    if (evaluationTime.isAfter(issuer.notAfter)) {
      return CertificatePathIssue(
        CertificatePathIssueCode.certificateExpired,
        'Issuer certificate has expired',
        certificateDepth: depth,
      );
    }
    if (issuer.criticalUnknownExtensions.isNotEmpty) {
      return CertificatePathIssue(
        CertificatePathIssueCode.unsupportedCriticalExtension,
        _criticalExtensionMessage(issuer.criticalUnknownExtensions.first.oid),
        certificateDepth: depth,
      );
    }
    if (issuer.basicConstraints?.isCa != true) {
      return CertificatePathIssue(
        CertificatePathIssueCode.issuerNotCa,
        'Issuer certificate is not a CA',
        certificateDepth: depth,
      );
    }
    if (issuer.keyUsage != null &&
        !issuer.keyUsage!.contains(X509KeyUsage.keyCertSign)) {
      return CertificatePathIssue(
        CertificatePathIssueCode.issuerMissingKeyCertSign,
        'Issuer KeyUsage does not permit keyCertSign',
        certificateDepth: depth,
      );
    }
    final pathLength = issuer.basicConstraints!.pathLength;
    final caCertificatesBelow = path
        .skip(1)
        .where(
          (certificate) =>
              certificate.basicConstraints?.isCa == true &&
              !_isSelfIssued(certificate),
        )
        .length;
    if (pathLength != null && caCertificatesBelow > pathLength) {
      return CertificatePathIssue(
        CertificatePathIssueCode.pathLengthExceeded,
        'Issuer pathLenConstraint is exceeded',
        certificateDepth: depth,
      );
    }
    return null;
  }

  CertificatePathIssue? _validateCompletedPath(
    List<X509Certificate> leafToAnchor,
  ) {
    final nameIssue = _validateNameConstraints(leafToAnchor);
    if (nameIssue != null) {
      return nameIssue;
    }
    return _validateCertificatePolicies(
      leafToAnchor,
      requiredCertificatePolicyOids,
    );
  }

  bool _isAnchor(X509Certificate certificate) =>
      anchors.any((anchor) => bytesEqual(anchor.der, certificate.der));
}

CertificatePathIssue? _validateNameConstraints(
  List<X509Certificate> leafToAnchor,
) {
  for (var issuerDepth = 1; issuerDepth < leafToAnchor.length; issuerDepth++) {
    final constraints = leafToAnchor[issuerDepth].nameConstraints;
    if (constraints == null) {
      continue;
    }
    for (var subjectDepth = 0; subjectDepth < issuerDepth; subjectDepth++) {
      final subject = leafToAnchor[subjectDepth];
      if (subjectDepth != 0 && _isSelfIssued(subject)) {
        continue;
      }
      final names = <X509GeneralName>[
        ...subject.subjectAlternativeNames,
        ...subject.subject.attributes
            .where((attribute) => attribute.oid == '1.2.840.113549.1.9.1')
            .map(
              (attribute) => X509GeneralName(
                X509GeneralNameType.email,
                text: attribute.value.toLowerCase(),
              ),
            ),
      ];
      for (final name in names) {
        final excluded = constraints.excluded
            .where((constraint) => constraint.type == name.type)
            .any((constraint) => _nameMatchesConstraint(name, constraint));
        if (excluded) {
          return CertificatePathIssue(
            CertificatePathIssueCode.nameConstraintExcluded,
            '${name.type.name} name is within an excluded subtree',
            certificateDepth: subjectDepth,
          );
        }
        final permitted = constraints.permitted
            .where((constraint) => constraint.type == name.type)
            .toList();
        if (permitted.isNotEmpty &&
            !permitted.any(
              (constraint) => _nameMatchesConstraint(name, constraint),
            )) {
          return CertificatePathIssue(
            CertificatePathIssueCode.nameConstraintNotPermitted,
            '${name.type.name} name is outside all permitted subtrees',
            certificateDepth: subjectDepth,
          );
        }
      }
    }
  }
  return null;
}

CertificatePathIssue? _validateCertificatePolicies(
  List<X509Certificate> leafToAnchor,
  Set<String> requiredPolicies,
) {
  final rootToLeaf = leafToAnchor.reversed.toList(growable: false);
  var explicitPolicy = rootToLeaf.length + 1;
  var inhibitAnyPolicy = rootToLeaf.length + 1;
  var inhibitPolicyMapping = rootToLeaf.length + 1;
  final activePolicies = <String>{...requiredPolicies};

  for (var index = 1; index < rootToLeaf.length; index++) {
    final certificate = rootToLeaf[index];
    final isLeaf = index == rootToLeaf.length - 1;
    final hasCaOnlyPolicyExtension =
        certificate.nameConstraints != null ||
        certificate.policyMappings != null ||
        certificate.policyConstraints != null ||
        certificate.inhibitAnyPolicy != null;
    if (hasCaOnlyPolicyExtension &&
        certificate.basicConstraints?.isCa != true) {
      return CertificatePathIssue(
        CertificatePathIssueCode.certificatePolicyViolation,
        'Path and policy constraint extensions require a CA certificate',
        certificateDepth: leafToAnchor.length - 1 - index,
      );
    }
    if (!_isSelfIssued(certificate) || isLeaf) {
      if (explicitPolicy > 0) explicitPolicy--;
      if (inhibitAnyPolicy > 0) inhibitAnyPolicy--;
      if (inhibitPolicyMapping > 0) inhibitPolicyMapping--;
    }

    final policies = certificate.certificatePolicies;
    if (explicitPolicy == 0 && (policies == null || policies.isEmpty)) {
      return CertificatePathIssue(
        CertificatePathIssueCode.explicitPolicyRequired,
        'Certificate policy processing requires an explicit policy',
        certificateDepth: leafToAnchor.length - 1 - index,
      );
    }
    if (policies != null) {
      final hasAnyPolicy = policies.contains('2.5.29.32.0');
      if (hasAnyPolicy &&
          inhibitAnyPolicy == 0 &&
          policies.every((policy) => policy == '2.5.29.32.0')) {
        return CertificatePathIssue(
          CertificatePathIssueCode.anyPolicyInhibited,
          'anyPolicy is inhibited for this certificate',
          certificateDepth: leafToAnchor.length - 1 - index,
        );
      }
      if (activePolicies.isNotEmpty &&
          !_certificatePoliciesMatch(
            policies,
            activePolicies,
            allowAnyPolicy: inhibitAnyPolicy > 0,
          )) {
        return CertificatePathIssue(
          CertificatePathIssueCode.certificatePolicyViolation,
          'Certificate does not satisfy the active policy set',
          certificateDepth: leafToAnchor.length - 1 - index,
        );
      }
    } else if (activePolicies.isNotEmpty) {
      return CertificatePathIssue(
        CertificatePathIssueCode.certificatePolicyViolation,
        'Certificate does not contain a required certificate policy',
        certificateDepth: leafToAnchor.length - 1 - index,
      );
    }

    final mappings = certificate.policyMappings;
    if (mappings != null && mappings.isNotEmpty) {
      if (inhibitPolicyMapping == 0) {
        return CertificatePathIssue(
          CertificatePathIssueCode.policyMappingInhibited,
          'Certificate policy mappings are inhibited',
          certificateDepth: leafToAnchor.length - 1 - index,
        );
      }
      for (final mapping in mappings) {
        if (activePolicies.contains(mapping.issuerDomainPolicy)) {
          activePolicies.add(mapping.subjectDomainPolicy);
        }
      }
    }

    final constraints = certificate.policyConstraints;
    if (constraints?.requireExplicitPolicy != null) {
      explicitPolicy = _minimum(
        explicitPolicy,
        constraints!.requireExplicitPolicy!,
      );
    }
    if (constraints?.inhibitPolicyMapping != null) {
      inhibitPolicyMapping = _minimum(
        inhibitPolicyMapping,
        constraints!.inhibitPolicyMapping!,
      );
    }
    if (certificate.inhibitAnyPolicy != null) {
      inhibitAnyPolicy = _minimum(
        inhibitAnyPolicy,
        certificate.inhibitAnyPolicy!,
      );
    }
  }
  return null;
}

bool _certificatePoliciesMatch(
  List<String>? policies,
  Set<String> required, {
  required bool allowAnyPolicy,
}) =>
    policies != null &&
    (policies.any(required.contains) ||
        (allowAnyPolicy && policies.contains('2.5.29.32.0')));

bool _nameMatchesConstraint(
  X509GeneralName name,
  X509NameConstraint constraint,
) {
  switch (name.type) {
    case X509GeneralNameType.dns:
      var dns = name.text!.toLowerCase();
      if (dns.startsWith('*.')) {
        dns = dns.substring(2);
      }
      return _domainMatches(dns, constraint.text!);
    case X509GeneralNameType.email:
      final email = name.text!.toLowerCase();
      final expected = constraint.text!.toLowerCase();
      if (expected.contains('@')) {
        return email == expected;
      }
      final separator = email.lastIndexOf('@');
      if (separator < 0) {
        return false;
      }
      final domain = email.substring(separator + 1);
      return expected.startsWith('.')
          ? _subdomainMatches(domain, expected)
          : domain == expected;
    case X509GeneralNameType.uri:
      final uri = Uri.tryParse(name.text!);
      if (uri == null || uri.host.isEmpty) {
        return false;
      }
      final expected = constraint.text!;
      final host = uri.host.toLowerCase();
      return expected.startsWith('.')
          ? _subdomainMatches(host, expected)
          : host == expected;
    case X509GeneralNameType.ipAddress:
      final address = name.bytes!;
      final base = constraint.address!;
      final mask = constraint.mask!;
      if (address.length != base.length) {
        return false;
      }
      var difference = 0;
      for (var index = 0; index < address.length; index++) {
        difference |= (address[index] & mask[index]) ^ base[index];
      }
      return difference == 0;
  }
}

bool _domainMatches(String name, String constraint) {
  final normalized = constraint.toLowerCase();
  if (normalized.startsWith('.')) {
    return _subdomainMatches(name, normalized);
  }
  return name == normalized || name.endsWith('.$normalized');
}

bool _subdomainMatches(String name, String constraint) =>
    name.length > constraint.length && name.endsWith(constraint);

bool _isSelfIssued(X509Certificate certificate) =>
    bytesEqual(certificate.subject.der, certificate.issuer.der);

int _minimum(int left, int right) => left < right ? left : right;

Future<bool> _verifyCertificateSignature(
  X509Certificate certificate,
  X509Certificate issuer,
) => verifySignatureWithCertificatePublicKey(
  certificate: issuer,
  signatureAlgorithm: certificate.signatureAlgorithm,
  data: certificate.tbsCertificateDer,
  signature: certificate.signature,
);

/// Verifies a signature using an X.509 certificate public key.
///
/// This supports the RSA PKCS#1 v1.5, RSA-PSS, NIST ECDSA, and Ed25519
/// algorithms accepted by certificate and CMS validation.
/// Verifies [signature] over [data] with [certificate] subject public key.
///
/// Supports RSA PKCS#1 v1.5, RSA-PSS, ECDSA, and Ed25519 OIDs accepted
/// elsewhere in the path validator. Returns `false` for parameter or key
/// mismatches and throws [UnsupportedError] for unknown signature OIDs.
Future<bool> verifySignatureWithCertificatePublicKey({
  required X509Certificate certificate,
  required X509AlgorithmIdentifier signatureAlgorithm,
  required List<int> data,
  required List<int> signature,
}) async {
  final signatureOid = signatureAlgorithm.oid;
  switch (signatureOid) {
    case '1.2.840.113549.1.1.11':
      if (!_nullOrAbsentParameters(signatureAlgorithm.parametersDer)) {
        return false;
      }
      return _verifyRsaPkcs1(certificate, signature, data, _HashSpec.sha256);
    case '1.2.840.113549.1.1.12':
      if (!_nullOrAbsentParameters(signatureAlgorithm.parametersDer)) {
        return false;
      }
      return _verifyRsaPkcs1(certificate, signature, data, _HashSpec.sha384);
    case '1.2.840.113549.1.1.13':
      if (!_nullOrAbsentParameters(signatureAlgorithm.parametersDer)) {
        return false;
      }
      return _verifyRsaPkcs1(certificate, signature, data, _HashSpec.sha512);
    case '1.2.840.113549.1.1.10':
      final parameters = _parseCertificatePssParameters(
        signatureAlgorithm.parametersDer,
      );
      if (parameters == null) {
        return false;
      }
      return _verifyRsaPss(
        certificate,
        signature,
        data,
        parameters.hash,
        parameters.saltLength,
      );
    case '1.2.840.10045.4.3.2':
      if (signatureAlgorithm.parametersDer != null) {
        return false;
      }
      return _verifyEcdsa(certificate, signature, data, _HashSpec.sha256);
    case '1.2.840.10045.4.3.3':
      if (signatureAlgorithm.parametersDer != null) {
        return false;
      }
      return _verifyEcdsa(certificate, signature, data, _HashSpec.sha384);
    case '1.2.840.10045.4.3.4':
      if (signatureAlgorithm.parametersDer != null) {
        return false;
      }
      return _verifyEcdsa(certificate, signature, data, _HashSpec.sha512);
    case '1.3.101.112':
      if (signatureAlgorithm.parametersDer != null ||
          certificate.subjectPublicKeyAlgorithm.oid != '1.3.101.112' ||
          certificate.subjectPublicKeyAlgorithm.parametersDer != null ||
          certificate.subjectPublicKey.length != 32 ||
          signature.length != 64) {
        return false;
      }
      return cryptography.Ed25519().verify(
        data,
        signature: cryptography.Signature(
          signature,
          publicKey: cryptography.SimplePublicKey(
            certificate.subjectPublicKey,
            type: cryptography.KeyPairType.ed25519,
          ),
        ),
      );
    default:
      throw UnsupportedError(
        'Unsupported certificate signature algorithm: $signatureOid',
      );
  }
}

Future<bool> _verifyRsaPkcs1(
  X509Certificate issuer,
  List<int> signature,
  List<int> data,
  _HashSpec hash,
) async {
  if (issuer.subjectPublicKeyAlgorithm.oid != '1.2.840.113549.1.1.1' ||
      !_nullOrAbsentParameters(
        issuer.subjectPublicKeyAlgorithm.parametersDer,
      )) {
    return false;
  }
  final parsed = keyenc.parseRsaPublicKeySpki(issuer.subjectPublicKeyInfoDer);
  if (parsed == null) {
    return false;
  }
  final key = pc.RSAPublicKey(parsed.modulus, parsed.exponent);
  final signer = pc.RSASigner(hash.digest(), hash.identifierHex)
    ..init(false, pc.PublicKeyParameter<pc.RSAPublicKey>(key));
  try {
    return signer.verifySignature(
      Uint8List.fromList(data),
      pc.RSASignature(Uint8List.fromList(signature)),
    );
  } on ArgumentError {
    return false;
  }
}

Future<bool> _verifyRsaPss(
  X509Certificate issuer,
  List<int> signature,
  List<int> data,
  _HashSpec hash,
  int saltLength,
) async {
  if (issuer.subjectPublicKeyAlgorithm.oid != '1.2.840.113549.1.1.1' &&
      issuer.subjectPublicKeyAlgorithm.oid != '1.2.840.113549.1.1.10') {
    return false;
  }
  final parsed = keyenc.parseRsaPublicKeySpki(issuer.subjectPublicKeyInfoDer);
  if (parsed == null) {
    return false;
  }
  final key = pc.RSAPublicKey(parsed.modulus, parsed.exponent);
  final verifier = pc.PSSSigner(pc.RSAEngine(), hash.digest(), hash.digest())
    ..init(
      false,
      pc.ParametersWithSaltConfiguration(
        pc.PublicKeyParameter<pc.RSAPublicKey>(key),
        _freshSecureRandom(),
        saltLength,
      ),
    );
  try {
    return verifier.verifySignature(
      Uint8List.fromList(data),
      pc.PSSSignature(Uint8List.fromList(signature)),
    );
  } on ArgumentError {
    return false;
  }
}

Future<bool> _verifyEcdsa(
  X509Certificate issuer,
  List<int> signature,
  List<int> data,
  _HashSpec hash,
) async {
  if (issuer.subjectPublicKeyAlgorithm.oid != '1.2.840.10045.2.1') {
    return false;
  }
  final curveOid = _parameterOid(issuer.subjectPublicKeyAlgorithm);
  final parameters = switch (curveOid) {
    '1.2.840.10045.3.1.7' => (pc.ECCurve_secp256r1(), 32),
    '1.3.132.0.34' => (pc.ECCurve_secp384r1(), 48),
    '1.3.132.0.35' => (pc.ECCurve_secp521r1(), 66),
    _ => throw UnsupportedError('Unsupported issuer EC curve: $curveOid'),
  };
  final p1363 = ecdsaDerToP1363(signature, componentLength: parameters.$2);
  final parsedSpki = keyenc.parseEcPublicKeySpki(
    issuer.subjectPublicKeyInfoDer,
  );
  if (parsedSpki == null) {
    return false;
  }
  final point = parameters.$1.curve.decodePoint(parsedSpki.point);
  if (point == null) {
    return false;
  }
  final key = pc.ECPublicKey(point, parameters.$1);
  final r = bigIntFromUnsignedBytes(p1363.sublist(0, parameters.$2));
  final s = bigIntFromUnsignedBytes(p1363.sublist(parameters.$2));
  final verifier = pc.ECDSASigner(hash.digest())
    ..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(key));
  return verifier.verifySignature(
    Uint8List.fromList(data),
    pc.ECSignature(r, s),
  );
}

pc.SecureRandom _freshSecureRandom() {
  final random = pc.FortunaRandom();
  final seedSource = Random();
  final seed = Uint8List.fromList(
    List<int>.generate(32, (_) => seedSource.nextInt(256)),
  );
  random.seed(pc.KeyParameter(seed));
  return random;
}

final class _HashSpec {
  const _HashSpec(this.digest, this.identifierHex);

  final pc.Digest Function() digest;
  final String identifierHex;

  static final sha256 = _HashSpec(
    pc.SHA256Digest.new,
    '0609608648016503040201',
  );
  static final sha384 = _HashSpec(
    pc.SHA384Digest.new,
    '0609608648016503040202',
  );
  static final sha512 = _HashSpec(
    pc.SHA512Digest.new,
    '0609608648016503040203',
  );
}

bool _nullOrAbsentParameters(List<int>? parameters) =>
    parameters == null ||
    (parameters.length == 2 && parameters[0] == 0x05 && parameters[1] == 0);

({_HashSpec hash, int saltLength})? _parseCertificatePssParameters(
  List<int>? der,
) {
  if (der == null) {
    return null;
  }
  try {
    final sequence = DerReader(der).single(0x30);
    final reader = DerReader(sequence);
    var hashOid = '1.3.14.3.2.26';
    var mgfHashOid = '1.3.14.3.2.26';
    var saltLength = 20;
    var trailerField = 1;
    var lastTag = -1;
    while (!reader.isAtEnd) {
      final field = reader.read();
      if (field.tag < 0xa0 || field.tag > 0xa3 || field.tag <= lastTag) {
        return null;
      }
      lastTag = field.tag;
      switch (field.tag) {
        case 0xa0:
          hashOid = _signatureAlgorithm(field.content).$1;
        case 0xa1:
          final mask = _signatureAlgorithm(field.content);
          if (mask.$1 != '1.2.840.113549.1.1.8' || mask.$2 == null) {
            return null;
          }
          mgfHashOid = _signatureAlgorithm(mask.$2!).$1;
        case 0xa2:
          saltLength = _signatureInteger(field.content);
        case 0xa3:
          trailerField = _signatureInteger(field.content);
      }
    }
    final hash = switch (hashOid) {
      '2.16.840.1.101.3.4.2.1' => _HashSpec.sha256,
      '2.16.840.1.101.3.4.2.2' => _HashSpec.sha384,
      '2.16.840.1.101.3.4.2.3' => _HashSpec.sha512,
      _ => null,
    };
    if (hash == null || mgfHashOid != hashOid || trailerField != 1) {
      return null;
    }
    return (hash: hash, saltLength: saltLength);
  } on FormatException {
    return null;
  }
}

(String, List<int>?) _signatureAlgorithm(List<int> der) {
  final sequence = DerReader(der).single(0x30);
  final reader = DerReader(sequence);
  final oid = _decodeOid(reader.read(0x06).content);
  final parameters = reader.isAtEnd ? null : reader.read().encoded;
  if (!reader.isAtEnd) {
    throw const FormatException('Invalid signature AlgorithmIdentifier');
  }
  return (oid, parameters);
}

int _signatureInteger(List<int> der) {
  final bytes = DerReader(der).single(0x02);
  if (bytes.isEmpty ||
      bytes.first & 0x80 != 0 ||
      (bytes.length > 1 && bytes.first == 0 && bytes[1] & 0x80 == 0)) {
    throw const FormatException('Invalid signature INTEGER');
  }
  var value = 0;
  for (final byte in bytes) {
    value = value << 8 | byte;
  }
  return value;
}

String? _parameterOid(X509AlgorithmIdentifier algorithm) {
  final der = algorithm.parametersDer;
  if (der == null || der.length < 3 || der[0] != 0x06) {
    return null;
  }
  var offset = 1;
  final firstLength = der[offset++];
  if (firstLength >= 0x80 || firstLength != der.length - offset) {
    return null;
  }
  return _decodeOid(der.sublist(offset));
}

String _decodeOid(List<int> bytes) {
  final values = <BigInt>[];
  var current = BigInt.zero;
  var start = true;
  for (final byte in bytes) {
    if (start && byte == 0x80) {
      throw const FormatException('Non-minimal signature OID');
    }
    current = current << 7 | BigInt.from(byte & 0x7f);
    start = false;
    if (byte & 0x80 == 0) {
      values.add(current);
      current = BigInt.zero;
      start = true;
    }
  }
  if (!start || values.isEmpty) {
    throw const FormatException('Invalid signature OID');
  }
  final first = values.removeAt(0);
  final firstArc = first < BigInt.from(40)
      ? BigInt.zero
      : first < BigInt.from(80)
      ? BigInt.one
      : BigInt.two;
  return [firstArc, first - firstArc * BigInt.from(40), ...values].join('.');
}

String _criticalExtensionMessage(String oid) {
  const unsupported = {
    '2.5.29.30': 'name constraints',
    '2.5.29.36': 'policy constraints',
    '2.5.29.54': 'inhibit anyPolicy',
    '2.5.29.31': 'CRL distribution points/revocation',
    '2.5.29.46': 'freshest CRL/revocation',
  };
  final feature = unsupported[oid];
  return feature == null
      ? 'Unsupported critical extension: $oid'
      : 'Unsupported critical $feature extension: $oid';
}

List<Uint8List> _copyDerList(Iterable<List<int>> values, String name) {
  final result = <Uint8List>[];
  final seen = <String>{};
  for (final value in values) {
    if (value.isEmpty || value.any((byte) => byte < 0 || byte > 0xff)) {
      throw ArgumentError.value(value, name, 'Must contain DER byte strings');
    }
    final copy = Uint8List.fromList(value);
    final identity = copy.join(',');
    if (seen.add(identity)) {
      result.add(copy);
    }
  }
  return List.unmodifiable(result);
}

List<Uint8List> _copyHashes(Iterable<List<int>> values) {
  final result = <Uint8List>[];
  for (final value in values) {
    if (value.length != 32 || value.any((byte) => byte < 0 || byte > 0xff)) {
      throw ArgumentError.value(
        value,
        'allowedEndEntitySha256Hashes',
        'Each SHA-256 hash must contain exactly 32 bytes',
      );
    }
    result.add(Uint8List.fromList(value));
  }
  return List.unmodifiable(result);
}
