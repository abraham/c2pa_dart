import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:webcrypto/webcrypto.dart' as webcrypto;

import 'certificate_profile.dart';
import 'ecdsa_signature.dart';
import 'hash_algorithm.dart';
import 'signing_algorithm.dart';
import 'x509_certificate.dart';

/// Immutable inputs controlling certificate path construction and validation.
final class TrustPolicy {
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
  final Set<String> allowedEkuOids;
  final Set<String> requiredCertificatePolicyOids;
  final DateTime evaluationTime;
  final int maxDepth;

  List<Uint8List> get trustAnchors =>
      _trustAnchors.map(Uint8List.fromList).toList(growable: false);

  List<Uint8List> get intermediates =>
      _intermediates.map(Uint8List.fromList).toList(growable: false);

  List<Uint8List> get allowedEndEntitySha256Hashes =>
      _allowedEndEntitySha256Hashes
          .map(Uint8List.fromList)
          .toList(growable: false);
}

enum CertificatePathStatus { trusted, invalid, untrusted, ambiguous }

enum CertificatePathIssueCode {
  malformedCertificate,
  leafProfile,
  certificateNotYetValid,
  certificateExpired,
  unsupportedCriticalExtension,
  issuerNotFound,
  issuerNotCa,
  issuerMissingKeyCertSign,
  pathLengthExceeded,
  nameConstraintExcluded,
  nameConstraintNotPermitted,
  explicitPolicyRequired,
  certificatePolicyViolation,
  policyMappingInhibited,
  anyPolicyInhibited,
  badCertificateSignature,
  unsupportedSignatureAlgorithm,
  loopDetected,
  maxDepthExceeded,
  ambiguousPath,
}

final class CertificatePathIssue {
  const CertificatePathIssue(this.code, this.message, {this.certificateDepth});

  final CertificatePathIssueCode code;
  final String message;
  final int? certificateDepth;
}

/// Structured result of certificate path construction and validation.
final class CertificatePathValidationResult {
  CertificatePathValidationResult({
    required this.status,
    required List<X509Certificate> path,
    required List<CertificatePathIssue> issues,
    required this.directlyAllowedEndEntity,
  }) : path = List.unmodifiable(path),
       issues = List.unmodifiable(issues);

  final CertificatePathStatus status;
  final List<X509Certificate> path;
  final List<CertificatePathIssue> issues;
  final bool directlyAllowedEndEntity;

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
    (allowed) => _equalBytes(allowed, leafHash),
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
      if (_equalBytes(current.subject.der, current.issuer.der)) {
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
          (candidate) => _equalBytes(candidate.subject.der, current.issuer.der),
        )
        .toList();
    final authorityKeyIdentifier = current.authorityKeyIdentifier;
    if (authorityKeyIdentifier != null) {
      issuers = issuers.where((candidate) {
        final subjectKeyIdentifier = candidate.subjectKeyIdentifier;
        return subjectKeyIdentifier == null ||
            _equalBytes(subjectKeyIdentifier, authorityKeyIdentifier);
      }).toList();
    }
    issuers.sort((left, right) => _compareBytes(left.der, right.der));
    // A self-issued certificate is its own issuer candidate. It terminates the
    // path rather than extending it: if it were a configured trust anchor the
    // walk would already have stopped above, so reaching here means the chain
    // ends at an anchor this policy does not trust. Treating that as a cycle
    // reported `loopDetected`, which marks the whole path invalid instead of
    // merely untrusted — enough to make callers discard an otherwise valid
    // RFC 3161 timestamp whose TSA ships its own root in the CMS certificate
    // set. Genuine multi-certificate cycles are still caught below.
    issuers = issuers
        .where((candidate) => !_equalBytes(candidate.der, current.der))
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
      if (path.any((certificate) => _equalBytes(certificate.der, issuer.der))) {
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
      anchors.any((anchor) => _equalBytes(anchor.der, certificate.der));
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
    _equalBytes(certificate.subject.der, certificate.issuer.der);

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
      return _verifyRsaPkcs1(
        certificate,
        signature,
        data,
        webcrypto.Hash.sha256,
      );
    case '1.2.840.113549.1.1.12':
      if (!_nullOrAbsentParameters(signatureAlgorithm.parametersDer)) {
        return false;
      }
      return _verifyRsaPkcs1(
        certificate,
        signature,
        data,
        webcrypto.Hash.sha384,
      );
    case '1.2.840.113549.1.1.13':
      if (!_nullOrAbsentParameters(signatureAlgorithm.parametersDer)) {
        return false;
      }
      return _verifyRsaPkcs1(
        certificate,
        signature,
        data,
        webcrypto.Hash.sha512,
      );
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
      return _verifyEcdsa(certificate, signature, data, webcrypto.Hash.sha256);
    case '1.2.840.10045.4.3.3':
      if (signatureAlgorithm.parametersDer != null) {
        return false;
      }
      return _verifyEcdsa(certificate, signature, data, webcrypto.Hash.sha384);
    case '1.2.840.10045.4.3.4':
      if (signatureAlgorithm.parametersDer != null) {
        return false;
      }
      return _verifyEcdsa(certificate, signature, data, webcrypto.Hash.sha512);
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
  webcrypto.Hash hash,
) async {
  if (issuer.subjectPublicKeyAlgorithm.oid != '1.2.840.113549.1.1.1' ||
      !_nullOrAbsentParameters(
        issuer.subjectPublicKeyAlgorithm.parametersDer,
      )) {
    return false;
  }
  final key = await webcrypto.RsassaPkcs1V15PublicKey.importSpkiKey(
    issuer.subjectPublicKeyInfoDer,
    hash,
  );
  return key.verifyBytes(signature, data);
}

Future<bool> _verifyRsaPss(
  X509Certificate issuer,
  List<int> signature,
  List<int> data,
  webcrypto.Hash hash,
  int saltLength,
) async {
  if (issuer.subjectPublicKeyAlgorithm.oid != '1.2.840.113549.1.1.1' &&
      issuer.subjectPublicKeyAlgorithm.oid != '1.2.840.113549.1.1.10') {
    return false;
  }
  final key = await webcrypto.RsaPssPublicKey.importSpkiKey(
    issuer.subjectPublicKeyInfoDer,
    hash,
  );
  return key.verifyBytes(signature, data, saltLength);
}

Future<bool> _verifyEcdsa(
  X509Certificate issuer,
  List<int> signature,
  List<int> data,
  webcrypto.Hash hash,
) async {
  if (issuer.subjectPublicKeyAlgorithm.oid != '1.2.840.10045.2.1') {
    return false;
  }
  final curveOid = _parameterOid(issuer.subjectPublicKeyAlgorithm);
  final parameters = switch (curveOid) {
    '1.2.840.10045.3.1.7' => (webcrypto.EllipticCurve.p256, 32),
    '1.3.132.0.34' => (webcrypto.EllipticCurve.p384, 48),
    '1.3.132.0.35' => (webcrypto.EllipticCurve.p521, 66),
    _ => throw UnsupportedError('Unsupported issuer EC curve: $curveOid'),
  };
  final p1363 = ecdsaDerToP1363(signature, componentLength: parameters.$2);
  final key = await webcrypto.EcdsaPublicKey.importSpkiKey(
    issuer.subjectPublicKeyInfoDer,
    parameters.$1,
  );
  return key.verifyBytes(p1363, data, hash);
}

bool _nullOrAbsentParameters(List<int>? parameters) =>
    parameters == null ||
    (parameters.length == 2 && parameters[0] == 0x05 && parameters[1] == 0);

({webcrypto.Hash hash, int saltLength})? _parseCertificatePssParameters(
  List<int>? der,
) {
  if (der == null) {
    return null;
  }
  try {
    final sequence = _SignatureDerReader(der).single(0x30);
    final reader = _SignatureDerReader(sequence);
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
      '2.16.840.1.101.3.4.2.1' => webcrypto.Hash.sha256,
      '2.16.840.1.101.3.4.2.2' => webcrypto.Hash.sha384,
      '2.16.840.1.101.3.4.2.3' => webcrypto.Hash.sha512,
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
  final sequence = _SignatureDerReader(der).single(0x30);
  final reader = _SignatureDerReader(sequence);
  final oid = _decodeOid(reader.read(0x06).content);
  final parameters = reader.isAtEnd ? null : reader.read().encoded;
  if (!reader.isAtEnd) {
    throw const FormatException('Invalid signature AlgorithmIdentifier');
  }
  return (oid, parameters);
}

int _signatureInteger(List<int> der) {
  final bytes = _SignatureDerReader(der).single(0x02);
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

final class _SignatureDerValue {
  const _SignatureDerValue(this.tag, this.content, this.encoded);

  final int tag;
  final List<int> content;
  final List<int> encoded;
}

final class _SignatureDerReader {
  _SignatureDerReader(this.bytes);

  final List<int> bytes;
  int offset = 0;

  bool get isAtEnd => offset == bytes.length;

  _SignatureDerValue read([int? expectedTag]) {
    final start = offset;
    if (offset >= bytes.length) {
      throw const FormatException('Truncated signature parameters');
    }
    final tag = bytes[offset++];
    if (tag & 0x1f == 0x1f || (expectedTag != null && tag != expectedTag)) {
      throw const FormatException('Invalid signature parameter tag');
    }
    if (offset >= bytes.length) {
      throw const FormatException('Truncated signature parameters');
    }
    final first = bytes[offset++];
    int length;
    if (first < 0x80) {
      length = first;
    } else {
      final count = first & 0x7f;
      if (count == 0 ||
          count > 4 ||
          count > bytes.length - offset ||
          bytes[offset] == 0) {
        throw const FormatException('Invalid signature parameter length');
      }
      length = 0;
      for (var index = 0; index < count; index++) {
        length = length << 8 | bytes[offset++];
      }
      if (length < 0x80) {
        throw const FormatException('Non-minimal signature parameter length');
      }
    }
    if (length > bytes.length - offset) {
      throw const FormatException('Truncated signature parameter value');
    }
    final contentStart = offset;
    offset += length;
    return _SignatureDerValue(
      tag,
      bytes.sublist(contentStart, offset),
      bytes.sublist(start, offset),
    );
  }

  List<int> single(int tag) {
    final value = read(tag);
    if (!isAtEnd) {
      throw const FormatException('Trailing signature parameter data');
    }
    return value.content;
  }
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

bool _equalBytes(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) {
      return false;
    }
  }
  return true;
}

int _compareBytes(List<int> left, List<int> right) {
  final length = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < length; index++) {
    final comparison = left[index].compareTo(right[index]);
    if (comparison != 0) {
      return comparison;
    }
  }
  return left.length.compareTo(right.length);
}
