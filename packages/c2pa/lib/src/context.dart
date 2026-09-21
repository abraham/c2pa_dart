import 'dart:async';
import 'dart:typed_data';

import 'package:c2pa_crypto/c2pa_crypto.dart';

import 'remote_manifest.dart';
import 'settings.dart';
import 'signing.dart';

/// A high-level SDK operation reported through [C2paProgressEvent].
enum C2paProgressPhase {
  /// Source bytes are being loaded or inspected before manifest processing.
  loadingResource,

  /// A remote manifest or referenced manifest is being resolved.
  resolvingRemoteManifest,

  /// Claims, assertions, trust, or builder inputs are being validated.
  validating,

  /// A manifest is being assembled and signed.
  signing,

  /// A signature or validation binding is being verified.
  verifying,
}

/// A progress notification emitted while reading, validating, or signing.
final class C2paProgressEvent {
  /// Creates a progress notification for [phase].
  const C2paProgressEvent({
    required this.phase,
    this.completed,
    this.total,
    this.message,
    this.uri,
  });

  /// The operation phase currently being reported.
  final C2paProgressPhase phase;

  /// The number of work units completed, or `null` when not measured.
  final int? completed;

  /// The total number of work units, or `null` when the total is unknown.
  final int? total;

  /// Optional human-readable detail associated with the progress event.
  final String? message;

  /// The manifest, resource, or endpoint URI associated with the event.
  final Uri? uri;
}

/// Receives progress events and may complete asynchronously.
typedef C2paProgressCallback = FutureOr<void> Function(C2paProgressEvent event);

/// Reports whether the current operation should be cancelled.
///
/// Returning `true` asks cooperative SDK code to stop at its next check.
typedef C2paCancellationCallback = FutureOr<bool> Function();

/// Sends an OCSP request to [endpoint] and returns a DER response.
///
/// The [requestDer] argument is the encoded OCSP request body. Implementations
/// perform any network I/O; the SDK does not install a default transport.
typedef C2paOcspTransport = Future<Uint8List> Function(
  Uri endpoint,
  Uint8List requestDer,
);

/// A policy for handling multiple CAWG identity validation failures.
enum CawgValidationPolicy {
  /// Stops CAWG validation after the first failure is recorded.
  stopOnFirstFailure,

  /// Records failures and keeps validating independent CAWG evidence.
  continueWhenPossible,
}

/// Selects stable CAWG 1.1 behavior or c2pa-rs 0.90.22 compatibility.
enum CawgIcaCompatibility {
  /// Applies the stable CAWG 1.1 identity-claims aggregation rules.
  stable11,

  /// Applies compatibility behavior used by c2pa-rs 0.90.22.
  c2paRs09022,
}

/// Trust anchors and certificate policy used for signature validation.
final class C2paTrustConfiguration {
  /// Creates an immutable trust policy.
  ///
  /// Throws [ArgumentError] if [maxPathDepth] is less than 1, if any DER
  /// byte list is empty or outside the byte range, or if an allowed end-entity
  /// hash is not exactly 32 bytes.
  C2paTrustConfiguration({
    this.verifyTrust = false,
    Iterable<List<int>> trustAnchors = const [],
    Iterable<List<int>> intermediates = const [],
    Iterable<List<int>> allowedEndEntitySha256Hashes = const [],
    Iterable<String> allowedEkuOids = const [
      ExtendedKeyUsageOids.codeSigning,
      ExtendedKeyUsageOids.emailProtection,
      ExtendedKeyUsageOids.documentSigning,
    ],
    DateTime? evaluationTime,
    this.maxPathDepth = 8,
    Iterable<Uri> trustListUris = const [],
  }) : trustAnchors = _copyBytes(trustAnchors, 'trustAnchors'),
       intermediates = _copyBytes(intermediates, 'intermediates'),
       allowedEndEntitySha256Hashes = _copyHashes(allowedEndEntitySha256Hashes),
       allowedEkuOids = Set<String>.unmodifiable(allowedEkuOids),
       evaluationTime = evaluationTime?.toUtc(),
       trustListUris = List<Uri>.unmodifiable(trustListUris) {
    if (maxPathDepth < 1) {
      throw ArgumentError.value(
        maxPathDepth,
        'maxPathDepth',
        'Must be positive',
      );
    }
  }

  /// Whether certificate path validation contributes trusted status.
  ///
  /// When `false`, trust inputs may still be stored but trust failures are not
  /// promoted to successful trusted validation results.
  final bool verifyTrust;

  /// DER-encoded root certificates trusted for path building.
  final List<Uint8List> trustAnchors;

  /// DER-encoded intermediate certificates available for path building.
  final List<Uint8List> intermediates;

  /// Allowed SHA-256 hashes of end-entity certificates.
  ///
  /// An empty list means no end-entity hash allow-list is enforced.
  final List<Uint8List> allowedEndEntitySha256Hashes;

  /// Allowed extended-key-usage OIDs for end-entity certificates.
  final Set<String> allowedEkuOids;

  /// UTC time used for certificate validity checks, or `null` for current time.
  final DateTime? evaluationTime;

  /// Maximum certificate path depth, including the end-entity certificate.
  final int maxPathDepth;

  /// Trust-list URIs configured for consumers that fetch trust material.
  final List<Uri> trustListUris;

  @override
  bool operator ==(Object other) =>
      other is C2paTrustConfiguration &&
      verifyTrust == other.verifyTrust &&
      _byteListsEqual(trustAnchors, other.trustAnchors) &&
      _byteListsEqual(intermediates, other.intermediates) &&
      _byteListsEqual(
        allowedEndEntitySha256Hashes,
        other.allowedEndEntitySha256Hashes,
      ) &&
      _setEquals(allowedEkuOids, other.allowedEkuOids) &&
      evaluationTime == other.evaluationTime &&
      maxPathDepth == other.maxPathDepth &&
      _listEquals(trustListUris, other.trustListUris);

  @override
  int get hashCode => Object.hash(
    verifyTrust,
    Object.hashAll(trustAnchors.map(Object.hashAll)),
    Object.hashAll(intermediates.map(Object.hashAll)),
    Object.hashAll(allowedEndEntitySha256Hashes.map(Object.hashAll)),
    Object.hashAll(allowedEkuOids.toList()..sort()),
    evaluationTime,
    maxPathDepth,
    Object.hashAll(trustListUris),
  );
}

/// Backwards-compatible alias for [C2paTrustConfiguration].
typedef C2paTrustConfig = C2paTrustConfiguration;

/// Immutable dependencies and policy used by future SDK operations.
final class C2paContext {
  /// Creates an immutable SDK execution context.
  ///
  /// Missing trust policies are default-deny, remote policies are derived from
  /// [settings], and no signer, verifier, network, or OCSP transport is
  /// installed unless supplied.
  C2paContext({
    this.settings = const C2paSettings(),
    C2paTrustConfiguration? trust,
    C2paTrustConfiguration? timestampTrust,
    C2paTrustConfiguration? cawgTrust,
    this.onProgress,
    this.isCancelled,
    this.remoteResolver,
    this.remoteManifestResolver,
    RemoteManifestPolicy? remoteManifestPolicy,
    this.didWebResolver,
    RemoteManifestPolicy? didWebPolicy,
    this.cawgValidationPolicy = CawgValidationPolicy.continueWhenPossible,
    this.cawgIcaCompatibility = CawgIcaCompatibility.stable11,
    this.signer,
    this.verifier,
    this.ocspTransport,
  }) : trust = trust ?? C2paTrustConfiguration(),
       timestampTrust = timestampTrust ?? trust ?? C2paTrustConfiguration(),
       cawgTrust = cawgTrust ?? C2paTrustConfiguration(),
       remoteManifestPolicy =
           remoteManifestPolicy ?? RemoteManifestPolicy.fromSettings(settings),
       didWebPolicy =
           didWebPolicy ??
           RemoteManifestPolicy(
             allowedSchemes: const {'https'},
             maxBytes: 1024 * 1024,
             maxRedirects: settings.maxRedirects,
           );

  /// Limits and feature switches applied by SDK operations.
  final C2paSettings settings;

  /// Trust policy used for manifest signing certificate chains.
  final C2paTrustConfiguration trust;

  /// Trust policy used for timestamp-token certificate chains.
  ///
  /// Defaults to [trust] when [timestampTrust] is omitted.
  final C2paTrustConfiguration timestampTrust;

  /// Trust policy used for CAWG identity assertions.
  final C2paTrustConfiguration cawgTrust;

  /// Optional progress callback invoked by cooperative SDK operations.
  final C2paProgressCallback? onProgress;

  /// Optional cancellation callback checked by long-running operations.
  final C2paCancellationCallback? isCancelled;

  /// Optional remote transport. No network resolver is installed by default.
  final C2paRemoteResolver? remoteResolver;

  /// Legacy resolver. Prefer [remoteResolver] for address-aware transports.
  final RemoteManifestResolver? remoteManifestResolver;

  /// Policy used before any remote manifest fetch is attempted.
  final RemoteManifestPolicy remoteManifestPolicy;

  /// Optional did:web transport. No DID resolver is installed by default.
  final C2paRemoteResolver? didWebResolver;

  /// Policy used before resolving did:web identity material.
  final RemoteManifestPolicy didWebPolicy;

  /// CAWG validation failure-handling policy.
  final CawgValidationPolicy cawgValidationPolicy;

  /// CAWG identity-claims aggregation compatibility mode.
  final CawgIcaCompatibility cawgIcaCompatibility;

  /// Optional signer used when building signed manifests.
  final C2paSigner? signer;

  /// Optional verifier used when checking externally supplied signatures.
  final C2paVerifier? verifier;

  /// Optional OCSP transport used for revocation checks.
  final C2paOcspTransport? ocspTransport;

  /// Invokes [onProgress] for [event] when a callback is configured.
  Future<void> reportProgress(C2paProgressEvent event) async {
    await onProgress?.call(event);
  }
}

List<Uint8List> _copyBytes(Iterable<List<int>> values, String name) =>
    List<Uint8List>.unmodifiable(
      values.map((value) {
        if (value.isEmpty || value.any((byte) => byte < 0 || byte > 0xff)) {
          throw ArgumentError.value(value, name, 'Must contain DER bytes');
        }
        return Uint8List.fromList(value).asUnmodifiableView();
      }),
    );

List<Uint8List> _copyHashes(Iterable<List<int>> values) =>
    List<Uint8List>.unmodifiable(
      values.map((value) {
        if (value.length != 32) {
          throw ArgumentError.value(
            value,
            'allowedEndEntitySha256Hashes',
            'SHA-256 hashes must contain exactly 32 bytes',
          );
        }
        return Uint8List.fromList(value).asUnmodifiableView();
      }),
    );

bool _byteListsEqual(List<Uint8List> left, List<Uint8List> right) =>
    left.length == right.length &&
    Iterable<int>.generate(left.length)
        .every((index) => _listEquals(left[index], right[index]));

bool _setEquals<T>(Set<T> left, Set<T> right) =>
    left.length == right.length && left.containsAll(right);

bool _listEquals<T>(List<T> left, List<T> right) {
  if (identical(left, right)) return true;
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) return false;
  }
  return true;
}
