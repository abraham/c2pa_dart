import 'dart:async';
import 'dart:typed_data';

import 'package:c2pa_crypto/c2pa_crypto.dart';

import 'remote_manifest.dart';
import 'settings.dart';
import 'signing.dart';

enum C2paProgressPhase {
  loadingResource,
  resolvingRemoteManifest,
  validating,
  signing,
  verifying,
}

final class C2paProgressEvent {
  const C2paProgressEvent({
    required this.phase,
    this.completed,
    this.total,
    this.message,
    this.uri,
  });

  final C2paProgressPhase phase;
  final int? completed;
  final int? total;
  final String? message;
  final Uri? uri;
}

typedef C2paProgressCallback = FutureOr<void> Function(C2paProgressEvent event);
typedef C2paCancellationCallback = FutureOr<bool> Function();
typedef C2paOcspTransport = Future<Uint8List> Function(
  Uri endpoint,
  Uint8List requestDer,
);

enum CawgValidationPolicy { stopOnFirstFailure, continueWhenPossible }

/// Selects stable CAWG 1.1 behavior or c2pa-rs 0.90.22 compatibility.
enum CawgIcaCompatibility { stable11, c2paRs09022 }

final class C2paTrustConfiguration {
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

  final bool verifyTrust;
  final List<Uint8List> trustAnchors;
  final List<Uint8List> intermediates;
  final List<Uint8List> allowedEndEntitySha256Hashes;
  final Set<String> allowedEkuOids;
  final DateTime? evaluationTime;
  final int maxPathDepth;
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

typedef C2paTrustConfig = C2paTrustConfiguration;

/// Immutable dependencies and policy used by future SDK operations.
final class C2paContext {
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

  final C2paSettings settings;
  final C2paTrustConfiguration trust;
  final C2paTrustConfiguration timestampTrust;
  final C2paTrustConfiguration cawgTrust;
  final C2paProgressCallback? onProgress;
  final C2paCancellationCallback? isCancelled;

  /// Optional remote transport. No network resolver is installed by default.
  final C2paRemoteResolver? remoteResolver;

  /// Legacy resolver. Prefer [remoteResolver] for address-aware transports.
  final RemoteManifestResolver? remoteManifestResolver;
  final RemoteManifestPolicy remoteManifestPolicy;

  /// Optional did:web transport. No DID resolver is installed by default.
  final C2paRemoteResolver? didWebResolver;
  final RemoteManifestPolicy didWebPolicy;
  final CawgValidationPolicy cawgValidationPolicy;
  final CawgIcaCompatibility cawgIcaCompatibility;
  final C2paSigner? signer;
  final C2paVerifier? verifier;
  final C2paOcspTransport? ocspTransport;

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
