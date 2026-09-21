import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';

/// Test-only signing callback for [FakeC2paSigner].
///
/// This is deterministic test plumbing, not a secure signer, and must never
/// be used in production. The [data] buffer is an owned copy.
typedef FakeSignCallback = FutureOr<Uint8List> Function(Uint8List data);

/// Test-only verification callback for [FakeC2paVerifier].
///
/// This is deterministic test plumbing, not a secure verifier, and must never
/// be used in production. All byte buffers are owned copies.
typedef FakeVerifyCallback = Future<bool> Function({
  required String algorithm,
  required Uint8List data,
  required Uint8List signature,
  required Uint8List publicKey,
});

/// A recorded fake-signing request with copied input data.
final class SignInvocation {
  /// Records one signing request and copies [data].
  SignInvocation(List<int> data) : _data = Uint8List.fromList(data);

  final Uint8List _data;

  /// A defensive copy of the data passed to the signer.
  Uint8List get data => Uint8List.fromList(_data);
}

/// A recorded fake-verification request with copied inputs.
final class VerifyInvocation {
  /// Records one verification request and copies all byte inputs.
  VerifyInvocation({
    required this.algorithm,
    required List<int> data,
    required List<int> signature,
    required List<int> publicKey,
  }) : _data = Uint8List.fromList(data),
       _signature = Uint8List.fromList(signature),
       _publicKey = Uint8List.fromList(publicKey);

  /// Signature algorithm requested by the code under test.
  final String algorithm;
  final Uint8List _data;
  final Uint8List _signature;
  final Uint8List _publicKey;

  /// A defensive copy of the data that was verified.
  Uint8List get data => Uint8List.fromList(_data);

  /// A defensive copy of the signature that was verified.
  Uint8List get signature => Uint8List.fromList(_signature);

  /// A defensive copy of the public key supplied for verification.
  Uint8List get publicKey => Uint8List.fromList(_publicKey);
}

/// A recording signer whose behavior is entirely supplied by [callback].
///
/// This deterministic helper is for tests only, is not cryptographically
/// secure, and must never be used in production signing paths.
final class FakeC2paSigner implements C2paSigner {
  /// Creates a fake signer for [algorithm] using [callback] for signatures.
  FakeC2paSigner({required this.algorithm, required this.callback});

  /// Signature algorithm advertised to the code under test.
  @override
  final String algorithm;

  /// Callback invoked for each copied signing input.
  final FakeSignCallback callback;
  final List<SignInvocation> _invocations = [];

  /// Immutable list of signing calls observed so far.
  List<SignInvocation> get invocations =>
      UnmodifiableListView<SignInvocation>(_invocations);

  /// Records [data], delegates to [callback], and returns a copied signature.
  @override
  Future<Uint8List> sign(Uint8List data) async {
    final input = Uint8List.fromList(data);
    _invocations.add(SignInvocation(input));
    return Uint8List.fromList(await callback(input));
  }
}

/// A recording verifier whose behavior is entirely supplied by [callback].
///
/// This deterministic helper is for tests only, is not cryptographically
/// secure, and must never be used in production verification paths.
final class FakeC2paVerifier implements C2paVerifier {
  /// Creates a fake verifier backed by [callback].
  FakeC2paVerifier(this.callback);

  /// Callback invoked for each copied verification request.
  final FakeVerifyCallback callback;
  final List<VerifyInvocation> _invocations = [];

  /// Immutable list of verification calls observed so far.
  List<VerifyInvocation> get invocations =>
      UnmodifiableListView<VerifyInvocation>(_invocations);

  /// Records the verification inputs and delegates to [callback].
  @override
  Future<bool> verify({
    required String algorithm,
    required Uint8List data,
    required Uint8List signature,
    required Uint8List publicKey,
  }) {
    final invocation = VerifyInvocation(
      algorithm: algorithm,
      data: data,
      signature: signature,
      publicKey: publicKey,
    );
    _invocations.add(invocation);
    return callback(
      algorithm: algorithm,
      data: invocation.data,
      signature: invocation.signature,
      publicKey: invocation.publicKey,
    );
  }
}
