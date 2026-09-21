import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';

typedef FakeSignCallback = FutureOr<Uint8List> Function(Uint8List data);

typedef FakeVerifyCallback = Future<bool> Function({
  required String algorithm,
  required Uint8List data,
  required Uint8List signature,
  required Uint8List publicKey,
});

final class SignInvocation {
  SignInvocation(List<int> data) : _data = Uint8List.fromList(data);

  final Uint8List _data;

  Uint8List get data => Uint8List.fromList(_data);
}

final class VerifyInvocation {
  VerifyInvocation({
    required this.algorithm,
    required List<int> data,
    required List<int> signature,
    required List<int> publicKey,
  }) : _data = Uint8List.fromList(data),
       _signature = Uint8List.fromList(signature),
       _publicKey = Uint8List.fromList(publicKey);

  final String algorithm;
  final Uint8List _data;
  final Uint8List _signature;
  final Uint8List _publicKey;

  Uint8List get data => Uint8List.fromList(_data);
  Uint8List get signature => Uint8List.fromList(_signature);
  Uint8List get publicKey => Uint8List.fromList(_publicKey);
}

/// A recording signer whose behavior is entirely supplied by [callback].
final class FakeC2paSigner implements C2paSigner {
  FakeC2paSigner({required this.algorithm, required this.callback});

  @override
  final String algorithm;
  final FakeSignCallback callback;
  final List<SignInvocation> _invocations = [];

  List<SignInvocation> get invocations =>
      UnmodifiableListView<SignInvocation>(_invocations);

  @override
  Future<Uint8List> sign(Uint8List data) async {
    final input = Uint8List.fromList(data);
    _invocations.add(SignInvocation(input));
    return Uint8List.fromList(await callback(input));
  }
}

/// A recording verifier whose behavior is entirely supplied by [callback].
final class FakeC2paVerifier implements C2paVerifier {
  FakeC2paVerifier(this.callback);

  final FakeVerifyCallback callback;
  final List<VerifyInvocation> _invocations = [];

  List<VerifyInvocation> get invocations =>
      UnmodifiableListView<VerifyInvocation>(_invocations);

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
