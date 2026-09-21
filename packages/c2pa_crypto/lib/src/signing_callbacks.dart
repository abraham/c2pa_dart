import 'signing_algorithm.dart';

/// Signs [data] with the caller-owned key for [algorithm].
typedef Signer = Future<List<int>> Function(
  SigningAlgorithm algorithm,
  List<int> data,
);

/// Verifies [signature] over [data] with the caller-owned key for [algorithm].
typedef Verifier = Future<bool> Function(
  SigningAlgorithm algorithm,
  List<int> data,
  List<int> signature,
);
