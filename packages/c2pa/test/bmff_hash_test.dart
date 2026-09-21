import 'dart:typed_data';

import 'package:c2pa/src/bmff_hash.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  group('BMFF Hash v3 Merkle models', () {
    test('round-trip deterministic CBOR and own byte collections', () {
      final initHash = Uint8List.fromList(List<int>.filled(32, 1));
      final root = Uint8List.fromList(List<int>.filled(32, 2));
      final map = MerkleMap(
        uniqueId: 9,
        localId: 4,
        count: 2,
        algorithm: 'sha256',
        initHash: initHash,
        hashes: [root],
        variableBlockSizes: const [100, 120],
      );
      final proofHash = Uint8List.fromList(List<int>.filled(32, 3));
      final proof = BmffMerkleProof(
        uniqueId: 9,
        localId: 4,
        location: 0,
        hashes: [proofHash],
      );
      final assertion = BmffHashAssertion(
        exclusions: [BmffHashExclusion(xpath: '/uuid')],
        algorithm: 'sha256',
        merkle: [map],
        name: 'fragments',
      );
      final encoded = encodeCbor(assertion.toCborMap());

      initHash[0] = 8;
      root[0] = 8;
      proofHash[0] = 8;

      expect(BmffHashAssertion.fromCbor(decodeCbor(encoded)), assertion);
      expect(encodeCbor(assertion.toCborMap()), encoded);
      expect(map.initHash!.first, 1);
      expect(map.hashes.single.first, 2);
      expect(proof.hashes!.single.first, 3);
      expect(
        BmffMerkleProof.fromCbor(decodeCbor(encodeCbor(proof.toCborMap()))),
        proof,
      );
    });

    test('enforces v3 count, row, digest, and block-size rules', () {
      expect(
        () => MerkleMap(
          uniqueId: 0,
          localId: 0,
          count: 0,
          hashes: [List<int>.filled(32, 0)],
        ),
        throwsFormatException,
      );
      expect(
        () => MerkleMap(
          uniqueId: 0,
          localId: 0,
          count: 4,
          hashes: [
            List<int>.filled(32, 0),
            List<int>.filled(32, 0),
            List<int>.filled(32, 0),
          ],
        ),
        throwsFormatException,
      );
      expect(
        () => MerkleMap(
          uniqueId: 0,
          localId: 0,
          count: 1,
          algorithm: 'sha512',
          hashes: [List<int>.filled(32, 0)],
        ),
        throwsFormatException,
      );
      expect(
        () => MerkleMap(
          uniqueId: 0,
          localId: 0,
          count: 2,
          hashes: [List<int>.filled(32, 0)],
          variableBlockSizes: const [10],
        ),
        throwsFormatException,
      );
      expect(
        () => MerkleMap(
          uniqueId: 0,
          localId: 0,
          count: 1,
          hashes: [List<int>.filled(32, 0)],
          fixedBlockSize: 10,
          variableBlockSizes: const [10],
        ),
        throwsFormatException,
      );
    });

    test('rejects unknown fields and malformed proofs', () {
      expect(
        () => MerkleMap.fromCbor({
          'uniqueId': 0,
          'localId': 0,
          'count': 1,
          'hashes': [Uint8List(32)],
          'other': true,
        }),
        throwsFormatException,
      );
      expect(
        () => BmffMerkleProof.fromCbor({
          'uniqueId': 0,
          'localId': 0,
          'location': -1,
        }),
        throwsFormatException,
      );
      expect(
        () => BmffHashAssertion(
          exclusions: [BmffHashExclusion(xpath: '/uuid')],
          hash: Uint8List(32),
          merkle: [
            MerkleMap(
              uniqueId: 0,
              localId: 0,
              count: 1,
              hashes: [Uint8List(32)],
            ),
          ],
        ),
        throwsFormatException,
      );
    });
  });
}
