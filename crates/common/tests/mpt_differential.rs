//! Differential testing of the MPT verifier against an independent
//! implementation (`alloy-trie`).
//!
//! The in-crate tests build tries with our own `build_trie` and verify them
//! with our own `walk_trie`. That catches self-inconsistency, but it cannot
//! catch a *shared misconception* — if the builder and the verifier agree on
//! a wrong encoding, both are wrong together and every test still passes.
//! The external review called this out specifically after finding that the
//! verifier accepted an empty proof as proof-of-absence against any root
//! (finding R1): a bug our own fixtures happily reproduced.
//!
//! So here the tries are built and the proofs extracted by `alloy-trie` —
//! the trie implementation used by reth — and only the *verification* is
//! ours. Divergence in either direction is a failure:
//!
//!   - alloy accepts, we reject  → we are over-strict (a liveness bug)
//!   - alloy rejects, we accept  → we are under-strict (a soundness bug)
//!
//! Note we deliberately do not treat alloy as an oracle for *everything*:
//! where our verifier is stricter by design (canonical encodings, trailing
//! proof nodes) that is asserted separately in `mpt.rs`'s own tests.

use alloy_primitives::{keccak256, Bytes, B256};
use alloy_trie::{
    proof::{verify_proof, ProofRetainer},
    HashBuilder, Nibbles, EMPTY_ROOT_HASH,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

use zk_pof_common::mpt;

/// Build a trie with alloy-trie and retain proofs for `targets`.
///
/// Returns `(root, proofs)` where each proof is the ordered node list for the
/// corresponding target, in the same shape `eth_getProof` returns.
fn build_with_alloy(
    entries: &[([u8; 32], Vec<u8>)],
    targets: &[[u8; 32]],
) -> (B256, Vec<Vec<Vec<u8>>>) {
    let target_nibbles: Vec<Nibbles> =
        targets.iter().map(|k| Nibbles::unpack(B256::from(*k))).collect();

    let mut builder =
        HashBuilder::default().with_proof_retainer(ProofRetainer::new(target_nibbles.clone()));

    // add_leaf requires ascending key order.
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted.dedup_by(|a, b| a.0 == b.0);
    for (key, value) in &sorted {
        builder.add_leaf(Nibbles::unpack(B256::from(*key)), value);
    }

    let root = builder.root();
    let proof_nodes = builder.take_proof_nodes();

    let proofs = target_nibbles
        .iter()
        .map(|target| {
            proof_nodes
                .matching_nodes_sorted(target)
                .into_iter()
                .map(|(_, node)| node.to_vec())
                .collect::<Vec<Vec<u8>>>()
        })
        .collect();

    (root, proofs)
}

/// Our verifier's answer for a storage-shaped trie, normalized to
/// `Ok(Some(value)) / Ok(None) / Err`.
fn ours(root: &B256, key: &[u8; 32], proof: &[Vec<u8>]) -> Result<Option<Vec<u8>>, String> {
    // `verify_storage_value` hashes the slot to get the trie key; these tries
    // are keyed by the raw 32-byte key, so go through the trie-key entry point
    // that skips that step. A present leaf decodes as an RLP-encoded word.
    mpt::walk_trie_for_test(&root.0, key, proof).map_err(|e| e.to_string())
}

/// alloy's answer for the same question, as a bool (accepts / rejects).
fn alloy_accepts(root: B256, key: &[u8; 32], expected: Option<Vec<u8>>, proof: &[Vec<u8>]) -> bool {
    let bytes: Vec<Bytes> = proof.iter().map(|n| Bytes::from(n.clone())).collect();
    verify_proof(root, Nibbles::unpack(B256::from(*key)), expected, bytes.iter()).is_ok()
}

#[test]
fn inclusion_agrees_with_alloy() {
    let mut rng = StdRng::seed_from_u64(0xD1FF_0001);

    for round in 0..25 {
        let n = 1 + (round * 7) % 120;
        let entries: Vec<([u8; 32], Vec<u8>)> = (0..n)
            .map(|_| {
                let key: [u8; 32] = rng.gen();
                // RLP-encoded storage words: 1..32 canonical bytes.
                let len = 1 + rng.gen_range(0..31usize);
                let mut value = vec![0u8; len];
                rng.fill(&mut value[..]);
                value[0] = value[0].max(1); // canonical: no leading zero
                let mut rlp = vec![0x80 + len as u8];
                rlp.extend_from_slice(&value);
                (key, rlp)
            })
            .collect();

        let targets: Vec<[u8; 32]> = entries.iter().map(|(k, _)| *k).collect();
        let (root, proofs) = build_with_alloy(&entries, &targets);

        let mut sorted = entries.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        sorted.dedup_by(|a, b| a.0 == b.0);

        for (key, expected_rlp) in &sorted {
            let idx = targets.iter().position(|t| t == key).unwrap();
            let proof = &proofs[idx];

            assert!(
                alloy_accepts(root, key, Some(expected_rlp.clone()), proof),
                "alloy rejected its own inclusion proof (round {round})"
            );

            match ours(&root, key, proof) {
                Ok(Some(value)) => assert_eq!(
                    &value, expected_rlp,
                    "value mismatch vs alloy-built trie (round {round})"
                ),
                Ok(None) => panic!("we reported absent for a key alloy proved present"),
                Err(e) => panic!("we rejected an alloy-valid inclusion proof: {e}"),
            }
        }
    }
}

#[test]
fn non_inclusion_agrees_with_alloy() {
    let mut rng = StdRng::seed_from_u64(0xD1FF_0002);

    for round in 0..25 {
        let n = 2 + (round * 5) % 90;
        let entries: Vec<([u8; 32], Vec<u8>)> = (0..n)
            .map(|_| {
                let key: [u8; 32] = rng.gen();
                (key, vec![0x2A])
            })
            .collect();

        // Keys that are (almost certainly) absent.
        let absent: Vec<[u8; 32]> = (0..8).map(|_| rng.gen()).collect();
        let (root, proofs) = build_with_alloy(&entries, &absent);

        for (i, key) in absent.iter().enumerate() {
            if entries.iter().any(|(k, _)| k == key) {
                continue;
            }
            let proof = &proofs[i];

            assert!(
                alloy_accepts(root, key, None, proof),
                "alloy rejected its own non-inclusion proof (round {round})"
            );

            match ours(&root, key, proof) {
                Ok(None) => {}
                Ok(Some(v)) => panic!("we returned a value for an absent key: {v:?}"),
                Err(e) => panic!("we rejected an alloy-valid non-inclusion proof: {e}"),
            }
        }
    }
}

/// The R1 case, cross-checked: an empty proof is absence only against the
/// empty-trie root. alloy-trie enforces exactly this, which is independent
/// confirmation that the fixed rule is the correct one rather than merely a
/// stricter one.
#[test]
fn empty_proof_rule_agrees_with_alloy() {
    let nonempty_root = B256::from(keccak256(b"not the empty trie"));
    let key = [0x11u8; 32];

    assert!(
        !alloy_accepts(nonempty_root, &key, None, &[]),
        "alloy must reject an empty proof against a nonempty root"
    );
    assert!(
        ours(&nonempty_root, &key, &[]).is_err(),
        "we must reject an empty proof against a nonempty root"
    );

    assert!(
        alloy_accepts(EMPTY_ROOT_HASH, &key, None, &[]),
        "alloy must accept an empty proof against the empty root"
    );
    assert_eq!(
        ours(&B256::from(mpt::EMPTY_TRIE_ROOT), &key, &[]).unwrap(),
        None,
        "we must accept an empty proof against the empty root"
    );
}

/// Mutated proofs must be rejected by both. This is the direction that
/// actually matters for soundness: a verifier that accepts a tampered proof
/// is broken even if it handles every well-formed input correctly.
#[test]
fn mutated_proofs_rejected_by_both() {
    let mut rng = StdRng::seed_from_u64(0xD1FF_0003);
    let mut checked = 0usize;

    for round in 0..20 {
        let n = 4 + (round * 3) % 40;
        let entries: Vec<([u8; 32], Vec<u8>)> = (0..n)
            .map(|_| (rng.gen::<[u8; 32]>(), vec![0x80 + 4, 0xDE, 0xAD, 0xBE, 0xEF]))
            .collect();
        let targets: Vec<[u8; 32]> = entries.iter().map(|(k, _)| *k).collect();
        let (root, proofs) = build_with_alloy(&entries, &targets);

        for (i, key) in targets.iter().enumerate() {
            let proof = &proofs[i];
            if proof.is_empty() {
                continue;
            }

            // Three independent mutations, each of which must break the proof.
            let mutations: Vec<Vec<Vec<u8>>> = vec![
                // (a) flip a byte inside a node
                {
                    let mut m = proof.clone();
                    let node = rng.gen_range(0..m.len());
                    let byte = rng.gen_range(0..m[node].len());
                    m[node][byte] ^= 0xFF;
                    m
                },
                // (b) drop the last node
                proof[..proof.len() - 1].to_vec(),
                // (c) duplicate the last node
                {
                    let mut m = proof.clone();
                    m.push(proof[proof.len() - 1].clone());
                    m
                },
            ];

            for (label, mutated) in ["byte-flip", "truncate", "duplicate"]
                .iter()
                .zip(mutations)
            {
                let expected = entries.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
                let alloy_ok = alloy_accepts(root, key, expected, &mutated);
                let ours_ok = matches!(ours(&root, key, &mutated), Ok(Some(_)));

                assert!(
                    !alloy_ok,
                    "alloy accepted a {label} mutation (round {round})"
                );
                assert!(
                    !ours_ok,
                    "WE ACCEPTED a {label} mutation alloy rejected (round {round}) — \
                     this is a soundness bug"
                );
                checked += 1;
            }
        }
    }

    assert!(checked > 100, "mutation coverage too thin: {checked}");
}
