use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use crate::crypto::schnorr;

/// Output a vector of signing keys for voters
/// with the corresponding vector of verification keys.
pub fn create_sks_vks<R: RngCore + CryptoRng>(rng: &mut R, voter_count: usize) -> (Vec<Scalar>, Vec<EdwardsPoint>) {
    let mut sks = Vec::with_capacity(voter_count);
    let mut vks = Vec::with_capacity(voter_count);
    for _ in 0..voter_count {
        let (sk, vk) = schnorr::keygen(rng);
        sks.push(sk);
        vks.push(vk);
    }
    (sks, vks)
}