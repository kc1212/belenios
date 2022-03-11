use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use crate::crypto;

pub struct Voter {
    sk: Scalar,
    vk: EdwardsPoint,
    pk: EdwardsPoint, // from polling station
}

impl Voter {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, pk: &EdwardsPoint) -> Voter {
        let (sk, vk) = crypto::schnorr::keygen(rng);
        Voter {
            sk, vk, pk: *pk,
        }
    }

    pub fn get_id(&self) -> [u8; 32] {
        self.pk.compress().to_bytes()
    }

    pub fn get_vk(&self) -> EdwardsPoint {
        self.vk
    }
}