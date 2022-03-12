use std::collections::HashMap;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use crate::crypto::*;
use crate::error::BeleniosError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Vote {
    pub(crate) ct: (EdwardsPoint, EdwardsPoint),
    pub(crate) proof: zkp_binary_ptxt::Proof,
    pub(crate) signature: schnorr::Signature,
}

impl Vote {
    pub(crate) fn verify(&self, vk: &EdwardsPoint, pk: &EdwardsPoint) -> bool {
        schnorr::verify_ct(vk, &self.ct, &self.signature) && zkp_binary_ptxt::verify(pk, &self.ct, &self.proof)
    }
}

pub struct Voter {
    sk: Scalar,
    vk: EdwardsPoint,
    pk: EdwardsPoint, // from polling station
    vote: Option<Vote>,
}

impl Voter {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, pk: &EdwardsPoint) -> Voter {
        let (sk, vk) = schnorr::keygen(rng);
        Voter {
            sk, vk, pk: *pk, vote: None
        }
    }

    pub fn vote<R: RngCore + CryptoRng>(&mut self, rng: &mut R, vote: bool)
        -> (Vote, EdwardsPoint) {
        let (ct, proof) = zkp_binary_ptxt::prove(rng, &self.pk, vote);
        let signature = schnorr::sign_ct(rng, &self.sk, &ct);
        let vote = Vote { ct, proof, signature };
        self.vote = Some(vote);
        (vote, self.vk)
    }

    pub fn get_vk(&self) -> EdwardsPoint {
        self.vk
    }

    pub fn check_bb(&self, bb: &HashMap<[u8; 32], Vote>) -> Result<(), BeleniosError> {
        let my_vote = self.vote.unwrap();
        match bb.get(&get_id(&self.vk)) {
            None => {
                Err(BeleniosError::MissingVote)
            }
            Some(vote) => {
                if vote == &my_vote {
                    Ok(())
                } else {
                    Err(BeleniosError::InvalidVote)
                }
            }
        }
    }
}