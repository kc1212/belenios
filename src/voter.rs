use std::collections::HashMap;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use crate::crypto::*;
use crate::error::BeleniosError;

/// Ballot is casted by a user
/// which contains an encrypted vote, a proof of binary plaintext and a signature.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Ballot {
    pub(crate) ct: (EdwardsPoint, EdwardsPoint),
    pub(crate) proof: zkp_binary_ptxt::Proof,
    pub(crate) signature: schnorr::Signature,
}

/// Voter represents the state of a user.
pub struct Voter {
    sk: Scalar,
    vk: EdwardsPoint,
    pk: EdwardsPoint, // from polling station
    ballot: Option<Ballot>,
}

impl Voter {
    /// Create a new voter which uses a given secret key from the registrar and holds the master public key.
    pub fn new(sk: Scalar, pk: &EdwardsPoint) -> Voter {
        let vk = sk * G;
        Voter {
            sk, vk, pk: *pk, ballot: None
        }
    }

    /// Cast a vote and output the ballot with the verification key.
    pub fn vote<R: RngCore + CryptoRng>(&mut self, rng: &mut R, vote: bool)
        -> (Ballot, EdwardsPoint) {
        let (ct, proof) = zkp_binary_ptxt::prove(rng, &self.pk, vote);
        let signature = schnorr::sign_ct(rng, &self.sk, &ct);
        let ballot = Ballot { ct, proof, signature };
        self.ballot = Some(ballot);
        (ballot, self.vk)
    }

    /// Check the bulletin board in the polling station for the vote that was casted.
    pub fn check_bb(&self, bb: &HashMap<[u8; 32], Ballot>) -> Result<(), BeleniosError> {
        let my_ballot = self.ballot.unwrap();
        match bb.get(&get_id(&self.vk)) {
            None => {
                Err(BeleniosError::MissingVote)
            }
            Some(ballot) => {
                if ballot == &my_ballot {
                    Ok(())
                } else {
                    Err(BeleniosError::BadMembershipProof)
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_voter() {
        let mut rng = ChaChaRng::from_entropy();
        let (_, pk) = binary_cipher::keygen(&mut rng);
        let sk = Scalar::random(&mut rng);
        let mut voter = Voter::new(sk, &pk);

        let ballot_vk = voter.vote(&mut rng, true);
        let mut bb: HashMap<[u8; 32], Ballot> = HashMap::new();
        assert_eq!(voter.check_bb(&bb).unwrap_err(), BeleniosError::MissingVote);

        let mut bad_voter = Voter::new(sk, &pk);
        let bad_ballot_vk = bad_voter.vote(&mut rng, true);
        bb.insert(get_id(&ballot_vk.1), bad_ballot_vk.0);
        assert_eq!(voter.check_bb(&bb).unwrap_err(), BeleniosError::BadMembershipProof);

        bb.insert(get_id(&ballot_vk.1), ballot_vk.0);
        assert_eq!(voter.check_bb(&bb).unwrap(), ());
    }
}