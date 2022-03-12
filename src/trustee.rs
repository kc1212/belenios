use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use crate::crypto::*;
use crate::error::*;

pub struct Trustee {
    id: usize,
    m: usize,
    dk_i: Option<Scalar>,
    shares: Vec<Scalar>,
    their_shares: Vec<Option<Scalar>>,
}

impl Trustee {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, id: usize, m: usize) -> Trustee {
        let (_, shares) = share(rng, m);
        Trustee {
            id,
            m,
            dk_i: None,
            shares,
            their_shares: vec![None; m],
        }
    }

    pub fn distribute_share(&self, receiver_id: usize) -> Scalar {
        // TODO(kc1212): check index
        self.shares[receiver_id]
    }

    pub fn store_share(&mut self, sender_id: usize, share: Scalar) -> Result<(), BeleniosError> {
        if sender_id >= self.m {
            return Err(BeleniosError::InvalidTrusteeID);
        }
        self.their_shares[sender_id] = Some(share);
        Ok(())
    }

    pub fn commit_share(&self) -> Vec<EdwardsPoint> {
        self.shares.iter().map(|s| s*G).collect()
    }

    fn check_commitment(&self, commitments: &Vec<Option<Vec<EdwardsPoint>>>) -> Result<(), BeleniosError> {
        for (i, o) in self.their_shares.iter().enumerate() {
            let s = o.ok_or(BeleniosError::MissingTrusteeShare)?;
            let c = commitments[i].as_ref().ok_or(BeleniosError::MissingTrusteeCommitments)?[self.id];
            if s*G != c {
                return Err(BeleniosError::BadTrusteeCommitments)
            }
        }
        Ok(())
    }

    pub fn publish_pk_pok<R: RngCore + CryptoRng>(&mut self, rng: &mut R, commitments: &Vec<Option<Vec<EdwardsPoint>>>)
        -> Result<(EdwardsPoint, (EdwardsPoint, Scalar)), BeleniosError> {
        self.check_commitment(commitments)?;
        let mut dk_i = Scalar::zero();
        for o in &self.their_shares {
            let share = o.ok_or(BeleniosError::MissingTrusteeShare)?;
            dk_i += share;
        }
        let pok = zkp_dl::prove(rng, &dk_i);
        let pk_i = dk_i * G;
        self.dk_i = Some(dk_i);
        Ok((pk_i, pok))
    }

    pub fn partial_decrypt_pok<R: CryptoRng + RngCore>(&self, rng: &mut R, ct: &(EdwardsPoint, EdwardsPoint)) -> (EdwardsPoint, zkp_decryption::Proof) {
        let dk = self.dk_i.expect("dk_i not yet computed");
        let m = dk * ct.0;
        let pok = zkp_decryption::prove(rng, &dk, &ct.0);
        (m, pok)
    }
}