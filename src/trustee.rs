use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use crate::crypto::*;
use crate::error::*;

pub struct Trustee {
    id: usize,
    m: usize,
    sk_i: Scalar,
    pk_i: EdwardsPoint,
}

impl Trustee {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, id: usize, m: usize) -> Trustee {
        let (sk_i, pk_i) = binary_cipher::keygen(rng);
        Trustee {
            id,
            m,
            sk_i,
            pk_i,
        }
    }

    pub fn publish_pk_pok<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (EdwardsPoint, (EdwardsPoint, Scalar)) {
        let pok = zkp_dl::prove(rng, &self.sk_i);
        (self.pk_i, pok)
    }

    pub fn check_bb(&self, pk_poks: &Vec<Option<(EdwardsPoint, (EdwardsPoint, Scalar))>>) -> Result<(), BeleniosError> {
        if pk_poks.len() != self.m {
            return Err(BeleniosError::NotEnoughTrusteeCommitments);
        }
        for (i, o) in pk_poks.iter().enumerate() {
            let (pk, pok) = &o.ok_or(BeleniosError::MissingTrusteePublicKey)?;
            if !zkp_dl::verify(pk, pok) {
                return Err(BeleniosError::BadDiscreteLogProof)
            }
            if i == self.id && pk != &self.pk_i {
                return Err(BeleniosError::MissingTrusteePublicKey);
            }
        }
        Ok(())
    }

}