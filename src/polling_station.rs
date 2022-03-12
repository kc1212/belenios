use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use crate::error::BeleniosError;
use crate::crypto::zkp_dl;

struct BulletinBoard {}

// Also known as the voting server
pub struct PollingStation {
    m: usize,
    pk: Option<EdwardsPoint>,
    vks: Vec<EdwardsPoint>,
    trustee_pk_pok: Vec<Option<(EdwardsPoint, (EdwardsPoint, Scalar))>>,
}

impl PollingStation {
    pub fn new(m: usize) -> PollingStation {
        PollingStation {
            m,
            pk: None,
            vks: vec![],
            trustee_pk_pok: vec![None; m],
        }
    }

    pub fn store_trustee_pk(&mut self, trustee_id: usize, pk_pok: &(EdwardsPoint, (EdwardsPoint, Scalar)))
    -> Result<(), BeleniosError> {
        let (pk, pok) = pk_pok;
        if !zkp_dl::verify(pk, pok) {
            return Err(BeleniosError::BadDiscreteLogProof)
        }
        if trustee_id >= self.m {
            return Err(BeleniosError::InvalidTrusteeID);
        }
        self.trustee_pk_pok[trustee_id] = Some(*pk_pok);
        Ok(())
    }

    pub fn compute_final_pk(&mut self) -> Result<EdwardsPoint, BeleniosError> {
        let mut final_pk = EdwardsPoint::identity();
        for o in &self.trustee_pk_pok {
            let (pk, _) = o.ok_or(BeleniosError::MissingTrusteePublicKey)?;
            final_pk += pk;
        }
        self.pk = Some(final_pk);
        Ok(final_pk)
    }

    pub fn store_vks(&mut self, vks: Vec<EdwardsPoint>) {
        self.vks = vks
    }

    pub fn get_trustee_pk_poks(&self) -> Vec<Option<(EdwardsPoint, (EdwardsPoint, Scalar))>> {
        self.trustee_pk_pok.clone()
    }

    pub fn get_pk(&self) -> Option<EdwardsPoint> {
        self.pk
    }
}