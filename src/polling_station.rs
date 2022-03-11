use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use crate::error::BeleniosError;
use crate::crypto::zkp_dl;

struct BulletinBoard {}

// Also known as the voting server
pub struct PollingStation {
    pub m: usize,
    pub trustee_commitments: Vec<Vec<EdwardsPoint>>,
    pub pk: Option<EdwardsPoint>,
    pub vks: Vec<EdwardsPoint>,
}

impl PollingStation {
    fn get_t(&self) -> usize {
        self.m - 1
    }

    pub fn new(m: usize) -> PollingStation {
        PollingStation {
            m,
            trustee_commitments: vec![vec![]; m],
            pk: None,
            vks: vec![],
        }
    }

    pub fn store_trustee_commitment(&mut self, trustee_id: usize, commitment: Vec<EdwardsPoint>) -> Result<(), BeleniosError> {
        if commitment.len() != self.get_t() + 1 {
            return Err(BeleniosError::NotEnoughTrusteeCommitments);
        }
        self.trustee_commitments[trustee_id] = commitment;
        Ok(())
    }

    pub fn store_trustee_pk(&mut self, trustee_id: usize, pk: &EdwardsPoint, pok: &(EdwardsPoint, Scalar))
    -> Result<(), BeleniosError> {
        self.check_trustee_pk(pk, pok)?;
        // TODO store trustee pks
        unimplemented!()
    }

    pub fn compute_final_pk(&mut self) -> Result<EdwardsPoint, BeleniosError> {
        let mut pk = self.trustee_commitments[0][0];
        for i in 1..self.m {
            pk += self.trustee_commitments[i][0];
        }
        self.pk = Some(pk);
        // TODO do the final check on trustee pks
        unimplemented!()
    }

    pub fn store_vks(&mut self, vks: Vec<EdwardsPoint>) {
        self.vks = vks
    }

    fn check_trustee_pk(&self, pk: &EdwardsPoint, pok: &(EdwardsPoint, Scalar)) -> Result<(), BeleniosError> {
        if !zkp_dl::verify(pk, pok) {
            return Err(BeleniosError::BadDiscreteLogProof);
        }
        Ok(())
    }
}