use std::collections::HashMap;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use crate::error::BeleniosError;
use crate::voter::Vote;
use crate::crypto::*;

// Also known as the voting server
pub struct PollingStation {
    m: usize,
    pk: Option<EdwardsPoint>,
    vks: Vec<EdwardsPoint>,
    trustee_pk_pok: Vec<Option<(EdwardsPoint, zkp_dl::Proof)>>,
    trustee_res_pok: Vec<Option<(EdwardsPoint, zkp_decryption::Proof)>>,
    bb: HashMap<[u8; 32], Vote>,
    tally: Option<(EdwardsPoint, EdwardsPoint)>,
}

impl PollingStation {
    pub fn new(m: usize) -> PollingStation {
        PollingStation {
            m,
            pk: None,
            vks: vec![],
            trustee_pk_pok: vec![None; m],
            trustee_res_pok: vec![None; m],
            bb: HashMap::new(), // use with_capacity
            tally: None,
        }
    }


    pub fn store_trustee_pk_pok(&mut self, trustee_id: usize, pk_pok: &(EdwardsPoint, zkp_dl::Proof))
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

    pub fn store_trustee_res_pok(&mut self, trustee_id: usize, res_pok: (EdwardsPoint, zkp_decryption::Proof))
                                -> Result<(), BeleniosError> {
        let ct = self.tally.unwrap();
        let pk_i = self.trustee_pk_pok[trustee_id].unwrap().0;
        let (m, pok) = res_pok;
        if !zkp_decryption::verify(&pk_i, &ct.0, &m, &pok) {
            return Err(BeleniosError::BadDecryptionProof)
        }
        if trustee_id >= self.m {
            return Err(BeleniosError::InvalidTrusteeID);
        }
        self.trustee_res_pok[trustee_id] = Some(res_pok);
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

    pub fn add_vote(&mut self, vote_vk: (Vote, EdwardsPoint)) -> Result<(), BeleniosError> {
        let (vote, vk) = vote_vk;
        if !self.vks.contains(&vk) {
            return Err(BeleniosError::VoterDoesNotExist);
        }
        if !vote.verify(&vk, &self.pk.unwrap()) {
            return Err(BeleniosError::InvalidVote)
        }
        // TODO(kc1212): log that an old entry is replaced
        let _ = self.bb.insert(get_id(&vk), vote);
        Ok(())
    }

    pub fn tally(&mut self) -> Result<(EdwardsPoint, EdwardsPoint), BeleniosError> {
        let tally = sum_tuple(self.bb.values().map(|vote| { vote.ct }));
        match self.tally {
            None => {
                self.tally = Some(tally);
                Ok(tally)
            }
            Some(_) => {
                Err(BeleniosError::AlreadyTallied)
            }
        }
    }

    pub fn compute_election_result(&self) -> Result<u32, BeleniosError> {
        let b = self.tally.unwrap().1;
        let mut a = EdwardsPoint::identity();
        for o in &self.trustee_res_pok {
            let (tmp, _) = o.unwrap();
            a += tmp;
        }
        binary_cipher::get_ptxt(&(b-a)).ok_or(BeleniosError::CannotDecrypt)
    }

    pub fn get_trustee_pk_poks(&self) -> Vec<Option<(EdwardsPoint, (EdwardsPoint, Scalar))>> {
        self.trustee_pk_pok.clone()
    }

    pub fn get_pk(&self) -> Option<EdwardsPoint> {
        self.pk
    }

    pub fn get_bb(&self) -> &HashMap<[u8; 32], Vote> {
        return &self.bb;
    }
}