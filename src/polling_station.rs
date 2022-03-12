use std::collections::HashMap;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::traits::Identity;
use crate::error::BeleniosError;
use crate::voter::Ballot;
use crate::crypto::*;

/// PollingStation, also known as the voting server,
/// is the central authority that organizes the election.
/// However, it cannot decrypt the ballots without the help of the trustees.
pub struct PollingStation {
    m: usize,
    pt_upper_bound: usize,
    pk: Option<EdwardsPoint>,
    vks: Vec<EdwardsPoint>,
    trustee_commitment: Vec<Option<Vec<EdwardsPoint>>>,
    trustee_pk_pok: Vec<Option<(EdwardsPoint, zkp_dl::Proof)>>,
    trustee_res_pok: Vec<Option<(EdwardsPoint, zkp_decryption::Proof)>>,
    bb: HashMap<[u8; 32], Ballot>,
    tally: Option<(EdwardsPoint, EdwardsPoint)>,
}

impl PollingStation {
    /// Create a new polling station.
    ///
    /// # Arguments
    /// * `m` - The number of trustees.
    /// * `pt_upper_bound` - The maximum plaintext in the final tally.
    pub fn new(m: usize, pt_upper_bound: usize) -> PollingStation {
        PollingStation {
            m,
            pt_upper_bound,
            pk: None,
            vks: vec![],
            trustee_commitment: vec![None; m],
            trustee_pk_pok: vec![None; m],
            trustee_res_pok: vec![None; m],
            bb: HashMap::new(), // use with_capacity
            tally: None,
        }
    }

    /// Store the commitments from the trustees, must be performed during the
    /// election key generation phase.
    pub fn store_trustee_commitment(&mut self, trustee_id: usize, commitment: Vec<EdwardsPoint>)
        -> Result<(), BeleniosError>
    {
        if trustee_id >= self.m {
            return Err(BeleniosError::InvalidTrusteeID);
        }
        self.trustee_commitment[trustee_id] = Some(commitment);
        Ok(())
    }

    /// Store the trustee public key and the proof of discrete log.
    pub fn store_trustee_pk_pok(&mut self, trustee_id: usize, pk_pok: (EdwardsPoint, zkp_dl::Proof))
                                -> Result<(), BeleniosError> {
        let (pk, pok) = pk_pok;
        if !zkp_dl::verify(&pk, &pok) {
            return Err(BeleniosError::BadDiscreteLogProof)
        }
        if trustee_id >= self.m {
            return Err(BeleniosError::InvalidTrusteeID);
        }
        self.trustee_pk_pok[trustee_id] = Some(pk_pok);
        Ok(())
    }

    /// Compute the encrypted tally.
    pub fn compute_final_pk(&mut self) -> Result<EdwardsPoint, BeleniosError> {
        let mut final_pk = EdwardsPoint::identity();
        for o in &self.trustee_pk_pok {
            let (pk, _) = o.ok_or(BeleniosError::MissingTrusteePublicKey)?;
            final_pk += pk;
        }
        // check that this is the same as summing the commitments
        let mut expected_pk = EdwardsPoint::identity();
        for o in &self.trustee_commitment {
            match o {
                None => {
                    return Err(BeleniosError::MissingTrusteeCommitments);
                }
                Some(commitments) => {
                    let s: EdwardsPoint = commitments.iter().sum();
                    expected_pk += s;
                }
            }
        }
        if expected_pk != final_pk {
            return Err(BeleniosError::BadPublicKey);
        }
        self.pk = Some(final_pk);
        Ok(final_pk)
    }

    /// Add a ballot along with the verification key to the bulletin board.
    pub fn add_ballot(&mut self, ballot_vk: (Ballot, EdwardsPoint)) -> Result<(), BeleniosError> {
        let (ballot, vk) = ballot_vk;
        if !self.vks.contains(&vk) {
            return Err(BeleniosError::VoterDoesNotExist);
        }
        if !ballot.verify(&vk, &self.pk.expect("final pk not computed yet")) {
            return Err(BeleniosError::InvalidVote)
        }
        // TODO(kc1212): log that an old entry is replaced
        let _ = self.bb.insert(get_id(&vk), ballot);
        Ok(())
    }

    /// Compute the encrypted tally.
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

    /// Store the trustee partial decryption and the proof of decryption.
    /// This function must be called after `store_trustee_pk_pok` and `tally`.
    pub fn store_trustee_res_pok(&mut self, trustee_id: usize, res_pok: (EdwardsPoint, zkp_decryption::Proof))
                                -> Result<(), BeleniosError> {
        let ct = self.tally.expect("votes are not tallied");
        let pk_i = self.trustee_pk_pok[trustee_id].expect("trustee pk and pok not stored").0;
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

    /// Compute the final tally from the partial decryptions.
    pub fn compute_final_tally(&self) -> Result<u32, BeleniosError> {
        let b = self.tally.expect("votes are not tallied").1;
        let mut a = EdwardsPoint::identity();
        for o in &self.trustee_res_pok {
            let (tmp, _) = o.expect("trustee partial decryption missing");
            a += tmp;
        }
        brute_force_dlog(&(b-a), self.pt_upper_bound).ok_or(BeleniosError::CannotDecrypt)
    }

    // Store the voter verification keys.
    pub fn store_vks(&mut self, vks: Vec<EdwardsPoint>) {
        if vks.len() > self.pt_upper_bound {
            panic!("too many verification keys");
        }
        self.vks = vks
    }

    /// Output a reference to the bulletin board which stores the encrypted votes.
    pub fn get_bb(&self) -> &HashMap<[u8; 32], Ballot> {
        &self.bb
    }

    /// Output the trustee commitments.
    pub fn get_commitments(&self) -> &Vec<Option<Vec<EdwardsPoint>>> {
        &self.trustee_commitment
    }
}