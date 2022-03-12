pub mod crypto;
pub mod trustee;
pub mod polling_station;
pub mod error;
pub mod voter;
pub mod registrar;

#[cfg(test)]
mod test {
    use super::*;
    use quickcheck_macros::quickcheck;
    use quickcheck::TestResult;
    use curve25519_dalek::scalar::Scalar;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use crate::crypto::*;
    use crate::voter::Voter;
    use crate::trustee::Trustee;

    #[quickcheck]
    fn quickcheck_good_execution(votes: Vec<bool>, trustee_count: usize) -> TestResult {
        if votes.len() < 2 || votes.len() > 50 {
        }
        if trustee_count <  2 || trustee_count > 10 {
            return TestResult::discard();
        }
        let expected: u32 = votes.iter().map(|x| *x as u32).sum();
        TestResult::from_bool(good_execution(votes, trustee_count) == expected)
    }

    #[test]
    fn test_good_execution() {
        let votes = vec![true, true, true, false, false];
        let expected: u32 = 3;
        let trustee_count = 4;
        assert_eq!(good_execution(votes, trustee_count), expected);
    }

    fn good_execution(votes: Vec<bool>, trustee_count: usize) -> u32 {
        let voter_count = votes.len();
        let upper_bound = voter_count + 1;
        let expected: u32 = votes.iter().map(|x| *x as u32).sum();
        let mut rng = ChaChaRng::from_entropy();
        let mut trustees: Vec<Trustee> = (0..trustee_count).map(|i| Trustee::new(&mut rng, i, trustee_count)).collect();
        let mut server = polling_station::PollingStation::new(trustee_count, upper_bound);

        // trustees commit to their shares to the server
        for (i, trustee) in trustees.iter().enumerate() {
            server.store_trustee_commitment(i, trustee.commit_share()).unwrap();
        }

        // trustees exchange shares
        let mut master_sk = Scalar::zero();
        for i in 0..trustee_count {
            for j in 0..trustee_count {
                let share = trustees[j].distribute_share(i);
                trustees[i].store_share(j, share).unwrap();
                master_sk += share;
            }
        }

        // trustees verify perform verification on the commitment and compute public key and proof,
        // which is stored on server
        for i in 0..trustee_count {
            let pk_pok = trustees[i].publish_pk_pok(&mut rng, server.get_commitments()).unwrap();
            server.store_trustee_pk_pok(i, pk_pok).unwrap();
        }

        // polling station compute final pk
        let pk = server.compute_final_pk().unwrap();
        assert_eq!(pk, master_sk * G);

        // initialize the voters and store the verification keys in server
        let (sks, vks)  = registrar::create_voters(&mut rng, voter_count);
        let mut voters: Vec<Voter> = sks.into_iter().map(|sk| Voter::new(sk, &pk)).collect();
        server.store_vks(vks);

        // voting phase
        for (voter, vote) in (&mut voters).iter_mut().zip(votes) {
            let v = voter.vote(&mut rng, vote);
            server.add_vote(v).unwrap();
            assert_eq!(binary_cipher::decrypt(&master_sk, &v.0.ct, upper_bound).unwrap(), vote as u32);
        }

        // voters check the bb
        for voter in &voters {
            voter.check_bb(server.get_bb()).unwrap();
        }

        // compute the encrypted tally
        let ct_tally = server.tally().unwrap();
        assert_eq!(binary_cipher::decrypt(&master_sk, &ct_tally, upper_bound).unwrap(), expected);

        // trustees perform distributed decryption
        for (i, trustee) in trustees.iter().enumerate() {
            let p = trustee.partial_decrypt_pok(&mut rng, &ct_tally);
            server.store_trustee_res_pok(i, p).unwrap();
        }

        // polling station computes the final outcome
        server.compute_election_result().unwrap()
    }
}