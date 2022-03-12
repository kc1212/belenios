pub mod crypto;
pub mod trustee;
pub mod polling_station;
pub mod error;
pub mod voter;

#[cfg(test)]
mod test {
    use super::*;
    use quickcheck_macros::quickcheck;
    use quickcheck::TestResult;
    use curve25519_dalek::edwards::EdwardsPoint;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use crate::voter::Voter;
    use crate::trustee::Trustee;

    #[quickcheck]
    fn quickcheck_good_execution(votes: Vec<bool>, trustee_count: usize) -> TestResult {
        if votes.len() < 1 || votes.len() > 50 {
            return TestResult::discard();
        }
        let expected: u32 = votes.iter().map(|x| *x as u32).sum();
        TestResult::from_bool(good_execution(votes, trustee_count) == expected)
    }

    #[test]
    fn test_good_execution() {
        let votes = vec![true; 10];
        let trustee_count = 4;
        let expected: u32 = votes.iter().map(|x| *x as u32).sum();
        assert_eq!(good_execution(votes, trustee_count), expected)
    }

    fn good_execution(votes: Vec<bool>, trustee_count: usize) -> u32 {
        let voter_count = votes.len();
        let mut rng = ChaChaRng::from_entropy();
        let trustees: Vec<Trustee> = (0..trustee_count).map(|i| Trustee::new(&mut rng, i, trustee_count)).collect();
        let mut server = polling_station::PollingStation::new(trustee_count);

        // trustees store public key and the proof on server
        for i in 0..trustee_count {
            server.store_trustee_pk_pok(i, &trustees[i].publish_pk_pok(&mut rng)).unwrap();
        }

        // trustees check the commitments on server
        let all_trustee_pk_poks = server.get_trustee_pk_poks();
        for trustee in &trustees {
            trustee.check_bb(&all_trustee_pk_poks).unwrap();
        }

        // polling station compute final pk
        let pk = server.compute_final_pk().unwrap();

        // initialize the voters and store the verification keys in server
        let mut voters: Vec<Voter> = (0..voter_count).map(|_| Voter::new(&mut rng, &pk)).collect();
        let vks: Vec<EdwardsPoint> = voters.iter().map(|v| v.get_vk()).collect();
        server.store_vks(vks);

        // voting phase
        for voter in &mut voters {
            let v = voter.vote(&mut rng, true);
            server.add_vote(v).unwrap();
        }

        // voters check the bb
        for voter in &voters {
            voter.check_bb(server.get_bb()).unwrap();
        }

        // compute the encrypted tally
        let ct_tally = server.tally().unwrap();

        // trustees perform distributed decryption
        for (i, trustee) in trustees.iter().enumerate() {
            let p = trustee.partial_decrypt_pok(&mut rng, &ct_tally);
            server.store_trustee_res_pok(i, p).unwrap();
        }

        // polling station computes the final outcome
        server.compute_election_result().unwrap()
    }
}