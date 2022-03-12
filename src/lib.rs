pub mod crypto;
pub mod trustee;
pub mod polling_station;
pub mod error;
pub mod voter;

#[cfg(test)]
mod test {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::edwards::EdwardsPoint;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use crate::error::BeleniosError;
    use crate::voter::Voter;
    use crate::trustee::Trustee;

    #[test]
    fn test_good_execution() {
        good_execution(10, 4);
    }

    fn good_execution(voter_count: usize, trustee_count: usize) {
        let mut rng = ChaChaRng::from_entropy();
        let trustees: Vec<Trustee> = (0..trustee_count).map(|i| Trustee::new(&mut rng, i, trustee_count)).collect();
        let mut server = polling_station::PollingStation::new(trustee_count);

        // trustees store public key and the proof on server
        for i in 0..trustee_count {
            server.store_trustee_pk(i, &trustees[i].publish_pk_pok(&mut rng)).unwrap();
        }

        // trustees check the commitments on server
        let all_trustee_pk_poks = server.get_trustee_pk_poks();
        for trustee in trustees {
            trustee.check_bb(&all_trustee_pk_poks).unwrap();
        }

        // polling station compute final pk
        let pk = server.compute_final_pk().unwrap();

        // initialize the voters and store the verification keys in server
        let voters: Vec<Voter> = (0..voter_count).map(|_| Voter::new(&mut rng, &pk)).collect();
        let vks: Vec<EdwardsPoint> = voters.iter().map(|v| v.get_vk()).collect();
        server.store_vks(vks);
    }
}