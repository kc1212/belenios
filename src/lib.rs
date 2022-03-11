pub mod crypto;
pub mod trustee;
pub mod polynomial;
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

    // taken from: https://stackoverflow.com/questions/64498617/how-to-transpose-a-vector-of-vectors-in-rust
    fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
        assert!(!v.is_empty());
        let len = v[0].len();
        let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
        (0..len)
            .map(|_| {
                iters
                    .iter_mut()
                    .map(|n| n.next().unwrap())
                    .collect::<Vec<T>>()
            })
            .collect()
    }

    fn good_execution(voter_count: usize, trustee_count: usize) {
        let mut rng = ChaChaRng::from_entropy();
        let mut trustees: Vec<Trustee> = (0..trustee_count).map(|i| Trustee::new(&mut rng, i, trustee_count)).collect();
        let mut server = polling_station::PollingStation::new(trustee_count);

        // trustees exchange polynomial evaluation
        let trustee_msgs: Vec<Vec<Scalar>> = trustees.iter().map(|t| t.make_trustee_msg()).collect();
        assert_eq!(trustee_msgs.len(), trustee_count);
        let trustee_msgs_t = transpose(trustee_msgs);
        assert_eq!(trustee_msgs_t.len(), trustee_count);
        for (i, (mut trustee, msg)) in trustees.iter_mut().zip(trustee_msgs_t).enumerate() {
            // TODO check error
            trustee.store_trustee_msg(i, msg);
        }

        // store commitment of coefficients to server
        for i in 0..trustee_count {
            server.store_trustee_commitment(i, trustees[i].commit());
        }

        // trustees compute pk and pok
        let pk_pok = trustees.iter().map(|t| t.compute_pk_pok(&mut rng, &server.trustee_commitments))
            .collect::<Result<Vec<(EdwardsPoint, (EdwardsPoint, Scalar))>, BeleniosError>>().unwrap();

        // polling station verify and compute pk
        for i in 0..trustee_count {
            server.store_trustee_pk(i, &pk_pok[i].0, &pk_pok[i].1).unwrap();
        }
        let pk = server.compute_final_pk().unwrap();

        // initialize the voters and store the verification keys in server
        let voters: Vec<Voter> = (0..voter_count).map(|_| Voter::new(&mut rng, &pk)).collect();
        let vks: Vec<EdwardsPoint> = voters.iter().map(|v| v.get_vk()).collect();
        server.store_vks(vks);
    }
}