use std::ops::RangeInclusive;
use std::str::FromStr;
use clap::Parser;
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};
use belenios::polling_station::PollingStation;
use belenios::registrar;
use belenios::trustee::Trustee;
use belenios::voter::Voter;

const VOTER_COUNT_RANGE: RangeInclusive<usize> = 2..=1000;
const TRUSTEE_COUNT_RANGE: RangeInclusive<usize> = 2..=100;

fn voter_in_range(s: &str) -> Result<(), String> {
    usize::from_str(s)
        .map(|n| VOTER_COUNT_RANGE.contains(&n))
        .map_err(|e| e.to_string())
        .and_then(|result| match result {
            true => Ok(()),
            false => Err(format!("voter count should be between {} and {}", VOTER_COUNT_RANGE.start(), VOTER_COUNT_RANGE.end()))
        })
}

fn trustee_in_range(s: &str) -> Result<(), String> {
    usize::from_str(s)
        .map(|n| TRUSTEE_COUNT_RANGE.contains(&n))
        .map_err(|e| e.to_string())
        .and_then(|result| match result {
            true => Ok(()),
            false => Err(format!("trustee count should be between {} and {}", TRUSTEE_COUNT_RANGE.start(), TRUSTEE_COUNT_RANGE.end()))
        })
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(validator=voter_in_range, short, long, default_value_t = 10)]
    voter_count: usize,

    #[clap(validator=trustee_in_range, short, long, default_value_t = 4)]
    trustee_count: usize,
}

fn main() {
    let cli = Cli::parse();
    let voter_count = cli.voter_count;
    let trustee_count = cli.trustee_count;
    let upper_bound = voter_count + 1;
    let mut rng = ChaChaRng::from_entropy();

    println!("setting up {} trustees...", trustee_count);
    let mut trustees: Vec<Trustee> = (0..trustee_count).map(|i| Trustee::new(&mut rng, i, trustee_count)).collect();
    let mut server = PollingStation::new(trustee_count, upper_bound);

    println!("trustees committing their shares to the polling station");
    for (i, trustee) in trustees.iter().enumerate() {
        server.store_trustee_commitment(i, trustee.commit_share()).unwrap();
    }

    println!("trustees exchanges their shares with each other");
    for i in 0..trustee_count {
        for j in 0..trustee_count {
            let share = trustees[j].distribute_share(i).unwrap();
            trustees[i].store_share(j, share).unwrap();
        }
    }

    println!("trustees publishing their public keys with proof of knowledge");
    for i in 0..trustee_count {
        let pk_pok = trustees[i].publish_pk_pok(&mut rng, server.get_commitments()).unwrap();
        server.store_trustee_pk_pok(i, pk_pok).unwrap();
    }

    println!("polling station computing aggregate public key");
    let pk = server.compute_final_pk().unwrap();

    println!("registrar is creating {} secret keys", voter_count);
    let (sks, vks)  = registrar::create_sks_vks(&mut rng, voter_count);
    println!("creating {} voters", voter_count);
    let mut voters: Vec<Voter> = sks.into_iter().map(|sk| Voter::new(sk, &pk)).collect();
    server.store_vks(vks);

    let votes: Vec<bool> = (0..voter_count).into_iter().map(|_| {
        rng.next_u32() % 2 == 0
    }).collect();
    println!("generated votes {:?}", votes);

    println!("casting ballots");
    for (voter, vote) in (&mut voters).iter_mut().zip(votes) {
        let v = voter.vote(&mut rng, vote);
        server.add_ballot(v).unwrap();
    }

    println!("voters checking the bulletin board");
    for voter in &voters {
        voter.check_bb(server.get_bb()).unwrap();
    }

    println!("computing the encrypted tally");
    let ct_tally = server.tally().unwrap();

    println!("trustees perform distributed decryption");
    for (i, trustee) in trustees.iter().enumerate() {
        let p = trustee.partial_decrypt_pok(&mut rng, &ct_tally);
        server.store_trustee_res_pok(i, p).unwrap();
    }

    let final_tally = server.compute_final_tally().unwrap();
    println!("the final tally is {}", final_tally);
}