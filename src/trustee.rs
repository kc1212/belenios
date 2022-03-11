use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use crate::polynomial::Polynomial;
use crate::crypto::G;
use crate::crypto::zkp_dl;
use crate::error::*;

fn scalar_pow(mut base: Scalar, mut exp: usize) -> Scalar {
    if exp == 0 { return Scalar::one(); }
    while exp & 1 == 0 {
        base = base.clone() * base;
        exp >>= 1;
    }
    if exp == 1 { return base; }
    let mut acc = base.clone();

    while exp > 1 {
        exp >>= 1;
        base = base.clone() * base;
        if exp & 1 == 1 {
            acc = acc * base.clone();
        }
    }
    acc
}

pub struct Trustee {
    id: usize,
    m: usize,
    f: Polynomial,
    s: Vec<Vec<Scalar>>,
}

impl Trustee {
    fn get_t(&self) -> usize {
        self.m - 1
    }

    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, id: usize, m: usize) -> Trustee {
        let t = m-1;
        let f = Polynomial::random(rng, t as u32 + 1);
        let mut s = vec![vec![]; m];
        s[id] = (0..m).into_iter().map(|j| {
            f.eval(&Scalar::from(j as u32))
        }).collect();
        Trustee {
            id,
            m,
            f,
            s,
        }
    }

    pub fn commit(&self) -> Vec<EdwardsPoint> {
        self.f.commit()
    }

    pub fn make_trustee_msg(&self) -> Vec<Scalar> {
        self.s[self.id].clone()
    }

    pub fn store_trustee_msg(&mut self, i: usize, v: Vec<Scalar>) -> Result<(), BeleniosError>{
        if v.len() != self.m {
            return Err(BeleniosError::BadTrusteeMessage);
        }
        for j in 0..self.m {
            self.s[i][j] = v[j];
        }
        Ok(())
    }

    pub fn compute_pk_pok<R: RngCore + CryptoRng>(&self, rng: &mut R, commitments: &Vec<Vec<EdwardsPoint>>)
        -> Result<(EdwardsPoint, (EdwardsPoint, Scalar)), BeleniosError> {
        self.check_trustee_msg(commitments)?;
        let mut dki = self.s[0][self.id];
        for j in 1..self.m {
            dki += self.s[j][self.id];
        }
        let pok = zkp_dl::prove(rng, &dki);
        let pk = dki * G;
        Ok((pk, pok))
    }

    fn check_trustee_msg(&self, commitments: &Vec<Vec<EdwardsPoint>>) -> Result<(), BeleniosError> {
        for j in 0..self.m {
            if commitments[j].len() != self.get_t()+1 {
                return Err(BeleniosError::NotEnoughTrusteeCommitments)
            }
            // compute prod_{k=0}^t A_{jk}^{i^k}
            let tmp = commitments[j].iter().enumerate().map(|(k, ajk)| {
                scalar_pow(Scalar::from(self.id as u32), k) * ajk
            }).into_iter().sum();

            // check g^{s_{ji}} == prod_{k=0}^t A_{jk}^{i^k}
            if self.s[j][self.id] * G != tmp {
                return Err(BeleniosError::BadTrusteeCommitments);
            }
        }
        Ok(())
    }
}