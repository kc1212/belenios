use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use crate::crypto::G;

struct Polynomial {
    coeffs: Vec<Scalar>,
}

impl Polynomial {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R, t: u32) -> Polynomial {
        let coeffs = (0..t).map(|_| {
            Scalar::random(rng)
        }).collect();
        Polynomial {
            coeffs
        }
    }

    pub fn eval(&self, x: &Scalar) -> Scalar {
        self.coeffs.iter().fold(Scalar::zero(), |acc, &coeff| {
            acc * x + coeff
        })
    }

    pub fn commit(&self) -> Vec<EdwardsPoint> {
        self.coeffs.iter().map(|x| { x*G }).collect()
    }
}