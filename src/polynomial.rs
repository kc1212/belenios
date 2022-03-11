use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use crate::crypto::G;

pub struct Polynomial {
    pub(crate) coeffs: Vec<Scalar>,
}

impl Polynomial {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R, degree: u32) -> Polynomial {
        let coeffs = (0..degree+1).map(|_| {
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

pub fn share<R: RngCore + CryptoRng>(rng: &mut R, m: usize, t: usize) -> (Scalar, Vec<(Scalar, Scalar)>) {
    // TODO(kc1212): check parameters
    let x = Scalar::random(rng);
    let p = Polynomial::random(rng, t as u32);

    let shares = (1..m+1).into_iter().map(|x| {
        let x = Scalar::from(x as u32);
        (x, p.eval(&x))
    }).collect();
    (x, shares)
}

pub fn reconstruct(shares: &Vec<(Scalar, Scalar)>, t: usize) -> Option<Scalar> {
    // TODO(kc1212): check parameters
    let xs: Vec<Scalar> = shares.iter().map(|share| share.0).collect();
    let mut secret = Scalar::zero();
    for (i, si) in shares.iter().take(t).enumerate() {
        let mut lagrange = Scalar::zero();
        let mut denominator = Scalar::zero();
        let xi = si.0;
        for (j, sj) in shares.iter().take(t).enumerate() {
            if j != i {
                let xj = sj.0;
                lagrange = lagrange * xs[j];
                denominator = denominator * (xj - xi);
            }
        }
        secret += lagrange * si.1 * denominator.invert();
    }
    // TODO(kc1212): verify the remaining shares
    Some(secret)
}

#[cfg(test)]
mod test {
    use quickcheck::TestResult;
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use quickcheck_macros::quickcheck;

    #[test]
    fn test_polynomial() {
        let mut rng = ChaChaRng::from_entropy();
        let n = 10;
        let a0 = Scalar::random(&mut rng);
        let a1 = Scalar::random(&mut rng);

        {
            // evaluate a constant polynomial
            let mut v = vec![];
            v.append(&mut vec![Scalar::zero(); n-1]);
            v.push(a0);
            let p = Polynomial {
                coeffs: v,
            };
            let x = Scalar::random(&mut rng);
            assert_eq!(p.eval(&x), a0);
        }

        {
            // eval the first two terms
            let mut v = vec![];
            v.append(&mut vec![Scalar::zero(); n-2]);
            v.push(a1);
            v.push(a0);
            let p = Polynomial {
                coeffs: v,
            };
            let x = Scalar::random(&mut rng);
            assert_eq!(p.eval(&x), a0 + x*a1);
        }
    }

    #[quickcheck]
    fn quickcheck_sharing_full_threshold(m: usize) -> TestResult {
        if m < 2 || m > 100 {
            return TestResult::discard();
        }
        let mut rng = ChaChaRng::from_entropy();
        let (x, shares) = share(&mut rng, m, m-1);
        TestResult::from_bool(reconstruct(&shares, m-1) == Some(x))
    }
}