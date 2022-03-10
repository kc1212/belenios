use curve25519_dalek::constants;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use sha3::{Sha3_512};
use rand_core::{CryptoRng, RngCore};

pub(crate) const G: EdwardsPoint = constants::ED25519_BASEPOINT_POINT;
const ORDER: Scalar = constants::BASEPOINT_ORDER;
const PREFIX_SCHNORR: [u8; 8] = *b"SCHNORRx";
const PREFIX_ZKP_DL: [u8; 8] = *b"ZKP_DLxx";
const PREFIX_ZKP_MEMBERSHIP: [u8; 8] = *b"ZKP_MEMB";

fn generic_keygen<R: CryptoRng + RngCore>(rng: &mut R) -> (Scalar, EdwardsPoint) {
    let x = Scalar::random(rng);
    let y = x * G;
    (x, y)
}

pub mod binary_cipher {
    use super::*;

    pub fn keygen<R: CryptoRng + RngCore>(rng: &mut R) -> (Scalar, EdwardsPoint) {
        generic_keygen(rng)
    }

    pub fn encrypt_with_r(pk: &EdwardsPoint, msg: bool, r: &Scalar) -> (EdwardsPoint, EdwardsPoint) {
        let b = msg as u32;
        (r * G, r * pk + Scalar::from(b) * G)
    }

    pub fn encrypt<R: CryptoRng + RngCore>(rng: &mut R, pk: &EdwardsPoint, msg: bool) -> (EdwardsPoint, EdwardsPoint) {
        let r = Scalar::random(rng);
        encrypt_with_r(pk, msg, &r)
    }

    pub fn decrypt(sk: &Scalar, ct: &(EdwardsPoint, EdwardsPoint)) -> Option<bool> {
        let (a, b) = ct;
        let gv = b - (sk * a);

        if Scalar::from(0u32) * G == gv {
            Some(false)
        } else if Scalar::from(1u32) * G == gv {
            Some(true)
        } else {
            None
        }
    }
}

pub mod schnorr {
    use super::*;

    pub fn keygen<R: CryptoRng + RngCore>(rng: &mut R) -> (Scalar, EdwardsPoint) {
        generic_keygen(rng)
    }

    pub fn sign<R: CryptoRng + RngCore>(rng: &mut R, sk: &Scalar, msg: &[u8]) -> (Scalar, Scalar) {
        let w = Scalar::random(rng);
        let gw = w * G;
        let mut buf = vec![]; // TODO(kc1212): consider remove the extra copying
        buf.extend_from_slice(&PREFIX_SCHNORR);
        buf.extend_from_slice(msg);
        buf.extend_from_slice(gw.compress().as_bytes());
        let c = Scalar::hash_from_bytes::<Sha3_512>(&buf);
        let r = w - sk * c;
        (r, c)
    }

    pub fn verify(vk: &EdwardsPoint, msg: &[u8], signature: &(Scalar, Scalar)) -> bool {
        let (r, c) = signature;
        let a = r * G + c * vk;
        let mut buf = vec![]; // TODO(kc1212): consider remove the extra copying
        buf.extend_from_slice(&PREFIX_SCHNORR);
        buf.extend_from_slice(msg);
        buf.extend_from_slice(a.compress().as_bytes());
        c == &Scalar::hash_from_bytes::<Sha3_512>(&buf)
    }
}

pub mod zkp_dl {
    // Section 2.1 https://hal.inria.fr/hal-01576379/document plus Fiet-Shamir
    use super::*;

    fn fiet_shamir(h: &EdwardsPoint, r: &EdwardsPoint) -> Scalar {
        // H(domain_separation || G || g^x || g^k)
        let mut buf = vec![];
        buf.extend_from_slice(&PREFIX_ZKP_DL);
        buf.extend_from_slice(G.compress().as_bytes());
        buf.extend_from_slice(h.compress().as_bytes());
        buf.extend_from_slice(r.compress().as_bytes());
        let e = Scalar::hash_from_bytes::<Sha3_512>(&buf);
        e
    }

    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, x: &Scalar) -> (EdwardsPoint, Scalar) {
        let k = Scalar::random(rng);
        let r = k * G;
        let h = x * G;
        let e = fiet_shamir(&h, &r);
        let s = k + x * e;
        (r, s)
    }

    pub fn verify(h: &EdwardsPoint, proof: &(EdwardsPoint, Scalar)) -> bool {
        let (r, s) = proof;
        let e = fiet_shamir(&h, &r);
        r == &(s * G - e * h)
    }
}

pub mod zkp_binary_ptxt {
    use super::*;

    fn fiet_shamir(h: &EdwardsPoint, ct: &(EdwardsPoint, EdwardsPoint), commitment: &[(EdwardsPoint, EdwardsPoint); 2]) -> Scalar {
        // H(domain_separation || G || ct || commitment)
        // TODO(kc1212): there might be other domain separation issues
        let mut buf = vec![];
        buf.extend_from_slice(&PREFIX_ZKP_MEMBERSHIP);
        buf.extend_from_slice(G.compress().as_bytes());
        buf.extend_from_slice(h.compress().as_bytes());
        buf.extend_from_slice(ct.0.compress().as_bytes());
        buf.extend_from_slice(ct.1.compress().as_bytes());
        for c in commitment {
            buf.extend_from_slice(c.0.compress().as_bytes());
            buf.extend_from_slice(c.1.compress().as_bytes());
        }
        let e = Scalar::hash_from_bytes::<Sha3_512>(&buf);
        e
    }

    pub fn prove<R: CryptoRng + RngCore>(rng: &mut R, pk: &EdwardsPoint, pt: bool)
                                     -> ((EdwardsPoint, EdwardsPoint), ([(EdwardsPoint, EdwardsPoint); 2], [(Scalar, Scalar); 2])) {
        let r = Scalar::random(rng);
        let h = pk;
        let ct = binary_cipher::encrypt_with_r(pk, pt, &r);
        let (alpha, beta) = ct;
        let mj = Scalar::from(!pt as u32);
        let sigmaj = Scalar::random(rng);
        let rhoj = Scalar::random(rng);
        let w = Scalar::random(rng);
        let aj = rhoj * G - sigmaj * alpha;
        let bj = rhoj * h - sigmaj * (beta - mj * G);
        let ai = w * G;
        let bi = w * h;

        let commitment = if pt {
            [(aj, bj), (ai, bi)]
        } else {
            [(ai, bi), (aj, bj)]
        };
        let e = fiet_shamir(&h, &ct, &commitment);

        let sigmai = e - sigmaj;
        let rhoi = w + r * sigmai;
        let response = if pt {
            [(sigmaj, rhoj), (sigmai, rhoi)]
        } else {
            [(sigmai, rhoi), (sigmaj, rhoj)]
        };
        (ct, (commitment, response))
    }

    pub fn verify(h: &EdwardsPoint, ct: &(EdwardsPoint, EdwardsPoint), proof: &([(EdwardsPoint, EdwardsPoint); 2], [(Scalar, Scalar); 2])) -> bool {
        let commitment = proof.0;
        let response = proof.1;
        let e = fiet_shamir(h, ct, &commitment);
        if e != response.iter().map(|x| x.0).sum() {
            return false;
        }
        let (alpha, beta) = ct;
        for j in 0usize..2 {
            let mj = Scalar::from(j as u32);
            let aj = commitment[j].0;
            let bj = commitment[j].1;
            let sigmaj = response[j].0;
            let rhoj = response[j].1;
            if aj != rhoj * G - sigmaj * alpha {
                return false;
            }
            if bj != rhoj * h - sigmaj * (beta - mj * G) {
                return false;
            }
        }
        return true;
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::traits::Identity;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use super::*;

    #[test]
    fn test_curve_identity() {
        assert_eq!(ORDER * G, EdwardsPoint::identity());
    }

    #[test]
    fn test_cipher() {
        // TODO(kc1212): quickcheck
        let mut rng = ChaChaRng::from_entropy();
        let (sk, pk) = binary_cipher::keygen(&mut rng);

        let msg = true;
        let ct = binary_cipher::encrypt(&mut rng, &pk, msg);
        let pt = binary_cipher::decrypt(&sk, &ct).unwrap();
        assert_eq!(msg, pt);
    }

    #[test]
    fn test_signature() {
        // TODO(kc1212): quickcheck
        let mut rng = ChaChaRng::from_entropy();
        let (sk, vk) = schnorr::keygen(&mut rng);
        let msg1 = *b"bonjour";
        let sig1 = schnorr::sign(&mut rng, &sk, &msg1);
        assert!(schnorr::verify(&vk, &msg1, &sig1));

        let msg2 = *b"ca va";
        assert!(!schnorr::verify(&vk, &msg2, &sig1));
    }

    #[test]
    fn test_zkp_dl() {
        // TODO(kc1212): quickcheck
        let mut rng = ChaChaRng::from_entropy();
        let x1 = Scalar::random(&mut rng);
        let h1 = x1 * G;
        let proof = zkp_dl::prove(&mut rng, &x1);
        assert!(zkp_dl::verify(&h1, &proof));

        let x2 = Scalar::random(&mut rng);
        let h2 = x2 * G;
        assert!(!zkp_dl::verify(&h2, &proof));
    }

    #[test]
    fn test_zkp_binary_ptxt() {
        // TODO(kc1212): quickcheck
        let mut rng = ChaChaRng::from_entropy();
        let (sk, pk) = binary_cipher::keygen(&mut rng);
        {
            let pt = true;
            let (ct, proof) = zkp_binary_ptxt::prove(&mut rng, &pk, pt);
            assert!(zkp_binary_ptxt::verify(&pk, &ct, &proof));
            assert_eq!(binary_cipher::decrypt(&sk, &ct), Some(pt));
        }
        {
            let pt = false;
            let (ct, proof) = zkp_binary_ptxt::prove(&mut rng, &pk, pt);
            assert!(zkp_binary_ptxt::verify(&pk, &ct, &proof));
            assert_eq!(binary_cipher::decrypt(&sk, &ct), Some(pt));
        }
    }
}