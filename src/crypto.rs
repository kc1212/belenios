use std::ops::Add;
use curve25519_dalek::constants;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand_core::{CryptoRng, RngCore};
use sha3::Sha3_512;

pub(crate) const G: EdwardsPoint = constants::ED25519_BASEPOINT_POINT;
const PREFIX_SCHNORR: [u8; 8] = *b"SCHNORRx";
const PREFIX_ZKP_DL: [u8; 8] = *b"ZKP_DLxx";
const PREFIX_ZKP_MEMBERSHIP: [u8; 8] = *b"ZKP_MEMB";
const PREFIX_ZKP_DECRYPTION: [u8; 8] = *b"ZKP_DECR";

fn generic_keygen<R: CryptoRng + RngCore>(rng: &mut R) -> (Scalar, EdwardsPoint) {
    let x = Scalar::random(rng);
    let y = x * G;
    (x, y)
}

// TODO(kc1212): impl Sum for tuple
pub(crate) fn sum_tuple<I, T>(xs: I) -> (T, T)
    where
        I: Iterator<Item=(T, T)>,
        T: Identity + Copy + Add<Output=T>
{
    let mut out = (T::identity(), T::identity());
    for x in xs {
        out = (out.0 + x.0, out.1 + x.1);
    }
    out
}

pub(crate) fn get_id(h: &EdwardsPoint) -> [u8; 32] {
    h.compress().to_bytes()
}

pub(crate) fn brute_force_dlog(gv: &EdwardsPoint, upper_bound: usize) -> Option<u32> {
    let mut tmp = Scalar::zero();
    for i in 0..upper_bound {
        if tmp * G == *gv {
            return Some(i as u32);
        }
        tmp += Scalar::one();
    }
    None
}

pub(crate) fn share<R: CryptoRng + RngCore>(rng: &mut R, t: usize) -> (Scalar, Vec<Scalar>) {
    let x = Scalar::random(rng);
    let mut shares: Vec<Scalar> = (0..t - 1).map(|_| Scalar::random(rng)).collect();
    let tmp_sum: Scalar = shares.iter().sum();
    shares.push(tmp_sum - x);
    (x, shares)
}

/// An additively homomorphic ElGamal cipher that encrypts binary messages.
pub mod binary_cipher {
    use super::*;

    /// Generate a private and a public key.
    ///
    /// # Arguments
    /// * `rng` - A cryptographic PRNG.
    pub fn keygen<R: CryptoRng + RngCore>(rng: &mut R) -> (Scalar, EdwardsPoint) {
        generic_keygen(rng)
    }

    /// Encrypt a binary message using a given randomness `r`.
    ///
    /// # Arguments
    /// * `pk` - A public key.
    /// * `msg` - A binary message.
    /// * `r` - Randomness used in encryption.
    pub fn encrypt_with_r(pk: &EdwardsPoint, msg: bool, r: &Scalar) -> (EdwardsPoint, EdwardsPoint) {
        let b = msg as u32;
        (r * G, r * pk + Scalar::from(b) * G)
    }

    /// Encrypt a binary message.
    ///
    /// # Arguments
    /// * `rng` - A cryptographic PRNG.
    /// * `pk` - A public key.
    /// * `msg` - A binary message.
    pub fn encrypt<R: CryptoRng + RngCore>(rng: &mut R, pk: &EdwardsPoint, msg: bool) -> (EdwardsPoint, EdwardsPoint) {
        let r = Scalar::random(rng);
        encrypt_with_r(pk, msg, &r)
    }

    /// Decrypt a ciphertext.
    /// The returned plaintext does not have to be binary due to the homomorphic property of ElGamal.
    ///
    /// # Arguments
    /// * `sk` - The secret key.
    /// * `ct` - The ElGamal ciphertext.
    /// * `upper_bound` - The upperbound on the plaintext.
    pub fn decrypt(sk: &Scalar, ct: &(EdwardsPoint, EdwardsPoint), upper_bound: usize) -> Option<u32> {
        let (a, b) = ct;
        let gv = b - (sk * a);
        brute_force_dlog(&gv, upper_bound)
    }
}

/// Module for signing and verifying a Schnorr signature.
pub mod schnorr {
    use super::*;

    pub type Signature = (Scalar, Scalar);

    /// Generate a signing key and a verification key.
    ///
    /// # Arguments
    /// * `rng` - A cryptographic PRNG.
    pub fn keygen<R: CryptoRng + RngCore>(rng: &mut R) -> (Scalar, EdwardsPoint) {
        generic_keygen(rng)
    }

    /// Sign a message and output a signature.
    ///
    /// # Arguments
    /// * `rng` - A cryptographic PRNG.
    /// * `sk` - The secret key.
    /// * `msg` - The message as a byte slice.
    pub fn sign<R: CryptoRng + RngCore>(rng: &mut R, sk: &Scalar, msg: &[u8]) -> Signature {
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

    /// Sign two points and output a signature.
    ///
    /// # Arguments
    /// * `rng` - A cryptographic PRNG.
    /// * `sk` - The secret key.
    /// * `ct` - Two curve points.
    pub fn sign_ct<R: CryptoRng + RngCore>(rng: &mut R, sk: &Scalar, ct: &(EdwardsPoint, EdwardsPoint)) -> Signature {
        let mut buf = vec![];
        buf.extend_from_slice(ct.0.compress().as_bytes());
        buf.extend_from_slice(ct.1.compress().as_bytes());
        sign(rng, sk, &buf)
    }

    /// Verify a signature of a byte slice.
    ///
    /// # Arguments
    /// * `vk` - The verification key.
    /// * `msg` - The byte slice that was signed.
    /// * `sig` - The signature.
    pub fn verify(vk: &EdwardsPoint, msg: &[u8], signature: &Signature) -> bool {
        let (r, c) = signature;
        let a = r * G + c * vk;
        let mut buf = vec![]; // TODO(kc1212): consider remove the extra copying
        buf.extend_from_slice(&PREFIX_SCHNORR);
        buf.extend_from_slice(msg);
        buf.extend_from_slice(a.compress().as_bytes());
        c == &Scalar::hash_from_bytes::<Sha3_512>(&buf)
    }

    /// Verify a signature of two points.
    ///
    /// # Arguments
    /// * `vk` - The verification key.
    /// * `ct` - The two elliptic curve points that was signed.
    /// * `sig` - The signature.
    pub fn verify_ct(vk: &EdwardsPoint, ct: &(EdwardsPoint, EdwardsPoint), signature: &Signature) -> bool {
        let mut buf = vec![];
        buf.extend_from_slice(ct.0.compress().as_bytes());
        buf.extend_from_slice(ct.1.compress().as_bytes());
        verify(vk, &buf, signature)
    }
}

/// Zero knowledge proof of knowledge of a discrete log relation.
/// Implemented according to
/// Section 2.1 <https://hal.inria.fr/hal-01576379/file/ZK-securityproof.pdf> plus Fiat-Shamir.
pub mod zkp_dl {
    use super::*;

    pub type Proof = (EdwardsPoint, Scalar);

    fn fiat_shamir(h: &EdwardsPoint, r: &EdwardsPoint) -> Scalar {
        // H(domain_separation || G || g^x || g^k)
        let mut buf = vec![];
        buf.extend_from_slice(&PREFIX_ZKP_DL);
        buf.extend_from_slice(G.compress().as_bytes());
        buf.extend_from_slice(h.compress().as_bytes());
        buf.extend_from_slice(r.compress().as_bytes());
        let e = Scalar::hash_from_bytes::<Sha3_512>(&buf);
        e
    }

    /// Prove the relation g^x = h where x is the witness
    ///
    /// # Arguments
    /// * `rng` - A cryptographic PRNG.
    /// * `x` - The witness (discrete log).
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, x: &Scalar) -> Proof {
        let k = Scalar::random(rng);
        let r = k * G;
        let h = x * G;
        let e = fiat_shamir(&h, &r);
        let s = k + x * e;
        (r, s)
    }

    /// Verify a discrete log proof.
    ///
    /// # Arguments
    /// * `h` - The public key.
    /// * `proof` - The discrete log proof for `h`.
    pub fn verify(h: &EdwardsPoint, proof: &Proof) -> bool {
        let (r, s) = proof;
        let e = fiat_shamir(&h, &r);
        r == &(s * G - e * h)
    }
}

/// Zero knowledge proof of a binary plaintext in an ElGamal ciphertext.
/// Implemented according to
/// Section 3.1 of <https://hal.inria.fr/hal-01576379/file/ZK-securityproof.pdf> plus Fiat-Shamir.
pub mod zkp_binary_ptxt {
    use super::*;

    pub type Proof = ([(EdwardsPoint, EdwardsPoint); 2], [(Scalar, Scalar); 2]);

    fn fiat_shamir(h: &EdwardsPoint, ct: &(EdwardsPoint, EdwardsPoint), commitment: &[(EdwardsPoint, EdwardsPoint); 2]) -> Scalar {
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

    /// Create a proof for the plaintext `pt` encrypted under the public key `h`.
    /// The ciphertext along with the proof is returned because the prover
    /// needs to know the randomness used in the ciphertext.
    ///
    /// # Arguments
    /// * `rng` - A cryptographic PRNG.
    /// * `h` - A public key.
    /// * `pt` - The binary plaintext.
    pub fn prove<R: CryptoRng + RngCore>(rng: &mut R, h: &EdwardsPoint, pt: bool)
                                         -> ((EdwardsPoint, EdwardsPoint), Proof) {
        let r = Scalar::random(rng);
        let ct = binary_cipher::encrypt_with_r(h, pt, &r);
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
        let e = fiat_shamir(&h, &ct, &commitment);

        let sigmai = e - sigmaj;
        let rhoi = w + r * sigmai;
        let response = if pt {
            [(sigmaj, rhoj), (sigmai, rhoi)]
        } else {
            [(sigmai, rhoi), (sigmaj, rhoj)]
        };
        (ct, (commitment, response))
    }

    /// Verify a binary plaintext proof.
    ///
    /// # Arguments
    /// * `h` - The public key.
    /// * `ct` - The ciphertext that is used for the proof.
    /// * `proof` - The binary plaintext proof.
    pub fn verify(h: &EdwardsPoint, ct: &(EdwardsPoint, EdwardsPoint), proof: &Proof) -> bool {
        let commitment = proof.0;
        let response = proof.1;
        let e = fiat_shamir(h, ct, &commitment);
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

/// Zero knowledge proof of the relation c^x = m where x is the witness.
/// The public values are c, m and h=g^x.
/// Implemented according to
/// Section 2.2 of <https://hal.inria.fr/hal-01576379/file/ZK-securityproof.pdf> plus Fiat-Shamir.
pub mod zkp_decryption {
    use super::*;

    pub type Proof = ((EdwardsPoint, EdwardsPoint), Scalar);

    fn fiat_shamir(a: &EdwardsPoint, b: &EdwardsPoint) -> Scalar {
        let mut buf = vec![];
        buf.extend_from_slice(&PREFIX_ZKP_DECRYPTION);
        buf.extend_from_slice(G.compress().as_bytes());
        buf.extend_from_slice(a.compress().as_bytes());
        buf.extend_from_slice(b.compress().as_bytes());
        let e = Scalar::hash_from_bytes::<Sha3_512>(&buf);
        e
    }

    /// Create a proof of the relation c^x = m.
    ///
    /// # Arguments
    /// * `rng` - A cryptographic PRNG.
    /// * `x` - The private key.
    /// * `c` - A point such that c^x = m.
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, x: &Scalar, c: &EdwardsPoint) -> Proof {
        let k = Scalar::random(rng);
        let (a, b) = (k * G, k * c);
        let e = fiat_shamir(&a, &b);
        let s = k + x * e;
        ((a, b), s)
    }

    /// Verify a proof of the relation c^x = m.
    ///
    /// # Arguments
    /// * `h` - This is typically the public key, e.g., g^x.
    /// * `c` - A point such that c^x = m.
    /// * `m` - A point such that c^x = m.
    /// * `proof` - The proof.
    pub fn verify(h: &EdwardsPoint, c: &EdwardsPoint, m: &EdwardsPoint, proof: &Proof) -> bool {
        let ((a, b), s) = proof;
        let e = fiat_shamir(&a, &b);
        (*a == s * G - e * h) && (*b == s * c - e * m)
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::traits::Identity;
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;

    const ORDER: Scalar = constants::BASEPOINT_ORDER;
    const MAX_PT: usize = 50;

    #[test]
    fn test_curve_identity() {
        assert_eq!(ORDER * G, EdwardsPoint::identity());
        assert_eq!(G, EdwardsPoint::identity() + G);
    }

    #[quickcheck]
    fn quickcheck_cipher(msg: bool) -> bool {
        let mut rng = ChaChaRng::from_entropy();
        let (sk, pk) = binary_cipher::keygen(&mut rng);
        let ct = binary_cipher::encrypt(&mut rng, &pk, msg);
        let pt = binary_cipher::decrypt(&sk, &ct, MAX_PT).unwrap();
        msg as u32 == pt
    }

    #[quickcheck]
    fn quickcheck_cipher_bad_key(msg: bool) -> bool {
        let mut rng = ChaChaRng::from_entropy();
        let (_, pk) = binary_cipher::keygen(&mut rng);
        let (bad_sk, _) = binary_cipher::keygen(&mut rng);
        let ct = binary_cipher::encrypt(&mut rng, &pk, msg);
        binary_cipher::decrypt(&bad_sk, &ct, 10) == None
    }

    #[quickcheck]
    fn quickcheck_cipher_homomorphism(msgs: Vec<bool>) -> TestResult {
        if msgs.len() < 1 || msgs.len() > 10 {
            return TestResult::discard();
        }

        let mut rng = ChaChaRng::from_entropy();
        let (sk, pk) = binary_cipher::keygen(&mut rng);
        let cts: Vec<(EdwardsPoint, EdwardsPoint)> = msgs.iter().map(|msg| {
            binary_cipher::encrypt(&mut rng, &pk, *msg)
        }).collect();

        let sum_ct = sum_tuple(cts.into_iter());
        let pt = binary_cipher::decrypt(&sk, &sum_ct, MAX_PT).unwrap();
        let expected = msgs.iter().map(|b| *b as u32).sum();
        TestResult::from_bool(pt == expected)
    }

    #[quickcheck]
    fn quickcheck_signature(msg: Vec<u8>) -> bool {
        let mut rng = ChaChaRng::from_entropy();
        let (sk, vk) = schnorr::keygen(&mut rng);
        let sig = schnorr::sign(&mut rng, &sk, &msg);
        schnorr::verify(&vk, &msg, &sig)
    }

    #[quickcheck]
    fn quickcheck_signature_bad_vk(msg: Vec<u8>) -> bool {
        let mut rng = ChaChaRng::from_entropy();
        let (sk, _) = schnorr::keygen(&mut rng);
        let sig = schnorr::sign(&mut rng, &sk, &msg);

        let (_, bad_vk) = schnorr::keygen(&mut rng);
        !schnorr::verify(&bad_vk, &msg, &sig)
    }

    #[quickcheck]
    fn quickcheck_signature_bad_msg(msgs: (Vec<u8>, Vec<u8>)) -> TestResult {
        if msgs.0 == msgs.1 {
            return TestResult::discard();
        }
        let mut rng = ChaChaRng::from_entropy();
        let (sk, vk) = schnorr::keygen(&mut rng);
        let sig = schnorr::sign(&mut rng, &sk, &msgs.0);
        TestResult::from_bool(!schnorr::verify(&vk, &msgs.1, &sig))
    }

    #[test]
    fn test_zkp_dl() {
        let mut rng = ChaChaRng::from_entropy();
        let x1 = Scalar::random(&mut rng);
        let h1 = x1 * G;
        let proof = zkp_dl::prove(&mut rng, &x1);
        assert!(zkp_dl::verify(&h1, &proof));

        let x2 = Scalar::random(&mut rng);
        let h2 = x2 * G;
        assert!(!zkp_dl::verify(&h2, &proof));
    }

    #[quickcheck]
    fn quickcheck_zkp_binary_ptxt(pt: bool) {
        let mut rng = ChaChaRng::from_entropy();
        let (sk, pk) = binary_cipher::keygen(&mut rng);
        let (_, bad_pk) = binary_cipher::keygen(&mut rng);
        let (ct, proof) = zkp_binary_ptxt::prove(&mut rng, &pk, pt);
        let (bad_ct, bad_proof) = zkp_binary_ptxt::prove(&mut rng, &pk, pt);

        assert!(!zkp_binary_ptxt::verify(&bad_pk, &ct, &proof));
        assert!(!zkp_binary_ptxt::verify(&pk, &bad_ct, &proof));
        assert!(!zkp_binary_ptxt::verify(&pk, &ct, &bad_proof));
        assert!(zkp_binary_ptxt::verify(&pk, &ct, &proof));
        assert_eq!(binary_cipher::decrypt(&sk, &ct, MAX_PT), Some(pt as u32));
    }

    #[test]
    fn test_zkp_decryption() {
        let mut rng = ChaChaRng::from_entropy();
        let x = Scalar::random(&mut rng);
        let h = x * G;
        let c = Scalar::random(&mut rng) * G;
        let m = x * c;
        let proof = zkp_decryption::prove(&mut rng, &x, &c);
        assert!(zkp_decryption::verify(&h, &c, &m, &proof))
    }

    #[test]
    fn test_zkp_decryption_bad_proof() {
        let mut rng = ChaChaRng::from_entropy();
        let x = Scalar::random(&mut rng);
        let h = x * G;
        let c = Scalar::random(&mut rng) * G;
        let m = x * c;
        let proof = zkp_decryption::prove(&mut rng, &x, &c);
        assert!(zkp_decryption::verify(&h, &c, &m, &proof))
    }

    #[test]
    fn test_zkp_decryption_bad_stmt() {
        let mut rng = ChaChaRng::from_entropy();
        let x = Scalar::random(&mut rng);
        let h = x * G;
        let c = Scalar::random(&mut rng) * G;
        let m = x * c;
        let proof = zkp_decryption::prove(&mut rng, &x, &c);
        assert!(zkp_decryption::verify(&h, &c, &m, &proof))
    }
}