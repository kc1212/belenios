use thiserror::Error;

#[derive(Error, Debug)]
pub enum BeleniosError {
    #[error("missing trustee public key")]
    MissingTrusteePublicKey,
    #[error("bad trustee commitments")]
    BadTrusteeCommitments,
    #[error("not enough trustee commitments")]
    NotEnoughTrusteeCommitments,
    #[error("bad discrete log proof")]
    BadDiscreteLogProof,
    #[error("invalid trustee id")]
    InvalidTrusteeID,
}