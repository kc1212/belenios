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
    #[error("bad decryption proof")]
    BadDecryptionProof,
    #[error("invalid trustee id")]
    InvalidTrusteeID,
    #[error("voter does not exist")]
    VoterDoesNotExist,
    #[error("invalid vote")]
    InvalidVote,
    #[error("missing vote")]
    MissingVote,
    #[error("already tallied")]
    AlreadyTallied,
    #[error("cannot decrypt")]
    CannotDecrypt,
}