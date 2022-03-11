use thiserror::Error;

#[derive(Error, Debug)]
pub enum BeleniosError {
    #[error("bad trustee message")]
    BadTrusteeMessage,
    #[error("bad trustee commitments")]
    BadTrusteeCommitments,
    #[error("not enough trustee messages")]
    NotEnoughTrusteeMessages,
    #[error("not enough trustee commitments")]
    NotEnoughTrusteeCommitments,
    #[error("bad discrete log proof")]
    BadDiscreteLogProof,
}