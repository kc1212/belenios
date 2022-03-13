use thiserror::Error;

#[derive(Error, Debug, Eq, PartialEq)]
pub enum BeleniosError {
    // trustee issues
    #[error("missing trustee share")]
    MissingTrusteeShare,
    #[error("missing trustee public key")]
    MissingTrusteePublicKey,
    #[error("bad trustee commitments")]
    BadTrusteeCommitments,
    #[error("missing trustee commitments")]
    MissingTrusteeCommitments,
    #[error("bad trustee id")]
    BadTrusteeID,
    // polling station issues
    #[error("already tallied")]
    AlreadyTallied,
    #[error("bad decryption")]
    BadDecryption,
    #[error("public key verification failed")]
    BadPublicKey,
    // voter issues
    #[error("voter does not exist")]
    NonExistentVoter,
    #[error("bad voter signature")]
    BadVoterSignature,
    #[error("missing vote")]
    MissingVote,
    // others
    #[error("bad discrete log proof")]
    BadDiscreteLogProof,
    #[error("bad decryption proof")]
    BadDecryptionProof,
    #[error("bad membership proof")]
    BadMembershipProof,
}