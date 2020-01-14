use std::path::PathBuf;

use crate::{Commitment, RegisteredPoStProof};

/// The minimal information required about a replica, in order to be able to generate
/// a PoSt over it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrivateReplicaInfo {
    /// The version of this replica.
    pub(crate) registered_proof: RegisteredPoStProof,
    /// Path to the replica.
    pub(crate) access: String,
    /// The replica commitment.
    pub(crate) comm_r: Commitment,
    /// Contains sector-specific (e.g. merkle trees) assets
    pub(crate) cache_dir: PathBuf,
}

impl PrivateReplicaInfo {
    pub fn new(
        registered_proof: RegisteredPoStProof,
        access: String,
        comm_r: Commitment,
        cache_dir: PathBuf,
    ) -> Self {
        PrivateReplicaInfo {
            registered_proof,
            access,
            comm_r,
            cache_dir,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicReplicaInfo {
    /// The version of this replica.
    pub(crate) registered_proof: RegisteredPoStProof,
    /// The replica commitment.
    pub(crate) comm_r: Commitment,
}

impl PublicReplicaInfo {
    pub fn new(registered_proof: RegisteredPoStProof, comm_r: Commitment) -> Self {
        PublicReplicaInfo {
            registered_proof,
            comm_r,
        }
    }
}
