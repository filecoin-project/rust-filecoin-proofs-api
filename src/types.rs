//! Data types for sector replication.
use std::path::PathBuf;

use crate::{Commitment, RegisteredPoStProof};

// A byte serialized representation of a vanilla proof.
pub type VanillaProofBytes = Vec<u8>;

// A byte serialized representation of a vanilla partition proof.
#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct PartitionProofBytes(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrivateReplicaInfo {
    /// The version of this replica.
    pub(crate) registered_proof: RegisteredPoStProof,
    /// The replica commitment.
    pub(crate) comm_r: Commitment,
    /// Contains sector-specific (e.g. Merkle trees) assets.
    pub(crate) cache_dir: PathBuf,
    /// Contains the replica.
    pub(crate) replica_path: PathBuf,
}

impl PrivateReplicaInfo {
    pub fn new(
        registered_proof: RegisteredPoStProof,
        comm_r: Commitment,
        cache_dir: PathBuf,
        replica_path: PathBuf,
    ) -> Self {
        PrivateReplicaInfo {
            registered_proof,
            comm_r,
            cache_dir,
            replica_path,
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
