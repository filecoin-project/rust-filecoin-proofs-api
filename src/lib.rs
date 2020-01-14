#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::too_many_arguments)]

pub mod post;
pub mod seal;

mod registry;
mod types;

pub use crate::registry::{RegisteredPoStProof, RegisteredSealProof};
pub use crate::types::{PrivateReplicaInfo, PublicReplicaInfo};

pub use filecoin_proofs_v1::storage_proofs::election_post::Candidate;
pub use filecoin_proofs_v1::storage_proofs::fr32;
pub use filecoin_proofs_v1::storage_proofs::sector::SectorId;
pub use filecoin_proofs_v1::types::{
    ChallengeSeed, Commitment, PaddedBytesAmount, PieceInfo, ProverId, Ticket, UnpaddedByteIndex,
    UnpaddedBytesAmount,
};
pub use filecoin_proofs_v1::SnarkProof;

/// The size (in bytes) of a single partition proof.
pub const SINGLE_PARTITION_PROOF_LEN: usize =
    filecoin_proofs_v1::constants::SINGLE_PARTITION_PROOF_LEN;
