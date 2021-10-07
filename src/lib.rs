#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::too_many_arguments)]
//requires nightly, or later stable version
//#![warn(clippy::unwrap_used)]
#![allow(clippy::upper_case_acronyms)]

pub mod post;
pub mod seal;
pub mod update;

mod registry;
mod types;

pub use crate::registry::{
    RegisteredAggregationProof, RegisteredEmptySectorUpdateProof, RegisteredPoStProof,
    RegisteredSealProof,
};
pub use crate::types::{PrivateReplicaInfo, PublicReplicaInfo};

pub use filecoin_proofs_v1::types::{
    AggregateSnarkProof, ChallengeSeed, Commitment, PaddedBytesAmount, PartitionSnarkProof,
    PieceInfo, PoStType, ProverId, Ticket, UnpaddedByteIndex, UnpaddedBytesAmount,
};
pub use filecoin_proofs_v1::{FallbackPoStSectorProof, SnarkProof, VanillaProof};
pub use fr32;
pub use storage_proofs_core::{
    api_version::ApiVersion,
    error::Error as StorageProofsError,
    merkle::MerkleTreeTrait,
    parameter_cache::{get_parameter_data, get_verifying_key_data},
    sector::{OrderedSectorSet, SectorId},
    util::NODE_SIZE,
};
