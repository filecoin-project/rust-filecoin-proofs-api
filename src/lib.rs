#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::too_many_arguments)]
//requires nightly, or later stable version
//#![warn(clippy::unwrap_used)]
#![allow(clippy::upper_case_acronyms)]

pub mod post;
pub mod seal;

mod registry;
mod types;

pub use crate::registry::{RegisteredPoStProof, RegisteredSealProof};
pub use crate::types::{PrivateReplicaInfo, PublicReplicaInfo};

pub use filecoin_proofs_v1::types::{
    AggregateSnarkProof, ChallengeSeed, Commitment, PaddedBytesAmount, PieceInfo, PoStType,
    ProverId, Ticket, UnpaddedByteIndex, UnpaddedBytesAmount,
};
pub use filecoin_proofs_v1::{FallbackPoStSectorProof, SnarkProof, VanillaProof};
pub use fr32;
pub use storage_proofs_core::error::Error as StorageProofsError;
pub use storage_proofs_core::sector::{OrderedSectorSet, SectorId};
pub use storage_proofs_core::{
    api_version::ApiVersion, merkle::MerkleTreeTrait, parameter_cache::get_parameter_data,
    parameter_cache::get_verifying_key_data, util::NODE_SIZE,
};
