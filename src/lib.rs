#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::too_many_arguments)]
//requires nightly, or later stable version
//#![warn(clippy::unwrap_used)]

pub mod post;
pub mod seal;

mod registry;
mod types;

pub use crate::registry::{RegisteredPoStProof, RegisteredSealProof};
pub use crate::types::{PrivateReplicaInfo, PublicReplicaInfo};

pub use filecoin_proofs_v1::types::{
    ChallengeSeed, Commitment, PaddedBytesAmount, PieceInfo, PoStType, ProverId, Ticket,
    UnpaddedByteIndex, UnpaddedBytesAmount,
};
pub use filecoin_proofs_v1::{FallbackPoStSectorProof, SnarkProof, VanillaProof};
pub use fr32;
pub use storage_proofs_core::api_version::ApiVersion;
pub use storage_proofs_core::error::Error as StorageProofsError;
pub use storage_proofs_core::sector::{OrderedSectorSet, SectorId};
