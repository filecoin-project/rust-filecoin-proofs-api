//! Proofs library for Filecoin open blockchain network.
//!
//! This goal of the filecoin-proofs-api crate is to provide the proving and verification
//! mechanisms used within Filecoin, to ensure [Storage Providers](https://sp.filecoin.io)
//! are properly storing client data, and retaining that data over time. The ‘Proofs’ are
//! used to assert that the work was done properly, and the nodes on the network are able
//! to verify proofs to maintain trust across the distributed storage network.
//! The proving system used by Filecoin is based on [Groth16](http://www.zeroknowledgeblog.com/index.php/groth16).
//! Specific poofs include [Proof-of-Spacetime](https://spec.filecoin.io/algorithms/pos/post/),
//! and [Proof-of-Replication](https://spec.filecoin.io/algorithms/pos/porep/).
//!
//! For further information, please see the [Filecoin specification](https://spec.filecoin.io/)

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
    RegisteredAggregationProof, RegisteredPoStProof, RegisteredSealProof, RegisteredUpdateProof,
};
pub use crate::types::{PartitionProofBytes, PrivateReplicaInfo, PublicReplicaInfo};

pub use filecoin_proofs_v1::types::{
    AggregateSnarkProof, ChallengeSeed, Commitment, PaddedBytesAmount, PartitionSnarkProof,
    PieceInfo, PoStType, ProverId, Ticket, UnpaddedByteIndex, UnpaddedBytesAmount,
};
pub use filecoin_proofs_v1::{FallbackPoStSectorProof, SnarkProof, VanillaProof};
pub use fr32;
pub use storage_proofs_core::{
    api_version::{AggregateVersion, ApiFeature, ApiVersion},
    error::Error as StorageProofsError,
    merkle::{Hasher, MerkleTreeTrait},
    parameter_cache::{get_parameter_data, get_verifying_key_data},
    sector::{OrderedSectorSet, SectorId},
    util::NODE_SIZE,
};
