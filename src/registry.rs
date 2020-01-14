use std::sync::atomic::Ordering;

use filecoin_proofs_v1::types::{PoRepConfig, PoRepProofPartitions, PoStConfig, SectorSize};

/// Available seal proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegisteredSealProof {
    StackedDrg32GiBV1,
}

impl RegisteredSealProof {
    /// Return the sector size for this proof.
    pub fn sector_size(self) -> SectorSize {
        match self {
            RegisteredSealProof::StackedDrg32GiBV1 => {
                SectorSize(filecoin_proofs_v1::constants::SECTOR_SIZE_32_GIB)
            }
        }
    }

    /// Return the number of partitions for this proof.
    pub fn partitions(self) -> u8 {
        match self {
            RegisteredSealProof::StackedDrg32GiBV1 => {
                filecoin_proofs_v1::constants::DEFAULT_POREP_PROOF_PARTITIONS
                    .load(Ordering::Relaxed)
            }
        }
    }

    pub fn as_v1_config(self) -> PoRepConfig {
        match self {
            RegisteredSealProof::StackedDrg32GiBV1 => PoRepConfig {
                sector_size: self.sector_size(),
                partitions: PoRepProofPartitions(self.partitions()),
            },
            // _ => panic!("Can only be called on V1 configs"),
        }
    }
}

/// Available seal proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegisteredPoStProof {
    StackedDrg32GiBV1,
}

impl RegisteredPoStProof {
    /// Return the sector size for this proof.
    pub fn sector_size(self) -> SectorSize {
        match self {
            RegisteredPoStProof::StackedDrg32GiBV1 => {
                SectorSize(filecoin_proofs_v1::constants::SECTOR_SIZE_32_GIB)
            }
        }
    }

    /// Return the number of partitions for this proof.
    pub fn partitions(self) -> u8 {
        match self {
            RegisteredPoStProof::StackedDrg32GiBV1 => 1,
        }
    }

    pub fn as_v1_config(self) -> PoStConfig {
        match self {
            RegisteredPoStProof::StackedDrg32GiBV1 => PoStConfig {
                sector_size: self.sector_size(),
                challenge_count: filecoin_proofs_v1::constants::POST_CHALLENGE_COUNT,
                challenged_nodes: filecoin_proofs_v1::constants::POST_CHALLENGED_NODES,
            },
            // _ => panic!("Can only be called on V1 configs"),
        }
    }
}

impl From<RegisteredSealProof> for RegisteredPoStProof {
    fn from(other: RegisteredSealProof) -> Self {
        match other {
            RegisteredSealProof::StackedDrg32GiBV1 => RegisteredPoStProof::StackedDrg32GiBV1,
        }
    }
}
