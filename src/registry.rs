use std::sync::atomic::Ordering;

use filecoin_proofs_v1::types::{PoRepConfig, PoRepProofPartitions, SectorSize};

/// Available seal proofs.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum RegisteredSealProof {
    StackedDrg32GiBV1,
}

impl RegisteredSealProof {
    /// Return the sector size for this proof.
    pub fn sector_size(&self) -> SectorSize {
        match self {
            RegisteredSealProof::StackedDrg32GiBV1 => {
                SectorSize(filecoin_proofs_v1::constants::SECTOR_SIZE_32_GIB)
            }
        }
    }

    /// Return the number of partitions for this proof.
    pub fn partitions(&self) -> u8 {
        match self {
            RegisteredSealProof::StackedDrg32GiBV1 => {
                filecoin_proofs_v1::constants::DEFAULT_POREP_PROOF_PARTITIONS
                    .load(Ordering::Relaxed)
            }
        }
    }

    pub fn as_v1_config(&self) -> PoRepConfig {
        match self {
            RegisteredSealProof::StackedDrg32GiBV1 => PoRepConfig {
                sector_size: self.sector_size(),
                partitions: PoRepProofPartitions(self.partitions()),
            },
            // _ => panic!("Can only be called on V1 configs"),
        }
    }
}
