use std::path::PathBuf;

use anyhow::{ensure, Result};
use filecoin_proofs_v1::types::{PoRepConfig, PoRepProofPartitions, PoStConfig, SectorSize};
use serde::{Deserialize, Serialize};

/// Available seal proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisteredSealProof {
    StackedDrg2KiBV1,
    StackedDrg8MiBV1,
    StackedDrg512MiBV1,
    StackedDrg32GiBV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Version {
    V1,
}

impl RegisteredSealProof {
    /// Return the version for this proof.
    pub fn version(self) -> Version {
        use RegisteredSealProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1 => {
                Version::V1
            }
        }
    }

    /// Return the sector size for this proof.
    pub fn sector_size(self) -> SectorSize {
        use filecoin_proofs_v1::constants;
        use RegisteredSealProof::*;
        let size = match self {
            StackedDrg2KiBV1 => constants::SECTOR_SIZE_2_KIB,
            StackedDrg8MiBV1 => constants::SECTOR_SIZE_8_MIB,
            StackedDrg512MiBV1 => constants::SECTOR_SIZE_512_MIB,
            StackedDrg32GiBV1 => constants::SECTOR_SIZE_32_GIB,
        };
        SectorSize(size)
    }

    /// Return the number of partitions for this proof.
    pub fn partitions(self) -> u8 {
        use filecoin_proofs_v1::constants;
        use RegisteredSealProof::*;
        match self {
            StackedDrg2KiBV1 => *constants::POREP_PARTITIONS
                .read()
                .unwrap()
                .get(&constants::SECTOR_SIZE_2_KIB)
                .expect("invalid sector size"),
            StackedDrg8MiBV1 => *constants::POREP_PARTITIONS
                .read()
                .unwrap()
                .get(&constants::SECTOR_SIZE_8_MIB)
                .expect("invalid sector size"),
            StackedDrg512MiBV1 => *constants::POREP_PARTITIONS
                .read()
                .unwrap()
                .get(&constants::SECTOR_SIZE_512_MIB)
                .expect("invalid sector size"),
            StackedDrg32GiBV1 => *constants::POREP_PARTITIONS
                .read()
                .unwrap()
                .get(&constants::SECTOR_SIZE_32_GIB)
                .expect("invalid sector size"),
        }
    }

    pub fn single_partition_proof_len(self) -> usize {
        use RegisteredSealProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1 => {
                filecoin_proofs_v1::SINGLE_PARTITION_PROOF_LEN
            }
        }
    }

    pub fn as_v1_config(self) -> PoRepConfig {
        use RegisteredSealProof::*;

        assert_eq!(self.version(), Version::V1);

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1 => {
                PoRepConfig {
                    sector_size: self.sector_size(),
                    partitions: PoRepProofPartitions(self.partitions()),
                }
            } // _ => panic!("Can only be called on V1 configs"),
        }
    }

    /// Returns the circuit identifier.
    pub fn circuit_identifier(self) -> Result<String> {
        match self.version() {
            Version::V1 => self.as_v1_config().get_cache_identifier(),
        }
    }

    pub fn cache_verifying_key_path(self) -> Result<PathBuf> {
        match self.version() {
            Version::V1 => self.as_v1_config().get_cache_verifying_key_path(),
        }
    }

    pub fn cache_params_path(self) -> Result<PathBuf> {
        match self.version() {
            Version::V1 => self.as_v1_config().get_cache_params_path(),
        }
    }

    pub fn verifying_key_cid(self) -> Result<String> {
        match self.version() {
            Version::V1 => {
                let id = self.as_v1_config().get_cache_identifier()?;
                let params = filecoin_proofs_v1::constants::PARAMETERS.get(&format!("{}.vk", &id));
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.unwrap().cid.clone())
            }
        }
    }

    pub fn params_cid(self) -> Result<String> {
        match self.version() {
            Version::V1 => {
                let id = self.as_v1_config().get_cache_identifier()?;
                let params =
                    filecoin_proofs_v1::constants::PARAMETERS.get(&format!("{}.params", &id));
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.unwrap().cid.clone())
            }
        }
    }
}

/// Available seal proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisteredPoStProof {
    StackedDrg2KiBV1,
    StackedDrg8MiBV1,
    StackedDrg512MiBV1,
    StackedDrg32GiBV1,
}

impl RegisteredPoStProof {
    /// Return the version for this proof.
    pub fn version(self) -> Version {
        use RegisteredPoStProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1 => {
                Version::V1
            }
        }
    }

    /// Return the sector size for this proof.
    pub fn sector_size(self) -> SectorSize {
        use filecoin_proofs_v1::constants;
        use RegisteredPoStProof::*;

        let size = match self {
            StackedDrg2KiBV1 => constants::SECTOR_SIZE_2_KIB,
            StackedDrg8MiBV1 => constants::SECTOR_SIZE_8_MIB,
            StackedDrg512MiBV1 => constants::SECTOR_SIZE_512_MIB,
            StackedDrg32GiBV1 => constants::SECTOR_SIZE_32_GIB,
        };
        SectorSize(size)
    }

    /// Return the number of partitions for this proof.
    pub fn partitions(self) -> u8 {
        use RegisteredPoStProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1 => 1,
        }
    }

    pub fn single_partition_proof_len(self) -> usize {
        use RegisteredPoStProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1 => {
                filecoin_proofs_v1::SINGLE_PARTITION_PROOF_LEN
            }
        }
    }

    pub fn as_v1_config(self) -> PoStConfig {
        assert_eq!(self.version(), Version::V1);

        use RegisteredPoStProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1 => {
                PoStConfig {
                    sector_size: self.sector_size(),
                    challenge_count: filecoin_proofs_v1::constants::POST_CHALLENGE_COUNT,
                    challenged_nodes: filecoin_proofs_v1::constants::POST_CHALLENGED_NODES,
                    priority: true,
                }
            } // _ => panic!("Can only be called on V1 configs"),
        }
    }

    /// Returns the circuit identifier.
    pub fn circuit_identifier(self) -> Result<String> {
        match self.version() {
            Version::V1 => self.as_v1_config().get_cache_identifier(),
        }
    }

    pub fn cache_verifying_key_path(self) -> Result<PathBuf> {
        match self.version() {
            Version::V1 => self.as_v1_config().get_cache_verifying_key_path(),
        }
    }

    pub fn cache_params_path(self) -> Result<PathBuf> {
        match self.version() {
            Version::V1 => self.as_v1_config().get_cache_params_path(),
        }
    }

    pub fn verifying_key_cid(self) -> Result<String> {
        match self.version() {
            Version::V1 => {
                let id = self.as_v1_config().get_cache_identifier()?;
                let params = filecoin_proofs_v1::constants::PARAMETERS.get(&format!("{}.vk", &id));
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.unwrap().cid.clone())
            }
        }
    }

    pub fn params_cid(self) -> Result<String> {
        match self.version() {
            Version::V1 => {
                let id = self.as_v1_config().get_cache_identifier()?;
                let params =
                    filecoin_proofs_v1::constants::PARAMETERS.get(&format!("{}.params", &id));
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.unwrap().cid.clone())
            }
        }
    }
}
