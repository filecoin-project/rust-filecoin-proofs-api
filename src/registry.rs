use std::path::PathBuf;

use anyhow::{ensure, Result};
use filecoin_proofs_v1::types::{
    MerkleTreeTrait, PoRepConfig, PoRepProofPartitions, PoStConfig, PoStType, SectorSize,
};
use filecoin_proofs_v1::{constants, with_shape};
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

// Hack to delegate to self config types.
macro_rules! self_shape {
    ($name:ident, $selfty:ty, $self:expr, $ret:ty) => {{
        fn $name<Tree: 'static + MerkleTreeTrait>(s: $selfty) -> Result<$ret> {
            s.as_v1_config().$name::<Tree>()
        }

        with_shape!(u64::from($self.sector_size()), $name, $self)
    }};
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
            Version::V1 => self_shape!(get_cache_identifier, RegisteredSealProof, self, String),
        }
    }

    pub fn cache_verifying_key_path(self) -> Result<PathBuf> {
        match self.version() {
            Version::V1 => self_shape!(
                get_cache_verifying_key_path,
                RegisteredSealProof,
                self,
                PathBuf
            ),
        }
    }

    pub fn cache_params_path(self) -> Result<PathBuf> {
        match self.version() {
            Version::V1 => self_shape!(get_cache_params_path, RegisteredSealProof, self, PathBuf),
        }
    }

    pub fn verifying_key_cid(self) -> Result<String> {
        match self.version() {
            Version::V1 => {
                let id = self.circuit_identifier()?;
                let params = filecoin_proofs_v1::constants::PARAMETERS.get(&format!("{}.vk", &id));
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.unwrap().cid.clone())
            }
        }
    }

    pub fn params_cid(self) -> Result<String> {
        match self.version() {
            Version::V1 => {
                let id = self.circuit_identifier()?;
                let params =
                    filecoin_proofs_v1::constants::PARAMETERS.get(&format!("{}.params", &id));
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.unwrap().cid.clone())
            }
        }
    }

    pub fn into_winning_post(self) -> RegisteredPoStProof {
        use RegisteredPoStProof::*;
        use RegisteredSealProof::*;
        match self {
            StackedDrg2KiBV1 => StackedDrgWinning2KiBV1,
            StackedDrg8MiBV1 => StackedDrgWinning8MiBV1,
            StackedDrg512MiBV1 => StackedDrgWinning512MiBV1,
            StackedDrg32GiBV1 => StackedDrgWinning32GiBV1,
        }
    }

    pub fn into_window_post(self) -> RegisteredPoStProof {
        use RegisteredPoStProof::*;
        use RegisteredSealProof::*;
        match self {
            StackedDrg2KiBV1 => StackedDrgWindow2KiBV1,
            StackedDrg8MiBV1 => StackedDrgWindow8MiBV1,
            StackedDrg512MiBV1 => StackedDrgWindow512MiBV1,
            StackedDrg32GiBV1 => StackedDrgWindow32GiBV1,
        }
    }
}

/// Available seal proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisteredPoStProof {
    StackedDrgWinning2KiBV1,
    StackedDrgWinning8MiBV1,
    StackedDrgWinning512MiBV1,
    StackedDrgWinning32GiBV1,
    StackedDrgWindow2KiBV1,
    StackedDrgWindow8MiBV1,
    StackedDrgWindow512MiBV1,
    StackedDrgWindow32GiBV1,
}

impl RegisteredPoStProof {
    /// Return the version for this proof.
    pub fn version(self) -> Version {
        use RegisteredPoStProof::*;

        match self {
            StackedDrgWinning2KiBV1
            | StackedDrgWinning8MiBV1
            | StackedDrgWinning512MiBV1
            | StackedDrgWinning32GiBV1
            | StackedDrgWindow2KiBV1
            | StackedDrgWindow8MiBV1
            | StackedDrgWindow512MiBV1
            | StackedDrgWindow32GiBV1 => Version::V1,
        }
    }

    /// Return the sector size for this proof.
    pub fn sector_size(self) -> SectorSize {
        use RegisteredPoStProof::*;

        let size = match self {
            StackedDrgWinning2KiBV1 | StackedDrgWindow2KiBV1 => constants::SECTOR_SIZE_2_KIB,
            StackedDrgWinning8MiBV1 | StackedDrgWindow8MiBV1 => constants::SECTOR_SIZE_8_MIB,
            StackedDrgWinning512MiBV1 | StackedDrgWindow512MiBV1 => constants::SECTOR_SIZE_512_MIB,
            StackedDrgWinning32GiBV1 | StackedDrgWindow32GiBV1 => constants::SECTOR_SIZE_32_GIB,
        };
        SectorSize(size)
    }

    /// Return the PoStType  for this proof.
    pub fn typ(self) -> PoStType {
        use RegisteredPoStProof::*;
        match self {
            StackedDrgWinning2KiBV1
            | StackedDrgWinning8MiBV1
            | StackedDrgWinning512MiBV1
            | StackedDrgWinning32GiBV1 => PoStType::Winning,
            StackedDrgWindow2KiBV1
            | StackedDrgWindow8MiBV1
            | StackedDrgWindow512MiBV1
            | StackedDrgWindow32GiBV1 => PoStType::Window,
        }
    }

    pub fn single_partition_proof_len(self) -> usize {
        match self.version() {
            Version::V1 => filecoin_proofs_v1::SINGLE_PARTITION_PROOF_LEN,
        }
    }

    /// Return the sector count for this proof.
    pub fn sector_count(self) -> usize {
        use RegisteredPoStProof::*;

        match self {
            StackedDrgWinning2KiBV1
            | StackedDrgWinning8MiBV1
            | StackedDrgWinning512MiBV1
            | StackedDrgWinning32GiBV1 => constants::WINNING_POST_SECTOR_COUNT,
            StackedDrgWindow2KiBV1
            | StackedDrgWindow8MiBV1
            | StackedDrgWindow512MiBV1
            | StackedDrgWindow32GiBV1 => *constants::WINDOW_POST_SECTOR_COUNT
                .read()
                .unwrap()
                .get(&u64::from(self.sector_size()))
                .expect("invalid sector size"),
        }
    }

    pub fn as_v1_config(self) -> PoStConfig {
        assert_eq!(self.version(), Version::V1);

        use RegisteredPoStProof::*;

        match self {
            StackedDrgWinning2KiBV1
            | StackedDrgWinning8MiBV1
            | StackedDrgWinning512MiBV1
            | StackedDrgWinning32GiBV1 => PoStConfig {
                typ: self.typ(),
                sector_size: self.sector_size(),
                sector_count: self.sector_count(),
                challenge_count: constants::WINNING_POST_CHALLENGE_COUNT,
                priority: true,
            },
            StackedDrgWindow2KiBV1
            | StackedDrgWindow8MiBV1
            | StackedDrgWindow512MiBV1
            | StackedDrgWindow32GiBV1 => PoStConfig {
                typ: self.typ(),
                sector_size: self.sector_size(),
                sector_count: self.sector_count(),
                challenge_count: constants::WINDOW_POST_CHALLENGE_COUNT,
                priority: true,
            }, // _ => panic!("Can only be called on V1 configs"),
        }
    }

    /// Returns the circuit identifier.
    pub fn circuit_identifier(self) -> Result<String> {
        match self.version() {
            Version::V1 => self_shape!(get_cache_identifier, RegisteredPoStProof, self, String),
        }
    }

    pub fn cache_verifying_key_path(self) -> Result<PathBuf> {
        match self.version() {
            Version::V1 => self_shape!(
                get_cache_verifying_key_path,
                RegisteredPoStProof,
                self,
                PathBuf
            ),
        }
    }

    pub fn cache_params_path(self) -> Result<PathBuf> {
        match self.version() {
            Version::V1 => self_shape!(get_cache_params_path, RegisteredPoStProof, self, PathBuf),
        }
    }

    pub fn verifying_key_cid(self) -> Result<String> {
        match self.version() {
            Version::V1 => {
                let id = self.circuit_identifier()?;
                let params = filecoin_proofs_v1::constants::PARAMETERS.get(&format!("{}.vk", &id));
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.unwrap().cid.clone())
            }
        }
    }

    pub fn params_cid(self) -> Result<String> {
        match self.version() {
            Version::V1 => {
                let id = self.circuit_identifier()?;
                let params =
                    filecoin_proofs_v1::constants::PARAMETERS.get(&format!("{}.params", &id));
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.unwrap().cid.clone())
            }
        }
    }
}
