//! Data types used for Proof-of-Replication and Proof-of-Spacetime

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{ensure, Result};
use filecoin_proofs_v1::{constants, with_shape};
use filecoin_proofs_v1::{PoRepConfig, PoRepProofPartitions, PoStConfig, PoStType, SectorSize};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use crate::{get_parameter_data, get_verifying_key_data, ApiFeature, ApiVersion, MerkleTreeTrait};

/// Available seal proofs.
// Enum is append-only: once published, a `RegisteredSealProof` value must never change.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisteredSealProof {
    StackedDrg2KiBV1,
    StackedDrg8MiBV1,
    StackedDrg512MiBV1,
    StackedDrg32GiBV1,
    StackedDrg64GiBV1,

    StackedDrg2KiBV1_1,
    StackedDrg8MiBV1_1,
    StackedDrg512MiBV1_1,
    StackedDrg32GiBV1_1,
    StackedDrg64GiBV1_1,

    StackedDrg2KiBV1_1_Feat_SyntheticPoRep,
    StackedDrg8MiBV1_1_Feat_SyntheticPoRep,
    StackedDrg512MiBV1_1_Feat_SyntheticPoRep,
    StackedDrg32GiBV1_1_Feat_SyntheticPoRep,
    StackedDrg64GiBV1_1_Feat_SyntheticPoRep,
}

// This maps all registered seal proof enum types to porep_id values.
lazy_static! {
    pub static ref REGISTERED_PROOF_IDS: HashMap<RegisteredSealProof, u64> = vec![
        (RegisteredSealProof::StackedDrg2KiBV1, 0),
        (RegisteredSealProof::StackedDrg8MiBV1, 1),
        (RegisteredSealProof::StackedDrg512MiBV1, 2),
        (RegisteredSealProof::StackedDrg32GiBV1, 3),
        (RegisteredSealProof::StackedDrg64GiBV1, 4),
        (RegisteredSealProof::StackedDrg2KiBV1_1, 5),
        (RegisteredSealProof::StackedDrg8MiBV1_1, 6),
        (RegisteredSealProof::StackedDrg512MiBV1_1, 7),
        (RegisteredSealProof::StackedDrg32GiBV1_1, 8),
        (RegisteredSealProof::StackedDrg64GiBV1_1, 9),
        (
            RegisteredSealProof::StackedDrg2KiBV1_1_Feat_SyntheticPoRep,
            10
        ),
        (
            RegisteredSealProof::StackedDrg8MiBV1_1_Feat_SyntheticPoRep,
            11
        ),
        (
            RegisteredSealProof::StackedDrg512MiBV1_1_Feat_SyntheticPoRep,
            12
        ),
        (
            RegisteredSealProof::StackedDrg32GiBV1_1_Feat_SyntheticPoRep,
            13
        ),
        (
            RegisteredSealProof::StackedDrg64GiBV1_1_Feat_SyntheticPoRep,
            14
        ),
    ]
    .into_iter()
    .collect();
}

/// Available aggregation of zk-SNARK proofs.
// Enum is append-only: once published, a `RegisteredAggregationProof` value must never change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisteredAggregationProof {
    SnarkPackV1,
    SnarkPackV2,
}

/// Available proofs for updating sectors
// Enum is append-only: once published, a `RegisteredUpdateProof` value must never change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisteredUpdateProof {
    // Note: StackedDrg*V1 maps to api version V1_1
    StackedDrg2KiBV1,
    StackedDrg8MiBV1,
    StackedDrg512MiBV1,
    StackedDrg32GiBV1,
    StackedDrg64GiBV1,
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
    pub fn version(self) -> ApiVersion {
        use RegisteredSealProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1
            | StackedDrg64GiBV1 => ApiVersion::V1_0_0,
            StackedDrg2KiBV1_1
            | StackedDrg8MiBV1_1
            | StackedDrg512MiBV1_1
            | StackedDrg32GiBV1_1
            | StackedDrg64GiBV1_1
            | StackedDrg2KiBV1_1_Feat_SyntheticPoRep
            | StackedDrg8MiBV1_1_Feat_SyntheticPoRep
            | StackedDrg512MiBV1_1_Feat_SyntheticPoRep
            | StackedDrg32GiBV1_1_Feat_SyntheticPoRep
            | StackedDrg64GiBV1_1_Feat_SyntheticPoRep => ApiVersion::V1_1_0,
        }
    }

    /// Return the major version for this proof.
    pub fn major_version(self) -> u64 {
        self.version().as_semver().major
    }

    /// Return the minor version for this proof.
    pub fn minor_version(self) -> u64 {
        self.version().as_semver().minor
    }

    /// Return the patch version for this proof.
    pub fn patch_version(self) -> u64 {
        self.version().as_semver().patch
    }

    /// Return the sector size for this proof.
    pub fn sector_size(self) -> SectorSize {
        use RegisteredSealProof::*;
        let size = match self {
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 | StackedDrg2KiBV1_1_Feat_SyntheticPoRep => {
                constants::SECTOR_SIZE_2_KIB
            }
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 | StackedDrg8MiBV1_1_Feat_SyntheticPoRep => {
                constants::SECTOR_SIZE_8_MIB
            }
            StackedDrg512MiBV1
            | StackedDrg512MiBV1_1
            | StackedDrg512MiBV1_1_Feat_SyntheticPoRep => constants::SECTOR_SIZE_512_MIB,
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 | StackedDrg32GiBV1_1_Feat_SyntheticPoRep => {
                constants::SECTOR_SIZE_32_GIB
            }
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 | StackedDrg64GiBV1_1_Feat_SyntheticPoRep => {
                constants::SECTOR_SIZE_64_GIB
            }
        };
        SectorSize(size)
    }

    /// Return the number of partitions for this proof.
    pub fn partitions(self) -> u8 {
        use RegisteredSealProof::*;
        match self {
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 | StackedDrg2KiBV1_1_Feat_SyntheticPoRep => {
                *constants::POREP_PARTITIONS
                    .read()
                    .expect("porep partitions read error")
                    .get(&constants::SECTOR_SIZE_2_KIB)
                    .expect("invalid sector size")
            }
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 | StackedDrg8MiBV1_1_Feat_SyntheticPoRep => {
                *constants::POREP_PARTITIONS
                    .read()
                    .expect("porep partitions read error")
                    .get(&constants::SECTOR_SIZE_8_MIB)
                    .expect("invalid sector size")
            }
            StackedDrg512MiBV1
            | StackedDrg512MiBV1_1
            | StackedDrg512MiBV1_1_Feat_SyntheticPoRep => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_512_MIB)
                .expect("invalid sector size"),
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 | StackedDrg32GiBV1_1_Feat_SyntheticPoRep => {
                *constants::POREP_PARTITIONS
                    .read()
                    .expect("porep partitions read error")
                    .get(&constants::SECTOR_SIZE_32_GIB)
                    .expect("invalid sector size")
            }
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 | StackedDrg64GiBV1_1_Feat_SyntheticPoRep => {
                *constants::POREP_PARTITIONS
                    .read()
                    .expect("porep partitions read error")
                    .get(&constants::SECTOR_SIZE_64_GIB)
                    .expect("invalid sector size")
            }
        }
    }

    /// Returns the size of a single zk-SNARK proof in bytes.
    pub fn single_partition_proof_len(self) -> usize {
        use RegisteredSealProof::*;

        match self {
            StackedDrg2KiBV1
            | StackedDrg8MiBV1
            | StackedDrg512MiBV1
            | StackedDrg32GiBV1
            | StackedDrg64GiBV1
            | StackedDrg2KiBV1_1
            | StackedDrg8MiBV1_1
            | StackedDrg512MiBV1_1
            | StackedDrg32GiBV1_1
            | StackedDrg64GiBV1_1
            | StackedDrg2KiBV1_1_Feat_SyntheticPoRep
            | StackedDrg8MiBV1_1_Feat_SyntheticPoRep
            | StackedDrg512MiBV1_1_Feat_SyntheticPoRep
            | StackedDrg32GiBV1_1_Feat_SyntheticPoRep
            | StackedDrg64GiBV1_1_Feat_SyntheticPoRep => {
                filecoin_proofs_v1::SINGLE_PARTITION_PROOF_LEN
            }
        }
    }

    fn nonce(self) -> u64 {
        #[allow(clippy::match_single_binding)]
        match self {
            // If we ever need to change the nonce for any given RegisteredSealProof, match it here.
            _ => 0,
        }
    }

    fn porep_id(self) -> [u8; 32] {
        let mut porep_id = [0; 32];
        let registered_proof_id = REGISTERED_PROOF_IDS
            .get(&self)
            .expect("unknown registered proof type!");
        let nonce = self.nonce();

        porep_id[0..8].copy_from_slice(&registered_proof_id.to_le_bytes());
        porep_id[8..16].copy_from_slice(&nonce.to_le_bytes());
        porep_id
    }

    /// Returns the PoRepConfig with correct Proof-of-Replication settings for this seal proof type.
    pub fn as_v1_config(self) -> PoRepConfig {
        use RegisteredSealProof::*;
        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1
            | StackedDrg64GiBV1 => {
                assert_eq!(self.version(), ApiVersion::V1_0_0);
                PoRepConfig {
                    sector_size: self.sector_size(),
                    partitions: PoRepProofPartitions(self.partitions()),
                    porep_id: self.porep_id(),
                    api_version: self.version(),
                    api_features: Vec::new(),
                }
            }
            StackedDrg2KiBV1_1 | StackedDrg8MiBV1_1 | StackedDrg512MiBV1_1
            | StackedDrg32GiBV1_1 | StackedDrg64GiBV1_1 => {
                assert_eq!(self.version(), ApiVersion::V1_1_0);
                PoRepConfig {
                    sector_size: self.sector_size(),
                    partitions: PoRepProofPartitions(self.partitions()),
                    porep_id: self.porep_id(),
                    api_version: self.version(),
                    api_features: Vec::new(),
                }
            }
            StackedDrg2KiBV1_1_Feat_SyntheticPoRep
            | StackedDrg8MiBV1_1_Feat_SyntheticPoRep
            | StackedDrg512MiBV1_1_Feat_SyntheticPoRep
            | StackedDrg32GiBV1_1_Feat_SyntheticPoRep
            | StackedDrg64GiBV1_1_Feat_SyntheticPoRep => {
                assert_eq!(self.version(), ApiVersion::V1_1_0);
                PoRepConfig {
                    sector_size: self.sector_size(),
                    partitions: PoRepProofPartitions(self.partitions()),
                    porep_id: self.porep_id(),
                    api_version: self.version(),
                    api_features: vec![ApiFeature::SyntheticPoRep],
                }
            } // _ => panic!("Can only be called on V1 configs"),
        }
    }

    /// Returns if the feature is enabled based on the proof type
    pub fn feature_enabled(self, api_feature: ApiFeature) -> bool {
        self.as_v1_config().api_features.contains(&api_feature)
    }

    /// Returns the circuit identifier.
    pub fn circuit_identifier(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 | ApiVersion::V1_2_0 => {
                self_shape!(get_cache_identifier, RegisteredSealProof, self, String)
            }
        }
    }

    /// Returns the expected file path of the verifying key (*.vk file) for the seal proof. By default
    /// this will be in the folder /var/tmp/filecoin-proof-parameters/ unless the default is changed by
    /// setting the environment variable FIL_PROOFS_PARAMETER_CACHE.
    pub fn cache_verifying_key_path(self) -> Result<PathBuf> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 | ApiVersion::V1_2_0 => self_shape!(
                get_cache_verifying_key_path,
                RegisteredSealProof,
                self,
                PathBuf
            ),
        }
    }

    /// Returns the expected file path of the params file (*.params) for the seal proof. By default
    /// this will be in the folder /var/tmp/filecoin-proof-parameters/ unless the default is changed by
    /// setting the environment variable FIL_PROOFS_PARAMETER_CACHE.
    pub fn cache_params_path(self) -> Result<PathBuf> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 | ApiVersion::V1_2_0 => {
                self_shape!(get_cache_params_path, RegisteredSealProof, self, PathBuf)
            }
        }
    }

    /// Get the correct verifying key data for the circuit identifier.
    pub fn verifying_key_cid(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 | ApiVersion::V1_2_0 => {
                let id = self.circuit_identifier()?;
                let params = get_verifying_key_data(&id);
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params
                    .expect("verifying key cid params failure")
                    .cid
                    .clone())
            }
        }
    }

    /// Get the correct parameter data for the circuit identifier.
    pub fn params_cid(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 | ApiVersion::V1_2_0 => {
                let id = self.circuit_identifier()?;
                let params = get_parameter_data(&id);
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.expect("param cid failure").cid.clone())
            }
        }
    }

    /// Returns the correct Proof-of-Spacetime window type for this seal proof.
    #[deprecated(
        since = "13.0.0",
        note = "contact the developers if this method is required"
    )]
    pub fn into_winning_post(self) -> RegisteredPoStProof {
        use RegisteredPoStProof::*;
        use RegisteredSealProof::*;
        match self {
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 | StackedDrg2KiBV1_1_Feat_SyntheticPoRep => {
                StackedDrgWinning2KiBV1
            }
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 | StackedDrg8MiBV1_1_Feat_SyntheticPoRep => {
                StackedDrgWinning8MiBV1
            }
            StackedDrg512MiBV1
            | StackedDrg512MiBV1_1
            | StackedDrg512MiBV1_1_Feat_SyntheticPoRep => StackedDrgWinning512MiBV1,
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 | StackedDrg32GiBV1_1_Feat_SyntheticPoRep => {
                StackedDrgWinning32GiBV1
            }
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 | StackedDrg64GiBV1_1_Feat_SyntheticPoRep => {
                StackedDrgWinning64GiBV1
            }
        }
    }

    // Returns the correct Proof-of-Spacetime window proof type for this seal proof.
    //
    // This call is deprecated, as it can no longer do the right thing
    // without a new SealProof type to map to WindowPoSt V1_2_0.
    #[deprecated(
        since = "13.0.0",
        note = "contact the developers if this method is required"
    )]
    pub fn into_window_post(self) -> RegisteredPoStProof {
        use RegisteredPoStProof::*;
        use RegisteredSealProof::*;
        match self {
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 | StackedDrg2KiBV1_1_Feat_SyntheticPoRep => {
                StackedDrgWindow2KiBV1_2
            }
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 | StackedDrg8MiBV1_1_Feat_SyntheticPoRep => {
                StackedDrgWindow8MiBV1_2
            }
            StackedDrg512MiBV1
            | StackedDrg512MiBV1_1
            | StackedDrg512MiBV1_1_Feat_SyntheticPoRep => StackedDrgWindow512MiBV1_2,
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 | StackedDrg32GiBV1_1_Feat_SyntheticPoRep => {
                StackedDrgWindow32GiBV1_2
            }
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 | StackedDrg64GiBV1_1_Feat_SyntheticPoRep => {
                StackedDrgWindow64GiBV1_2
            }
        }
    }
}

/// Available PoSt proofs.
// Enum is append-only: once published, a `RegisteredPoStProof` value must never change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisteredPoStProof {
    StackedDrgWinning2KiBV1,
    StackedDrgWinning8MiBV1,
    StackedDrgWinning512MiBV1,
    StackedDrgWinning32GiBV1,
    StackedDrgWinning64GiBV1,

    StackedDrgWindow2KiBV1,
    StackedDrgWindow8MiBV1,
    StackedDrgWindow512MiBV1,
    StackedDrgWindow32GiBV1,
    StackedDrgWindow64GiBV1,

    // WindowPoSt uses V1_2 to fix the grindability issue.
    StackedDrgWindow2KiBV1_2,
    StackedDrgWindow8MiBV1_2,
    StackedDrgWindow512MiBV1_2,
    StackedDrgWindow32GiBV1_2,
    StackedDrgWindow64GiBV1_2,
}

impl RegisteredPoStProof {
    /// Return the version for this proof.
    pub fn version(self) -> ApiVersion {
        use RegisteredPoStProof::*;

        match self {
            StackedDrgWinning2KiBV1
            | StackedDrgWinning8MiBV1
            | StackedDrgWinning512MiBV1
            | StackedDrgWinning32GiBV1
            | StackedDrgWinning64GiBV1
            | StackedDrgWindow2KiBV1
            | StackedDrgWindow8MiBV1
            | StackedDrgWindow512MiBV1
            | StackedDrgWindow32GiBV1
            | StackedDrgWindow64GiBV1 => ApiVersion::V1_0_0,
            StackedDrgWindow2KiBV1_2
            | StackedDrgWindow8MiBV1_2
            | StackedDrgWindow512MiBV1_2
            | StackedDrgWindow32GiBV1_2
            | StackedDrgWindow64GiBV1_2 => ApiVersion::V1_2_0,
        }
    }

    /// Return the major version for this proof.
    pub fn major_version(self) -> u64 {
        self.version().as_semver().major
    }

    /// Return the minor version for this proof.
    pub fn minor_version(self) -> u64 {
        self.version().as_semver().minor
    }

    /// Return the patch version for this proof.
    pub fn patch_version(self) -> u64 {
        self.version().as_semver().patch
    }

    /// Return the sector size for this proof.
    pub fn sector_size(self) -> SectorSize {
        use RegisteredPoStProof::*;

        let size = match self {
            StackedDrgWinning2KiBV1 | StackedDrgWindow2KiBV1 | StackedDrgWindow2KiBV1_2 => {
                constants::SECTOR_SIZE_2_KIB
            }
            StackedDrgWinning8MiBV1 | StackedDrgWindow8MiBV1 | StackedDrgWindow8MiBV1_2 => {
                constants::SECTOR_SIZE_8_MIB
            }
            StackedDrgWinning512MiBV1 | StackedDrgWindow512MiBV1 | StackedDrgWindow512MiBV1_2 => {
                constants::SECTOR_SIZE_512_MIB
            }
            StackedDrgWinning32GiBV1 | StackedDrgWindow32GiBV1 | StackedDrgWindow32GiBV1_2 => {
                constants::SECTOR_SIZE_32_GIB
            }
            StackedDrgWinning64GiBV1 | StackedDrgWindow64GiBV1 | StackedDrgWindow64GiBV1_2 => {
                constants::SECTOR_SIZE_64_GIB
            }
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
            | StackedDrgWinning32GiBV1
            | StackedDrgWinning64GiBV1 => PoStType::Winning,
            StackedDrgWindow2KiBV1
            | StackedDrgWindow8MiBV1
            | StackedDrgWindow512MiBV1
            | StackedDrgWindow32GiBV1
            | StackedDrgWindow64GiBV1
            | StackedDrgWindow2KiBV1_2
            | StackedDrgWindow8MiBV1_2
            | StackedDrgWindow512MiBV1_2
            | StackedDrgWindow32GiBV1_2
            | StackedDrgWindow64GiBV1_2 => PoStType::Window,
        }
    }

    // Return the proof length for a single partition in bytes.
    pub fn single_partition_proof_len(self) -> usize {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_2_0 => {
                filecoin_proofs_v1::SINGLE_PARTITION_PROOF_LEN
            }
            _ => panic!("Invalid PoSt api version"),
        }
    }

    /// Return the sector count for this proof.
    pub fn sector_count(self) -> usize {
        use RegisteredPoStProof::*;

        match self {
            StackedDrgWinning2KiBV1
            | StackedDrgWinning8MiBV1
            | StackedDrgWinning512MiBV1
            | StackedDrgWinning32GiBV1
            | StackedDrgWinning64GiBV1 => constants::WINNING_POST_SECTOR_COUNT,
            StackedDrgWindow2KiBV1
            | StackedDrgWindow8MiBV1
            | StackedDrgWindow512MiBV1
            | StackedDrgWindow32GiBV1
            | StackedDrgWindow64GiBV1
            | StackedDrgWindow2KiBV1_2
            | StackedDrgWindow8MiBV1_2
            | StackedDrgWindow512MiBV1_2
            | StackedDrgWindow32GiBV1_2
            | StackedDrgWindow64GiBV1_2 => *constants::WINDOW_POST_SECTOR_COUNT
                .read()
                .expect("window post sector count failure")
                .get(&u64::from(self.sector_size()))
                .expect("invalid sector size"),
        }
    }

    /// Returns the PoStConfig with correct Proof-of-Spacetime settings for this proof type.
    pub fn as_v1_config(self) -> PoStConfig {
        // PoSt did not change between ApiVersion V1_0_0 and V1_1_0.
        // Before adding the set of StackedDrgWindow*V1_2 registered
        // PoSt Proof types, there was no way to signal to Proofs that
        // different behaviour was expected.  Now that there is an
        // update in PoSt in ApiVersion::V1_2_0, we allow the new PoSt
        // version to be used.  It's not technically incorrect for the
        // ApiVersion to be V1_1_0, but there is currently no way to
        // wire that in via registered PoSt Proof types.
        assert!(
            self.version() == ApiVersion::V1_0_0 || self.version() == ApiVersion::V1_2_0,
            "Unsupported V1 PoSt Api version"
        );

        use RegisteredPoStProof::*;

        match self {
            StackedDrgWinning2KiBV1
            | StackedDrgWinning8MiBV1
            | StackedDrgWinning512MiBV1
            | StackedDrgWinning32GiBV1
            | StackedDrgWinning64GiBV1 => PoStConfig {
                typ: self.typ(),
                sector_size: self.sector_size(),
                sector_count: self.sector_count(),
                challenge_count: constants::WINNING_POST_CHALLENGE_COUNT,
                priority: true,
                api_version: self.version(),
            },
            StackedDrgWindow2KiBV1
            | StackedDrgWindow8MiBV1
            | StackedDrgWindow512MiBV1
            | StackedDrgWindow32GiBV1
            | StackedDrgWindow64GiBV1
            | StackedDrgWindow2KiBV1_2
            | StackedDrgWindow8MiBV1_2
            | StackedDrgWindow512MiBV1_2
            | StackedDrgWindow32GiBV1_2
            | StackedDrgWindow64GiBV1_2 => PoStConfig {
                typ: self.typ(),
                sector_size: self.sector_size(),
                sector_count: self.sector_count(),
                challenge_count: constants::WINDOW_POST_CHALLENGE_COUNT,
                priority: true,
                api_version: self.version(),
            }, // _ => panic!("Can only be called on V1 configs"),
        }
    }

    /// Returns the circuit identifier.
    pub fn circuit_identifier(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_2_0 => {
                self_shape!(get_cache_identifier, RegisteredPoStProof, self, String)
            }
            _ => panic!("Invalid PoSt api version"),
        }
    }

    /// Returns the expected file path of the verifying key (*.vk file) for this PoSt proof. By default
    /// this will be in the folder /var/tmp/filecoin-proof-parameters/ unless the default is changed by
    /// setting the environment variable FIL_PROOFS_PARAMETER_CACHE.
    pub fn cache_verifying_key_path(self) -> Result<PathBuf> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_2_0 => self_shape!(
                get_cache_verifying_key_path,
                RegisteredPoStProof,
                self,
                PathBuf
            ),
            _ => panic!("Invalid PoSt api version"),
        }
    }

    /// Returns the expected file path of the params file (*.params) for the PoSt proof. By default
    /// this will be in the folder /var/tmp/filecoin-proof-parameters/ unless the default is changed by
    /// setting the environment variable FIL_PROOFS_PARAMETER_CACHE.
    pub fn cache_params_path(self) -> Result<PathBuf> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_2_0 => {
                self_shape!(get_cache_params_path, RegisteredPoStProof, self, PathBuf)
            }
            _ => panic!("Invalid PoSt api version"),
        }
    }

    /// Get the correct verifying key data for the circuit identifier.
    pub fn verifying_key_cid(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_2_0 => {
                let id = self.circuit_identifier()?;
                let params = get_verifying_key_data(&id);
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params
                    .expect("verifying key cid params failure")
                    .cid
                    .clone())
            }
            _ => panic!("Invalid PoSt api version"),
        }
    }

    /// Get the correct parameter data for the circuit identifier.
    pub fn params_cid(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_2_0 => {
                let id = self.circuit_identifier()?;
                let params = get_parameter_data(&id);
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.expect("params cid failure").cid.clone())
            }
            _ => panic!("Invalid PoSt api version"),
        }
    }
}

impl RegisteredUpdateProof {
    /// Return the version for this proof.
    pub fn version(self) -> ApiVersion {
        use RegisteredUpdateProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1
            | StackedDrg64GiBV1 => ApiVersion::V1_2_0,
        }
    }

    /// Return the major version for this proof.
    pub fn major_version(self) -> u64 {
        self.version().as_semver().major
    }

    /// Return the minor version for this proof.
    pub fn minor_version(self) -> u64 {
        self.version().as_semver().minor
    }

    /// Return the patch version for this proof.
    pub fn patch_version(self) -> u64 {
        self.version().as_semver().patch
    }

    /// Return the sector size for this proof.
    pub fn sector_size(self) -> SectorSize {
        use RegisteredUpdateProof::*;
        let size = match self {
            StackedDrg2KiBV1 => constants::SECTOR_SIZE_2_KIB,
            StackedDrg8MiBV1 => constants::SECTOR_SIZE_8_MIB,
            StackedDrg512MiBV1 => constants::SECTOR_SIZE_512_MIB,
            StackedDrg32GiBV1 => constants::SECTOR_SIZE_32_GIB,
            StackedDrg64GiBV1 => constants::SECTOR_SIZE_64_GIB,
        };
        SectorSize(size)
    }

    /// Return the number of partitions for this proof.
    pub fn partitions(self) -> u8 {
        use RegisteredUpdateProof::*;
        match self {
            StackedDrg2KiBV1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_2_KIB)
                .expect("invalid sector size"),
            StackedDrg8MiBV1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_8_MIB)
                .expect("invalid sector size"),
            StackedDrg512MiBV1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_512_MIB)
                .expect("invalid sector size"),
            StackedDrg32GiBV1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_32_GIB)
                .expect("invalid sector size"),
            StackedDrg64GiBV1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_64_GIB)
                .expect("invalid sector size"),
        }
    }

    /// Returns length of proof for a single partition in bytes.
    pub fn single_partition_proof_len(self) -> usize {
        use RegisteredUpdateProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1
            | StackedDrg64GiBV1 => filecoin_proofs_v1::SINGLE_PARTITION_PROOF_LEN,
        }
    }

    /// Returns nonce value for this RegisteredUpdateProof, currently 0 but may be updated in the future.
    fn nonce(self) -> u64 {
        #[allow(clippy::match_single_binding)]
        match self {
            // If we ever need to change the nonce for any given RegisteredUpdateProof, match it here.
            _ => 0,
        }
    }

    fn porep_id(self) -> [u8; 32] {
        let mut porep_id = [0; 32];
        let registered_proof_id = self as u64;
        let nonce = self.nonce();

        porep_id[0..8].copy_from_slice(&registered_proof_id.to_le_bytes());
        porep_id[8..16].copy_from_slice(&nonce.to_le_bytes());
        porep_id
    }

    /// Returns the PoRepConfig with correct Proof-of-Replication settings for this PoRep update proof.
    pub fn as_v1_config(self) -> PoRepConfig {
        use RegisteredUpdateProof::*;
        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1
            | StackedDrg64GiBV1 => {
                assert_eq!(self.version(), ApiVersion::V1_2_0);
                PoRepConfig {
                    sector_size: self.sector_size(),
                    partitions: PoRepProofPartitions(self.partitions()),
                    porep_id: self.porep_id(),
                    api_version: self.version(),
                    api_features: Vec::new(),
                }
            } // _ => panic!("Can only be called on V1 configs"),
        }
    }

    /// Returns the circuit identifier.
    pub fn circuit_identifier(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 => panic!("Not supported on API V1.0.0"),
            ApiVersion::V1_1_0 | ApiVersion::V1_2_0 => {
                self_shape!(get_cache_identifier, RegisteredUpdateProof, self, String)
            }
        }
    }

    /// Returns the expected file path of the verifying key (*.vk file) for this PoRep update proof. By
    /// default this will be in the folder /var/tmp/filecoin-proof-parameters/ unless the default is
    /// changed by setting the environment variable FIL_PROOFS_PARAMETER_CACHE.
    pub fn cache_verifying_key_path(self) -> Result<PathBuf> {
        match self.version() {
            ApiVersion::V1_0_0 => panic!("Not supported on API V1.0.0"),
            ApiVersion::V1_1_0 | ApiVersion::V1_2_0 => self_shape!(
                get_cache_verifying_key_path,
                RegisteredUpdateProof,
                self,
                PathBuf
            ),
        }
    }

    /// Returns the expected file path of the params file (*.params) for this PoRep update proof. By
    /// default this will be in the folder /var/tmp/filecoin-proof-parameters/ unless the default is
    ///  changed by setting the environment variable FIL_PROOFS_PARAMETER_CACHE.
    pub fn cache_params_path(self) -> Result<PathBuf> {
        match self.version() {
            ApiVersion::V1_0_0 => panic!("Not supported on API V1.0.0"),
            ApiVersion::V1_1_0 | ApiVersion::V1_2_0 => {
                self_shape!(get_cache_params_path, RegisteredUpdateProof, self, PathBuf)
            }
        }
    }

    /// Get the correct verifying key data for this circuit identifier.
    pub fn verifying_key_cid(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 => panic!("Not supported on API V1.0.0"),
            ApiVersion::V1_1_0 | ApiVersion::V1_2_0 => {
                let id = self.circuit_identifier()?;
                let params = get_verifying_key_data(&id);
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params
                    .expect("verifying key cid params failure")
                    .cid
                    .clone())
            }
        }
    }

    /// Get the correct parameter data for this circuit identifier.
    pub fn params_cid(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 => panic!("Not supported on API V1.0.0"),
            ApiVersion::V1_1_0 | ApiVersion::V1_2_0 => {
                let id = self.circuit_identifier()?;
                let params = get_parameter_data(&id);
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.expect("param cid failure").cid.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use filecoin_proofs_v1::MAX_LEGACY_REGISTERED_SEAL_PROOF_ID;

    const REGISTERED_SEAL_PROOFS: [RegisteredSealProof; 15] = [
        RegisteredSealProof::StackedDrg2KiBV1,
        RegisteredSealProof::StackedDrg8MiBV1,
        RegisteredSealProof::StackedDrg512MiBV1,
        RegisteredSealProof::StackedDrg32GiBV1,
        RegisteredSealProof::StackedDrg64GiBV1,
        RegisteredSealProof::StackedDrg2KiBV1_1,
        RegisteredSealProof::StackedDrg8MiBV1_1,
        RegisteredSealProof::StackedDrg512MiBV1_1,
        RegisteredSealProof::StackedDrg32GiBV1_1,
        RegisteredSealProof::StackedDrg64GiBV1_1,
        RegisteredSealProof::StackedDrg2KiBV1_1_Feat_SyntheticPoRep,
        RegisteredSealProof::StackedDrg8MiBV1_1_Feat_SyntheticPoRep,
        RegisteredSealProof::StackedDrg512MiBV1_1_Feat_SyntheticPoRep,
        RegisteredSealProof::StackedDrg32GiBV1_1_Feat_SyntheticPoRep,
        RegisteredSealProof::StackedDrg64GiBV1_1_Feat_SyntheticPoRep,
    ];

    #[test]
    fn test_porep_id() {
        for rsp in &REGISTERED_SEAL_PROOFS {
            test_porep_id_aux(rsp);
        }
    }

    fn test_porep_id_aux(rsp: &RegisteredSealProof) {
        let expected_porep_id = match rsp {
            RegisteredSealProof::StackedDrg2KiBV1 => {
                "0000000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg8MiBV1 => {
                "0100000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg512MiBV1 => {
                "0200000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg32GiBV1 => {
                "0300000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg64GiBV1 => {
                "0400000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg2KiBV1_1 => {
                "0500000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg8MiBV1_1 => {
                "0600000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg512MiBV1_1 => {
                "0700000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg32GiBV1_1 => {
                "0800000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg64GiBV1_1 => {
                "0900000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg2KiBV1_1_Feat_SyntheticPoRep => {
                "0a00000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg8MiBV1_1_Feat_SyntheticPoRep => {
                "0b00000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg512MiBV1_1_Feat_SyntheticPoRep => {
                "0c00000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg32GiBV1_1_Feat_SyntheticPoRep => {
                "0d00000000000000000000000000000000000000000000000000000000000000"
            }
            RegisteredSealProof::StackedDrg64GiBV1_1_Feat_SyntheticPoRep => {
                "0e00000000000000000000000000000000000000000000000000000000000000"
            }
        };
        let hex: String = rsp
            .porep_id()
            .iter()
            .map(|x| format!("{:01$x}", x, 2))
            .collect();

        assert_eq!(expected_porep_id, &hex);
    }

    #[test]
    fn test_max_initial_porep_id() {
        for rsp in &REGISTERED_SEAL_PROOFS {
            let mut porep_id_type_bytes = [0u8; 8];
            let porep_id = rsp.porep_id();

            porep_id_type_bytes.copy_from_slice(&porep_id[..8]);
            let porep_type = u64::from_le_bytes(porep_id_type_bytes);

            let is_legacy = porep_type <= MAX_LEGACY_REGISTERED_SEAL_PROOF_ID;

            match rsp {
                RegisteredSealProof::StackedDrg2KiBV1
                | RegisteredSealProof::StackedDrg8MiBV1
                | RegisteredSealProof::StackedDrg512MiBV1
                | RegisteredSealProof::StackedDrg32GiBV1
                | RegisteredSealProof::StackedDrg64GiBV1 => assert!(is_legacy),

                RegisteredSealProof::StackedDrg2KiBV1_1
                | RegisteredSealProof::StackedDrg8MiBV1_1
                | RegisteredSealProof::StackedDrg512MiBV1_1
                | RegisteredSealProof::StackedDrg32GiBV1_1
                | RegisteredSealProof::StackedDrg64GiBV1_1
                | RegisteredSealProof::StackedDrg2KiBV1_1_Feat_SyntheticPoRep
                | RegisteredSealProof::StackedDrg8MiBV1_1_Feat_SyntheticPoRep
                | RegisteredSealProof::StackedDrg512MiBV1_1_Feat_SyntheticPoRep
                | RegisteredSealProof::StackedDrg32GiBV1_1_Feat_SyntheticPoRep
                | RegisteredSealProof::StackedDrg64GiBV1_1_Feat_SyntheticPoRep => {
                    assert!(!is_legacy)
                }
            }
        }
    }

    #[test]
    fn test_verifying_key_path() {
        for rsp in &REGISTERED_SEAL_PROOFS {
            rsp.cache_verifying_key_path()
                .expect("failed to get verifying key path");
        }
    }

    #[test]
    fn test_verifying_key_cid() {
        for rsp in &REGISTERED_SEAL_PROOFS {
            rsp.verifying_key_cid()
                .expect("failed to get verifying key cid");
        }
    }

    #[test]
    fn test_params_path() {
        for rsp in &REGISTERED_SEAL_PROOFS {
            rsp.cache_params_path().expect("failed to get params path");
        }
    }

    #[test]
    fn test_params_cid() {
        for rsp in &REGISTERED_SEAL_PROOFS {
            rsp.params_cid().expect("failed to get params_cid");
        }
    }
}
