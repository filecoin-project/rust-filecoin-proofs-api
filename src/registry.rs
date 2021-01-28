use std::path::PathBuf;

use anyhow::{ensure, Result};
use filecoin_proofs_v1::types::{
    MerkleTreeTrait, PoRepConfig, PoRepProofPartitions, PoStConfig, PoStType, SectorSize,
};
use filecoin_proofs_v1::{constants, with_shape};
use serde::{Deserialize, Serialize};
use storage_proofs_core::api_version::ApiVersion;
use storage_proofs_core::parameter_cache::{get_parameter_data, get_verifying_key_data};

/// Available seal proofs.
/// Enum is append-only: once published, a `RegisteredSealProof` value must never change.
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
            StackedDrg2KiBV1_1 | StackedDrg8MiBV1_1 | StackedDrg512MiBV1_1
            | StackedDrg32GiBV1_1 | StackedDrg64GiBV1_1 => ApiVersion::V1_1_0,
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
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 => constants::SECTOR_SIZE_2_KIB,
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 => constants::SECTOR_SIZE_8_MIB,
            StackedDrg512MiBV1 | StackedDrg512MiBV1_1 => constants::SECTOR_SIZE_512_MIB,
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 => constants::SECTOR_SIZE_32_GIB,
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 => constants::SECTOR_SIZE_64_GIB,
        };
        SectorSize(size)
    }

    /// Return the number of partitions for this proof.
    pub fn partitions(self) -> u8 {
        use RegisteredSealProof::*;
        match self {
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_2_KIB)
                .expect("invalid sector size"),
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_8_MIB)
                .expect("invalid sector size"),
            StackedDrg512MiBV1 | StackedDrg512MiBV1_1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_512_MIB)
                .expect("invalid sector size"),
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_32_GIB)
                .expect("invalid sector size"),
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_64_GIB)
                .expect("invalid sector size"),
        }
    }

    pub fn single_partition_proof_len(self) -> usize {
        use RegisteredSealProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1
            | StackedDrg64GiBV1 | StackedDrg2KiBV1_1 | StackedDrg8MiBV1_1
            | StackedDrg512MiBV1_1 | StackedDrg32GiBV1_1 | StackedDrg64GiBV1_1 => {
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
        let registered_proof_id = self as u64;
        let nonce = self.nonce();

        porep_id[0..8].copy_from_slice(&registered_proof_id.to_le_bytes());
        porep_id[8..16].copy_from_slice(&nonce.to_le_bytes());
        porep_id
    }

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
                }
            } // _ => panic!("Can only be called on V1 configs"),
        }
    }

    /// Returns the circuit identifier.
    pub fn circuit_identifier(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 => {
                self_shape!(get_cache_identifier, RegisteredSealProof, self, String)
            }
        }
    }

    pub fn cache_verifying_key_path(self) -> Result<PathBuf> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 => self_shape!(
                get_cache_verifying_key_path,
                RegisteredSealProof,
                self,
                PathBuf
            ),
        }
    }

    pub fn cache_params_path(self) -> Result<PathBuf> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 => {
                self_shape!(get_cache_params_path, RegisteredSealProof, self, PathBuf)
            }
        }
    }

    pub fn verifying_key_cid(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 => {
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

    pub fn params_cid(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 => {
                let id = self.circuit_identifier()?;
                let params = get_parameter_data(&id);
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.expect("param cid failure").cid.clone())
            }
        }
    }

    pub fn into_winning_post(self) -> RegisteredPoStProof {
        use RegisteredPoStProof::*;
        use RegisteredSealProof::*;
        match self {
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 => StackedDrgWinning2KiBV1,
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 => StackedDrgWinning8MiBV1,
            StackedDrg512MiBV1 | StackedDrg512MiBV1_1 => StackedDrgWinning512MiBV1,
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 => StackedDrgWinning32GiBV1,
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 => StackedDrgWinning64GiBV1,
        }
    }

    pub fn into_window_post(self) -> RegisteredPoStProof {
        use RegisteredPoStProof::*;
        use RegisteredSealProof::*;
        match self {
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 => StackedDrgWindow2KiBV1,
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 => StackedDrgWindow8MiBV1,
            StackedDrg512MiBV1 | StackedDrg512MiBV1_1 => StackedDrgWindow512MiBV1,
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 => StackedDrgWindow32GiBV1,
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 => StackedDrgWindow64GiBV1,
        }
    }
}

/// Available PoSt proofs.
/// Enum is append-only: once published, a `RegisteredSealProof` value must never change.
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
            StackedDrgWinning2KiBV1 | StackedDrgWindow2KiBV1 => constants::SECTOR_SIZE_2_KIB,
            StackedDrgWinning8MiBV1 | StackedDrgWindow8MiBV1 => constants::SECTOR_SIZE_8_MIB,
            StackedDrgWinning512MiBV1 | StackedDrgWindow512MiBV1 => constants::SECTOR_SIZE_512_MIB,
            StackedDrgWinning32GiBV1 | StackedDrgWindow32GiBV1 => constants::SECTOR_SIZE_32_GIB,
            StackedDrgWinning64GiBV1 | StackedDrgWindow64GiBV1 => constants::SECTOR_SIZE_64_GIB,
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
            | StackedDrgWindow64GiBV1 => PoStType::Window,
        }
    }

    pub fn single_partition_proof_len(self) -> usize {
        match self.version() {
            ApiVersion::V1_0_0 => filecoin_proofs_v1::SINGLE_PARTITION_PROOF_LEN,
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
            | StackedDrgWindow64GiBV1 => *constants::WINDOW_POST_SECTOR_COUNT
                .read()
                .expect("window post sector count failure")
                .get(&u64::from(self.sector_size()))
                .expect("invalid sector size"),
        }
    }

    pub fn as_v1_config(self) -> PoStConfig {
        assert_eq!(self.version(), ApiVersion::V1_0_0);

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
            | StackedDrgWindow64GiBV1 => PoStConfig {
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
            ApiVersion::V1_0_0 => {
                self_shape!(get_cache_identifier, RegisteredPoStProof, self, String)
            }
            _ => panic!("Invalid PoSt api version"),
        }
    }

    pub fn cache_verifying_key_path(self) -> Result<PathBuf> {
        match self.version() {
            ApiVersion::V1_0_0 => self_shape!(
                get_cache_verifying_key_path,
                RegisteredPoStProof,
                self,
                PathBuf
            ),
            _ => panic!("Invalid PoSt api version"),
        }
    }

    pub fn cache_params_path(self) -> Result<PathBuf> {
        match self.version() {
            ApiVersion::V1_0_0 => {
                self_shape!(get_cache_params_path, RegisteredPoStProof, self, PathBuf)
            }
            _ => panic!("Invalid PoSt api version"),
        }
    }

    pub fn verifying_key_cid(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 => {
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

    pub fn params_cid(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 => {
                let id = self.circuit_identifier()?;
                let params = get_parameter_data(&id);
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.expect("params cid failure").cid.clone())
            }
            _ => panic!("Invalid PoSt api version"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use filecoin_proofs_v1::MAX_LEGACY_REGISTERED_SEAL_PROOF_ID;

    const REGISTERED_SEAL_PROOFS: [RegisteredSealProof; 10] = [
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
                | RegisteredSealProof::StackedDrg64GiBV1_1 => assert!(!is_legacy),
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
