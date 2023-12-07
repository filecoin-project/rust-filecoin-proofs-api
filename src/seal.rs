//! Proof-of-Replication for sealing, unsealing, and verifying data sectors
use std::convert::TryInto;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Error, Result};
use bellperson::groth16::aggregate::AggregateVersion;
use blstrs::Scalar as Fr;
use filecoin_hashers::Hasher;

use filecoin_proofs_v1::constants::{
    SectorShape16KiB, SectorShape16MiB, SectorShape1GiB, SectorShape2KiB, SectorShape32GiB,
    SectorShape32KiB, SectorShape4KiB, SectorShape512MiB, SectorShape64GiB, SectorShape8MiB,
    LAYERS, SECTOR_SIZE_16_KIB, SECTOR_SIZE_16_MIB, SECTOR_SIZE_1_GIB, SECTOR_SIZE_2_KIB,
    SECTOR_SIZE_32_GIB, SECTOR_SIZE_32_KIB, SECTOR_SIZE_4_KIB, SECTOR_SIZE_512_MIB,
    SECTOR_SIZE_64_GIB, SECTOR_SIZE_8_MIB,
};
use filecoin_proofs_v1::types::{MerkleTreeTrait, VanillaSealProof as RawVanillaSealProof};
use filecoin_proofs_v1::{with_shape, Labels as RawLabels};
use serde::{Deserialize, Serialize};

use crate::{
    AggregateSnarkProof, ApiFeature, Commitment, PieceInfo, ProverId, RegisteredAggregationProof,
    RegisteredSealProof, SectorId, Ticket, UnpaddedByteIndex, UnpaddedBytesAmount,
};

/// The output of [`seal_pre_commit_phase1`].
///  * 'registered_proof' - The seal proof type.
///  * `labels` - Label for each node in Merkle tree showing hash of all child nodes below it.
///  * 'config' - Struct detailing how the Merkle tree is stored on disk.
///  * 'comm_d' - The root hash of the unsealed sector’s Merkle tree, also referred to as data commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealPreCommitPhase1Output {
    pub registered_proof: RegisteredSealProof,
    pub labels: Labels,
    pub config: filecoin_proofs_v1::StoreConfig,
    pub comm_d: filecoin_proofs_v1::Commitment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Labels {
    StackedDrg2KiBV1(RawLabels<SectorShape2KiB>),
    StackedDrg8MiBV1(RawLabels<SectorShape8MiB>),
    StackedDrg512MiBV1(RawLabels<SectorShape512MiB>),
    StackedDrg32GiBV1(RawLabels<SectorShape32GiB>),
    StackedDrg64GiBV1(RawLabels<SectorShape64GiB>),
}

impl Labels {
    fn from_raw<Tree: 'static + MerkleTreeTrait>(
        proof: RegisteredSealProof,
        labels: &RawLabels<Tree>,
    ) -> Result<Self> {
        use std::any::Any;
        use RegisteredSealProof::*;
        match proof {
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 | StackedDrg2KiBV1_1_Feat_SyntheticPoRep => {
                if let Some(labels) = <dyn Any>::downcast_ref::<RawLabels<SectorShape2KiB>>(labels)
                {
                    Ok(Labels::StackedDrg2KiBV1(labels.clone()))
                } else {
                    bail!("invalid labels provided")
                }
            }
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 | StackedDrg8MiBV1_1_Feat_SyntheticPoRep => {
                if let Some(labels) = <dyn Any>::downcast_ref::<RawLabels<SectorShape8MiB>>(labels)
                {
                    Ok(Labels::StackedDrg8MiBV1(labels.clone()))
                } else {
                    bail!("invalid labels provided")
                }
            }
            StackedDrg512MiBV1
            | StackedDrg512MiBV1_1
            | StackedDrg512MiBV1_1_Feat_SyntheticPoRep => {
                if let Some(labels) =
                    <dyn Any>::downcast_ref::<RawLabels<SectorShape512MiB>>(labels)
                {
                    Ok(Labels::StackedDrg512MiBV1(labels.clone()))
                } else {
                    bail!("invalid labels provided")
                }
            }
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 | StackedDrg32GiBV1_1_Feat_SyntheticPoRep => {
                if let Some(labels) = <dyn Any>::downcast_ref::<RawLabels<SectorShape32GiB>>(labels)
                {
                    Ok(Labels::StackedDrg32GiBV1(labels.clone()))
                } else {
                    bail!("invalid labels provided")
                }
            }
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 | StackedDrg64GiBV1_1_Feat_SyntheticPoRep => {
                if let Some(labels) = <dyn Any>::downcast_ref::<RawLabels<SectorShape64GiB>>(labels)
                {
                    Ok(Labels::StackedDrg64GiBV1(labels.clone()))
                } else {
                    bail!("invalid labels provided")
                }
            }
        }
    }
}

impl<Tree: 'static + MerkleTreeTrait> TryInto<RawLabels<Tree>> for Labels {
    type Error = Error;

    fn try_into(self) -> Result<RawLabels<Tree>> {
        use std::any::Any;
        use Labels::*;

        match self {
            StackedDrg2KiBV1(raw) => {
                if let Some(raw) = <dyn Any>::downcast_ref::<RawLabels<Tree>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 2kib into different structure")
                }
            }
            StackedDrg8MiBV1(raw) => {
                if let Some(raw) = <dyn Any>::downcast_ref::<RawLabels<Tree>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 8Mib into different structure")
                }
            }
            StackedDrg512MiBV1(raw) => {
                if let Some(raw) = <dyn Any>::downcast_ref::<RawLabels<Tree>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 512Mib into different structure")
                }
            }
            StackedDrg32GiBV1(raw) => {
                if let Some(raw) = <dyn Any>::downcast_ref::<RawLabels<Tree>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 32gib into different structure")
                }
            }
            StackedDrg64GiBV1(raw) => {
                if let Some(raw) = <dyn Any>::downcast_ref::<RawLabels<Tree>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 64gib into different structure")
                }
            }
        }
    }
}

/// The output of [`seal_pre_commit_phase2`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealPreCommitPhase2Output {
    pub registered_proof: RegisteredSealProof,
    pub comm_r: Commitment,
    pub comm_d: Commitment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealCommitPhase1Output {
    pub registered_proof: RegisteredSealProof,
    pub vanilla_proofs: VanillaSealProof,
    pub comm_r: Commitment,
    pub comm_d: Commitment,
    pub replica_id: <filecoin_proofs_v1::constants::DefaultTreeHasher as Hasher>::Domain,
    pub seed: Ticket,
    pub ticket: Ticket,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VanillaSealProof {
    StackedDrg2KiBV1(Vec<Vec<RawVanillaSealProof<SectorShape2KiB>>>),
    StackedDrg8MiBV1(Vec<Vec<RawVanillaSealProof<SectorShape8MiB>>>),
    StackedDrg512MiBV1(Vec<Vec<RawVanillaSealProof<SectorShape512MiB>>>),
    StackedDrg32GiBV1(Vec<Vec<RawVanillaSealProof<SectorShape32GiB>>>),
    StackedDrg64GiBV1(Vec<Vec<RawVanillaSealProof<SectorShape64GiB>>>),
}

impl VanillaSealProof {
    #[allow(clippy::ptr_arg)]
    fn from_raw<Tree: 'static + MerkleTreeTrait>(
        proof: RegisteredSealProof,
        proofs: &Vec<Vec<RawVanillaSealProof<Tree>>>,
    ) -> Result<Self> {
        use std::any::Any;
        use RegisteredSealProof::*;
        match proof {
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 | StackedDrg2KiBV1_1_Feat_SyntheticPoRep => {
                if let Some(proofs) = <dyn Any>::downcast_ref::<
                    Vec<Vec<RawVanillaSealProof<SectorShape2KiB>>>,
                >(proofs)
                {
                    Ok(VanillaSealProof::StackedDrg2KiBV1(proofs.clone()))
                } else {
                    bail!("invalid proofs provided")
                }
            }
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 | StackedDrg8MiBV1_1_Feat_SyntheticPoRep => {
                if let Some(proofs) = <dyn Any>::downcast_ref::<
                    Vec<Vec<RawVanillaSealProof<SectorShape8MiB>>>,
                >(proofs)
                {
                    Ok(VanillaSealProof::StackedDrg8MiBV1(proofs.clone()))
                } else {
                    bail!("invalid proofs provided")
                }
            }
            StackedDrg512MiBV1
            | StackedDrg512MiBV1_1
            | StackedDrg512MiBV1_1_Feat_SyntheticPoRep => {
                if let Some(proofs) = <dyn Any>::downcast_ref::<
                    Vec<Vec<RawVanillaSealProof<SectorShape512MiB>>>,
                >(proofs)
                {
                    Ok(VanillaSealProof::StackedDrg512MiBV1(proofs.clone()))
                } else {
                    bail!("invalid proofs provided")
                }
            }
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 | StackedDrg32GiBV1_1_Feat_SyntheticPoRep => {
                if let Some(proofs) = <dyn Any>::downcast_ref::<
                    Vec<Vec<RawVanillaSealProof<SectorShape32GiB>>>,
                >(proofs)
                {
                    Ok(VanillaSealProof::StackedDrg32GiBV1(proofs.clone()))
                } else {
                    bail!("invalid proofs provided")
                }
            }
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 | StackedDrg64GiBV1_1_Feat_SyntheticPoRep => {
                if let Some(proofs) = <dyn Any>::downcast_ref::<
                    Vec<Vec<RawVanillaSealProof<SectorShape64GiB>>>,
                >(proofs)
                {
                    Ok(VanillaSealProof::StackedDrg64GiBV1(proofs.clone()))
                } else {
                    bail!("invalid proofs provided")
                }
            }
        }
    }
}

impl<Tree: 'static + MerkleTreeTrait> TryInto<Vec<Vec<RawVanillaSealProof<Tree>>>>
    for VanillaSealProof
{
    type Error = Error;

    fn try_into(self) -> Result<Vec<Vec<RawVanillaSealProof<Tree>>>> {
        use std::any::Any;
        use VanillaSealProof::*;

        match self {
            StackedDrg2KiBV1(raw) => {
                if let Some(raw) =
                    <dyn Any>::downcast_ref::<Vec<Vec<RawVanillaSealProof<Tree>>>>(&raw)
                {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 2kib into different structure")
                }
            }
            StackedDrg8MiBV1(raw) => {
                if let Some(raw) =
                    <dyn Any>::downcast_ref::<Vec<Vec<RawVanillaSealProof<Tree>>>>(&raw)
                {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 8Mib into different structure")
                }
            }
            StackedDrg512MiBV1(raw) => {
                if let Some(raw) =
                    <dyn Any>::downcast_ref::<Vec<Vec<RawVanillaSealProof<Tree>>>>(&raw)
                {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 512Mib into different structure")
                }
            }
            StackedDrg32GiBV1(raw) => {
                if let Some(raw) =
                    <dyn Any>::downcast_ref::<Vec<Vec<RawVanillaSealProof<Tree>>>>(&raw)
                {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 32gib into different structure")
                }
            }
            StackedDrg64GiBV1(raw) => {
                if let Some(raw) =
                    <dyn Any>::downcast_ref::<Vec<Vec<RawVanillaSealProof<Tree>>>>(&raw)
                {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 64gib into different structure")
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealCommitPhase2Output {
    pub proof: Vec<u8>,
}

/// Ensure that any persisted cached data for specified sector size is discarded.
///
/// # Arguments
///
/// * `sector_size` - Sector size associated with cache data to clear.
/// * `cache_path` - Path to directory where cached data is stored.
pub fn clear_cache(sector_size: u64, cache_path: &Path) -> Result<()> {
    use filecoin_proofs_v1::clear_cache;

    with_shape!(sector_size, clear_cache, cache_path)
}

/// Generate and persist synthetic Merkle tree proofs for sector replica. Must be called with output from [`seal_pre_commit_phase2`].
///
/// # Arguments
///
/// * `cache_path` - Directory path to use for generation of Merkle tree on disk.
/// * `replica_path` - out_path from [`seal_pre_commit_phase2`], which points to generated sector replica.
/// * `prover_id` - Unique ID of the storage provider.
/// * `sector_id` - ID of the sector, usually relative to the miner.
/// * `ticket` - The ticket used to generate this sector's replica-id.
/// * `seed` - Interactive randomnessthe seed used to derive the Proof-of-Replication (PoRep) challenges.
/// * `piece_infos` - The piece info (commitment and byte length) for each piece in the sector.
///
/// Returns vanilla Merkle tree proof for use by [`seal_commit_phase2`].
pub fn generate_synth_proofs<T: AsRef<Path>>(
    cache_path: T,
    replica_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    pre_commit: SealPreCommitPhase2Output,
    piece_infos: &[PieceInfo],
) -> Result<()> {
    ensure!(
        pre_commit.registered_proof.major_version() == 1,
        "unusupported version"
    );
    ensure!(
        pre_commit
            .registered_proof
            .feature_enabled(ApiFeature::SyntheticPoRep),
        "synthetic porep feature MUST be enabled"
    );

    with_shape!(
        u64::from(pre_commit.registered_proof.sector_size()),
        generate_synth_proofs_inner,
        cache_path.as_ref(),
        replica_path.as_ref(),
        prover_id,
        sector_id,
        ticket,
        pre_commit,
        piece_infos,
    )
}

fn generate_synth_proofs_inner<Tree: 'static + MerkleTreeTrait>(
    cache_path: &Path,
    replica_path: &Path,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    pre_commit: SealPreCommitPhase2Output,
    piece_infos: &[PieceInfo],
) -> Result<()> {
    let SealPreCommitPhase2Output {
        comm_r,
        comm_d,
        registered_proof,
    } = pre_commit;

    let config = registered_proof.as_v1_config();
    let pc = filecoin_proofs_v1::types::SealPreCommitOutput { comm_r, comm_d };

    filecoin_proofs_v1::validate_cache_for_commit::<_, _, Tree>(&cache_path, &replica_path)?;

    filecoin_proofs_v1::generate_synth_proofs::<_, Tree>(
        &config,
        cache_path,
        replica_path,
        prover_id,
        sector_id,
        ticket,
        pc,
        piece_infos,
    )
}

/// Ensure that any persisted layers are discarded.
///
/// # Arguments
///
/// * `sector_size` - Sector size associated with cache data to clear.
/// * `cache_path` - Path to directory where cached data is stored.
pub fn clear_layer_data(sector_size: u64, cache_path: &Path) -> Result<()> {
    use filecoin_proofs_v1::clear_layer_data;

    with_shape!(sector_size, clear_layer_data, cache_path)
}

/// Ensure that any persisted synthetic proofs are discarded.
///
/// # Arguments
///
/// * `sector_size` - Sector size associated with cache data to clear.
/// * `cache_path` - Path to directory where cached data is stored.
pub fn clear_synthetic_proofs(sector_size: u64, cache_path: &Path) -> Result<()> {
    use filecoin_proofs_v1::clear_synthetic_proofs;

    with_shape!(sector_size, clear_synthetic_proofs, cache_path)
}

/// First step in sector sealing process. Called before [`seal_pre_commit_phase2`].
/// Reads unsealed data from `in_path`, generates sealed data and writes to `out_path`.
///
/// # Arguments
///
/// * `registered_proof` - Seal proof to generate.
/// * `cache_path` - Directory path to use for generation of Merkle tree on disk.
/// * `in_path` - File path of the input sector file to perform the seal operation on.
/// * `out_path` - File path to write the resultant sealed sector to.
/// * `prover_id` - Unique ID of the storage provider.
/// * `sector_id` - ID of the sector, usually relative to the miner.
/// * `ticket` - The ticket used to generate this sector's replica-id. For Filecoin this
///              randomness drawn from the Filecoin blockchain’s verifiable random function
///              (VRF), which generates tickets with each new block.
/// * `piece_infos` - The piece info (commitment and byte length) for each piece in the sector.
///
/// Returns Merkle tree labels and commitment for use by [`seal_pre_commit_phase2`].
pub fn seal_pre_commit_phase1<R, S, T>(
    registered_proof: RegisteredSealProof,
    cache_path: R,
    in_path: S,
    out_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: &[PieceInfo],
) -> Result<SealPreCommitPhase1Output>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
    T: AsRef<Path>,
{
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        seal_pre_commit_phase1_inner,
        registered_proof,
        cache_path.as_ref(),
        in_path.as_ref(),
        out_path.as_ref(),
        prover_id,
        sector_id,
        ticket,
        piece_infos
    )
}

fn seal_pre_commit_phase1_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof: RegisteredSealProof,
    cache_path: &Path,
    in_path: &Path,
    out_path: &Path,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: &[PieceInfo],
) -> Result<SealPreCommitPhase1Output> {
    let config = registered_proof.as_v1_config();

    let output = filecoin_proofs_v1::seal_pre_commit_phase1::<_, _, _, Tree>(
        &config,
        cache_path,
        in_path,
        out_path,
        prover_id,
        sector_id,
        ticket,
        piece_infos,
    )?;

    let filecoin_proofs_v1::types::SealPreCommitPhase1Output::<Tree> {
        labels,
        config,
        comm_d,
    } = output;

    Ok(SealPreCommitPhase1Output {
        registered_proof,
        labels: Labels::from_raw::<Tree>(registered_proof, &labels)?,
        config,
        comm_d,
    })
}

/// Generate label layers (SDR).
///
/// # Arguments
/// * `registered_proof` - Selected seal operation.
/// * `cache_path` - Directory path to use for generation of Merkle tree on disk.
/// * `output_dir` - Directory where the TreeRLast(s) are stored.
pub fn sdr<R>(
    registered_proof: RegisteredSealProof,
    cache_path: R,
    replica_id: <filecoin_proofs_v1::constants::DefaultTreeHasher as Hasher>::Domain,
) -> Result<()>
where
    R: AsRef<Path>,
{
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        sdr_inner,
        registered_proof,
        cache_path.as_ref(),
        replica_id,
    )?;

    Ok(())
}

fn sdr_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof: RegisteredSealProof,
    cache_path: &Path,
    replica_id: <Tree::Hasher as Hasher>::Domain,
) -> Result<()> {
    let config = registered_proof.as_v1_config();
    filecoin_proofs_v1::sdr::<_, Tree>(&config, cache_path, &replica_id)?;
    Ok(())
}

/// Second phase of seal precommit operation, must be called with output of
/// [`seal_pre_commit_phase1`]. Generates `comm_r` replica commitment from outputs
/// of previous step.
///
/// # Arguments
///
/// * `phase1_output` - Struct returned from [`seal_pre_commit_phase1`].
/// * `cache_path` - Directory path to use for generation of Merkle tree on disk.
/// * `out_path` - File path of the sealed sector replica.
///
/// Returns data and replica commitments required for [`seal_commit_phase1`].
pub fn seal_pre_commit_phase2<R, S>(
    phase1_output: SealPreCommitPhase1Output,
    cache_path: R,
    out_path: S,
) -> Result<SealPreCommitPhase2Output>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
{
    ensure!(
        phase1_output.registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(phase1_output.registered_proof.sector_size()),
        seal_pre_commit_phase2_inner,
        phase1_output,
        cache_path.as_ref(),
        out_path.as_ref(),
    )
}

fn seal_pre_commit_phase2_inner<Tree: 'static + MerkleTreeTrait>(
    phase1_output: SealPreCommitPhase1Output,
    cache_path: &Path,
    out_path: &Path,
) -> Result<SealPreCommitPhase2Output> {
    let SealPreCommitPhase1Output {
        registered_proof,
        labels,
        config,
        comm_d,
    } = phase1_output;

    let seal_pre_commit_phase1_output =
        filecoin_proofs_v1::types::SealPreCommitPhase1Output::<Tree> {
            labels: labels.try_into()?,
            config,
            comm_d,
        };

    filecoin_proofs_v1::validate_cache_for_precommit_phase2::<_, _, Tree>(
        &cache_path,
        &out_path,
        &seal_pre_commit_phase1_output,
    )?;

    let output = filecoin_proofs_v1::seal_pre_commit_phase2::<_, _, Tree>(
        &registered_proof.as_v1_config(),
        seal_pre_commit_phase1_output,
        cache_path,
        out_path,
    )?;

    let filecoin_proofs_v1::types::SealPreCommitOutput { comm_d, comm_r } = output;

    Ok(SealPreCommitPhase2Output {
        registered_proof,
        comm_d,
        comm_r,
    })
}

/// Generate Merkle tree for sector replica (TreeRLast) and return the root hash (CommRLast).
///
/// # Arguments
/// * `registered_proof` - Selected seal operation.
/// * `replica_path` - File path of replica.
/// * `output_dir` - Directory where the TreeRLast(s) are stored.
pub fn generate_tree_r_last<O, R>(
    registered_proof: RegisteredSealProof,
    replica_path: R,
    output_dir: O,
) -> Result<Commitment>
where
    O: AsRef<Path>,
    R: AsRef<Path>,
{
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let sector_size = u64::from(registered_proof.sector_size());
    let comm_r_last = with_shape!(
        sector_size,
        generate_tree_r_last_inner,
        sector_size,
        replica_path.as_ref(),
        output_dir.as_ref(),
    )?;

    Ok(comm_r_last.into())
}

fn generate_tree_r_last_inner<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    replica_path: &Path,
    output_dir: &Path,
) -> Result<<Tree::Hasher as Hasher>::Domain> {
    filecoin_proofs_v1::generate_tree_r_last::<_, _, Tree>(sector_size, &replica_path, &output_dir)
}

/// Generate Merkle tree for the label layers (TreeC) and return the root hash (CommC).
///
/// # Arguments
/// * `registered_proof` - Selected seal operation.
/// * `input_dir` - Directory where the label layers are stored.
/// * `output_dir` - Directory where the TreeRLast(s) are stored.
pub fn generate_tree_c<O, R>(
    registered_proof: RegisteredSealProof,
    input_dir: R,
    output_dir: O,
) -> Result<Commitment>
where
    O: AsRef<Path>,
    R: AsRef<Path>,
{
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let sector_size = u64::from(registered_proof.sector_size());
    let comm_c = with_shape!(
        sector_size,
        generate_tree_c_inner,
        sector_size,
        input_dir.as_ref(),
        output_dir.as_ref(),
    )?;

    Ok(comm_c.into())
}

fn generate_tree_c_inner<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    input_dir: &Path,
    output_dir: &Path,
) -> Result<<Tree::Hasher as Hasher>::Domain> {
    let num_layers = *LAYERS
        .read()
        .expect("LAYERS poisoned")
        .get(&sector_size)
        .expect("unknown sector size");
    filecoin_proofs_v1::generate_tree_c::<_, _, Tree>(
        sector_size,
        &input_dir,
        &output_dir,
        num_layers,
    )
}

/// Computes a sectors's `comm_d` data commitment given its pieces.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `piece_infos` - the piece info (commitment and byte length) for each piece in this sector.
///
/// Returns `comm_d` data commitment.
pub fn compute_comm_d(
    registered_proof: RegisteredSealProof,
    piece_infos: &[PieceInfo],
) -> Result<Commitment> {
    filecoin_proofs_v1::compute_comm_d(registered_proof.sector_size(), piece_infos)
}

/// Generate Merkle tree proofs for sector replica. Must be called with output from [`seal_pre_commit_phase2`].
///
/// # Arguments
///
/// * `cache_path` - Directory path to use for generation of Merkle tree on disk.
/// * `replica_path` - out_path from [`seal_pre_commit_phase2`], which points to generated sector replica.
/// * `prover_id` - Unique ID of the storage provider.
/// * `sector_id` - ID of the sector, usually relative to the miner.
/// * `ticket` - The ticket used to generate this sector's replica-id.
/// * `seed` - Interactive randomnessthe seed used to derive the Proof-of-Replication (PoRep) challenges.
/// * `piece_infos` - The piece info (commitment and byte length) for each piece in the sector.
///
/// Returns vanilla Merkle tree proof for use by [`seal_commit_phase2`].
pub fn seal_commit_phase1<T: AsRef<Path>>(
    cache_path: T,
    replica_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    pre_commit: SealPreCommitPhase2Output,
    piece_infos: &[PieceInfo],
) -> Result<SealCommitPhase1Output> {
    ensure!(
        pre_commit.registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(pre_commit.registered_proof.sector_size()),
        seal_commit_phase1_inner,
        cache_path.as_ref(),
        replica_path.as_ref(),
        prover_id,
        sector_id,
        ticket,
        seed,
        pre_commit,
        piece_infos,
    )
}

fn seal_commit_phase1_inner<Tree: 'static + MerkleTreeTrait>(
    cache_path: &Path,
    replica_path: &Path,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    pre_commit: SealPreCommitPhase2Output,
    piece_infos: &[PieceInfo],
) -> Result<SealCommitPhase1Output> {
    let SealPreCommitPhase2Output {
        comm_r,
        comm_d,
        registered_proof,
    } = pre_commit;

    let config = registered_proof.as_v1_config();
    let pc = filecoin_proofs_v1::types::SealPreCommitOutput { comm_r, comm_d };

    // If we're NOT using synthetic porep, validate that all required data (e.g. layers) are present.
    if !registered_proof.feature_enabled(ApiFeature::SyntheticPoRep) {
        filecoin_proofs_v1::validate_cache_for_commit::<_, _, Tree>(&cache_path, &replica_path)?;
    }

    let output = filecoin_proofs_v1::seal_commit_phase1::<_, Tree>(
        &config,
        cache_path,
        replica_path,
        prover_id,
        sector_id,
        ticket,
        seed,
        pc,
        piece_infos,
    )?;

    let filecoin_proofs_v1::types::SealCommitPhase1Output::<Tree> {
        vanilla_proofs,
        comm_r,
        comm_d,
        replica_id,
        seed,
        ticket,
    } = output;

    let replica_id: Fr = replica_id.into();
    Ok(SealCommitPhase1Output {
        registered_proof,
        vanilla_proofs: VanillaSealProof::from_raw::<Tree>(registered_proof, &vanilla_proofs)?,
        comm_r,
        comm_d,
        replica_id: replica_id.into(),
        seed,
        ticket,
    })
}

/// Generates zk-SNARK proof for sector replica. Must be called with output of [`seal_commit_phase1`].
///
/// # Arguments
///
/// * `phase1_output` - Struct returned from [`seal_commit_phase1`] containing Merkle tree proof.
/// * `prover_id` - Unique ID of the storage provider.
/// * `sector_id` - ID of the sector, usually relative to the miner.
///
/// Returns [`SealCommitPhase2Output`] struct containing vector of zk-SNARK proofs.
pub fn seal_commit_phase2(
    phase1_output: SealCommitPhase1Output,
    prover_id: ProverId,
    sector_id: SectorId,
) -> Result<SealCommitPhase2Output> {
    ensure!(
        phase1_output.registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(phase1_output.registered_proof.sector_size()),
        seal_commit_phase2_inner,
        phase1_output,
        prover_id,
        sector_id,
    )
}

fn seal_commit_phase2_inner<Tree: 'static + MerkleTreeTrait>(
    phase1_output: SealCommitPhase1Output,
    prover_id: ProverId,
    sector_id: SectorId,
) -> Result<SealCommitPhase2Output> {
    let SealCommitPhase1Output {
        vanilla_proofs,
        comm_r,
        comm_d,
        replica_id,
        seed,
        ticket,
        registered_proof,
    } = phase1_output;

    let config = registered_proof.as_v1_config();
    let replica_id: Fr = replica_id.into();

    let co = filecoin_proofs_v1::types::SealCommitPhase1Output {
        vanilla_proofs: vanilla_proofs.try_into()?,
        comm_r,
        comm_d,
        replica_id: replica_id.into(),
        seed,
        ticket,
    };

    let output = filecoin_proofs_v1::seal_commit_phase2::<Tree>(&config, co, prover_id, sector_id)?;

    Ok(SealCommitPhase2Output {
        proof: output.proof,
    })
}

/// Given the specified arguments, this method returns the inputs that were used to
/// generate the seal proof. This can be useful for proof aggregation, as verification
/// requires these inputs.
///
/// This method allows them to be retrieved when needed, rather than storing them for
/// some amount of time.
///
/// # Arguments
///
/// * `registered_proof` - Selected seal operation.
/// * `comm_r` - A commitment to a sector's replica.
/// * `comm_d` - A commitment to a sector's data.
/// * `prover_id` - Unique ID of the storage provider.
/// * `sector_id` - ID of the sector, usually relative to the miner.
/// * `ticket` - The ticket used to generate this sector's replica-id.
/// * `seed` - The seed used to derive the porep challenges.
///
/// Returns the inputs that were used to generate seal proof.
pub fn get_seal_inputs(
    registered_proof: RegisteredSealProof,
    comm_r: Commitment,
    comm_d: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
) -> Result<Vec<Vec<Fr>>> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        get_seal_inputs_inner,
        registered_proof,
        comm_r,
        comm_d,
        prover_id,
        sector_id,
        ticket,
        seed,
    )
}

// TODO: does this need to be public?
pub fn get_seal_inputs_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof: RegisteredSealProof,
    comm_r: Commitment,
    comm_d: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
) -> Result<Vec<Vec<Fr>>> {
    let config = registered_proof.as_v1_config();

    filecoin_proofs_v1::get_seal_inputs::<Tree>(
        &config, comm_r, comm_d, prover_id, sector_id, ticket, seed,
    )
}

/// Given a `porep_config` and a list of seal commit outputs, this method aggregates
/// those proofs (naively padding the count if necessary up to a power of 2) and
/// returns the aggregate proof bytes.
///
/// # Arguments
///
/// * `registered_proof` - Selected seal operation.
/// * `registered_aggregation` - Aggregation proof types.
/// * `seeds` - Ordered list of seeds used to derive the PoRep challenges.
/// * `commit_outputs` - Ordered list of seal proof outputs returned from [`seal_commit_phase2`].
///
/// Returns aggregate of zk-SNARK proofs in [`AggregateSnarkProof`].
pub fn aggregate_seal_commit_proofs(
    registered_proof: RegisteredSealProof,
    registered_aggregation: RegisteredAggregationProof,
    comm_rs: &[Commitment],
    seeds: &[Ticket],
    commit_outputs: &[SealCommitPhase2Output],
) -> Result<AggregateSnarkProof> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    ensure!(
        (registered_aggregation == RegisteredAggregationProof::SnarkPackV1
            || registered_aggregation == RegisteredAggregationProof::SnarkPackV2),
        "unsupported aggregation or registered proof version"
    );

    let aggregate_version = match registered_aggregation {
        RegisteredAggregationProof::SnarkPackV1 => AggregateVersion::V1,
        RegisteredAggregationProof::SnarkPackV2 => AggregateVersion::V2,
    };

    with_shape!(
        u64::from(registered_proof.sector_size()),
        aggregate_seal_commit_proofs_inner,
        registered_proof,
        comm_rs,
        seeds,
        commit_outputs,
        aggregate_version,
    )
}

fn aggregate_seal_commit_proofs_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof: RegisteredSealProof,
    comm_rs: &[Commitment],
    seeds: &[Ticket],
    commit_outputs: &[SealCommitPhase2Output],
    aggregate_version: AggregateVersion,
) -> Result<AggregateSnarkProof> {
    let config = registered_proof.as_v1_config();
    let outputs: Vec<filecoin_proofs_v1::types::SealCommitOutput> = commit_outputs
        .iter()
        .map(|co| filecoin_proofs_v1::types::SealCommitOutput {
            proof: co.proof.clone(),
        })
        .collect();

    filecoin_proofs_v1::aggregate_seal_commit_proofs::<Tree>(
        &config,
        comm_rs,
        seeds,
        &outputs,
        aggregate_version,
    )
}

/// Given a `porep_config`, an aggregate proof, a list of seeds and a combined and flattened list
/// of public inputs, this method verifies the aggregate seal proof.
///
/// # Arguments
///
/// * `registered_proof` - Selected seal operation.
/// * `registered_aggregation` - Aggregation proof types.
/// * `aggregate_proof_bytes` - The returned aggregate proof from [`aggregate_seal_commit_proofs`].
/// * `comm_rs` - Ordered list of sector replica commitments.
/// * `seeds` - Ordered list of seeds used to derive the PoRep challenges.
/// * `commit_inputs` - A flattened/combined and ordered list of all public inputs, which must match
///    the ordering of the seal proofs when aggregated.
///
/// Returns true if proof is validated.
pub fn verify_aggregate_seal_commit_proofs(
    registered_proof: RegisteredSealProof,
    registered_aggregation: RegisteredAggregationProof,
    aggregate_proof_bytes: AggregateSnarkProof,
    comm_rs: &[Commitment],
    seeds: &[Ticket],
    commit_inputs: Vec<Vec<Fr>>,
) -> Result<bool> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    ensure!(
        (registered_aggregation == RegisteredAggregationProof::SnarkPackV1
            || registered_aggregation == RegisteredAggregationProof::SnarkPackV2),
        "unsupported aggregation or registered proof version"
    );

    let aggregate_version = match registered_aggregation {
        RegisteredAggregationProof::SnarkPackV1 => AggregateVersion::V1,
        RegisteredAggregationProof::SnarkPackV2 => AggregateVersion::V2,
    };

    with_shape!(
        u64::from(registered_proof.sector_size()),
        verify_aggregate_seal_commit_proofs_inner,
        registered_proof,
        aggregate_proof_bytes,
        comm_rs,
        seeds,
        commit_inputs,
        aggregate_version,
    )
}

// TODO: Does this need to be public?
pub fn verify_aggregate_seal_commit_proofs_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof: RegisteredSealProof,
    aggregate_proof_bytes: AggregateSnarkProof,
    comm_rs: &[Commitment],
    seeds: &[Ticket],
    commit_inputs: Vec<Vec<Fr>>,
    aggregate_version: AggregateVersion,
) -> Result<bool> {
    let config = registered_proof.as_v1_config();

    filecoin_proofs_v1::verify_aggregate_seal_commit_proofs::<Tree>(
        &config,
        aggregate_proof_bytes,
        comm_rs,
        seeds,
        commit_inputs,
        aggregate_version,
    )
}

// Special case implementation of porep sealing which does not depend on slow sealing,
// intended to be used at chain genesis.
///
/// # Arguments
///
/// * `registered_proof` - Selected seal operation.
/// * `cache_path` - Directory path to use for generation of Merkle tree on disk.
/// * `replica_path` - out_path from [`seal_pre_commit_phase2`], which points to generated sector replica.
///
/// Returns [`Commitment`] data for the faux replica.
pub fn fauxrep<R: AsRef<Path>, S: AsRef<Path>>(
    registered_proof: RegisteredSealProof,
    cache_path: R,
    replica_path: S,
) -> Result<Commitment> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let config = registered_proof.as_v1_config();
    let sector_size: u64 = u64::from(registered_proof.sector_size());

    // TODO: Clean-up this method, as it more or less unrolls the with_shape macro in order to pass along the R and S generics as well as the Tree.
    //
    // Note also that not all of these sector sizes are production, so some could be pruned.
    match sector_size {
        SECTOR_SIZE_2_KIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape2KiB>(&config, cache_path, replica_path)
        }
        SECTOR_SIZE_4_KIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape4KiB>(&config, cache_path, replica_path)
        }
        SECTOR_SIZE_16_KIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape16KiB>(&config, cache_path, replica_path)
        }
        SECTOR_SIZE_32_KIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape32KiB>(&config, cache_path, replica_path)
        }
        SECTOR_SIZE_8_MIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape8MiB>(&config, cache_path, replica_path)
        }
        SECTOR_SIZE_16_MIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape16MiB>(&config, cache_path, replica_path)
        }
        SECTOR_SIZE_512_MIB => filecoin_proofs_v1::fauxrep::<_, _, SectorShape512MiB>(
            &config,
            cache_path,
            replica_path,
        ),
        SECTOR_SIZE_1_GIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape1GiB>(&config, cache_path, replica_path)
        }
        SECTOR_SIZE_32_GIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape32GiB>(&config, cache_path, replica_path)
        }
        SECTOR_SIZE_64_GIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape64GiB>(&config, cache_path, replica_path)
        }
        _ => panic!("unsupported sector size: {}", sector_size),
    }
}

/// fauxrep2 is a faster way to generate sectors for network genesis setup by reusing data from
/// a previously generated sector.
///
/// # Arguments
/// * `registered_proof` - Selected seal operation.
/// * `cache_path` - Directory path to use for generation of Merkle tree on disk.
/// * `existing_p_aux_path` - `p_aux` file path from previously generated sector.
///
/// Returns [`Commitment`] data for the faux replica.
pub fn fauxrep2<R: AsRef<Path>, S: AsRef<Path>>(
    registered_proof: RegisteredSealProof,
    cache_path: R,
    existing_p_aux_path: S,
) -> Result<Commitment> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let sector_size: u64 = u64::from(registered_proof.sector_size());

    // TODO: Clean-up this method, as it more or less unrolls the with_shape macro in order to pass along the R and S generics as well as the Tree.
    //
    // Note also that not all of these sector sizes are production, so some could be pruned.
    match sector_size {
        SECTOR_SIZE_2_KIB => {
            filecoin_proofs_v1::fauxrep2::<_, _, SectorShape2KiB>(cache_path, existing_p_aux_path)
        }
        SECTOR_SIZE_4_KIB => {
            filecoin_proofs_v1::fauxrep2::<_, _, SectorShape4KiB>(cache_path, existing_p_aux_path)
        }
        SECTOR_SIZE_16_KIB => {
            filecoin_proofs_v1::fauxrep2::<_, _, SectorShape16KiB>(cache_path, existing_p_aux_path)
        }
        SECTOR_SIZE_32_KIB => {
            filecoin_proofs_v1::fauxrep2::<_, _, SectorShape32KiB>(cache_path, existing_p_aux_path)
        }
        SECTOR_SIZE_8_MIB => {
            filecoin_proofs_v1::fauxrep2::<_, _, SectorShape8MiB>(cache_path, existing_p_aux_path)
        }
        SECTOR_SIZE_16_MIB => {
            filecoin_proofs_v1::fauxrep2::<_, _, SectorShape16MiB>(cache_path, existing_p_aux_path)
        }
        SECTOR_SIZE_512_MIB => {
            filecoin_proofs_v1::fauxrep2::<_, _, SectorShape512MiB>(cache_path, existing_p_aux_path)
        }
        SECTOR_SIZE_1_GIB => {
            filecoin_proofs_v1::fauxrep2::<_, _, SectorShape1GiB>(cache_path, existing_p_aux_path)
        }
        SECTOR_SIZE_32_GIB => {
            filecoin_proofs_v1::fauxrep2::<_, _, SectorShape32GiB>(cache_path, existing_p_aux_path)
        }
        SECTOR_SIZE_64_GIB => {
            filecoin_proofs_v1::fauxrep2::<_, _, SectorShape64GiB>(cache_path, existing_p_aux_path)
        }
        _ => panic!("unsupported sector size: {}", sector_size),
    }
}

/// Verify a single proof of a sealed sector.
///
/// # Arguments
/// * `registered_proof` - Selected seal operation.
/// * `comm_r_in` - comm_r replica commitment from seal operation.
/// * `comm_d_in` - comm_d data commitment from seal operation.
/// * `prover_id` - Unique ID of the storage provider.
/// * `sector_id` - ID of the sector, usually relative to the miner.
/// * `ticket` - The ticket used to generate this sector's replica-id.
/// * `seed` - The seed used to derive the porep challenges.
/// * `proof_vec` - Proof to verify.
///
/// Returns result of the proof verification.
pub fn verify_seal(
    registered_proof: RegisteredSealProof,
    comm_r_in: Commitment,
    comm_d_in: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    proof_vec: &[u8],
) -> Result<bool> {
    let config = registered_proof.as_v1_config();
    use filecoin_proofs_v1::verify_seal;

    with_shape!(
        u64::from(registered_proof.sector_size()),
        verify_seal,
        &config,
        comm_r_in,
        comm_d_in,
        prover_id,
        sector_id,
        ticket,
        seed,
        proof_vec,
    )
}

/// Verify multiple proofs of sealed sector. Each input argument is an ordered vector
/// corresponding to the proof to verify.
///
/// # Arguments
/// * `registered_proof` - Selected seal operation.
/// * `comm_r_ins` - comm_r replica commitment from seal operation.
/// * `comm_d_in` - comm_d data commitment from seal operation.
/// * `prover_id` - Unique ID of the storage provider.
/// * `sector_id` - ID of the sector, usually relative to the miner.
/// * `ticket` - The ticket used to generate this sector's replica-id.
/// * `seed` - The seed used to derive the porep challenges.
/// * `proof_vec` - Proofs to verify.
///
/// Returns result of proofs verification.
pub fn verify_batch_seal(
    registered_proof: RegisteredSealProof,
    comm_r_ins: &[Commitment],
    comm_d_ins: &[Commitment],
    prover_ids: &[ProverId],
    sector_ids: &[SectorId],
    tickets: &[Ticket],
    seeds: &[Ticket],
    proof_vecs: &[&[u8]],
) -> Result<bool> {
    let config = registered_proof.as_v1_config();
    use filecoin_proofs_v1::verify_batch_seal;

    with_shape!(
        u64::from(registered_proof.sector_size()),
        verify_batch_seal,
        &config,
        comm_r_ins,
        comm_d_ins,
        prover_ids,
        sector_ids,
        tickets,
        seeds,
        proof_vecs,
    )
}

/// Unseals the sector at `sealed_path` and returns the bytes for a piece
/// whose first (unpadded) byte begins at `offset` and ends at `offset` plus
/// `num_bytes`, inclusive. Note that the entire sector is unsealed each time
/// this function is called.
///
/// # Arguments
///
/// * `registered_proof` - Selected seal operation.
/// * `cache_path` - Path to the directory in which the sector data's Merkle tree is written.
/// * `sealed_path` - Path to the sealed sector file that we will unseal and read a byte range.
/// * `output_path` - Path to a file that we will write the requested byte range to.
/// * `prover_id` - Unique ID of the storage provider.
/// * `sector_id` - ID of the sector, usually relative to the miner.
/// * `comm_d` - The commitment to the sector's data.
/// * `ticket` - The ticket that was used to generate the sector's replica-id.
/// * `offset` - The byte index in the unsealed sector of the first byte that we want to read.
/// * `num_bytes` - The number of bytes that we want to read.
///
/// Returns count of bytes unsealed.
pub fn get_unsealed_range<T: Into<PathBuf> + AsRef<Path>>(
    registered_proof: RegisteredSealProof,
    cache_path: T,
    sealed_path: T,
    output_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    comm_d: Commitment,
    ticket: Ticket,
    offset: UnpaddedByteIndex,
    num_bytes: UnpaddedBytesAmount,
) -> Result<UnpaddedBytesAmount> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        get_unsealed_range_inner,
        registered_proof,
        cache_path.as_ref(),
        sealed_path.as_ref(),
        output_path.as_ref(),
        prover_id,
        sector_id,
        comm_d,
        ticket,
        offset,
        num_bytes,
    )
}

fn get_unsealed_range_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof: RegisteredSealProof,
    cache_path: &Path,
    sealed_path: &Path,
    output_path: &Path,
    prover_id: ProverId,
    sector_id: SectorId,
    comm_d: Commitment,
    ticket: Ticket,
    offset: UnpaddedByteIndex,
    num_bytes: UnpaddedBytesAmount,
) -> Result<UnpaddedBytesAmount> {
    let config = registered_proof.as_v1_config();

    filecoin_proofs_v1::get_unsealed_range::<_, Tree>(
        &config,
        cache_path,
        sealed_path,
        output_path,
        prover_id,
        sector_id,
        comm_d,
        ticket,
        offset,
        num_bytes,
    )
}

/// Unseals the sector read from `sealed_sector`, memory maps the sector into virtal
/// memory, and returns the bytes for a piece whose first (unpadded) byte begins at `offset`
/// and ends at `offset` plus `num_bytes`, inclusive. Note that the entire sector is unsealed
/// each time this function is called.
///
/// # Arguments
///
/// * `registered_proof` - Selected seal operation.
/// * `cache_path` - Path to the directory in which the sector data's Merkle tree is written.
/// * `sealed_sector` - A byte source from which we read sealed sector data.
/// * `unsealed_output` - A byte sink to which we write unsealed, un-bit-padded sector bytes.
/// * `prover_id` - Unique ID of the storage provider.
/// * `sector_id` - ID of the sector, usually relative to the miner.
/// * `comm_d` - The commitment to the sector's data.
/// * `ticket` - The ticket that was used to generate the sector's replica-id.
/// * `offset` - The byte index in the unsealed sector of the first byte that we want to read.
/// * `num_bytes` - The number of bytes that we want to read.
///
/// Returns count of bytes unsealed.
pub fn get_unsealed_range_mapped<T: Into<PathBuf> + AsRef<Path>, W: Write>(
    registered_proof: RegisteredSealProof,
    cache_path: T,
    sealed_path: T,
    unsealed_output: W,
    prover_id: ProverId,
    sector_id: SectorId,
    comm_d: Commitment,
    ticket: Ticket,
    offset: UnpaddedByteIndex,
    num_bytes: UnpaddedBytesAmount,
) -> Result<UnpaddedBytesAmount> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let config = registered_proof.as_v1_config();
    let sector_size: u64 = u64::from(registered_proof.sector_size());

    // TODO: Clean-up this method, as it more or less unrolls the with_shape macro in order to pass along the R and W generics as well as the Tree.
    //
    // Note also that not all of these sector sizes are production, so some could be pruned.
    match sector_size {
        SECTOR_SIZE_2_KIB => filecoin_proofs_v1::unseal_range_mapped::<_, _, SectorShape2KiB>(
            &config,
            cache_path,
            sealed_path.into(),
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_4_KIB => filecoin_proofs_v1::unseal_range_mapped::<_, _, SectorShape4KiB>(
            &config,
            cache_path,
            sealed_path.into(),
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_16_KIB => filecoin_proofs_v1::unseal_range_mapped::<_, _, SectorShape16KiB>(
            &config,
            cache_path,
            sealed_path.into(),
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_32_KIB => filecoin_proofs_v1::unseal_range_mapped::<_, _, SectorShape32KiB>(
            &config,
            cache_path,
            sealed_path.into(),
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_8_MIB => filecoin_proofs_v1::unseal_range_mapped::<_, _, SectorShape8MiB>(
            &config,
            cache_path,
            sealed_path.into(),
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_16_MIB => filecoin_proofs_v1::unseal_range_mapped::<_, _, SectorShape16MiB>(
            &config,
            cache_path,
            sealed_path.into(),
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_512_MIB => filecoin_proofs_v1::unseal_range_mapped::<_, _, SectorShape512MiB>(
            &config,
            cache_path,
            sealed_path.into(),
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_1_GIB => filecoin_proofs_v1::unseal_range_mapped::<_, _, SectorShape1GiB>(
            &config,
            cache_path,
            sealed_path.into(),
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_32_GIB => filecoin_proofs_v1::unseal_range_mapped::<_, _, SectorShape32GiB>(
            &config,
            cache_path,
            sealed_path.into(),
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_64_GIB => filecoin_proofs_v1::unseal_range_mapped::<_, _, SectorShape64GiB>(
            &config,
            cache_path,
            sealed_path.into(),
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        _ => panic!("unsupported sector size: {}", sector_size),
    }
}

/// Unseals the sector read from `sealed_sector` and returns the bytes for a
/// piece whose first (unpadded) byte begins at `offset` and ends at `offset`
/// plus `num_bytes`, inclusive. Note that the entire sector is unsealed each
/// time this function is called.
///
/// # Arguments
///
/// * `registered_proof` - Selected seal operation.
/// * `cache_path` - Path to the directory in which the sector data's Merkle tree is written.
/// * `sealed_sector` - A byte source from which we read sealed sector data.
/// * `unsealed_output` - A byte sink to which we write unsealed, un-bit-padded sector bytes.
/// * `prover_id` - Unique ID of the storage provider.
/// * `sector_id` - ID of the sector, usually relative to the miner.
/// * `comm_d` - The commitment to the sector's data.
/// * `ticket` - The ticket that was used to generate the sector's replica-id.
/// * `offset` - The byte index in the unsealed sector of the first byte that we want to read.
/// * `num_bytes` - The number of bytes that we want to read.
///
/// Returns count of bytes unsealed.
pub fn unseal_range<T: Into<PathBuf> + AsRef<Path>, R: Read, W: Write>(
    registered_proof: RegisteredSealProof,
    cache_path: T,
    sealed_sector: R,
    unsealed_output: W,
    prover_id: ProverId,
    sector_id: SectorId,
    comm_d: Commitment,
    ticket: Ticket,
    offset: UnpaddedByteIndex,
    num_bytes: UnpaddedBytesAmount,
) -> Result<UnpaddedBytesAmount> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let config = registered_proof.as_v1_config();
    let sector_size: u64 = u64::from(registered_proof.sector_size());

    // TODO: Clean-up this method, as it more or less unrolls the with_shape macro in order to pass along the R and W generics as well as the Tree.
    //
    // Note also that not all of these sector sizes are production, so some could be pruned.
    match sector_size {
        SECTOR_SIZE_2_KIB => filecoin_proofs_v1::unseal_range::<_, _, _, SectorShape2KiB>(
            &config,
            cache_path,
            sealed_sector,
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_4_KIB => filecoin_proofs_v1::unseal_range::<_, _, _, SectorShape4KiB>(
            &config,
            cache_path,
            sealed_sector,
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_16_KIB => filecoin_proofs_v1::unseal_range::<_, _, _, SectorShape16KiB>(
            &config,
            cache_path,
            sealed_sector,
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_32_KIB => filecoin_proofs_v1::unseal_range::<_, _, _, SectorShape32KiB>(
            &config,
            cache_path,
            sealed_sector,
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_8_MIB => filecoin_proofs_v1::unseal_range::<_, _, _, SectorShape8MiB>(
            &config,
            cache_path,
            sealed_sector,
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_16_MIB => filecoin_proofs_v1::unseal_range::<_, _, _, SectorShape16MiB>(
            &config,
            cache_path,
            sealed_sector,
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_512_MIB => filecoin_proofs_v1::unseal_range::<_, _, _, SectorShape512MiB>(
            &config,
            cache_path,
            sealed_sector,
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_1_GIB => filecoin_proofs_v1::unseal_range::<_, _, _, SectorShape1GiB>(
            &config,
            cache_path,
            sealed_sector,
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_32_GIB => filecoin_proofs_v1::unseal_range::<_, _, _, SectorShape32GiB>(
            &config,
            cache_path,
            sealed_sector,
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        SECTOR_SIZE_64_GIB => filecoin_proofs_v1::unseal_range::<_, _, _, SectorShape64GiB>(
            &config,
            cache_path,
            sealed_sector,
            unsealed_output,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            offset,
            num_bytes,
        ),
        _ => panic!("unsupported sector size: {}", sector_size),
    }
}

/// Generates a piece commitment for the provided byte source. Returns an error
/// if the byte source produced more than `piece_size` bytes.
///
/// # Arguments
///
/// * `registered_proof` - Selected seal proof for this byte source.
/// * `source` - A readable source of unprocessed piece bytes. The piece's commitment will be
/// generated for the bytes read from the source plus any added padding.
/// * `piece_size` - The number of unpadded user-bytes which can be read from source before EOF.
///
/// Returns piece commitment in [`PieceInfo`] struct.
pub fn generate_piece_commitment<T: Read>(
    registered_proof: RegisteredSealProof,
    source: T,
    piece_size: UnpaddedBytesAmount,
) -> Result<PieceInfo> {
    use RegisteredSealProof::*;
    match registered_proof {
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
            filecoin_proofs_v1::generate_piece_commitment(source, piece_size)
        }
    }
}

/// Computes a NUL-byte prefix and/or suffix for `source` using the provided
/// `piece_lengths` and `piece_size` (such that the `source`, after
/// preprocessing, will occupy a subtree of a Merkle tree built using the bytes
/// from `target`), runs the resultant byte stream through the preprocessor,
/// and writes the result to `target`. Returns a tuple containing the number of
/// bytes written to `target` (`source` plus alignment) and the commitment.
///
/// WARNING: Depending on the ordering and size of the pieces in
/// `piece_lengths`, this function could write a prefix of NUL bytes which
/// wastes ($SIZESECTORSIZE/2)-$MINIMUM_PIECE_SIZE space. This function will be
/// deprecated in favor of `write_and_preprocess`, and miners will be prevented
/// from sealing sectors containing more than $TOOMUCH alignment bytes.
///
/// # Arguments
///
/// * `registered_proof` - Selected seal proof for this byte source.
/// * `source` - A readable source of unprocessed piece bytes.
/// * `target` - A writer where we will write the processed piece bytes.
/// * `piece_size` - The number of unpadded user-bytes which can be read from source before EOF.
/// * `piece_lengths` - The number of bytes for each previous piece in the sector.
///
/// Returns a tuple containing the number of bytes written to `target` (`source` plus alignment)
/// and the commitment.
pub fn add_piece<R, W>(
    registered_proof: RegisteredSealProof,
    source: R,
    target: W,
    piece_size: UnpaddedBytesAmount,
    piece_lengths: &[UnpaddedBytesAmount],
) -> Result<(PieceInfo, UnpaddedBytesAmount)>
where
    R: Read,
    W: Read + Write + Seek,
{
    use RegisteredSealProof::*;
    match registered_proof {
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
            filecoin_proofs_v1::add_piece(source, target, piece_size, piece_lengths)
        }
    }
}

/// Writes bytes from `source` to `target`, adding bit-padding ("preprocessing")
/// as needed. Returns a tuple containing the number of bytes written to
/// `target` and the commitment.
///
/// WARNING: This function neither prepends nor appends alignment bytes to the
/// `target`; it is the caller's responsibility to ensure properly sized
/// and ordered writes to `target` such that `source`-bytes occupy whole
/// subtrees of the final Merkle tree built over `target`.
///
/// # Arguments
///
/// * `registered_proof` - Selected seal proof for this byte source.
/// * `source` - A readable source of unprocessed piece bytes.
/// * `target` - A writer where we will write the processed piece bytes.
/// * `piece_size` - The number of unpadded user-bytes which can be read from source before EOF.
///
/// Returns a tuple containing the number of bytes written to `target` and the commitment.
pub fn write_and_preprocess<R, W>(
    registered_proof: RegisteredSealProof,
    source: R,
    target: W,
    piece_size: UnpaddedBytesAmount,
) -> Result<(PieceInfo, UnpaddedBytesAmount)>
where
    R: Read,
    W: Read + Write + Seek,
{
    use RegisteredSealProof::*;
    match registered_proof {
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
            filecoin_proofs_v1::write_and_preprocess(source, target, piece_size)
        }
    }
}
