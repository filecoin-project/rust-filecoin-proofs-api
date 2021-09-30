use std::convert::TryInto;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Error, Result};
use blstrs::Scalar as Fr;
use filecoin_hashers::Hasher;

use filecoin_proofs_v1::constants::{
    SectorShape16KiB, SectorShape16MiB, SectorShape1GiB, SectorShape2KiB, SectorShape32GiB,
    SectorShape32KiB, SectorShape4KiB, SectorShape512MiB, SectorShape64GiB, SectorShape8MiB,
    SECTOR_SIZE_16_KIB, SECTOR_SIZE_16_MIB, SECTOR_SIZE_1_GIB, SECTOR_SIZE_2_KIB,
    SECTOR_SIZE_32_GIB, SECTOR_SIZE_32_KIB, SECTOR_SIZE_4_KIB, SECTOR_SIZE_512_MIB,
    SECTOR_SIZE_64_GIB, SECTOR_SIZE_8_MIB,
};
use filecoin_proofs_v1::types::MerkleTreeTrait;
use filecoin_proofs_v1::types::VanillaSealProof as RawVanillaSealProof;
use filecoin_proofs_v1::{with_shape, Labels as RawLabels};
use serde::{Deserialize, Serialize};

use crate::{
    AggregateSnarkProof, Commitment, PieceInfo, ProverId, RegisteredAggregationProof,
    RegisteredSealProof, SectorId, Ticket, UnpaddedByteIndex, UnpaddedBytesAmount,
};

/// The output of `seal_pre_commit_phase1`.
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
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 => {
                if let Some(labels) = Any::downcast_ref::<RawLabels<SectorShape2KiB>>(labels) {
                    Ok(Labels::StackedDrg2KiBV1(labels.clone()))
                } else {
                    bail!("invalid labels provided")
                }
            }
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 => {
                if let Some(labels) = Any::downcast_ref::<RawLabels<SectorShape8MiB>>(labels) {
                    Ok(Labels::StackedDrg8MiBV1(labels.clone()))
                } else {
                    bail!("invalid labels provided")
                }
            }
            StackedDrg512MiBV1 | StackedDrg512MiBV1_1 => {
                if let Some(labels) = Any::downcast_ref::<RawLabels<SectorShape512MiB>>(labels) {
                    Ok(Labels::StackedDrg512MiBV1(labels.clone()))
                } else {
                    bail!("invalid labels provided")
                }
            }
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 => {
                if let Some(labels) = Any::downcast_ref::<RawLabels<SectorShape32GiB>>(labels) {
                    Ok(Labels::StackedDrg32GiBV1(labels.clone()))
                } else {
                    bail!("invalid labels provided")
                }
            }
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 => {
                if let Some(labels) = Any::downcast_ref::<RawLabels<SectorShape64GiB>>(labels) {
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
                if let Some(raw) = Any::downcast_ref::<RawLabels<Tree>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 2kib into different structure")
                }
            }
            StackedDrg8MiBV1(raw) => {
                if let Some(raw) = Any::downcast_ref::<RawLabels<Tree>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 8Mib into different structure")
                }
            }
            StackedDrg512MiBV1(raw) => {
                if let Some(raw) = Any::downcast_ref::<RawLabels<Tree>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 512Mib into different structure")
                }
            }
            StackedDrg32GiBV1(raw) => {
                if let Some(raw) = Any::downcast_ref::<RawLabels<Tree>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 32gib into different structure")
                }
            }
            StackedDrg64GiBV1(raw) => {
                if let Some(raw) = Any::downcast_ref::<RawLabels<Tree>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 64gib into different structure")
                }
            }
        }
    }
}

/// The output of `seal_pre_commit_phase2`.
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
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 => {
                if let Some(proofs) =
                    Any::downcast_ref::<Vec<Vec<RawVanillaSealProof<SectorShape2KiB>>>>(proofs)
                {
                    Ok(VanillaSealProof::StackedDrg2KiBV1(proofs.clone()))
                } else {
                    bail!("invalid proofs provided")
                }
            }
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 => {
                if let Some(proofs) =
                    Any::downcast_ref::<Vec<Vec<RawVanillaSealProof<SectorShape8MiB>>>>(proofs)
                {
                    Ok(VanillaSealProof::StackedDrg8MiBV1(proofs.clone()))
                } else {
                    bail!("invalid proofs provided")
                }
            }
            StackedDrg512MiBV1 | StackedDrg512MiBV1_1 => {
                if let Some(proofs) =
                    Any::downcast_ref::<Vec<Vec<RawVanillaSealProof<SectorShape512MiB>>>>(proofs)
                {
                    Ok(VanillaSealProof::StackedDrg512MiBV1(proofs.clone()))
                } else {
                    bail!("invalid proofs provided")
                }
            }
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 => {
                if let Some(proofs) =
                    Any::downcast_ref::<Vec<Vec<RawVanillaSealProof<SectorShape32GiB>>>>(proofs)
                {
                    Ok(VanillaSealProof::StackedDrg32GiBV1(proofs.clone()))
                } else {
                    bail!("invalid proofs provided")
                }
            }
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 => {
                if let Some(proofs) =
                    Any::downcast_ref::<Vec<Vec<RawVanillaSealProof<SectorShape64GiB>>>>(proofs)
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
                if let Some(raw) = Any::downcast_ref::<Vec<Vec<RawVanillaSealProof<Tree>>>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 2kib into different structure")
                }
            }
            StackedDrg8MiBV1(raw) => {
                if let Some(raw) = Any::downcast_ref::<Vec<Vec<RawVanillaSealProof<Tree>>>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 8Mib into different structure")
                }
            }
            StackedDrg512MiBV1(raw) => {
                if let Some(raw) = Any::downcast_ref::<Vec<Vec<RawVanillaSealProof<Tree>>>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 512Mib into different structure")
                }
            }
            StackedDrg32GiBV1(raw) => {
                if let Some(raw) = Any::downcast_ref::<Vec<Vec<RawVanillaSealProof<Tree>>>>(&raw) {
                    Ok(raw.clone())
                } else {
                    bail!("cannot convert 32gib into different structure")
                }
            }
            StackedDrg64GiBV1(raw) => {
                if let Some(raw) = Any::downcast_ref::<Vec<Vec<RawVanillaSealProof<Tree>>>>(&raw) {
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

pub fn clear_cache(sector_size: u64, cache_path: &Path) -> Result<()> {
    use filecoin_proofs_v1::clear_cache;

    with_shape!(sector_size, clear_cache, cache_path)
}

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
        config,
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
        registered_proof.as_v1_config(),
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

pub fn compute_comm_d(
    registered_proof: RegisteredSealProof,
    piece_infos: &[PieceInfo],
) -> Result<Commitment> {
    filecoin_proofs_v1::compute_comm_d(registered_proof.sector_size(), piece_infos)
}

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

    filecoin_proofs_v1::validate_cache_for_commit::<_, _, Tree>(&cache_path, &replica_path)?;

    let output = filecoin_proofs_v1::seal_commit_phase1::<_, Tree>(
        config,
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

    let output = filecoin_proofs_v1::seal_commit_phase2::<Tree>(config, co, prover_id, sector_id)?;

    Ok(SealCommitPhase2Output {
        proof: output.proof,
    })
}

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
        config, comm_r, comm_d, prover_id, sector_id, ticket, seed,
    )
}

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
        registered_aggregation == RegisteredAggregationProof::SnarkPackV1,
        "unusupported aggregation version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        aggregate_seal_commit_proofs_inner,
        registered_proof,
        comm_rs,
        seeds,
        commit_outputs,
    )
}

pub fn aggregate_seal_commit_proofs_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof: RegisteredSealProof,
    comm_rs: &[Commitment],
    seeds: &[Ticket],
    commit_outputs: &[SealCommitPhase2Output],
) -> Result<AggregateSnarkProof> {
    let config = registered_proof.as_v1_config();
    let outputs: Vec<filecoin_proofs_v1::types::SealCommitOutput> = commit_outputs
        .iter()
        .map(|co| filecoin_proofs_v1::types::SealCommitOutput {
            proof: co.proof.clone(),
        })
        .collect();

    filecoin_proofs_v1::aggregate_seal_commit_proofs::<Tree>(config, comm_rs, seeds, &outputs)
}

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
        registered_aggregation == RegisteredAggregationProof::SnarkPackV1,
        "unusupported aggregation version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        verify_aggregate_seal_commit_proofs_inner,
        registered_proof,
        aggregate_proof_bytes,
        comm_rs,
        seeds,
        commit_inputs,
    )
}

pub fn verify_aggregate_seal_commit_proofs_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof: RegisteredSealProof,
    aggregate_proof_bytes: AggregateSnarkProof,
    comm_rs: &[Commitment],
    seeds: &[Ticket],
    commit_inputs: Vec<Vec<Fr>>,
) -> Result<bool> {
    let config = registered_proof.as_v1_config();

    filecoin_proofs_v1::verify_aggregate_seal_commit_proofs::<Tree>(
        config,
        aggregate_proof_bytes,
        comm_rs,
        seeds,
        commit_inputs,
    )
}

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
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape2KiB>(config, cache_path, replica_path)
        }
        SECTOR_SIZE_4_KIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape4KiB>(config, cache_path, replica_path)
        }
        SECTOR_SIZE_16_KIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape16KiB>(config, cache_path, replica_path)
        }
        SECTOR_SIZE_32_KIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape32KiB>(config, cache_path, replica_path)
        }
        SECTOR_SIZE_8_MIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape8MiB>(config, cache_path, replica_path)
        }
        SECTOR_SIZE_16_MIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape16MiB>(config, cache_path, replica_path)
        }
        SECTOR_SIZE_512_MIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape512MiB>(config, cache_path, replica_path)
        }
        SECTOR_SIZE_1_GIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape1GiB>(config, cache_path, replica_path)
        }
        SECTOR_SIZE_32_GIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape32GiB>(config, cache_path, replica_path)
        }
        SECTOR_SIZE_64_GIB => {
            filecoin_proofs_v1::fauxrep::<_, _, SectorShape64GiB>(config, cache_path, replica_path)
        }
        _ => panic!("unsupported sector size: {}", sector_size),
    }
}

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
        config,
        comm_r_in,
        comm_d_in,
        prover_id,
        sector_id,
        ticket,
        seed,
        proof_vec,
    )
}

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
        config,
        comm_r_ins,
        comm_d_ins,
        prover_ids,
        sector_ids,
        tickets,
        seeds,
        proof_vecs,
    )
}

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
        config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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

pub fn generate_piece_commitment<T: Read>(
    registered_proof: RegisteredSealProof,
    source: T,
    piece_size: UnpaddedBytesAmount,
) -> Result<PieceInfo> {
    use RegisteredSealProof::*;
    match registered_proof {
        StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1
        | StackedDrg64GiBV1 | StackedDrg2KiBV1_1 | StackedDrg8MiBV1_1 | StackedDrg512MiBV1_1
        | StackedDrg32GiBV1_1 | StackedDrg64GiBV1_1 => {
            filecoin_proofs_v1::generate_piece_commitment(source, piece_size)
        }
    }
}

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
        StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1
        | StackedDrg64GiBV1 | StackedDrg2KiBV1_1 | StackedDrg8MiBV1_1 | StackedDrg512MiBV1_1
        | StackedDrg32GiBV1_1 | StackedDrg64GiBV1_1 => {
            filecoin_proofs_v1::add_piece(source, target, piece_size, piece_lengths)
        }
    }
}

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
        StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1
        | StackedDrg64GiBV1 | StackedDrg2KiBV1_1 | StackedDrg8MiBV1_1 | StackedDrg512MiBV1_1
        | StackedDrg32GiBV1_1 | StackedDrg64GiBV1_1 => {
            filecoin_proofs_v1::write_and_preprocess(source, target, piece_size)
        }
    }
}
