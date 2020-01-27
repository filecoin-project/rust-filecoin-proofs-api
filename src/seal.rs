use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::{
    Commitment, PieceInfo, ProverId, RegisteredSealProof, SectorId, Ticket, UnpaddedByteIndex,
    UnpaddedBytesAmount,
};

/// The output of `seal_pre_commit`.
#[derive(Clone, Debug)]
pub struct SealPreCommitOutput {
    pub registered_proof: RegisteredSealProof,
    pub comm_r: Commitment,
    pub comm_d: Commitment,
}

#[derive(Clone, Debug)]
pub struct SealCommitOutput {
    pub proof: Vec<u8>,
}

pub fn seal_pre_commit(
    registered_proof: RegisteredSealProof,
    cache_path: PathBuf,
    in_path: PathBuf,
    out_path: PathBuf,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: Vec<PieceInfo>,
) -> Result<SealPreCommitOutput> {
    use RegisteredSealProof::*;

    match registered_proof {
        StackedDrg1KiBV1 | StackedDrg16MiBV1 | StackedDrg256MiBV1 | StackedDrg1GiBV1
        | StackedDrg32GiBV1 => {
            let config = registered_proof.as_v1_config();
            let output = filecoin_proofs_v1::seal_pre_commit(
                config,
                cache_path,
                in_path,
                out_path,
                prover_id,
                sector_id,
                ticket,
                piece_infos,
            )?;

            let filecoin_proofs_v1::types::SealPreCommitOutput { comm_r, comm_d } = output;

            Ok(SealPreCommitOutput {
                registered_proof,
                comm_r,
                comm_d,
            })
        }
    }
}

pub fn seal_pre_commit_many(
    registered_proof: RegisteredSealProof,
    cache_path: &[PathBuf],
    in_path: &[PathBuf],
    out_path: &[PathBuf],
    prover_id: &[ProverId],
    sector_id: &[SectorId],
    ticket: &[Ticket],
    piece_infos: &[Vec<PieceInfo>],
) -> Result<Vec<SealPreCommitOutput>> {
    use RegisteredSealProof::*;

    match registered_proof {
        StackedDrg1KiBV1 | StackedDrg16MiBV1 | StackedDrg256MiBV1 | StackedDrg1GiBV1
        | StackedDrg32GiBV1 => {
            let config = registered_proof.as_v1_config();
            let output = filecoin_proofs_v1::seal_pre_commit_many(
                config,
                cache_path,
                in_path,
                out_path,
                prover_id,
                sector_id,
                ticket,
                piece_infos,
            )?;

            let outputs = output
                .into_iter()
                .map(|out| {
                    let filecoin_proofs_v1::types::SealPreCommitOutput { comm_r, comm_d } = out;
                    SealPreCommitOutput {
                        registered_proof,
                        comm_r,
                        comm_d,
                    }
                })
                .collect();

            Ok(outputs)
        }
    }
}

pub fn compute_comm_d(
    registered_proof: RegisteredSealProof,
    piece_infos: &[PieceInfo],
) -> Result<Commitment> {
    filecoin_proofs_v1::compute_comm_d(registered_proof.sector_size(), piece_infos)
}

pub fn seal_commit<T: AsRef<Path>>(
    cache_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    pre_commit: SealPreCommitOutput,
    piece_infos: &[PieceInfo],
) -> Result<SealCommitOutput> {
    let SealPreCommitOutput {
        comm_r,
        comm_d,
        registered_proof,
    } = pre_commit;
    use RegisteredSealProof::*;
    match registered_proof {
        StackedDrg1KiBV1 | StackedDrg16MiBV1 | StackedDrg256MiBV1 | StackedDrg1GiBV1
        | StackedDrg32GiBV1 => {
            let config = registered_proof.as_v1_config();
            let pc = filecoin_proofs_v1::types::SealPreCommitOutput { comm_r, comm_d };

            let output = filecoin_proofs_v1::seal_commit(
                config,
                cache_path,
                prover_id,
                sector_id,
                ticket,
                seed,
                pc,
                piece_infos,
            )?;

            Ok(SealCommitOutput {
                proof: output.proof,
            })
        }
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
    use RegisteredSealProof::*;
    match registered_proof {
        StackedDrg1KiBV1 | StackedDrg16MiBV1 | StackedDrg256MiBV1 | StackedDrg1GiBV1
        | StackedDrg32GiBV1 => {
            let config = registered_proof.as_v1_config();

            filecoin_proofs_v1::verify_seal(
                config, comm_r_in, comm_d_in, prover_id, sector_id, ticket, seed, proof_vec,
            )
        }
    }
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
    use RegisteredSealProof::*;
    match registered_proof {
        StackedDrg1KiBV1 | StackedDrg16MiBV1 | StackedDrg256MiBV1 | StackedDrg1GiBV1
        | StackedDrg32GiBV1 => {
            let config = registered_proof.as_v1_config();

            filecoin_proofs_v1::get_unsealed_range(
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
    }
}

pub fn generate_piece_commitment<T: Read>(
    registered_proof: RegisteredSealProof,
    source: T,
    piece_size: UnpaddedBytesAmount,
) -> Result<PieceInfo> {
    use RegisteredSealProof::*;
    match registered_proof {
        StackedDrg1KiBV1 | StackedDrg16MiBV1 | StackedDrg256MiBV1 | StackedDrg1GiBV1
        | StackedDrg32GiBV1 => filecoin_proofs_v1::generate_piece_commitment(source, piece_size),
    }
}

pub fn add_piece<R, W>(
    registered_proof: RegisteredSealProof,
    source: R,
    target: W,
    piece_size: UnpaddedBytesAmount,
    piece_lengths: &[UnpaddedBytesAmount],
) -> Result<(UnpaddedBytesAmount, Commitment)>
where
    R: Read,
    W: Read + Write + Seek,
{
    use RegisteredSealProof::*;
    match registered_proof {
        StackedDrg1KiBV1 | StackedDrg16MiBV1 | StackedDrg256MiBV1 | StackedDrg1GiBV1
        | StackedDrg32GiBV1 => {
            filecoin_proofs_v1::add_piece(source, target, piece_size, piece_lengths)
        }
    }
}

pub fn write_and_preprocess<R, W>(
    registered_proof: RegisteredSealProof,
    source: R,
    target: W,
    piece_size: UnpaddedBytesAmount,
) -> Result<(UnpaddedBytesAmount, Commitment)>
where
    R: Read,
    W: Read + Write + Seek,
{
    use RegisteredSealProof::*;
    match registered_proof {
        StackedDrg1KiBV1 | StackedDrg16MiBV1 | StackedDrg256MiBV1 | StackedDrg1GiBV1
        | StackedDrg32GiBV1 => filecoin_proofs_v1::write_and_preprocess(source, target, piece_size),
    }
}
