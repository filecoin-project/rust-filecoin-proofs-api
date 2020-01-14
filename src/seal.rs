use std::path::Path;
use std::sync::atomic::Ordering;

use anyhow::Result;

use filecoin_proofs_v1::storage_proofs::sector::SectorId;
use filecoin_proofs_v1::types::{
    Commitment, PieceInfo, PoRepProofPartitions, ProverId, SectorSize, Ticket,
};

#[derive(Debug)]
pub enum RegisteredProof {
    StackedDrg32GiBV1,
}

impl RegisteredProof {
    pub fn as_config(&self) -> filecoin_proofs_v1::types::PoRepConfig {
        match self {
            RegisteredProof::StackedDrg32GiBV1 => filecoin_proofs_v1::types::PoRepConfig {
                sector_size: SectorSize(filecoin_proofs_v1::constants::SECTOR_SIZE_32_GIB),
                partitions: PoRepProofPartitions(
                    filecoin_proofs_v1::constants::DEFAULT_POREP_PROOF_PARTITIONS
                        .load(Ordering::Relaxed),
                ),
            },
        }
    }
}

#[derive(Debug)]
pub struct SealPreCommitOutput {
    registered_proof: RegisteredProof,
    comm_r: Commitment,
    comm_d: Commitment,
}

pub fn seal_pre_commit<R: AsRef<Path>, T: AsRef<Path>, S: AsRef<Path>>(
    registered_proof: RegisteredProof,
    cache_path: R,
    in_path: T,
    out_path: S,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: &[PieceInfo],
) -> Result<SealPreCommitOutput> {
    match registered_proof {
        RegisteredProof::StackedDrg32GiBV1 => {
            let config = registered_proof.as_config();
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
