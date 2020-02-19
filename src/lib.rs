#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::too_many_arguments)]

pub mod post;
pub mod seal;

mod registry;
mod types;

pub use crate::registry::{RegisteredPoStProof, RegisteredSealProof};
pub use crate::types::{PrivateReplicaInfo, PublicReplicaInfo};

pub use filecoin_proofs_v1::storage_proofs::election_post::Candidate;
pub use filecoin_proofs_v1::storage_proofs::fr32;
pub use filecoin_proofs_v1::storage_proofs::sector::SectorId;
pub use filecoin_proofs_v1::types::{
    ChallengeSeed, Commitment, PaddedBytesAmount, PieceInfo, ProverId, SectorSize, Ticket,
    UnpaddedByteIndex, UnpaddedBytesAmount,
};
pub use filecoin_proofs_v1::SnarkProof;

use std::path::Path;

#[derive(Clone, Copy)]
pub enum ResponseStatus {
    NoErr,
    UnClassified,
}

impl Default for ResponseStatus {
    fn default() -> Self {
        ResponseStatus::UnClassified
    }
}

#[derive(Clone, Copy, Default)]
pub struct SealPreCommitResponse {
    status_code: ResponseStatus,
    comm_d: Commitment,
    comm_r: Commitment,
}

pub fn seal_pre_commit<R, S, T>(
    registered_proof: RegisteredSealProof,
    cache_path: R,
    in_path: S,
    out_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: &[PieceInfo],
) -> SealPreCommitResponse
where
    R: AsRef<Path> + Clone,
    S: AsRef<Path>,
    T: AsRef<Path> + Clone,
{
    let mut response = SealPreCommitResponse::default();
    let seal_pre_commit_phase1_output = seal::seal_pre_commit_phase1(
        registered_proof,
        cache_path.clone(),
        in_path,
        out_path.clone(),
        prover_id,
        sector_id,
        ticket,
        piece_infos,
    );
    match seal_pre_commit_phase1_output {
        Ok(output) => {
            let seal_pre_commit_phase2_output =
                seal::seal_pre_commit_phase2(output, cache_path, out_path);
            match seal_pre_commit_phase2_output {
                Ok(output) => {
                    response.status_code = ResponseStatus::NoErr;
                    response.comm_d = output.comm_d;
                    response.comm_r = output.comm_r;
                }
                Err(_) => {
                    response.status_code = ResponseStatus::UnClassified;
                }
            }
        }
        Err(_) => {
            response.status_code = ResponseStatus::UnClassified;
        }
    }
    response
}
