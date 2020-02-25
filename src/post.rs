use std::collections::BTreeMap;

use anyhow::{ensure, Result};

use crate::{
    Candidate, ChallengeSeed, PrivateReplicaInfo, ProverId, PublicReplicaInfo, RegisteredPoStProof,
    SectorId, SnarkProof,
};
use std::iter;

pub fn generate_candidates(
    randomness: &ChallengeSeed,
    challenge_count: u64,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<Vec<Candidate>> {
    let (replicas_v1, config_v1) = split_replicas(replicas)?;
    ensure!(!replicas_v1.is_empty(), "missing v1 replicas");

    let candidates_v1 = filecoin_proofs_v1::generate_candidates(
        config_v1.expect("checked before").as_v1_config(),
        randomness,
        challenge_count,
        &replicas_v1,
        prover_id,
    )?;

    // once there are multiple versions, merge them before returning

    Ok(candidates_v1)
}

pub fn finalize_ticket(partial_ticket: &[u8; 32]) -> Result<[u8; 32]> {
    filecoin_proofs_v1::finalize_ticket(partial_ticket)
}

pub fn generate_post(
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    winners: Vec<Candidate>,
    prover_id: ProverId,
) -> Result<Vec<(RegisteredPoStProof, SnarkProof)>> {
    let (replicas_v1, registered_post_proof_type_v1) = split_replicas(replicas)?;
    ensure!(!replicas_v1.is_empty(), "missing v1 replicas");

    let winners_v1 = filter_candidates(&winners, &replicas_v1);

    let rpp_v1 = registered_post_proof_type_v1.expect("already checked");

    let posts_v1 = filecoin_proofs_v1::generate_post(
        rpp_v1.as_v1_config(),
        randomness,
        &replicas_v1,
        winners_v1,
        prover_id,
    )?;

    let post_tuples = posts_v1.into_iter().zip(iter::repeat(rpp_v1)).map(|(snark_proof, rpp)| {
        (rpp, snark_proof)
    }).collect();

    // once there are multiple versions, merge them before returning

    Ok(post_tuples)
}

pub fn verify_post(
    randomness: &ChallengeSeed,
    challenge_count: u64,
    proofs: &[Vec<u8>],
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    winners: &[Candidate],
    prover_id: ProverId,
) -> Result<bool> {
    let (replicas_v1, config_v1) = split_public_replicas(replicas)?;
    ensure!(!replicas_v1.is_empty(), "missing v1 replicas");

    let winners_v1 = filter_candidates(winners, &replicas_v1);
    let valid_v1 = filecoin_proofs_v1::verify_post(
        config_v1.expect("already checked"),
        randomness,
        challenge_count,
        proofs,
        &replicas_v1,
        &winners_v1,
        prover_id,
    )?;

    // once there are multiple versions, merge them before returning

    Ok(valid_v1)
}

fn split_replicas(
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
) -> Result<(
    BTreeMap<SectorId, filecoin_proofs_v1::PrivateReplicaInfo>,
    Option<RegisteredPoStProof>,
)> {
    let mut replicas_v1 = BTreeMap::new();

    let mut registered_post_proof_type_v1 = None;

    for (id, info) in replicas.iter() {
        let PrivateReplicaInfo {
            registered_proof,
            comm_r,
            cache_dir,
            replica_path,
        } = info;

        use RegisteredPoStProof::*;

        match registered_proof {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1 => {
                if registered_post_proof_type_v1.is_none() {
                    registered_post_proof_type_v1 = Some(*registered_proof);
                }

                let info_v1 = filecoin_proofs_v1::PrivateReplicaInfo::new(
                    replica_path.clone(),
                    *comm_r,
                    cache_dir.into(),
                )?;

                replicas_v1.insert(*id, info_v1);
            }
        }
    }

    Ok((replicas_v1, registered_post_proof_type_v1))
}

fn split_public_replicas(
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
) -> Result<(
    BTreeMap<SectorId, filecoin_proofs_v1::PublicReplicaInfo>,
    Option<filecoin_proofs_v1::types::PoStConfig>,
)> {
    let mut replicas_v1 = BTreeMap::new();

    let mut config_v1 = None;
    for (id, info) in replicas.iter() {
        let PublicReplicaInfo {
            registered_proof,
            comm_r,
        } = info;

        use RegisteredPoStProof::*;
        match registered_proof {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1 => {
                if config_v1.is_none() {
                    config_v1 = Some(registered_proof.as_v1_config());
                }

                let info_v1 = filecoin_proofs_v1::PublicReplicaInfo::new(*comm_r)?;
                replicas_v1.insert(*id, info_v1);
            }
        }
    }

    Ok((replicas_v1, config_v1))
}

fn filter_candidates<T>(
    candidates: &[Candidate],
    replicas: &BTreeMap<SectorId, T>,
) -> Vec<Candidate> {
    candidates
        .iter()
        .filter(|c| replicas.contains_key(&c.sector_id))
        .cloned()
        .collect()
}
