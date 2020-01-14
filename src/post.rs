use std::collections::BTreeMap;

use anyhow::{ensure, Result};

use crate::{
    Candidate, ChallengeSeed, PrivateReplicaInfo, ProverId, PublicReplicaInfo, RegisteredPoStProof,
    SectorId, SnarkProof,
};

pub fn generate_candidates(
    randomness: &ChallengeSeed,
    challenge_count: u64,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<Vec<Candidate>> {
    let (replicas_v1, config_v1) = split_replicas(replicas)?;
    ensure!(!replicas_v1.is_empty(), "missing v1 replicas");

    let candidates_v1 = filecoin_proofs_v1::generate_candidates(
        config_v1.expect("checked before"),
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
) -> Result<Vec<SnarkProof>> {
    let (replicas_v1, config_v1) = split_replicas(replicas)?;
    ensure!(!replicas_v1.is_empty(), "missing v1 replicas");

    let winners_v1 = filter_candidates(&winners, &replicas_v1);

    let posts_v1 = filecoin_proofs_v1::generate_post(
        config_v1.expect("already checked"),
        randomness,
        &replicas_v1,
        winners_v1,
        prover_id,
    )?;

    // once there are multiple versions, merge them before returning

    Ok(posts_v1)
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
    Option<filecoin_proofs_v1::types::PoStConfig>,
)> {
    let mut replicas_v1 = BTreeMap::new();

    let mut config_v1 = None;
    for (id, info) in replicas.iter() {
        let PrivateReplicaInfo {
            registered_proof,
            access,
            comm_r,
            cache_dir,
        } = info;

        use RegisteredPoStProof::*;

        match registered_proof {
            StackedDrg1KiBV1 | StackedDrg16MiBV1 | StackedDrg256MiBV1 | StackedDrg1GiBV1
            | StackedDrg32GiBV1 => {
                if config_v1.is_none() {
                    config_v1 = Some(registered_proof.as_v1_config());
                }

                let info_v1 = filecoin_proofs_v1::PrivateReplicaInfo::new(
                    access.clone(),
                    *comm_r,
                    cache_dir.clone(),
                )?;
                replicas_v1.insert(*id, info_v1);
            }
        }
    }

    Ok((replicas_v1, config_v1))
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
            StackedDrg1KiBV1 | StackedDrg16MiBV1 | StackedDrg256MiBV1 | StackedDrg1GiBV1
            | StackedDrg32GiBV1 => {
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
