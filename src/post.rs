use std::collections::BTreeMap;

use anyhow::{ensure, Result};
use filecoin_proofs_v1::types::MerkleTreeTrait;
use filecoin_proofs_v1::with_shape;

use crate::{
    ChallengeSeed, PoStType, PrivateReplicaInfo, ProverId, PublicReplicaInfo, RegisteredPoStProof,
    SectorId, SnarkProof, Version,
};

pub fn generate_winning_post_sector_challenge(
    proof_type: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    sector_set_len: u64,
    prover_id: ProverId,
) -> Result<Vec<u64>> {
    ensure!(
        proof_type.typ() == PoStType::Winning,
        "invalid post type provide"
    );

    with_shape!(
        u64::from(proof_type.sector_size()),
        generate_winning_post_sector_challenge_inner,
        proof_type,
        randomness,
        sector_set_len,
        prover_id,
    )
}

fn generate_winning_post_sector_challenge_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    sector_set_len: u64,
    prover_id: ProverId,
) -> Result<Vec<u64>> {
    filecoin_proofs_v1::generate_winning_post_sector_challenge::<Tree>(
        &registered_proof.as_v1_config(),
        randomness,
        sector_set_len,
        prover_id,
    )
}

pub fn generate_winning_post(
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<Vec<(RegisteredPoStProof, SnarkProof)>> {
    ensure!(!replicas.is_empty(), "no replicas supplied");
    let registered_post_proof_type_v1 = replicas
        .values()
        .next()
        .map(|v| v.registered_proof)
        .expect("replica map failure");
    ensure!(
        registered_post_proof_type_v1.typ() == PoStType::Winning,
        "invalid post type provide"
    );

    with_shape!(
        u64::from(registered_post_proof_type_v1.sector_size()),
        generate_winning_post_inner,
        registered_post_proof_type_v1,
        randomness,
        replicas,
        prover_id,
    )
}

fn generate_winning_post_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof_v1: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<Vec<(RegisteredPoStProof, SnarkProof)>> {
    let mut replicas_v1 = Vec::new();

    for (id, info) in replicas.iter() {
        let PrivateReplicaInfo {
            registered_proof,
            comm_r,
            cache_dir,
            replica_path,
        } = info;

        ensure!(
            registered_proof == &registered_proof_v1,
            "can only generate the same kind of PoSt"
        );
        let info_v1 = filecoin_proofs_v1::PrivateReplicaInfo::new(
            replica_path.clone(),
            *comm_r,
            cache_dir.into(),
        )?;

        replicas_v1.push((*id, info_v1));
    }

    ensure!(!replicas_v1.is_empty(), "missing v1 replicas");
    let posts_v1 = filecoin_proofs_v1::generate_winning_post::<Tree>(
        &registered_proof_v1.as_v1_config(),
        randomness,
        &replicas_v1,
        prover_id,
    )?;

    // once there are multiple versions, merge them before returning

    Ok(vec![(registered_proof_v1, posts_v1)])
}

pub fn verify_winning_post(
    randomness: &ChallengeSeed,
    proof: &[u8],
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
) -> Result<bool> {
    ensure!(!replicas.is_empty(), "no replicas supplied");
    let registered_post_proof_type_v1 = replicas
        .values()
        .next()
        .map(|v| v.registered_proof)
        .expect("replica map failure");
    ensure!(
        registered_post_proof_type_v1.typ() == PoStType::Winning,
        "invalid post type provide"
    );

    with_shape!(
        u64::from(registered_post_proof_type_v1.sector_size()),
        verify_winning_post_inner,
        registered_post_proof_type_v1,
        randomness,
        proof,
        replicas,
        prover_id,
    )
}

fn verify_winning_post_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof_v1: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    proof: &[u8],
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
) -> Result<bool> {
    let mut replicas_v1 = Vec::new();

    for (id, info) in replicas.iter() {
        let PublicReplicaInfo {
            registered_proof,
            comm_r,
        } = info;

        ensure!(
            registered_proof == &registered_proof_v1,
            "can only generate the same kind of PoSt"
        );

        let info_v1 = filecoin_proofs_v1::PublicReplicaInfo::new(*comm_r)?;
        replicas_v1.push((*id, info_v1));
    }

    let valid_v1 = filecoin_proofs_v1::verify_winning_post::<Tree>(
        &registered_proof_v1.as_v1_config(),
        randomness,
        &replicas_v1,
        prover_id,
        proof,
    )?;

    // once there are multiple versions, merge them before returning

    Ok(valid_v1)
}

pub fn generate_window_post(
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<Vec<(RegisteredPoStProof, SnarkProof)>> {
    ensure!(!replicas.is_empty(), "no replicas supplied");
    let registered_post_proof_type = replicas
        .values()
        .next()
        .map(|v| v.registered_proof)
        .expect("replica map failure");
    ensure!(
        registered_post_proof_type.typ() == PoStType::Window,
        "invalid post type provide"
    );

    with_shape!(
        u64::from(registered_post_proof_type.sector_size()),
        generate_window_post_inner,
        registered_post_proof_type,
        randomness,
        replicas,
        prover_id,
    )
}

fn generate_window_post_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<Vec<(RegisteredPoStProof, SnarkProof)>> {
    let mut replicas_v1 = BTreeMap::new();
    let mut replicas_v2 = BTreeMap::new();

    for (id, info) in replicas.iter() {
        let PrivateReplicaInfo {
            registered_proof,
            comm_r,
            cache_dir,
            replica_path,
        } = info;

        let info = filecoin_proofs_v1::PrivateReplicaInfo::new(
            replica_path.clone(),
            *comm_r,
            cache_dir.into(),
        )?;

        match registered_proof.version() {
            Version::V1 => replicas_v1.insert(*id, info),
            Version::V2 => replicas_v2.insert(*id, info),
        };
    }

    ensure!(
        !replicas_v1.is_empty() || !replicas_v2.is_empty(),
        "missing v1/v2 replicas"
    );

    let mut posts = Vec::new();

    if !replicas_v1.is_empty() {
        let posts_v1 = filecoin_proofs_v1::generate_window_post::<Tree>(
            &registered_proof.as_v1_config(),
            randomness,
            &replicas_v1,
            prover_id,
        )?;

        posts.push((registered_proof, posts_v1));
    }

    if !replicas_v2.is_empty() {
        let posts_v2 = filecoin_proofs_v1::generate_window_post::<Tree>(
            &registered_proof.as_v2_config(),
            randomness,
            &replicas_v2,
            prover_id,
        )?;

        posts.push((registered_proof, posts_v2));
    }

    Ok(posts)
}

pub fn verify_window_post(
    randomness: &ChallengeSeed,
    proofs: &[(RegisteredPoStProof, &[u8])],
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
) -> Result<bool> {
    ensure!(!replicas.is_empty(), "no replicas supplied");
    ensure!(proofs.len() == 1, "only one version of PoSt supported");

    let registered_post_proof_type = proofs[0].0;

    ensure!(
        registered_post_proof_type.typ() == PoStType::Window,
        "invalid post type provide"
    );

    with_shape!(
        u64::from(registered_post_proof_type.sector_size()),
        verify_window_post_inner,
        registered_post_proof_type,
        randomness,
        proofs,
        replicas,
        prover_id,
    )
}

fn verify_window_post_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    proofs: &[(RegisteredPoStProof, &[u8])],
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
) -> Result<bool> {
    let mut replicas_v1 = BTreeMap::new();
    let mut replicas_v2 = BTreeMap::new();

    for (id, info) in replicas.iter() {
        let PublicReplicaInfo {
            registered_proof,
            comm_r,
        } = info;

        let info = filecoin_proofs_v1::PublicReplicaInfo::new(*comm_r)?;
        match registered_proof.version() {
            Version::V1 => replicas_v1.insert(*id, info),
            Version::V2 => replicas_v2.insert(*id, info),
        };
    }

    ensure!(
        !replicas_v1.is_empty() || !replicas_v2.is_empty(),
        "missing v1/v2 replicas"
    );

    let valid_v1 = if !replicas_v1.is_empty() {
        filecoin_proofs_v1::verify_window_post::<Tree>(
            &registered_proof.as_v1_config(),
            randomness,
            &replicas_v1,
            prover_id,
            proofs[0].1,
        )?
    } else {
        true
    };

    let valid_v2 = if !replicas_v2.is_empty() {
        filecoin_proofs_v1::verify_window_post::<Tree>(
            &registered_proof.as_v2_config(),
            randomness,
            &replicas_v2,
            prover_id,
            proofs[0].1,
        )?
    } else {
        true
    };

    Ok(valid_v1 && valid_v2)
}
