use std::path::Path;

use anyhow::{ensure, Result};

use filecoin_proofs_v1::types::{
    EmptySectorUpdateEncoded, EmptySectorUpdateProof, MerkleTreeTrait, PartitionProof,
    SectorUpdateConfig,
};
use filecoin_proofs_v1::{with_shape, TreeRHasher};

use crate::{types::PartitionProofBytes, Commitment, PieceInfo, RegisteredUpdateProof};

fn empty_sector_update_encode_into_inner<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    registered_proof: RegisteredUpdateProof,
    new_replica_path: &Path,
    new_cache_path: &Path,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    staged_data_path: &Path,
    piece_infos: &[PieceInfo],
) -> Result<EmptySectorUpdateEncoded> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let config = registered_proof.as_v1_config();

    filecoin_proofs_v1::encode_into::<Tree>(
        config,
        new_replica_path,
        new_cache_path,
        sector_key_path,
        sector_key_cache_path,
        staged_data_path,
        piece_infos,
    )
}

/// Encodes data into an existing replica.
/// Returns tuple of (comm_r_new, comm_r_last_new, comm_d_new)
pub fn empty_sector_update_encode_into<R, S, T, U, V>(
    registered_proof: RegisteredUpdateProof,
    new_replica_path: R,
    new_cache_path: S,
    sector_key_path: T,
    sector_key_cache_path: U,
    staged_data_path: V,
    piece_infos: &[PieceInfo],
) -> Result<EmptySectorUpdateEncoded>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
    T: AsRef<Path>,
    U: AsRef<Path>,
    V: AsRef<Path>,
{
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        empty_sector_update_encode_into_inner,
        registered_proof,
        new_replica_path.as_ref(),
        new_cache_path.as_ref(),
        sector_key_path.as_ref(),
        sector_key_cache_path.as_ref(),
        staged_data_path.as_ref(),
        piece_infos,
    )
}

fn empty_sector_update_decode_from_inner<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    registered_proof: RegisteredUpdateProof,
    out_data_path: &Path,
    replica_path: &Path,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    comm_d_new: Commitment,
) -> Result<()> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let config = registered_proof.as_v1_config();
    let update_config = SectorUpdateConfig::from_porep_config(config);

    filecoin_proofs_v1::decode_from::<Tree>(
        update_config,
        out_data_path,
        replica_path,
        sector_key_path,
        sector_key_cache_path,
        comm_d_new,
    )
}

/// Reverses the encoding process and outputs the data into out_data_path.
pub fn empty_sector_update_decode_from<R, S, T, U>(
    registered_proof: RegisteredUpdateProof,
    out_data_path: R,
    replica_path: S,
    sector_key_path: T,
    sector_key_cache_path: U,
    comm_d_new: Commitment,
) -> Result<()>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
    T: AsRef<Path>,
    U: AsRef<Path>,
{
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        empty_sector_update_decode_from_inner,
        registered_proof,
        out_data_path.as_ref(),
        replica_path.as_ref(),
        sector_key_path.as_ref(),
        sector_key_cache_path.as_ref(),
        comm_d_new,
    )
}

fn empty_sector_update_remove_encoded_data_inner<
    Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>,
>(
    registered_proof: RegisteredUpdateProof,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    replica_path: &Path,
    replica_cache_path: &Path,
    data_path: &Path,
    comm_d_new: Commitment,
) -> Result<()> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let config = registered_proof.as_v1_config();
    let update_config = SectorUpdateConfig::from_porep_config(config);

    filecoin_proofs_v1::remove_encoded_data::<Tree>(
        update_config,
        sector_key_path,
        sector_key_cache_path,
        replica_path,
        replica_cache_path,
        data_path,
        comm_d_new,
    )
}

/// Removes encoded data and outputs the sector key.
pub fn empty_sector_update_remove_encoded_data<R, S, T, U, V>(
    registered_proof: RegisteredUpdateProof,
    sector_key_path: R,
    sector_key_cache_path: S,
    replica_path: T,
    replica_cache_path: U,
    data_path: V,
    comm_d_new: Commitment,
) -> Result<()>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
    T: AsRef<Path>,
    U: AsRef<Path>,
    V: AsRef<Path>,
{
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        empty_sector_update_remove_encoded_data_inner,
        registered_proof,
        sector_key_path.as_ref(),
        sector_key_cache_path.as_ref(),
        replica_path.as_ref(),
        replica_cache_path.as_ref(),
        data_path.as_ref(),
        comm_d_new,
    )
}

fn generate_partition_proofs_inner<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    registered_proof: RegisteredUpdateProof,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    replica_path: &Path,
    replica_cache_path: &Path,
) -> Result<Vec<PartitionProofBytes>> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let config = registered_proof.as_v1_config();
    let sector_config = SectorUpdateConfig::from_porep_config(config);

    let partition_proofs = filecoin_proofs_v1::generate_partition_proofs::<Tree>(
        sector_config,
        comm_r_old,
        comm_r_new,
        comm_d_new,
        sector_key_path,
        sector_key_cache_path,
        replica_path,
        replica_cache_path,
    )?;

    let mut returned_proofs = Vec::with_capacity(partition_proofs.len());
    for proof in partition_proofs {
        returned_proofs.push(PartitionProofBytes(bincode::serialize(&proof)?));
    }

    Ok(returned_proofs)
}

pub fn generate_partition_proofs<R, S, T, U>(
    registered_proof: RegisteredUpdateProof,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
    sector_key_path: R,
    sector_key_cache_path: S,
    replica_path: T,
    replica_cache_path: U,
) -> Result<Vec<PartitionProofBytes>>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
    T: AsRef<Path>,
    U: AsRef<Path>,
{
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        generate_partition_proofs_inner,
        registered_proof,
        comm_r_old,
        comm_r_new,
        comm_d_new,
        sector_key_path.as_ref(),
        sector_key_cache_path.as_ref(),
        replica_path.as_ref(),
        replica_cache_path.as_ref(),
    )
}

fn verify_partition_proofs_inner<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    registered_proof: RegisteredUpdateProof,
    partition_proofs: &[PartitionProofBytes],
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
) -> Result<bool> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let config = registered_proof.as_v1_config();
    let sector_config = SectorUpdateConfig::from_porep_config(config);

    let mut proofs = Vec::with_capacity(partition_proofs.len());
    for proof in partition_proofs {
        let proof: PartitionProof<Tree> = bincode::deserialize(&proof.0)?;
        proofs.push(proof);
    }

    let valid = filecoin_proofs_v1::verify_partition_proofs::<Tree>(
        sector_config,
        &proofs,
        comm_r_old,
        comm_r_new,
        comm_d_new,
    )?;

    Ok(valid)
}

pub fn verify_partition_proofs(
    registered_proof: RegisteredUpdateProof,
    partition_proofs: &[PartitionProofBytes],
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
) -> Result<bool> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        verify_partition_proofs_inner,
        registered_proof,
        partition_proofs,
        comm_r_old,
        comm_r_new,
        comm_d_new,
    )
}

fn generate_empty_sector_update_proof_inner_with_vanilla<
    Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>,
>(
    registered_proof: RegisteredUpdateProof,
    vanilla_proofs: Vec<PartitionProofBytes>,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
) -> Result<EmptySectorUpdateProof> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let config = registered_proof.as_v1_config();

    let mut partition_proofs = Vec::with_capacity(vanilla_proofs.len());
    for proof in vanilla_proofs {
        let proof: PartitionProof<Tree> = bincode::deserialize(&proof.0)?;
        partition_proofs.push(proof);
    }

    filecoin_proofs_v1::generate_empty_sector_update_proof_with_vanilla::<Tree>(
        config,
        partition_proofs,
        comm_r_old,
        comm_r_new,
        comm_d_new,
    )
}

pub fn generate_empty_sector_update_proof_with_vanilla(
    registered_proof: RegisteredUpdateProof,
    vanilla_proofs: Vec<PartitionProofBytes>,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
) -> Result<EmptySectorUpdateProof> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        generate_empty_sector_update_proof_inner_with_vanilla,
        registered_proof,
        vanilla_proofs,
        comm_r_old,
        comm_r_new,
        comm_d_new,
    )
}

fn generate_empty_sector_update_proof_inner<
    Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>,
>(
    registered_proof: RegisteredUpdateProof,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    replica_path: &Path,
    replica_cache_path: &Path,
) -> Result<EmptySectorUpdateProof> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let config = registered_proof.as_v1_config();

    filecoin_proofs_v1::generate_empty_sector_update_proof::<Tree>(
        config,
        comm_r_old,
        comm_r_new,
        comm_d_new,
        sector_key_path,
        sector_key_cache_path,
        replica_path,
        replica_cache_path,
    )
}

pub fn generate_empty_sector_update_proof<R, S, T, U>(
    registered_proof: RegisteredUpdateProof,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
    sector_key_path: R,
    sector_key_cache_path: S,
    replica_path: T,
    replica_cache_path: U,
) -> Result<EmptySectorUpdateProof>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
    T: AsRef<Path>,
    U: AsRef<Path>,
{
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        generate_empty_sector_update_proof_inner,
        registered_proof,
        comm_r_old,
        comm_r_new,
        comm_d_new,
        sector_key_path.as_ref(),
        sector_key_cache_path.as_ref(),
        replica_path.as_ref(),
        replica_cache_path.as_ref(),
    )
}

fn verify_empty_sector_update_proof_inner<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    registered_proof: RegisteredUpdateProof,
    proof: &[u8],
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
) -> Result<bool> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    let config = registered_proof.as_v1_config();

    filecoin_proofs_v1::verify_empty_sector_update_proof::<Tree>(
        config, proof, comm_r_old, comm_r_new, comm_d_new,
    )
}

pub fn verify_empty_sector_update_proof(
    registered_proof: RegisteredUpdateProof,
    proof: &[u8],
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
) -> Result<bool> {
    ensure!(
        registered_proof.major_version() == 1,
        "unusupported version"
    );

    with_shape!(
        u64::from(registered_proof.sector_size()),
        verify_empty_sector_update_proof_inner,
        registered_proof,
        proof,
        comm_r_old,
        comm_r_new,
        comm_d_new,
    )
}
