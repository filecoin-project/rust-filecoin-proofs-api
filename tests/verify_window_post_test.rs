use filecoin_proofs_api::post::verify_window_post;
use filecoin_proofs_api::RegisteredPoStProof::{
    StackedDrgWindow32GiBV1, StackedDrgWindow32GiBV1_2,
};
use filecoin_proofs_api::{PublicReplicaInfo, RegisteredPoStProof};
use filecoin_proofs_v1::{ChallengeSeed, ProverId};
use std::collections::BTreeMap;
use storage_proofs_core::sector::SectorId;

#[test]
#[cfg(feature = "big-tests")]
fn verify_post() {
    let randomness = ChallengeSeed::from([
        47, 180, 15, 215, 4, 51, 54, 214, 69, 205, 19, 137, 99, 198, 249, 96, 246, 73, 219, 83,
        160, 245, 50, 226, 100, 89, 142, 159, 83, 226, 237, 35,
    ]);
    let post_proof_v1: &[(RegisteredPoStProof, &[u8])] = &[(
        StackedDrgWindow32GiBV1,
        &[
            181, 223, 130, 56, 59, 30, 190, 80, 43, 249, 221, 153, 147, 148, 98, 121, 237, 44, 151,
            249, 139, 112, 43, 60, 46, 204, 169, 18, 51, 14, 113, 152, 215, 192, 189, 33, 229, 57,
            132, 48, 44, 14, 223, 15, 212, 245, 113, 23, 132, 212, 146, 166, 26, 242, 115, 122, 83,
            72, 156, 7, 218, 41, 27, 153, 254, 3, 232, 30, 133, 190, 150, 211, 250, 86, 117, 123,
            227, 85, 180, 236, 61, 183, 1, 165, 5, 116, 230, 132, 224, 247, 194, 126, 12, 111, 86,
            243, 9, 194, 191, 175, 150, 27, 154, 113, 247, 166, 200, 119, 62, 0, 186, 134, 155, 83,
            232, 227, 89, 161, 156, 246, 37, 112, 85, 22, 24, 241, 108, 85, 234, 247, 225, 18, 234,
            136, 107, 23, 50, 21, 166, 75, 167, 77, 227, 40, 128, 21, 11, 121, 154, 22, 160, 200,
            152, 249, 6, 90, 78, 190, 217, 21, 141, 63, 90, 34, 125, 180, 161, 13, 220, 119, 173,
            169, 86, 170, 200, 48, 12, 90, 80, 26, 79, 213, 92, 19, 174, 30, 29, 11, 53, 47, 157,
            1,
        ],
    )];
    let public_replica_info_v1 = PublicReplicaInfo::new(
        StackedDrgWindow32GiBV1,
        [
            85, 177, 161, 128, 182, 149, 59, 73, 186, 144, 39, 142, 172, 241, 4, 165, 209, 60, 20,
            153, 120, 49, 236, 233, 203, 115, 95, 195, 117, 182, 84, 31,
        ],
    );
    let replicas_v1: BTreeMap<SectorId, PublicReplicaInfo> =
        BTreeMap::from([(SectorId::from(132), public_replica_info_v1)]);
    let prover_id = ProverId::from([
        167, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ]);

    assert!(verify_window_post(&randomness, &post_proof_v1, &replicas_v1, prover_id).unwrap());

    let post_proof_v2: &[(RegisteredPoStProof, &[u8])] = &[(
        StackedDrgWindow32GiBV1_2,
        &[
            181, 223, 130, 56, 59, 30, 190, 80, 43, 249, 221, 153, 147, 148, 98, 121, 237, 44, 151,
            249, 139, 112, 43, 60, 46, 204, 169, 18, 51, 14, 113, 152, 215, 192, 189, 33, 229, 57,
            132, 48, 44, 14, 223, 15, 212, 245, 113, 23, 132, 212, 146, 166, 26, 242, 115, 122, 83,
            72, 156, 7, 218, 41, 27, 153, 254, 3, 232, 30, 133, 190, 150, 211, 250, 86, 117, 123,
            227, 85, 180, 236, 61, 183, 1, 165, 5, 116, 230, 132, 224, 247, 194, 126, 12, 111, 86,
            243, 9, 194, 191, 175, 150, 27, 154, 113, 247, 166, 200, 119, 62, 0, 186, 134, 155, 83,
            232, 227, 89, 161, 156, 246, 37, 112, 85, 22, 24, 241, 108, 85, 234, 247, 225, 18, 234,
            136, 107, 23, 50, 21, 166, 75, 167, 77, 227, 40, 128, 21, 11, 121, 154, 22, 160, 200,
            152, 249, 6, 90, 78, 190, 217, 21, 141, 63, 90, 34, 125, 180, 161, 13, 220, 119, 173,
            169, 86, 170, 200, 48, 12, 90, 80, 26, 79, 213, 92, 19, 174, 30, 29, 11, 53, 47, 157,
            1,
        ],
    )];
    let public_replica_info_v2 = PublicReplicaInfo::new(
        StackedDrgWindow32GiBV1_2,
        [
            85, 177, 161, 128, 182, 149, 59, 73, 186, 144, 39, 142, 172, 241, 4, 165, 209, 60, 20,
            153, 120, 49, 236, 233, 203, 115, 95, 195, 117, 182, 84, 31,
        ],
    );
    let replicas_v2: BTreeMap<SectorId, PublicReplicaInfo> =
        BTreeMap::from([(SectorId::from(132), public_replica_info_v2)]);
    assert!(verify_window_post(&randomness, &post_proof_v2, &replicas_v2, prover_id).unwrap());
}
