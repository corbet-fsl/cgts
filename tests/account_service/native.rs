//! Host-supplied real native artifacts; no generated or accepting proof fixture.
use cblc::{
    accounting_service::NativeAccountVerifier,
    artifacts::{AccountArtifacts, ArtifactBytes, NativeVerifierOptions},
};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    directory: PathBuf,
    manifest_sha256: String,
}

pub fn verifier() -> NativeAccountVerifier {
    verifier_with_limit(1024)
}

pub fn verifier_with_limit(max_proof_bytes: usize) -> NativeAccountVerifier {
    let root = PathBuf::from(
        std::env::var_os("CBLC_PROOF_DIRECTORY")
            .expect("account tests require original authenticated native artifact fixtures"),
    );
    assert!(root.is_absolute());
    let config: Config =
        serde_json::from_slice(&std::fs::read(root.join("config.json")).unwrap()).unwrap();
    assert!(config.directory.is_absolute());
    let pin = data_encoding::HEXLOWER
        .decode(config.manifest_sha256.as_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    let manifest = std::fs::read(config.directory.join("manifest.json")).unwrap();
    let circuit = std::fs::read(config.directory.join("circuit.json")).unwrap();
    let keys = std::fs::read(config.directory.join("vk.bin")).unwrap();
    let srs_g1 = std::fs::read(config.directory.join("setup/g1.dat")).unwrap();
    let srs_g2 = std::fs::read(config.directory.join("setup/g2.dat")).unwrap();
    let artifacts = AccountArtifacts::authenticate(ArtifactBytes {
        manifest: &manifest,
        manifest_sha256: pin,
        circuit: &circuit,
        keys: &keys,
        srs_g1: &srs_g1,
        srs_g2: &srs_g2,
    })
    .unwrap();
    NativeAccountVerifier::new(
        NativeVerifierOptions {
            executable: std::env::var_os("CBLC_BB")
                .expect("account tests require the maintained native worker")
                .into(),
            timeout: Duration::from_secs(180),
            maximum_parallel: 1,
            max_proof_bytes,
            threads: 1,
            memory_megabytes: 8192,
        },
        artifacts,
    )
    .unwrap()
}
