use crate::gen::{CGenConfig, CGenSuite, Command, RemoteAttestationConfig};
use anyhow::Result;
use clap::Parser;
use crypto::Address;
use enclave_api::Enclave;
use host_environment::Environment;
use ibc_test_framework::prelude::run_binary_channel_test;
use keymanager::EnclaveKeyManager;
use std::{
    path::PathBuf,
    str::FromStr,
    sync::{Arc, RwLock},
};
use store::{host::HostStore, memory::MemStore};
use tempfile::TempDir;

/// Entry point for LCP CLI.
#[derive(Debug, Parser)]
#[clap(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION"),
    arg_required_else_help = true,
)]
pub struct Cli {
    /// Path to the enclave binary
    #[clap(long = "enclave", help = "Path to enclave binary")]
    pub enclave: PathBuf,
    /// Output path to LCP commitments
    #[clap(long = "out", help = "Output path to LCP commitments")]
    pub out_dir: PathBuf,
    /// Commands to process
    #[clap(long = "commands", help = "Commands to process", multiple = true)]
    pub commands: Vec<String>,

    #[clap(long = "eknum", default_value = "1", help = "Enclave key number")]
    pub eknum: u32,

    #[clap(long = "default_operator", help = "Default operator address")]
    pub default_operator: Option<String>,

    /// Whether to simulate the remote attestation
    #[clap(long = "simulate", help = "Whether to simulate the remote attestation")]
    pub simulate: bool,

    /// Path to a der-encoded file that contains X.509 certificate
    #[clap(
        long = "signing_cert_path",
        help = "Path to a der-encoded file that contains X.509 certificate"
    )]
    pub signing_cert_path: Option<PathBuf>,

    /// Path to a PEM-encoded file that contains PKCS#8 private key
    #[clap(
        long = "signing_key",
        help = "Path to a PEM-encoded file that contains PKCS#8 private key"
    )]
    pub signing_key_path: Option<PathBuf>,
}

impl Cli {
    pub fn run(self) -> Result<()> {
        let tmp_dir = TempDir::new()?;
        let home = tmp_dir.path();

        host::set_environment(Environment::new(
            home.into(),
            Arc::new(RwLock::new(HostStore::Memory(MemStore::default()))),
        ))
        .unwrap();

        let env = host::get_environment().unwrap();
        let ekm = EnclaveKeyManager::new(home)?;
        let enclave = Enclave::create(&self.enclave, true, ekm, env.store.clone())?;

        let mut commands = vec![];
        for c in self.commands.iter() {
            commands.push(Command::from_str(c)?);
        }

        let config = self.build_config()?;
        let default_operator: Option<Address> = self
            .default_operator
            .map(|s| Address::from_hex_string(&s))
            .transpose()?;
        run_binary_channel_test(&CGenSuite::new(
            config,
            enclave,
            commands,
            self.eknum,
            default_operator,
        ))?;
        Ok(())
    }

    #[cfg(not(feature = "simulation"))]
    fn build_config(&self) -> Result<CGenConfig> {
        let spid = std::env::var("SPID")?.as_bytes().to_vec();
        let ias_key = std::env::var("IAS_KEY")?.as_bytes().to_vec();
        Ok(CGenConfig {
            ra_config: RemoteAttestationConfig::IAS { spid, ias_key },
            out_dir: self.out_dir.clone(),
        })
    }

    #[cfg(feature = "simulation")]
    fn build_config(&self) -> Result<CGenConfig> {
        use enclave_api::rsa::{pkcs1v15::SigningKey, pkcs8::DecodePrivateKey, RsaPrivateKey};
        use enclave_api::sha2::Sha256;
        let signing_cert = std::fs::read(self.signing_cert_path.as_ref().expect(
            "if simulate is true, then signing_cert_path and signing_key_path must be provided",
        ))?;
        let signing_key = SigningKey::<Sha256>::new(RsaPrivateKey::read_pkcs8_pem_file(
            self.signing_key_path.as_ref().expect(
                "if simulate is true, then signing_cert_path and signing_key_path must be provided",
            ),
        )?);
        Ok(CGenConfig {
            ra_config: RemoteAttestationConfig::Simulate {
                signing_cert,
                signing_key,
            },
            out_dir: self.out_dir.clone(),
        })
    }
}
