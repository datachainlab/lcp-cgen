use crate::relayer::Relayer;
use crate::relayer::{to_ibc_channel_id, to_ibc_connection_id, to_ibc_port_id};
use crate::types::{JSONCommitmentProof, JSONInitClientResult, JSONSerializer};
use anyhow::{anyhow, bail};
use commitments::{CommitmentProof, UpdateStateProxyMessage};
use crypto::Address;
use ecall_commands::{
    AggregateMessagesInput, CommitmentProofPair, GenerateEnclaveKeyInput,
    IASRemoteAttestationInput, InitClientInput, UpdateClientInput, VerifyMembershipInput,
    VerifyNonMembershipInput,
};
use enclave_api::{Enclave, EnclaveCommandAPI};
use ibc::core::ics04_channel::packet::Sequence;
use ibc::core::ics23_commitment::commitment::CommitmentProofBytes;
use ibc::core::ics23_commitment::merkle::MerkleProof;
use ibc::core::ics24_host::path::{ChannelEndPath, CommitmentPath, ConnectionPath, ReceiptPath};
use ibc::core::ics24_host::Path;
use ibc::Height;
use ibc_proto::protobuf::Protobuf;
use ibc_test_framework::prelude::*;
use ibc_test_framework::util::random::random_u64_range;
use lcp_types::{ClientId, Time};
use std::str::FromStr;
use std::sync::Arc;
use std::{fs::File, io::Write, path::PathBuf};
use tokio::runtime::Runtime as TokioRuntime;

pub struct CGenSuite {
    config: CGenConfig,
    enclave: Enclave<store::memory::MemStore>,
    commands: Vec<Command>,
    eknum: u32,
}

impl CGenSuite {
    pub fn new(
        config: CGenConfig,
        enclave: Enclave<store::memory::MemStore>,
        commands: Vec<Command>,
        eknum: u32,
    ) -> Self {
        Self {
            config,
            enclave,
            commands,
            eknum,
        }
    }
}

#[derive(Clone)]
pub struct CGenConfig {
    pub(crate) ra_config: RemoteAttestationConfig,
    pub(crate) out_dir: PathBuf,
}

#[derive(Clone)]
pub enum RemoteAttestationConfig {
    #[cfg(feature = "simulation")]
    Simulate {
        signing_cert: Vec<u8>,
        signing_key: enclave_api::rsa::pkcs1v15::SigningKey<enclave_api::sha2::Sha256>,
    },
    IAS {
        spid: Vec<u8>,
        ias_key: Vec<u8>,
    },
}

pub enum Command {
    GenerateEnclaveKey,
    CreateClient(u64),
    UpdateClient(Vec<usize>),
    AggregateMessages(u64, u64, u64),
    VerifyConnection(u64),
    VerifyChannel(u64),
    VerifyPacket(u64),
    VerifyPacketReceiptAbsence(u64),
    WaitBlocks(u64),
}

impl FromStr for Command {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        match parts[0] {
            "generate_enclave_key" => Ok(Command::GenerateEnclaveKey),
            "create_client" => {
                if parts.len() != 2 {
                    bail!("`create_client` requires one argument");
                }
                Ok(Command::CreateClient(u64::from_str(parts[1])?))
            }
            "update_client" => {
                if parts.len() != 2 {
                    bail!("`update_client` requires one argument");
                }
                let parts: Vec<&str> = parts[1].split(',').collect();
                Ok(Command::UpdateClient(
                    parts
                        .iter()
                        .map(|s| usize::from_str(s))
                        .collect::<Result<_, _>>()?,
                ))
            }
            "aggregate_messages" => {
                if parts.len() != 4 {
                    bail!("`aggregate_messages` requires three arguments");
                }
                Ok(Command::AggregateMessages(
                    u64::from_str(parts[1])?,
                    u64::from_str(parts[2])?,
                    u64::from_str(parts[3])?,
                ))
            }
            "verify_connection" => {
                if parts.len() != 2 {
                    bail!("`verify_connection` requires one argument");
                }
                Ok(Command::VerifyConnection(u64::from_str(parts[1])?))
            }
            "verify_channel" => {
                if parts.len() != 2 {
                    bail!("`verify_channel` requires one argument");
                }
                Ok(Command::VerifyChannel(u64::from_str(parts[1])?))
            }
            "verify_packet" => {
                if parts.len() != 2 {
                    bail!("`verify_packet` requires one argument");
                }
                Ok(Command::VerifyPacket(u64::from_str(parts[1])?))
            }
            "verify_packet_receipt_absence" => {
                if parts.len() != 2 {
                    bail!("`verify_packet_receipt_absence` requires one argument");
                }
                Ok(Command::VerifyPacketReceiptAbsence(u64::from_str(
                    parts[1],
                )?))
            }
            "wait_blocks" => {
                if parts.len() != 2 {
                    bail!("`wait` requires one argument");
                }
                Ok(Command::WaitBlocks(u64::from_str(parts[1])?))
            }
            _ => bail!("unknown command: '{}'", s),
        }
    }
}

pub struct CommandFileGenerator<'e, ChainA: ChainHandle, ChainB: ChainHandle> {
    config: CGenConfig,
    enclave: &'e Enclave<store::memory::MemStore>,
    rly: Relayer,

    enclave_key: Vec<Address>,
    channel: ConnectedChannel<ChainA, ChainB>,
    command_sequence: u64,

    client_counter: u64,
    client_latest_height: Option<Height>, // latest height of client state
    chain_latest_provable_height: Height, // latest provable height of chainA
}

impl<'e, ChainA: ChainHandle, ChainB: ChainHandle> CommandFileGenerator<'e, ChainA, ChainB> {
    pub fn new(
        config: CGenConfig,
        enclave: &'e Enclave<store::memory::MemStore>,
        rly: Relayer,
        channel: ConnectedChannel<ChainA, ChainB>,
    ) -> Self {
        let chain_latest_provable_height = rly.query_latest_height().unwrap().decrement().unwrap();
        Self {
            config,
            enclave,
            rly,
            enclave_key: Default::default(),
            channel,
            command_sequence: 1,
            client_counter: 0,
            client_latest_height: None,
            chain_latest_provable_height,
        }
    }

    pub fn gen(
        &mut self,
        commands: &[Command],
        wait_blocks: u64,
        eknum: u32,
    ) -> Result<(), anyhow::Error> {
        if eknum == 0 {
            bail!("`eknum` must be greater than 0");
        }
        if wait_blocks > 0 {
            self.wait_blocks(wait_blocks)?;
        }
        // generate enclave key `eknum` times
        for _ in 0..eknum {
            self.generate_enclave_key()?;
            self.command_sequence += 1;
        }
        let (seq, client_id) = self.create_client(0)?;
        self.command_sequence += seq;
        self.wait_blocks(1)?;

        for cmd in commands.iter() {
            assert!(self.command_sequence < 1000);
            self.command_sequence += match cmd {
                Command::GenerateEnclaveKey => self.generate_enclave_key()?,
                Command::CreateClient(ek_index) => self.create_client(*ek_index as usize)?.0,
                Command::UpdateClient(ek_indice) => {
                    self.update_client(client_id.clone(), ek_indice.clone(), false)?
                        .0
                }
                Command::AggregateMessages(ek_index, interval, msg_num) => self
                    .aggregate_messages(
                        client_id.clone(),
                        *ek_index as usize,
                        *interval,
                        *msg_num,
                    )?,
                Command::VerifyConnection(ek_index) => {
                    self.verify_connection(client_id.clone(), *ek_index as usize)?
                }
                Command::VerifyChannel(ek_index) => {
                    self.verify_channel(client_id.clone(), *ek_index as usize)?
                }
                // TODO get sequence from command
                Command::VerifyPacket(ek_index) => {
                    self.verify_packet(client_id.clone(), *ek_index as usize, 1u64.into())?
                }
                Command::VerifyPacketReceiptAbsence(ek_index) => self
                    .verify_packet_receipt_absence(
                        client_id.clone(),
                        *ek_index as usize,
                        2u64.into(),
                    )?,
                Command::WaitBlocks(n) => {
                    self.wait_blocks(*n)?;
                    0
                }
            };
        }
        Ok(())
    }

    fn generate_enclave_key(&mut self) -> Result<u64, anyhow::Error> {
        let res = match self.enclave.generate_enclave_key(GenerateEnclaveKeyInput) {
            Ok(res) => res,
            Err(e) => {
                bail!("Init Enclave Failed {:?}", e);
            }
        };
        info!(
            "generated enclave key: addr={:?} index={}",
            res.pub_key.as_address(),
            self.enclave_key.len()
        );
        self.enclave_key.push(res.pub_key.as_address());
        self.remote_attestation(res.pub_key.as_address())?;
        Ok(1)
    }

    #[cfg(not(feature = "simulation"))]
    fn remote_attestation(&mut self, ek: Address) -> Result<(), anyhow::Error> {
        match self.config.ra_config.clone() {
            RemoteAttestationConfig::IAS { spid, ias_key } => {
                let res = match self
                    .enclave
                    .ias_remote_attestation(IASRemoteAttestationInput {
                        target_enclave_key: ek,
                        spid,
                        ias_key,
                    }) {
                    Ok(res) => res.report,
                    Err(e) => {
                        bail!("IAS Remote Attestation Failed {:?}!", e);
                    }
                };

                self.write_to_file("avr", &res)?;
                Ok(())
            }
        }
    }

    #[cfg(feature = "simulation")]
    fn remote_attestation(&mut self, ek: Address) -> Result<(), anyhow::Error> {
        use attestation_report::EndorsedAttestationVerificationReport;
        use enclave_api::rsa::{
            pkcs1v15::SigningKey,
            signature::{SignatureEncoding, Signer},
        };
        use enclave_api::sha2::Sha256;

        match self.config.ra_config.clone() {
            RemoteAttestationConfig::Simulate {
                signing_cert,
                signing_key,
            } => {
                let res = self.enclave.simulate_remote_attestation(
                    ecall_commands::SimulateRemoteAttestationInput {
                        target_enclave_key: ek,
                        advisory_ids: vec![],
                        isv_enclave_quote_status: "OK".to_string(),
                    },
                    signing_key.clone(),
                    signing_cert.clone(),
                )?;
                let avr_json = res.avr.to_canonical_json().unwrap();
                let signature = signing_key.sign(avr_json.as_bytes()).to_vec();
                self.write_to_file(
                    "avr",
                    &EndorsedAttestationVerificationReport {
                        avr: avr_json,
                        signature,
                        signing_cert,
                    },
                )?;
                Ok(())
            }
            _ => {
                bail!("RA with IAS is not supported");
            }
        }
    }

    fn create_client(&mut self, ek_index: usize) -> Result<(u64, ClientId), anyhow::Error> {
        let (client_state, consensus_state) = self
            .rly
            .fetch_state_as_any(self.chain_latest_provable_height)?;
        log::info!(
            "initial_height: {:?} client_state: {:?}, consensus_state: {:?}",
            self.chain_latest_provable_height,
            client_state,
            consensus_state
        );

        let client_id = ClientId::new("07-tendermint", self.client_counter)?;
        let input = InitClientInput {
            client_id: client_id.to_string(),
            any_client_state: client_state,
            any_consensus_state: consensus_state,
            current_timestamp: Time::now(),
            signer: self.enclave_key[ek_index],
        };

        self.write_to_file("init_client_input", &input)?;

        let res = self.enclave.init_client(input).unwrap();
        assert!(!res.proof.is_proven());
        self.client_counter += 1;

        log::info!("generated client id is {}", client_id);

        self.write_to_file(
            "init_client_result",
            &JSONInitClientResult {
                client_id: client_id.clone(),
                proof: JSONCommitmentProof {
                    message: res.proof.message,
                    signer: res.proof.signer.to_vec(),
                    signature: res.proof.signature,
                },
            },
        )?;

        self.client_latest_height = Some(self.chain_latest_provable_height);

        Ok((1, client_id))
    }

    fn update_client(
        &mut self,
        client_id: ClientId,
        ek_indice: Vec<usize>,
        no_logs: bool,
    ) -> Result<(u64, CommitmentProof), anyhow::Error> {
        assert!(ek_indice.len() > 0, "invalid arguments");
        assert!(
            self.chain_latest_provable_height > self.client_latest_height.unwrap(),
            "To update the client, you need to advance block's height with `wait_blocks`"
        );
        let trusted_height = self.client_latest_height.unwrap();

        let target_header = self
            .rly
            .create_header(trusted_height, self.chain_latest_provable_height)?;

        let mut proofs = Vec::new();
        for ek_index in ek_indice.iter() {
            let input = UpdateClientInput {
                client_id: client_id.clone(),
                any_header: target_header.clone(),
                current_timestamp: Time::now(),
                include_state: true,
                signer: self.enclave_key[*ek_index],
            };

            info!("update_client's input is {:?}", input);

            if !no_logs {
                self.write_to_file("update_client_input", &input)?;
            }

            let res = self.enclave.update_client(input)?;
            info!("update_client's result is {:?}", res);
            assert!(res.0.is_proven());

            if !no_logs {
                self.write_to_file("update_client_result", &res.0)?;
            }

            let msg: UpdateStateProxyMessage = res.0.message()?.try_into()?;
            assert!(self.chain_latest_provable_height == msg.post_height.try_into()?);
            proofs.push(res.0);
            self.command_sequence += 1;
        }
        self.client_latest_height = Some(self.chain_latest_provable_height);
        Ok((0, proofs.pop().unwrap()))
    }

    fn aggregate_messages(
        &mut self,
        client_id: ClientId,
        ek_index: usize,
        interval: u64,
        msg_num: u64,
    ) -> Result<u64, anyhow::Error> {
        assert!(msg_num > 0 && interval > 0, "invalid arguments");
        let mut proofs = Vec::new();
        for _ in 0..msg_num {
            let proof = self.update_client(client_id.clone(), vec![ek_index], true)?;
            self.wait_blocks(interval)?;
            proofs.push(proof);
        }
        let messages = proofs
            .iter()
            .map(|(_, p)| p.message().map(|m| m.to_bytes()))
            .collect::<Result<_, _>>()?;
        let signatures = proofs.into_iter().map(|(_, p)| p.signature).collect();
        let input = AggregateMessagesInput {
            messages,
            signatures,
            current_timestamp: Time::now(),
            signer: self.enclave_key[ek_index],
        };
        self.write_to_file("aggregate_messages_input", &input)?;
        let res = self.enclave.aggregate_messages(input)?;
        self.write_to_file("aggregate_messages_result", &res.0)?;
        Ok(1)
    }

    fn verify_connection(
        &mut self,
        client_id: ClientId,
        ek_index: usize,
    ) -> Result<u64, anyhow::Error> {
        let res = self.rly.query_connection_proof(
            to_ibc_connection_id(
                self.channel
                    .connection
                    .connection
                    .a_connection_id()
                    .unwrap()
                    .clone(),
            ),
            self.client_latest_height,
        )?;

        let input = VerifyMembershipInput {
            client_id,
            prefix: "ibc".into(),
            path: Path::Connection(ConnectionPath(to_ibc_connection_id(
                self.channel
                    .connection
                    .connection
                    .a_connection_id()
                    .unwrap()
                    .clone(),
            )))
            .to_string(),
            value: res.0.encode_vec().unwrap(),
            proof: CommitmentProofPair(
                res.2.try_into().map_err(|e| anyhow!("{:?}", e))?,
                merkle_proof_to_bytes(res.1)?,
            ),
            signer: self.enclave_key[ek_index],
        };
        self.write_to_file("verify_connection_input", &input)?;
        let res = self.enclave.verify_membership(input)?;
        self.write_to_file("verify_connection_result", &res.0)?;

        Ok(1)
    }

    fn verify_channel(
        &mut self,
        client_id: ClientId,
        ek_index: usize,
    ) -> Result<u64, anyhow::Error> {
        let res = self.rly.query_channel_proof(
            to_ibc_port_id(self.channel.channel.a_side.port_id().clone()),
            to_ibc_channel_id(self.channel.channel.a_side.channel_id().unwrap().clone()),
            self.client_latest_height,
        )?;

        let input = VerifyMembershipInput {
            client_id,
            prefix: "ibc".into(),
            path: Path::ChannelEnd(ChannelEndPath(
                to_ibc_port_id(self.channel.channel.a_side.port_id().clone()),
                to_ibc_channel_id(self.channel.channel.a_side.channel_id().unwrap().clone()),
            ))
            .to_string(),
            value: res.0.encode_vec().unwrap(),
            proof: CommitmentProofPair(
                res.2.try_into().map_err(|e| anyhow!("{:?}", e))?,
                merkle_proof_to_bytes(res.1)?,
            ),
            signer: self.enclave_key[ek_index],
        };
        self.write_to_file("verify_channel_input", &input)?;
        let res = self.enclave.verify_membership(input)?;
        self.write_to_file("verify_channel_result", &res.0)?;

        Ok(1)
    }

    fn verify_packet(
        &mut self,
        client_id: ClientId,
        ek_index: usize,
        sequence: Sequence,
    ) -> Result<u64, anyhow::Error> {
        let res = self.rly.query_packet_proof(
            to_ibc_port_id(self.channel.channel.a_side.port_id().clone()),
            to_ibc_channel_id(self.channel.channel.a_side.channel_id().unwrap().clone()),
            sequence,
            self.client_latest_height,
        )?;

        let input = VerifyMembershipInput {
            client_id,
            prefix: "ibc".into(),
            path: Path::Commitment(CommitmentPath {
                port_id: to_ibc_port_id(self.channel.channel.a_side.port_id().clone()),
                channel_id: to_ibc_channel_id(
                    self.channel.channel.a_side.channel_id().unwrap().clone(),
                ),
                sequence,
            })
            .to_string(),
            value: res.0.into_vec(),
            proof: CommitmentProofPair(
                res.2.try_into().map_err(|e| anyhow!("{:?}", e))?,
                merkle_proof_to_bytes(res.1)?,
            ),
            signer: self.enclave_key[ek_index],
        };

        self.write_to_file("verify_packet_input", &input)?;
        let res = self.enclave.verify_membership(input)?;
        self.write_to_file("verify_packet_result", &res.0)?;

        Ok(1)
    }

    fn verify_packet_receipt_absence(
        &mut self,
        client_id: ClientId,
        ek_index: usize,
        sequence: Sequence,
    ) -> Result<u64, anyhow::Error> {
        let res = self.rly.query_packet_receipt_proof(
            to_ibc_port_id(self.channel.channel.a_side.port_id().clone()),
            to_ibc_channel_id(self.channel.channel.a_side.channel_id().unwrap().clone()),
            sequence,
            self.client_latest_height,
        )?;

        let input = VerifyNonMembershipInput {
            client_id,
            prefix: "ibc".into(),
            path: Path::Receipt(ReceiptPath {
                port_id: to_ibc_port_id(self.channel.channel.a_side.port_id().clone()),
                channel_id: to_ibc_channel_id(
                    self.channel.channel.a_side.channel_id().unwrap().clone(),
                ),
                sequence,
            })
            .to_string(),
            proof: CommitmentProofPair(
                res.2.try_into().map_err(|e| anyhow!("{:?}", e))?,
                merkle_proof_to_bytes(res.1)?,
            ),
            signer: self.enclave_key[ek_index],
        };

        self.write_to_file("verify_packet_receipt_absence_input", &input)?;
        let res = self.enclave.verify_non_membership(input)?;
        self.write_to_file("verify_packet_receipt_absence_result", &res.0)?;

        Ok(1)
    }

    fn wait_blocks(&mut self, n: u64) -> Result<(), anyhow::Error> {
        let target = self.chain_latest_provable_height.add(n);
        loop {
            let h = self.rly.query_latest_height()?.decrement()?;
            info!(
                "wait_blocks: found new height: height={} target={}",
                h, target
            );
            if h > target {
                self.chain_latest_provable_height = target;
                return Ok(());
            }
        }
    }

    fn write_to_file<S: JSONSerializer>(
        &self,
        name: &str,
        content: &S,
    ) -> Result<(), anyhow::Error> {
        let s = content.to_json_string()?;

        let out_path = self
            .config
            .out_dir
            .join(format!("{:03}-{}", self.command_sequence, name));
        if out_path.exists() {
            bail!(format!("dir '{:?}' already exists", out_path));
        }

        File::create(out_path)?.write_all(s.as_bytes())?;
        Ok(())
    }
}

impl TestOverrides for CGenSuite {
    fn modify_relayer_config(&self, config: &mut Config) {
        // disable packet relay
        config.mode.packets.enabled = false;
    }
}

impl BinaryChannelTest for CGenSuite {
    fn run<ChainA: ChainHandle, ChainB: ChainHandle>(
        &self,
        _config: &TestConfig,
        _relayer: RelayerDriver,
        chains: ConnectedChains<ChainA, ChainB>,
        channel: ConnectedChannel<ChainA, ChainB>,
    ) -> Result<(), Error> {
        // Begin: IBC transfer

        let denom_a = chains.node_a.denom();
        let wallet_a = chains.node_a.wallets().user1().cloned();
        let wallet_b = chains.node_b.wallets().user1().cloned();
        let balance_a = chains
            .node_a
            .chain_driver()
            .query_balance(&wallet_a.address(), &denom_a)?;

        let a_to_b_amount = random_u64_range(1000, 5000);

        chains.node_a.chain_driver().ibc_transfer_token(
            &channel.port_a.as_ref(),
            &channel.channel_id_a.as_ref(),
            &wallet_a.as_ref(),
            &wallet_b.address(),
            &denom_a.with_amount(a_to_b_amount).as_ref(),
        )?;

        chains.node_a.chain_driver().assert_eventual_wallet_amount(
            &wallet_a.address(),
            &denom_a
                .with_amount(balance_a.amount().checked_sub(a_to_b_amount).unwrap())
                .as_ref(),
        )?;

        log::info!(
            "Sending IBC transfer from chain {} to chain {} with amount of {} {}",
            chains.chain_id_a(),
            chains.chain_id_b(),
            a_to_b_amount,
            denom_a
        );

        // End: IBC transfer

        let rt = Arc::new(TokioRuntime::new()?);
        let config_a = chains.handle_a().config()?;
        let rly = Relayer::new(config_a, rt).unwrap();
        CommandFileGenerator::new(self.config.clone(), &self.enclave, rly, channel)
            .gen(&self.commands, 1, self.eknum)
            .map_err(|e| Error::assertion(e.to_string()))
    }
}

fn merkle_proof_to_bytes(proof: MerkleProof) -> Result<Vec<u8>, anyhow::Error> {
    let proof = CommitmentProofBytes::try_from(proof)?;
    Ok(proof.into())
}
