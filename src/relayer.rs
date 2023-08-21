use anyhow::Result;
use ibc::clients::ics07_tendermint::client_state::ClientState;
use ibc::clients::ics07_tendermint::consensus_state::ConsensusState;
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics04_channel::commitment::PacketCommitment;
use ibc::core::ics04_channel::packet::Sequence;
use ibc::core::ics23_commitment::merkle::MerkleProof;
use ibc::{
    clients::ics07_tendermint::{
        client_state::ClientState as TendermintClientState,
        consensus_state::ConsensusState as TendermintConsensusState, header::Header,
    },
    core::{
        ics04_channel::channel::ChannelEnd,
        ics24_host::identifier::{ChainId, ChannelId, ConnectionId, PortId},
    },
    Height,
};
use ibc_proto::{google::protobuf::Any as IBCAny, protobuf::Protobuf};
use ibc_proto_relayer::{
    google::protobuf::Any as IBCRelayerAny, protobuf::Protobuf as RelayerProtobuf,
};
use ibc_relayer::chain::requests::QueryConnectionRequest;
use ibc_relayer::chain::{
    client::ClientSettings,
    cosmos::{client::Settings, CosmosSdkChain},
    endpoint::ChainEndpoint,
    requests::{IncludeProof, QueryChannelRequest, QueryHeight, QueryPacketCommitmentRequest},
};
use ibc_relayer::client_state::AnyClientState;
use ibc_relayer::config::ChainConfig;
use ibc_relayer::light_client::tendermint::LightClient as TmLightClient;
use ibc_relayer::light_client::{tendermint::LightClient, LightClient as IBCLightClient};
use ibc_relayer_types::core::ics04_channel::packet::Sequence as RSequence;
use ibc_relayer_types::core::ics24_host::identifier::{
    ChannelId as RChannelId, ConnectionId as RConnectionId, PortId as RPortId,
};
use ibc_relayer_types::{
    clients::ics07_tendermint::{
        client_state::ClientState as RTendermintClientState,
        consensus_state::ConsensusState as RTendermintConsensusState, header::Header as RHeader,
    },
    core::{
        ics03_connection::connection::ConnectionEnd as RConnectionEnd,
        ics04_channel::channel::ChannelEnd as RChannelEnd,
    },
};
use ibc_relayer_types::{core::ics24_host::identifier::ChainId as RChainId, Height as RHeight};
use lcp_types::Any;
use std::str::FromStr;
use std::sync::Arc;
use tendermint_rpc::{Client, HttpClient};
use tokio::runtime::Runtime as TokioRuntime;

/// WARNING: The following converters are very inefficient, so they should not be used except for testing purpose.
/// ibc-relayer(hermes) has owned ibc crate, not cosmos/ibc-rs. Therefore, the following converters are required for now.

/// relayer-types to lcp types

pub fn relayer_header_to_any(value: RHeader) -> Any {
    let any = IBCRelayerAny::from(value);
    Any::new(any.type_url, any.value)
}

/// relayer-types to ibc

pub fn to_ibc_connection(value: RConnectionEnd) -> ConnectionEnd {
    ConnectionEnd::decode_vec(&value.encode_vec().unwrap()).unwrap()
}

pub fn to_ibc_connection_id(value: RConnectionId) -> ConnectionId {
    ConnectionId::from_str(value.as_str()).unwrap()
}

pub fn to_ibc_channel(value: RChannelEnd) -> ChannelEnd {
    ChannelEnd::decode_vec(&value.encode_vec().unwrap()).unwrap()
}

pub fn to_ibc_channel_id(value: RChannelId) -> ChannelId {
    ChannelId::from_str(value.as_str()).unwrap()
}

pub fn to_ibc_port_id(value: RPortId) -> PortId {
    PortId::from_str(value.as_str()).unwrap()
}

pub fn to_ibc_height(value: RHeight) -> Height {
    Height::new(value.revision_number(), value.revision_height()).unwrap()
}

pub fn to_ibc_client_state(value: RTendermintClientState) -> TendermintClientState {
    let any = IBCRelayerAny::from(value);
    TendermintClientState::try_from(IBCAny {
        type_url: any.type_url,
        value: any.value,
    })
    .unwrap()
}

pub fn to_ibc_consensus_state(value: RTendermintConsensusState) -> TendermintConsensusState {
    let any = IBCRelayerAny::from(value);
    TendermintConsensusState::try_from(IBCAny {
        type_url: any.type_url,
        value: any.value,
    })
    .unwrap()
}

pub fn to_ibc_header(value: RHeader) -> Header {
    let any = IBCRelayerAny::from(value);
    Header::try_from(IBCAny {
        type_url: any.type_url,
        value: any.value,
    })
    .unwrap()
}

/// ibc to relayer-types

pub fn to_relayer_chain_id(value: ChainId) -> RChainId {
    RChainId::from_str(value.as_str()).unwrap()
}

pub fn to_relayer_height(value: Height) -> RHeight {
    RHeight::new(value.revision_number(), value.revision_height()).unwrap()
}

pub fn to_relayer_connection_id(value: ConnectionId) -> RConnectionId {
    RConnectionId::from_str(value.as_str()).unwrap()
}

pub fn to_relayer_channel_id(value: ChannelId) -> RChannelId {
    RChannelId::from_str(value.as_str()).unwrap()
}

pub fn to_relayer_port_id(value: PortId) -> RPortId {
    RPortId::from_str(value.as_str()).unwrap()
}

pub fn to_relayer_sequence(value: Sequence) -> RSequence {
    RSequence::from_str(value.to_string().as_str()).unwrap()
}

pub fn to_relayer_client_state(value: TendermintClientState) -> RTendermintClientState {
    let any = IBCAny::from(value);
    RTendermintClientState::try_from(IBCRelayerAny {
        type_url: any.type_url,
        value: any.value,
    })
    .unwrap()
}

pub fn to_relayer_consensus_state(value: TendermintConsensusState) -> RTendermintConsensusState {
    let any = IBCAny::from(value);
    RTendermintConsensusState::try_from(IBCRelayerAny {
        type_url: any.type_url,
        value: any.value,
    })
    .unwrap()
}

pub struct Relayer {
    tmlc: LightClient,
    chain: CosmosSdkChain,

    client_state: Option<ClientState>,
}

/// Initialize the light client for the given chain using the given HTTP client
/// to fetch the node identifier to be used as peer id in the light client.
async fn init_light_client(rpc_client: &HttpClient, config: &ChainConfig) -> TmLightClient {
    use tendermint_light_client_verifier::types::PeerId;

    let peer_id: PeerId = rpc_client.status().await.map(|s| s.node_info.id).unwrap();
    TmLightClient::from_config(config, peer_id).unwrap()
}

impl Relayer {
    pub fn new(cc: ChainConfig, rt: Arc<TokioRuntime>) -> Result<Relayer> {
        let chain = CosmosSdkChain::bootstrap(cc.clone(), rt.clone()).unwrap();
        let rpc_client = HttpClient::new(cc.rpc_addr.clone()).unwrap();
        let tmlc = rt.block_on(init_light_client(&rpc_client, &cc));
        Ok(Self {
            tmlc,
            chain,
            client_state: None,
        })
    }

    pub fn create_header(&mut self, trusted_height: Height, target_height: Height) -> Result<Any> {
        let (target, supporting) = self.chain.build_header(
            to_relayer_height(trusted_height),
            to_relayer_height(target_height),
            &AnyClientState::Tendermint(to_relayer_client_state(
                self.client_state.clone().unwrap(),
            )),
        )?;
        assert!(supporting.is_empty());
        Ok(relayer_header_to_any(target))
    }

    pub fn fetch_state(&mut self, height: Height) -> Result<(ClientState, ConsensusState)> {
        let height = to_relayer_height(height);
        let block = self.tmlc.fetch(height)?;
        let config = self.chain.config();
        let client_state = to_ibc_client_state(self.chain.build_client_state(
            height,
            ClientSettings::Tendermint(Settings {
                max_clock_drift: config.clock_drift,
                trusting_period: config.trusting_period,
                trust_threshold: config.trust_threshold.into(),
            }),
        )?);
        let consensus_state = to_ibc_consensus_state(self.chain.build_consensus_state(block)?);
        self.client_state = Some(client_state.clone());
        Ok((client_state, consensus_state))
    }

    pub fn fetch_state_as_any(&mut self, height: Height) -> Result<(Any, Any)> {
        let (client_state, consensus_state) = self.fetch_state(height)?;
        let any_client_state = IBCAny::from(client_state);
        let any_consensus_state = IBCAny::from(consensus_state);
        Ok((any_client_state.into(), any_consensus_state.into()))
    }

    pub fn query_latest_height(&self) -> Result<Height> {
        Ok(to_ibc_height(self.chain.query_chain_latest_height()?))
    }

    pub fn query_connection_proof(
        &self,
        connection_id: ConnectionId,
        height: Option<Height>, // height of consensus state
    ) -> Result<(ConnectionEnd, MerkleProof, Height)> {
        let height = match height {
            Some(height) => height.decrement().unwrap(),
            None => self.query_latest_height()?.decrement().unwrap(),
        };
        let req = QueryConnectionRequest {
            connection_id: to_relayer_connection_id(connection_id),
            height: QueryHeight::Specific(to_relayer_height(height)),
        };
        let res = self.chain.query_connection(req, IncludeProof::Yes)?;
        Ok((
            to_ibc_connection(res.0),
            MerkleProof {
                proofs: res.1.unwrap().proofs,
            },
            height.increment(),
        ))
    }

    pub fn query_channel_proof(
        &self,
        port_id: PortId,
        channel_id: ChannelId,
        height: Option<Height>, // height of consensus state
    ) -> Result<(ChannelEnd, MerkleProof, Height)> {
        let height = match height {
            Some(height) => height.decrement().unwrap(),
            None => self.query_latest_height()?.decrement().unwrap(),
        };
        let req = QueryChannelRequest {
            port_id: to_relayer_port_id(port_id),
            channel_id: to_relayer_channel_id(channel_id),
            height: QueryHeight::Specific(to_relayer_height(height)),
        };
        let res = self.chain.query_channel(req, IncludeProof::Yes)?;
        Ok((
            to_ibc_channel(res.0),
            MerkleProof {
                proofs: res.1.unwrap().proofs,
            },
            height.increment(),
        ))
    }

    pub fn query_packet_proof(
        &self,
        port_id: PortId,
        channel_id: ChannelId,
        sequence: Sequence,
        height: Option<Height>, // height of consensus state
    ) -> Result<(PacketCommitment, MerkleProof, Height)> {
        let height = match height {
            Some(height) => height.decrement().unwrap(),
            None => self.query_latest_height()?.decrement().unwrap(),
        };
        let res = self.chain.query_packet_commitment(
            QueryPacketCommitmentRequest {
                port_id: to_relayer_port_id(port_id),
                channel_id: to_relayer_channel_id(channel_id),
                sequence: to_relayer_sequence(sequence),
                height: QueryHeight::Specific(to_relayer_height(height)),
            },
            IncludeProof::Yes,
        )?;
        Ok((
            res.0.into(),
            MerkleProof {
                proofs: res.1.unwrap().proofs,
            },
            height.increment(),
        ))
    }
}
