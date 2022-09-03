use super::{
    compute_prefix,
    remote_error::RemoteError,
    signature::SignableMsg,
    validate::{self, ConsensusMessage, Error::*},
    SignedMsgType, TendermintRequest,
};
use crate::{config::validator::ProtocolVersion, rpc};
use bytes::BufMut;
use ed25519_dalek as ed25519;
use once_cell::sync::Lazy;
use prost_amino::error::EncodeError;
use prost_amino_derive::Message;
use tendermint::{chain, consensus};

pub const BUILD_BLOCK_REQUEST_AMINO_NAME: &str =
    "tendermint/remotesigner/SignMekatekBuildBlockRequest";
pub static BUILD_BLOCK_REQUEST_AMINO_PREFIX: Lazy<Vec<u8>> =
    Lazy::new(|| compute_prefix(BUILD_BLOCK_REQUEST_AMINO_NAME));

//
// Build block request
//

#[derive(Clone, PartialEq, Message)]
pub struct BuildBlockRequest {
    #[prost_amino(string, tag = "1")]
    pub chain_id: String,
    #[prost_amino(int64)]
    pub height: i64,
    #[prost_amino(string)]
    pub validator_address: String,
    #[prost_amino(int64)]
    pub max_bytes: i64,
    #[prost_amino(int64)]
    pub max_gas: i64,
    #[prost_amino(bytes, repeated)]
    pub txs: Vec<Vec<u8>>,
    #[prost_amino(bytes)]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
#[amino_name = "tendermint/remotesigner/SignMekatekBuildBlockRequest"]
pub struct SignMekatekBuildBlockRequest {
    #[prost_amino(message, tag = "1")]
    pub req: Option<BuildBlockRequest>,
}

#[derive(Clone, PartialEq, Message)]
#[amino_name = "tendermint/remotesigner/SignMekatekBuildBlockRequestResponse"]
pub struct SignMekatekBuildBlockRequestResponse {
    #[prost_amino(message, tag = "1")]
    pub req: Option<BuildBlockRequest>,
    #[prost_amino(message)]
    pub err: Option<RemoteError>,
}

impl SignableMsg for SignMekatekBuildBlockRequest {
    fn sign_bytes<B>(
        &self,
        _chain_id: chain::Id,
        _protocol_version: ProtocolVersion,
        sign_bytes: &mut B,
    ) -> Result<bool, EncodeError>
    where
        B: BufMut,
    {
        let mut sign_req = self.clone();

        if let Some(ref mut req) = sign_req.req {
            req.signature = vec![];
        }

        let req = sign_req.req.unwrap();

        sign_bytes.put_slice("build-block-request".as_bytes());
        sign_bytes.put_u64_le(req.chain_id.as_bytes().len() as u64);
        sign_bytes.put_slice(req.chain_id.as_bytes());
        sign_bytes.put_u64_le(req.height as u64);
        sign_bytes.put_u64_le(req.validator_address.as_bytes().len() as u64);
        sign_bytes.put_slice(req.validator_address.as_bytes());
        sign_bytes.put_u64_le(req.max_bytes as u64);
        sign_bytes.put_u64_le(req.max_gas as u64);
        sign_bytes.put_u64_le(req.txs.len() as u64);

        for tx in req.txs {
            sign_bytes.put_u64_le(tx.len() as u64);
            sign_bytes.put_slice(&tx);
        }

        Ok(true)
    }

    fn set_signature(&mut self, sig: &ed25519::Signature) {
        if let Some(ref mut req) = self.req {
            req.signature = sig.as_ref().to_vec();
        }
    }

    fn validate(&self) -> Result<(), validate::Error> {
        match self.req {
            Some(ref v) => v.validate_basic(),
            None => Err(MissingConsensusMessage),
        }
    }

    fn consensus_state(&self) -> Option<consensus::State> {
        None
    }

    fn height(&self) -> Option<i64> {
        self.req.as_ref().map(|req| req.height)
    }

    fn msg_type(&self) -> Option<SignedMsgType> {
        Some(SignedMsgType::MekatekBuildBlockRequest)
    }
}

impl ConsensusMessage for BuildBlockRequest {
    fn validate_basic(&self) -> Result<(), validate::Error> {
        if self.height < 0 {
            return Err(NegativeHeight);
        }
        return Ok(());
    }
}

impl TendermintRequest for SignMekatekBuildBlockRequest {
    fn build_response(self, error: Option<RemoteError>) -> rpc::Response {
        let response = if let Some(e) = error {
            SignMekatekBuildBlockRequestResponse {
                req: None,
                err: Some(e),
            }
        } else {
            SignMekatekBuildBlockRequestResponse {
                req: self.req,
                err: None,
            }
        };

        rpc::Response::SignMekatekBuildBlockRequestResponse(response)
    }
}

//
// Register challenge
//

pub const REGISTER_CHALLENGE_AMINO_NAME: &str =
    "tendermint/remotesigner/SignMekatekRegisterChallenge";
pub static REGISTER_CHALLENGE_AMINO_PREFIX: Lazy<Vec<u8>> =
    Lazy::new(|| compute_prefix(REGISTER_CHALLENGE_AMINO_NAME));

#[derive(Clone, PartialEq, Message)]
pub struct RegisterChallenge {
    #[prost_amino(string, tag = "1")]
    pub chain_id: String,
    #[prost_amino(bytes)]
    pub challenge: Vec<u8>,
    #[prost_amino(bytes)]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
#[amino_name = "tendermint/remotesigner/SignMekatekRegisterChallenge"]
pub struct SignMekatekRegisterChallenge {
    #[prost_amino(message, tag = "1")]
    pub rc: Option<RegisterChallenge>,
}

#[derive(Clone, PartialEq, Message)]
#[amino_name = "tendermint/remotesigner/SignMekatekRegisterChallengeResponse"]
pub struct SignMekatekRegisterChallengeResponse {
    #[prost_amino(message, tag = "1")]
    pub rc: Option<RegisterChallenge>,
    #[prost_amino(message)]
    pub err: Option<RemoteError>,
}

impl SignableMsg for SignMekatekRegisterChallenge {
    fn sign_bytes<B>(
        &self,
        _chain_id: chain::Id,
        _protocol_version: ProtocolVersion,
        sign_bytes: &mut B,
    ) -> Result<bool, EncodeError>
    where
        B: BufMut,
    {
        let mut sign_req = self.clone();

        if let Some(ref mut rc) = sign_req.rc {
            rc.signature = vec![];
        }

        let rc = sign_req.rc.unwrap();

        sign_bytes.put_slice("register-challenge".as_bytes());
        sign_bytes.put_u64_le(rc.chain_id.as_bytes().len() as u64);
        sign_bytes.put_slice(rc.chain_id.as_bytes());
        sign_bytes.put_slice(&rc.challenge);

        Ok(true)
    }

    fn set_signature(&mut self, sig: &ed25519::Signature) {
        if let Some(ref mut rc) = self.rc {
            rc.signature = sig.as_ref().to_vec();
        }
    }

    fn validate(&self) -> Result<(), validate::Error> {
        match self.rc {
            Some(ref rc) => rc.validate_basic(),
            None => Err(MissingConsensusMessage),
        }
    }

    fn consensus_state(&self) -> Option<consensus::State> {
        None
    }

    fn height(&self) -> Option<i64> {
        None
    }

    fn msg_type(&self) -> Option<SignedMsgType> {
        Some(SignedMsgType::MekatekRegisterChallenge)
    }
}

impl ConsensusMessage for RegisterChallenge {
    fn validate_basic(&self) -> Result<(), validate::Error> {
        Ok(())
    }
}

impl TendermintRequest for SignMekatekRegisterChallenge {
    fn build_response(self, error: Option<RemoteError>) -> rpc::Response {
        let response = if let Some(e) = error {
            SignMekatekRegisterChallengeResponse {
                rc: None,
                err: Some(e),
            }
        } else {
            SignMekatekRegisterChallengeResponse {
                rc: self.rc,
                err: None,
            }
        };

        rpc::Response::SignMekatekRegisterChallengeResponse(response)
    }
}
