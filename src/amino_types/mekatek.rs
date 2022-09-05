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

pub const SIGN_MEKATEK_BUILD_REQUEST_AMINO_NAME: &str =
    "tendermint/remotesigner/SignMekatekBuildRequest";
pub static SIGN_MEKATEK_BUILD_REQUEST_AMINO_PREFIX: Lazy<Vec<u8>> =
    Lazy::new(|| compute_prefix(SIGN_MEKATEK_BUILD_REQUEST_AMINO_NAME));

//
// Build request
//

#[derive(Clone, PartialEq, Message)]
pub struct MekatekBuild {
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
    #[prost_amino(bytes)]
    pub txs_hash: Vec<u8>,
    #[prost_amino(bytes)]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
#[amino_name = "tendermint/remotesigner/SignMekatekBuildRequest"]
pub struct SignMekatekBuildRequest {
    #[prost_amino(message, tag = "1")]
    pub build: Option<MekatekBuild>,
}

#[derive(Clone, PartialEq, Message)]
#[amino_name = "tendermint/remotesigner/SignedMekatekBuildResponse"]
pub struct SignedMekatekBuildResponse {
    #[prost_amino(message, tag = "1")]
    pub build: Option<MekatekBuild>,
    #[prost_amino(message)]
    pub err: Option<RemoteError>,
}

impl SignableMsg for SignMekatekBuildRequest {
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

        if let Some(ref mut build) = sign_req.build {
            build.signature = vec![];
        }

        let build = sign_req.build.unwrap();

        sign_bytes.put_slice("build-block-request".as_bytes());
        sign_bytes.put_u64_le(build.chain_id.as_bytes().len() as u64);
        sign_bytes.put_slice(build.chain_id.as_bytes());
        sign_bytes.put_u64_le(build.height as u64);
        sign_bytes.put_u64_le(build.validator_address.as_bytes().len() as u64);
        sign_bytes.put_slice(build.validator_address.as_bytes());
        sign_bytes.put_u64_le(build.max_bytes as u64);
        sign_bytes.put_u64_le(build.max_gas as u64);
        sign_bytes.put_u64_le(build.txs_hash.len() as u64);
        sign_bytes.put_slice(&build.txs_hash);

        Ok(true)
    }

    fn set_signature(&mut self, sig: &ed25519::Signature) {
        if let Some(ref mut build) = self.build {
            build.signature = sig.as_ref().to_vec();
        }
    }

    fn validate(&self) -> Result<(), validate::Error> {
        match self.build {
            Some(ref build) => build.validate_basic(),
            None => Err(MissingConsensusMessage),
        }
    }

    fn consensus_state(&self) -> Option<consensus::State> {
        None
    }

    fn height(&self) -> Option<i64> {
        self.build.as_ref().map(|build| build.height)
    }

    fn msg_type(&self) -> Option<SignedMsgType> {
        Some(SignedMsgType::MekatekBuildBlockRequest)
    }
}

impl ConsensusMessage for MekatekBuild {
    fn validate_basic(&self) -> Result<(), validate::Error> {
        if self.height < 0 {
            return Err(NegativeHeight);
        }
        return Ok(());
    }
}

impl TendermintRequest for SignMekatekBuildRequest {
    fn build_response(self, error: Option<RemoteError>) -> rpc::Response {
        let response = if let Some(e) = error {
            SignedMekatekBuildResponse {
                build: None,
                err: Some(e),
            }
        } else {
            SignedMekatekBuildResponse {
                build: self.build,
                err: None,
            }
        };

        rpc::Response::SignedMekatekBuildResponse(response)
    }
}

//
// Challenge
//

pub const SIGN_MEKATEK_CHALLENGE_REQUEST_AMINO_NAME: &str =
    "tendermint/remotesigner/SignMekatekChallengeRequest";
pub static SIGN_MEKATEK_CHALLENGE_REQUEST_AMINO_PREFIX: Lazy<Vec<u8>> =
    Lazy::new(|| compute_prefix(SIGN_MEKATEK_CHALLENGE_REQUEST_AMINO_NAME));

#[derive(Clone, PartialEq, Message)]
pub struct MekatekChallenge {
    #[prost_amino(string, tag = "1")]
    pub chain_id: String,
    #[prost_amino(bytes)]
    pub challenge: Vec<u8>,
    #[prost_amino(bytes)]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
#[amino_name = "tendermint/remotesigner/SignMekatekChallengeRequest"]
pub struct SignMekatekChallengeRequest {
    #[prost_amino(message, tag = "1")]
    pub challenge: Option<MekatekChallenge>,
}

#[derive(Clone, PartialEq, Message)]
#[amino_name = "tendermint/remotesigner/SignedMekatekChallengeResponse"]
pub struct SignedMekatekChallengeResponse {
    #[prost_amino(message, tag = "1")]
    pub challenge: Option<MekatekChallenge>,
    #[prost_amino(message)]
    pub err: Option<RemoteError>,
}

impl SignableMsg for SignMekatekChallengeRequest {
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

        if let Some(ref mut challenge) = sign_req.challenge {
            challenge.signature = vec![];
        }

        let challenge = sign_req.challenge.unwrap();

        sign_bytes.put_slice("register-challenge".as_bytes());
        sign_bytes.put_u64_le(challenge.chain_id.as_bytes().len() as u64);
        sign_bytes.put_slice(challenge.chain_id.as_bytes());
        sign_bytes.put_u64_le(challenge.challenge.len() as u64);
        sign_bytes.put_slice(&challenge.challenge);

        Ok(true)
    }

    fn set_signature(&mut self, sig: &ed25519::Signature) {
        if let Some(ref mut challenge) = self.challenge {
            challenge.signature = sig.as_ref().to_vec();
        }
    }

    fn validate(&self) -> Result<(), validate::Error> {
        match self.challenge {
            Some(ref challenge) => challenge.validate_basic(),
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

impl ConsensusMessage for MekatekChallenge {
    fn validate_basic(&self) -> Result<(), validate::Error> {
        Ok(())
    }
}

impl TendermintRequest for SignMekatekChallengeRequest {
    fn build_response(self, error: Option<RemoteError>) -> rpc::Response {
        let response = if let Some(e) = error {
            SignedMekatekChallengeResponse {
                challenge: None,
                err: Some(e),
            }
        } else {
            SignedMekatekChallengeResponse {
                challenge: self.challenge,
                err: None,
            }
        };

        rpc::Response::SignedMekatekChallengeResponse(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mekatek_build_sign_bytes() {
        let build = MekatekBuild {
            chain_id: "testchain-1".to_string(),
            height: 500,
            validator_address: "validator-42".to_string(),
            max_bytes: 1234,
            max_gas: 5678,
            txs_hash: "txsHash".as_bytes().to_vec(),
            signature: vec![],
        };

        let mut got = vec![];

        let chain_id = chain::Id::try_from(build.chain_id.to_string()).unwrap();

        let _have = SignMekatekBuildRequest { build: Some(build) }.sign_bytes(
            chain_id,
            ProtocolVersion::V0_34,
            &mut got,
        );

        let want = vec![
            0x62, 0x75, 0x69, 0x6c, 0x64, 0x2d, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x72, 0x65,
            0x71, 0x75, 0x65, 0x73, 0x74, 0xb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x74, 0x65, 0x73,
            0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x2d, 0x31, 0xf4, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
            0x6f, 0x72, 0x2d, 0x34, 0x32, 0xd2, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2e, 0x16, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x74, 0x78, 0x73,
            0x48, 0x61, 0x73, 0x68,
        ];

        assert_eq!(got, want)
    }

    #[test]
    fn test_mekatek_challenge_sign_bytes() {
        let challenge = MekatekChallenge {
            chain_id: "testchain-1".to_string(),
            challenge: "such challenge, much difficulty".as_bytes().to_vec(),
            signature: vec![],
        };
        let mut got = vec![];

        let chain_id = chain::Id::try_from(challenge.chain_id.to_string()).unwrap();

        let _have = SignMekatekChallengeRequest {
            challenge: Some(challenge),
        }
        .sign_bytes(chain_id, ProtocolVersion::V0_34, &mut got);

        let want = vec![
            0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x2d, 0x63, 0x68, 0x61, 0x6c, 0x6c,
            0x65, 0x6e, 0x67, 0x65, 0xb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x74, 0x65, 0x73, 0x74,
            0x63, 0x68, 0x61, 0x69, 0x6e, 0x2d, 0x31, 0x1f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x73, 0x75, 0x63, 0x68, 0x20, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65,
            0x2c, 0x20, 0x6d, 0x75, 0x63, 0x68, 0x20, 0x64, 0x69, 0x66, 0x66, 0x69, 0x63, 0x75,
            0x6c, 0x74, 0x79,
        ];

        assert_eq!(got, want)
    }
}
