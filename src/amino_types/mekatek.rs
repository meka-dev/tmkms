use super::{
    block_id::{BlockId, CanonicalBlockId, CanonicalPartSetHeader, ParseId},
    compute_prefix,
    remote_error::RemoteError,
    signature::SignableMsg,
    time::TimeMsg,
    validate::{self, ConsensusMessage, Error::*},
    ParseChainId, SignedMsgType, TendermintRequest,
};
use crate::{config::validator::ProtocolVersion, rpc};
use bytes::BufMut;
use bytes_v0_5::BytesMut as BytesMutV05;
use ed25519_dalek as ed25519;
use once_cell::sync::Lazy;
use prost::Message as _;
use prost_amino::{error::EncodeError, Message};
use prost_amino_derive::Message;
use tendermint::{block, chain, consensus, error::Error};
use tendermint_proto::types as proto_types;

pub const AMINO_NAME: &str = "tendermint/remotesigner/SignMekatekBuildBlockRequest";
pub static AMINO_PREFIX: Lazy<Vec<u8>> = Lazy::new(|| compute_prefix(AMINO_NAME));

#[derive(Clone, PartialEq, Message)]
pub struct BuildBlockRequest {
    #[prost_amino(string, tag = "1")]
    pub chain_id: String,
    #[prost_amino(int64)]
    pub height: i64,
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
        chain_id: chain::Id,
        protocol_version: ProtocolVersion,
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
        // TODO: Some basic validation
        return Ok(())
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



// #[cfg(test)]
// mod tests {
//     use super::super::PartsSetHeader;
//     use super::*;
//     use crate::amino_types::message::AminoMessage;
//     use crate::amino_types::SignedMsgType;
//     use chrono::{DateTime, Utc};

//     #[test]
//     fn test_vote_serialization() {
//         let dt = "2017-12-25T03:00:01.234Z".parse::<DateTime<Utc>>().unwrap();
//         let t = TimeMsg {
//             seconds: dt.timestamp(),
//             nanos: dt.timestamp_subsec_nanos() as i32,
//         };
//         let vote = BuildBlockRequest {
//             vote_type: SignedMsgType::PreBuildBlockRequest.to_u32(),
//             height: 12345,
//             round: 2,
//             timestamp: Some(t),
//             block_id: Some(BlockId {
//                 hash: b"hash".to_vec(),
//                 parts_header: Some(PartsSetHeader {
//                     total: 1_000_000,
//                     hash: b"parts_hash".to_vec(),
//                 }),
//             }),
//             validator_address: vec![
//                 0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21, 0xf2, 0x48, 0x2a, 0xf4,
//                 0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35,
//             ],
//             validator_index: 56789,
//             signature: vec![],
//             /* signature: vec![130u8, 246, 183, 50, 153, 248, 28, 57, 51, 142, 55, 217, 194, 24,
//              * 134, 212, 233, 100, 211, 10, 24, 174, 179, 117, 41, 65, 141, 134, 149, 239, 65,
//              * 174, 217, 42, 6, 184, 112, 17, 7, 97, 255, 221, 252, 16, 60, 144, 30, 212, 167,
//              * 39, 67, 35, 118, 192, 133, 130, 193, 115, 32, 206, 152, 91, 173, 10], */
//         };
//         let sign_vote_msg = SignBuildBlockRequestRequest { vote: Some(vote) };
//         let mut got = vec![];
//         let _have = sign_vote_msg.encode(&mut got);

//         // the following vector is generated via:
//         //
//         // cdc := amino.NewCodec()
//         // privval.RegisterRemoteSignerMsg(cdc)
//         // stamp, _ := time.Parse(time.RFC3339Nano, "2017-12-25T03:00:01.234Z")
//         // data, _ := cdc.MarshalBinaryLengthPrefixed(privval.SignBuildBlockRequestRequest{BuildBlockRequest: &types.BuildBlockRequest{
//         //     Type:             types.PrevoteType, // pre-vote
//         //     Height:           12345,
//         //     Round:            2,
//         //     Timestamp:        stamp,
//         //     BlockID: types.BlockID{
//         //         Hash: []byte("hash"),
//         //         PartsHeader: types.PartSetHeader{
//         //             Total: 1000000,
//         //             Hash:  []byte("parts_hash"),
//         //         },
//         //     },
//         //     ValidatorAddress: []byte{0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21,
//         // 0xf2, 0x48, 0x2a, 0xf4, 0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35},     ValidatorIndex:
//         // 56789, }})
//         // fmt.Println(strings.Join(strings.Split(fmt.Sprintf("%v",data), " "), ", "))

//         let want = vec![
//             78, 243, 244, 18, 4, 10, 72, 8, 1, 16, 185, 96, 24, 2, 34, 24, 10, 4, 104, 97, 115,
//             104, 18, 16, 8, 192, 132, 61, 18, 10, 112, 97, 114, 116, 115, 95, 104, 97, 115, 104,
//             42, 11, 8, 177, 211, 129, 210, 5, 16, 128, 157, 202, 111, 50, 20, 163, 178, 204, 221,
//             113, 134, 241, 104, 95, 33, 242, 72, 42, 244, 251, 52, 70, 168, 75, 53, 56, 213, 187,
//             3,
//         ];
//         let svr = SignBuildBlockRequestRequest::decode(got.as_ref()).unwrap();
//         println!("got back: {:?}", svr);
//         assert_eq!(got, want);
//     }

//     #[test]
//     fn test_sign_bytes_compatibility() {
//         let cv = CanonicalBuildBlockRequest::new(BuildBlockRequest::default(), "");
//         let mut got = vec![];
//         // SignBytes are encoded using MarshalBinary and not MarshalBinaryBare
//         cv.encode_length_delimited(&mut got).unwrap();
//         let want = vec![
//             0xd, 0x2a, 0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
//         ];
//         assert_eq!(got, want);

//         // with proper (fixed size) height and round (PreCommit):
//         {
//             let mut vt_precommit = BuildBlockRequest::default();
//             vt_precommit.height = 1;
//             vt_precommit.round = 1;
//             vt_precommit.vote_type = SignedMsgType::PreCommit.to_u32(); // precommit
//             println!("{:?}", vt_precommit);
//             let cv_precommit = CanonicalBuildBlockRequest::new(vt_precommit, "");
//             let got = AminoMessage::bytes_vec(&cv_precommit);
//             let want = vec![
//                 0x8,  // (field_number << 3) | wire_type
//                 0x2,  // PrecommitType
//                 0x11, // (field_number << 3) | wire_type
//                 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
//                 0x19, // (field_number << 3) | wire_type
//                 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
//                 0x2a, // (field_number << 3) | wire_type
//                 // remaining fields (timestamp):
//                 0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
//             ];
//             assert_eq!(got, want);
//         }
//         // with proper (fixed size) height and round (PreBuildBlockRequest):
//         {
//             let mut vt_prevote = BuildBlockRequest::default();
//             vt_prevote.height = 1;
//             vt_prevote.round = 1;
//             vt_prevote.vote_type = SignedMsgType::PreBuildBlockRequest.to_u32();

//             let cv_prevote = CanonicalBuildBlockRequest::new(vt_prevote, "");

//             let got = AminoMessage::bytes_vec(&cv_prevote);

//             let want = vec![
//                 0x8,  // (field_number << 3) | wire_type
//                 0x1,  // PrevoteType
//                 0x11, // (field_number << 3) | wire_type
//                 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
//                 0x19, // (field_number << 3) | wire_type
//                 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
//                 0x2a, // (field_number << 3) | wire_type
//                 // remaining fields (timestamp):
//                 0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
//             ];
//             assert_eq!(got, want);
//         }
//         // with proper (fixed size) height and round (msg typ missing):
//         {
//             let mut vt_no_type = BuildBlockRequest::default();
//             vt_no_type.height = 1;
//             vt_no_type.round = 1;

//             let cv = CanonicalBuildBlockRequest::new(vt_no_type, "");
//             let got = AminoMessage::bytes_vec(&cv);

//             let want = vec![
//                 0x11, // (field_number << 3) | wire_type
//                 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
//                 0x19, // (field_number << 3) | wire_type
//                 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // round
//                 // remaining fields (timestamp):
//                 0x2a, 0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
//             ];
//             assert_eq!(got, want);
//         }
//         // containing non-empty chain_id:
//         {
//             let mut no_vote_type2 = BuildBlockRequest::default();
//             no_vote_type2.height = 1;
//             no_vote_type2.round = 1;

//             let with_chain_id = CanonicalBuildBlockRequest::new(no_vote_type2, "test_chain_id");
//             got = AminoMessage::bytes_vec(&with_chain_id);
//             let want = vec![
//                 0x11, // (field_number << 3) | wire_type
//                 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
//                 0x19, // (field_number << 3) | wire_type
//                 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // round
//                 // remaining fields:
//                 0x2a, // (field_number << 3) | wire_type
//                 0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff,
//                 0x1,  // timestamp
//                 0x32, // (field_number << 3) | wire_type
//                 0xd, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x5f, 0x69,
//                 0x64, // chainID
//             ];
//             assert_eq!(got, want);
//         }
//     }

//     #[test]
//     fn test_vote_rountrip_with_sig() {
//         let dt = "2017-12-25T03:00:01.234Z".parse::<DateTime<Utc>>().unwrap();
//         let t = TimeMsg {
//             seconds: dt.timestamp(),
//             nanos: dt.timestamp_subsec_nanos() as i32,
//         };
//         let vote = BuildBlockRequest {
//             validator_address: vec![
//                 0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21, 0xf2, 0x48, 0x2a, 0xf4,
//                 0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35,
//             ],
//             validator_index: 56789,
//             height: 12345,
//             round: 2,
//             timestamp: Some(t),
//             vote_type: 0x01,
//             block_id: Some(BlockId {
//                 hash: b"hash".to_vec(),
//                 parts_header: Some(PartsSetHeader {
//                     total: 1_000_000,
//                     hash: b"parts_hash".to_vec(),
//                 }),
//             }),
//             // signature: None,
//             signature: vec![
//                 130u8, 246, 183, 50, 153, 248, 28, 57, 51, 142, 55, 217, 194, 24, 134, 212, 233,
//                 100, 211, 10, 24, 174, 179, 117, 41, 65, 141, 134, 149, 239, 65, 174, 217, 42, 6,
//                 184, 112, 17, 7, 97, 255, 221, 252, 16, 60, 144, 30, 212, 167, 39, 67, 35, 118,
//                 192, 133, 130, 193, 115, 32, 206, 152, 91, 173, 10,
//             ],
//         };
//         let mut got = vec![];
//         let _have = vote.encode(&mut got);
//         let v = BuildBlockRequest::decode(got.as_ref()).unwrap();

//         assert_eq!(v, vote);
//         // SignBuildBlockRequestRequest
//         {
//             let svr = SignBuildBlockRequestRequest { vote: Some(vote) };
//             let mut got = vec![];
//             let _have = svr.encode(&mut got);

//             let svr2 = SignBuildBlockRequestRequest::decode(got.as_ref()).unwrap();
//             assert_eq!(svr, svr2);
//         }
//     }

//     #[test]
//     fn test_deserialization() {
//         let encoded = vec![
//             78, 243, 244, 18, 4, 10, 72, 8, 1, 16, 185, 96, 24, 2, 34, 24, 10, 4, 104, 97, 115,
//             104, 18, 16, 8, 192, 132, 61, 18, 10, 112, 97, 114, 116, 115, 95, 104, 97, 115, 104,
//             42, 11, 8, 177, 211, 129, 210, 5, 16, 128, 157, 202, 111, 50, 20, 163, 178, 204, 221,
//             113, 134, 241, 104, 95, 33, 242, 72, 42, 244, 251, 52, 70, 168, 75, 53, 56, 213, 187,
//             3,
//         ];
//         let dt = "2017-12-25T03:00:01.234Z".parse::<DateTime<Utc>>().unwrap();
//         let t = TimeMsg {
//             seconds: dt.timestamp(),
//             nanos: dt.timestamp_subsec_nanos() as i32,
//         };
//         let vote = BuildBlockRequest {
//             validator_address: vec![
//                 0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21, 0xf2, 0x48, 0x2a, 0xf4,
//                 0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35,
//             ],
//             validator_index: 56789,
//             height: 12345,
//             round: 2,
//             timestamp: Some(t),
//             vote_type: 0x01,
//             block_id: Some(BlockId {
//                 hash: b"hash".to_vec(),
//                 parts_header: Some(PartsSetHeader {
//                     total: 1_000_000,
//                     hash: b"parts_hash".to_vec(),
//                 }),
//             }),
//             signature: vec![],
//         };
//         let want = SignBuildBlockRequestRequest { vote: Some(vote) };
//         match SignBuildBlockRequestRequest::decode(encoded.as_ref()) {
//             Ok(have) => {
//                 assert_eq!(have, want);
//             }
//             Err(err) => panic!("{}", err.to_string()),
//         }
//     }
// }
