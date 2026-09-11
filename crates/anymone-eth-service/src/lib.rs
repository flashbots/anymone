pub mod crypto;

use sha2::{Digest, Sha256};
use bincode::Options;
use serde::{Deserialize, Serialize};
use crate::{crypto::DeliveryBinding, crypto::DeliverySpec, crypto::ResponseCapability, crypto::SealedResponse};
use serde_json::{Map, Value};
use std::collections::HashSet;

pub const VERSION: u16 = 0;
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid envelope context")]
    Context,
    #[error("message exceeds protocol limits")]
    Limit,
    #[error("cryptographic authentication failed")]
    Authentication,
    #[error("invalid JSON-RPC message")]
    Rpc,
    #[error("encoding: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("binary encoding: {0}")]
    Binary(#[from] Box<bincode::ErrorKind>),
}

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let bytes = bincode::DefaultOptions::new().with_fixint_encoding()
        .with_limit(MAX_MESSAGE_BYTES as u64).serialize(value)?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::Limit);
    }
    Ok(bytes)
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::Limit);
    }
    Ok(bincode::DefaultOptions::new().with_fixint_encoding()
        .with_limit(MAX_MESSAGE_BYTES as u64).reject_trailing_bytes().deserialize(bytes)?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceLimits {
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    pub max_batch: u32,
    pub max_log_blocks: u64,
    pub max_lifetime_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDescriptor {
    pub version: u16,
    pub network: [u8; 32],
    pub chain: u64,
    pub service_identity: [u8; 32],
    pub signing_key: [u8; 32],
    pub request_key: [u8; 32],
    pub tag: String,
    pub backend_routes: Vec<String>,
    pub limits: ServiceLimits,
    pub feed: FeedDescriptor,
    pub feed_mirrors: Vec<String>,
    pub expires_at: u64,
}

impl ServiceDescriptor {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        encode(&(b"anymone.ethereum.service.descriptor.v0".as_slice(), self))
    }

    pub fn validate(&self, now: u64) -> Result<(), Error> {
        if self.version != VERSION || now >= self.expires_at
            || self.backend_routes.is_empty() || self.tag.is_empty() || self.tag.len() > 128
            || self.limits.max_request_bytes == 0 || self.limits.max_request_bytes > 1024 * 1024
            || self.limits.max_response_bytes == 0 || self.limits.max_response_bytes > 1024 * 1024
            || self.limits.max_batch == 0 || self.limits.max_batch > 128
            || self.limits.max_lifetime_seconds == 0 || self.limits.max_lifetime_seconds > 86400
            || u64::from(self.limits.max_response_bytes) + 512 > u64::from(self.feed.max_epoch_bytes)
        {
            return Err(Error::Context);
        }
        self.feed.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceDescriptor {
    pub descriptor: ServiceDescriptor,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub capability: ResponseCapability,
    pub backend_route: String,
    pub payload: Vec<u8>,
}

impl RequestEnvelope {
    pub fn payload_digest(backend_route: &str, payload: &[u8]) -> Result<[u8; 32], Error> {
        Ok(digest(&encode(&(backend_route, payload))?))
    }

    pub fn validate(&self, descriptor: &ServiceDescriptor, operation: [u8; 32], now: u64) -> Result<(), Error> {
        descriptor.validate(now)?;
        let context = &self.capability.context;
        if context.version != VERSION || context.network != descriptor.network
            || context.chain != descriptor.chain || context.service != descriptor.signing_key
            || context.operation != operation || context.expires_at <= now
            || context.expires_at > descriptor.expires_at
            || context.expires_at - now > descriptor.limits.max_lifetime_seconds
            || !descriptor.backend_routes.contains(&self.backend_route)
            || self.payload.len() > descriptor.limits.max_request_bytes as usize
            || context.request_digest != Self::payload_digest(&self.backend_route, &self.payload)?
        {
            return Err(Error::Context);
        }
        let DeliverySpec { feed, first_epoch, last_epoch } = &self.capability.delivery;
        let descriptor = &descriptor.feed;
        if feed != &descriptor.feed || first_epoch > last_epoch
            || last_epoch - first_epoch >= u64::from(descriptor.retained_epochs)
            || descriptor.epoch(now)? > *last_epoch
        { return Err(Error::Context); }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> { encode(self) }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> { crate::decode(bytes) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyPacket {
    pub binding: DeliveryBinding,
    pub sealed: SealedResponse,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RpcCall {
    pub method: String,
    pub params: Option<Value>,
    pub id: Option<Value>,
}

impl RpcCall {
    pub fn parse(value: &Value) -> Result<Self, Error> {
        let obj = value.as_object().ok_or(Error::Rpc)?;
        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(Error::Rpc);
        }
        let method = obj.get("method").and_then(Value::as_str).ok_or(Error::Rpc)?;
        if let Some(id) = obj.get("id") {
            if !(id.is_null() || id.is_string() || id.is_number()) {
                return Err(Error::Rpc);
            }
        }
        if let Some(params) = obj.get("params") {
            if !(params.is_array() || params.is_object()) {
                return Err(Error::Rpc);
            }
        }
        Ok(Self {
            method: method.to_owned(),
            params: obj.get("params").cloned(),
            id: obj.get("id").cloned(),
        })
    }

    pub fn to_value(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("jsonrpc".into(), Value::String("2.0".into()));
        obj.insert("method".into(), Value::String(self.method.clone()));
        if let Some(params) = &self.params {
            obj.insert("params".into(), params.clone());
        }
        if let Some(id) = &self.id {
            obj.insert("id".into(), id.clone());
        }
        Value::Object(obj)
    }
}

pub fn parse_request(bytes: &[u8], max_batch: usize) -> Result<(bool, Vec<Value>), Error> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::Limit);
    }
    let value: Value = serde_json::from_slice(bytes)?;
    match value {
        Value::Array(items) if items.is_empty() || items.len() > max_batch => Err(Error::Rpc),
        Value::Array(items) => Ok((true, items)),
        value => Ok((false, vec![value])),
    }
}

pub fn validate_response(response: &Value, expected_id: &Value) -> Result<(), Error> {
    let obj = response.as_object().ok_or(Error::Rpc)?;
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || obj.get("id") != Some(expected_id)
        || obj.contains_key("result") == obj.contains_key("error")
    {
        return Err(Error::Rpc);
    }
    if let Some(error) = obj.get("error") {
        let error = error.as_object().ok_or(Error::Rpc)?;
        if error.get("code").and_then(Value::as_i64).is_none()
            || error.get("message").and_then(Value::as_str).is_none()
        {
            return Err(Error::Rpc);
        }
    }
    Ok(())
}

pub fn is_read_method(method: &str) -> bool {
    matches!(method,
        "eth_chainId" | "net_version" | "eth_blockNumber" | "eth_syncing"
        | "eth_getBalance" | "eth_getTransactionCount" | "eth_getCode"
        | "eth_getStorageAt" | "eth_getProof" | "eth_call" | "eth_estimateGas"
        | "eth_gasPrice" | "eth_maxPriorityFeePerGas" | "eth_feeHistory"
        | "eth_getBlockByHash" | "eth_getBlockByNumber"
        | "eth_getBlockTransactionCountByHash" | "eth_getBlockTransactionCountByNumber"
        | "eth_getTransactionByHash" | "eth_getTransactionByBlockHashAndIndex"
        | "eth_getTransactionByBlockNumberAndIndex" | "eth_getTransactionReceipt"
        | "eth_getBlockReceipts" | "eth_getLogs" | "eth_createAccessList")
}

#[cfg(test)]
mod rpc_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn notifications_are_distinct_from_null_ids() {
        let notification = json!({"jsonrpc":"2.0","method":"eth_chainId"});
        let mut call = RpcCall::parse(&notification).unwrap();
        assert_eq!(call.id, None);
        assert_eq!(call.to_value(), notification);
        call.id = Some(Value::Null);
        assert_eq!(RpcCall::parse(&call.to_value()).unwrap().id, Some(Value::Null));
    }

    #[test]
    fn upstream_shape_and_identity_are_checked() {
        let id = json!(7);
        for bad in [
            json!({"jsonrpc":"2.0","id":8,"result":"0x1"}),
            json!({"jsonrpc":"2.0","id":7,"result":null,"error":{"code":-1,"message":"x"}}),
            json!({"jsonrpc":"2.0","id":7,"error":{"code":"-1","message":"x"}}),
        ] {
            assert!(validate_response(&bad, &id).is_err());
        }
        assert!(validate_response(&json!({"jsonrpc":"2.0","id":7,"result":null}), &id).is_ok());
        assert!(!is_read_method("eth_sendRawTransaction"));
        assert!(!is_read_method("personal_sign"));
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FeedDescriptor {
    pub feed: [u8; 32],
    pub genesis_time: u64,
    pub epoch_seconds: u64,
    pub max_epoch_bytes: u32,
    pub retained_epochs: u32,
}

impl FeedDescriptor {
    pub fn validate(&self) -> Result<(), Error> {
        if self.epoch_seconds == 0 || self.max_epoch_bytes < 1024
            || self.max_epoch_bytes > 256 * 1024 * 1024
            || self.retained_epochs == 0 || self.retained_epochs > 65536
        { return Err(Error::Context); }
        Ok(())
    }

    pub fn epoch(&self, now: u64) -> Result<u64, Error> {
        self.validate()?;
        Ok(now.checked_sub(self.genesis_time).ok_or(Error::Context)? / self.epoch_seconds)
    }

    pub fn closes_at(&self, epoch: u64) -> Result<u64, Error> {
        epoch.checked_add(1).and_then(|e| e.checked_mul(self.epoch_seconds))
            .and_then(|t| self.genesis_time.checked_add(t)).ok_or(Error::Limit)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochBatch {
    pub feed: [u8; 32],
    pub epoch: u64,
    pub responses: Vec<ReplyPacket>,
}

impl EpochBatch {
    pub fn validate(&self, descriptor: &FeedDescriptor, epoch: u64, now: u64) -> Result<(), Error> {
        let current = descriptor.epoch(now)?;
        if self.feed != descriptor.feed || self.epoch != epoch || epoch >= current
            || current - epoch > u64::from(descriptor.retained_epochs)
            || bincode::serialized_size(self)? > u64::from(descriptor.max_epoch_bytes)
            || self.responses.iter().any(|r| r.binding.feed != self.feed || r.binding.epoch != epoch)
        { return Err(Error::Context); }
        let unique: HashSet<_> = self.responses.iter().map(|r| r.binding.locator).collect();
        if unique.len() != self.responses.len() { return Err(Error::Context); }
        Ok(())
    }
}

#[cfg(test)]
mod bulletin_tests {
    use super::*;
    use crate::{crypto::DeliveryBinding, crypto::SealedResponse};

    #[test]
    fn epochs_contain_only_actual_responses_and_enforce_byte_limits() {
        let descriptor = FeedDescriptor { feed: [1; 32], genesis_time: 0, epoch_seconds: 10,
            max_epoch_bytes: 1024, retained_epochs: 3 };
        let mut batch = EpochBatch { feed: descriptor.feed, epoch: 100, responses: vec![] };
        batch.validate(&descriptor,100,1010).unwrap();
        let empty_size = bincode::serialized_size(&batch).unwrap();
        assert!(empty_size < 100);
        let packet = ReplyPacket { binding: DeliveryBinding { feed:descriptor.feed,epoch:100,locator:[2;32] },
            sealed:SealedResponse { nonce:[3;24],ciphertext:vec![4;200] } };
        batch.responses.push(packet.clone());
        batch.validate(&descriptor,100,1010).unwrap();
        assert_eq!(bincode::serialized_size(&batch).unwrap(), empty_size + bincode::serialized_size(&packet).unwrap());
        assert!(batch.validate(&descriptor,99,1010).is_err());
        assert!(batch.validate(&descriptor,100,1000).is_err());
        assert!(batch.validate(&descriptor,100,1040).is_err());
        batch.responses.push(packet);
        assert!(batch.validate(&descriptor,100,1010).is_err());
        batch.responses.pop();
        batch.responses[0].sealed.ciphertext.resize(1024,0);
        assert!(batch.validate(&descriptor,100,1010).is_err());
    }
}
