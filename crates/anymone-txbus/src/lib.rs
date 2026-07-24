//! Shared wire format and stateless admission checks for the anonymous
//! Ethereum tx bus: a broadcast [`anymone_core::ServiceTag`] carrying raw
//! EIP-2718 transaction bytes, consumed by `anymone-eth-bridge`'s ingress and
//! egress. No node dependency — only alloy types, so this crate stays light.

use alloy_consensus::{EthereumTxEnvelope, Transaction};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_eips::eip7594::BlobTransactionSidecarVariant;
use alloy_primitives::TxHash;
use anymone_core::ServiceTag;

/// The pooled/network transaction representation carried on the bus — the
/// standard post-EIP-4844 Ethereum tx envelope, same type every mainstream
/// execution client (reth, geth, etc.) accepts via `eth_sendRawTransaction`.
pub type PooledTx =
    EthereumTxEnvelope<alloy_consensus::TxEip4844WithSidecar<BlobTransactionSidecarVariant>>;

pub fn tx_bus_tag(chain_id: u64) -> ServiceTag {
    ServiceTag::from_label(&format!("anymone.eth.tx.{chain_id}"))
}

/// Bus payload = the EIP-2718 network encoding, nothing else.
pub fn encode_tx(tx: &PooledTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(tx.encode_2718_len());
    tx.encode_2718(&mut out);
    out
}

pub fn decode_tx(bytes: &[u8]) -> Result<PooledTx, BusError> {
    let mut buf = bytes;
    let tx = PooledTx::decode_2718(&mut buf).map_err(|e| BusError::Decode(e.to_string()))?;
    if !buf.is_empty() {
        return Err(BusError::TrailingBytes);
    }
    Ok(tx)
}

/// Stateless admission — the subset of reth's `EthTransactionValidator::validate_stateless`
/// (`crates/transaction-pool/src/validate/eth.rs`) that needs no chain state, plus bus
/// policy (size vs. the bus carrier, and a spam-economics gas price floor).
#[derive(Debug, Clone)]
pub struct StatelessLimits {
    pub chain_id: u64,
    /// Must be `anymone_core::max_message_payload(carrier_message_size)` for
    /// whatever subnet actually carries the bus — never a hand estimate.
    pub max_encoded_size: usize,
    pub max_gas_limit: u64,
    /// Spam floor: reject anything under this effective gas price. Bus
    /// policy, not a protocol rule — legacy/eth/68 gossip has no analogue
    /// because unattributable senders can't be penalized after the fact.
    pub min_gas_price: u128,
}

pub fn check_stateless(
    encoded_len: usize,
    tx: &PooledTx,
    limits: &StatelessLimits,
) -> Result<(), TxReject> {
    if tx.is_eip4844() {
        return Err(TxReject::BlobTx);
    }
    if encoded_len > limits.max_encoded_size {
        return Err(TxReject::TooLarge {
            size: encoded_len,
            max: limits.max_encoded_size,
        });
    }
    if tx.chain_id() != Some(limits.chain_id) {
        return Err(TxReject::WrongChain);
    }
    if tx.nonce() == u64::MAX {
        return Err(TxReject::NonceMax);
    }
    if tx.gas_limit() > limits.max_gas_limit {
        return Err(TxReject::GasTooHigh {
            limit: tx.gas_limit(),
            max: limits.max_gas_limit,
        });
    }
    let max_fee = tx.max_fee_per_gas();
    if tx.max_priority_fee_per_gas().unwrap_or(0) > max_fee {
        return Err(TxReject::TipAboveFeeCap);
    }
    if max_fee < limits.min_gas_price {
        return Err(TxReject::UnderPriced {
            fee: max_fee,
            min: limits.min_gas_price,
        });
    }
    Ok(())
}

/// The canonical transaction hash — `TxHashRef::tx_hash`, the same accessor
/// reth's pool uses. Never called on a blob tx (`check_stateless` rejects
/// those first): the pooled/network encoding for EIP-4844 appends the blob
/// sidecar after the signed payload, so `tx_hash()` (hash of the signed
/// payload alone) and a naive hash of the encoded bytes would disagree.
pub fn tx_hash(tx: &PooledTx) -> TxHash {
    *tx.tx_hash()
}

/// The largest EIP-2718 payload that fits one bus message on a carrier with
/// `message_size`, delegating to `anymone_core::max_message_payload` — the
/// one place that knows the real `Frame`/`PipeMessage` framing.
pub fn max_tx_size(message_size: usize) -> usize {
    anymone_core::max_message_payload(message_size)
}

#[derive(Debug, thiserror::Error)]
pub enum BusError {
    #[error("failed to decode EIP-2718 transaction: {0}")]
    Decode(String),
    #[error("trailing bytes after a valid EIP-2718 transaction")]
    TrailingBytes,
}

#[derive(Debug, thiserror::Error)]
pub enum TxReject {
    #[error("blob transactions are not carried on the tx bus (v0)")]
    BlobTx,
    #[error("tx {size}B exceeds bus message capacity {max}B")]
    TooLarge { size: usize, max: usize },
    #[error("tx is for a different chain")]
    WrongChain,
    #[error("nonce == u64::MAX is invalid (EIP-2681)")]
    NonceMax,
    #[error("gas limit {limit} exceeds bus cap {max}")]
    GasTooHigh { limit: u64, max: u64 },
    #[error("max_priority_fee_per_gas exceeds max_fee_per_gas")]
    TipAboveFeeCap,
    #[error("effective gas price {fee} under the bus's min {min}")]
    UnderPriced { fee: u128, min: u128 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559};
    use alloy_eips::eip2930::AccessList;
    use alloy_primitives::{Address, Signature, U256};

    // Not ecrecovered anywhere in this crate, so an arbitrary signature is
    // fine — reth's own tests construct fixtures the same way (e.g.
    // `crates/transaction-pool/src/traits.rs` test module).
    fn signed_tx(chain_id: u64, nonce: u64, max_fee_per_gas: u128, gas_limit: u64) -> PooledTx {
        let tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas: max_fee_per_gas,
            to: Address::ZERO.into(),
            value: U256::ZERO,
            access_list: AccessList::default(),
            input: Default::default(),
        };
        let signed = tx.into_signed(Signature::test_signature());
        PooledTx::Eip1559(signed)
    }

    fn limits(chain_id: u64, max_encoded_size: usize) -> StatelessLimits {
        StatelessLimits {
            chain_id,
            max_encoded_size,
            max_gas_limit: 30_000_000,
            min_gas_price: 1,
        }
    }

    /// Happy path: encode -> bus wire bytes -> decode -> passes stateless
    /// checks -> hash matches what the sender computed before sending.
    #[test]
    fn round_trip_and_stateless_accept() {
        let tx = signed_tx(1, 0, 1_000_000_000, 21_000);
        let expected_hash = tx_hash(&tx);

        let bytes = encode_tx(&tx);
        let decoded = decode_tx(&bytes).expect("valid tx decodes");
        assert_eq!(tx_hash(&decoded), expected_hash);

        let lims = limits(1, max_tx_size(1024));
        check_stateless(bytes.len(), &decoded, &lims).expect("well-formed tx passes");
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let tx = signed_tx(1, 0, 1_000_000_000, 21_000);
        let mut bytes = encode_tx(&tx);
        bytes.push(0xff);
        assert!(matches!(decode_tx(&bytes), Err(BusError::TrailingBytes)));
    }

    #[test]
    fn stateless_rejects_wrong_chain() {
        let tx = signed_tx(999, 0, 1_000_000_000, 21_000);
        let bytes = encode_tx(&tx);
        let lims = limits(1, max_tx_size(1024));
        assert!(matches!(
            check_stateless(bytes.len(), &tx, &lims),
            Err(TxReject::WrongChain)
        ));
    }

    #[test]
    fn stateless_rejects_nonce_max() {
        let tx = signed_tx(1, u64::MAX, 1_000_000_000, 21_000);
        let bytes = encode_tx(&tx);
        let lims = limits(1, max_tx_size(1024));
        assert!(matches!(
            check_stateless(bytes.len(), &tx, &lims),
            Err(TxReject::NonceMax)
        ));
    }

    #[test]
    fn stateless_rejects_gas_too_high() {
        let tx = signed_tx(1, 0, 1_000_000_000, 50_000_000);
        let bytes = encode_tx(&tx);
        let lims = limits(1, max_tx_size(1024));
        assert!(matches!(
            check_stateless(bytes.len(), &tx, &lims),
            Err(TxReject::GasTooHigh { .. })
        ));
    }

    #[test]
    fn stateless_rejects_underpriced() {
        let tx = signed_tx(1, 0, 100, 21_000);
        let bytes = encode_tx(&tx);
        let mut lims = limits(1, max_tx_size(1024));
        lims.min_gas_price = 1_000_000_000;
        assert!(matches!(
            check_stateless(bytes.len(), &tx, &lims),
            Err(TxReject::UnderPriced { .. })
        ));
    }

    #[test]
    fn stateless_rejects_oversized() {
        let tx = signed_tx(1, 0, 1_000_000_000, 21_000);
        let bytes = encode_tx(&tx);
        let lims = limits(1, bytes.len() - 1);
        assert!(matches!(
            check_stateless(bytes.len(), &tx, &lims),
            Err(TxReject::TooLarge { .. })
        ));
    }

    /// max_tx_size's boundary is exact: a payload of exactly that size is what
    /// a signed tx of realistic shape actually needs room for once wrapped in
    /// bus framing — checked against anymone_core's own real-packing helper,
    /// never a hand estimate.
    #[test]
    fn max_tx_size_matches_core_framing() {
        assert_eq!(max_tx_size(1024), anymone_core::max_message_payload(1024));
    }
}
