//! Wire format for messages flowing through an anymone subnet.
//!
//! Per README §Message wire format:
//! ```text
//! | version (1 byte) | header | data |
//!
//! | version | type           | header fields                                                 |
//! | 00      | raw            | service_tag (20 bytes)                                        |
//! | 01      | multi-fragment | service_tag (20) || n_chunks (1) || chunk_index (1) || sig    |
//! ```
//!
//! The v1 signature binds the version, service_tag, n_chunks, chunk_index,
//! and the chunk's data — so reassembly can group chunks by signer.
//! Reassembly itself lands in M6; for now we parse and re-emit v1 frames
//! but don't combine them.

use std::fmt;

use thiserror::Error;

pub const VERSION_RAW: u8 = 0x00;
pub const VERSION_MULTI_FRAGMENT: u8 = 0x01;
pub const SERVICE_TAG_LEN: usize = 20;
pub const SIGNATURE_LEN: usize = 64;

/// A 20-byte routing tag identifying a service (or a per-pipe return path).
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceTag(pub [u8; SERVICE_TAG_LEN]);

impl ServiceTag {
    pub const fn from_bytes(bytes: [u8; SERVICE_TAG_LEN]) -> Self {
        ServiceTag(bytes)
    }

    /// Derive a tag from a human-readable string: SHA-256, truncated to the tag
    /// length. Two labels sharing a raw prefix must not collide into the same
    /// tag, so this hashes rather than copying bytes directly.
    pub fn from_label(s: &str) -> Self {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(s.as_bytes());
        let mut out = [0u8; SERVICE_TAG_LEN];
        out.copy_from_slice(&digest[..SERVICE_TAG_LEN]);
        ServiceTag(out)
    }
}

impl fmt::Debug for ServiceTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceTag({})", hex::encode(self.0))
    }
}

impl fmt::Display for ServiceTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl serde::Serialize for ServiceTag {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(self.0))
        } else {
            // Use the default array encoding so serialize/deserialize match
            // under bincode (which encodes [u8; N] as N raw bytes, with no
            // length prefix).
            self.0.serialize(s)
        }
    }
}

impl<'de> serde::Deserialize<'de> for ServiceTag {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            let arr: [u8; SERVICE_TAG_LEN] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| serde::de::Error::custom("service tag must be 20 bytes"))?;
            Ok(ServiceTag(arr))
        } else {
            let bytes = <[u8; SERVICE_TAG_LEN]>::deserialize(d)?;
            Ok(ServiceTag(bytes))
        }
    }
}

/// A 20-byte delivery address the transport routes to. A destination is either a
/// service (reachable at its [`ServiceTag`]) or a client's per-pipe return path;
/// on the wire both are just delivery addresses, distinct from service *identity*.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct RouteTag(pub [u8; SERVICE_TAG_LEN]);

impl RouteTag {
    pub const fn from_bytes(bytes: [u8; SERVICE_TAG_LEN]) -> Self {
        RouteTag(bytes)
    }
}

impl From<ServiceTag> for RouteTag {
    fn from(t: ServiceTag) -> Self {
        RouteTag(t.0)
    }
}

impl fmt::Debug for RouteTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RouteTag({})", hex::encode(self.0))
    }
}

/// A parsed message off the broadcast channel, borrowed from the underlying buffer.
#[derive(Debug, Clone)]
pub enum Frame<'a> {
    Raw { dst: RouteTag, data: &'a [u8] },
    Fragment {
        dst: RouteTag,
        n_chunks: u8,
        chunk_index: u8,
        signature: [u8; SIGNATURE_LEN],
        data: &'a [u8],
    },
}

impl<'a> Frame<'a> {
    pub fn dst(&self) -> RouteTag {
        match self {
            Frame::Raw { dst, .. } => *dst,
            Frame::Fragment { dst, .. } => *dst,
        }
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, WireError> {
        let (version, rest) = bytes.split_first().ok_or(WireError::Truncated)?;
        match *version {
            VERSION_RAW => {
                if rest.len() < SERVICE_TAG_LEN {
                    return Err(WireError::Truncated);
                }
                let (tag, data) = rest.split_at(SERVICE_TAG_LEN);
                let mut tag_bytes = [0u8; SERVICE_TAG_LEN];
                tag_bytes.copy_from_slice(tag);
                Ok(Frame::Raw { dst: RouteTag(tag_bytes), data })
            }
            VERSION_MULTI_FRAGMENT => {
                let min_len = SERVICE_TAG_LEN + 1 + 1 + SIGNATURE_LEN;
                if rest.len() < min_len {
                    return Err(WireError::Truncated);
                }
                let (tag, rest) = rest.split_at(SERVICE_TAG_LEN);
                let n_chunks = rest[0];
                let chunk_index = rest[1];
                let (sig, data) = rest[2..].split_at(SIGNATURE_LEN);
                if n_chunks == 0 {
                    return Err(WireError::InvalidChunkCount);
                }
                if chunk_index >= n_chunks {
                    return Err(WireError::InvalidChunkIndex { index: chunk_index, count: n_chunks });
                }
                let mut tag_bytes = [0u8; SERVICE_TAG_LEN];
                tag_bytes.copy_from_slice(tag);
                let mut sig_bytes = [0u8; SIGNATURE_LEN];
                sig_bytes.copy_from_slice(sig);
                Ok(Frame::Fragment {
                    dst: RouteTag(tag_bytes),
                    n_chunks,
                    chunk_index,
                    signature: sig_bytes,
                    data,
                })
            }
            other => Err(WireError::UnknownVersion(other)),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Raw { dst, data } => {
                out.push(VERSION_RAW);
                out.extend_from_slice(&dst.0);
                out.extend_from_slice(data);
            }
            Frame::Fragment { dst, n_chunks, chunk_index, signature, data } => {
                out.push(VERSION_MULTI_FRAGMENT);
                out.extend_from_slice(&dst.0);
                out.push(*n_chunks);
                out.push(*chunk_index);
                out.extend_from_slice(signature);
                out.extend_from_slice(data);
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

/// Bytes the v1 signature is computed over: version || dst || n_chunks
/// || chunk_index || data. Useful for both signing and verification.
pub fn fragment_signing_bytes(
    dst: &RouteTag,
    n_chunks: u8,
    chunk_index: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + SERVICE_TAG_LEN + 1 + 1 + data.len());
    buf.push(VERSION_MULTI_FRAGMENT);
    buf.extend_from_slice(&dst.0);
    buf.push(n_chunks);
    buf.push(chunk_index);
    buf.extend_from_slice(data);
    buf
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("truncated frame")]
    Truncated,
    #[error("unknown wire version: {0:#04x}")]
    UnknownVersion(u8),
    #[error("invalid chunk count (0 not allowed)")]
    InvalidChunkCount,
    #[error("chunk index {index} out of range for count {count}")]
    InvalidChunkIndex { index: u8, count: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag() -> RouteTag {
        ServiceTag::from_label("anymone.echo").into()
    }

    #[test]
    fn raw_roundtrip() {
        let f = Frame::Raw { dst: tag(), data: b"hello" };
        let bytes = f.to_bytes();
        let parsed = Frame::decode(&bytes).unwrap();
        match parsed {
            Frame::Raw { dst, data } => {
                assert_eq!(dst, tag());
                assert_eq!(data, b"hello");
            }
            other => panic!("expected Raw, got {other:?}"),
        }
    }

    #[test]
    fn fragment_roundtrip() {
        let f = Frame::Fragment {
            dst: tag(),
            n_chunks: 3,
            chunk_index: 1,
            signature: [7u8; SIGNATURE_LEN],
            data: b"chunk-data",
        };
        let bytes = f.to_bytes();
        let parsed = Frame::decode(&bytes).unwrap();
        match parsed {
            Frame::Fragment { dst, n_chunks, chunk_index, signature, data } => {
                assert_eq!(dst, tag());
                assert_eq!(n_chunks, 3);
                assert_eq!(chunk_index, 1);
                assert_eq!(signature, [7u8; SIGNATURE_LEN]);
                assert_eq!(data, b"chunk-data");
            }
            other => panic!("expected Fragment, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_version() {
        let bytes = [0x99u8; 25];
        assert_eq!(Frame::decode(&bytes).unwrap_err(), WireError::UnknownVersion(0x99));
    }

    #[test]
    fn rejects_truncated_raw() {
        let bytes = [VERSION_RAW, 1, 2, 3];
        assert_eq!(Frame::decode(&bytes).unwrap_err(), WireError::Truncated);
    }

    #[test]
    fn rejects_truncated_fragment() {
        let bytes = [VERSION_MULTI_FRAGMENT, 1, 2, 3];
        assert_eq!(Frame::decode(&bytes).unwrap_err(), WireError::Truncated);
    }

    #[test]
    fn rejects_zero_chunks() {
        let f = Frame::Fragment {
            dst: tag(),
            n_chunks: 0,
            chunk_index: 0,
            signature: [0u8; SIGNATURE_LEN],
            data: b"x",
        };
        // We can encode invalid frames, but decode must reject.
        let bytes = f.to_bytes();
        assert_eq!(Frame::decode(&bytes).unwrap_err(), WireError::InvalidChunkCount);
    }

    #[test]
    fn rejects_chunk_index_past_count() {
        let f = Frame::Fragment {
            dst: tag(),
            n_chunks: 2,
            chunk_index: 5,
            signature: [0u8; SIGNATURE_LEN],
            data: b"x",
        };
        let bytes = f.to_bytes();
        assert_eq!(
            Frame::decode(&bytes).unwrap_err(),
            WireError::InvalidChunkIndex { index: 5, count: 2 }
        );
    }

    #[test]
    fn service_tag_string_roundtrip() {
        let t = ServiceTag::from_label("anymone.echo");
        let json = serde_json::to_string(&t).unwrap();
        let t2: ServiceTag = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }
}
