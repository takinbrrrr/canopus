//! Low-level byte codecs for bLIP-17 hosted channel messages.
//!
//! All multi-byte integers on the wire are **big-endian** unless noted
//! otherwise (the HC messages reuse BOLT-2 message bodies which are BE).
//! The sighash inside [`crate::wire::lcss`] uses little-endian for the
//! numeric fields, matching the scoin reference.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("unexpected end of buffer")]
    Eof,
    #[error("invalid value: {0}")]
    Invalid(String),
}

pub type DecodeResult<T> = Result<T, DecodeError>;

// ---------------------------------------------------------------------------
// Primitive readers
// ---------------------------------------------------------------------------

pub fn read_u8(buf: &mut &[u8]) -> DecodeResult<u8> {
    if buf.is_empty() {
        return Err(DecodeError::Eof);
    }
    Ok(buf.get_u8())
}

pub fn read_u16(buf: &mut &[u8]) -> DecodeResult<u16> {
    if buf.remaining() < 2 {
        return Err(DecodeError::Eof);
    }
    Ok(buf.get_u16())
}

pub fn read_u32(buf: &mut &[u8]) -> DecodeResult<u32> {
    if buf.remaining() < 4 {
        return Err(DecodeError::Eof);
    }
    Ok(buf.get_u32())
}

pub fn read_u64(buf: &mut &[u8]) -> DecodeResult<u64> {
    if buf.remaining() < 8 {
        return Err(DecodeError::Eof);
    }
    Ok(buf.get_u64())
}

pub fn read_bool(buf: &mut &[u8]) -> DecodeResult<bool> {
    Ok(read_u8(buf)? != 0)
}

/// Read a length-prefixed blob: `u16 len` followed by `len` bytes.
pub fn read_varsize(buf: &mut &[u8]) -> DecodeResult<Bytes> {
    let len = read_u16(buf)? as usize;
    if buf.remaining() < len {
        return Err(DecodeError::Eof);
    }
    Ok(buf.copy_to_bytes(len))
}

/// Read a fixed-size byte slice.
pub fn read_bytes(buf: &mut &[u8], n: usize) -> DecodeResult<Bytes> {
    if buf.remaining() < n {
        return Err(DecodeError::Eof);
    }
    Ok(buf.copy_to_bytes(n))
}

/// Read a 32-byte hash / preimage / signature-half.
pub fn read_32(buf: &mut &[u8]) -> DecodeResult<[u8; 32]> {
    let b = read_bytes(buf, 32)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Ok(arr)
}

/// Read a 64-byte compact ECDSA signature.
pub fn read_signature(buf: &mut &[u8]) -> DecodeResult<[u8; 64]> {
    let b = read_bytes(buf, 64)?;
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&b);
    Ok(arr)
}

// ---------------------------------------------------------------------------
// Primitive writers
// ---------------------------------------------------------------------------

pub fn write_u8(buf: &mut BytesMut, v: u8) {
    buf.put_u8(v);
}

pub fn write_u16(buf: &mut BytesMut, v: u16) {
    buf.put_u16(v);
}

pub fn write_u32(buf: &mut BytesMut, v: u32) {
    buf.put_u32(v);
}

pub fn write_u64(buf: &mut BytesMut, v: u64) {
    buf.put_u64(v);
}

pub fn write_bool(buf: &mut BytesMut, v: bool) {
    buf.put_u8(if v { 1 } else { 0 });
}

pub fn write_varsize(buf: &mut BytesMut, data: &[u8]) {
    debug_assert!(data.len() <= u16::MAX as usize, "varsize blob exceeds u16");
    buf.put_u16(data.len() as u16);
    buf.extend_from_slice(data);
}

pub fn write_bytes(buf: &mut BytesMut, data: &[u8]) {
    buf.extend_from_slice(data);
}

pub fn write_32(buf: &mut BytesMut, arr: &[u8; 32]) {
    buf.extend_from_slice(arr);
}

pub fn write_signature(buf: &mut BytesMut, arr: &[u8; 64]) {
    buf.extend_from_slice(arr);
}

// ---------------------------------------------------------------------------
// Little-endian helpers (used only by the sighash)
// ---------------------------------------------------------------------------

pub fn write_u64_le(buf: &mut BytesMut, v: u64) {
    buf.put_u64_le(v);
}

pub fn write_u32_le(buf: &mut BytesMut, v: u32) {
    buf.put_u32_le(v);
}

// ---------------------------------------------------------------------------
// BOLT-2 update_add_htlc body encoding
// ---------------------------------------------------------------------------

/// `update_add_htlc` message body (BOLT-2), without the type prefix.
///
/// ```text
/// u64 channel_id
/// u64 amount_msat
/// u64 payment_hash
/// u64 cltv_expiry
/// u16 onion_routing_packet_len  (always 1366)
/// [1366]byte onion_routing_packet
/// ```
pub fn encode_update_add_htlc_body(buf: &mut BytesMut, htlc: &UpdateAddHtlc) {
    write_u64(buf, htlc.channel_id);
    write_u64(buf, htlc.amount_msat);
    write_32(buf, &htlc.payment_hash);
    write_u32(buf, htlc.cltv_expiry);
    write_u16(buf, htlc.onion_routing_packet.len() as u16);
    write_bytes(buf, &htlc.onion_routing_packet);
}

pub fn decode_update_add_htlc_body(buf: &mut &[u8]) -> DecodeResult<UpdateAddHtlc> {
    let channel_id = read_u64(buf)?;
    let amount_msat = read_u64(buf)?;
    let payment_hash = read_32(buf)?;
    let cltv_expiry = read_u32(buf)?;
    let onion = read_varsize(buf)?;
    if onion.len() != 1366 {
        return Err(DecodeError::Invalid(format!(
            "onion packet must be 1366 bytes, got {}",
            onion.len()
        )));
    }
    Ok(UpdateAddHtlc {
        channel_id,
        amount_msat,
        payment_hash,
        cltv_expiry,
        onion_routing_packet: onion,
    })
}

/// An `update_add_htlc` as carried inside a `last_cross_signed_state`.
///
/// Note: in the BOLT-2 body, the `channel_id` field serves as the HTLC id
/// within the hosted channel (there is no separate per-channel funding).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateAddHtlc {
    /// In HC context, this is the HTLC id (unique within the channel).
    pub channel_id: u64,
    pub amount_msat: u64,
    pub payment_hash: [u8; 32],
    pub cltv_expiry: u32,
    #[serde(with = "serde_bytes_hex")]
    pub onion_routing_packet: Bytes,
}

impl UpdateAddHtlc {
    /// The HTLC id — in HC, `channel_id` from the BOLT-2 body is used as the id.
    pub fn htlc_id(&self) -> u64 {
        self.channel_id
    }
}

pub mod serde_bytes_hex {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &Bytes, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s)
            .map(Bytes::from)
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u64() {
        let mut buf = BytesMut::new();
        write_u64(&mut buf, 0x0123_4567_89AB_CDEF);
        let mut slice: &[u8] = &buf;
        assert_eq!(read_u64(&mut slice).unwrap(), 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn roundtrip_varsize() {
        let mut buf = BytesMut::new();
        write_varsize(&mut buf, &[1, 2, 3]);
        let mut slice: &[u8] = &buf;
        assert_eq!(read_varsize(&mut slice).unwrap(), &b"\x01\x02\x03"[..]);
    }

    #[test]
    fn roundtrip_update_add_htlc() {
        let htlc = UpdateAddHtlc {
            channel_id: 42,
            amount_msat: 1_000_000,
            payment_hash: [0xAA; 32],
            cltv_expiry: 800_000,
            onion_routing_packet: Bytes::from(vec![0xBB; 1366]),
        };
        let mut buf = BytesMut::new();
        encode_update_add_htlc_body(&mut buf, &htlc);
        let mut slice: &[u8] = &buf;
        let decoded = decode_update_add_htlc_body(&mut slice).unwrap();
        assert_eq!(decoded, htlc);
        assert!(slice.is_empty());
    }

    #[test]
    fn eof_on_short_buffer() {
        let mut slice: &[u8] = &[1, 2, 3];
        assert!(read_u64(&mut slice).is_err());
    }
}
