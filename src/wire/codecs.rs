//! Low-level byte codecs for bLIP-17 hosted channel messages.
//!
//! All multi-byte integers on the wire are **big-endian** unless noted
//! otherwise (the HC messages reuse BOLT-2 message bodies which are BE).
//! The sighash inside [`crate::wire::lcss`] uses little-endian for the
//! numeric fields, matching the scoin reference.
//!
//! The `lengthDelimited` wrappers used in LCSS encoding use BOLT/TLV
//! varint length prefixes, matching scoin's `variableSizeBytesLong(varintoverflow, codec)`.
//!
//! `uint64overflow` is scoin's signed-int64 codec that rejects values >= 2^63.
//! It is used for all `millisatoshi`, `satoshi`, and HTLC `id` fields.

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

#[derive(Debug, Error)]
pub enum EncodeError {
    #[error("uint64overflow: value {0} exceeds 2^63 - 1")]
    Overflow(u64),
    #[error("varsize blob exceeds u16::MAX: {0} bytes")]
    VarsizeTooLarge(usize),
    #[error("onion routing packet must be exactly {expected} bytes, got {actual}")]
    InvalidOnionLength { expected: usize, actual: usize },
    #[error("invalid UTF-8: {0}")]
    InvalidUtf8(String),
}

pub type EncodeResult<T> = Result<T, EncodeError>;

/// Maximum value representable in scoin's `uint64overflow` (signed int64 >= 0).
pub const UINT64_OVERFLOW_MAX: u64 = i64::MAX as u64;

/// TLV type high-range boundary: even tags below this value are mandatory
/// and must be rejected when unknown (matching scoin's `validateGenericTlv`).
pub const TLV_TYPE_HIGH_RANGE: u64 = 0x1_0000_0000;

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

/// Read a `uint64overflow` value (signed int64 big-endian, must be >= 0).
pub fn read_u64_overflow(buf: &mut &[u8]) -> DecodeResult<u64> {
    let v = read_u64(buf)?;
    if v > UINT64_OVERFLOW_MAX {
        return Err(DecodeError::Invalid(format!(
            "uint64overflow: value {} exceeds 2^63 - 1",
            v
        )));
    }
    Ok(v)
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

/// Read all remaining bytes in the buffer.
pub fn read_remaining(buf: &mut &[u8]) -> Bytes {
    let len = buf.len();
    if len == 0 {
        return Bytes::new();
    }
    buf.copy_to_bytes(len)
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
// BOLT varint (used by lengthDelimited in scoin)
// ---------------------------------------------------------------------------

/// Write a BOLT/TLV varint (big-endian multi-byte forms).
pub fn write_varint(buf: &mut BytesMut, v: u64) {
    if v < 0xfd {
        buf.put_u8(v as u8);
    } else if v <= 0xffff {
        buf.put_u8(0xfd);
        buf.put_u16(v as u16);
    } else if v <= 0xffff_ffff {
        buf.put_u8(0xfe);
        buf.put_u32(v as u32);
    } else {
        buf.put_u8(0xff);
        buf.put_u64(v);
    }
}

/// Read a BOLT/TLV varint (big-endian multi-byte forms).
///
/// Enforces minimal encoding as required by BOLT and scoin's
/// `varintoverflow`: a value that could have been encoded in a shorter
/// form is rejected.
pub fn read_varint(buf: &mut &[u8]) -> DecodeResult<u64> {
    let prefix = read_u8(buf)?;
    Ok(match prefix {
        0xff => {
            let v = read_u64(buf)?;
            if v < TLV_TYPE_HIGH_RANGE {
                return Err(DecodeError::Invalid(
                    "non-minimal varint: 0xff prefix for value < 0x100000000".into(),
                ));
            }
            v
        }
        0xfe => {
            let v = read_u32(buf)? as u64;
            if v < 0x1_0000 {
                return Err(DecodeError::Invalid(
                    "non-minimal varint: 0xfe prefix for value < 0x10000".into(),
                ));
            }
            v
        }
        0xfd => {
            let v = read_u16(buf)? as u64;
            if v < 0xfd {
                return Err(DecodeError::Invalid(
                    "non-minimal varint: 0xfd prefix for value < 0xfd".into(),
                ));
            }
            v
        }
        _ => prefix as u64,
    })
}

/// Write a lengthDelimited body: varint length prefix + body bytes.
pub fn write_length_delimited(buf: &mut BytesMut, body: &[u8]) -> EncodeResult<()> {
    write_varint(buf, body.len() as u64);
    buf.extend_from_slice(body);
    Ok(())
}

/// Read a lengthDelimited body: varint length prefix + body bytes.
/// Returns the body and consumes it from the buffer.
pub fn read_length_delimited(buf: &mut &[u8]) -> DecodeResult<Bytes> {
    let len = read_varint(buf)? as usize;
    if buf.remaining() < len {
        return Err(DecodeError::Eof);
    }
    Ok(buf.copy_to_bytes(len))
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

/// Write a `uint64overflow` value (must be < 2^63).
pub fn write_u64_overflow(buf: &mut BytesMut, v: u64) -> EncodeResult<()> {
    if v > UINT64_OVERFLOW_MAX {
        return Err(EncodeError::Overflow(v));
    }
    buf.put_u64(v);
    Ok(())
}

pub fn write_bool(buf: &mut BytesMut, v: bool) {
    buf.put_u8(if v { 1 } else { 0 });
}

/// Write a length-prefixed blob: `u16 len` followed by `len` bytes.
pub fn write_varsize(buf: &mut BytesMut, data: &[u8]) -> EncodeResult<()> {
    if data.len() > u16::MAX as usize {
        return Err(EncodeError::VarsizeTooLarge(data.len()));
    }
    buf.put_u16(data.len() as u16);
    buf.extend_from_slice(data);
    Ok(())
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

/// Write a `uint64overflow` value in little-endian (for sighash).
pub fn write_u64_overflow_le(buf: &mut BytesMut, v: u64) -> EncodeResult<()> {
    if v > UINT64_OVERFLOW_MAX {
        return Err(EncodeError::Overflow(v));
    }
    buf.put_u64_le(v);
    Ok(())
}

// ---------------------------------------------------------------------------
// BOLT-2 update_add_htlc body encoding (scoin-compatible)
// ---------------------------------------------------------------------------

/// The fixed onion routing packet size (version + pubkey + payload + hmac).
pub const ONION_ROUTING_PACKET_SIZE: usize = 1366;

/// `update_add_htlc` message body, matching scoin's `updateAddHtlcCodec`.
///
/// ```text
/// [32] channel_id (bytes32 — the hosted channel id)
/// [8]  id (uint64overflow BE — the HTLC id)
/// [8]  amount_msat (uint64overflow BE)
/// [32] payment_hash (bytes32)
/// [4]  cltv_expiry (u32 BE)
/// [1366] onion_routing_packet (fixed, no length prefix)
/// [0+] tlv_stream (trailing TLV stream, empty for HC)
/// ```
pub fn encode_update_add_htlc_body(buf: &mut BytesMut, htlc: &UpdateAddHtlc) -> EncodeResult<()> {
    write_32(buf, &htlc.channel_id);
    write_u64_overflow(buf, htlc.id)?;
    write_u64_overflow(buf, htlc.amount_msat)?;
    write_32(buf, &htlc.payment_hash);
    write_u32(buf, htlc.cltv_expiry);
    if htlc.onion_routing_packet.len() != ONION_ROUTING_PACKET_SIZE {
        return Err(EncodeError::InvalidOnionLength {
            expected: ONION_ROUTING_PACKET_SIZE,
            actual: htlc.onion_routing_packet.len(),
        });
    }
    write_bytes(buf, &htlc.onion_routing_packet);
    write_bytes(buf, &htlc.tlv_stream);
    Ok(())
}

pub fn decode_update_add_htlc_body(buf: &mut &[u8]) -> DecodeResult<UpdateAddHtlc> {
    let channel_id = read_32(buf)?;
    let id = read_u64_overflow(buf)?;
    let amount_msat = read_u64_overflow(buf)?;
    let payment_hash = read_32(buf)?;
    let cltv_expiry = read_u32(buf)?;
    let onion = read_bytes(buf, ONION_ROUTING_PACKET_SIZE)?;
    let tlv_stream = read_remaining(buf);
    validate_tlv_stream(&tlv_stream)?;
    Ok(UpdateAddHtlc {
        channel_id,
        id,
        amount_msat,
        payment_hash,
        cltv_expiry,
        onion_routing_packet: onion,
        tlv_stream,
    })
}

/// An `update_add_htlc` as carried inside hosted channel messages.
///
/// Uses the full scoin/BOLT-2 body layout with a 32-byte `channel_id`
/// (the hosted channel id) and a separate `id` field (the HTLC id).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateAddHtlc {
    pub channel_id: [u8; 32],
    pub id: u64,
    pub amount_msat: u64,
    pub payment_hash: [u8; 32],
    pub cltv_expiry: u32,
    #[serde(with = "serde_bytes_hex")]
    pub onion_routing_packet: Bytes,
    #[serde(default, with = "serde_bytes_hex")]
    pub tlv_stream: Bytes,
}

impl UpdateAddHtlc {
    pub fn htlc_id(&self) -> u64 {
        self.id
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

pub mod serde_array_hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// ---------------------------------------------------------------------------
// TLV stream validation (matches scoin's validateStream + validateGenericTlv)
// ---------------------------------------------------------------------------

/// Validate a raw TLV stream for canonical ordering and mandatory-type rules.
///
/// Rules (matching scoin):
/// - Tags must be in strictly monotonically increasing order (no duplicates).
/// - Each tag and length must use minimal varint encoding (enforced by `read_varint`).
/// - Even tags below `TLV_TYPE_HIGH_RANGE` (2^32) are mandatory and rejected when unknown.
/// - Odd tags and tags >= 2^32 are accepted (preserved as raw bytes).
pub fn validate_tlv_stream(data: &[u8]) -> DecodeResult<()> {
    if data.is_empty() {
        return Ok(());
    }
    let mut buf: &[u8] = data;
    let mut prev_tag: Option<u64> = None;

    while !buf.is_empty() {
        let tag = read_varint(&mut buf)?;
        let len = read_varint(&mut buf)? as usize;
        if buf.remaining() < len {
            return Err(DecodeError::Eof);
        }
        let _value = read_bytes(&mut buf, len)?;

        if let Some(pt) = prev_tag {
            if tag <= pt {
                return Err(DecodeError::Invalid(
                    "TLV tags must be strictly monotonically increasing".into(),
                ));
            }
        }

        if tag < TLV_TYPE_HIGH_RANGE && tag % 2 == 0 {
            return Err(DecodeError::Invalid(format!(
                "unknown even TLV type {}",
                tag
            )));
        }

        prev_tag = Some(tag);
    }
    Ok(())
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
    fn roundtrip_u64_overflow() {
        let mut buf = BytesMut::new();
        write_u64_overflow(&mut buf, 1_000_000).unwrap();
        let mut slice: &[u8] = &buf;
        assert_eq!(read_u64_overflow(&mut slice).unwrap(), 1_000_000);
    }

    #[test]
    fn u64_overflow_rejects_large_values() {
        let mut buf = BytesMut::new();
        let val = UINT64_OVERFLOW_MAX + 1;
        assert!(write_u64_overflow(&mut buf, val).is_err());

        buf.clear();
        write_u64(&mut buf, val);
        let mut slice: &[u8] = &buf;
        assert!(read_u64_overflow(&mut slice).is_err());
    }

    #[test]
    fn roundtrip_varsize() {
        let mut buf = BytesMut::new();
        write_varsize(&mut buf, &[1, 2, 3]).unwrap();
        let mut slice: &[u8] = &buf;
        assert_eq!(read_varsize(&mut slice).unwrap(), &b"\x01\x02\x03"[..]);
    }

    #[test]
    fn varsize_rejects_too_large() {
        let mut buf = BytesMut::new();
        let big = vec![0u8; (u16::MAX as usize) + 1];
        assert!(write_varsize(&mut buf, &big).is_err());
    }

    #[test]
    fn roundtrip_varint() {
        let cases: &[u64] = &[
            0,
            1,
            0xfc,
            0xfd,
            0xffff,
            0x10000,
            0xffff_ffff,
            0x1_0000_0000,
        ];
        for &v in cases {
            let mut buf = BytesMut::new();
            write_varint(&mut buf, v);
            let mut slice: &[u8] = &buf;
            assert_eq!(
                read_varint(&mut slice).unwrap(),
                v,
                "varint roundtrip for {}",
                v
            );
        }
    }

    #[test]
    fn non_minimal_varint_rejected() {
        let bad_cases: &[(u8, &[u8], &str)] = &[
            (0xfd, &[0x00, 0xfc], "0xfd prefix for 252"),
            (0xfd, &[0x00, 0x00], "0xfd prefix for 0"),
            (0xfe, &[0x00, 0x00, 0x00, 0xfc], "0xfe prefix for 252"),
            (0xfe, &[0x00, 0x00, 0xff, 0xff], "0xfe prefix for 0xffff"),
            (
                0xff,
                &[0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
                "0xff prefix for 0xffffffff",
            ),
        ];
        for (prefix, payload, desc) in bad_cases {
            let mut buf = vec![*prefix];
            buf.extend_from_slice(payload);
            let mut slice: &[u8] = &buf;
            assert!(
                read_varint(&mut slice).is_err(),
                "should reject non-minimal varint: {}",
                desc
            );
        }
    }

    #[test]
    fn roundtrip_update_add_htlc() {
        let htlc = UpdateAddHtlc {
            channel_id: [0xCC; 32],
            id: 42,
            amount_msat: 1_000_000,
            payment_hash: [0xAA; 32],
            cltv_expiry: 800_000,
            onion_routing_packet: Bytes::from(vec![0xBB; ONION_ROUTING_PACKET_SIZE]),
            tlv_stream: Bytes::new(),
        };
        let mut buf = BytesMut::new();
        encode_update_add_htlc_body(&mut buf, &htlc).unwrap();
        let mut slice: &[u8] = &buf;
        let decoded = decode_update_add_htlc_body(&mut slice).unwrap();
        assert_eq!(decoded, htlc);
        assert!(slice.is_empty());
    }

    #[test]
    fn encode_rejects_wrong_onion_length() {
        let htlc = UpdateAddHtlc {
            channel_id: [0xCC; 32],
            id: 42,
            amount_msat: 1_000_000,
            payment_hash: [0xAA; 32],
            cltv_expiry: 800_000,
            onion_routing_packet: Bytes::from(vec![0xBB; 100]),
            tlv_stream: Bytes::new(),
        };
        let mut buf = BytesMut::new();
        assert!(encode_update_add_htlc_body(&mut buf, &htlc).is_err());
    }

    #[test]
    fn eof_on_short_buffer() {
        let mut slice: &[u8] = &[1, 2, 3];
        assert!(read_u64(&mut slice).is_err());
    }

    #[test]
    fn tlv_empty_stream_valid() {
        assert!(validate_tlv_stream(&[]).is_ok());
    }

    #[test]
    fn tlv_odd_tag_accepted() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 1);
        write_varint(&mut buf, 4);
        write_bytes(&mut buf, &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(validate_tlv_stream(&buf).is_ok());
    }

    #[test]
    fn tlv_even_tag_below_high_range_rejected() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 2);
        write_varint(&mut buf, 1);
        write_bytes(&mut buf, &[0xFF]);
        assert!(validate_tlv_stream(&buf).is_err());
    }

    #[test]
    fn tlv_tags_must_be_increasing() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 3);
        write_varint(&mut buf, 0);
        write_varint(&mut buf, 1);
        write_varint(&mut buf, 0);
        assert!(validate_tlv_stream(&buf).is_err());
    }

    #[test]
    fn tlv_duplicate_tags_rejected() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 1);
        write_varint(&mut buf, 1);
        write_bytes(&mut buf, &[0xAA]);
        write_varint(&mut buf, 1);
        write_varint(&mut buf, 1);
        write_bytes(&mut buf, &[0xBB]);
        assert!(validate_tlv_stream(&buf).is_err());
    }

    #[test]
    fn tlv_multiple_odd_tags_in_order_accepted() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 1);
        write_varint(&mut buf, 2);
        write_bytes(&mut buf, &[0xAA, 0xBB]);
        write_varint(&mut buf, 3);
        write_varint(&mut buf, 1);
        write_bytes(&mut buf, &[0xCC]);
        assert!(validate_tlv_stream(&buf).is_ok());
    }
}
