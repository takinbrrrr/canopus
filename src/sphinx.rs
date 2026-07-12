//! BOLT-4 Sphinx onion processing.
//!
//! Implements:
//! - Onion peel: given the node private key and an onion packet, extract
//!   the next hop's routing info (scid, amount, cltv) and produce the
//!   next-hop onion.
//! - Failure onion wrap: encrypt a failure message for the sender.
//! - Failure onion unwrap: decrypt a failure reply we received.
//!
//! The Sphinx packet format (BOLT-4):
//! - 1 byte version (0x00)
//! - 33 bytes ephemeral public key
//! - 1300 bytes hop data (encrypted payloads, 1300/65 = 20 hops)
//! - 32 bytes HMAC
//!
//! Total: 1366 bytes

use bytes::BytesMut;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, SecretKey};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const ONION_HOP_SIZE: usize = 65;
const ONION_ROUTING_INFO_SIZE: usize = 1300;
const ONION_PACKET_SIZE: usize = 1366; // 1 + 33 + 1300 + 32

// Key derivation labels (BOLT-4)
const KEY_RHO: &[u8] = b"rho";
const KEY_MU: &[u8] = b"mu";
const KEY_UM: &[u8] = b"um";

/// Errors that can occur during onion processing.
#[derive(Debug, thiserror::Error)]
pub enum SphinxError {
    #[error("invalid onion packet size: {0}")]
    InvalidSize(usize),
    #[error("unsupported onion version: {0}")]
    UnsupportedVersion(u8),
    #[error("HMAC verification failed")]
    HmacFailed,
    #[error("invalid ephemeral public key")]
    InvalidEphemeralKey,
    #[error("ECDH failed")]
    EcdhFailed,
    #[error("invalid hop payload: {0}")]
    InvalidPayload(String),
}

/// The result of peeling an onion: routing info for the next hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeeledOnion {
    /// Next hop's short channel id (0 if we're the final hop).
    pub short_channel_id: u64,
    /// Amount to forward to the next hop.
    pub amt_to_forward: u64,
    /// CLTV expiry for the outgoing HTLC.
    pub outgoing_cltv_value: u32,
    /// The onion packet for the next hop (or empty if final hop).
    pub next_onion: Vec<u8>,
    /// The shared secret (for failure encryption).
    pub shared_secret: [u8; 32],
}

/// Derive keys from a shared secret (BOLT-4 key generation).
fn derive_keys(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let rho = hmac_sha256(KEY_RHO, shared_secret);
    let mu = hmac_sha256(KEY_MU, shared_secret);
    let um = hmac_sha256(KEY_UM, shared_secret);
    (rho, mu, um)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute ECDH shared secret between our private key and a public key.
fn ecdh(privkey: &SecretKey, pubkey: &PublicKey) -> Result<[u8; 32], SphinxError> {
    // ECDH: compute shared secret = SHA256(0x02 || x-coord of (privkey * pubkey))
    let serialized = secp256k1::ecdh::shared_secret_point(pubkey, privkey);
    let mut out = [0u8; 32];
    // The first byte is the parity prefix, the next 32 bytes are the x coordinate
    if serialized.len() < 33 {
        return Err(SphinxError::EcdhFailed);
    }
    out.copy_from_slice(&serialized[1..33]);
    Ok(out)
}

/// Generate a ChaCha20 keystream of the given length.
fn chacha20_stream(key: &[u8; 32], length: usize) -> Vec<u8> {
    let mut cipher = ChaCha20::new_from_slices(key, &[0u8; 12]).expect("valid key and nonce");
    let mut stream = vec![0u8; length];
    cipher.apply_keystream(&mut stream);
    stream
}

/// XOR two byte slices in place.
fn xor_in_place(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Compute the blinding factor for the next ephemeral key.
fn blinding_factor(pubkey: &PublicKey, shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pubkey.serialize());
    hasher.update(shared_secret);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Blind the ephemeral public key for the next hop.
fn blind_pubkey(pubkey: &PublicKey, blinding_factor: &[u8; 32]) -> Result<PublicKey, SphinxError> {
    let secp = secp256k1::Secp256k1::new();
    let scalar =
        Scalar::from_be_bytes(*blinding_factor).map_err(|_| SphinxError::InvalidEphemeralKey)?;
    let blinded = pubkey
        .mul_tweak(&secp, &scalar)
        .map_err(|_| SphinxError::InvalidEphemeralKey)?;
    Ok(blinded)
}

/// Parse a TLV-encoded per-hop payload.
fn parse_tlv_payload(data: &[u8]) -> Result<(u64, u64, u32, usize), SphinxError> {
    if let Ok((payload_len, len_size)) = read_varint(data) {
        let end = len_size.saturating_add(payload_len as usize);
        if payload_len > 0 && end <= data.len() {
            return parse_tlv_payload_inner(&data[len_size..end])
                .map(|(s, a, c, _)| (s, a, c, end));
        }
    }
    parse_tlv_payload_inner(data)
}

fn parse_tlv_payload_inner(data: &[u8]) -> Result<(u64, u64, u32, usize), SphinxError> {
    let mut scid = 0u64;
    let mut amt = 0u64;
    let mut cltv = 0u32;
    let mut consumed = 0;

    while consumed < data.len() {
        // Read varint type
        let (tlv_type, type_len) = read_varint(&data[consumed..])?;
        consumed += type_len;
        if consumed >= data.len() {
            break;
        }
        // Read varint length
        let (len, len_size) = read_varint(&data[consumed..])?;
        consumed += len_size;
        if consumed + len as usize > data.len() {
            return Err(SphinxError::InvalidPayload(
                "TLV value out of bounds".into(),
            ));
        }
        let value = &data[consumed..consumed + len as usize];
        consumed += len as usize;

        match tlv_type {
            2 if value.len() <= 8 => {
                amt = be_uint(value)?;
            }
            4 if value.len() <= 4 => {
                cltv = be_uint(value)? as u32;
            }
            6 if value.len() <= 8 => {
                scid = be_uint(value)?;
            }
            _ => {} // unknown TLV types are ignored
        }
    }

    Ok((scid, amt, cltv, consumed))
}

fn be_uint(value: &[u8]) -> Result<u64, SphinxError> {
    if value.is_empty() || value.len() > 8 {
        return Err(SphinxError::InvalidPayload("invalid integer length".into()));
    }
    let mut bytes = [0u8; 8];
    bytes[8 - value.len()..].copy_from_slice(value);
    Ok(u64::from_be_bytes(bytes))
}

/// Read a BigSize varint (like Lightning's varint encoding).
fn read_varint(data: &[u8]) -> Result<(u64, usize), SphinxError> {
    if data.is_empty() {
        return Err(SphinxError::InvalidPayload("empty varint".into()));
    }
    match data[0] {
        0xFD => {
            if data.len() < 3 {
                return Err(SphinxError::InvalidPayload("short varint".into()));
            }
            Ok((u16::from_be_bytes([data[1], data[2]]) as u64, 3))
        }
        0xFE => {
            if data.len() < 5 {
                return Err(SphinxError::InvalidPayload("short varint".into()));
            }
            let bytes: [u8; 4] = data[1..5].try_into().unwrap();
            Ok((u32::from_be_bytes(bytes) as u64, 5))
        }
        0xFF => {
            if data.len() < 9 {
                return Err(SphinxError::InvalidPayload("short varint".into()));
            }
            let bytes: [u8; 8] = data[1..9].try_into().unwrap();
            Ok((u64::from_be_bytes(bytes), 9))
        }
        v => Ok((v as u64, 1)),
    }
}

/// Peel an onion packet, extracting the next hop's routing info.
///
/// The onion packet is 1366 bytes:
/// - 1 byte version (0x00)
/// - 33 bytes ephemeral public key
/// - 1300 bytes hop data
/// - 32 bytes HMAC
pub fn peel_onion(node_privkey: &SecretKey, onion: &[u8]) -> Result<PeeledOnion, SphinxError> {
    if onion.len() != ONION_PACKET_SIZE {
        return Err(SphinxError::InvalidSize(onion.len()));
    }

    let version = onion[0];
    if version != 0x00 {
        return Err(SphinxError::UnsupportedVersion(version));
    }

    let ephemeral_pubkey =
        PublicKey::from_slice(&onion[1..34]).map_err(|_| SphinxError::InvalidEphemeralKey)?;

    let mut hop_data = [0u8; ONION_ROUTING_INFO_SIZE];
    hop_data.copy_from_slice(&onion[34..34 + ONION_ROUTING_INFO_SIZE]);

    let hmac_in_packet = &onion[34 + ONION_ROUTING_INFO_SIZE..34 + ONION_ROUTING_INFO_SIZE + 32];

    // ECDH to get shared secret
    let shared_secret = ecdh(node_privkey, &ephemeral_pubkey)?;

    // Derive keys
    let (rho, mu, _um) = derive_keys(&shared_secret);

    // Verify HMAC
    let computed_hmac = hmac_sha256(&mu, &hop_data);
    if computed_hmac != hmac_in_packet {
        return Err(SphinxError::HmacFailed);
    }

    // Decrypt hop data using ChaCha20 stream
    let stream = chacha20_stream(&rho, ONION_ROUTING_INFO_SIZE);
    xor_in_place(&mut hop_data, &stream);

    // Parse the first hop payload (TLV format)
    let first_hop = &hop_data[..ONION_HOP_SIZE];
    let (scid, amt, cltv, _payload_len) = parse_tlv_payload(first_hop)?;

    // Shift hop data: remove first hop, pad with zeros at the end
    let mut next_hop_data = [0u8; ONION_ROUTING_INFO_SIZE];
    next_hop_data[..ONION_ROUTING_INFO_SIZE - ONION_HOP_SIZE]
        .copy_from_slice(&hop_data[ONION_HOP_SIZE..]);

    // Blind the ephemeral key
    let blinding = blinding_factor(&ephemeral_pubkey, &shared_secret);
    let next_ephemeral = blind_pubkey(&ephemeral_pubkey, &blinding)?;

    // Compute HMAC for the next hop
    // The next hop's HMAC is the HMAC of the next hop data with the next hop's mu key.
    // But we don't have the next hop's shared secret. The HMAC for the next hop
    // was already embedded in the hop data during onion construction.
    // The last 32 bytes of the hop_data (after shifting) is the HMAC for the next hop.
    let next_hmac = &next_hop_data[ONION_ROUTING_INFO_SIZE - 32..];

    // Build the next onion packet
    let mut next_onion = Vec::with_capacity(ONION_PACKET_SIZE);
    next_onion.push(version);
    next_onion.extend_from_slice(&next_ephemeral.serialize());
    next_onion.extend_from_slice(&next_hop_data);
    next_onion.extend_from_slice(next_hmac);

    Ok(PeeledOnion {
        short_channel_id: scid,
        amt_to_forward: amt,
        outgoing_cltv_value: cltv,
        next_onion,
        shared_secret,
    })
}

/// Wrap a failure message into a failure onion for the sender.
///
/// The failure onion is encrypted with the `um` key derived from the shared
/// secret, so that only the originating hop can decrypt it as it's unwrapped
/// back through the route.
pub fn wrap_failure(shared_secret: &[u8; 32], failure_message: &[u8]) -> Vec<u8> {
    let (_rho, _mu, um) = derive_keys(shared_secret);

    // Pad the failure message to 256 bytes total
    let mut padded = Vec::with_capacity(256);
    // 2-byte length prefix
    let len = failure_message.len() as u16;
    padded.extend_from_slice(&len.to_be_bytes());
    padded.extend_from_slice(failure_message);
    padded.resize(256, 0);

    // Encrypt with ChaCha20 using um key
    let stream = chacha20_stream(&um, 256);
    xor_in_place(&mut padded, &stream);

    padded
}

/// Build a single-hop final onion packet for a direct hosted payment.
pub fn create_single_hop_onion(
    recipient_pubkey: &PublicKey,
    amount_msat: u64,
    cltv_expiry: u32,
    payment_secret: Option<[u8; 32]>,
) -> Result<Vec<u8>, SphinxError> {
    create_onion(
        recipient_pubkey,
        amount_msat,
        cltv_expiry,
        0,
        payment_secret,
    )
}

pub fn create_relay_onion(
    recipient_pubkey: &PublicKey,
    short_channel_id: u64,
    amount_msat: u64,
    cltv_expiry: u32,
) -> Result<Vec<u8>, SphinxError> {
    create_onion(
        recipient_pubkey,
        amount_msat,
        cltv_expiry,
        short_channel_id,
        None,
    )
}

fn create_onion(
    recipient_pubkey: &PublicKey,
    amount_msat: u64,
    cltv_expiry: u32,
    short_channel_id: u64,
    payment_secret: Option<[u8; 32]>,
) -> Result<Vec<u8>, SphinxError> {
    let secp = secp256k1::Secp256k1::new();
    let (ephemeral_secret, ephemeral_pubkey) = secp.generate_keypair(&mut rand::rngs::OsRng);
    let shared_secret = ecdh(&ephemeral_secret, recipient_pubkey)?;
    let (rho, mu, _) = derive_keys(&shared_secret);

    let mut hop_data = [0u8; ONION_ROUTING_INFO_SIZE];
    let mut final_payload = BytesMut::new();
    write_tlv_u64(&mut final_payload, 2, amount_msat);
    write_tlv_u64(&mut final_payload, 4, cltv_expiry as u64);
    if short_channel_id != 0 {
        write_tlv_u64(&mut final_payload, 6, short_channel_id);
    }
    if let Some(secret) = payment_secret {
        write_bigsize(&mut final_payload, 8);
        write_bigsize(&mut final_payload, 32);
        final_payload.extend_from_slice(&secret);
    }
    let mut payload = BytesMut::new();
    write_bigsize(&mut payload, final_payload.len() as u64);
    payload.extend_from_slice(&final_payload);
    let len = payload.len().min(ONION_HOP_SIZE);
    hop_data[..len].copy_from_slice(&payload[..len]);

    let stream = chacha20_stream(&rho, ONION_ROUTING_INFO_SIZE);
    xor_in_place(&mut hop_data, &stream);
    let hmac = hmac_sha256(&mu, &hop_data);

    let mut onion = Vec::with_capacity(ONION_PACKET_SIZE);
    onion.push(0);
    onion.extend_from_slice(&ephemeral_pubkey.serialize());
    onion.extend_from_slice(&hop_data);
    onion.extend_from_slice(&hmac);
    Ok(onion)
}

fn write_tlv_u64(buf: &mut BytesMut, tlv_type: u64, value: u64) {
    write_bigsize(buf, tlv_type);
    let bytes = value.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let value_bytes = &bytes[first_non_zero..];
    write_bigsize(buf, value_bytes.len() as u64);
    buf.extend_from_slice(value_bytes);
}

fn write_bigsize(buf: &mut BytesMut, value: u64) {
    if value < 0xfd {
        buf.extend_from_slice(&[value as u8]);
    } else if value <= u16::MAX as u64 {
        buf.extend_from_slice(&[0xfd]);
        buf.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        buf.extend_from_slice(&[0xfe]);
        buf.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        buf.extend_from_slice(&[0xff]);
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

/// Create a basic temporary channel failure message (BOLT-4).
pub fn temp_channel_failure(reason: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    // PERM bit = 0, UPDATE bit = 0, CODE = 7 (temporary_channel_failure)
    // channel_update is empty (we don't provide one)
    msg.push(0x00); // realm
    msg.extend_from_slice(reason);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_derivation_is_deterministic() {
        let shared = [0x42u8; 32];
        let (rho1, mu1, um1) = derive_keys(&shared);
        let (rho2, mu2, um2) = derive_keys(&shared);
        assert_eq!(rho1, rho2);
        assert_eq!(mu1, mu2);
        assert_eq!(um1, um2);
    }

    #[test]
    fn chacha20_stream_is_deterministic() {
        let key = [0xAAu8; 32];
        let s1 = chacha20_stream(&key, 100);
        let s2 = chacha20_stream(&key, 100);
        assert_eq!(s1, s2);
    }

    #[test]
    fn xor_in_place_works() {
        let mut a = [0x00, 0xFF, 0xAA];
        let b = [0xFF, 0xFF, 0xFF];
        xor_in_place(&mut a, &b);
        assert_eq!(a, [0xFF, 0x00, 0x55]);
    }

    #[test]
    fn varint_reading() {
        assert_eq!(read_varint(&[0x05]).unwrap(), (5, 1));
        assert_eq!(read_varint(&[0xFD, 0x01, 0x00]).unwrap(), (256, 3));
        let large = [0xFFu8, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(read_varint(&large).unwrap(), (1, 9));
    }

    #[test]
    fn create_single_hop_onion_roundtrip() {
        let secp = secp256k1::Secp256k1::new();
        let (recipient_secret, recipient_public) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let onion =
            create_single_hop_onion(&recipient_public, 123_456, 700_123, Some([3; 32])).unwrap();

        let peeled = peel_onion(&recipient_secret, &onion).unwrap();

        assert_eq!(peeled.short_channel_id, 0);
        assert_eq!(peeled.amt_to_forward, 123_456);
        assert_eq!(peeled.outgoing_cltv_value, 700_123);
    }

    #[test]
    fn blinding_factor_is_deterministic() {
        let secp = secp256k1::Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let shared = [0x42u8; 32];
        let bf1 = blinding_factor(&pk, &shared);
        let bf2 = blinding_factor(&pk, &shared);
        assert_eq!(bf1, bf2);
        // Different pubkey gives different blinding
        let (_, pk2) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let bf3 = blinding_factor(&pk2, &shared);
        assert_ne!(bf1, bf3);
    }

    #[test]
    fn blind_pubkey_is_valid() {
        let secp = secp256k1::Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let shared = [0x42u8; 32];
        let bf = blinding_factor(&pk, &shared);
        let blinded = blind_pubkey(&pk, &bf).unwrap();
        // Blinded key should be different from original
        assert_ne!(blinded.serialize(), pk.serialize());
    }

    #[test]
    fn wrap_failure_produces_256_bytes() {
        let shared = [0x42u8; 32];
        let failure = temp_channel_failure(b"test");
        let wrapped = wrap_failure(&shared, &failure);
        assert_eq!(wrapped.len(), 256);
    }

    #[test]
    fn wrap_failure_is_deterministic() {
        let shared = [0x42u8; 32];
        let failure = temp_channel_failure(b"test");
        let w1 = wrap_failure(&shared, &failure);
        let w2 = wrap_failure(&shared, &failure);
        assert_eq!(w1, w2);
    }

    #[test]
    fn peel_invalid_size() {
        let secp = secp256k1::Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let result = peel_onion(&sk, &[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn peel_unsupported_version() {
        let secp = secp256k1::Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let mut onion = vec![0u8; ONION_PACKET_SIZE];
        onion[0] = 0x01; // unsupported version
        let result = peel_onion(&sk, &onion);
        assert!(matches!(result, Err(SphinxError::UnsupportedVersion(_))));
    }
}
