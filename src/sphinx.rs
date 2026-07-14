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
//! - 1300 bytes hop payloads
//! - 32 bytes HMAC
//!
//! Total: 1366 bytes

use bytes::BytesMut;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

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
    #[error("unsupported onion payload: {0}")]
    UnsupportedPayload(String),
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

/// Compute the BOLT-4 ECDH shared secret between our private key and a public key.
fn ecdh(privkey: &SecretKey, pubkey: &PublicKey) -> Result<[u8; 32], SphinxError> {
    let secp = Secp256k1::new();
    let scalar =
        Scalar::from_be_bytes(privkey.secret_bytes()).map_err(|_| SphinxError::EcdhFailed)?;
    let point = pubkey
        .mul_tweak(&secp, &scalar)
        .map_err(|_| SphinxError::EcdhFailed)?;
    let digest = Sha256::digest(point.serialize());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (left, right)| acc | (left ^ right))
        == 0
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

#[derive(Debug, Default)]
struct PayloadFields {
    short_channel_id: Option<u64>,
    amt_to_forward: Option<u64>,
    outgoing_cltv_value: Option<u32>,
}

fn parse_tlv_payload(data: &[u8], is_final: bool) -> Result<PayloadFields, SphinxError> {
    let mut fields = PayloadFields::default();
    let mut consumed = 0;
    let mut last_type = None;

    while consumed < data.len() {
        let (tlv_type, type_len) = read_bigsize(&data[consumed..])?;
        if let Some(last) = last_type {
            if tlv_type <= last {
                return Err(SphinxError::InvalidPayload(
                    "TLV types must be strictly increasing".into(),
                ));
            }
        }
        last_type = Some(tlv_type);
        consumed += type_len;
        let (len, len_size) = read_bigsize(&data[consumed..])?;
        consumed += len_size;
        if consumed + len as usize > data.len() {
            return Err(SphinxError::InvalidPayload(
                "TLV value out of bounds".into(),
            ));
        }
        let value = &data[consumed..consumed + len as usize];
        consumed += len as usize;

        match tlv_type {
            2 => {
                fields.amt_to_forward = Some(be_tu(value, 8)?);
            }
            4 => {
                fields.outgoing_cltv_value = Some(be_tu(value, 4)? as u32);
            }
            6 => {
                if value.len() != 8 {
                    return Err(SphinxError::InvalidPayload(
                        "short_channel_id must be 8 bytes".into(),
                    ));
                }
                fields.short_channel_id = Some(u64::from_be_bytes(value.try_into().unwrap()));
            }
            8 | 16 | 18 => {}
            10 | 12 => {
                return Err(SphinxError::UnsupportedPayload(
                    "blinded payment payloads are not supported".into(),
                ));
            }
            _ if tlv_type % 2 == 0 => {
                return Err(SphinxError::InvalidPayload(format!(
                    "unknown even TLV type {tlv_type}"
                )));
            }
            _ => {}
        }
    }

    if fields.amt_to_forward.is_none() {
        return Err(SphinxError::InvalidPayload("missing amt_to_forward".into()));
    }
    if fields.outgoing_cltv_value.is_none() {
        return Err(SphinxError::InvalidPayload(
            "missing outgoing_cltv_value".into(),
        ));
    }
    if !is_final && fields.short_channel_id.is_none() {
        return Err(SphinxError::InvalidPayload(
            "missing short_channel_id for non-final payload".into(),
        ));
    }

    Ok(fields)
}

fn be_tu(value: &[u8], max_len: usize) -> Result<u64, SphinxError> {
    if value.is_empty() || value.len() > max_len || value.len() > 8 {
        return Err(SphinxError::InvalidPayload("invalid integer length".into()));
    }
    if value.len() > 1 && value[0] == 0 {
        return Err(SphinxError::InvalidPayload(
            "non-minimal truncated integer".into(),
        ));
    }
    let mut bytes = [0u8; 8];
    bytes[8 - value.len()..].copy_from_slice(value);
    Ok(u64::from_be_bytes(bytes))
}

fn read_bigsize(data: &[u8]) -> Result<(u64, usize), SphinxError> {
    if data.is_empty() {
        return Err(SphinxError::InvalidPayload("empty varint".into()));
    }
    match data[0] {
        0xFD => {
            if data.len() < 3 {
                return Err(SphinxError::InvalidPayload("short varint".into()));
            }
            let value = u16::from_be_bytes([data[1], data[2]]) as u64;
            if value < 0xfd {
                return Err(SphinxError::InvalidPayload("non-canonical bigsize".into()));
            }
            Ok((value, 3))
        }
        0xFE => {
            if data.len() < 5 {
                return Err(SphinxError::InvalidPayload("short varint".into()));
            }
            let bytes: [u8; 4] = data[1..5].try_into().unwrap();
            let value = u32::from_be_bytes(bytes) as u64;
            if value <= u16::MAX as u64 {
                return Err(SphinxError::InvalidPayload("non-canonical bigsize".into()));
            }
            Ok((value, 5))
        }
        0xFF => {
            if data.len() < 9 {
                return Err(SphinxError::InvalidPayload("short varint".into()));
            }
            let bytes: [u8; 8] = data[1..9].try_into().unwrap();
            let value = u64::from_be_bytes(bytes);
            if value <= u32::MAX as u64 {
                return Err(SphinxError::InvalidPayload("non-canonical bigsize".into()));
            }
            Ok((value, 9))
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
pub fn peel_onion(
    node_privkey: &SecretKey,
    onion: &[u8],
    associated_data: &[u8],
) -> Result<PeeledOnion, SphinxError> {
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

    let mut hmac_data = Vec::with_capacity(ONION_ROUTING_INFO_SIZE + associated_data.len());
    hmac_data.extend_from_slice(&hop_data);
    hmac_data.extend_from_slice(associated_data);
    let computed_hmac = hmac_sha256(&mu, &hmac_data);
    if !constant_time_eq(&computed_hmac, hmac_in_packet) {
        return Err(SphinxError::HmacFailed);
    }

    let mut unwrapped = vec![0u8; ONION_ROUTING_INFO_SIZE * 2];
    unwrapped[..ONION_ROUTING_INFO_SIZE].copy_from_slice(&hop_data);
    let stream = chacha20_stream(&rho, ONION_ROUTING_INFO_SIZE * 2);
    xor_in_place(&mut unwrapped, &stream);

    let (payload_len, len_size) = read_bigsize(&unwrapped)?;
    if payload_len < 2 {
        return Err(SphinxError::InvalidPayload(
            "payload length below minimum".into(),
        ));
    }
    let payload_start = len_size;
    let payload_end = payload_start
        .checked_add(payload_len as usize)
        .ok_or_else(|| SphinxError::InvalidPayload("payload length overflow".into()))?;
    let next_hmac_end = payload_end
        .checked_add(32)
        .ok_or_else(|| SphinxError::InvalidPayload("next hmac overflow".into()))?;
    if next_hmac_end > unwrapped.len() {
        return Err(SphinxError::InvalidPayload(
            "payload exceeds onion routing info".into(),
        ));
    }

    let payload = &unwrapped[payload_start..payload_end];
    let next_hmac = &unwrapped[payload_end..next_hmac_end];
    let remaining = &unwrapped[next_hmac_end..];
    if remaining.len() < ONION_ROUTING_INFO_SIZE {
        return Err(SphinxError::InvalidPayload(
            "not enough forwarding payload".into(),
        ));
    }

    let is_final = next_hmac.iter().all(|b| *b == 0);
    let fields = parse_tlv_payload(payload, is_final)?;
    let next_onion = if is_final {
        Vec::new()
    } else {
        let blinding = blinding_factor(&ephemeral_pubkey, &shared_secret);
        let next_ephemeral = blind_pubkey(&ephemeral_pubkey, &blinding)?;
        let mut next = Vec::with_capacity(ONION_PACKET_SIZE);
        next.push(version);
        next.extend_from_slice(&next_ephemeral.serialize());
        next.extend_from_slice(&remaining[..ONION_ROUTING_INFO_SIZE]);
        next.extend_from_slice(next_hmac);
        next
    };

    Ok(PeeledOnion {
        short_channel_id: fields.short_channel_id.unwrap_or(0),
        amt_to_forward: fields.amt_to_forward.unwrap(),
        outgoing_cltv_value: fields.outgoing_cltv_value.unwrap(),
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
    payment_hash: &[u8; 32],
) -> Result<Vec<u8>, SphinxError> {
    create_onion(
        recipient_pubkey,
        amount_msat,
        cltv_expiry,
        0,
        payment_secret,
        payment_hash,
    )
}

pub fn create_relay_onion(
    recipient_pubkey: &PublicKey,
    next_pubkey: &PublicKey,
    short_channel_id: u64,
    amount_msat: u64,
    cltv_expiry: u32,
    payment_hash: &[u8; 32],
) -> Result<Vec<u8>, SphinxError> {
    let relay_payload = build_payload(amount_msat, cltv_expiry, Some(short_channel_id), None);
    let final_payload = build_payload(amount_msat, cltv_expiry, None, None);
    create_payment_onion(
        &[
            (*recipient_pubkey, relay_payload),
            (*next_pubkey, final_payload),
        ],
        payment_hash,
    )
}

fn create_onion(
    recipient_pubkey: &PublicKey,
    amount_msat: u64,
    cltv_expiry: u32,
    short_channel_id: u64,
    payment_secret: Option<[u8; 32]>,
    associated_data: &[u8],
) -> Result<Vec<u8>, SphinxError> {
    let payload = build_payload(
        amount_msat,
        cltv_expiry,
        (short_channel_id != 0).then_some(short_channel_id),
        payment_secret,
    );
    create_payment_onion(&[(*recipient_pubkey, payload)], associated_data)
}

fn build_payload(
    amount_msat: u64,
    cltv_expiry: u32,
    short_channel_id: Option<u64>,
    payment_secret: Option<[u8; 32]>,
) -> BytesMut {
    let mut final_payload = BytesMut::new();
    write_tlv_u64(&mut final_payload, 2, amount_msat);
    write_tlv_u64(&mut final_payload, 4, cltv_expiry as u64);
    if let Some(short_channel_id) = short_channel_id {
        write_bigsize(&mut final_payload, 6);
        write_bigsize(&mut final_payload, 8);
        final_payload.extend_from_slice(&short_channel_id.to_be_bytes());
    }
    if let Some(secret) = payment_secret {
        write_bigsize(&mut final_payload, 8);
        write_bigsize(&mut final_payload, 40);
        final_payload.extend_from_slice(&secret);
        final_payload.extend_from_slice(&amount_msat.to_be_bytes());
    }

    final_payload
}

fn create_payment_onion(
    hops: &[(PublicKey, BytesMut)],
    associated_data: &[u8],
) -> Result<Vec<u8>, SphinxError> {
    if hops.is_empty() {
        return Err(SphinxError::InvalidPayload("empty route".into()));
    }
    if hops.len() > 2 {
        return Err(SphinxError::UnsupportedPayload(
            "test onion construction supports at most two hops".into(),
        ));
    }

    let secp = Secp256k1::new();
    let (session_secret, first_ephemeral) = secp.generate_keypair(&mut rand::rngs::OsRng);
    let mut ephemeral_secret = session_secret;
    let mut shared_secrets = Vec::with_capacity(hops.len());
    for (pubkey, _) in hops {
        let ephemeral_pubkey = PublicKey::from_secret_key(&secp, &ephemeral_secret);
        let shared_secret = ecdh(&ephemeral_secret, pubkey)?;
        let blinding = blinding_factor(&ephemeral_pubkey, &shared_secret);
        shared_secrets.push(shared_secret);
        let scalar =
            Scalar::from_be_bytes(blinding).map_err(|_| SphinxError::InvalidEphemeralKey)?;
        ephemeral_secret = ephemeral_secret
            .mul_tweak(&scalar)
            .map_err(|_| SphinxError::InvalidEphemeralKey)?;
    }

    let final_filler = if hops.len() == 2 {
        let first_shift = encoded_hop_data_len(hops[0].1.len());
        let (rho, _, _) = derive_keys(&shared_secrets[0]);
        let stream = chacha20_stream(&rho, ONION_ROUTING_INFO_SIZE * 2);
        Some(stream[ONION_ROUTING_INFO_SIZE..ONION_ROUTING_INFO_SIZE + first_shift].to_vec())
    } else {
        None
    };

    let mut hop_payloads = [0u8; ONION_ROUTING_INFO_SIZE];
    let mut next_hmac = [0u8; 32];
    for (idx, ((_, payload), shared_secret)) in
        hops.iter().zip(shared_secrets.iter()).enumerate().rev()
    {
        let mut hop_data = BytesMut::new();
        write_bigsize(&mut hop_data, payload.len() as u64);
        hop_data.extend_from_slice(payload);
        hop_data.extend_from_slice(&next_hmac);
        if hop_data.len() > ONION_ROUTING_INFO_SIZE {
            return Err(SphinxError::InvalidPayload("payload too large".into()));
        }

        let mut shifted = [0u8; ONION_ROUTING_INFO_SIZE];
        shifted[..hop_data.len()].copy_from_slice(&hop_data);
        shifted[hop_data.len()..]
            .copy_from_slice(&hop_payloads[..ONION_ROUTING_INFO_SIZE - hop_data.len()]);

        let (rho, mu, _) = derive_keys(shared_secret);
        let stream = chacha20_stream(&rho, ONION_ROUTING_INFO_SIZE);
        xor_in_place(&mut shifted, &stream);
        if idx == hops.len() - 1 {
            if let Some(filler) = &final_filler {
                if filler.len() > ONION_ROUTING_INFO_SIZE - hop_data.len() {
                    return Err(SphinxError::InvalidPayload("filler too large".into()));
                }
                let start = ONION_ROUTING_INFO_SIZE - filler.len();
                shifted[start..].copy_from_slice(filler);
            }
        }

        let mut hmac_data = Vec::with_capacity(ONION_ROUTING_INFO_SIZE + associated_data.len());
        hmac_data.extend_from_slice(&shifted);
        hmac_data.extend_from_slice(associated_data);
        next_hmac = hmac_sha256(&mu, &hmac_data);
        hop_payloads = shifted;
    }

    let mut onion = Vec::with_capacity(ONION_PACKET_SIZE);
    onion.push(0);
    onion.extend_from_slice(&first_ephemeral.serialize());
    onion.extend_from_slice(&hop_payloads);
    onion.extend_from_slice(&next_hmac);
    Ok(onion)
}

fn encoded_hop_data_len(payload_len: usize) -> usize {
    bigsize_len(payload_len as u64) + payload_len + 32
}

fn bigsize_len(value: u64) -> usize {
    if value < 0xfd {
        1
    } else if value <= u16::MAX as u64 {
        3
    } else if value <= u32::MAX as u64 {
        5
    } else {
        9
    }
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
        assert_eq!(read_bigsize(&[0x05]).unwrap(), (5, 1));
        assert_eq!(read_bigsize(&[0xFD, 0x01, 0x00]).unwrap(), (256, 3));
        let large = [0xFFu8, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(read_bigsize(&large).is_err());
    }

    #[test]
    fn create_single_hop_onion_roundtrip() {
        let secp = secp256k1::Secp256k1::new();
        let (recipient_secret, recipient_public) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let payment_hash = [9u8; 32];
        let onion = create_single_hop_onion(
            &recipient_public,
            123_456,
            700_123,
            Some([3; 32]),
            &payment_hash,
        )
        .unwrap();

        let peeled = peel_onion(&recipient_secret, &onion, &payment_hash).unwrap();

        assert_eq!(peeled.short_channel_id, 0);
        assert_eq!(peeled.amt_to_forward, 123_456);
        assert_eq!(peeled.outgoing_cltv_value, 700_123);
        assert!(peeled.next_onion.is_empty());
    }

    #[test]
    fn associated_data_is_authenticated() {
        let secp = secp256k1::Secp256k1::new();
        let (recipient_secret, recipient_public) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let payment_hash = [1u8; 32];
        let onion =
            create_single_hop_onion(&recipient_public, 50_000, 700_010, None, &payment_hash)
                .unwrap();

        assert!(peel_onion(&recipient_secret, &onion, &payment_hash).is_ok());
        assert!(matches!(
            peel_onion(&recipient_secret, &onion, &[2u8; 32]),
            Err(SphinxError::HmacFailed)
        ));
    }

    #[test]
    fn create_relay_onion_roundtrip_for_two_hops() {
        let secp = secp256k1::Secp256k1::new();
        let (first_secret, first_public) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let (final_secret, final_public) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let payment_hash = [5u8; 32];
        let scid = 123_456_789;
        let onion = create_relay_onion(
            &first_public,
            &final_public,
            scid,
            321_000,
            700_321,
            &payment_hash,
        )
        .unwrap();

        let first = peel_onion(&first_secret, &onion, &payment_hash).unwrap();
        assert_eq!(first.short_channel_id, scid);
        assert_eq!(first.amt_to_forward, 321_000);
        assert_eq!(first.outgoing_cltv_value, 700_321);
        assert_eq!(first.next_onion.len(), ONION_PACKET_SIZE);

        let final_hop = peel_onion(&final_secret, &first.next_onion, &payment_hash).unwrap();
        assert_eq!(final_hop.short_channel_id, 0);
        assert_eq!(final_hop.amt_to_forward, 321_000);
        assert_eq!(final_hop.outgoing_cltv_value, 700_321);
        assert!(final_hop.next_onion.is_empty());
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
        let result = peel_onion(&sk, &[0u8; 100], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn peel_unsupported_version() {
        let secp = secp256k1::Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let mut onion = vec![0u8; ONION_PACKET_SIZE];
        onion[0] = 0x01; // unsupported version
        let result = peel_onion(&sk, &onion, &[0u8; 32]);
        assert!(matches!(result, Err(SphinxError::UnsupportedVersion(_))));
    }
}
