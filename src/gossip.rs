//! BOLT-7 `channel_update` construction for fake hosted-channel scids.

use bytes::{BufMut, Bytes, BytesMut};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use crate::channel_id::{hosted_short_channel_id, is_node1};
use crate::config::ChannelPolicy;
use crate::wire::{ChannelUpdate, PhcChannelUpdate, TAG_PHC_CHANNEL_UPDATE_SYNC};

/// Build a signed BOLT-7 `channel_update` as a typed [`ChannelUpdate`].
///
/// The signature covers the double-SHA256 of the witness (everything after
/// the signature field, including the TLV stream).
#[allow(clippy::too_many_arguments)]
pub fn build_channel_update(
    node_secret: &SecretKey,
    node_public: &PublicKey,
    peer_id: &PublicKey,
    chain_hash: [u8; 32],
    policy: &ChannelPolicy,
    htlc_maximum_msat: u64,
    enabled: bool,
    timestamp: u32,
) -> ChannelUpdate {
    let scid = hosted_short_channel_id(node_public, peer_id);
    let channel_flags = channel_flags(node_public, peer_id, enabled);

    let cu = ChannelUpdate {
        signature: [0u8; 64],
        chain_hash,
        short_channel_id: scid,
        timestamp,
        message_flags: 0x01,
        channel_flags,
        cltv_expiry_delta: policy.cltv_expiry_delta,
        htlc_minimum_msat: policy.htlc_minimum_msat,
        fee_base_msat: policy.fee_base_msat,
        fee_proportional_millionths: policy.fee_proportional_millionths,
        htlc_maximum_msat,
        tlv_stream: Bytes::new(),
    };

    let witness = cu.witness();
    let first = Sha256::digest(&witness);
    let second = Sha256::digest(first);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&second);

    let secp = Secp256k1::signing_only();
    let msg = Message::from_digest(digest);
    let sig = secp.sign_ecdsa(&msg, node_secret).serialize_compact();

    ChannelUpdate {
        signature: sig,
        ..cu
    }
}

/// Build a standard BOLT-7 `channel_update` message (type tag `258` + body).
#[allow(clippy::too_many_arguments)]
pub fn channel_update(
    node_secret: &SecretKey,
    node_public: &PublicKey,
    peer_id: &PublicKey,
    chain_hash: [u8; 32],
    policy: &ChannelPolicy,
    htlc_maximum_msat: u64,
    enabled: bool,
    timestamp: u32,
) -> Bytes {
    let cu = build_channel_update(
        node_secret,
        node_public,
        peer_id,
        chain_hash,
        policy,
        htlc_maximum_msat,
        enabled,
        timestamp,
    );
    let mut out = BytesMut::with_capacity(2 + 136);
    out.put_u16(258);
    let _ = cu.encode(&mut out);
    out.freeze()
}

/// Build a PHC-wrapped `channel_update` for direct peer sync (tag `64507`).
///
/// cliche/immortan uses `PHC_UPDATE_SYNC_TAG` (64507) for outbound hosted
/// channel updates sent directly to the peer.  The body is identical to the
/// standard BOLT-7 `channel_update` body (without the `258` type prefix).
#[allow(clippy::too_many_arguments)]
pub fn phc_channel_update_sync(
    node_secret: &SecretKey,
    node_public: &PublicKey,
    peer_id: &PublicKey,
    chain_hash: [u8; 32],
    policy: &ChannelPolicy,
    htlc_maximum_msat: u64,
    enabled: bool,
    timestamp: u32,
) -> PhcChannelUpdate {
    let body = build_channel_update(
        node_secret,
        node_public,
        peer_id,
        chain_hash,
        policy,
        htlc_maximum_msat,
        enabled,
        timestamp,
    );
    PhcChannelUpdate {
        tag: TAG_PHC_CHANNEL_UPDATE_SYNC,
        body,
    }
}

pub fn channel_flags(node_public: &PublicKey, peer_id: &PublicKey, enabled: bool) -> u8 {
    let direction = if is_node1(node_public, peer_id) { 0 } else { 1 };
    let disabled = if enabled { 0 } else { 1 << 1 };
    direction | disabled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_update_has_expected_size_and_type() {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let (_, peer) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let policy = ChannelPolicy::default();
        let bytes = channel_update(
            &sk,
            &pk,
            &peer,
            [1; 32],
            &policy,
            policy.channel_capacity_msat,
            true,
            1_700_000_000,
        );
        assert_eq!(bytes.len(), 138);
        assert_eq!(&bytes[..2], &[0x01, 0x02]);
    }

    #[test]
    fn phc_channel_update_sync_uses_tag_64507() {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let (_, peer) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let policy = ChannelPolicy::default();
        let phc = phc_channel_update_sync(
            &sk,
            &pk,
            &peer,
            [1; 32],
            &policy,
            policy.channel_capacity_msat,
            true,
            1_700_000_000,
        );
        assert_eq!(phc.tag, 64507);
        let encoded = crate::wire::HostedMessage::PhcChannelUpdate(phc)
            .encode()
            .unwrap();
        assert_eq!(&encoded[..2], &[0xFB, 0xFB]);
    }

    #[test]
    fn phc_body_matches_bolt_body() {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let (_, peer) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let policy = ChannelPolicy::default();
        let bolt = channel_update(
            &sk,
            &pk,
            &peer,
            [1; 32],
            &policy,
            policy.channel_capacity_msat,
            true,
            42,
        );
        let phc = phc_channel_update_sync(
            &sk,
            &pk,
            &peer,
            [1; 32],
            &policy,
            policy.channel_capacity_msat,
            true,
            42,
        );
        let mut phc_encoded = BytesMut::new();
        phc.body.encode(&mut phc_encoded).unwrap();
        assert_eq!(&bolt[2..], &phc_encoded[..]);
    }

    #[test]
    fn channel_flags_match_node_order_and_enabled() {
        let secp = Secp256k1::new();
        let (_, a) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let (_, b) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let enabled = channel_flags(&a, &b, true);
        let disabled = channel_flags(&a, &b, false);
        assert_eq!(disabled & 0x02, 0x02);
        assert_eq!(enabled & 0x02, 0);
        assert_eq!(channel_flags(&a, &b, true) & 1, (!is_node1(&a, &b)) as u8);
    }
}
