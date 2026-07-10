//! BOLT-7 `channel_update` construction for fake hosted-channel scids.

use bytes::{BufMut, Bytes, BytesMut};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use crate::channel_id::{hosted_short_channel_id, is_node1};
use crate::config::ChannelPolicy;

pub fn channel_update(
    node_secret: &SecretKey,
    node_public: &PublicKey,
    peer_id: &PublicKey,
    chain_hash: [u8; 32],
    policy: &ChannelPolicy,
    enabled: bool,
    timestamp: u32,
) -> Bytes {
    let scid = hosted_short_channel_id(node_public, peer_id);
    let channel_flags = channel_flags(node_public, peer_id, enabled);

    let mut witness = BytesMut::with_capacity(72);
    witness.extend_from_slice(&chain_hash);
    witness.put_u64(scid);
    witness.put_u32(timestamp);
    witness.put_u8(0x01);
    witness.put_u8(channel_flags);
    witness.put_u16(policy.cltv_expiry_delta);
    witness.put_u64(policy.htlc_minimum_msat);
    witness.put_u32(policy.fee_base_msat);
    witness.put_u32(policy.fee_proportional_millionths);
    witness.put_u64(policy.channel_capacity_msat);

    let first = Sha256::digest(&witness);
    let second = Sha256::digest(first);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&second);

    let secp = Secp256k1::signing_only();
    let msg = Message::from_digest(digest);
    let sig = secp.sign_ecdsa(&msg, node_secret).serialize_compact();

    let mut out = BytesMut::with_capacity(2 + 64 + witness.len());
    out.put_u16(258);
    out.extend_from_slice(&sig);
    out.extend_from_slice(&witness);
    out.freeze()
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
        let bytes = channel_update(&sk, &pk, &peer, [1; 32], &policy, true, 1_700_000_000);
        assert_eq!(bytes.len(), 138);
        assert_eq!(&bytes[..2], &[0x01, 0x02]);
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
