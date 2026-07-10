//! Channel ID and short channel ID derivation for hosted channels.
//!
//! Hosted channels don't have real on-chain funding transactions, so their
//! identifiers are derived deterministically from the two participants' public
//! keys. This matches the scoin reference (`hc/package.scala`):
//!
//! - `channel_id = SHA256(lexicographically-sorted concat of both pubkeys)`
//! - `short_channel_id` = sum of the eight big-endian u64 chunks of the
//!   same 66-byte sorted concat (used as a fake scid in route hints,
//!   htlc_accepted matching, and sendpay labels).

use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

/// The 32-byte hosted channel identifier.
pub fn channel_id(local: &PublicKey, remote: &PublicKey) -> [u8; 32] {
    let (a, b) = sort_keys(local, remote);
    let mut concat = Vec::with_capacity(66);
    concat.extend_from_slice(&a.serialize());
    concat.extend_from_slice(&b.serialize());

    let mut hasher = Sha256::new();
    hasher.update(&concat);
    let hash = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// The fake short channel id used for routing and HTLC matching.
///
/// Computed as the sum of eight big-endian u64 chunks of the 66-byte
/// sorted pubkey concatenation.
pub fn hosted_short_channel_id(local: &PublicKey, remote: &PublicKey) -> u64 {
    let (a, b) = sort_keys(local, remote);
    let mut concat = [0u8; 66];
    concat[..33].copy_from_slice(&a.serialize());
    concat[33..].copy_from_slice(&b.serialize());

    let mut sum: u64 = 0;
    for chunk in concat.chunks_exact(8) {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(chunk);
        sum = sum.wrapping_add(u64::from_be_bytes(arr));
    }
    // Handle the remaining 2 bytes (66 = 8*8 + 2)
    let remaining = &concat[64..];
    let mut arr = [0u8; 8];
    arr[6..].copy_from_slice(remaining);
    sum = sum.wrapping_add(u64::from_be_bytes(arr));

    sum
}

fn sort_keys(a: &PublicKey, b: &PublicKey) -> (PublicKey, PublicKey) {
    let a_bytes = a.serialize();
    let b_bytes = b.serialize();
    if a_bytes <= b_bytes {
        (*a, *b)
    } else {
        (*b, *a)
    }
}

/// Determine whether the local node is "node1" in the BOLT-7 sense
/// (lexicographically smaller pubkey).
pub fn is_node1(local: &PublicKey, remote: &PublicKey) -> bool {
    let local_bytes = local.serialize();
    let remote_bytes = remote.serialize();
    local_bytes <= remote_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;

    fn gen_key(byte: u8) -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    #[test]
    fn channel_id_is_symmetric() {
        let a = gen_key(1);
        let b = gen_key(2);
        assert_eq!(channel_id(&a, &b), channel_id(&b, &a));
    }

    #[test]
    fn scid_is_symmetric() {
        let a = gen_key(1);
        let b = gen_key(2);
        assert_eq!(
            hosted_short_channel_id(&a, &b),
            hosted_short_channel_id(&b, &a)
        );
    }

    #[test]
    fn different_pairs_give_different_ids() {
        let a = gen_key(1);
        let b = gen_key(2);
        let c = gen_key(3);
        assert_ne!(channel_id(&a, &b), channel_id(&a, &c));
    }

    #[test]
    fn is_node1_correct() {
        let a = gen_key(1);
        let b = gen_key(2);
        // The lexicographically smaller key is node1
        let a_is_node1 = is_node1(&a, &b);
        let b_is_node1 = is_node1(&b, &a);
        assert_ne!(a_is_node1, b_is_node1);
    }
}
