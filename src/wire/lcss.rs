//! Last Cross-Signed State (LCSS) — the core channel state object of bLIP-17.
//!
//! Contains the full signed state, its byte-level encoding for the wire,
//! the `reverse()` operation, and the `hosted_sig_hash` used for signing
//! (matching the scoin reference implementation exactly).

use crate::wire::codecs::{
    self, decode_update_add_htlc_body, encode_update_add_htlc_body, read_bool, read_signature,
    read_u16, read_u32, read_u64, read_varsize, write_bool, write_signature, write_u16, write_u32,
    write_u32_le, write_u64, write_u64_le, write_varsize, DecodeResult,
};
use bytes::{Bytes, BytesMut};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// The parameters offered by the host in `init_hosted_channel`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InitHostedChannel {
    pub max_htlc_value_in_flight_msat: u64,
    pub htlc_minimum_msat: u64,
    pub max_accepted_htlcs: u16,
    pub channel_capacity_msat: u64,
    pub initial_client_balance_msat: u64,
    #[serde(with = "crate::wire::codecs::serde_bytes_hex")]
    pub features: Bytes,
}

impl InitHostedChannel {
    pub fn encode(&self, buf: &mut BytesMut) {
        write_u64(buf, self.max_htlc_value_in_flight_msat);
        write_u64(buf, self.htlc_minimum_msat);
        write_u16(buf, self.max_accepted_htlcs);
        write_u64(buf, self.channel_capacity_msat);
        write_u64(buf, self.initial_client_balance_msat);
        write_varsize(buf, &self.features);
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            max_htlc_value_in_flight_msat: read_u64(buf)?,
            htlc_minimum_msat: read_u64(buf)?,
            max_accepted_htlcs: read_u16(buf)?,
            channel_capacity_msat: read_u64(buf)?,
            initial_client_balance_msat: read_u64(buf)?,
            features: read_varsize(buf)?,
        })
    }
}

/// The full `last_cross_signed_state` message body.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LastCrossSignedState {
    pub is_host: bool,
    #[serde(with = "crate::wire::codecs::serde_bytes_hex")]
    pub last_refund_scriptpubkey: Bytes,
    pub init_hosted_channel: InitHostedChannel,
    pub block_day: u32,
    pub local_balance_msat: u64,
    pub remote_balance_msat: u64,
    pub local_updates: u32,
    pub remote_updates: u32,
    pub incoming_htlcs: Vec<codecs::UpdateAddHtlc>,
    pub outgoing_htlcs: Vec<codecs::UpdateAddHtlc>,
    #[serde(with = "serde_array_hex_64")]
    pub remote_sig_of_local: [u8; 64],
    #[serde(with = "serde_array_hex_64")]
    pub local_sig_of_remote: [u8; 64],
}

mod serde_array_hex_64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl LastCrossSignedState {
    // -- wire encode/decode (the 65531 message body) --

    pub fn encode(&self, buf: &mut BytesMut) {
        write_bool(buf, self.is_host);
        write_varsize(buf, &self.last_refund_scriptpubkey);
        self.init_hosted_channel.encode(buf);
        write_u32(buf, self.block_day);
        write_u64(buf, self.local_balance_msat);
        write_u64(buf, self.remote_balance_msat);
        write_u32(buf, self.local_updates);
        write_u32(buf, self.remote_updates);
        write_u16(buf, self.incoming_htlcs.len() as u16);
        for h in &self.incoming_htlcs {
            encode_update_add_htlc_body(buf, h);
        }
        write_u16(buf, self.outgoing_htlcs.len() as u16);
        for h in &self.outgoing_htlcs {
            encode_update_add_htlc_body(buf, h);
        }
        write_signature(buf, &self.remote_sig_of_local);
        write_signature(buf, &self.local_sig_of_remote);
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        let is_host = read_bool(buf)?;
        let last_refund_scriptpubkey = read_varsize(buf)?;
        let init_hosted_channel = InitHostedChannel::decode(buf)?;
        let block_day = read_u32(buf)?;
        let local_balance_msat = read_u64(buf)?;
        let remote_balance_msat = read_u64(buf)?;
        let local_updates = read_u32(buf)?;
        let remote_updates = read_u32(buf)?;
        let n_in = read_u16(buf)? as usize;
        let mut incoming_htlcs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            incoming_htlcs.push(decode_update_add_htlc_body(buf)?);
        }
        let n_out = read_u16(buf)? as usize;
        let mut outgoing_htlcs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            outgoing_htlcs.push(decode_update_add_htlc_body(buf)?);
        }
        let remote_sig_of_local = read_signature(buf)?;
        let local_sig_of_remote = read_signature(buf)?;
        Ok(Self {
            is_host,
            last_refund_scriptpubkey,
            init_hosted_channel,
            block_day,
            local_balance_msat,
            remote_balance_msat,
            local_updates,
            remote_updates,
            incoming_htlcs,
            outgoing_htlcs,
            remote_sig_of_local,
            local_sig_of_remote,
        })
    }

    /// Total number of updates (local + remote).
    pub fn total_updates(&self) -> u64 {
        self.local_updates as u64 + self.remote_updates as u64
    }

    /// Produce the "reverse" view — how the counterparty sees this state.
    pub fn reverse(&self) -> Self {
        Self {
            is_host: !self.is_host,
            last_refund_scriptpubkey: self.last_refund_scriptpubkey.clone(),
            init_hosted_channel: self.init_hosted_channel.clone(),
            block_day: self.block_day,
            local_balance_msat: self.remote_balance_msat,
            remote_balance_msat: self.local_balance_msat,
            local_updates: self.remote_updates,
            remote_updates: self.local_updates,
            incoming_htlcs: self.outgoing_htlcs.clone(),
            outgoing_htlcs: self.incoming_htlcs.clone(),
            remote_sig_of_local: self.local_sig_of_remote,
            local_sig_of_remote: self.remote_sig_of_local,
        }
    }

    // -- sighash (matches scoin HostedChannelMessages.hostedSigHash) --

    /// Compute the deterministic hash that is signed for this state.
    ///
    /// The material is the concatenation of:
    ///   refund_scriptpubkey
    ///   channel_capacity_msat      (u64 LE)
    ///   initial_client_balance_msat (u64 LE)
    ///   block_day                   (u32 LE)
    ///   local_balance_msat          (u64 LE)
    ///   remote_balance_msat         (u64 LE)
    ///   local_updates               (u32 LE)
    ///   remote_updates              (u32 LE)
    ///   concat(incoming_htlcs encoded as update_add_htlc bodies)
    ///   concat(outgoing_htlcs encoded as update_add_htlc bodies)
    ///   1 byte hostFlag (1 if is_host else 0)
    pub fn hosted_sig_hash(&self) -> [u8; 32] {
        let mut buf = BytesMut::with_capacity(256);
        // refund_scriptpubkey — raw bytes, no length prefix
        codecs::write_bytes(&mut buf, &self.last_refund_scriptpubkey);
        // numeric fields, little-endian
        write_u64_le(&mut buf, self.init_hosted_channel.channel_capacity_msat);
        write_u64_le(
            &mut buf,
            self.init_hosted_channel.initial_client_balance_msat,
        );
        write_u32_le(&mut buf, self.block_day);
        write_u64_le(&mut buf, self.local_balance_msat);
        write_u64_le(&mut buf, self.remote_balance_msat);
        write_u32_le(&mut buf, self.local_updates);
        write_u32_le(&mut buf, self.remote_updates);
        // HTLC lists — full update_add_htlc bodies (BE wire encoding)
        for h in &self.incoming_htlcs {
            encode_update_add_htlc_body(&mut buf, h);
        }
        for h in &self.outgoing_htlcs {
            encode_update_add_htlc_body(&mut buf, h);
        }
        // hostFlag
        codecs::write_u8(&mut buf, if self.is_host { 1 } else { 0 });

        let mut hasher = Sha256::new();
        hasher.update(&buf);
        let hash = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    // -- signing & verification --

    /// Sign the **reverse** of this state (the peer's view) with `priv_key`,
    /// storing the result in `local_sig_of_remote`.
    pub fn sign(&mut self, priv_key: &SecretKey) {
        let reverse_hash = self.reverse().hosted_sig_hash();
        let secp = Secp256k1::signing_only();
        let msg = Message::from_digest(reverse_hash);
        let sig = secp.sign_ecdsa(&msg, priv_key);
        self.local_sig_of_remote = sig.serialize_compact();
    }

    /// Verify that `remote_sig_of_local` is a valid signature over *our* view
    /// (i.e. the hash of this state as-is) by the given public key.
    pub fn verify_remote_sig(&self, pub_key: &PublicKey) -> bool {
        let hash = self.hosted_sig_hash();
        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest(hash);
        let sig = match secp256k1::ecdsa::Signature::from_compact(&self.remote_sig_of_local) {
            Ok(s) => s,
            Err(_) => return false,
        };
        secp.verify_ecdsa(&msg, &sig, pub_key).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_lcss() -> LastCrossSignedState {
        LastCrossSignedState {
            is_host: true,
            last_refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14, 0x01]),
            init_hosted_channel: InitHostedChannel {
                max_htlc_value_in_flight_msat: 1_000_000_000,
                htlc_minimum_msat: 1_000,
                max_accepted_htlcs: 12,
                channel_capacity_msat: 100_000_000,
                initial_client_balance_msat: 10_000_000,
                features: Bytes::new(),
            },
            block_day: 600_000,
            local_balance_msat: 90_000_000,
            remote_balance_msat: 10_000_000,
            local_updates: 5,
            remote_updates: 3,
            incoming_htlcs: vec![],
            outgoing_htlcs: vec![],
            remote_sig_of_local: [0xAA; 64],
            local_sig_of_remote: [0xBB; 64],
        }
    }

    #[test]
    fn lcss_roundtrip() {
        let lcss = dummy_lcss();
        let mut buf = BytesMut::new();
        lcss.encode(&mut buf);
        let mut slice: &[u8] = &buf;
        let decoded = LastCrossSignedState::decode(&mut slice).unwrap();
        assert_eq!(decoded, lcss);
        assert!(slice.is_empty());
    }

    #[test]
    fn reverse_is_involution() {
        let lcss = dummy_lcss();
        let reversed = lcss.reverse();
        let back = reversed.reverse();
        // reverse twice restores everything except the sig swap is symmetric
        assert_eq!(back.is_host, lcss.is_host);
        assert_eq!(back.local_balance_msat, lcss.local_balance_msat);
        assert_eq!(back.remote_balance_msat, lcss.remote_balance_msat);
        assert_eq!(back.local_updates, lcss.local_updates);
        assert_eq!(back.incoming_htlcs, lcss.incoming_htlcs);
        // double-reverse of sigs: remote_sig_of_local goes to local_sig_of_remote and back
        assert_eq!(back.remote_sig_of_local, lcss.remote_sig_of_local);
        assert_eq!(back.local_sig_of_remote, lcss.local_sig_of_remote);
    }

    #[test]
    fn reverse_swaps_fields() {
        let lcss = dummy_lcss();
        let r = lcss.reverse();
        assert!(!r.is_host);
        assert_eq!(r.local_balance_msat, lcss.remote_balance_msat);
        assert_eq!(r.remote_balance_msat, lcss.local_balance_msat);
        assert_eq!(r.local_updates, lcss.remote_updates);
        assert_eq!(r.remote_updates, lcss.local_updates);
        assert_eq!(r.incoming_htlcs, lcss.outgoing_htlcs);
        assert_eq!(r.outgoing_htlcs, lcss.incoming_htlcs);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let secp = Secp256k1::new();
        let (secret, public) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let mut lcss = dummy_lcss();
        lcss.sign(&secret);
        // sign() produces local_sig_of_remote (sig over the reverse/peer view).
        // verify_remote_sig() checks remote_sig_of_local (sig over our view).
        // The peer's sig over their view = our sig over the reverse.
        // So copy local_sig_of_remote → remote_sig_of_local for verification.
        lcss.remote_sig_of_local = lcss.local_sig_of_remote;
        // But verify checks against OUR view's hash, and the sig was over the REVERSE.
        // So we need to verify on the reversed state.
        let reversed = lcss.reverse();
        assert!(
            reversed.verify_remote_sig(&public),
            "verify_remote_sig should succeed after sign"
        );

        // Tamper: flip is_host, should fail
        let mut tampered = reversed.clone();
        tampered.is_host = !tampered.is_host;
        assert!(
            !tampered.verify_remote_sig(&public),
            "verify should fail after tampering"
        );
    }

    #[test]
    fn cross_sign_consistency() {
        // Host signs reverse of its view → local_sig_of_remote.
        // Client receives it, reverses, and the host's sig should verify
        // as the client's remote_sig_of_local.
        let secp = Secp256k1::new();
        let (host_secret, host_public) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let mut host_view = dummy_lcss();
        host_view.sign(&host_secret);

        // Client's view is the reverse of host's view
        let mut client_view = host_view.reverse();
        // The host's local_sig_of_remote becomes the client's remote_sig_of_local
        client_view.remote_sig_of_local = host_view.local_sig_of_remote;
        assert!(
            client_view.verify_remote_sig(&host_public),
            "client should verify host's signature on client's view"
        );
    }

    #[test]
    fn sighash_deterministic() {
        let lcss = dummy_lcss();
        let h1 = lcss.hosted_sig_hash();
        let h2 = lcss.hosted_sig_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn sighash_changes_with_balance() {
        let lcss = dummy_lcss();
        let h1 = lcss.hosted_sig_hash();
        let mut lcss2 = lcss.clone();
        lcss2.local_balance_msat += 1;
        let h2 = lcss2.hosted_sig_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn sighash_changes_with_host_flag() {
        let lcss = dummy_lcss();
        let h1 = lcss.hosted_sig_hash();
        let mut lcss2 = lcss.clone();
        lcss2.is_host = !lcss2.is_host;
        let h2 = lcss2.hosted_sig_hash();
        assert_ne!(h1, h2);
    }
}
