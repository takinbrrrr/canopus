//! bLIP-17 hosted channel wire messages.
//!
//! Each message type uses a `u16` tag picked from the end of the available
//! range. The HTLC update messages reuse the BOLT-2 bodies but with different
//! type numbers so they don't collide with the standard protocol.

pub mod codecs;
pub mod lcss;

use self::codecs::{
    read_32, read_signature, read_u32, read_u64, read_varsize, write_32, write_signature,
    write_u32, write_u64, write_varsize, DecodeError, DecodeResult, UpdateAddHtlc,
};
use bytes::{Bytes, BytesMut};

// Message type tags (from bLIP-17)
pub const TAG_INVOKE_HOSTED_CHANNEL: u16 = 65535;
pub const TAG_INIT_HOSTED_CHANNEL: u16 = 65533;
pub const TAG_LAST_CROSS_SIGNED_STATE: u16 = 65531;
pub const TAG_STATE_UPDATE: u16 = 65529;
pub const TAG_STATE_OVERRIDE: u16 = 65527;
pub const TAG_HOSTED_CHANNEL_BRANDING: u16 = 65525;
pub const TAG_RESIZE_CHANNEL: u16 = 65521;
pub const TAG_QUERY_PREIMAGES: u16 = 65515;
pub const TAG_REPLY_PREIMAGES: u16 = 65513;
pub const TAG_ASK_BRANDING_INFO: u16 = 65511;
pub const TAG_UPDATE_ADD_HTLC: u16 = 63505;
pub const TAG_UPDATE_FULFILL_HTLC: u16 = 63503;
pub const TAG_UPDATE_FAIL_HTLC: u16 = 63501;
pub const TAG_UPDATE_FAIL_MALFORMED_HTLC: u16 = 63499;
pub const TAG_ERROR: u16 = 63497;

/// All HC message types.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedMessage {
    InvokeHostedChannel(InvokeHostedChannel),
    InitHostedChannel(lcss::InitHostedChannel),
    LastCrossSignedState(lcss::LastCrossSignedState),
    StateUpdate(StateUpdate),
    StateOverride(StateOverride),
    HostedChannelBranding(HostedChannelBranding),
    ResizeChannel(ResizeChannel),
    QueryPreimages(QueryPreimages),
    ReplyPreimages(ReplyPreimages),
    AskBrandingInfo(AskBrandingInfo),
    UpdateAddHtlc(UpdateAddHtlc),
    UpdateFulfillHtlc(UpdateFulfillHtlc),
    UpdateFailHtlc(UpdateFailHtlc),
    UpdateFailMalformedHtlc(UpdateFailMalformedHtlc),
    Error(HcError),
}

impl HostedMessage {
    pub fn tag(&self) -> u16 {
        match self {
            HostedMessage::InvokeHostedChannel(_) => TAG_INVOKE_HOSTED_CHANNEL,
            HostedMessage::InitHostedChannel(_) => TAG_INIT_HOSTED_CHANNEL,
            HostedMessage::LastCrossSignedState(_) => TAG_LAST_CROSS_SIGNED_STATE,
            HostedMessage::StateUpdate(_) => TAG_STATE_UPDATE,
            HostedMessage::StateOverride(_) => TAG_STATE_OVERRIDE,
            HostedMessage::HostedChannelBranding(_) => TAG_HOSTED_CHANNEL_BRANDING,
            HostedMessage::ResizeChannel(_) => TAG_RESIZE_CHANNEL,
            HostedMessage::QueryPreimages(_) => TAG_QUERY_PREIMAGES,
            HostedMessage::ReplyPreimages(_) => TAG_REPLY_PREIMAGES,
            HostedMessage::AskBrandingInfo(_) => TAG_ASK_BRANDING_INFO,
            HostedMessage::UpdateAddHtlc(_) => TAG_UPDATE_ADD_HTLC,
            HostedMessage::UpdateFulfillHtlc(_) => TAG_UPDATE_FULFILL_HTLC,
            HostedMessage::UpdateFailHtlc(_) => TAG_UPDATE_FAIL_HTLC,
            HostedMessage::UpdateFailMalformedHtlc(_) => TAG_UPDATE_FAIL_MALFORMED_HTLC,
            HostedMessage::Error(_) => TAG_ERROR,
        }
    }

    /// Encode to raw bytes: `u16 tag` + body.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        codecs::write_u16(&mut buf, self.tag());
        match self {
            HostedMessage::InvokeHostedChannel(m) => m.encode(&mut buf),
            HostedMessage::InitHostedChannel(m) => m.encode(&mut buf),
            HostedMessage::LastCrossSignedState(m) => m.encode(&mut buf),
            HostedMessage::StateUpdate(m) => m.encode(&mut buf),
            HostedMessage::StateOverride(m) => m.encode(&mut buf),
            HostedMessage::HostedChannelBranding(m) => m.encode(&mut buf),
            HostedMessage::ResizeChannel(m) => m.encode(&mut buf),
            HostedMessage::QueryPreimages(m) => m.encode(&mut buf),
            HostedMessage::ReplyPreimages(m) => m.encode(&mut buf),
            HostedMessage::AskBrandingInfo(m) => m.encode(&mut buf),
            HostedMessage::UpdateAddHtlc(m) => m.encode(&mut buf),
            HostedMessage::UpdateFulfillHtlc(m) => m.encode(&mut buf),
            HostedMessage::UpdateFailHtlc(m) => m.encode(&mut buf),
            HostedMessage::UpdateFailMalformedHtlc(m) => m.encode(&mut buf),
            HostedMessage::Error(m) => m.encode(&mut buf),
        }
        buf.freeze()
    }

    /// Decode from raw bytes (without the tag — caller reads tag first,
    /// or use [`decode_with_tag`]).
    pub fn decode_with_tag(tag: u16, buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(match tag {
            TAG_INVOKE_HOSTED_CHANNEL => {
                HostedMessage::InvokeHostedChannel(InvokeHostedChannel::decode(buf)?)
            }
            TAG_INIT_HOSTED_CHANNEL => {
                HostedMessage::InitHostedChannel(lcss::InitHostedChannel::decode(buf)?)
            }
            TAG_LAST_CROSS_SIGNED_STATE => {
                HostedMessage::LastCrossSignedState(lcss::LastCrossSignedState::decode(buf)?)
            }
            TAG_STATE_UPDATE => HostedMessage::StateUpdate(StateUpdate::decode(buf)?),
            TAG_STATE_OVERRIDE => HostedMessage::StateOverride(StateOverride::decode(buf)?),
            TAG_HOSTED_CHANNEL_BRANDING => {
                HostedMessage::HostedChannelBranding(HostedChannelBranding::decode(buf)?)
            }
            TAG_RESIZE_CHANNEL => HostedMessage::ResizeChannel(ResizeChannel::decode(buf)?),
            TAG_QUERY_PREIMAGES => HostedMessage::QueryPreimages(QueryPreimages::decode(buf)?),
            TAG_REPLY_PREIMAGES => HostedMessage::ReplyPreimages(ReplyPreimages::decode(buf)?),
            TAG_ASK_BRANDING_INFO => HostedMessage::AskBrandingInfo(AskBrandingInfo::decode(buf)?),
            TAG_UPDATE_ADD_HTLC => HostedMessage::UpdateAddHtlc(UpdateAddHtlc::decode_body(buf)?),
            TAG_UPDATE_FULFILL_HTLC => {
                HostedMessage::UpdateFulfillHtlc(UpdateFulfillHtlc::decode_body(buf)?)
            }
            TAG_UPDATE_FAIL_HTLC => {
                HostedMessage::UpdateFailHtlc(UpdateFailHtlc::decode_body(buf)?)
            }
            TAG_UPDATE_FAIL_MALFORMED_HTLC => {
                HostedMessage::UpdateFailMalformedHtlc(UpdateFailMalformedHtlc::decode_body(buf)?)
            }
            TAG_ERROR => HostedMessage::Error(HcError::decode(buf)?),
            _ => return Err(DecodeError::Invalid(format!("unknown tag {}", tag))),
        })
    }

    /// Decode from raw bytes that include the leading `u16 tag`.
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut buf: &[u8] = data;
        let tag = codecs::read_u16(&mut buf)?;
        Self::decode_with_tag(tag, &mut buf)
    }

    /// Decode standard bLIP-17 framing or the legacy `tag || len || body` framing.
    pub fn decode_legacy_aware(data: &[u8]) -> DecodeResult<Self> {
        match Self::decode_strict(data) {
            Ok(msg) => Ok(msg),
            Err(standard_err) => Self::decode_legacy(data).map_err(|_| standard_err),
        }
    }

    fn decode_strict(data: &[u8]) -> DecodeResult<Self> {
        let mut buf: &[u8] = data;
        let tag = codecs::read_u16(&mut buf)?;
        let msg = Self::decode_with_tag(tag, &mut buf)?;
        if !buf.is_empty() {
            return Err(DecodeError::Invalid(format!(
                "{} trailing bytes after message",
                buf.len()
            )));
        }
        Ok(msg)
    }

    fn decode_legacy(data: &[u8]) -> DecodeResult<Self> {
        let mut buf: &[u8] = data;
        let tag = codecs::read_u16(&mut buf)?;
        let len = codecs::read_u16(&mut buf)? as usize;
        if buf.len() != len {
            return Err(DecodeError::Invalid("legacy frame length mismatch".into()));
        }
        let msg = Self::decode_with_tag(tag, &mut buf)?;
        if !buf.is_empty() {
            return Err(DecodeError::Invalid(format!(
                "{} trailing bytes after legacy message",
                buf.len()
            )));
        }
        Ok(msg)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPreimages {
    pub hashes: Vec<[u8; 32]>,
}

impl QueryPreimages {
    pub fn encode(&self, buf: &mut BytesMut) {
        codecs::write_u16(buf, self.hashes.len() as u16);
        for hash in &self.hashes {
            write_32(buf, hash);
        }
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        let count = codecs::read_u16(buf)? as usize;
        let mut hashes = Vec::with_capacity(count);
        for _ in 0..count {
            hashes.push(read_32(buf)?);
        }
        Ok(Self { hashes })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyPreimages {
    pub preimages: Vec<[u8; 32]>,
}

impl ReplyPreimages {
    pub fn encode(&self, buf: &mut BytesMut) {
        codecs::write_u16(buf, self.preimages.len() as u16);
        for preimage in &self.preimages {
            write_32(buf, preimage);
        }
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        let count = codecs::read_u16(buf)? as usize;
        let mut preimages = Vec::with_capacity(count);
        for _ in 0..count {
            preimages.push(read_32(buf)?);
        }
        Ok(Self { preimages })
    }
}

// ---------------------------------------------------------------------------
// Individual messages
// ---------------------------------------------------------------------------

/// `invoke_hosted_channel` (65535)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeHostedChannel {
    pub chain_hash: [u8; 32],
    pub refund_scriptpubkey: Bytes,
    pub secret: Bytes,
}

impl InvokeHostedChannel {
    pub fn encode(&self, buf: &mut BytesMut) {
        codecs::write_32(buf, &self.chain_hash);
        codecs::write_varsize(buf, &self.refund_scriptpubkey);
        codecs::write_varsize(buf, &self.secret);
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            chain_hash: read_32(buf)?,
            refund_scriptpubkey: read_varsize(buf)?,
            secret: read_varsize(buf)?,
        })
    }
}

/// `state_update` (65529)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateUpdate {
    pub block_day: u32,
    pub local_updates: u32,
    pub remote_updates: u32,
    pub local_sig_of_remote: [u8; 64],
}

impl StateUpdate {
    pub fn encode(&self, buf: &mut BytesMut) {
        write_u32(buf, self.block_day);
        write_u32(buf, self.local_updates);
        write_u32(buf, self.remote_updates);
        write_signature(buf, &self.local_sig_of_remote);
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            block_day: read_u32(buf)?,
            local_updates: read_u32(buf)?,
            remote_updates: read_u32(buf)?,
            local_sig_of_remote: read_signature(buf)?,
        })
    }
}

/// `state_override` (65527) — includes local_balance, matching scoin's StateOverride.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateOverride {
    pub block_day: u32,
    pub local_balance_msat: u64,
    pub local_updates: u32,
    pub remote_updates: u32,
    pub local_sig_of_remote: [u8; 64],
}

impl StateOverride {
    pub fn encode(&self, buf: &mut BytesMut) {
        write_u32(buf, self.block_day);
        write_u64(buf, self.local_balance_msat);
        write_u32(buf, self.local_updates);
        write_u32(buf, self.remote_updates);
        write_signature(buf, &self.local_sig_of_remote);
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            block_day: read_u32(buf)?,
            local_balance_msat: read_u64(buf)?,
            local_updates: read_u32(buf)?,
            remote_updates: read_u32(buf)?,
            local_sig_of_remote: read_signature(buf)?,
        })
    }
}

/// `ask_branding_info` (65511)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskBrandingInfo {
    pub chain_hash: [u8; 32],
}

/// Poncho extension `resize_channel` (65521).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResizeChannel {
    pub new_capacity_sat: u64,
    pub client_sig: [u8; 64],
}

impl ResizeChannel {
    pub fn encode(&self, buf: &mut BytesMut) {
        write_u64(buf, self.new_capacity_sat);
        write_signature(buf, &self.client_sig);
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            new_capacity_sat: read_u64(buf)?,
            client_sig: read_signature(buf)?,
        })
    }

    pub fn sig_hash(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut material = BytesMut::with_capacity(8);
        material.extend_from_slice(&self.new_capacity_sat.to_le_bytes());
        sha2::Sha256::digest(&material).into()
    }

    pub fn verify_client_sig(&self, pubkey: &secp256k1::PublicKey) -> bool {
        let secp = secp256k1::Secp256k1::verification_only();
        let Ok(sig) = secp256k1::ecdsa::Signature::from_compact(&self.client_sig) else {
            return false;
        };
        let msg = secp256k1::Message::from_digest(self.sig_hash());
        secp.verify_ecdsa(&msg, &sig, pubkey).is_ok()
    }
}

impl AskBrandingInfo {
    pub fn encode(&self, buf: &mut BytesMut) {
        codecs::write_32(buf, &self.chain_hash);
    }
    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            chain_hash: read_32(buf)?,
        })
    }
}

/// `hosted_channel_branding` (65525)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedChannelBranding {
    pub rgb_color: [u8; 3],
    pub png_icon: Option<Bytes>,
    pub contact_info: Bytes,
}

impl HostedChannelBranding {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.rgb_color);
        match &self.png_icon {
            Some(png) => {
                codecs::write_u8(buf, 1);
                write_varsize(buf, png);
            }
            None => {
                codecs::write_u8(buf, 0);
            }
        }
        write_varsize(buf, &self.contact_info);
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        let mut rgb = [0u8; 3];
        let raw = codecs::read_bytes(buf, 3)?;
        rgb.copy_from_slice(&raw);
        let has_png = codecs::read_u8(buf)? != 0;
        let png_icon = if has_png {
            Some(read_varsize(buf)?)
        } else {
            None
        };
        let contact_info = read_varsize(buf)?;
        Ok(Self {
            rgb_color: rgb,
            png_icon,
            contact_info,
        })
    }
}

/// `update_add_htlc` (63505) — full scoin/BOLT-2 body with 32-byte channel_id.
impl UpdateAddHtlc {
    pub fn encode(&self, buf: &mut BytesMut) {
        codecs::encode_update_add_htlc_body(buf, self);
    }
    pub fn decode_body(buf: &mut &[u8]) -> DecodeResult<Self> {
        codecs::decode_update_add_htlc_body(buf)
    }
}

/// `update_fulfill_htlc` (63503)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFulfillHtlc {
    pub channel_id: [u8; 32],
    pub id: u64,
    pub payment_preimage: [u8; 32],
}

impl UpdateFulfillHtlc {
    pub fn encode(&self, buf: &mut BytesMut) {
        write_32(buf, &self.channel_id);
        write_u64(buf, self.id);
        write_32(buf, &self.payment_preimage);
    }
    pub fn decode_body(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            channel_id: read_32(buf)?,
            id: read_u64(buf)?,
            payment_preimage: read_32(buf)?,
        })
    }
}

/// `update_fail_htlc` (63501)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFailHtlc {
    pub channel_id: [u8; 32],
    pub id: u64,
    pub reason: Bytes,
}

impl UpdateFailHtlc {
    pub fn encode(&self, buf: &mut BytesMut) {
        write_32(buf, &self.channel_id);
        write_u64(buf, self.id);
        write_varsize(buf, &self.reason);
    }
    pub fn decode_body(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            channel_id: read_32(buf)?,
            id: read_u64(buf)?,
            reason: read_varsize(buf)?,
        })
    }
}

/// `update_fail_malformed_htlc` (63499)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFailMalformedHtlc {
    pub channel_id: [u8; 32],
    pub id: u64,
    pub sha256_of_onion: [u8; 32],
    pub failure_code: u16,
}

impl UpdateFailMalformedHtlc {
    pub fn encode(&self, buf: &mut BytesMut) {
        write_32(buf, &self.channel_id);
        write_u64(buf, self.id);
        write_32(buf, &self.sha256_of_onion);
        codecs::write_u16(buf, self.failure_code);
    }
    pub fn decode_body(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            channel_id: read_32(buf)?,
            id: read_u64(buf)?,
            sha256_of_onion: read_32(buf)?,
            failure_code: codecs::read_u16(buf)?,
        })
    }
}

/// `error` (63497) — matches scoin's errorCodec: channelId + varsize data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HcError {
    pub channel_id: [u8; 32],
    pub data: Bytes,
}

impl HcError {
    pub fn encode(&self, buf: &mut BytesMut) {
        codecs::write_32(buf, &self.channel_id);
        codecs::write_varsize(buf, &self.data);
    }
    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            channel_id: read_32(buf)?,
            data: read_varsize(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoke_roundtrip() {
        let msg = InvokeHostedChannel {
            chain_hash: [0x42; 32],
            refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14, 0x20]),
            secret: Bytes::from_static(b"my-secret"),
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        let mut slice = &buf[..];
        let dec = InvokeHostedChannel::decode(&mut slice).unwrap();
        assert_eq!(dec, msg);
        assert!(slice.is_empty());
    }

    #[test]
    fn legacy_framed_invoke_decodes() {
        let msg = HostedMessage::InvokeHostedChannel(InvokeHostedChannel {
            chain_hash: [1u8; 32],
            refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14]),
            secret: Bytes::from_static(b"secret"),
        });
        let encoded = msg.encode();
        let body_len = encoded.len() - 2;
        let mut legacy = BytesMut::new();
        codecs::write_u16(&mut legacy, msg.tag());
        codecs::write_u16(&mut legacy, body_len as u16);
        legacy.extend_from_slice(&encoded[2..]);

        let decoded = HostedMessage::decode_legacy_aware(&legacy).unwrap();

        assert_eq!(msg, decoded);
    }

    #[test]
    fn strict_decode_rejects_trailing_bytes() {
        let msg = HostedMessage::AskBrandingInfo(AskBrandingInfo {
            chain_hash: [0; 32],
        });
        let mut encoded = msg.encode().to_vec();
        encoded.push(0);

        assert!(HostedMessage::decode_legacy_aware(&encoded).is_err());
    }

    #[test]
    fn state_update_roundtrip() {
        let msg = StateUpdate {
            block_day: 600_000,
            local_updates: 5,
            remote_updates: 3,
            local_sig_of_remote: [0xAB; 64],
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        let mut slice = &buf[..];
        let dec = StateUpdate::decode(&mut slice).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn state_override_roundtrip() {
        let msg = StateOverride {
            block_day: 600_000,
            local_balance_msat: 50_000_000,
            local_updates: 5,
            remote_updates: 3,
            local_sig_of_remote: [0xAB; 64],
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        let mut slice = &buf[..];
        let dec = StateOverride::decode(&mut slice).unwrap();
        assert_eq!(dec, msg);
        assert!(slice.is_empty());
    }

    #[test]
    fn all_messages_tag_dispatch() {
        let secp = secp256k1::Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let mut lcss = lcss::LastCrossSignedState {
            is_host: true,
            last_refund_scriptpubkey: Bytes::from_static(&[0x00]),
            init_hosted_channel: lcss::InitHostedChannel {
                max_htlc_value_in_flight_msat: 1_000_000_000,
                htlc_minimum_msat: 1_000,
                max_accepted_htlcs: 12,
                channel_capacity_msat: 100_000_000,
                initial_client_balance_msat: 0,
                features: vec![],
            },
            block_day: 600_000,
            local_balance_msat: 100_000_000,
            remote_balance_msat: 0,
            local_updates: 0,
            remote_updates: 0,
            incoming_htlcs: vec![],
            outgoing_htlcs: vec![],
            remote_sig_of_local: [0; 64],
            local_sig_of_remote: [0; 64],
        };
        lcss.sign(&sk);

        let messages = vec![
            HostedMessage::InvokeHostedChannel(InvokeHostedChannel {
                chain_hash: [1; 32],
                refund_scriptpubkey: Bytes::new(),
                secret: Bytes::new(),
            }),
            HostedMessage::InitHostedChannel(lcss.init_hosted_channel.clone()),
            HostedMessage::LastCrossSignedState(lcss.clone()),
            HostedMessage::StateUpdate(StateUpdate {
                block_day: 600_000,
                local_updates: 1,
                remote_updates: 0,
                local_sig_of_remote: [0; 64],
            }),
            HostedMessage::StateOverride(StateOverride {
                block_day: 600_000,
                local_balance_msat: 80_000_000,
                local_updates: 1,
                remote_updates: 1,
                local_sig_of_remote: [0; 64],
            }),
            HostedMessage::AskBrandingInfo(AskBrandingInfo {
                chain_hash: [2; 32],
            }),
            HostedMessage::HostedChannelBranding(HostedChannelBranding {
                rgb_color: [0xff, 0x00, 0x00],
                png_icon: Some(Bytes::from_static(&[0x89, 0x50, 0x4e, 0x47])),
                contact_info: Bytes::from_static(b"https://example.com"),
            }),
            HostedMessage::HostedChannelBranding(HostedChannelBranding {
                rgb_color: [0x00, 0xff, 0x00],
                png_icon: None,
                contact_info: Bytes::from_static(b"https://example.org"),
            }),
            HostedMessage::UpdateAddHtlc(UpdateAddHtlc {
                channel_id: [0x42; 32],
                id: 42,
                amount_msat: 1_000_000,
                payment_hash: [3; 32],
                cltv_expiry: 700_000,
                onion_routing_packet: Bytes::from(vec![0; codecs::ONION_ROUTING_PACKET_SIZE]),
            }),
            HostedMessage::UpdateFulfillHtlc(UpdateFulfillHtlc {
                channel_id: [0x42; 32],
                id: 1,
                payment_preimage: [4; 32],
            }),
            HostedMessage::UpdateFailHtlc(UpdateFailHtlc {
                channel_id: [0x42; 32],
                id: 1,
                reason: Bytes::from_static(b"fail"),
            }),
            HostedMessage::UpdateFailMalformedHtlc(UpdateFailMalformedHtlc {
                channel_id: [0x42; 32],
                id: 1,
                sha256_of_onion: [5; 32],
                failure_code: 0x4000,
            }),
            HostedMessage::Error(HcError {
                channel_id: [6; 32],
                data: Bytes::from_static(b"err"),
            }),
        ];

        for msg in &messages {
            let encoded = msg.encode();
            let decoded = HostedMessage::decode(&encoded).unwrap();
            assert_eq!(&decoded, msg, "roundtrip failed for {:?}", msg.tag());
        }
    }

    #[test]
    fn branding_with_and_without_png() {
        let with_png = HostedChannelBranding {
            rgb_color: [1, 2, 3],
            png_icon: Some(Bytes::from_static(&[0x89, 0x50])),
            contact_info: Bytes::from_static(b"https://x.com"),
        };
        let mut buf = BytesMut::new();
        with_png.encode(&mut buf);
        let mut slice = &buf[..];
        let dec = HostedChannelBranding::decode(&mut slice).unwrap();
        assert_eq!(dec, with_png);

        let without_png = HostedChannelBranding {
            rgb_color: [4, 5, 6],
            png_icon: None,
            contact_info: Bytes::from_static(b"https://y.com"),
        };
        buf.clear();
        without_png.encode(&mut buf);
        let mut slice = &buf[..];
        let dec = HostedChannelBranding::decode(&mut slice).unwrap();
        assert_eq!(dec, without_png);
    }
}
