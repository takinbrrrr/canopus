//! bLIP-17 hosted channel wire messages.
//!
//! Each message type uses a `u16` tag picked from the end of the available
//! range. The HTLC update messages reuse the BOLT-2 bodies but with different
//! type numbers so they don't collide with the standard protocol.

pub mod codecs;
pub mod lcss;

use self::codecs::{
    read_32, read_bytes, read_signature, read_u16, read_u32, read_u64, read_u64_overflow,
    read_varsize, validate_tlv_stream, write_32, write_signature, write_u16, write_u32, write_u64,
    write_u64_overflow, write_varsize, DecodeError, DecodeResult, EncodeError, EncodeResult,
    UpdateAddHtlc,
};
use bytes::{Bytes, BytesMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireEncoding {
    Strict,
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedHostedMessage {
    pub message: HostedMessage,
    pub encoding: WireEncoding,
}

// Message type tags (from bLIP-17)
pub const TAG_INVOKE_HOSTED_CHANNEL: u16 = 65535;
pub const TAG_INIT_HOSTED_CHANNEL: u16 = 65533;
pub const TAG_LAST_CROSS_SIGNED_STATE: u16 = 65531;
pub const TAG_STATE_UPDATE: u16 = 65529;
pub const TAG_STATE_OVERRIDE: u16 = 65527;
pub const TAG_HOSTED_CHANNEL_BRANDING: u16 = 65525;
pub const TAG_ANNOUNCEMENT_SIGNATURE: u16 = 65523;
pub const TAG_RESIZE_CHANNEL: u16 = 65521;
pub const TAG_QUERY_PUBLIC_HOSTED_CHANNELS: u16 = 65519;
pub const TAG_REPLY_PUBLIC_HOSTED_CHANNELS_END: u16 = 65517;
pub const TAG_QUERY_PREIMAGES: u16 = 65515;
pub const TAG_REPLY_PREIMAGES: u16 = 65513;
pub const TAG_ASK_BRANDING_INFO: u16 = 65511;
pub const TAG_UPDATE_ADD_HTLC: u16 = 63505;
pub const TAG_UPDATE_FULFILL_HTLC: u16 = 63503;
pub const TAG_UPDATE_FAIL_HTLC: u16 = 63501;
pub const TAG_UPDATE_FAIL_MALFORMED_HTLC: u16 = 63499;
pub const TAG_ERROR: u16 = 63497;

// PHC gossip / sync tags (from immortan/scoin)
pub const TAG_PHC_CHANNEL_ANNOUNCEMENT_GOSSIP: u16 = 64513;
pub const TAG_PHC_CHANNEL_ANNOUNCEMENT_SYNC: u16 = 64511;
pub const TAG_PHC_CHANNEL_UPDATE_GOSSIP: u16 = 64509;
pub const TAG_PHC_CHANNEL_UPDATE_SYNC: u16 = 64507;

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
    AnnouncementSignature(AnnouncementSignature),
    ResizeChannel(ResizeChannel),
    QueryPublicHostedChannels(QueryPublicHostedChannels),
    ReplyPublicHostedChannelsEnd(ReplyPublicHostedChannelsEnd),
    QueryPreimages(QueryPreimages),
    ReplyPreimages(ReplyPreimages),
    AskBrandingInfo(AskBrandingInfo),
    UpdateAddHtlc(UpdateAddHtlc),
    UpdateFulfillHtlc(UpdateFulfillHtlc),
    UpdateFailHtlc(UpdateFailHtlc),
    UpdateFailMalformedHtlc(UpdateFailMalformedHtlc),
    Error(HcError),
    /// A PHC-wrapped BOLT-7 `channel_update` (tags 64509 gossip / 64507 sync).
    PhcChannelUpdate(PhcChannelUpdate),
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
            HostedMessage::AnnouncementSignature(_) => TAG_ANNOUNCEMENT_SIGNATURE,
            HostedMessage::ResizeChannel(_) => TAG_RESIZE_CHANNEL,
            HostedMessage::QueryPublicHostedChannels(_) => TAG_QUERY_PUBLIC_HOSTED_CHANNELS,
            HostedMessage::ReplyPublicHostedChannelsEnd(_) => TAG_REPLY_PUBLIC_HOSTED_CHANNELS_END,
            HostedMessage::QueryPreimages(_) => TAG_QUERY_PREIMAGES,
            HostedMessage::ReplyPreimages(_) => TAG_REPLY_PREIMAGES,
            HostedMessage::AskBrandingInfo(_) => TAG_ASK_BRANDING_INFO,
            HostedMessage::UpdateAddHtlc(_) => TAG_UPDATE_ADD_HTLC,
            HostedMessage::UpdateFulfillHtlc(_) => TAG_UPDATE_FULFILL_HTLC,
            HostedMessage::UpdateFailHtlc(_) => TAG_UPDATE_FAIL_HTLC,
            HostedMessage::UpdateFailMalformedHtlc(_) => TAG_UPDATE_FAIL_MALFORMED_HTLC,
            HostedMessage::Error(_) => TAG_ERROR,
            HostedMessage::PhcChannelUpdate(m) => m.tag,
        }
    }

    /// Encode to raw bytes: `u16 tag` + body.
    pub fn encode(&self) -> EncodeResult<Bytes> {
        self.encode_with_encoding(WireEncoding::Strict)
    }

    /// Encode to raw bytes using either strict `tag || body` or legacy
    /// `tag || u16_len || body` framing.
    pub fn encode_with_encoding(&self, encoding: WireEncoding) -> EncodeResult<Bytes> {
        let mut buf = BytesMut::new();
        codecs::write_u16(&mut buf, self.tag());
        match encoding {
            WireEncoding::Strict => self.encode_body(&mut buf)?,
            WireEncoding::Legacy => {
                let mut body = BytesMut::new();
                self.encode_body(&mut body)?;
                write_varsize(&mut buf, &body)?;
            }
        }
        Ok(buf.freeze())
    }

    fn encode_body(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        match self {
            HostedMessage::InvokeHostedChannel(m) => m.encode(buf)?,
            HostedMessage::InitHostedChannel(m) => m.encode(buf)?,
            HostedMessage::LastCrossSignedState(m) => m.encode(buf)?,
            HostedMessage::StateUpdate(m) => m.encode(buf)?,
            HostedMessage::StateOverride(m) => m.encode(buf)?,
            HostedMessage::HostedChannelBranding(m) => m.encode(buf)?,
            HostedMessage::AnnouncementSignature(m) => m.encode(buf)?,
            HostedMessage::ResizeChannel(m) => m.encode(buf)?,
            HostedMessage::QueryPublicHostedChannels(m) => m.encode(buf)?,
            HostedMessage::ReplyPublicHostedChannelsEnd(m) => m.encode(buf)?,
            HostedMessage::QueryPreimages(m) => m.encode(buf)?,
            HostedMessage::ReplyPreimages(m) => m.encode(buf)?,
            HostedMessage::AskBrandingInfo(m) => m.encode(buf)?,
            HostedMessage::UpdateAddHtlc(m) => m.encode(buf)?,
            HostedMessage::UpdateFulfillHtlc(m) => m.encode(buf)?,
            HostedMessage::UpdateFailHtlc(m) => m.encode(buf)?,
            HostedMessage::UpdateFailMalformedHtlc(m) => m.encode(buf)?,
            HostedMessage::Error(m) => m.encode(buf)?,
            HostedMessage::PhcChannelUpdate(m) => m.body.encode(buf)?,
        }
        Ok(())
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
            TAG_ANNOUNCEMENT_SIGNATURE => {
                HostedMessage::AnnouncementSignature(AnnouncementSignature::decode(buf)?)
            }
            TAG_RESIZE_CHANNEL => HostedMessage::ResizeChannel(ResizeChannel::decode(buf)?),
            TAG_QUERY_PUBLIC_HOSTED_CHANNELS => {
                HostedMessage::QueryPublicHostedChannels(QueryPublicHostedChannels::decode(buf)?)
            }
            TAG_REPLY_PUBLIC_HOSTED_CHANNELS_END => HostedMessage::ReplyPublicHostedChannelsEnd(
                ReplyPublicHostedChannelsEnd::decode(buf)?,
            ),
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
            TAG_PHC_CHANNEL_UPDATE_GOSSIP | TAG_PHC_CHANNEL_UPDATE_SYNC => {
                let body = ChannelUpdate::decode(buf)?;
                HostedMessage::PhcChannelUpdate(PhcChannelUpdate { tag, body })
            }
            _ => return Err(DecodeError::Invalid(format!("unknown tag {}", tag))),
        })
    }

    /// Decode from raw bytes that include the leading `u16 tag`.
    /// Checks that no trailing bytes remain after the message body.
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
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

    /// Decode strict `tag || body` framing or legacy `tag || u16_len || body`
    /// framing used by older cliche/immortan hosted-channel messages.
    pub fn decode_legacy_aware(data: &[u8]) -> DecodeResult<DecodedHostedMessage> {
        match Self::decode(data) {
            Ok(message) => Ok(DecodedHostedMessage {
                message,
                encoding: WireEncoding::Strict,
            }),
            Err(strict_err) => Self::decode_legacy(data).map_err(|legacy_err| {
                DecodeError::Invalid(format!(
                    "strict decode failed: {}; legacy decode failed: {}",
                    strict_err, legacy_err
                ))
            }),
        }
    }

    fn decode_legacy(data: &[u8]) -> DecodeResult<DecodedHostedMessage> {
        let mut buf: &[u8] = data;
        let tag = codecs::read_u16(&mut buf)?;
        let body = read_varsize(&mut buf)?;
        if !buf.is_empty() {
            return Err(DecodeError::Invalid(format!(
                "{} trailing bytes after legacy frame",
                buf.len()
            )));
        }
        let mut body_slice: &[u8] = &body;
        let message = Self::decode_with_tag(tag, &mut body_slice)?;
        if !body_slice.is_empty() {
            return Err(DecodeError::Invalid(format!(
                "{} trailing bytes after legacy message",
                body_slice.len()
            )));
        }
        Ok(DecodedHostedMessage {
            message,
            encoding: WireEncoding::Legacy,
        })
    }
}

// ---------------------------------------------------------------------------
// PHC ChannelUpdate (typed BOLT-7 channel_update body)
// ---------------------------------------------------------------------------

/// A typed BOLT-7 `channel_update` matching scoin's `channelUpdateCodec`.
///
/// This is the body carried by both PHC gossip tag `64509` and PHC sync
/// tag `64507`, as well as standard BOLT-7 tag `258` (with the tag prepended).
///
/// ```text
/// [64]  signature (compact ECDSA)
/// [32]  chain_hash
/// [8]   short_channel_id (int64 BE, no overflow check)
/// [4]   timestamp (uint32)
/// [1]   message_flags (constant 0x01)
/// [1]   channel_flags
/// [2]   cltv_expiry_delta (uint16)
/// [8]   htlc_minimum_msat (uint64overflow)
/// [4]   fee_base_msat (uint32)
/// [4]   fee_proportional_millionths (uint32)
/// [8]   htlc_maximum_msat (uint64overflow)
/// [0+]  tlv_stream
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelUpdate {
    pub signature: [u8; 64],
    pub chain_hash: [u8; 32],
    pub short_channel_id: u64,
    pub timestamp: u32,
    pub message_flags: u8,
    pub channel_flags: u8,
    pub cltv_expiry_delta: u16,
    pub htlc_minimum_msat: u64,
    pub fee_base_msat: u32,
    pub fee_proportional_millionths: u32,
    pub htlc_maximum_msat: u64,
    pub tlv_stream: Bytes,
}

impl ChannelUpdate {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        write_signature(buf, &self.signature);
        write_32(buf, &self.chain_hash);
        write_u64(buf, self.short_channel_id);
        write_u32(buf, self.timestamp);
        codecs::write_u8(buf, self.message_flags);
        codecs::write_u8(buf, self.channel_flags);
        write_u16(buf, self.cltv_expiry_delta);
        write_u64_overflow(buf, self.htlc_minimum_msat)?;
        write_u32(buf, self.fee_base_msat);
        write_u32(buf, self.fee_proportional_millionths);
        write_u64_overflow(buf, self.htlc_maximum_msat)?;
        codecs::write_bytes(buf, &self.tlv_stream);
        Ok(())
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        let signature = read_signature(buf)?;
        let chain_hash = read_32(buf)?;
        let short_channel_id = read_u64(buf)?;
        let timestamp = read_u32(buf)?;
        let message_flags = codecs::read_u8(buf)?;
        if message_flags != 0x01 {
            return Err(DecodeError::Invalid(format!(
                "channel_update message_flags must be 0x01, got {:#04x}",
                message_flags
            )));
        }
        let channel_flags = codecs::read_u8(buf)?;
        let cltv_expiry_delta = read_u16(buf)?;
        let htlc_minimum_msat = read_u64_overflow(buf)?;
        let fee_base_msat = read_u32(buf)?;
        let fee_proportional_millionths = read_u32(buf)?;
        let htlc_maximum_msat = read_u64_overflow(buf)?;
        let tlv_stream = codecs::read_remaining(buf);
        validate_tlv_stream(&tlv_stream)?;
        Ok(Self {
            signature,
            chain_hash,
            short_channel_id,
            timestamp,
            message_flags,
            channel_flags,
            cltv_expiry_delta,
            htlc_minimum_msat,
            fee_base_msat,
            fee_proportional_millionths,
            htlc_maximum_msat,
            tlv_stream,
        })
    }

    /// The signed witness material (everything after the signature).
    pub fn witness(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(72);
        write_32(&mut buf, &self.chain_hash);
        write_u64(&mut buf, self.short_channel_id);
        write_u32(&mut buf, self.timestamp);
        codecs::write_u8(&mut buf, self.message_flags);
        codecs::write_u8(&mut buf, self.channel_flags);
        write_u16(&mut buf, self.cltv_expiry_delta);
        let _ = write_u64_overflow(&mut buf, self.htlc_minimum_msat);
        write_u32(&mut buf, self.fee_base_msat);
        write_u32(&mut buf, self.fee_proportional_millionths);
        let _ = write_u64_overflow(&mut buf, self.htlc_maximum_msat);
        codecs::write_bytes(&mut buf, &self.tlv_stream);
        buf.freeze()
    }
}

/// A PHC-wrapped `channel_update` message.
///
/// Both `64509` (gossip) and `64507` (sync) carry the same typed
/// `ChannelUpdate` body. We preserve the original tag so replies can
/// match the peer's convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhcChannelUpdate {
    pub tag: u16,
    pub body: ChannelUpdate,
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
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        codecs::write_32(buf, &self.chain_hash);
        write_varsize(buf, &self.refund_scriptpubkey)?;
        write_varsize(buf, &self.secret)?;
        Ok(())
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
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        write_u32(buf, self.block_day);
        write_u32(buf, self.local_updates);
        write_u32(buf, self.remote_updates);
        write_signature(buf, &self.local_sig_of_remote);
        Ok(())
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
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        write_u32(buf, self.block_day);
        write_u64_overflow(buf, self.local_balance_msat)?;
        write_u32(buf, self.local_updates);
        write_u32(buf, self.remote_updates);
        write_signature(buf, &self.local_sig_of_remote);
        Ok(())
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            block_day: read_u32(buf)?,
            local_balance_msat: read_u64_overflow(buf)?,
            local_updates: read_u32(buf)?,
            remote_updates: read_u32(buf)?,
            local_sig_of_remote: read_signature(buf)?,
        })
    }
}

/// `announcement_signature` (65523) — PHC announcement signature request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementSignature {
    pub node_signature: [u8; 64],
    pub wants_reply: bool,
}

impl AnnouncementSignature {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        write_signature(buf, &self.node_signature);
        codecs::write_bool(buf, self.wants_reply);
        Ok(())
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            node_signature: read_signature(buf)?,
            wants_reply: codecs::read_bool(buf)?,
        })
    }
}

/// `query_public_hosted_channels` (65519)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPublicHostedChannels {
    pub chain_hash: [u8; 32],
}

impl QueryPublicHostedChannels {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        codecs::write_32(buf, &self.chain_hash);
        Ok(())
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            chain_hash: read_32(buf)?,
        })
    }
}

/// `reply_public_hosted_channels_end` (65517)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyPublicHostedChannelsEnd {
    pub chain_hash: [u8; 32],
}

impl ReplyPublicHostedChannelsEnd {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        codecs::write_32(buf, &self.chain_hash);
        Ok(())
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            chain_hash: read_32(buf)?,
        })
    }
}

/// `ask_branding_info` (65511)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskBrandingInfo {
    pub chain_hash: [u8; 32],
}

impl AskBrandingInfo {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        codecs::write_32(buf, &self.chain_hash);
        Ok(())
    }
    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            chain_hash: read_32(buf)?,
        })
    }
}

/// Poncho extension `resize_channel` (65521).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResizeChannel {
    pub new_capacity_sat: u64,
    pub client_sig: [u8; 64],
}

impl ResizeChannel {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        write_u64_overflow(buf, self.new_capacity_sat)?;
        write_signature(buf, &self.client_sig);
        Ok(())
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        Ok(Self {
            new_capacity_sat: read_u64_overflow(buf)?,
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

/// `hosted_channel_branding` (65525)
///
/// `contact_info` is stored as `Bytes` but validated as UTF-8 on
/// encode/decode, matching scoin's `variableSizeBytes(uint16, utf8)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedChannelBranding {
    pub rgb_color: [u8; 3],
    pub png_icon: Option<Bytes>,
    pub contact_info: Bytes,
}

impl HostedChannelBranding {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        buf.extend_from_slice(&self.rgb_color);
        match &self.png_icon {
            Some(png) => {
                codecs::write_u8(buf, 1);
                write_varsize(buf, png)?;
            }
            None => {
                codecs::write_u8(buf, 0);
            }
        }
        if std::str::from_utf8(&self.contact_info).is_err() {
            return Err(EncodeError::InvalidUtf8(
                "contact_info is not valid UTF-8".into(),
            ));
        }
        write_varsize(buf, &self.contact_info)?;
        Ok(())
    }

    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        let mut rgb = [0u8; 3];
        let raw = read_bytes(buf, 3)?;
        rgb.copy_from_slice(&raw);
        let has_png = codecs::read_u8(buf)? != 0;
        let png_icon = if has_png {
            Some(read_varsize(buf)?)
        } else {
            None
        };
        let contact_info = read_varsize(buf)?;
        if std::str::from_utf8(&contact_info).is_err() {
            return Err(DecodeError::Invalid(
                "hosted_channel_branding contact_info is not valid UTF-8".into(),
            ));
        }
        Ok(Self {
            rgb_color: rgb,
            png_icon,
            contact_info,
        })
    }
}

/// `update_add_htlc` (63505) — full scoin/BOLT-2 body with 32-byte channel_id.
impl UpdateAddHtlc {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        codecs::encode_update_add_htlc_body(buf, self)
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
    pub tlv_stream: Bytes,
}

impl UpdateFulfillHtlc {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        write_32(buf, &self.channel_id);
        write_u64_overflow(buf, self.id)?;
        write_32(buf, &self.payment_preimage);
        codecs::write_bytes(buf, &self.tlv_stream);
        Ok(())
    }
    pub fn decode_body(buf: &mut &[u8]) -> DecodeResult<Self> {
        let channel_id = read_32(buf)?;
        let id = read_u64_overflow(buf)?;
        let payment_preimage = read_32(buf)?;
        let tlv_stream = codecs::read_remaining(buf);
        validate_tlv_stream(&tlv_stream)?;
        Ok(Self {
            channel_id,
            id,
            payment_preimage,
            tlv_stream,
        })
    }
}

/// `update_fail_htlc` (63501)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFailHtlc {
    pub channel_id: [u8; 32],
    pub id: u64,
    pub reason: Bytes,
    pub tlv_stream: Bytes,
}

impl UpdateFailHtlc {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        write_32(buf, &self.channel_id);
        write_u64_overflow(buf, self.id)?;
        write_varsize(buf, &self.reason)?;
        codecs::write_bytes(buf, &self.tlv_stream);
        Ok(())
    }
    pub fn decode_body(buf: &mut &[u8]) -> DecodeResult<Self> {
        let channel_id = read_32(buf)?;
        let id = read_u64_overflow(buf)?;
        let reason = read_varsize(buf)?;
        let tlv_stream = codecs::read_remaining(buf);
        validate_tlv_stream(&tlv_stream)?;
        Ok(Self {
            channel_id,
            id,
            reason,
            tlv_stream,
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
    pub tlv_stream: Bytes,
}

impl UpdateFailMalformedHtlc {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        write_32(buf, &self.channel_id);
        write_u64_overflow(buf, self.id)?;
        write_32(buf, &self.sha256_of_onion);
        codecs::write_u16(buf, self.failure_code);
        codecs::write_bytes(buf, &self.tlv_stream);
        Ok(())
    }
    pub fn decode_body(buf: &mut &[u8]) -> DecodeResult<Self> {
        let channel_id = read_32(buf)?;
        let id = read_u64_overflow(buf)?;
        let sha256_of_onion = read_32(buf)?;
        let failure_code = read_u16(buf)?;
        let tlv_stream = codecs::read_remaining(buf);
        validate_tlv_stream(&tlv_stream)?;
        Ok(Self {
            channel_id,
            id,
            sha256_of_onion,
            failure_code,
            tlv_stream,
        })
    }
}

/// `error` (63497) — matches scoin's errorCodec: channelId + varsize data + tlv_stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HcError {
    pub channel_id: [u8; 32],
    pub data: Bytes,
    pub tlv_stream: Bytes,
}

impl HcError {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        codecs::write_32(buf, &self.channel_id);
        write_varsize(buf, &self.data)?;
        codecs::write_bytes(buf, &self.tlv_stream);
        Ok(())
    }
    pub fn decode(buf: &mut &[u8]) -> DecodeResult<Self> {
        let channel_id = read_32(buf)?;
        let data = read_varsize(buf)?;
        let tlv_stream = codecs::read_remaining(buf);
        validate_tlv_stream(&tlv_stream)?;
        Ok(Self {
            channel_id,
            data,
            tlv_stream,
        })
    }
}

// ---------------------------------------------------------------------------
// Preimages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPreimages {
    pub hashes: Vec<[u8; 32]>,
}

impl QueryPreimages {
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        codecs::write_u16(buf, self.hashes.len() as u16);
        for hash in &self.hashes {
            write_32(buf, hash);
        }
        Ok(())
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
    pub fn encode(&self, buf: &mut BytesMut) -> EncodeResult<()> {
        codecs::write_u16(buf, self.preimages.len() as u16);
        for preimage in &self.preimages {
            write_32(buf, preimage);
        }
        Ok(())
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
        msg.encode(&mut buf).unwrap();
        let mut slice = &buf[..];
        let dec = InvokeHostedChannel::decode(&mut slice).unwrap();
        assert_eq!(dec, msg);
        assert!(slice.is_empty());
    }

    #[test]
    fn strict_decode_rejects_trailing_bytes() {
        let msg = HostedMessage::AskBrandingInfo(AskBrandingInfo {
            chain_hash: [0; 32],
        });
        let mut encoded = msg.encode().unwrap().to_vec();
        encoded.push(0);

        assert!(HostedMessage::decode(&encoded).is_err());
    }

    #[test]
    fn legacy_framed_invoke_decodes() {
        let msg = HostedMessage::InvokeHostedChannel(InvokeHostedChannel {
            chain_hash: [1u8; 32],
            refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14]),
            secret: Bytes::from_static(&[0x42; 32]),
        });
        let encoded = msg.encode_with_encoding(WireEncoding::Legacy).unwrap();
        assert_eq!(&encoded[..2], &[0xff, 0xff]);
        assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]) as usize, 70);

        let decoded = HostedMessage::decode_legacy_aware(&encoded).unwrap();
        assert_eq!(decoded.encoding, WireEncoding::Legacy);
        assert_eq!(decoded.message, msg);
    }

    #[test]
    fn decode_legacy_aware_prefers_strict_when_valid() {
        let msg = HostedMessage::AskBrandingInfo(AskBrandingInfo {
            chain_hash: [2; 32],
        });
        let encoded = msg.encode().unwrap();
        let decoded = HostedMessage::decode_legacy_aware(&encoded).unwrap();
        assert_eq!(decoded.encoding, WireEncoding::Strict);
        assert_eq!(decoded.message, msg);
    }

    #[test]
    fn legacy_decode_rejects_length_mismatch() {
        let msg = HostedMessage::AskBrandingInfo(AskBrandingInfo {
            chain_hash: [3; 32],
        });
        let mut encoded = msg
            .encode_with_encoding(WireEncoding::Legacy)
            .unwrap()
            .to_vec();
        encoded[3] = encoded[3].saturating_add(1);
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
        msg.encode(&mut buf).unwrap();
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
        msg.encode(&mut buf).unwrap();
        let mut slice = &buf[..];
        let dec = StateOverride::decode(&mut slice).unwrap();
        assert_eq!(dec, msg);
        assert!(slice.is_empty());
    }

    #[test]
    fn announcement_signature_roundtrip() {
        let msg = AnnouncementSignature {
            node_signature: [0xCD; 64],
            wants_reply: true,
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf).unwrap();
        let mut slice = &buf[..];
        let dec = AnnouncementSignature::decode(&mut slice).unwrap();
        assert_eq!(dec, msg);
        assert!(slice.is_empty());
    }

    #[test]
    fn query_public_hosted_channels_roundtrip() {
        let msg = QueryPublicHostedChannels {
            chain_hash: [0x42; 32],
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf).unwrap();
        let mut slice = &buf[..];
        let dec = QueryPublicHostedChannels::decode(&mut slice).unwrap();
        assert_eq!(dec, msg);
        assert!(slice.is_empty());
    }

    #[test]
    fn reply_public_hosted_channels_end_roundtrip() {
        let msg = ReplyPublicHostedChannelsEnd {
            chain_hash: [0x42; 32],
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf).unwrap();
        let mut slice = &buf[..];
        let dec = ReplyPublicHostedChannelsEnd::decode(&mut slice).unwrap();
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
        lcss.sign(&sk).unwrap();

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
            HostedMessage::AnnouncementSignature(AnnouncementSignature {
                node_signature: [0; 64],
                wants_reply: false,
            }),
            HostedMessage::AskBrandingInfo(AskBrandingInfo {
                chain_hash: [2; 32],
            }),
            HostedMessage::QueryPublicHostedChannels(QueryPublicHostedChannels {
                chain_hash: [2; 32],
            }),
            HostedMessage::ReplyPublicHostedChannelsEnd(ReplyPublicHostedChannelsEnd {
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
                tlv_stream: Bytes::new(),
            }),
            HostedMessage::UpdateFulfillHtlc(UpdateFulfillHtlc {
                channel_id: [0x42; 32],
                id: 1,
                payment_preimage: [4; 32],
                tlv_stream: Bytes::new(),
            }),
            HostedMessage::UpdateFailHtlc(UpdateFailHtlc {
                channel_id: [0x42; 32],
                id: 1,
                reason: Bytes::from_static(b"fail"),
                tlv_stream: Bytes::new(),
            }),
            HostedMessage::UpdateFailMalformedHtlc(UpdateFailMalformedHtlc {
                channel_id: [0x42; 32],
                id: 1,
                sha256_of_onion: [5; 32],
                failure_code: 0x4000,
                tlv_stream: Bytes::new(),
            }),
            HostedMessage::Error(HcError {
                channel_id: [6; 32],
                data: Bytes::from_static(b"err"),
                tlv_stream: Bytes::new(),
            }),
        ];

        for msg in &messages {
            let encoded = msg.encode().unwrap();
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
        with_png.encode(&mut buf).unwrap();
        let mut slice = &buf[..];
        let dec = HostedChannelBranding::decode(&mut slice).unwrap();
        assert_eq!(dec, with_png);

        let without_png = HostedChannelBranding {
            rgb_color: [4, 5, 6],
            png_icon: None,
            contact_info: Bytes::from_static(b"https://y.com"),
        };
        buf.clear();
        without_png.encode(&mut buf).unwrap();
        let mut slice = &buf[..];
        let dec = HostedChannelBranding::decode(&mut slice).unwrap();
        assert_eq!(dec, without_png);
    }

    #[test]
    fn branding_rejects_non_utf8_contact_info() {
        let mut buf = BytesMut::new();
        let bad = HostedChannelBranding {
            rgb_color: [0, 0, 0],
            png_icon: None,
            contact_info: Bytes::from_static(&[0xFF, 0xFE, 0xFD]),
        };
        assert!(bad.encode(&mut buf).is_err());
    }

    #[test]
    fn channel_update_roundtrip() {
        let cu = ChannelUpdate {
            signature: [0xAA; 64],
            chain_hash: [0x42; 32],
            short_channel_id: 123456789,
            timestamp: 1_700_000_000,
            message_flags: 0x01,
            channel_flags: 0x00,
            cltv_expiry_delta: 144,
            htlc_minimum_msat: 1_000,
            fee_base_msat: 1_000,
            fee_proportional_millionths: 100,
            htlc_maximum_msat: 100_000_000,
            tlv_stream: Bytes::new(),
        };
        let mut buf = BytesMut::new();
        cu.encode(&mut buf).unwrap();
        let mut slice: &[u8] = &buf;
        let dec = ChannelUpdate::decode(&mut slice).unwrap();
        assert_eq!(dec, cu);
        assert!(slice.is_empty());
    }

    #[test]
    fn phc_channel_update_64507_roundtrip() {
        let cu = ChannelUpdate {
            signature: [0xAA; 64],
            chain_hash: [0x42; 32],
            short_channel_id: 999,
            timestamp: 42,
            message_flags: 0x01,
            channel_flags: 0x01,
            cltv_expiry_delta: 144,
            htlc_minimum_msat: 1_000,
            fee_base_msat: 1_000,
            fee_proportional_millionths: 100,
            htlc_maximum_msat: 100_000_000,
            tlv_stream: Bytes::new(),
        };
        let msg = HostedMessage::PhcChannelUpdate(PhcChannelUpdate {
            tag: TAG_PHC_CHANNEL_UPDATE_SYNC,
            body: cu,
        });
        let encoded = msg.encode().unwrap();
        let decoded = HostedMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn phc_channel_update_64509_roundtrip() {
        let cu = ChannelUpdate {
            signature: [0xBB; 64],
            chain_hash: [0x42; 32],
            short_channel_id: 888,
            timestamp: 99,
            message_flags: 0x01,
            channel_flags: 0x00,
            cltv_expiry_delta: 144,
            htlc_minimum_msat: 1_000,
            fee_base_msat: 1_000,
            fee_proportional_millionths: 100,
            htlc_maximum_msat: 100_000_000,
            tlv_stream: Bytes::new(),
        };
        let msg = HostedMessage::PhcChannelUpdate(PhcChannelUpdate {
            tag: TAG_PHC_CHANNEL_UPDATE_GOSSIP,
            body: cu,
        });
        let encoded = msg.encode().unwrap();
        let decoded = HostedMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn update_add_htlc_with_tlv_stream_preserves_bytes() {
        let tlv = Bytes::from_static(&[0x01, 0x02, 0xAA, 0xBB]);
        let htlc = UpdateAddHtlc {
            channel_id: [0x42; 32],
            id: 7,
            amount_msat: 500_000,
            payment_hash: [0x99; 32],
            cltv_expiry: 700_000,
            onion_routing_packet: Bytes::from(vec![0; codecs::ONION_ROUTING_PACKET_SIZE]),
            tlv_stream: tlv.clone(),
        };
        let mut buf = BytesMut::new();
        codecs::encode_update_add_htlc_body(&mut buf, &htlc).unwrap();
        let mut slice: &[u8] = &buf;
        let decoded = codecs::decode_update_add_htlc_body(&mut slice).unwrap();
        assert_eq!(decoded.tlv_stream, tlv);
        assert!(slice.is_empty());
    }

    #[test]
    fn update_fulfill_htlc_with_tlv_preserves_bytes() {
        let tlv = Bytes::from_static(&[0x03, 0x02, 0xBB, 0xCC]);
        let msg = UpdateFulfillHtlc {
            channel_id: [0x42; 32],
            id: 1,
            payment_preimage: [4; 32],
            tlv_stream: tlv.clone(),
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf).unwrap();
        let mut slice: &[u8] = &buf;
        let decoded = UpdateFulfillHtlc::decode_body(&mut slice).unwrap();
        assert_eq!(decoded.tlv_stream, tlv);
        assert!(slice.is_empty());
    }

    #[test]
    fn update_fail_htlc_with_tlv_preserves_bytes() {
        let tlv = Bytes::from_static(&[0x05, 0x01, 0xDD]);
        let msg = UpdateFailHtlc {
            channel_id: [0x42; 32],
            id: 1,
            reason: Bytes::from_static(b"fail"),
            tlv_stream: tlv.clone(),
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf).unwrap();
        let mut slice: &[u8] = &buf;
        let decoded = UpdateFailHtlc::decode_body(&mut slice).unwrap();
        assert_eq!(decoded.tlv_stream, tlv);
        assert!(slice.is_empty());
    }

    #[test]
    fn update_fail_malformed_htlc_with_tlv_preserves_bytes() {
        let tlv = Bytes::from_static(&[0x07, 0x01, 0xEE]);
        let msg = UpdateFailMalformedHtlc {
            channel_id: [0x42; 32],
            id: 1,
            sha256_of_onion: [5; 32],
            failure_code: 0x4000,
            tlv_stream: tlv.clone(),
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf).unwrap();
        let mut slice: &[u8] = &buf;
        let decoded = UpdateFailMalformedHtlc::decode_body(&mut slice).unwrap();
        assert_eq!(decoded.tlv_stream, tlv);
        assert!(slice.is_empty());
    }

    #[test]
    fn hc_error_with_tlv_preserves_bytes() {
        let tlv = Bytes::from_static(&[0x09, 0x02, 0xFF, 0x00]);
        let msg = HcError {
            channel_id: [6; 32],
            data: Bytes::from_static(b"err"),
            tlv_stream: tlv.clone(),
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf).unwrap();
        let mut slice: &[u8] = &buf;
        let decoded = HcError::decode(&mut slice).unwrap();
        assert_eq!(decoded.tlv_stream, tlv);
        assert!(slice.is_empty());
    }
}
