//! Per-peer hosted channel state machine (HOST side).
//!
//! Handles:
//! - Channel establishment (invoke → init → state_update exchange)
//! - Reconnection (last_cross_signed_state reconciliation with reversal)
//! - Normal operation (HTLC add/fulfill/fail + state_update signing)
//! - Error states and state_override/reset flow
//!
//! All state changes are persisted via the [`Store`] trait before any side
//! effects (sending messages, resolving HTLCs) — this is a critical funds-safety
//! invariant.

use crate::channel_id::{channel_id, hosted_short_channel_id};
use crate::config::{ChannelPolicy, Config};
use crate::ledger::{LedgerEventType, LedgerManager};
use crate::node::{HtlcResolution, NodeActions, PaymentStatus};
use crate::state::{StateError, StateManager};
use crate::store::{ChannelData, ForwardLink, PendingUpdate, Store, StoreError};
use crate::wire::codecs::UpdateAddHtlc;
use crate::wire::lcss::{InitHostedChannel, LastCrossSignedState};
use crate::wire::{
    AskBrandingInfo, HcError, HostedChannelBranding, HostedMessage, InvokeHostedChannel,
    StateOverride, StateUpdate, WireEncoding,
};
use bytes::Bytes;
use secp256k1::{PublicKey, SecretKey};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("state error: {0}")]
    State(#[from] StateError),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("node error: {0}")]
    Node(#[from] crate::node::NodeError),
    #[error("encode error: {0}")]
    Encode(String),
    #[error("channel not found: {0}")]
    NotFound(String),
    #[error("channel is errored")]
    Errored,
    #[error("chain hash mismatch")]
    ChainHashMismatch,
    #[error("secret required but not provided or invalid")]
    InvalidSecret,
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    #[error("block day out of range: got {got}, current {current}")]
    BlockDayOutOfRange { got: u32, current: u32 },
    #[error("channel has in-flight HTLCs or pending updates; retry with force=true")]
    InFlightHtlcs,
}

impl From<crate::wire::codecs::EncodeError> for ChannelError {
    fn from(e: crate::wire::codecs::EncodeError) -> Self {
        ChannelError::Encode(e.to_string())
    }
}

pub type ChannelResult<T> = Result<T, ChannelError>;

/// Channel status (derived from ChannelData, not stored separately).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// No channel exists yet.
    NotOpened,
    /// We received invoke, sent init, waiting for client state_update.
    Opening,
    /// Channel is active.
    Active,
    /// Channel is in error state.
    Errored,
    /// Override has been proposed, waiting for client acceptance.
    Overriding,
    /// Channel is administratively suspended.
    Suspended,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::NotOpened => write!(f, "NOT_OPENED"),
            Status::Opening => write!(f, "OPENING"),
            Status::Active => write!(f, "ACTIVE"),
            Status::Errored => write!(f, "ERRORED"),
            Status::Overriding => write!(f, "OVERRIDING"),
            Status::Suspended => write!(f, "SUSPENDED"),
        }
    }
}

/// Derives the channel status from the persisted ChannelData.
pub fn derive_status(data: &ChannelData) -> Status {
    if data.suspended {
        return Status::Suspended;
    }
    if data.proposed_override.is_some() {
        return Status::Overriding;
    }
    if !data.local_errors.is_empty() || !data.remote_errors.is_empty() {
        return Status::Errored;
    }
    if !data.established {
        if data.lcss.local_updates == 0 && data.lcss.remote_updates == 0 {
            // Check if we have a refund script but no committed state yet
            if data.last_refund_scriptpubkey.is_empty() {
                return Status::NotOpened;
            }
            return Status::Opening;
        }
        return Status::Opening;
    }
    Status::Active
}

/// The hosted channel controller — owns the store, node, config, and node key.
pub struct ChannelController {
    pub store: Arc<dyn Store>,
    pub node: Arc<dyn NodeActions>,
    pub config: Config,
    pub node_secret: SecretKey,
    pub node_public: PublicKey,
    pub peer_wire_encodings: Arc<Mutex<HashMap<PublicKey, WireEncoding>>>,
}

impl ChannelController {
    /// Get the store key for a channel.
    fn channel_key(peer_id: &PublicKey) -> Vec<String> {
        vec![
            "canopusd".to_string(),
            "channels".to_string(),
            hex::encode(peer_id.serialize()),
        ]
    }

    /// Get the store key for a secret.
    fn secret_key(secret: &[u8]) -> Vec<String> {
        vec![
            "canopusd".to_string(),
            "secrets".to_string(),
            hex::encode(secret),
        ]
    }

    fn parse_secret_hex(secret: &str) -> ChannelResult<[u8; 32]> {
        let bytes = hex::decode(secret)
            .map_err(|_| ChannelError::InvalidMessage("secret must be 32-byte hex".into()))?;
        bytes
            .try_into()
            .map_err(|_| ChannelError::InvalidMessage("secret must be 32-byte hex".into()))
    }

    pub async fn note_peer_wire_encoding(&self, peer_id: &PublicKey, encoding: WireEncoding) {
        self.peer_wire_encodings
            .lock()
            .await
            .insert(*peer_id, encoding);
    }

    async fn peer_wire_encoding(&self, peer_id: &PublicKey) -> WireEncoding {
        self.peer_wire_encodings
            .lock()
            .await
            .get(peer_id)
            .copied()
            .unwrap_or(WireEncoding::Strict)
    }

    /// Get the store key for an HTLC forward.
    pub fn forward_key(scid: u64, htlc_id: u64) -> Vec<String> {
        vec![
            "canopusd".to_string(),
            "htlc_forwards".to_string(),
            scid.to_string(),
            htlc_id.to_string(),
        ]
    }

    /// Get the store key for a preimage.
    #[allow(dead_code)]
    fn preimage_key(payment_hash: &[u8; 32]) -> Vec<String> {
        vec![
            "canopusd".to_string(),
            "preimages".to_string(),
            hex::encode(payment_hash),
        ]
    }

    /// Load a channel's data from the store.
    pub async fn load_channel(&self, peer_id: &PublicKey) -> ChannelResult<Option<ChannelData>> {
        let key = Self::channel_key(peer_id);
        let key_ref: Vec<&str> = key.iter().map(|s| s.as_str()).collect();
        match crate::store::get_json::<ChannelData>(self.store.as_ref(), &key_ref).await {
            Ok((data, _)) => Ok(Some(data)),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Save a channel's data to the store (create or update).
    pub async fn save_channel(
        &self,
        peer_id: &PublicKey,
        data: &ChannelData,
        existing_gen: Option<u64>,
    ) -> ChannelResult<()> {
        let key_vec = Self::channel_key(peer_id);
        let key: Vec<&str> = key_vec.iter().map(|s| s.as_str()).collect();
        match existing_gen {
            Some(gen) => {
                crate::store::update_json(self.store.as_ref(), &key, data, gen).await?;
            }
            None => {
                match crate::store::create_json(self.store.as_ref(), &key, data).await {
                    Ok(()) => {}
                    Err(StoreError::AlreadyExists(_)) => {
                        // Race: someone else created it. Read and update.
                        let (_, gen) =
                            crate::store::get_json::<ChannelData>(self.store.as_ref(), &key)
                                .await?;
                        crate::store::update_json(self.store.as_ref(), &key, data, gen).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }

    /// Get the current block day (block height / 144).
    async fn current_block_day(&self) -> ChannelResult<u32> {
        let height = self.node.get_block_height().await?;
        Ok(height / 144)
    }

    fn policy_key() -> Vec<String> {
        vec!["canopusd".to_string(), "policy".to_string()]
    }

    pub async fn effective_policy(&self) -> ChannelResult<ChannelPolicy> {
        let key = Self::policy_key();
        let key_ref: Vec<&str> = key.iter().map(|s| s.as_str()).collect();
        match crate::store::get_json::<ChannelPolicy>(self.store.as_ref(), &key_ref).await {
            Ok((policy, _)) => Ok(policy),
            Err(StoreError::NotFound(_)) => Ok(self.config.policy.clone()),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn set_policy(&self, policy: ChannelPolicy) -> ChannelResult<()> {
        let key = Self::policy_key();
        let key_ref: Vec<&str> = key.iter().map(|s| s.as_str()).collect();
        match crate::store::create_json(self.store.as_ref(), &key_ref, &policy).await {
            Ok(()) => Ok(()),
            Err(StoreError::AlreadyExists(_)) => {
                let (_, gen) =
                    crate::store::get_json::<ChannelPolicy>(self.store.as_ref(), &key_ref).await?;
                crate::store::update_json(self.store.as_ref(), &key_ref, &policy, gen).await?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    // -----------------------------------------------------------------------
    // Channel establishment
    // -----------------------------------------------------------------------

    /// Handle an `invoke_hosted_channel` message from a peer.
    ///
    /// If no channel exists: verify chain hash and secret, store refund
    /// script, send `init_hosted_channel`.
    /// If a channel exists: send `last_cross_signed_state` for reconciliation.
    /// If channel is overriding: send lcss + error + state_override.
    pub async fn handle_invoke(
        &self,
        peer_id: &PublicKey,
        msg: InvokeHostedChannel,
    ) -> ChannelResult<()> {
        // Verify chain hash
        if msg.chain_hash != self.config.chain_hash {
            warn!(
                expected = %hex::encode(self.config.chain_hash),
                sent = %hex::encode(msg.chain_hash),
                "chain hash mismatch"
            );
            let err = HcError {
                channel_id: channel_id(&self.node_public, peer_id),
                data: Bytes::from_static(b"chain hash mismatch"),
                tlv_stream: Bytes::new(),
            };
            self.send_message(peer_id, HostedMessage::Error(err))
                .await?;
            return Err(ChannelError::ChainHashMismatch);
        }

        let existing = self.load_channel(peer_id).await?;

        match existing {
            None => {
                // New channel request
                self.handle_new_channel_invoke(peer_id, msg).await
            }
            Some(data) => {
                let status = derive_status(&data);
                match status {
                    Status::NotOpened | Status::Suspended => {
                        self.handle_new_channel_invoke(peer_id, msg).await
                    }
                    Status::Errored | Status::Overriding => {
                        // Send lcss + error + state_override for recovery
                        self.handle_reconnect_errored(peer_id, data).await
                    }
                    _ => {
                        // Active or Opening: send lcss for reconciliation
                        self.handle_reconnect_active(peer_id, data).await
                    }
                }
            }
        }
    }

    /// Handle a new channel request (no existing channel).
    async fn handle_new_channel_invoke(
        &self,
        peer_id: &PublicKey,
        msg: InvokeHostedChannel,
    ) -> ChannelResult<()> {
        // Check secret if required
        let policy = if self.config.require_secret {
            if msg.secret.is_empty() {
                warn!(
                    %peer_id,
                    error_type = %"missing_required_secret",
                    "ignoring invoke_hosted_channel"
                );
                return Ok(());
            }
            match self.consume_secret(&msg.secret).await? {
                Some(cap) => cap,
                None => {
                    warn!(
                        %peer_id,
                        error_type = %"unknown_or_consumed_secret",
                        "ignoring invoke_hosted_channel"
                    );
                    return Ok(());
                }
            }
        } else if !msg.secret.is_empty() {
            // Secret provided but not required — check if it matches a known secret
            match self.consume_secret(&msg.secret).await? {
                Some(cap) => cap,
                None => self.effective_policy().await?,
            }
        } else {
            self.effective_policy().await?
        };

        // Build init_hosted_channel
        let init = InitHostedChannel {
            max_htlc_value_in_flight_msat: policy.max_htlc_value_in_flight_msat,
            htlc_minimum_msat: policy.htlc_minimum_msat,
            max_accepted_htlcs: policy.max_accepted_htlcs,
            channel_capacity_msat: policy.channel_capacity_msat,
            initial_client_balance_msat: policy.initial_client_balance_msat,
            features: vec![],
        };

        // Store initial channel data (not yet established)
        let data = ChannelData {
            lcss: LastCrossSignedState {
                is_host: true,
                last_refund_scriptpubkey: msg.refund_scriptpubkey.clone(),
                init_hosted_channel: init.clone(),
                block_day: 0,
                local_balance_msat: policy.channel_capacity_msat
                    - policy.initial_client_balance_msat,
                remote_balance_msat: policy.initial_client_balance_msat,
                local_updates: 0,
                remote_updates: 0,
                incoming_htlcs: vec![],
                outgoing_htlcs: vec![],
                remote_sig_of_local: [0; 64],
                local_sig_of_remote: [0; 64],
            },
            uncommitted: vec![],
            local_errors: vec![],
            remote_errors: vec![],
            suspended: false,
            proposed_override: None,
            last_refund_scriptpubkey: msg.refund_scriptpubkey,
            established: false,
            accepting_resize_sat: None,
        };
        self.save_channel(peer_id, &data, None).await?;

        // Send init_hosted_channel
        self.send_message(peer_id, HostedMessage::InitHostedChannel(init))
            .await?;
        Ok(())
    }

    /// Handle reconnection when channel is active.
    async fn handle_reconnect_active(
        &self,
        peer_id: &PublicKey,
        data: ChannelData,
    ) -> ChannelResult<()> {
        // Extract uncommitted local updates for replay
        let uncommitted_local: Vec<_> = data
            .uncommitted
            .iter()
            .filter(|u| matches!(u, crate::store::UncommittedUpdate::Local(_)))
            .cloned()
            .collect();

        // Send stored lcss
        self.send_message(
            peer_id,
            HostedMessage::LastCrossSignedState(data.lcss.clone()),
        )
        .await?;

        // Replay uncommitted local updates exactly as they are included in the
        // persisted uncommitted state. The state_update below signs these ids.
        let mut sm = StateManager::new(data.lcss.clone());
        sm.uncommitted = data.uncommitted.clone();

        for update in &uncommitted_local {
            if let crate::store::UncommittedUpdate::Local(update) = update {
                match update {
                    PendingUpdate::Add { htlc } => {
                        let mut htlc = htlc.clone();
                        htlc.channel_id = channel_id(&self.node_public, peer_id);
                        self.send_message(peer_id, HostedMessage::UpdateAddHtlc(htlc))
                            .await?;
                    }
                    PendingUpdate::Fulfill {
                        channel_id,
                        id,
                        preimage,
                    } => {
                        self.send_message(
                            peer_id,
                            HostedMessage::UpdateFulfillHtlc(crate::wire::UpdateFulfillHtlc {
                                channel_id: *channel_id,
                                id: *id,
                                payment_preimage: *preimage,
                                tlv_stream: Bytes::new(),
                            }),
                        )
                        .await?;
                    }
                    PendingUpdate::Fail {
                        channel_id,
                        id,
                        reason,
                    } => {
                        self.send_message(
                            peer_id,
                            HostedMessage::UpdateFailHtlc(crate::wire::UpdateFailHtlc {
                                channel_id: *channel_id,
                                id: *id,
                                reason: reason.clone(),
                                tlv_stream: Bytes::new(),
                            }),
                        )
                        .await?;
                    }
                    PendingUpdate::FailMalformed {
                        channel_id,
                        id,
                        sha256_of_onion,
                        failure_code,
                    } => {
                        self.send_message(
                            peer_id,
                            HostedMessage::UpdateFailMalformedHtlc(
                                crate::wire::UpdateFailMalformedHtlc {
                                    channel_id: *channel_id,
                                    id: *id,
                                    sha256_of_onion: *sha256_of_onion,
                                    failure_code: *failure_code,
                                    tlv_stream: Bytes::new(),
                                },
                            ),
                        )
                        .await?;
                    }
                }
            }
        }

        // Send state_update if we have uncommitted updates
        if !sm.uncommitted.is_empty() {
            let mut next = sm.lcss_next()?;
            next.block_day = self.current_block_day().await?;
            next.sign(&self.node_secret)?;
            self.send_message(
                peer_id,
                HostedMessage::StateUpdate(StateUpdate {
                    block_day: next.block_day,
                    local_updates: next.local_updates,
                    remote_updates: next.remote_updates,
                    local_sig_of_remote: next.local_sig_of_remote,
                }),
            )
            .await?;
        }

        Ok(())
    }

    /// Handle reconnection when channel is errored or overriding.
    async fn handle_reconnect_errored(
        &self,
        peer_id: &PublicKey,
        data: ChannelData,
    ) -> ChannelResult<()> {
        // Send lcss
        self.send_message(
            peer_id,
            HostedMessage::LastCrossSignedState(data.lcss.clone()),
        )
        .await?;

        // Send error if we have one
        if let Some(err_msg) = data.local_errors.first() {
            let err = HcError {
                channel_id: channel_id(&self.node_public, peer_id),
                data: Bytes::copy_from_slice(err_msg.as_bytes()),
                tlv_stream: Bytes::new(),
            };
            self.send_message(peer_id, HostedMessage::Error(err))
                .await?;
        }

        // Send state_override if we have one proposed
        if let Some(ref override_lcss) = data.proposed_override {
            let override_msg = StateOverride {
                block_day: override_lcss.block_day,
                local_balance_msat: override_lcss.local_balance_msat,
                local_updates: override_lcss.local_updates,
                remote_updates: override_lcss.remote_updates,
                local_sig_of_remote: override_lcss.local_sig_of_remote,
            };
            self.send_message(peer_id, HostedMessage::StateOverride(override_msg))
                .await?;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // State update handling (establishment + normal operation)
    // -----------------------------------------------------------------------

    /// Handle a `state_update` message from the peer.
    pub async fn handle_state_update(
        &self,
        peer_id: &PublicKey,
        msg: StateUpdate,
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;

        let status = derive_status(&data);

        match status {
            Status::Opening => {
                // This is the initial state_update during establishment
                self.handle_opening_state_update(peer_id, data, msg).await
            }
            Status::Overriding => {
                // Client accepted our override
                self.handle_override_acceptance(peer_id, data, msg).await
            }
            Status::Active => {
                // Normal operation state_update
                self.handle_active_state_update(peer_id, data, msg).await
            }
            Status::Errored => {
                // Only accept fail/fulfill for pending HTLCs (handled in handle_update)
                debug!("ignoring state_update for errored channel");
                Ok(())
            }
            _ => {
                debug!(
                    "ignoring state_update in status {:?} for {}",
                    status,
                    hex::encode(peer_id.serialize())
                );
                Ok(())
            }
        }
    }

    /// Handle the initial state_update during channel opening.
    async fn handle_opening_state_update(
        &self,
        peer_id: &PublicKey,
        data: ChannelData,
        msg: StateUpdate,
    ) -> ChannelResult<()> {
        let current_block_day = self.current_block_day().await?;

        // Check block day tolerance (±1)
        let day_diff = msg.block_day.abs_diff(current_block_day);
        if day_diff > 1 {
            warn!(
                "block day out of range during opening: got {}, current {}",
                msg.block_day, current_block_day
            );
            // Silently refuse
            return Ok(());
        }

        // Build the initial lcss from our stored state
        let mut lcss = data.lcss.clone();
        lcss.block_day = msg.block_day;
        lcss.local_updates = 0;
        lcss.remote_updates = 0;
        lcss.incoming_htlcs = vec![];
        lcss.outgoing_htlcs = vec![];

        // The client's signature should verify against our view
        lcss.remote_sig_of_local = msg.local_sig_of_remote;
        if !lcss.verify_remote_sig(peer_id) {
            warn!(
                "bad signature in initial state_update from {}",
                hex::encode(peer_id.serialize())
            );
            return Ok(()); // silently refuse
        }

        // Sign our view
        lcss.sign(&self.node_secret)?;

        // Persist the established channel
        let mut new_data = data.clone();
        new_data.lcss = lcss.clone();
        new_data.established = true;
        new_data.last_refund_scriptpubkey = data.last_refund_scriptpubkey.clone();
        self.save_channel(peer_id, &new_data, None).await?;
        self.record_ledger_once(
            peer_id,
            format!(
                "{}:{}:{}:open",
                hex::encode(peer_id.serialize()),
                lcss.local_updates,
                lcss.remote_updates
            ),
            LedgerEventType::ChannelOpen,
            lcss.remote_balance_msat,
            None,
        )
        .await?;

        // Send our state_update back
        let state_update = StateUpdate {
            block_day: lcss.block_day,
            local_updates: lcss.local_updates,
            remote_updates: lcss.remote_updates,
            local_sig_of_remote: lcss.local_sig_of_remote,
        };
        self.send_message(peer_id, HostedMessage::StateUpdate(state_update))
            .await?;

        // Send a channel_update (gossip) for routing
        self.send_channel_update(peer_id).await?;

        Ok(())
    }

    /// Handle a state_update during active operation (committing updates).
    async fn handle_active_state_update(
        &self,
        peer_id: &PublicKey,
        data: ChannelData,
        msg: StateUpdate,
    ) -> ChannelResult<()> {
        if data.uncommitted.is_empty() {
            debug!("ignoring active state_update with no pending transition");
            return Ok(());
        }

        let mut sm = StateManager::new(data.lcss.clone());
        sm.uncommitted = data.uncommitted.clone();

        // Compute expected next state counters
        let expected_local = sm.next_local_updates();
        let expected_remote = sm.next_remote_updates();
        let expected_peer_local = expected_remote;
        let expected_peer_remote = expected_local;

        // Check if this state_update advances the state
        if msg.local_updates < expected_peer_local || msg.remote_updates < expected_peer_remote {
            // Peer is behind — ignore
            debug!("state_update from peer is behind, ignoring");
            return Ok(());
        }

        if msg.local_updates != expected_peer_local || msg.remote_updates != expected_peer_remote {
            // Counter mismatch
            debug!(
                "state_update counter mismatch: expected peer local={} peer remote={} (host local={} host remote={}), got local={} remote={}",
                expected_peer_local,
                expected_peer_remote,
                expected_local,
                expected_remote,
                msg.local_updates,
                msg.remote_updates
            );
            return Ok(());
        }

        // Check block day
        let current_block_day = self.current_block_day().await?;
        if msg.block_day != current_block_day {
            debug!(
                "block day mismatch in state_update: got {}, current {}",
                msg.block_day, current_block_day
            );
            // Don't commit, wait for peer to retry
            return Ok(());
        }

        // Compute the next lcss and verify the peer's signature
        let mut next = sm.lcss_next()?;
        next.block_day = msg.block_day;
        next.remote_sig_of_local = msg.local_sig_of_remote;

        if !next.verify_remote_sig(peer_id) {
            warn!(
                "bad signature in state_update from {}",
                hex::encode(peer_id.serialize())
            );
            // Deliberately lenient — just ignore
            return Ok(());
        }

        // Sign our view of the next state
        next.sign(&self.node_secret)?;

        // Persist BEFORE any side effects
        let mut new_data = data.clone();
        new_data.lcss = next.clone();
        new_data.uncommitted.clear();
        self.save_channel(peer_id, &new_data, None).await?;
        self.record_committed_update_events(peer_id, &data.uncommitted, &data.lcss, &next)
            .await?;

        // Send our state_update to confirm
        let state_update = StateUpdate {
            block_day: next.block_day,
            local_updates: next.local_updates,
            remote_updates: next.remote_updates,
            local_sig_of_remote: next.local_sig_of_remote,
        };
        self.send_message(peer_id, HostedMessage::StateUpdate(state_update))
            .await?;

        // Dispatch committed side effects (relay HTLCs, etc.)
        self.dispatch_committed_effects(peer_id, &data, &data.uncommitted, &next)
            .await?;

        Ok(())
    }

    /// Handle client acceptance of our state_override.
    async fn handle_override_acceptance(
        &self,
        peer_id: &PublicKey,
        data: ChannelData,
        msg: StateUpdate,
    ) -> ChannelResult<()> {
        let proposed = data
            .proposed_override
            .as_ref()
            .ok_or(ChannelError::InvalidMessage("no proposed override".into()))?;

        // Check counters and block day match the proposal
        if msg.local_updates != proposed.remote_updates
            || msg.remote_updates != proposed.local_updates
        {
            debug!("override state_update counters don't match proposal");
            return Ok(());
        }

        let current_block_day = self.current_block_day().await?;
        if msg.block_day != current_block_day {
            debug!("override state_update block day mismatch");
            return Ok(());
        }

        // Verify signature
        let mut lcss = proposed.clone();
        lcss.remote_sig_of_local = msg.local_sig_of_remote;
        if !lcss.verify_remote_sig(peer_id) {
            warn!("bad signature in override acceptance");
            return Ok(());
        }

        // Sign and persist
        lcss.sign(&self.node_secret)?;
        let new_data = ChannelData {
            lcss: lcss.clone(),
            uncommitted: vec![],
            local_errors: vec![],
            remote_errors: vec![],
            suspended: false,
            proposed_override: None,
            last_refund_scriptpubkey: data.last_refund_scriptpubkey.clone(),
            established: true,
            accepting_resize_sat: data.accepting_resize_sat,
        };
        self.save_channel(peer_id, &new_data, None).await?;
        self.record_ledger_once(
            peer_id,
            format!(
                "{}:{}:{}:override",
                hex::encode(peer_id.serialize()),
                lcss.local_updates,
                lcss.remote_updates
            ),
            LedgerEventType::Override,
            lcss.local_balance_msat,
            None,
        )
        .await?;

        // Send our state_update to confirm
        self.send_message(
            peer_id,
            HostedMessage::StateUpdate(StateUpdate {
                block_day: lcss.block_day,
                local_updates: lcss.local_updates,
                remote_updates: lcss.remote_updates,
                local_sig_of_remote: lcss.local_sig_of_remote,
            }),
        )
        .await?;

        // Send channel_update
        self.send_channel_update(peer_id).await?;

        debug!(
            "channel override accepted for {}",
            hex::encode(peer_id.serialize())
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // HTLC handling
    // -----------------------------------------------------------------------

    /// Handle an `update_add_htlc` from the peer (client sending a payment).
    pub async fn handle_update_add(
        &self,
        peer_id: &PublicKey,
        htlc: UpdateAddHtlc,
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;

        let status = derive_status(&data);
        if status != Status::Active {
            // Channel not active — can't accept HTLCs
            // Fail the HTLC back
            let reason = self.failure_onion_for_peer_htlc(&htlc, 0x1007);
            self.send_message(
                peer_id,
                HostedMessage::UpdateFailHtlc(crate::wire::UpdateFailHtlc {
                    channel_id: htlc.channel_id,
                    id: htlc.id,
                    reason,
                    tlv_stream: Bytes::new(),
                }),
            )
            .await?;
            return Ok(());
        }

        let mut sm = StateManager::new(data.lcss.clone());
        sm.uncommitted = data.uncommitted.clone();

        let next = sm.lcss_next()?;
        if htlc.amount_msat > next.remote_balance_msat {
            self.mark_errored(
                peer_id,
                &data,
                "peer sent update_add_htlc above available balance",
            )
            .await?;
            self.send_message(
                peer_id,
                HostedMessage::Error(HcError {
                    channel_id: channel_id(&self.node_public, peer_id),
                    data: Bytes::from_static(b"update_add_htlc above available balance"),
                    tlv_stream: Bytes::new(),
                }),
            )
            .await?;
            return Ok(());
        }

        // Add as remote update and persist
        let mut new_data = data.clone();
        new_data
            .uncommitted
            .push(crate::store::UncommittedUpdate::Remote(
                PendingUpdate::Add { htlc: htlc.clone() },
            ));
        self.save_channel(peer_id, &new_data, None).await?;

        Ok(())
    }

    /// Handle an `update_fail_malformed_htlc` from the peer.
    pub async fn handle_update_fail_malformed(
        &self,
        peer_id: &PublicKey,
        msg: crate::wire::UpdateFailMalformedHtlc,
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;

        let status = derive_status(&data);
        if status != Status::Active && status != Status::Errored {
            return Ok(());
        }

        let mut new_data = data.clone();
        new_data
            .uncommitted
            .push(crate::store::UncommittedUpdate::Remote(
                PendingUpdate::FailMalformed {
                    channel_id: msg.channel_id,
                    id: msg.id,
                    sha256_of_onion: msg.sha256_of_onion,
                    failure_code: msg.failure_code,
                },
            ));
        self.save_channel(peer_id, &new_data, None).await?;

        Ok(())
    }

    /// Handle an `update_fulfill_htlc` from the peer.
    pub async fn handle_update_fulfill(
        &self,
        peer_id: &PublicKey,
        msg: crate::wire::UpdateFulfillHtlc,
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;

        let status = derive_status(&data);
        if status != Status::Active && status != Status::Errored {
            return Ok(());
        }

        // Verify the preimage matches the outgoing HTLC
        let preimage = msg.payment_preimage;
        let hash = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(preimage);
            h.finalize()
        };

        // Find the outgoing HTLC with this payment hash
        let outgoing = data
            .lcss
            .outgoing_htlcs
            .iter()
            .find(|h| h.htlc_id() == msg.id);

        if let Some(htlc) = outgoing {
            if htlc.payment_hash != hash.as_slice() {
                warn!("fulfill preimage doesn't match payment hash");
                return Ok(());
            }

            // Persist preimage for safety before processing
            self.node
                .store_preimage(&htlc.payment_hash, &preimage)
                .await?;

            // Add as remote update
            let mut new_data = data.clone();
            new_data
                .uncommitted
                .push(crate::store::UncommittedUpdate::Remote(
                    PendingUpdate::Fulfill {
                        channel_id: msg.channel_id,
                        id: msg.id,
                        preimage,
                    },
                ));
            self.save_channel(peer_id, &new_data, None).await?;

            let scid = hosted_short_channel_id(&self.node_public, peer_id);
            self.resolve_forward_fulfill(scid, msg.id, preimage).await?;
        }

        Ok(())
    }

    /// Handle an `update_fail_htlc` from the peer.
    pub async fn handle_update_fail(
        &self,
        peer_id: &PublicKey,
        msg: crate::wire::UpdateFailHtlc,
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;

        let status = derive_status(&data);
        if status != Status::Active && status != Status::Errored {
            return Ok(());
        }

        // Empty reason is an error per poncho
        if msg.reason.is_empty() {
            self.mark_errored(peer_id, &data, "peer sent empty fail reason")
                .await?;
            return Ok(());
        }

        // Add as remote update
        let mut new_data = data.clone();
        new_data
            .uncommitted
            .push(crate::store::UncommittedUpdate::Remote(
                PendingUpdate::Fail {
                    channel_id: msg.channel_id,
                    id: msg.id,
                    reason: msg.reason.clone(),
                },
            ));
        self.save_channel(peer_id, &new_data, None).await?;

        Ok(())
    }

    /// Handle an `error` message from the peer.
    pub async fn handle_error(&self, peer_id: &PublicKey, msg: HcError) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;

        let error_str = String::from_utf8_lossy(&msg.data).to_string();
        self.mark_remote_errored(peer_id, &data, &error_str).await?;
        Ok(())
    }

    pub async fn handle_query_preimages(
        &self,
        peer_id: &PublicKey,
        msg: crate::wire::QueryPreimages,
    ) -> ChannelResult<()> {
        let mut preimages = Vec::new();
        for hash in msg.hashes {
            if let Some(preimage) = self.node.lookup_preimage(&hash).await? {
                preimages.push(preimage);
            }
        }
        if !preimages.is_empty() {
            self.send_message(
                peer_id,
                HostedMessage::ReplyPreimages(crate::wire::ReplyPreimages { preimages }),
            )
            .await?;
        }
        Ok(())
    }

    pub async fn handle_reply_preimages(
        &self,
        _peer_id: &PublicKey,
        msg: crate::wire::ReplyPreimages,
    ) -> ChannelResult<()> {
        for preimage in msg.preimages {
            let payment_hash: [u8; 32] = {
                use sha2::Digest;
                sha2::Sha256::digest(preimage).into()
            };
            self.node.store_preimage(&payment_hash, &preimage).await?;
        }
        Ok(())
    }

    /// Handle poncho-compatible `resize_channel` extension messages.
    pub async fn handle_resize_channel(
        &self,
        peer_id: &PublicKey,
        msg: crate::wire::ResizeChannel,
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;
        if derive_status(&data) != Status::Active || !msg.verify_client_sig(peer_id) {
            return Ok(());
        }
        let Some(max_capacity_sat) = data.accepting_resize_sat else {
            return Ok(());
        };
        if msg.new_capacity_sat > max_capacity_sat {
            return Ok(());
        }
        let new_capacity_msat = msg
            .new_capacity_sat
            .checked_mul(1000)
            .ok_or_else(|| ChannelError::InvalidMessage("resize capacity overflow".into()))?;
        if new_capacity_msat <= data.lcss.remote_balance_msat {
            return Ok(());
        }

        let old_capacity_msat = data.lcss.init_hosted_channel.channel_capacity_msat;
        let new_local_balance = if new_capacity_msat >= old_capacity_msat {
            data.lcss
                .local_balance_msat
                .checked_add(new_capacity_msat - old_capacity_msat)
        } else {
            data.lcss
                .local_balance_msat
                .checked_sub(old_capacity_msat - new_capacity_msat)
        }
        .ok_or_else(|| ChannelError::InvalidMessage("resize balance overflow".into()))?;

        let mut new_data = data.clone();
        new_data.accepting_resize_sat = None;
        new_data.lcss.init_hosted_channel.channel_capacity_msat = new_capacity_msat;
        new_data
            .lcss
            .init_hosted_channel
            .max_htlc_value_in_flight_msat = new_capacity_msat;
        new_data.lcss.local_balance_msat = new_local_balance;
        new_data.lcss.sign(&self.node_secret)?;
        self.save_channel(peer_id, &new_data, None).await?;
        self.record_ledger_once(
            peer_id,
            format!(
                "{}:{}:{}:resize:{}",
                hex::encode(peer_id.serialize()),
                new_data.lcss.local_updates,
                new_data.lcss.remote_updates,
                new_capacity_msat
            ),
            LedgerEventType::Resize,
            new_capacity_msat,
            None,
        )
        .await?;

        self.send_message(
            peer_id,
            HostedMessage::StateUpdate(StateUpdate {
                block_day: new_data.lcss.block_day,
                local_updates: new_data.lcss.local_updates,
                remote_updates: new_data.lcss.remote_updates,
                local_sig_of_remote: new_data.lcss.local_sig_of_remote,
            }),
        )
        .await?;
        Ok(())
    }

    /// Allow a peer to resize up to `max_capacity_sat`; `None` cancels pending resize authorization.
    pub async fn accept_resize(
        &self,
        peer_id: &PublicKey,
        max_capacity_sat: Option<u64>,
    ) -> ChannelResult<()> {
        let key_vec = Self::channel_key(peer_id);
        let key_ref: Vec<&str> = key_vec.iter().map(|s| s.as_str()).collect();
        crate::store::cas_json::<ChannelData, _, _>(self.store.as_ref(), &key_ref, |data| {
            data.accepting_resize_sat = max_capacity_sat;
            Ok(())
        })
        .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Last cross-signed state handling (reconnection reconciliation)
    // -----------------------------------------------------------------------

    /// Handle a `last_cross_signed_state` message from the peer.
    pub async fn handle_lcss(
        &self,
        peer_id: &PublicKey,
        msg: LastCrossSignedState,
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;

        // The peer sends LCSS from its own view. In that view, remote_sig_of_local
        // is our signature and local_sig_of_remote is the peer's signature.
        if !msg.verify_remote_sig(&self.node_public) {
            // Bad signature — error the channel
            self.mark_errored(peer_id, &data, "our signature doesn't match in peer lcss")
                .await?;
            // Send error to peer
            self.send_message(
                peer_id,
                HostedMessage::Error(HcError {
                    channel_id: channel_id(&self.node_public, peer_id),
                    data: Bytes::from_static(b"bad signature"),
                    tlv_stream: Bytes::new(),
                }),
            )
            .await?;
            return Err(ChannelError::Errored);
        }

        let reversed = msg.reverse();
        if !reversed.verify_remote_sig(peer_id) {
            self.mark_errored(peer_id, &data, "bad signature in lcss from peer")
                .await?;
            return Err(ChannelError::Errored);
        }

        if reversed.local_updates < data.lcss.local_updates
            || reversed.remote_updates < data.lcss.remote_updates
        {
            // We are ahead — send our lcss, peer should adopt it
            self.send_message(
                peer_id,
                HostedMessage::LastCrossSignedState(data.lcss.clone()),
            )
            .await?;
        } else if reversed.local_updates == data.lcss.local_updates
            && reversed.remote_updates == data.lcss.remote_updates
        {
            // In agreement — send our lcss to acknowledge
            self.send_message(
                peer_id,
                HostedMessage::LastCrossSignedState(data.lcss.clone()),
            )
            .await?;
        } else {
            // We are behind — adopt the peer's state (reverse it)
            let adopted = reversed;
            let mut new_data = data.clone();
            new_data.lcss = adopted;
            new_data.uncommitted.clear();
            self.save_channel(peer_id, &new_data, None).await?;

            // Send our updated lcss
            self.send_message(
                peer_id,
                HostedMessage::LastCrossSignedState(new_data.lcss.clone()),
            )
            .await?;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Branding
    // -----------------------------------------------------------------------

    /// Handle an `ask_branding_info` message.
    pub async fn handle_ask_branding(
        &self,
        peer_id: &PublicKey,
        _msg: AskBrandingInfo,
    ) -> ChannelResult<()> {
        if self.config.branding.contact_url.is_none() {
            // No branding configured — don't reply
            return Ok(());
        }

        let contact_url = self.config.branding.contact_url.clone().unwrap_or_default();
        let branding = HostedChannelBranding {
            rgb_color: self.config.rgb_color().unwrap_or([0, 0, 0]),
            png_icon: self.config.logo_bytes(),
            contact_info: Bytes::from(contact_url.into_bytes()),
        };
        self.send_message(peer_id, HostedMessage::HostedChannelBranding(branding))
            .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Reset / override
    // -----------------------------------------------------------------------

    /// Propose a state_override to reset an errored channel.
    ///
    /// Uses the last known counterparty-signed cross-signed state.
    /// Optionally allows specifying a new local balance.
    pub async fn propose_override(
        &self,
        peer_id: &PublicKey,
        new_local_balance: Option<u64>,
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;

        let status = derive_status(&data);
        if status != Status::Errored && status != Status::Overriding {
            return Err(ChannelError::InvalidMessage(format!(
                "can only override errored/overriding channels, got {}",
                status
            )));
        }

        let capacity = data.lcss.init_hosted_channel.channel_capacity_msat;
        let local_balance = new_local_balance.unwrap_or(data.lcss.local_balance_msat);
        let remote_balance =
            capacity
                .checked_sub(local_balance)
                .ok_or(ChannelError::InvalidMessage(
                    "local balance exceeds capacity".into(),
                ))?;

        let block_day = self.current_block_day().await?;

        let mut override_lcss = LastCrossSignedState {
            is_host: true,
            last_refund_scriptpubkey: data.last_refund_scriptpubkey.clone(),
            init_hosted_channel: data.lcss.init_hosted_channel.clone(),
            block_day,
            local_balance_msat: local_balance,
            remote_balance_msat: remote_balance,
            local_updates: data.lcss.local_updates + 1,
            remote_updates: data.lcss.remote_updates + 1,
            incoming_htlcs: vec![],
            outgoing_htlcs: vec![],
            remote_sig_of_local: [0; 64],
            local_sig_of_remote: [0; 64],
        };
        override_lcss.sign(&self.node_secret)?;

        // Persist the proposed override
        let mut new_data = data.clone();
        new_data.proposed_override = Some(override_lcss.clone());
        self.save_channel(peer_id, &new_data, None).await?;

        // Send state_override
        self.send_message(
            peer_id,
            HostedMessage::StateOverride(StateOverride {
                block_day: override_lcss.block_day,
                local_balance_msat: override_lcss.local_balance_msat,
                local_updates: override_lcss.local_updates,
                remote_updates: override_lcss.remote_updates,
                local_sig_of_remote: override_lcss.local_sig_of_remote,
            }),
        )
        .await?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Secrets management
    // -----------------------------------------------------------------------

    /// Add a new channel secret.
    pub async fn add_secret(
        &self,
        secret: String,
        capacity_msat: u64,
        initial_balance_msat: u64,
    ) -> ChannelResult<()> {
        let secret_bytes = Self::parse_secret_hex(&secret)?;
        let secret_hex = hex::encode(secret_bytes);
        let channel_secret = crate::config::ChannelSecret {
            secret: secret_hex,
            capacity_msat,
            initial_balance_msat,
            consumed: false,
        };

        let key_vec = Self::secret_key(&secret_bytes);
        let key: Vec<&str> = key_vec.iter().map(|s| s.as_str()).collect();
        crate::store::create_json(self.store.as_ref(), &key, &channel_secret)
            .await
            .map_err(|e| match e {
                StoreError::AlreadyExists(_) => {
                    ChannelError::InvalidMessage("secret already exists".into())
                }
                e => e.into(),
            })?;
        Ok(())
    }

    /// Remove a secret.
    pub async fn remove_secret(&self, secret: &str) -> ChannelResult<()> {
        let secret_bytes = Self::parse_secret_hex(secret)?;
        let key_vec = Self::secret_key(&secret_bytes);
        let key: Vec<&str> = key_vec.iter().map(|s| s.as_str()).collect();
        self.store.delete(&key).await?;
        Ok(())
    }

    /// Consume a secret (mark as used). Returns the policy if valid.
    async fn consume_secret(&self, secret: &[u8]) -> ChannelResult<Option<ChannelPolicy>> {
        if secret.len() != 32 {
            return Ok(None);
        }
        let key_vec = Self::secret_key(secret);
        let key: Vec<&str> = key_vec.iter().map(|s| s.as_str()).collect();

        match crate::store::get_json::<crate::config::ChannelSecret>(self.store.as_ref(), &key)
            .await
        {
            Ok((mut s, gen)) => {
                if s.consumed {
                    return Ok(None);
                }
                // Mark consumed (CAS)
                s.consumed = true;
                let policy = ChannelPolicy {
                    channel_capacity_msat: s.capacity_msat,
                    initial_client_balance_msat: s.initial_balance_msat,
                    ..self.effective_policy().await?
                };
                crate::store::update_json(self.store.as_ref(), &key, &s, gen).await?;
                // Delete the secret (one-time use)
                self.store.delete(&key).await?;
                Ok(Some(policy))
            }
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all secrets (redacted).
    pub async fn list_secrets(&self) -> ChannelResult<Vec<String>> {
        let children = self.store.list(&["canopusd", "secrets"]).await?;
        Ok(children
            .into_iter()
            .map(|c| c.last().cloned().unwrap_or_default())
            .collect())
    }

    // -----------------------------------------------------------------------
    // Error handling
    // -----------------------------------------------------------------------

    /// Mark the channel as errored.
    async fn mark_errored(
        &self,
        peer_id: &PublicKey,
        data: &ChannelData,
        error: &str,
    ) -> ChannelResult<()> {
        let mut new_data = data.clone();
        new_data.local_errors.push(error.to_string());
        self.save_channel(peer_id, &new_data, None).await?;
        warn!(
            "channel {} errored: {}",
            hex::encode(peer_id.serialize()),
            error
        );
        Ok(())
    }

    async fn mark_remote_errored(
        &self,
        peer_id: &PublicKey,
        data: &ChannelData,
        error: &str,
    ) -> ChannelResult<()> {
        let mut new_data = data.clone();
        new_data.remote_errors.push(error.to_string());
        self.save_channel(peer_id, &new_data, None).await?;
        warn!(
            "channel {} errored: remote error: {}",
            hex::encode(peer_id.serialize()),
            error
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Send a message to the peer.
    async fn send_message(&self, peer_id: &PublicKey, msg: HostedMessage) -> ChannelResult<()> {
        let encoding = self.peer_wire_encoding(peer_id).await;
        self.send_message_with_encoding(peer_id, msg, encoding)
            .await
    }

    async fn send_message_with_encoding(
        &self,
        peer_id: &PublicKey,
        msg: HostedMessage,
        encoding: WireEncoding,
    ) -> ChannelResult<()> {
        let bytes = msg.encode_with_encoding(encoding)?;
        self.node.send_custom_msg(peer_id, bytes).await?;
        Ok(())
    }

    /// Send a PHC-wrapped channel_update (tag 64507) for the fake hosted scid.
    ///
    /// cliche/immortan expects `PHC_UPDATE_SYNC_TAG` (64507) for direct
    /// peer channel updates, not the standard BOLT-7 tag `258`.
    async fn send_channel_update(&self, peer_id: &PublicKey) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let policy = self.effective_policy().await?;
        let phc = crate::gossip::phc_channel_update_sync(
            &self.node_secret,
            &self.node_public,
            peer_id,
            self.config.chain_hash,
            &ChannelPolicy {
                channel_capacity_msat: data.lcss.init_hosted_channel.channel_capacity_msat,
                initial_client_balance_msat: data
                    .lcss
                    .init_hosted_channel
                    .initial_client_balance_msat,
                max_htlc_value_in_flight_msat: data
                    .lcss
                    .init_hosted_channel
                    .max_htlc_value_in_flight_msat,
                htlc_minimum_msat: data.lcss.init_hosted_channel.htlc_minimum_msat,
                max_accepted_htlcs: data.lcss.init_hosted_channel.max_accepted_htlcs,
                fee_base_msat: policy.fee_base_msat,
                fee_proportional_millionths: policy.fee_proportional_millionths,
                cltv_expiry_delta: policy.cltv_expiry_delta,
            },
            derive_status(&data) == Status::Active,
            timestamp,
        );
        let encoding = self.peer_wire_encoding(peer_id).await;
        self.node
            .send_custom_msg(
                peer_id,
                HostedMessage::PhcChannelUpdate(phc).encode_with_encoding(encoding)?,
            )
            .await?;
        Ok(())
    }

    /// Dispatch committed side effects (relay HTLCs, etc.).
    async fn dispatch_committed_effects(
        &self,
        peer_id: &PublicKey,
        old_data: &ChannelData,
        committed_updates: &[crate::store::UncommittedUpdate],
        new_lcss: &LastCrossSignedState,
    ) -> ChannelResult<()> {
        let hosted_scid = hosted_short_channel_id(&self.node_public, peer_id);
        for htlc in &new_lcss.incoming_htlcs {
            if old_data
                .lcss
                .incoming_htlcs
                .iter()
                .any(|old| old.htlc_id() == htlc.htlc_id())
            {
                continue;
            }

            let policy = &new_lcss.init_hosted_channel;
            let total_htlcs = new_lcss.incoming_htlcs.len() + new_lcss.outgoing_htlcs.len();
            let total_inflight = new_lcss
                .incoming_htlcs
                .iter()
                .chain(new_lcss.outgoing_htlcs.iter())
                .map(|h| h.amount_msat)
                .sum::<u64>();
            if htlc.amount_msat < policy.htlc_minimum_msat
                || total_htlcs > policy.max_accepted_htlcs as usize
                || total_inflight > policy.max_htlc_value_in_flight_msat
            {
                let reason = self.failure_onion_for_peer_htlc(htlc, 0x1007);
                self.send_local_fail_for_htlc(peer_id, htlc.htlc_id(), reason)
                    .await?;
                continue;
            }

            let peeled = match crate::sphinx::peel_onion(
                &self.node_secret,
                &htlc.onion_routing_packet,
                &htlc.payment_hash,
            ) {
                Ok(peeled) => peeled,
                Err(_) => {
                    let onion_hash: [u8; 32] =
                        sha2::Sha256::digest(&htlc.onion_routing_packet).into();
                    self.send_local_fail_malformed_for_htlc(
                        peer_id,
                        htlc.htlc_id(),
                        onion_hash,
                        0xc005,
                    )
                    .await?;
                    continue;
                }
            };

            let current_height = self.node.get_block_height().await.unwrap_or_default();
            let default_policy = self.effective_policy().await?;
            let required_fee = (peeled.amt_to_forward / 1_000_000)
                .saturating_mul(default_policy.fee_proportional_millionths as u64)
                .saturating_add(default_policy.fee_base_msat as u64);
            if peeled.outgoing_cltv_value < current_height.saturating_add(2)
                || htlc.amount_msat < peeled.amt_to_forward.saturating_add(required_fee)
                || htlc.cltv_expiry
                    < peeled
                        .outgoing_cltv_value
                        .saturating_add(default_policy.cltv_expiry_delta as u32)
            {
                let reason = self.failure_onion_for_peer_htlc(htlc, 0x1007);
                self.send_local_fail_for_htlc(peer_id, htlc.htlc_id(), reason)
                    .await?;
                continue;
            }

            let outgoing_scid = peeled.short_channel_id;
            if let Some(target_peer) = self.peer_for_hosted_scid(outgoing_scid).await? {
                if target_peer == *peer_id {
                    return Err(ChannelError::InvalidMessage(
                        "cannot forward hosted HTLC back to same channel".into(),
                    ));
                }
                let outgoing_htlc = UpdateAddHtlc {
                    channel_id: channel_id(&self.node_public, &target_peer),
                    id: 0,
                    amount_msat: peeled.amt_to_forward,
                    payment_hash: htlc.payment_hash,
                    cltv_expiry: peeled.outgoing_cltv_value,
                    onion_routing_packet: Bytes::from(peeled.next_onion),
                    tlv_stream: Bytes::new(),
                };
                let result_key = format!("{hosted_scid}/{}", htlc.htlc_id());
                self.channel_handle_htlc_add(
                    &target_peer,
                    outgoing_htlc,
                    &result_key,
                    hosted_scid,
                    htlc.htlc_id(),
                    Some(peeled.shared_secret),
                )
                .await?;
                continue;
            }
            let outgoing_htlc_id = htlc.htlc_id();
            let link = ForwardLink {
                incoming_scid: hosted_scid,
                incoming_htlc_id: htlc.htlc_id(),
                outgoing_scid,
                outgoing_htlc_id,
                payment_hash: htlc.payment_hash,
                shared_secret: Some(peeled.shared_secret),
            };
            let key = Self::forward_key(outgoing_scid, outgoing_htlc_id);
            let key_ref: Vec<&str> = key.iter().map(|s| s.as_str()).collect();
            match crate::store::create_json(self.store.as_ref(), &key_ref, &link).await {
                Ok(()) | Err(StoreError::AlreadyExists(_)) => {}
                Err(e) => return Err(e.into()),
            }

            let current_height = self.node.get_block_height().await.unwrap_or_default();
            let first_delay = peeled
                .outgoing_cltv_value
                .saturating_sub(current_height)
                .saturating_sub(1)
                .min(u16::MAX as u32) as u16;
            let label = format!("{outgoing_scid}/{outgoing_htlc_id}");
            self.node
                .send_onion(
                    Bytes::from(peeled.next_onion),
                    htlc.payment_hash,
                    outgoing_scid,
                    peeled.amt_to_forward,
                    first_delay,
                    label,
                    outgoing_scid / 100,
                    outgoing_htlc_id,
                )
                .await?;
        }

        for update in committed_updates {
            match update {
                crate::store::UncommittedUpdate::Remote(PendingUpdate::Fail {
                    id, reason, ..
                }) => {
                    self.resolve_forward_fail(hosted_scid, *id, reason).await?;
                }
                crate::store::UncommittedUpdate::Remote(PendingUpdate::FailMalformed {
                    id,
                    sha256_of_onion,
                    failure_code,
                    ..
                }) => {
                    let mut failure = Vec::with_capacity(34);
                    failure.extend_from_slice(&failure_code.to_be_bytes());
                    failure.extend_from_slice(sha256_of_onion);
                    self.resolve_forward_fail(hosted_scid, *id, &failure)
                        .await?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn peer_for_hosted_scid(&self, scid: u64) -> ChannelResult<Option<PublicKey>> {
        for peer in self.list_channels().await? {
            if hosted_short_channel_id(&self.node_public, &peer) == scid {
                return Ok(Some(peer));
            }
        }
        Ok(None)
    }

    async fn record_ledger_once(
        &self,
        peer_id: &PublicKey,
        event_id: String,
        event_type: LedgerEventType,
        amount_msat: u64,
        payment_hash: Option<&[u8; 32]>,
    ) -> ChannelResult<()> {
        let ledger = LedgerManager::new(self.store.clone());
        ledger
            .record_once(
                &event_id,
                &hex::encode(peer_id.serialize()),
                event_type,
                amount_msat,
                0,
                payment_hash,
            )
            .await?;
        Ok(())
    }

    async fn record_committed_update_events(
        &self,
        peer_id: &PublicKey,
        committed_updates: &[crate::store::UncommittedUpdate],
        old_lcss: &LastCrossSignedState,
        new_lcss: &LastCrossSignedState,
    ) -> ChannelResult<()> {
        for update in committed_updates {
            match update {
                crate::store::UncommittedUpdate::Local(PendingUpdate::Add { htlc }) => {
                    self.record_ledger_once(
                        peer_id,
                        format!(
                            "{}:{}:{}:local-add:{}",
                            hex::encode(peer_id.serialize()),
                            new_lcss.local_updates,
                            new_lcss.remote_updates,
                            htlc.htlc_id()
                        ),
                        LedgerEventType::HtlcForwarded,
                        htlc.amount_msat,
                        Some(&htlc.payment_hash),
                    )
                    .await?;
                }
                crate::store::UncommittedUpdate::Remote(PendingUpdate::Add { htlc }) => {
                    self.record_ledger_once(
                        peer_id,
                        format!(
                            "{}:{}:{}:remote-add:{}",
                            hex::encode(peer_id.serialize()),
                            new_lcss.local_updates,
                            new_lcss.remote_updates,
                            htlc.htlc_id()
                        ),
                        LedgerEventType::HtlcForwarded,
                        htlc.amount_msat,
                        Some(&htlc.payment_hash),
                    )
                    .await?;
                }
                crate::store::UncommittedUpdate::Local(PendingUpdate::Fulfill { id, .. }) => {
                    if let Some(htlc) = old_lcss.incoming_htlcs.iter().find(|h| h.htlc_id() == *id)
                    {
                        self.record_ledger_once(
                            peer_id,
                            format!(
                                "{}:{}:{}:local-fulfill:{}",
                                hex::encode(peer_id.serialize()),
                                new_lcss.local_updates,
                                new_lcss.remote_updates,
                                id
                            ),
                            LedgerEventType::HtlcFulfilled,
                            htlc.amount_msat,
                            Some(&htlc.payment_hash),
                        )
                        .await?;
                    }
                }
                crate::store::UncommittedUpdate::Remote(PendingUpdate::Fulfill { id, .. }) => {
                    if let Some(htlc) = old_lcss.outgoing_htlcs.iter().find(|h| h.htlc_id() == *id)
                    {
                        self.record_ledger_once(
                            peer_id,
                            format!(
                                "{}:{}:{}:remote-fulfill:{}",
                                hex::encode(peer_id.serialize()),
                                new_lcss.local_updates,
                                new_lcss.remote_updates,
                                id
                            ),
                            LedgerEventType::HtlcFulfilled,
                            htlc.amount_msat,
                            Some(&htlc.payment_hash),
                        )
                        .await?;
                    }
                }
                crate::store::UncommittedUpdate::Local(PendingUpdate::Fail { id, .. })
                | crate::store::UncommittedUpdate::Local(PendingUpdate::FailMalformed {
                    id, ..
                }) => {
                    if let Some(htlc) = old_lcss.incoming_htlcs.iter().find(|h| h.htlc_id() == *id)
                    {
                        self.record_ledger_once(
                            peer_id,
                            format!(
                                "{}:{}:{}:local-fail:{}",
                                hex::encode(peer_id.serialize()),
                                new_lcss.local_updates,
                                new_lcss.remote_updates,
                                id
                            ),
                            LedgerEventType::HtlcFailed,
                            htlc.amount_msat,
                            Some(&htlc.payment_hash),
                        )
                        .await?;
                    }
                }
                crate::store::UncommittedUpdate::Remote(PendingUpdate::Fail { id, .. })
                | crate::store::UncommittedUpdate::Remote(PendingUpdate::FailMalformed {
                    id,
                    ..
                }) => {
                    if let Some(htlc) = old_lcss.outgoing_htlcs.iter().find(|h| h.htlc_id() == *id)
                    {
                        self.record_ledger_once(
                            peer_id,
                            format!(
                                "{}:{}:{}:remote-fail:{}",
                                hex::encode(peer_id.serialize()),
                                new_lcss.local_updates,
                                new_lcss.remote_updates,
                                id
                            ),
                            LedgerEventType::HtlcFailed,
                            htlc.amount_msat,
                            Some(&htlc.payment_hash),
                        )
                        .await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn resolve_forward_fulfill(
        &self,
        outgoing_scid: u64,
        outgoing_htlc_id: u64,
        preimage: [u8; 32],
    ) -> ChannelResult<()> {
        let forward_key = Self::forward_key(outgoing_scid, outgoing_htlc_id);
        let key_ref: Vec<&str> = forward_key.iter().map(|s| s.as_str()).collect();
        let (link, _) =
            match crate::store::get_json::<ForwardLink>(self.store.as_ref(), &key_ref).await {
                Ok(link) => link,
                Err(StoreError::NotFound(_)) => return Ok(()),
                Err(e) => return Err(e.into()),
            };

        if let Some(source_peer) = self.peer_for_hosted_scid(link.incoming_scid).await? {
            self.send_local_fulfill(&source_peer, &link, preimage)
                .await?;
        } else {
            let result_key = format!("{}/{}", link.incoming_scid, link.incoming_htlc_id);
            self.node
                .resolve_htlc(&result_key, HtlcResolution::Resolve { preimage })
                .await?;
        }
        let _ = self.store.delete(&key_ref).await;
        Ok(())
    }

    async fn resolve_forward_fail(
        &self,
        outgoing_scid: u64,
        outgoing_htlc_id: u64,
        failure: &[u8],
    ) -> ChannelResult<()> {
        let forward_key = Self::forward_key(outgoing_scid, outgoing_htlc_id);
        let key_ref: Vec<&str> = forward_key.iter().map(|s| s.as_str()).collect();
        let (link, _) =
            match crate::store::get_json::<ForwardLink>(self.store.as_ref(), &key_ref).await {
                Ok(link) => link,
                Err(StoreError::NotFound(_)) => return Ok(()),
                Err(e) => return Err(e.into()),
            };
        let failure_onion = self.wrap_forward_failure(&link, failure);

        if let Some(source_peer) = self.peer_for_hosted_scid(link.incoming_scid).await? {
            self.send_local_fail(&source_peer, &link, failure_onion)
                .await?;
        } else {
            let result_key = format!("{}/{}", link.incoming_scid, link.incoming_htlc_id);
            self.node
                .resolve_htlc(&result_key, HtlcResolution::Fail { failure_onion })
                .await?;
        }
        let _ = self.store.delete(&key_ref).await;
        Ok(())
    }

    pub async fn handle_outgoing_payment_result(
        &self,
        outgoing_scid: u64,
        outgoing_htlc_id: u64,
        status: PaymentStatus,
    ) -> ChannelResult<()> {
        let forward_key = Self::forward_key(outgoing_scid, outgoing_htlc_id);
        let key_ref: Vec<&str> = forward_key.iter().map(|s| s.as_str()).collect();
        let (link, _) =
            match crate::store::get_json::<ForwardLink>(self.store.as_ref(), &key_ref).await {
                Ok(link) => link,
                Err(StoreError::NotFound(_)) => return Ok(()),
                Err(e) => return Err(e.into()),
            };
        let Some(peer_id) = self.peer_for_hosted_scid(link.incoming_scid).await? else {
            return Ok(());
        };
        match status {
            PaymentStatus::Succeeded { preimage } => {
                self.node
                    .store_preimage(&link.payment_hash, &preimage)
                    .await?;
                self.send_local_fulfill(&peer_id, &link, preimage).await?;
                let _ = self.store.delete(&key_ref).await;
            }
            PaymentStatus::Failed { failure_onion } => {
                let reason = self.wrap_forward_failure(&link, &failure_onion);
                self.send_local_fail(&peer_id, &link, reason).await?;
                let _ = self.store.delete(&key_ref).await;
            }
            PaymentStatus::Pending => {}
        }
        Ok(())
    }

    pub async fn send_direct_payment(
        &self,
        peer_id: &PublicKey,
        amount_msat: u64,
        payment_hash: [u8; 32],
        final_cltv_expiry: u32,
        payment_secret: Option<[u8; 32]>,
    ) -> ChannelResult<u64> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;
        if derive_status(&data) != Status::Active {
            return Err(ChannelError::Errored);
        }
        let mut sm = StateManager::new(data.lcss.clone());
        sm.uncommitted = data.uncommitted.clone();
        let next = sm.lcss_next()?;
        if amount_msat > next.local_balance_msat {
            return Err(ChannelError::InvalidMessage(
                "insufficient hosted balance".into(),
            ));
        }
        let htlc_id = sm.next_local_updates() as u64 + 1;
        let onion = crate::sphinx::create_single_hop_onion(
            peer_id,
            amount_msat,
            final_cltv_expiry,
            payment_secret,
            &payment_hash,
        )
        .map_err(|e| ChannelError::InvalidMessage(e.to_string()))?;
        let htlc = UpdateAddHtlc {
            channel_id: channel_id(&self.node_public, peer_id),
            id: htlc_id,
            amount_msat,
            payment_hash,
            cltv_expiry: final_cltv_expiry,
            onion_routing_packet: Bytes::from(onion),
            tlv_stream: Bytes::new(),
        };
        let mut new_data = data.clone();
        new_data
            .uncommitted
            .push(crate::store::UncommittedUpdate::Local(PendingUpdate::Add {
                htlc: htlc.clone(),
            }));
        let state_update = self.state_update_for_uncommitted(&new_data).await?;
        self.save_channel(peer_id, &new_data, None).await?;
        self.send_message(peer_id, HostedMessage::UpdateAddHtlc(htlc))
            .await?;
        self.send_message(peer_id, HostedMessage::StateUpdate(state_update))
            .await?;
        Ok(htlc_id)
    }

    async fn send_local_fulfill(
        &self,
        peer_id: &PublicKey,
        link: &ForwardLink,
        preimage: [u8; 32],
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;
        if !data
            .lcss
            .incoming_htlcs
            .iter()
            .any(|h| h.htlc_id() == link.incoming_htlc_id)
        {
            return Ok(());
        }
        let mut new_data = data.clone();
        new_data
            .uncommitted
            .push(crate::store::UncommittedUpdate::Local(
                PendingUpdate::Fulfill {
                    channel_id: channel_id(&self.node_public, peer_id),
                    id: link.incoming_htlc_id,
                    preimage,
                },
            ));
        let state_update = self.state_update_for_uncommitted(&new_data).await?;
        self.save_channel(peer_id, &new_data, None).await?;
        self.send_message(
            peer_id,
            HostedMessage::UpdateFulfillHtlc(crate::wire::UpdateFulfillHtlc {
                channel_id: channel_id(&self.node_public, peer_id),
                id: link.incoming_htlc_id,
                payment_preimage: preimage,
                tlv_stream: Bytes::new(),
            }),
        )
        .await?;
        self.send_message(peer_id, HostedMessage::StateUpdate(state_update))
            .await?;
        Ok(())
    }

    async fn send_local_fail(
        &self,
        peer_id: &PublicKey,
        link: &ForwardLink,
        reason: Bytes,
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;
        if !data
            .lcss
            .incoming_htlcs
            .iter()
            .any(|h| h.htlc_id() == link.incoming_htlc_id)
        {
            return Ok(());
        }
        let mut new_data = data.clone();
        new_data
            .uncommitted
            .push(crate::store::UncommittedUpdate::Local(
                PendingUpdate::Fail {
                    channel_id: channel_id(&self.node_public, peer_id),
                    id: link.incoming_htlc_id,
                    reason: reason.clone(),
                },
            ));
        let state_update = self.state_update_for_uncommitted(&new_data).await?;
        self.save_channel(peer_id, &new_data, None).await?;
        self.send_message(
            peer_id,
            HostedMessage::UpdateFailHtlc(crate::wire::UpdateFailHtlc {
                channel_id: channel_id(&self.node_public, peer_id),
                id: link.incoming_htlc_id,
                reason,
                tlv_stream: Bytes::new(),
            }),
        )
        .await?;
        self.send_message(peer_id, HostedMessage::StateUpdate(state_update))
            .await?;
        Ok(())
    }

    async fn send_local_fail_for_htlc(
        &self,
        peer_id: &PublicKey,
        htlc_id: u64,
        reason: Bytes,
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;
        if !data
            .lcss
            .incoming_htlcs
            .iter()
            .any(|h| h.htlc_id() == htlc_id)
        {
            return Ok(());
        }
        let mut new_data = data.clone();
        new_data
            .uncommitted
            .push(crate::store::UncommittedUpdate::Local(
                PendingUpdate::Fail {
                    channel_id: channel_id(&self.node_public, peer_id),
                    id: htlc_id,
                    reason: reason.clone(),
                },
            ));
        let state_update = self.state_update_for_uncommitted(&new_data).await?;
        self.save_channel(peer_id, &new_data, None).await?;
        self.send_message(
            peer_id,
            HostedMessage::UpdateFailHtlc(crate::wire::UpdateFailHtlc {
                channel_id: channel_id(&self.node_public, peer_id),
                id: htlc_id,
                reason,
                tlv_stream: Bytes::new(),
            }),
        )
        .await?;
        self.send_message(peer_id, HostedMessage::StateUpdate(state_update))
            .await?;
        Ok(())
    }

    async fn send_local_fail_malformed_for_htlc(
        &self,
        peer_id: &PublicKey,
        htlc_id: u64,
        sha256_of_onion: [u8; 32],
        failure_code: u16,
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;
        if !data
            .lcss
            .incoming_htlcs
            .iter()
            .any(|h| h.htlc_id() == htlc_id)
        {
            return Ok(());
        }
        let mut new_data = data.clone();
        new_data
            .uncommitted
            .push(crate::store::UncommittedUpdate::Local(
                PendingUpdate::FailMalformed {
                    channel_id: channel_id(&self.node_public, peer_id),
                    id: htlc_id,
                    sha256_of_onion,
                    failure_code,
                },
            ));
        let state_update = self.state_update_for_uncommitted(&new_data).await?;
        self.save_channel(peer_id, &new_data, None).await?;
        self.send_message(
            peer_id,
            HostedMessage::UpdateFailMalformedHtlc(crate::wire::UpdateFailMalformedHtlc {
                channel_id: channel_id(&self.node_public, peer_id),
                id: htlc_id,
                sha256_of_onion,
                failure_code,
                tlv_stream: Bytes::new(),
            }),
        )
        .await?;
        self.send_message(peer_id, HostedMessage::StateUpdate(state_update))
            .await?;
        Ok(())
    }

    async fn state_update_for_uncommitted(&self, data: &ChannelData) -> ChannelResult<StateUpdate> {
        let mut sm = StateManager::new(data.lcss.clone());
        sm.uncommitted = data.uncommitted.clone();
        let mut next = sm.lcss_next()?;
        next.block_day = self.current_block_day().await?;
        next.sign(&self.node_secret)?;
        Ok(StateUpdate {
            block_day: next.block_day,
            local_updates: next.local_updates,
            remote_updates: next.remote_updates,
            local_sig_of_remote: next.local_sig_of_remote,
        })
    }

    /// Get channel status.
    pub async fn get_status(&self, peer_id: &PublicKey) -> ChannelResult<Status> {
        match self.load_channel(peer_id).await? {
            Some(data) => Ok(derive_status(&data)),
            None => Ok(Status::NotOpened),
        }
    }

    /// List all channel peer pubkeys.
    pub async fn list_channels(&self) -> ChannelResult<Vec<PublicKey>> {
        let children = self.store.list(&["canopusd", "channels"]).await?;
        let mut peers = Vec::new();
        for child in children {
            if let Some(hex_id) = child.last() {
                if let Ok(bytes) = hex::decode(hex_id) {
                    if bytes.len() == 33 {
                        if let Ok(pk) = PublicKey::from_slice(&bytes) {
                            peers.push(pk);
                        }
                    }
                }
            }
        }
        Ok(peers)
    }

    pub async fn remove_channel(&self, peer_id: &PublicKey, force: bool) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;
        let mut sm = StateManager::new(data.lcss.clone());
        sm.uncommitted = data.uncommitted.clone();
        let next = sm.lcss_next()?;
        if !force
            && (!next.incoming_htlcs.is_empty()
                || !next.outgoing_htlcs.is_empty()
                || !data.uncommitted.is_empty())
        {
            return Err(ChannelError::InFlightHtlcs);
        }

        let hosted_scid = hosted_short_channel_id(&self.node_public, peer_id).to_string();
        for key in self
            .store
            .list(&["canopusd", "htlc_forwards", &hosted_scid])
            .await?
        {
            let key_ref: Vec<&str> = key.iter().map(|part| part.as_str()).collect();
            self.store.delete(&key_ref).await?;
        }

        let key = Self::channel_key(peer_id);
        let key_ref: Vec<&str> = key.iter().map(|part| part.as_str()).collect();
        self.store.delete(&key_ref).await?;
        self.peer_wire_encodings.lock().await.remove(peer_id);
        Ok(())
    }

    /// Handle an incoming HTLC add (from htlc_accepted hook).
    pub async fn channel_handle_htlc_add(
        &self,
        peer_id: &PublicKey,
        htlc: UpdateAddHtlc,
        result_key: &str,
        incoming_scid: u64,
        incoming_htlc_id: u64,
        shared_secret: Option<[u8; 32]>,
    ) -> ChannelResult<()> {
        let data = self
            .load_channel(peer_id)
            .await?
            .ok_or(ChannelError::NotFound(hex::encode(peer_id.serialize())))?;

        let status = derive_status(&data);
        if status != Status::Active {
            return Err(ChannelError::Errored);
        }

        // Check for known preimage (idempotency)
        if let Ok(Some(preimage)) = self.node.lookup_preimage(&htlc.payment_hash).await {
            self.node
                .resolve_htlc(result_key, HtlcResolution::Resolve { preimage })
                .await?;
            return Ok(());
        }

        // Validate HTLC parameters
        let policy = &data.lcss.init_hosted_channel;
        if htlc.amount_msat < policy.htlc_minimum_msat {
            self.node
                .resolve_htlc(
                    result_key,
                    HtlcResolution::FailMessage {
                        code: 0x400e, // amount_below_minimum
                        data: Bytes::new(),
                    },
                )
                .await?;
            return Ok(());
        }

        // Check balance: host must have enough to add this HTLC
        let mut sm = StateManager::new(data.lcss.clone());
        sm.uncommitted = data.uncommitted.clone();
        let next = sm.lcss_next()?;
        if htlc.amount_msat > next.local_balance_msat {
            self.node
                .resolve_htlc(
                    result_key,
                    HtlcResolution::FailMessage {
                        code: 0x1007, // temporary_channel_failure
                        data: Bytes::new(),
                    },
                )
                .await?;
            return Ok(());
        }

        // Check max in-flight
        let total_inflight: u64 = next
            .incoming_htlcs
            .iter()
            .map(|h| h.amount_msat)
            .sum::<u64>()
            .saturating_add(htlc.amount_msat);
        if total_inflight > policy.max_htlc_value_in_flight_msat {
            self.node
                .resolve_htlc(
                    result_key,
                    HtlcResolution::FailMessage {
                        code: 0x1007,
                        data: Bytes::new(),
                    },
                )
                .await?;
            return Ok(());
        }

        // Assign HTLC id
        let htlc_id = sm.next_local_updates() as u64 + 1;
        let mut htlc = htlc;
        htlc.channel_id = channel_id(&self.node_public, peer_id);
        htlc.id = htlc_id;

        let hosted_scid = hosted_short_channel_id(&self.node_public, peer_id);
        let link = ForwardLink {
            incoming_scid,
            incoming_htlc_id,
            outgoing_scid: hosted_scid,
            outgoing_htlc_id: htlc_id,
            payment_hash: htlc.payment_hash,
            shared_secret,
        };
        let forward_key = Self::forward_key(hosted_scid, htlc_id);
        let key_ref: Vec<&str> = forward_key.iter().map(|s| s.as_str()).collect();
        match crate::store::create_json(self.store.as_ref(), &key_ref, &link).await {
            Ok(()) | Err(StoreError::AlreadyExists(_)) => {}
            Err(e) => return Err(e.into()),
        }

        // Add as local update (from our perspective, this is an HTLC we're adding
        // on behalf of the incoming CLN HTLC)
        let mut new_data = data.clone();
        new_data
            .uncommitted
            .push(crate::store::UncommittedUpdate::Local(PendingUpdate::Add {
                htlc: htlc.clone(),
            }));
        self.save_channel(peer_id, &new_data, None).await?;

        sm.uncommitted = new_data.uncommitted.clone();

        // Send update_add_htlc to client
        self.send_message(peer_id, HostedMessage::UpdateAddHtlc(htlc))
            .await?;

        // Send state_update
        let mut next = sm.lcss_next()?;
        next.block_day = self.current_block_day().await?;
        next.sign(&self.node_secret)?;
        self.send_message(
            peer_id,
            HostedMessage::StateUpdate(StateUpdate {
                block_day: next.block_day,
                local_updates: next.local_updates,
                remote_updates: next.remote_updates,
                local_sig_of_remote: next.local_sig_of_remote,
            }),
        )
        .await?;

        Ok(())
    }

    fn failure_onion_for_peer_htlc(&self, htlc: &UpdateAddHtlc, failure_code: u16) -> Bytes {
        let mut failure = Vec::with_capacity(2);
        failure.extend_from_slice(&failure_code.to_be_bytes());
        match crate::sphinx::peel_onion(
            &self.node_secret,
            &htlc.onion_routing_packet,
            &htlc.payment_hash,
        ) {
            Ok(peeled) => Bytes::from(crate::sphinx::wrap_failure(&peeled.shared_secret, &failure)),
            Err(_) => Bytes::from(failure),
        }
    }

    fn wrap_forward_failure(&self, link: &ForwardLink, failure: &[u8]) -> Bytes {
        match link.shared_secret {
            Some(shared_secret) => {
                Bytes::from(crate::sphinx::wrap_failure(&shared_secret, failure))
            }
            None => Bytes::copy_from_slice(failure),
        }
    }

    /// Get channel data for inspection.
    pub async fn get_channel_data(
        &self,
        peer_id: &PublicKey,
    ) -> ChannelResult<Option<ChannelData>> {
        self.load_channel(peer_id).await
    }

    /// Handle a disconnect notification.
    pub async fn handle_disconnect(&self, peer_id: &PublicKey) -> ChannelResult<()> {
        self.peer_wire_encodings.lock().await.remove(peer_id);
        // Nothing to do — state is persisted; reconciliation happens on reconnect
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::MockNode;
    use crate::store::MemoryStore;

    async fn make_controller_with_config(config: Config) -> (ChannelController, Arc<MockNode>) {
        let secp = secp256k1::Secp256k1::new();
        let (secret, public) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let store = Arc::new(MemoryStore::new());
        let node = Arc::new(MockNode::new(700_000, public, "regtest"));
        let controller = ChannelController {
            store: store.clone(),
            node: node.clone(),
            config,
            node_secret: secret,
            node_public: public,
            peer_wire_encodings: Arc::new(Mutex::new(HashMap::new())),
        };
        (controller, node)
    }

    async fn make_controller() -> (ChannelController, Arc<MockNode>) {
        let config = Config {
            chain_hash: [0x06u8; 32],
            network: "regtest".to_string(),
            require_secret: false,
            ..Config::default()
        };
        make_controller_with_config(config).await
    }

    fn make_invoke(secret: &str) -> InvokeHostedChannel {
        let secret = secret.to_string();
        InvokeHostedChannel {
            chain_hash: [0x06u8; 32],
            refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14, 0x20]),
            secret: Bytes::from(secret.into_bytes()),
        }
    }

    fn make_invoke_hex_secret(secret: &str) -> InvokeHostedChannel {
        InvokeHostedChannel {
            chain_hash: [0x06u8; 32],
            refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14, 0x20]),
            secret: Bytes::from(hex::decode(secret).unwrap()),
        }
    }

    #[tokio::test]
    async fn establish_channel() {
        let (controller, node) = make_controller().await;
        let secp = secp256k1::Secp256k1::new();
        let (_client_secret, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

        // Client sends invoke
        controller
            .handle_invoke(&client_public, make_invoke(""))
            .await
            .unwrap();

        // Host should have sent init_hosted_channel
        {
            let sent = node.sent_messages.lock().unwrap();
            assert_eq!(sent.len(), 1);
            let msg = HostedMessage::decode(&sent[0].1).unwrap();
            assert!(matches!(msg, HostedMessage::InitHostedChannel(_)));
        }

        // Channel should be in Opening state
        let status = controller.get_status(&client_public).await.unwrap();
        assert_eq!(status, Status::Opening);
    }

    #[tokio::test]
    async fn full_establishment_flow() {
        let (controller, node) = make_controller().await;
        let secp = secp256k1::Secp256k1::new();
        let (client_secret, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

        // 1. Client sends invoke
        controller
            .handle_invoke(&client_public, make_invoke(""))
            .await
            .unwrap();

        // 2. Host sends init — client receives it
        let init_bytes = {
            let sent = node.sent_messages.lock().unwrap();
            sent[0].1.clone()
        };
        let init_msg = HostedMessage::decode(&init_bytes).unwrap();
        let init = match init_msg {
            HostedMessage::InitHostedChannel(i) => i,
            _ => panic!("expected init"),
        };

        // 3. Client builds lcss and sends state_update
        let mut client_lcss = LastCrossSignedState {
            is_host: false,
            last_refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14, 0x20]),
            init_hosted_channel: init,
            block_day: 700_000 / 144,
            local_balance_msat: 0,            // client
            remote_balance_msat: 100_000_000, // host
            local_updates: 0,
            remote_updates: 0,
            incoming_htlcs: vec![],
            outgoing_htlcs: vec![],
            remote_sig_of_local: [0; 64],
            local_sig_of_remote: [0; 64],
        };
        client_lcss.sign(&client_secret).unwrap();

        let state_update = StateUpdate {
            block_day: client_lcss.block_day,
            local_updates: 0,
            remote_updates: 0,
            local_sig_of_remote: client_lcss.local_sig_of_remote,
        };

        // 4. Host handles state_update
        controller
            .handle_state_update(&client_public, state_update)
            .await
            .unwrap();

        // Channel should be active
        let status = controller.get_status(&client_public).await.unwrap();
        assert_eq!(status, Status::Active);

        // Host should have sent init, state_update, and PHC channel_update (64507).
        let sent = node.sent_messages.lock().unwrap();
        assert_eq!(sent.len(), 3);
        let msg = HostedMessage::decode(&sent[1].1).unwrap();
        assert!(matches!(msg, HostedMessage::StateUpdate(_)));
        let phc_msg = HostedMessage::decode(&sent[2].1).unwrap();
        match phc_msg {
            HostedMessage::PhcChannelUpdate(p) => assert_eq!(p.tag, 64507),
            other => panic!("expected PhcChannelUpdate, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn chain_hash_mismatch_rejected() {
        let (controller, _node) = make_controller().await;
        let secp = secp256k1::Secp256k1::new();
        let (_, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

        let mut invoke = make_invoke("");
        invoke.chain_hash = [0xFF; 32]; // wrong chain hash

        let result = controller.handle_invoke(&client_public, invoke).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn secret_required_without_secret_ignored() {
        let (mut controller, node) = make_controller().await;
        controller.config.require_secret = true;

        let secp = secp256k1::Secp256k1::new();
        let (_, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

        controller
            .handle_invoke(&client_public, make_invoke(""))
            .await
            .unwrap();

        // Should not send init (secret required, none provided)
        let sent = node.sent_messages.lock().unwrap();
        assert!(sent.is_empty());
    }

    #[tokio::test]
    async fn default_requires_secret_without_secret_ignored() {
        let config = Config {
            chain_hash: [0x06u8; 32],
            network: "regtest".to_string(),
            ..Config::default()
        };
        let (controller, node) = make_controller_with_config(config).await;

        let secp = secp256k1::Secp256k1::new();
        let (_, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

        controller
            .handle_invoke(&client_public, make_invoke(""))
            .await
            .unwrap();

        assert!(node.sent_messages.lock().unwrap().is_empty());
        assert!(controller
            .load_channel(&client_public)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn legacy_session_invoke_gets_legacy_init() {
        let (controller, node) = make_controller().await;

        let secp = secp256k1::Secp256k1::new();
        let (_, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);
        controller
            .note_peer_wire_encoding(&client_public, WireEncoding::Legacy)
            .await;

        controller
            .handle_invoke(&client_public, make_invoke(""))
            .await
            .unwrap();

        let sent = node.sent_messages.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(&sent[0].1[..2], &[0xff, 0xfd]);
        let body_len = u16::from_be_bytes([sent[0].1[2], sent[0].1[3]]) as usize;
        assert_eq!(body_len, sent[0].1.len() - 4);
        let decoded = HostedMessage::decode_legacy_aware(&sent[0].1).unwrap();
        assert_eq!(decoded.encoding, WireEncoding::Legacy);
        assert!(matches!(
            decoded.message,
            HostedMessage::InitHostedChannel(_)
        ));
    }

    #[tokio::test]
    async fn disconnect_clears_legacy_session_encoding() {
        let (controller, _node) = make_controller().await;

        let secp = secp256k1::Secp256k1::new();
        let (_, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);
        controller
            .note_peer_wire_encoding(&client_public, WireEncoding::Legacy)
            .await;
        assert_eq!(
            controller.peer_wire_encoding(&client_public).await,
            WireEncoding::Legacy
        );

        controller.handle_disconnect(&client_public).await.unwrap();

        assert_eq!(
            controller.peer_wire_encoding(&client_public).await,
            WireEncoding::Strict
        );
    }

    #[tokio::test]
    async fn secret_grants_channel() {
        let (mut controller, node) = make_controller().await;
        controller.config.require_secret = true;
        let secret = "0101010101010101010101010101010101010101010101010101010101010101";

        // Add a secret
        controller
            .add_secret(secret.to_string(), 200_000_000, 50_000_000)
            .await
            .unwrap();

        let secp = secp256k1::Secp256k1::new();
        let (_, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

        controller
            .handle_invoke(&client_public, make_invoke_hex_secret(secret))
            .await
            .unwrap();

        // Should send init with secret-specific params
        let sent = node.sent_messages.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let msg = HostedMessage::decode(&sent[0].1).unwrap();
        if let HostedMessage::InitHostedChannel(init) = msg {
            assert_eq!(init.channel_capacity_msat, 200_000_000);
            assert_eq!(init.initial_client_balance_msat, 50_000_000);
        } else {
            panic!("expected init");
        }
    }

    #[tokio::test]
    async fn secret_consumed_on_use() {
        let (mut controller, node) = make_controller().await;
        controller.config.require_secret = true;
        let secret = "0202020202020202020202020202020202020202020202020202020202020202";

        controller
            .add_secret(secret.to_string(), 200_000_000, 50_000_000)
            .await
            .unwrap();

        let secp = secp256k1::Secp256k1::new();
        let (_, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

        // First use — should work
        controller
            .handle_invoke(&client_public, make_invoke_hex_secret(secret))
            .await
            .unwrap();
        assert_eq!(node.sent_messages.lock().unwrap().len(), 1);

        // Second use — should be ignored (secret consumed)
        let (_, client2) = secp.generate_keypair(&mut rand::rngs::OsRng);
        controller
            .handle_invoke(&client2, make_invoke_hex_secret(secret))
            .await
            .unwrap();
        // No new message sent
        assert_eq!(node.sent_messages.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn invalid_secret_hex_rejected() {
        let (controller, _node) = make_controller().await;

        assert!(controller
            .add_secret("not-hex".to_string(), 200_000_000, 50_000_000)
            .await
            .is_err());
        assert!(controller
            .add_secret("00".to_string(), 200_000_000, 50_000_000)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn override_resets_errored_channel() {
        let (controller, node) = make_controller().await;
        let secp = secp256k1::Secp256k1::new();
        let (client_secret, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

        // Establish channel first
        controller
            .handle_invoke(&client_public, make_invoke(""))
            .await
            .unwrap();

        let init_msg = {
            let sent = node.sent_messages.lock().unwrap();
            HostedMessage::decode(&sent[0].1).unwrap()
        };
        let init = match init_msg {
            HostedMessage::InitHostedChannel(i) => i,
            _ => panic!(),
        };

        let mut client_lcss = LastCrossSignedState {
            is_host: false,
            last_refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14, 0x20]),
            init_hosted_channel: init,
            block_day: 700_000 / 144,
            local_balance_msat: 0,
            remote_balance_msat: 100_000_000,
            local_updates: 0,
            remote_updates: 0,
            incoming_htlcs: vec![],
            outgoing_htlcs: vec![],
            remote_sig_of_local: [0; 64],
            local_sig_of_remote: [0; 64],
        };
        client_lcss.sign(&client_secret).unwrap();

        controller
            .handle_state_update(
                &client_public,
                StateUpdate {
                    block_day: client_lcss.block_day,
                    local_updates: 0,
                    remote_updates: 0,
                    local_sig_of_remote: client_lcss.local_sig_of_remote,
                },
            )
            .await
            .unwrap();

        // Error the channel
        let data = controller
            .load_channel(&client_public)
            .await
            .unwrap()
            .unwrap();
        controller
            .mark_errored(&client_public, &data, "test error")
            .await
            .unwrap();
        assert_eq!(
            controller.get_status(&client_public).await.unwrap(),
            Status::Errored
        );

        // Propose override
        controller
            .propose_override(&client_public, Some(80_000_000))
            .await
            .unwrap();

        assert_eq!(
            controller.get_status(&client_public).await.unwrap(),
            Status::Overriding
        );

        // Check that state_override was sent
        {
            let sent = node.sent_messages.lock().unwrap();
            let last_msg = HostedMessage::decode(&sent.last().unwrap().1).unwrap();
            assert!(matches!(last_msg, HostedMessage::StateOverride(_)));
        }

        // Client accepts override
        let override_lcss = controller
            .load_channel(&client_public)
            .await
            .unwrap()
            .unwrap()
            .proposed_override
            .unwrap();

        let mut accepted_lcss = override_lcss.reverse();
        accepted_lcss.sign(&client_secret).unwrap();

        controller
            .handle_state_update(
                &client_public,
                StateUpdate {
                    block_day: override_lcss.block_day,
                    local_updates: override_lcss.local_updates,
                    remote_updates: override_lcss.remote_updates,
                    local_sig_of_remote: accepted_lcss.local_sig_of_remote,
                },
            )
            .await
            .unwrap();

        // Channel should be active again
        assert_eq!(
            controller.get_status(&client_public).await.unwrap(),
            Status::Active
        );
    }

    #[tokio::test]
    async fn branding_sent_on_request() {
        let (mut controller, node) = make_controller().await;
        controller.config.branding.contact_url = Some("https://example.com".to_string());
        controller.config.branding.color = Some("#ff8800".to_string());

        let secp = secp256k1::Secp256k1::new();
        let (_, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

        controller
            .handle_ask_branding(
                &client_public,
                AskBrandingInfo {
                    chain_hash: [0; 32],
                },
            )
            .await
            .unwrap();

        let sent = node.sent_messages.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let msg = HostedMessage::decode(&sent[0].1).unwrap();
        if let HostedMessage::HostedChannelBranding(b) = msg {
            assert_eq!(b.rgb_color, [0xff, 0x88, 0x00]);
            assert_eq!(b.contact_info.as_ref(), b"https://example.com");
        } else {
            panic!("expected branding");
        }
    }

    #[tokio::test]
    async fn branding_not_sent_without_contact_url() {
        let (controller, node) = make_controller().await;
        // No contact URL configured

        let secp = secp256k1::Secp256k1::new();
        let (_, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

        controller
            .handle_ask_branding(
                &client_public,
                AskBrandingInfo {
                    chain_hash: [0; 32],
                },
            )
            .await
            .unwrap();

        let sent = node.sent_messages.lock().unwrap();
        assert!(sent.is_empty());
    }
}
