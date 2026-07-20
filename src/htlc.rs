//! HTLC forwarding logic.
//!
//! Connects the hosted channel state machine to CLN's HTLC hooks:
//! - Inbound: `htlc_accepted` hook → match hosted scid → add to channel
//! - Outbound: client sends `update_add_htlc` → peel onion → sendonion
//! - Settlement: sendpay_success/failure → resolve upstream HTLC

use crate::channel::ChannelController;
use crate::channel_id::hosted_short_channel_id;
use crate::node::{HtlcResolution, PaymentStatus};
use crate::sphinx;
use crate::store::{ForwardLink, Store};
use crate::wire::codecs::UpdateAddHtlc;
use bytes::Bytes;
use secp256k1::PublicKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Pending HTLC resolution — an incoming HTLC that we're processing.
#[derive(Debug, Clone)]
pub struct PendingHtlc {
    pub result_key: String,
    pub incoming_scid: u64,
    pub incoming_htlc_id: u64,
    pub amount_msat: u64,
    pub payment_hash: [u8; 32],
    pub cltv_expiry: u32,
    pub onion: Bytes,
    pub shared_secret: Option<[u8; 32]>,
}

/// The HTLC manager handles forwarding of HTLCs between CLN and hosted channels.
pub struct HtlcManager {
    pub controller: Arc<ChannelController>,
    /// Pending incoming HTLCs awaiting resolution.
    pub pending: Arc<Mutex<HashMap<String, PendingHtlc>>>,
    /// Whether we're in the startup grace period (delay HTLC processing).
    pub startup_time: std::time::Instant,
}

impl HtlcManager {
    pub fn new(controller: Arc<ChannelController>) -> Self {
        Self {
            controller,
            pending: Arc::new(Mutex::new(HashMap::new())),
            startup_time: std::time::Instant::now(),
        }
    }

    /// Check if we're still in the startup grace period.
    fn in_startup_grace(&self) -> bool {
        self.startup_time.elapsed().as_secs() < 10
    }

    /// Handle an incoming HTLC from the `htlc_accepted` hook.
    ///
    /// Returns `Some(resolution)` if we should immediately resolve it,
    /// or `None` if it's being processed asynchronously.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_htlc_accepted(
        &self,
        result_key: &str,
        incoming_scid: Option<u64>,
        amount_msat: u64,
        payment_hash: [u8; 32],
        cltv_expiry: u32,
        onion: Bytes,
        shared_secret: Option<[u8; 32]>,
    ) -> Option<HtlcResolution> {
        // During startup grace period, delay processing
        if self.in_startup_grace() {
            // Wait 3 seconds before processing
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }

        // If no incoming scid, we're the final hop — let CLN handle it
        let incoming_scid = match incoming_scid {
            Some(s) => s,
            None => return Some(HtlcResolution::Continue),
        };

        // Find which hosted channel matches this scid
        let peer_id = match self.find_channel_by_scid(incoming_scid).await {
            Some(p) => p,
            None => return Some(HtlcResolution::Continue),
        };

        // Check if we already know the preimage (idempotency after restart)
        if let Ok(Some(preimage)) = self.controller.node.lookup_preimage(&payment_hash).await {
            return Some(HtlcResolution::Resolve { preimage });
        }

        // Store the pending HTLC for async resolution
        let incoming_htlc_id = result_key
            .rsplit_once('/')
            .and_then(|(_, id)| id.parse::<u64>().ok())
            .unwrap_or_default();
        let pending_htlc = PendingHtlc {
            result_key: result_key.to_string(),
            incoming_scid,
            incoming_htlc_id,
            amount_msat,
            payment_hash,
            cltv_expiry,
            onion: onion.clone(),
            shared_secret,
        };

        // Add the HTLC to the channel
        let htlc = UpdateAddHtlc {
            channel_id: [0u8; 32], // will be assigned by channel_handle_htlc_add
            id: 0,
            amount_msat,
            payment_hash,
            cltv_expiry,
            onion_routing_packet: onion,
            tlv_stream: Bytes::new(),
        };

        match self
            .controller
            .channel_handle_htlc_add_with_upstream_expiry(
                &peer_id,
                htlc,
                result_key,
                incoming_scid,
                pending_htlc.incoming_htlc_id,
                pending_htlc.shared_secret,
                Some(cltv_expiry),
            )
            .await
        {
            Ok(_) => {
                self.pending
                    .lock()
                    .await
                    .insert(result_key.to_string(), pending_htlc);
                None // async resolution
            }
            Err(e) => {
                warn!("failed to add HTLC to channel: {}", e);
                Some(HtlcResolution::FailMessage {
                    code: 0x1007, // temporary_channel_failure
                    data: Bytes::new(),
                })
            }
        }
    }

    /// Find the peer whose hosted channel has the given short channel id.
    async fn find_channel_by_scid(&self, scid: u64) -> Option<PublicKey> {
        let channels = self.controller.list_channels().await.ok()?;
        for peer_id in channels {
            let expected_scid = hosted_short_channel_id(&self.controller.node_public, &peer_id);
            if expected_scid == scid {
                return Some(peer_id);
            }
        }
        None
    }

    /// Handle the result of an outgoing payment (sendpay_success/failure).
    pub async fn handle_payment_result(
        &self,
        outgoing_scid: u64,
        outgoing_htlc_id: u64,
        status: PaymentStatus,
    ) {
        // Look up the forward link to find the incoming HTLC
        let forward_key = ChannelController::forward_key(outgoing_scid, outgoing_htlc_id);
        let key_ref: Vec<&str> = forward_key.iter().map(|s| s.as_str()).collect();

        let (link, _gen) =
            match crate::store::get_json::<ForwardLink>(self.controller.store.as_ref(), &key_ref)
                .await
            {
                Ok(l) => l,
                Err(_) => {
                    debug!(
                        "no forward link for scid={} htlc_id={}",
                        outgoing_scid, outgoing_htlc_id
                    );
                    return;
                }
            };

        let result_key = format!("{}/{}", link.incoming_scid, link.incoming_htlc_id);

        match status {
            PaymentStatus::Succeeded { preimage } => {
                // Persist preimage before resolving
                let _ = self
                    .controller
                    .node
                    .store_preimage(&link.payment_hash(), &preimage)
                    .await;
                let _ = self
                    .controller
                    .node
                    .resolve_htlc(&result_key, HtlcResolution::Resolve { preimage })
                    .await;
                // Clean up forward link
                let _ = self.controller.store.delete(&key_ref).await;
            }
            PaymentStatus::Failed { failure_onion } => {
                let _ = self
                    .controller
                    .node
                    .resolve_htlc(&result_key, HtlcResolution::Fail { failure_onion })
                    .await;
                let _ = self.controller.store.delete(&key_ref).await;
            }
            PaymentStatus::Pending => {
                // Still waiting — do nothing
            }
            PaymentStatus::Unknown => {
                // No outgoing payment record exists.
            }
        }
    }

    /// Peel an onion from a client's update_add_htlc to determine the
    /// next hop for forwarding.
    pub fn peel_client_onion(
        &self,
        onion: &[u8],
        payment_hash: &[u8; 32],
    ) -> Result<sphinx::PeeledOnion, sphinx::SphinxError> {
        sphinx::peel_onion(&self.controller.node_secret, onion, payment_hash)
    }
}

impl ForwardLink {
    /// Get the payment hash for this forward link.
    pub fn payment_hash(&self) -> [u8; 32] {
        self.payment_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_link_payment_hash_returns_stored_hash() {
        let link = ForwardLink {
            incoming_scid: 1,
            incoming_htlc_id: 1,
            outgoing_scid: 2,
            outgoing_htlc_id: 2,
            upstream_cltv_expiry: None,
            hosted_commit_deadline_unix: None,
            payment_hash: [3; 32],
            shared_secret: Some([4; 32]),
        };
        let _ = link.payment_hash();
    }
}
