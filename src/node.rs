//! Abstract node interface — the set of operations the channel logic needs
//! from the host (CLN in production, a mock in tests).
//!
//! This abstraction allows the entire channel state machine to be unit-tested
//! without a real lightningd.

use async_trait::async_trait;
use bytes::Bytes;
use secp256k1::PublicKey;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(String),
}

pub type NodeResult<T> = Result<T, NodeError>;

/// The status of an outgoing payment (sendonion).
#[derive(Debug, Clone)]
pub enum PaymentStatus {
    /// Payment succeeded — contains the preimage.
    Succeeded { preimage: [u8; 32] },
    /// Payment failed — contains the failure onion reply.
    Failed { failure_onion: Bytes },
    /// Payment is still pending.
    Pending,
    /// No matching outgoing payment record exists.
    Unknown,
}

/// Actions the channel logic can request from the host node.
#[async_trait]
pub trait NodeActions: Send + Sync {
    /// Send a custom message to a peer (via sendcustommsg).
    async fn send_custom_msg(&self, peer_pubkey: &PublicKey, msg_bytes: Bytes) -> NodeResult<()>;

    /// Send an onion-routed payment (via sendonion).
    /// Returns immediately; results come via [`payment_result`].
    #[allow(clippy::too_many_arguments)]
    async fn send_onion(
        &self,
        onion: Bytes,
        payment_hash: [u8; 32],
        first_scid: u64,
        first_amount_msat: u64,
        first_delay: u16,
        label: String,
        group_id: u64,
        part_id: u64,
    ) -> NodeResult<()>;

    /// Look up the result of an outgoing payment by payment hash and label.
    async fn inspect_outgoing_payment(
        &self,
        payment_hash: &[u8; 32],
        label: &str,
    ) -> NodeResult<PaymentStatus>;

    /// Get the current block height.
    async fn get_block_height(&self) -> NodeResult<u32>;

    /// Get a raw block by height as hex.
    async fn get_raw_block_by_height(&self, height: u32) -> NodeResult<String>;

    /// Get a new on-chain address (for refund purposes).
    async fn new_address(&self) -> NodeResult<String>;

    /// Resolve an incoming HTLC (from htlc_accepted hook).
    /// The result_key identifies which pending hook to resolve.
    async fn resolve_htlc(&self, result_key: &str, resolution: HtlcResolution) -> NodeResult<()>;

    /// Get info about the node (network, chain hash, etc.).
    async fn get_info(&self) -> NodeResult<NodeInfo>;

    /// Persist a preimage for crash recovery.
    async fn store_preimage(&self, payment_hash: &[u8; 32], preimage: &[u8; 32]) -> NodeResult<()>;

    /// Look up a stored preimage.
    async fn lookup_preimage(&self, payment_hash: &[u8; 32]) -> NodeResult<Option<[u8; 32]>>;

    /// Delete a stored preimage.
    async fn delete_preimage(&self, payment_hash: &[u8; 32]) -> NodeResult<()>;

    /// Emit a custom notification.
    async fn notify(&self, notification: &str, payload: serde_json::Value) -> NodeResult<()>;
}

/// How to resolve an incoming HTLC.
#[derive(Debug, Clone)]
pub enum HtlcResolution {
    /// Fulfill with the given preimage.
    Resolve { preimage: [u8; 32] },
    /// Fail with the given failure onion.
    Fail { failure_onion: Bytes },
    /// Fail with a specific failure message.
    FailMessage { code: u16, data: Bytes },
    /// Let lightningd handle it normally.
    Continue,
}

/// Basic node info.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub network: String,
    pub chain_hash: [u8; 32],
    pub block_height: u32,
    pub our_pubkey: PublicKey,
}

/// A mock node for testing — records all actions for later inspection.
#[derive(Debug, Default)]
pub struct MockNode {
    pub sent_messages: std::sync::Mutex<Vec<(PublicKey, Bytes)>>,
    pub sent_onions: std::sync::Mutex<Vec<SendOnionParams>>,
    pub block_height: std::sync::atomic::AtomicU32,
    pub preimages: std::sync::Mutex<HashMap<[u8; 32], [u8; 32]>>,
    pub htlc_resolutions: std::sync::Mutex<Vec<(String, HtlcResolution)>>,
    pub notifications: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
    pub payment_results: std::sync::Mutex<HashMap<String, PaymentStatus>>,
    pub send_onion_error: std::sync::Mutex<Option<String>>,
    pub send_custom_msg_error: std::sync::Mutex<Option<String>>,
    pub send_custom_msg_fail_after: std::sync::Mutex<Option<(usize, String)>>,
    pub node_info: std::sync::Mutex<Option<NodeInfo>>,
    pub raw_blocks: std::sync::Mutex<HashMap<u32, String>>,
}

#[derive(Debug, Clone)]
pub struct SendOnionParams {
    pub onion: Bytes,
    pub payment_hash: [u8; 32],
    pub first_scid: u64,
    pub first_amount_msat: u64,
    pub first_delay: u16,
    pub label: String,
    pub group_id: u64,
    pub part_id: u64,
}

impl MockNode {
    pub fn new(block_height: u32, our_pubkey: PublicKey, network: &str) -> Self {
        let info = NodeInfo {
            network: network.to_string(),
            chain_hash: [0u8; 32], // set by caller
            block_height,
            our_pubkey,
        };
        Self {
            sent_messages: std::sync::Mutex::new(Vec::new()),
            sent_onions: std::sync::Mutex::new(Vec::new()),
            block_height: std::sync::atomic::AtomicU32::new(block_height),
            preimages: std::sync::Mutex::new(HashMap::new()),
            htlc_resolutions: std::sync::Mutex::new(Vec::new()),
            notifications: std::sync::Mutex::new(Vec::new()),
            payment_results: std::sync::Mutex::new(HashMap::new()),
            send_onion_error: std::sync::Mutex::new(None),
            send_custom_msg_error: std::sync::Mutex::new(None),
            send_custom_msg_fail_after: std::sync::Mutex::new(None),
            node_info: std::sync::Mutex::new(Some(info)),
            raw_blocks: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn set_block_height(&self, h: u32) {
        self.block_height
            .store(h, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_payment_result(&self, label: &str, status: PaymentStatus) {
        self.payment_results
            .lock()
            .unwrap()
            .insert(label.to_string(), status);
    }

    pub fn fail_next_send_onion(&self, message: impl Into<String>) {
        *self.send_onion_error.lock().unwrap() = Some(message.into());
    }

    pub fn fail_next_send_custom_msg(&self, message: impl Into<String>) {
        *self.send_custom_msg_error.lock().unwrap() = Some(message.into());
    }

    pub fn fail_send_custom_msg_after_successes(
        &self,
        successes: usize,
        message: impl Into<String>,
    ) {
        *self.send_custom_msg_fail_after.lock().unwrap() = Some((successes, message.into()));
    }

    pub fn set_raw_block(&self, height: u32, block_hex: String) {
        self.raw_blocks.lock().unwrap().insert(height, block_hex);
    }
}

#[async_trait]
impl NodeActions for MockNode {
    async fn send_custom_msg(&self, peer_pubkey: &PublicKey, msg_bytes: Bytes) -> NodeResult<()> {
        if let Some(message) = self.send_custom_msg_error.lock().unwrap().take() {
            return Err(NodeError::Rpc(message));
        }
        let mut delayed_failure = self.send_custom_msg_fail_after.lock().unwrap();
        if let Some((successes, _)) = delayed_failure.as_mut() {
            if *successes == 0 {
                let (_, message) = delayed_failure.take().unwrap();
                return Err(NodeError::Rpc(message));
            }
            *successes -= 1;
        }
        self.sent_messages
            .lock()
            .unwrap()
            .push((*peer_pubkey, msg_bytes));
        Ok(())
    }

    async fn send_onion(
        &self,
        onion: Bytes,
        payment_hash: [u8; 32],
        first_scid: u64,
        first_amount_msat: u64,
        first_delay: u16,
        label: String,
        group_id: u64,
        part_id: u64,
    ) -> NodeResult<()> {
        if let Some(message) = self.send_onion_error.lock().unwrap().take() {
            return Err(NodeError::Rpc(message));
        }
        self.sent_onions.lock().unwrap().push(SendOnionParams {
            onion,
            payment_hash,
            first_scid,
            first_amount_msat,
            first_delay,
            label,
            group_id,
            part_id,
        });
        Ok(())
    }

    async fn inspect_outgoing_payment(
        &self,
        _payment_hash: &[u8; 32],
        label: &str,
    ) -> NodeResult<PaymentStatus> {
        match self.payment_results.lock().unwrap().get(label) {
            Some(s) => Ok(s.clone()),
            None => Ok(PaymentStatus::Unknown),
        }
    }

    async fn get_block_height(&self) -> NodeResult<u32> {
        Ok(self.block_height.load(std::sync::atomic::Ordering::Relaxed))
    }

    async fn get_raw_block_by_height(&self, height: u32) -> NodeResult<String> {
        self.raw_blocks
            .lock()
            .unwrap()
            .get(&height)
            .cloned()
            .ok_or_else(|| NodeError::NotFound(format!("raw block at height {height}")))
    }

    async fn new_address(&self) -> NodeResult<String> {
        Ok("bc1qmockaddress".to_string())
    }

    async fn resolve_htlc(&self, result_key: &str, resolution: HtlcResolution) -> NodeResult<()> {
        self.htlc_resolutions
            .lock()
            .unwrap()
            .push((result_key.to_string(), resolution));
        Ok(())
    }

    async fn get_info(&self) -> NodeResult<NodeInfo> {
        self.node_info
            .lock()
            .unwrap()
            .clone()
            .ok_or(NodeError::NotFound("node_info".into()))
    }

    async fn store_preimage(&self, payment_hash: &[u8; 32], preimage: &[u8; 32]) -> NodeResult<()> {
        self.preimages
            .lock()
            .unwrap()
            .insert(*payment_hash, *preimage);
        Ok(())
    }

    async fn lookup_preimage(&self, payment_hash: &[u8; 32]) -> NodeResult<Option<[u8; 32]>> {
        Ok(self.preimages.lock().unwrap().get(payment_hash).copied())
    }

    async fn delete_preimage(&self, payment_hash: &[u8; 32]) -> NodeResult<()> {
        self.preimages.lock().unwrap().remove(payment_hash);
        Ok(())
    }

    async fn notify(&self, notification: &str, payload: serde_json::Value) -> NodeResult<()> {
        self.notifications
            .lock()
            .unwrap()
            .push((notification.to_string(), payload));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_records_sent_messages() {
        let secp = secp256k1::Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let node = MockNode::new(700_000, pk, "regtest");

        node.send_custom_msg(&pk, Bytes::from_static(b"hello"))
            .await
            .unwrap();

        let sent = node.sent_messages.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, pk);
        assert_eq!(sent[0].1.as_ref(), b"hello");
    }
}
