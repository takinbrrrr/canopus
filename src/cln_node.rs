//! CLN RPC-backed [`NodeActions`] implementation.

use async_trait::async_trait;
use bytes::Bytes;
use cln_rpc::ClnRpc;
use secp256k1::PublicKey;
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::node::{HtlcResolution, NodeActions, NodeError, NodeInfo, NodeResult, PaymentStatus};

#[derive(Clone)]
pub struct ClnNode {
    rpc: Arc<Mutex<ClnRpc>>,
    pub node_id: PublicKey,
    pub pending_resolutions: Arc<Mutex<HashMap<String, HtlcResolution>>>,
}

impl ClnNode {
    pub async fn new(path: impl AsRef<Path>, node_id: PublicKey) -> anyhow::Result<Self> {
        let rpc = ClnRpc::new(path).await?;
        Ok(Self::from_rpc(Arc::new(Mutex::new(rpc)), node_id))
    }

    pub fn from_rpc(rpc: Arc<Mutex<ClnRpc>>, node_id: PublicKey) -> Self {
        Self {
            rpc,
            node_id,
            pending_resolutions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn take_resolution(&self, key: &str) -> Option<HtlcResolution> {
        self.pending_resolutions.lock().await.remove(key)
    }

    async fn call(&self, method: &str, params: serde_json::Value) -> NodeResult<serde_json::Value> {
        let mut rpc = self.rpc.lock().await;
        rpc.call_raw(method, &params)
            .await
            .map_err(|e| NodeError::Rpc(e.message))
    }

    async fn peer_for_scid(&self, scid: u64) -> NodeResult<PublicKey> {
        let response = self.call("listpeers", json!({})).await?;
        let peers = response
            .get("peers")
            .and_then(|v| v.as_array())
            .ok_or_else(|| NodeError::Rpc("listpeers missing peers array".into()))?;
        for peer in peers {
            let Some(id) = peer.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(channels) = peer.get("channels").and_then(|v| v.as_array()) else {
                continue;
            };
            for channel in channels {
                let short_channel_id = channel
                    .get("short_channel_id")
                    .or_else(|| channel.get("alias"))
                    .and_then(|v| v.as_str());
                if short_channel_id == Some(&scid.to_string()) {
                    return PublicKey::from_str(id).map_err(|e| NodeError::Rpc(e.to_string()));
                }
            }
        }
        Err(NodeError::NotFound(format!("peer for scid {scid}")))
    }
}

#[async_trait]
impl NodeActions for ClnNode {
    async fn send_custom_msg(&self, peer_pubkey: &PublicKey, msg_bytes: Bytes) -> NodeResult<()> {
        self.call(
            "sendcustommsg",
            json!({
                "node_id": peer_pubkey.to_string(),
                "msg": hex::encode(msg_bytes),
            }),
        )
        .await?;
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
        let first_peer = self.peer_for_scid(first_scid).await?;
        self.call(
            "sendonion",
            json!({
                "onion": hex::encode(onion),
                "payment_hash": hex::encode(payment_hash),
                "label": label,
                "groupid": group_id,
                "partid": part_id,
                "first_hop": {
                    "id": first_peer.to_string(),
                    "amount_msat": format!("{first_amount_msat}msat"),
                    "delay": first_delay,
                }
            }),
        )
        .await?;
        Ok(())
    }

    async fn inspect_outgoing_payment(&self, label: &str) -> NodeResult<PaymentStatus> {
        let response = self.call("listsendpays", json!({ "label": label })).await?;
        let Some(pays) = response.get("payments").and_then(|v| v.as_array()) else {
            return Ok(PaymentStatus::Pending);
        };
        for payment in pays {
            match payment.get("status").and_then(|v| v.as_str()) {
                Some("complete") => {
                    let preimage_hex = payment
                        .get("payment_preimage")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            NodeError::Rpc("complete sendpay missing preimage".into())
                        })?;
                    let bytes =
                        hex::decode(preimage_hex).map_err(|e| NodeError::Rpc(e.to_string()))?;
                    let preimage: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| NodeError::Rpc("preimage is not 32 bytes".into()))?;
                    return Ok(PaymentStatus::Succeeded { preimage });
                }
                Some("failed") => {
                    let onion = payment
                        .get("erroronion")
                        .or_else(|| payment.get("onionreply"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let bytes = hex::decode(onion).unwrap_or_default();
                    return Ok(PaymentStatus::Failed {
                        failure_onion: Bytes::from(bytes),
                    });
                }
                _ => {}
            }
        }
        Ok(PaymentStatus::Pending)
    }

    async fn get_block_height(&self) -> NodeResult<u32> {
        let response = self.call("getinfo", json!({})).await?;
        response
            .get("blockheight")
            .and_then(|v| v.as_u64())
            .map(|h| h as u32)
            .ok_or_else(|| NodeError::Rpc("getinfo missing blockheight".into()))
    }

    async fn get_raw_block_by_height(&self, height: u32) -> NodeResult<String> {
        let response = self
            .call("getrawblockbyheight", json!({ "height": height }))
            .await?;
        response
            .get("block")
            .or_else(|| response.get("hex"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string)
            .ok_or_else(|| NodeError::Rpc("getrawblockbyheight missing block hex".into()))
    }

    async fn new_address(&self) -> NodeResult<String> {
        let response = self.call("newaddr", json!({})).await?;
        response
            .get("bech32")
            .or_else(|| response.get("p2tr"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| NodeError::Rpc("newaddr returned no address".into()))
    }

    async fn resolve_htlc(&self, result_key: &str, resolution: HtlcResolution) -> NodeResult<()> {
        self.pending_resolutions
            .lock()
            .await
            .insert(result_key.to_string(), resolution);
        Ok(())
    }

    async fn get_info(&self) -> NodeResult<NodeInfo> {
        let response = self.call("getinfo", json!({})).await?;
        let network = response
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let block_height = response
            .get("blockheight")
            .and_then(|v| v.as_u64())
            .unwrap_or_default() as u32;
        Ok(NodeInfo {
            network,
            chain_hash: [0; 32],
            block_height,
            our_pubkey: self.node_id,
        })
    }

    async fn store_preimage(&self, payment_hash: &[u8; 32], preimage: &[u8; 32]) -> NodeResult<()> {
        self.call(
            "datastore",
            json!({
                "key": ["canopusd", "preimages", hex::encode(payment_hash)],
                "hex": hex::encode(preimage),
                "mode": "create-or-replace",
            }),
        )
        .await?;
        Ok(())
    }

    async fn lookup_preimage(&self, payment_hash: &[u8; 32]) -> NodeResult<Option<[u8; 32]>> {
        let response = self
            .call(
                "listdatastore",
                json!({ "key": ["canopusd", "preimages", hex::encode(payment_hash)] }),
            )
            .await?;
        let Some(entry) = response
            .get("datastore")
            .and_then(|v| v.as_array())
            .and_then(|entries| entries.first())
        else {
            return Ok(None);
        };
        let Some(hex_value) = entry.get("hex").and_then(|v| v.as_str()) else {
            return Ok(None);
        };
        let bytes = hex::decode(hex_value).map_err(|e| NodeError::Rpc(e.to_string()))?;
        let preimage = bytes
            .try_into()
            .map_err(|_| NodeError::Rpc("preimage is not 32 bytes".into()))?;
        Ok(Some(preimage))
    }

    async fn delete_preimage(&self, payment_hash: &[u8; 32]) -> NodeResult<()> {
        self.call(
            "deldatastore",
            json!({ "key": ["canopusd", "preimages", hex::encode(payment_hash)] }),
        )
        .await?;
        Ok(())
    }

    async fn notify(&self, _notification: &str, _payload: serde_json::Value) -> NodeResult<()> {
        Ok(())
    }
}
