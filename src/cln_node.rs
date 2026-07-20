//! CLN RPC-backed [`NodeActions`] implementation.

use async_trait::async_trait;
use bytes::Bytes;
use cln_rpc::ClnRpc;
use secp256k1::PublicKey;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::channel_id::{format_short_channel_id, parse_short_channel_id};
use crate::node::{HtlcResolution, NodeActions, NodeError, NodeInfo, NodeResult, PaymentStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
struct FirstHop {
    id: PublicKey,
}

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

    async fn first_hop_for_scid(&self, scid: u64) -> NodeResult<FirstHop> {
        let scid_string = format_short_channel_id(scid);
        let response = self
            .call("listchannels", json!({ "short_channel_id": scid_string }))
            .await?;
        first_hop_from_listchannels(&self.node_id, scid, &response)
    }

    pub async fn peer_connection_states(&self) -> NodeResult<HashMap<PublicKey, bool>> {
        let response = self.call("listpeers", json!({})).await?;
        peer_connection_states_from_listpeers(&response)
    }
}

fn peer_connection_states_from_listpeers(response: &Value) -> NodeResult<HashMap<PublicKey, bool>> {
    let peers = response
        .get("peers")
        .and_then(|value| value.as_array())
        .ok_or_else(|| NodeError::Rpc("listpeers missing peers array".into()))?;
    let mut states = HashMap::new();
    for peer in peers {
        let Some(id) = peer.get("id").and_then(|value| value.as_str()) else {
            continue;
        };
        let Ok(id) = PublicKey::from_str(id) else {
            continue;
        };
        let connected = peer
            .get("connected")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        states.insert(id, connected);
    }
    Ok(states)
}

fn first_hop_from_listchannels(
    node_id: &PublicKey,
    scid: u64,
    response: &Value,
) -> NodeResult<FirstHop> {
    let channels = response
        .get("channels")
        .and_then(|v| v.as_array())
        .ok_or_else(|| NodeError::Rpc("listchannels missing channels array".into()))?;
    let node_id = node_id.to_string();
    for channel in channels {
        let short_channel_id = channel
            .get("short_channel_id")
            .and_then(|v| v.as_str())
            .and_then(parse_short_channel_id);
        if short_channel_id != Some(scid) {
            continue;
        }
        if channel.get("source").and_then(|v| v.as_str()) != Some(node_id.as_str()) {
            continue;
        }
        if channel.get("active").and_then(|v| v.as_bool()) == Some(false) {
            continue;
        }
        let destination = channel
            .get("destination")
            .and_then(|v| v.as_str())
            .ok_or_else(|| NodeError::Rpc("listchannels entry missing destination".into()))?;
        let id = PublicKey::from_str(destination).map_err(|e| NodeError::Rpc(e.to_string()))?;
        return Ok(FirstHop { id });
    }

    Err(NodeError::NotFound(format!(
        "active outgoing channel for scid {}",
        format_short_channel_id(scid)
    )))
}

fn payment_status_from_listsendpays_response(
    label: &str,
    response: &Value,
) -> NodeResult<PaymentStatus> {
    let Some(pays) = response.get("payments").and_then(|v| v.as_array()) else {
        return Ok(PaymentStatus::Unknown);
    };
    for payment in pays {
        if payment.get("label").and_then(|v| v.as_str()) != Some(label) {
            continue;
        }
        match payment.get("status").and_then(|v| v.as_str()) {
            Some("complete") => {
                let preimage_hex = payment
                    .get("payment_preimage")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| NodeError::Rpc("complete sendpay missing preimage".into()))?;
                let bytes = hex::decode(preimage_hex).map_err(|e| NodeError::Rpc(e.to_string()))?;
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
            Some("pending") => return Ok(PaymentStatus::Pending),
            _ => {}
        }
    }
    Ok(PaymentStatus::Unknown)
}

#[allow(clippy::too_many_arguments)]
fn sendonion_params(
    first_hop: &FirstHop,
    onion: &[u8],
    payment_hash: [u8; 32],
    first_amount_msat: u64,
    first_delay: u16,
    label: String,
    group_id: u64,
    part_id: u64,
) -> Value {
    json!({
        "onion": hex::encode(onion),
        "payment_hash": hex::encode(payment_hash),
        "label": label,
        "groupid": group_id,
        "partid": part_id,
        "first_hop": {
            "id": first_hop.id.to_string(),
            "amount_msat": format!("{first_amount_msat}msat"),
            "delay": first_delay,
        }
    })
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
        let first_hop = self.first_hop_for_scid(first_scid).await?;
        self.call(
            "sendonion",
            sendonion_params(
                &first_hop,
                &onion,
                payment_hash,
                first_amount_msat,
                first_delay,
                label,
                group_id,
                part_id,
            ),
        )
        .await?;
        Ok(())
    }

    async fn inspect_outgoing_payment(
        &self,
        payment_hash: &[u8; 32],
        label: &str,
    ) -> NodeResult<PaymentStatus> {
        let response = self
            .call(
                "listsendpays",
                json!({ "payment_hash": hex::encode(payment_hash) }),
            )
            .await?;
        payment_status_from_listsendpays_response(label, &response)
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
                "key": ["canopus", "preimages", hex::encode(payment_hash)],
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
                json!({ "key": ["canopus", "preimages", hex::encode(payment_hash)] }),
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
            json!({ "key": ["canopus", "preimages", hex::encode(payment_hash)] }),
        )
        .await?;
        Ok(())
    }

    async fn notify(&self, _notification: &str, _payload: serde_json::Value) -> NodeResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn pubkey(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    #[test]
    fn first_hop_uses_active_outgoing_listchannels_entry() {
        let node = pubkey(1);
        let peer = pubkey(2);
        let scid = parse_short_channel_id("5061345x3x1").unwrap();
        let response = json!({
            "channels": [
                {
                    "source": peer.to_string(),
                    "destination": node.to_string(),
                    "short_channel_id": "5061345x3x1",
                    "direction": 0,
                    "active": true
                },
                {
                    "source": node.to_string(),
                    "destination": peer.to_string(),
                    "short_channel_id": "5061345x3x1",
                    "direction": 1,
                    "active": false
                },
                {
                    "source": node.to_string(),
                    "destination": peer.to_string(),
                    "short_channel_id": "5061345x3x1",
                    "direction": 1,
                    "active": true
                }
            ]
        });

        let first_hop = first_hop_from_listchannels(&node, scid, &response).unwrap();
        assert_eq!(first_hop.id, peer);
    }

    #[test]
    fn listpeers_connection_states_include_connected_and_disconnected_peers() {
        let connected = pubkey(2);
        let disconnected = pubkey(3);
        let states = peer_connection_states_from_listpeers(&json!({
            "peers": [
                { "id": connected.to_string(), "connected": true },
                { "id": disconnected.to_string(), "connected": false }
            ]
        }))
        .unwrap();

        assert_eq!(states.get(&connected), Some(&true));
        assert_eq!(states.get(&disconnected), Some(&false));
    }

    #[test]
    fn sendonion_params_do_not_pin_first_hop_channel() {
        let peer = pubkey(2);
        let params = sendonion_params(
            &FirstHop { id: peer },
            &[1, 2, 3],
            [4; 32],
            1000,
            40,
            "label".to_string(),
            5,
            6,
        );

        let first_hop = params.get("first_hop").unwrap();
        let peer_string = peer.to_string();
        assert_eq!(
            first_hop.get("id").and_then(|v| v.as_str()),
            Some(peer_string.as_str())
        );
        assert_eq!(
            first_hop.get("amount_msat").and_then(|v| v.as_str()),
            Some("1000msat")
        );
        assert_eq!(first_hop.get("delay").and_then(|v| v.as_u64()), Some(40));
        assert!(first_hop.get("channel").is_none());
        assert!(first_hop.get("direction").is_none());
    }

    #[test]
    fn listsendpays_status_filters_by_label() {
        let response = json!({
            "payments": [
                {
                    "label": "1/1",
                    "status": "complete",
                    "payment_preimage": "1111111111111111111111111111111111111111111111111111111111111111"
                },
                {
                    "label": "2/2",
                    "status": "pending"
                }
            ]
        });

        match payment_status_from_listsendpays_response("2/2", &response).unwrap() {
            PaymentStatus::Pending => {}
            other => panic!("unexpected payment status: {other:?}"),
        }
    }

    #[test]
    fn listsendpays_status_unknown_without_matching_label() {
        let response = json!({
            "payments": [
                {
                    "label": "1/1",
                    "status": "complete",
                    "payment_preimage": "1111111111111111111111111111111111111111111111111111111111111111"
                }
            ]
        });

        match payment_status_from_listsendpays_response("2/2", &response).unwrap() {
            PaymentStatus::Unknown => {}
            other => panic!("unexpected payment status: {other:?}"),
        }
    }
}
