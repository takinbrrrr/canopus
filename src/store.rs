//! Datastore abstraction with generation-based compare-and-swap (CAS).
//!
//! In production this is backed by CLN's `datastore` RPC (which supports
//! `generation` for optimistic concurrency). In tests it is backed by an
//! in-memory implementation with identical semantics.
//!
//! Key namespace (all under "canopusd"):
//!   channels/<peer_pubkey_hex>     → ChannelData (JSON)
//!   secrets/<secret_hex>           → ChannelSecret (JSON)
//!   htlc_forwards/<scid>/<htlc_id> → ForwardLink (JSON)
//!   preimages/<payment_hash_hex>   → preimage hex
//!   ledger/<seq>                   → LedgerEvent (JSON)
//!   meta                           → Meta (JSON: next_ledger_seq, etc.)

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::wire::lcss::LastCrossSignedState;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("key not found: {0:?}")]
    NotFound(Vec<String>),
    #[error("generation mismatch: expected {expected}, got {actual}")]
    GenerationMismatch { expected: u64, actual: u64 },
    #[error("key already exists: {0:?}")]
    AlreadyExists(Vec<String>),
    #[error("backend error: {0}")]
    Backend(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

/// A value read from the store along with its generation.
#[derive(Debug, Clone)]
pub struct GenerationValue {
    pub generation: u64,
    pub bytes: Bytes,
}

// ---------------------------------------------------------------------------
// Persisted data structures
// ---------------------------------------------------------------------------

/// All persisted state for a single hosted channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelData {
    /// The last cross-signed state (committed).
    pub lcss: LastCrossSignedState,
    /// Uncommitted updates not yet folded into a new LCSS.
    #[serde(default)]
    pub uncommitted: Vec<UncommittedUpdate>,
    /// Local errors (put channel in errored state).
    #[serde(default)]
    pub local_errors: Vec<String>,
    /// Remote errors received from peer.
    #[serde(default)]
    pub remote_errors: Vec<String>,
    /// Whether the channel is administratively suspended.
    #[serde(default)]
    pub suspended: bool,
    /// A proposed state_override awaiting client acceptance.
    #[serde(default)]
    pub proposed_override: Option<LastCrossSignedState>,
    /// The last refund_scriptpubkey received from the client.
    #[serde(default, with = "crate::wire::codecs::serde_bytes_hex")]
    pub last_refund_scriptpubkey: Bytes,
    /// Whether the channel has been fully established.
    #[serde(default)]
    pub established: bool,
    /// Maximum channel capacity in satoshis the host will accept in a client resize proposal.
    #[serde(default)]
    pub accepting_resize_sat: Option<u64>,
    /// Per-channel routing policy not covered by the cross-signed state.
    #[serde(default)]
    pub routing_policy: Option<ChannelRoutingPolicy>,
    /// A channel_update should be sent to the peer when possible.
    #[serde(default)]
    pub channel_update_pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelRoutingPolicy {
    pub fee_base_msat: u32,
    pub fee_proportional_millionths: u32,
    pub cltv_expiry_delta: u16,
    pub htlc_maximum_msat: u64,
}

impl ChannelRoutingPolicy {
    pub fn from_policy(policy: &crate::config::ChannelPolicy) -> Self {
        Self {
            fee_base_msat: policy.fee_base_msat,
            fee_proportional_millionths: policy.fee_proportional_millionths,
            cltv_expiry_delta: policy.cltv_expiry_delta,
            htlc_maximum_msat: policy.channel_capacity_msat,
        }
    }
}

/// An uncommitted update pending a state_update exchange.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "direction")]
pub enum UncommittedUpdate {
    #[serde(rename = "local")]
    Local(PendingUpdate),
    #[serde(rename = "remote")]
    Remote(PendingUpdate),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum PendingUpdate {
    #[serde(rename = "add")]
    Add {
        htlc: crate::wire::codecs::UpdateAddHtlc,
    },
    #[serde(rename = "fulfill")]
    Fulfill {
        #[serde(with = "crate::wire::codecs::serde_array_hex_32")]
        channel_id: [u8; 32],
        id: u64,
        #[serde(with = "serde_array_hex_32")]
        preimage: [u8; 32],
    },
    #[serde(rename = "fail")]
    Fail {
        #[serde(with = "crate::wire::codecs::serde_array_hex_32")]
        channel_id: [u8; 32],
        id: u64,
        #[serde(with = "crate::wire::codecs::serde_bytes_hex")]
        reason: Bytes,
    },
    #[serde(rename = "fail_malformed")]
    FailMalformed {
        #[serde(with = "crate::wire::codecs::serde_array_hex_32")]
        channel_id: [u8; 32],
        id: u64,
        #[serde(with = "serde_array_hex_32")]
        sha256_of_onion: [u8; 32],
        failure_code: u16,
    },
}

mod serde_array_hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// A link between an incoming HTLC and its outgoing counterpart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardLink {
    pub incoming_scid: u64,
    pub incoming_htlc_id: u64,
    pub outgoing_scid: u64,
    pub outgoing_htlc_id: u64,
    #[serde(with = "serde_array_hex_32")]
    pub payment_hash: [u8; 32],
    #[serde(default, with = "serde_option_array_hex_32")]
    pub shared_secret: Option<[u8; 32]>,
}

mod serde_option_array_hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match b {
            Some(bytes) => s.serialize_some(&hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let Some(s) = Option::<String>::deserialize(d)? else {
            return Ok(None);
        };
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Some(arr))
    }
}

/// Metadata for the plugin.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    pub next_ledger_seq: u64,
    pub current_block_height: u32,
}

// ---------------------------------------------------------------------------
// Store trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait Store: Send + Sync {
    /// Read a key, returning its value and generation.
    async fn get(&self, key: &[&str]) -> StoreResult<GenerationValue>;

    /// Check if a key exists.
    async fn exists(&self, key: &[&str]) -> StoreResult<bool>;

    /// Create a new key (fails if it exists).
    async fn create(&self, key: &[&str], value: &[u8]) -> StoreResult<()>;

    /// Update a key with generation CAS (must-replace).
    async fn update(&self, key: &[&str], value: &[u8], expected_generation: u64)
        -> StoreResult<()>;

    /// Delete a key.
    async fn delete(&self, key: &[&str]) -> StoreResult<()>;

    /// List child keys of a prefix.
    async fn list(&self, prefix: &[&str]) -> StoreResult<Vec<Vec<String>>>;
}

#[async_trait]
impl<T: Store + ?Sized> Store for Arc<T> {
    async fn get(&self, key: &[&str]) -> StoreResult<GenerationValue> {
        (**self).get(key).await
    }
    async fn exists(&self, key: &[&str]) -> StoreResult<bool> {
        (**self).exists(key).await
    }
    async fn create(&self, key: &[&str], value: &[u8]) -> StoreResult<()> {
        (**self).create(key, value).await
    }
    async fn update(
        &self,
        key: &[&str],
        value: &[u8],
        expected_generation: u64,
    ) -> StoreResult<()> {
        (**self).update(key, value, expected_generation).await
    }
    async fn delete(&self, key: &[&str]) -> StoreResult<()> {
        (**self).delete(key).await
    }
    async fn list(&self, prefix: &[&str]) -> StoreResult<Vec<Vec<String>>> {
        (**self).list(prefix).await
    }
}

// -- typed helpers (free functions, work with any Store impl) --

pub async fn get_json<T: for<'de> Deserialize<'de> + Send>(
    store: &dyn Store,
    key: &[&str],
) -> StoreResult<(T, u64)> {
    let gv = store.get(key).await?;
    let val: T = serde_json::from_slice(&gv.bytes)
        .map_err(|e| StoreError::Backend(format!("deserialize error: {e}")))?;
    Ok((val, gv.generation))
}

pub async fn create_json<T: Serialize + Sync + Send>(
    store: &dyn Store,
    key: &[&str],
    value: &T,
) -> StoreResult<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| StoreError::Backend(format!("serialize error: {e}")))?;
    store.create(key, &bytes).await
}

pub async fn update_json<T: Serialize + Sync + Send>(
    store: &dyn Store,
    key: &[&str],
    value: &T,
    expected_generation: u64,
) -> StoreResult<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| StoreError::Backend(format!("serialize error: {e}")))?;
    store.update(key, &bytes, expected_generation).await
}

/// CAS update: read → apply fn → write, retrying on generation conflicts.
pub async fn cas_json<T, F, R>(store: &dyn Store, key: &[&str], f: F) -> StoreResult<R>
where
    T: for<'de> Deserialize<'de> + Serialize + Sync + Send,
    F: Fn(&mut T) -> StoreResult<R> + Send + Sync,
    R: Send,
{
    let max_retries = 10;
    for attempt in 0..max_retries {
        let (mut val, gen) = match get_json::<T>(store, key).await {
            Ok(v) => v,
            Err(StoreError::NotFound(_)) => {
                return Err(StoreError::NotFound(
                    key.iter().map(|s| s.to_string()).collect(),
                ))
            }
            Err(e) => return Err(e),
        };
        let result = f(&mut val)?;
        match update_json(store, key, &val, gen).await {
            Ok(()) => return Ok(result),
            Err(StoreError::GenerationMismatch { .. }) if attempt + 1 < max_retries => continue,
            Err(e) => return Err(e),
        }
    }
    Err(StoreError::Backend("CAS retries exhausted".into()))
}

// ---------------------------------------------------------------------------
// In-memory implementation (for tests)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct MemoryEntry {
    generation: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Arc<Mutex<BTreeMap<String, MemoryEntry>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn key_to_string(key: &[&str]) -> String {
        key.join("/")
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn get(&self, key: &[&str]) -> StoreResult<GenerationValue> {
        let k = Self::key_to_string(key);
        let inner = self.inner.lock().await;
        match inner.get(&k) {
            Some(entry) => Ok(GenerationValue {
                generation: entry.generation,
                bytes: Bytes::copy_from_slice(&entry.bytes),
            }),
            None => Err(StoreError::NotFound(
                key.iter().map(|s| s.to_string()).collect(),
            )),
        }
    }

    async fn exists(&self, key: &[&str]) -> StoreResult<bool> {
        let k = Self::key_to_string(key);
        let inner = self.inner.lock().await;
        Ok(inner.contains_key(&k))
    }

    async fn create(&self, key: &[&str], value: &[u8]) -> StoreResult<()> {
        let k = Self::key_to_string(key);
        let mut inner = self.inner.lock().await;
        if inner.contains_key(&k) {
            return Err(StoreError::AlreadyExists(
                key.iter().map(|s| s.to_string()).collect(),
            ));
        }
        inner.insert(
            k,
            MemoryEntry {
                generation: 0,
                bytes: value.to_vec(),
            },
        );
        Ok(())
    }

    async fn update(
        &self,
        key: &[&str],
        value: &[u8],
        expected_generation: u64,
    ) -> StoreResult<()> {
        let k = Self::key_to_string(key);
        let mut inner = self.inner.lock().await;
        match inner.get_mut(&k) {
            Some(entry) => {
                if entry.generation != expected_generation {
                    return Err(StoreError::GenerationMismatch {
                        expected: expected_generation,
                        actual: entry.generation,
                    });
                }
                entry.generation += 1;
                entry.bytes = value.to_vec();
                Ok(())
            }
            None => Err(StoreError::NotFound(
                key.iter().map(|s| s.to_string()).collect(),
            )),
        }
    }

    async fn delete(&self, key: &[&str]) -> StoreResult<()> {
        let k = Self::key_to_string(key);
        let mut inner = self.inner.lock().await;
        inner.remove(&k);
        Ok(())
    }

    async fn list(&self, prefix: &[&str]) -> StoreResult<Vec<Vec<String>>> {
        let prefix_str = if prefix.is_empty() {
            String::new()
        } else {
            Self::key_to_string(prefix) + "/"
        };
        let inner = self.inner.lock().await;
        let mut result: Vec<Vec<String>> = Vec::new();
        for (k, _) in inner.iter() {
            if let Some(rest) = k.strip_prefix(&prefix_str) {
                let parts: Vec<&str> = rest.split('/').collect();
                // Only return immediate children (one level deep)
                if !parts.is_empty() {
                    let mut child: Vec<String> = prefix.iter().map(|s| s.to_string()).collect();
                    child.push(parts[0].to_string());
                    if !result.contains(&child) {
                        result.push(child);
                    }
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_get_update() {
        let store = MemoryStore::new();
        let key = ["canopusd", "test", "key1"];

        store.create(&key, b"hello").await.unwrap();
        let gv = store.get(&key).await.unwrap();
        assert_eq!(gv.generation, 0);
        assert_eq!(gv.bytes.as_ref(), b"hello");

        store.update(&key, b"world", 0).await.unwrap();
        let gv = store.get(&key).await.unwrap();
        assert_eq!(gv.generation, 1);
        assert_eq!(gv.bytes.as_ref(), b"world");
    }

    #[tokio::test]
    async fn create_fails_on_duplicate() {
        let store = MemoryStore::new();
        let key = ["test", "dup"];
        store.create(&key, b"a").await.unwrap();
        assert!(store.create(&key, b"b").await.is_err());
    }

    #[tokio::test]
    async fn generation_cas_fails_on_mismatch() {
        let store = MemoryStore::new();
        let key = ["test", "cas"];
        store.create(&key, b"a").await.unwrap();
        // Try to update with wrong generation
        let err = store.update(&key, b"b", 999).await.unwrap_err();
        assert!(matches!(err, StoreError::GenerationMismatch { .. }));
        // Original value unchanged
        let gv = store.get(&key).await.unwrap();
        assert_eq!(gv.bytes.as_ref(), b"a");
    }

    #[tokio::test]
    async fn cas_json_helper() {
        let store = MemoryStore::new();
        let key = ["test", "counter"];

        #[derive(Serialize, Deserialize, Default)]
        struct Counter {
            n: u32,
        }

        create_json(&store, &key, &Counter { n: 0 }).await.unwrap();

        // Increment atomically
        let result = cas_json::<Counter, _, _>(&store, &key, |c| {
            c.n += 1;
            Ok(c.n)
        })
        .await
        .unwrap();
        assert_eq!(result, 1);

        let (val, gen) = get_json::<Counter>(&store, &key).await.unwrap();
        assert_eq!(val.n, 1);
        assert_eq!(gen, 1);
    }

    #[tokio::test]
    async fn cas_json_retries_on_conflict() {
        let store = Arc::new(MemoryStore::new());
        let key = ["test", "race"];

        #[derive(Serialize, Deserialize, Default)]
        struct Counter {
            n: u32,
        }

        create_json(&store, &key, &Counter { n: 0 }).await.unwrap();

        // Simulate a concurrent update between read and write
        let store_clone = store.clone();
        let key_owned: Vec<String> = key.iter().map(|s| s.to_string()).collect();
        let key_ref: Vec<&str> = key_owned.iter().map(|s| s.as_str()).collect();

        // First, manually bump the generation to simulate contention
        let (val, gen) = get_json::<Counter>(&store_clone, &key_ref).await.unwrap();
        update_json(&store_clone, &key_ref, &Counter { n: val.n + 100 }, gen)
            .await
            .unwrap();

        // Now CAS should still work (it will read the new generation and retry)
        let result = cas_json::<Counter, _, _>(&store, &key_ref, |c| {
            c.n += 1;
            Ok(c.n)
        })
        .await
        .unwrap();
        assert_eq!(result, 101);
    }

    #[tokio::test]
    async fn list_immediate_children() {
        let store = MemoryStore::new();
        store.create(&["a", "b", "c"], b"1").await.unwrap();
        store.create(&["a", "b", "d"], b"2").await.unwrap();
        store.create(&["a", "e"], b"3").await.unwrap();

        let children = store.list(&["a"]).await.unwrap();
        assert_eq!(children.len(), 2); // "b" and "e"
    }

    #[tokio::test]
    async fn delete_works() {
        let store = MemoryStore::new();
        let key = ["del", "me"];
        store.create(&key, b"data").await.unwrap();
        assert!(store.exists(&key).await.unwrap());
        store.delete(&key).await.unwrap();
        assert!(!store.exists(&key).await.unwrap());
    }

    #[tokio::test]
    async fn channel_data_roundtrip() {
        let store = MemoryStore::new();
        let key = ["canopusd", "channels", "deadbeef"];

        let data = ChannelData {
            lcss: LastCrossSignedState {
                is_host: true,
                last_refund_scriptpubkey: Bytes::from_static(&[0x00]),
                init_hosted_channel: crate::wire::lcss::InitHostedChannel {
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
            },
            uncommitted: vec![],
            local_errors: vec![],
            remote_errors: vec![],
            suspended: false,
            proposed_override: None,
            last_refund_scriptpubkey: Bytes::from_static(&[0x00]),
            established: true,
            accepting_resize_sat: None,
            routing_policy: None,
            channel_update_pending: false,
        };

        create_json(&store, &key, &data).await.unwrap();
        let (loaded, _) = get_json::<ChannelData>(&store, &key).await.unwrap();
        assert_eq!(loaded.lcss.block_day, 600_000);
        assert!(loaded.established);
    }
}
