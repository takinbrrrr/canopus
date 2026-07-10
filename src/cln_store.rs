//! CLN datastore-backed [`Store`] implementation.

use async_trait::async_trait;
use bytes::Bytes;
use cln_rpc::ClnRpc;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::store::{GenerationValue, Store, StoreError, StoreResult};

#[derive(Clone)]
pub struct ClnStore {
    rpc: Arc<Mutex<ClnRpc>>,
}

impl ClnStore {
    pub async fn new(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let rpc = ClnRpc::new(path).await?;
        Ok(Self {
            rpc: Arc::new(Mutex::new(rpc)),
        })
    }

    pub fn from_rpc(rpc: Arc<Mutex<ClnRpc>>) -> Self {
        Self { rpc }
    }

    fn key_vec(key: &[&str]) -> Vec<String> {
        key.iter().map(|s| s.to_string()).collect()
    }

    fn map_rpc_error(key: &[&str], err: cln_rpc::RpcError) -> StoreError {
        let message = err.message.to_lowercase();
        if message.contains("already exists") || message.contains("already have") {
            StoreError::AlreadyExists(Self::key_vec(key))
        } else if message.contains("generation") || message.contains("does not match") {
            StoreError::GenerationMismatch {
                expected: 0,
                actual: 0,
            }
        } else if message.contains("not found") || message.contains("no such") {
            StoreError::NotFound(Self::key_vec(key))
        } else {
            StoreError::Backend(err.message)
        }
    }

    async fn datastore_call(
        &self,
        key: &[&str],
        hex: Option<String>,
        mode: &str,
        generation: Option<u64>,
    ) -> StoreResult<serde_json::Value> {
        let params = json!({
            "key": Self::key_vec(key),
            "hex": hex,
            "mode": mode,
            "generation": generation,
        });
        let mut rpc = self.rpc.lock().await;
        rpc.call_raw("datastore", &params)
            .await
            .map_err(|e| Self::map_rpc_error(key, e))
    }
}

#[async_trait]
impl Store for ClnStore {
    async fn get(&self, key: &[&str]) -> StoreResult<GenerationValue> {
        let params = json!({ "key": Self::key_vec(key) });
        let mut rpc = self.rpc.lock().await;
        let response: serde_json::Value = rpc
            .call_raw("listdatastore", &params)
            .await
            .map_err(|e| Self::map_rpc_error(key, e))?;

        let entries = response
            .get("datastore")
            .and_then(|v| v.as_array())
            .ok_or_else(|| StoreError::Backend("listdatastore missing datastore array".into()))?;
        let entry = entries
            .iter()
            .find(|entry| {
                entry
                    .get("key")
                    .and_then(|v| v.as_array())
                    .map(|parts| {
                        parts
                            .iter()
                            .filter_map(|p| p.as_str())
                            .eq(key.iter().copied())
                    })
                    .unwrap_or(false)
            })
            .ok_or_else(|| StoreError::NotFound(Self::key_vec(key)))?;

        let hex = entry
            .get("hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| StoreError::Backend("datastore entry missing hex".into()))?;
        let bytes = hex::decode(hex).map_err(|e| StoreError::Backend(e.to_string()))?;
        let generation = entry
            .get("generation")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        Ok(GenerationValue {
            generation,
            bytes: Bytes::from(bytes),
        })
    }

    async fn exists(&self, key: &[&str]) -> StoreResult<bool> {
        match self.get(key).await {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn create(&self, key: &[&str], value: &[u8]) -> StoreResult<()> {
        self.datastore_call(key, Some(hex::encode(value)), "must-create", None)
            .await?;
        Ok(())
    }

    async fn update(
        &self,
        key: &[&str],
        value: &[u8],
        expected_generation: u64,
    ) -> StoreResult<()> {
        self.datastore_call(
            key,
            Some(hex::encode(value)),
            "must-replace",
            Some(expected_generation),
        )
        .await?;
        Ok(())
    }

    async fn delete(&self, key: &[&str]) -> StoreResult<()> {
        let params = json!({ "key": Self::key_vec(key) });
        let mut rpc = self.rpc.lock().await;
        rpc.call_raw::<serde_json::Value, _>("deldatastore", &params)
            .await
            .map_err(|e| Self::map_rpc_error(key, e))?;
        Ok(())
    }

    async fn list(&self, prefix: &[&str]) -> StoreResult<Vec<Vec<String>>> {
        let params = json!({ "key": Self::key_vec(prefix) });
        let mut rpc = self.rpc.lock().await;
        let response: serde_json::Value = rpc
            .call_raw("listdatastore", &params)
            .await
            .map_err(|e| Self::map_rpc_error(prefix, e))?;
        let entries = response
            .get("datastore")
            .and_then(|v| v.as_array())
            .ok_or_else(|| StoreError::Backend("listdatastore missing datastore array".into()))?;

        let mut result = Vec::new();
        for entry in entries {
            let Some(parts) = entry.get("key").and_then(|v| v.as_array()) else {
                continue;
            };
            let key_parts: Vec<String> = parts
                .iter()
                .filter_map(|p| p.as_str().map(|s| s.to_string()))
                .collect();
            if key_parts.len() <= prefix.len() {
                continue;
            }
            if key_parts
                .iter()
                .take(prefix.len())
                .map(|s| s.as_str())
                .eq(prefix.iter().copied())
            {
                let child = key_parts[..=prefix.len()].to_vec();
                if !result.contains(&child) {
                    result.push(child);
                }
            }
        }
        Ok(result)
    }
}
