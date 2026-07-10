//! Append-only accounting ledger for hosted channel HTLCs.
//!
//! Every fulfill/fail/override is recorded as a ledger event in the datastore,
//! and optionally emitted as a custom notification for other plugins to consume.

use crate::store::Store;
use serde::{Deserialize, Serialize};

/// A ledger event representing a balance change in a hosted channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEvent {
    pub seq: u64,
    pub peer_pubkey: String,
    pub event_type: LedgerEventType,
    pub amount_msat: u64,
    pub fee_msat: u64,
    pub payment_hash: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerEventType {
    /// Channel opened with initial balances.
    ChannelOpen,
    /// An HTLC was forwarded (outgoing).
    HtlcForwarded,
    /// An HTLC was fulfilled (incoming settled).
    HtlcFulfilled,
    /// An HTLC was failed.
    HtlcFailed,
    /// Channel state was overridden.
    Override,
    /// Fee earned.
    FeeEarned,
}

/// The ledger manager writes events and queries them.
pub struct LedgerManager {
    pub store: std::sync::Arc<dyn Store>,
}

impl LedgerManager {
    pub fn new(store: std::sync::Arc<dyn Store>) -> Self {
        Self { store }
    }

    /// Record a ledger event.
    pub async fn record(
        &self,
        peer_pubkey: &str,
        event_type: LedgerEventType,
        amount_msat: u64,
        fee_msat: u64,
        payment_hash: Option<&[u8; 32]>,
    ) -> Result<(), crate::store::StoreError> {
        // Get and increment the sequence number
        let meta_key = ["canopusd", "meta"];
        let (mut meta, gen) = match crate::store::get_json::<crate::store::Meta>(
            self.store.as_ref(),
            &meta_key,
        )
        .await
        {
            Ok((m, g)) => (m, g),
            Err(crate::store::StoreError::NotFound(_)) => {
                let meta = crate::store::Meta {
                    next_ledger_seq: 0,
                    current_block_height: 0,
                };
                crate::store::create_json(self.store.as_ref(), &meta_key, &meta).await?;
                (meta, 0)
            }
            Err(e) => return Err(e),
        };

        let seq = meta.next_ledger_seq;
        meta.next_ledger_seq += 1;
        crate::store::update_json(self.store.as_ref(), &meta_key, &meta, gen).await?;

        let event = LedgerEvent {
            seq,
            peer_pubkey: peer_pubkey.to_string(),
            event_type,
            amount_msat,
            fee_msat,
            payment_hash: payment_hash.map(hex::encode),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let key = [
            "canopusd".to_string(),
            "ledger".to_string(),
            seq.to_string(),
        ];
        let key_ref: Vec<&str> = key.iter().map(|s| s.as_str()).collect();
        crate::store::create_json(self.store.as_ref(), &key_ref, &event).await?;

        Ok(())
    }

    /// List all ledger events for a given peer.
    pub async fn list_events(
        &self,
        peer_pubkey: Option<&str>,
    ) -> Result<Vec<LedgerEvent>, crate::store::StoreError> {
        let children = self.store.list(&["canopusd", "ledger"]).await?;
        let mut events = Vec::new();
        for child in children {
            let key_ref: Vec<&str> = child.iter().map(|s| s.as_str()).collect();
            if let Ok((event, _)) =
                crate::store::get_json::<LedgerEvent>(self.store.as_ref(), &key_ref).await
            {
                if let Some(pk) = peer_pubkey {
                    if event.peer_pubkey != pk {
                        continue;
                    }
                }
                events.push(event);
            }
        }
        events.sort_by_key(|e| e.seq);
        Ok(events)
    }

    /// Compute the total balance for a peer's channel based on ledger events.
    pub async fn channel_balance(
        &self,
        peer_pubkey: &str,
    ) -> Result<u64, crate::store::StoreError> {
        let events = self.list_events(Some(peer_pubkey)).await?;
        let mut balance: u64 = 0;
        for event in events {
            match event.event_type {
                LedgerEventType::ChannelOpen => {
                    balance = balance.saturating_add(event.amount_msat);
                }
                LedgerEventType::HtlcFulfilled => {
                    balance = balance.saturating_add(event.amount_msat);
                }
                LedgerEventType::HtlcForwarded => {
                    balance = balance.saturating_sub(event.amount_msat);
                }
                LedgerEventType::FeeEarned => {
                    balance = balance.saturating_add(event.fee_msat);
                }
                _ => {}
            }
        }
        Ok(balance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    #[tokio::test]
    async fn record_and_list_events() {
        let store = std::sync::Arc::new(MemoryStore::new());
        let ledger = LedgerManager::new(store);

        ledger
            .record(
                "deadbeef",
                LedgerEventType::ChannelOpen,
                100_000_000,
                0,
                None,
            )
            .await
            .unwrap();

        ledger
            .record(
                "deadbeef",
                LedgerEventType::HtlcForwarded,
                10_000_000,
                100,
                Some(&[0xAA; 32]),
            )
            .await
            .unwrap();

        ledger
            .record(
                "deadbeef",
                LedgerEventType::HtlcFulfilled,
                10_000_000,
                0,
                Some(&[0xAA; 32]),
            )
            .await
            .unwrap();

        let events = ledger.list_events(Some("deadbeef")).await.unwrap();
        assert_eq!(events.len(), 3);

        let balance = ledger.channel_balance("deadbeef").await.unwrap();
        // 100M open + 10M fulfilled - 10M forwarded = 100M
        assert_eq!(balance, 100_000_000);
    }

    #[tokio::test]
    async fn events_separated_by_peer() {
        let store = std::sync::Arc::new(MemoryStore::new());
        let ledger = LedgerManager::new(store);

        ledger
            .record("aaa", LedgerEventType::ChannelOpen, 100, 0, None)
            .await
            .unwrap();
        ledger
            .record("bbb", LedgerEventType::ChannelOpen, 200, 0, None)
            .await
            .unwrap();
        ledger
            .record("aaa", LedgerEventType::FeeEarned, 0, 50, None)
            .await
            .unwrap();

        let aaa_events = ledger.list_events(Some("aaa")).await.unwrap();
        assert_eq!(aaa_events.len(), 2);
        let bbb_events = ledger.list_events(Some("bbb")).await.unwrap();
        assert_eq!(bbb_events.len(), 1);
        let all_events = ledger.list_events(None).await.unwrap();
        assert_eq!(all_events.len(), 3);
    }
}
