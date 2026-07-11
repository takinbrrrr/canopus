//! State manager: folds uncommitted updates into the next LCSS.
//!
//! This is the pure-functional core of the channel state machine.
//! It holds the current committed LCSS and a list of pending updates,
//! and computes the "next" LCSS that will be committed once both parties
//! exchange `state_update` messages.

use crate::store::{PendingUpdate, UncommittedUpdate};

use crate::wire::lcss::LastCrossSignedState;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("balance would go negative: {0} - {1}")]
    NegativeBalance(u64, u64),
    #[error("max accepted HTLCs exceeded")]
    TooManyHtlcs,
    #[error("max HTLC value in flight exceeded: {0} > {1}")]
    MaxInFlightExceeded(u64, u64),
    #[error("HTLC below minimum: {0} < {1}")]
    BelowMinimum(u64, u64),
    #[error("update counter mismatch: expected local={expected_local} remote={expected_remote}, got local={got_local} remote={got_remote}")]
    CounterMismatch {
        expected_local: u32,
        expected_remote: u32,
        got_local: u32,
        got_remote: u32,
    },
    #[error("block day mismatch: expected {expected}, got {got}")]
    BlockDayMismatch { expected: u32, got: u32 },
    #[error("signature verification failed")]
    BadSignature,
    #[error("channel is errored, cannot accept updates")]
    Errored,
    #[error("HTLC not found: id={0}")]
    HtlcNotFound(u64),
    #[error("preimage does not match payment hash")]
    WrongPreimage,
    #[error("arithmetic overflow")]
    Overflow,
}

pub type StateResult<T> = Result<T, StateError>;

/// The state manager holds the committed LCSS and uncommitted updates.
#[derive(Debug, Clone)]
pub struct StateManager {
    pub lcss: LastCrossSignedState,
    pub uncommitted: Vec<UncommittedUpdate>,
}

impl StateManager {
    pub fn new(lcss: LastCrossSignedState) -> Self {
        Self {
            lcss,
            uncommitted: Vec::new(),
        }
    }

    /// The number of local updates in the next (uncommitted) state.
    pub fn next_local_updates(&self) -> u32 {
        self.lcss.local_updates
            + self
                .uncommitted
                .iter()
                .filter(|u| matches!(u, UncommittedUpdate::Local(_)))
                .count() as u32
    }

    /// The number of remote updates in the next (uncommitted) state.
    pub fn next_remote_updates(&self) -> u32 {
        self.lcss.remote_updates
            + self
                .uncommitted
                .iter()
                .filter(|u| matches!(u, UncommittedUpdate::Remote(_)))
                .count() as u32
    }

    /// Compute the next LCSS by folding all uncommitted updates.
    /// Does NOT sign the result — caller must sign before sending.
    pub fn lcss_next(&self) -> StateResult<LastCrossSignedState> {
        let mut next = self.lcss.clone();
        next.local_updates = 0;
        next.remote_updates = 0;

        for update in &self.uncommitted {
            match update {
                UncommittedUpdate::Local(PendingUpdate::Add { htlc }) => {
                    // Local add: our balance decreases, incoming HTLC added
                    next.local_balance_msat = next
                        .local_balance_msat
                        .checked_sub(htlc.amount_msat)
                        .ok_or(StateError::NegativeBalance(
                            next.local_balance_msat,
                            htlc.amount_msat,
                        ))?;
                    next.outgoing_htlcs.push(htlc.clone());
                    next.local_updates += 1;
                }
                UncommittedUpdate::Remote(PendingUpdate::Add { htlc }) => {
                    // Remote add: their balance decreases, incoming (to us) HTLC added
                    next.remote_balance_msat = next
                        .remote_balance_msat
                        .checked_sub(htlc.amount_msat)
                        .ok_or(StateError::NegativeBalance(
                            next.remote_balance_msat,
                            htlc.amount_msat,
                        ))?;
                    next.incoming_htlcs.push(htlc.clone());
                    next.remote_updates += 1;
                }
                UncommittedUpdate::Local(PendingUpdate::Fulfill { id, preimage, .. }) => {
                    // We fulfill an incoming HTLC (from remote): remove it,
                    // add amount to our balance, add preimage to remote's outgoing
                    let pos = next
                        .incoming_htlcs
                        .iter()
                        .position(|h| h.htlc_id() == *id)
                        .ok_or(StateError::HtlcNotFound(*id))?;
                    let htlc = next.incoming_htlcs.remove(pos);
                    // Verify preimage
                    let hash = {
                        use sha2::Digest;
                        let mut h = sha2::Sha256::new();
                        h.update(preimage);
                        h.finalize()
                    };
                    if hash.as_slice() != htlc.payment_hash.as_slice() {
                        return Err(StateError::WrongPreimage);
                    }
                    next.local_balance_msat = next
                        .local_balance_msat
                        .checked_add(htlc.amount_msat)
                        .ok_or(StateError::Overflow)?;
                    next.local_updates += 1;
                }
                UncommittedUpdate::Remote(PendingUpdate::Fulfill { id, preimage, .. }) => {
                    // Remote fulfills an outgoing HTLC (from us): remove it,
                    // add amount to their balance
                    let pos = next
                        .outgoing_htlcs
                        .iter()
                        .position(|h| h.htlc_id() == *id)
                        .ok_or(StateError::HtlcNotFound(*id))?;
                    let htlc = next.outgoing_htlcs.remove(pos);
                    let hash = {
                        use sha2::Digest;
                        let mut h = sha2::Sha256::new();
                        h.update(preimage);
                        h.finalize()
                    };
                    if hash.as_slice() != htlc.payment_hash.as_slice() {
                        return Err(StateError::WrongPreimage);
                    }
                    next.remote_balance_msat = next
                        .remote_balance_msat
                        .checked_add(htlc.amount_msat)
                        .ok_or(StateError::Overflow)?;
                    next.remote_updates += 1;
                }
                UncommittedUpdate::Local(PendingUpdate::Fail { id, .. }) => {
                    // We fail an incoming HTLC: remove it, refund to remote
                    let pos = next
                        .incoming_htlcs
                        .iter()
                        .position(|h| h.htlc_id() == *id)
                        .ok_or(StateError::HtlcNotFound(*id))?;
                    let htlc = next.incoming_htlcs.remove(pos);
                    next.remote_balance_msat = next
                        .remote_balance_msat
                        .checked_add(htlc.amount_msat)
                        .ok_or(StateError::Overflow)?;
                    next.local_updates += 1;
                }
                UncommittedUpdate::Remote(PendingUpdate::Fail { id, .. }) => {
                    // Remote fails an outgoing HTLC: remove it, refund to us
                    let pos = next
                        .outgoing_htlcs
                        .iter()
                        .position(|h| h.htlc_id() == *id)
                        .ok_or(StateError::HtlcNotFound(*id))?;
                    let htlc = next.outgoing_htlcs.remove(pos);
                    next.local_balance_msat = next
                        .local_balance_msat
                        .checked_add(htlc.amount_msat)
                        .ok_or(StateError::Overflow)?;
                    next.remote_updates += 1;
                }
                UncommittedUpdate::Local(PendingUpdate::FailMalformed { id, .. }) => {
                    let pos = next
                        .incoming_htlcs
                        .iter()
                        .position(|h| h.htlc_id() == *id)
                        .ok_or(StateError::HtlcNotFound(*id))?;
                    let htlc = next.incoming_htlcs.remove(pos);
                    next.remote_balance_msat = next
                        .remote_balance_msat
                        .checked_add(htlc.amount_msat)
                        .ok_or(StateError::Overflow)?;
                    next.local_updates += 1;
                }
                UncommittedUpdate::Remote(PendingUpdate::FailMalformed { id, .. }) => {
                    let pos = next
                        .outgoing_htlcs
                        .iter()
                        .position(|h| h.htlc_id() == *id)
                        .ok_or(StateError::HtlcNotFound(*id))?;
                    let htlc = next.outgoing_htlcs.remove(pos);
                    next.local_balance_msat = next
                        .local_balance_msat
                        .checked_add(htlc.amount_msat)
                        .ok_or(StateError::Overflow)?;
                    next.remote_updates += 1;
                }
            }
        }

        next.local_updates = self.next_local_updates();
        next.remote_updates = self.next_remote_updates();
        next.block_day = self.lcss.block_day;

        Ok(next)
    }

    /// Add a local update (we initiated it).
    pub fn add_local(&mut self, update: PendingUpdate) {
        self.uncommitted.push(UncommittedUpdate::Local(update));
    }

    /// Add a remote update (peer initiated it).
    pub fn add_remote(&mut self, update: PendingUpdate) {
        self.uncommitted.push(UncommittedUpdate::Remote(update));
    }

    /// Commit: replace the current LCSS with the folded next state and clear
    /// uncommitted updates.
    pub fn commit(&mut self, lcss: LastCrossSignedState) {
        self.lcss = lcss;
        self.uncommitted.clear();
    }

    /// Clear uncommitted updates without committing.
    pub fn clear_uncommitted(&mut self) {
        self.uncommitted.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::codecs::UpdateAddHtlc;
    use crate::wire::lcss::InitHostedChannel;
    use bytes::Bytes;

    fn make_lcss(local_balance: u64, remote_balance: u64) -> LastCrossSignedState {
        LastCrossSignedState {
            is_host: true,
            last_refund_scriptpubkey: Bytes::from_static(&[0x00]),
            init_hosted_channel: InitHostedChannel {
                max_htlc_value_in_flight_msat: 1_000_000_000,
                htlc_minimum_msat: 1_000,
                max_accepted_htlcs: 12,
                channel_capacity_msat: 100_000_000,
                initial_client_balance_msat: 0,
                features: vec![],
            },
            block_day: 600_000,
            local_balance_msat: local_balance,
            remote_balance_msat: remote_balance,
            local_updates: 0,
            remote_updates: 0,
            incoming_htlcs: vec![],
            outgoing_htlcs: vec![],
            remote_sig_of_local: [0; 64],
            local_sig_of_remote: [0; 64],
        }
    }

    fn make_htlc(_id: u64, amount: u64, payment_hash: [u8; 32]) -> UpdateAddHtlc {
        UpdateAddHtlc {
            channel_id: [0u8; 32],
            id: _id,
            amount_msat: amount,
            payment_hash,
            cltv_expiry: 700_000,
            onion_routing_packet: Bytes::from(vec![0; 1366]),
            tlv_stream: Bytes::new(),
        }
    }

    #[test]
    fn next_state_with_local_add() {
        let lcss = make_lcss(100_000, 50_000);
        let mut sm = StateManager::new(lcss);

        sm.add_local(PendingUpdate::Add {
            htlc: make_htlc(1, 10_000, [0xAA; 32]),
        });

        let next = sm.lcss_next().unwrap();
        assert_eq!(next.local_balance_msat, 90_000);
        assert_eq!(next.remote_balance_msat, 50_000);
        assert_eq!(next.local_updates, 1);
        assert_eq!(next.remote_updates, 0);
        assert_eq!(next.outgoing_htlcs.len(), 1);
        assert_eq!(next.incoming_htlcs.len(), 0);
    }

    #[test]
    fn next_state_with_remote_add() {
        let lcss = make_lcss(100_000, 50_000);
        let mut sm = StateManager::new(lcss);

        sm.add_remote(PendingUpdate::Add {
            htlc: make_htlc(1, 10_000, [0xBB; 32]),
        });

        let next = sm.lcss_next().unwrap();
        assert_eq!(next.local_balance_msat, 100_000);
        assert_eq!(next.remote_balance_msat, 40_000);
        assert_eq!(next.local_updates, 0);
        assert_eq!(next.remote_updates, 1);
        assert_eq!(next.incoming_htlcs.len(), 1);
        assert_eq!(next.outgoing_htlcs.len(), 0);
    }

    #[test]
    fn next_state_balance_underflow_fails() {
        let lcss = make_lcss(5_000, 50_000);
        let mut sm = StateManager::new(lcss);

        sm.add_local(PendingUpdate::Add {
            htlc: make_htlc(1, 10_000, [0xAA; 32]),
        });

        assert!(sm.lcss_next().is_err());
    }

    #[test]
    fn fulfill_incoming_htlc() {
        let preimage = [0x42u8; 32];
        let payment_hash = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(preimage);
            h.finalize()
        };
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&payment_hash);

        let mut lcss = make_lcss(90_000, 10_000);
        // incoming HTLC from remote
        lcss.incoming_htlcs.push(make_htlc(1, 10_000, hash_arr));
        lcss.remote_updates = 1;
        let mut sm = StateManager::new(lcss);

        // We fulfill it
        sm.add_local(PendingUpdate::Fulfill {
            channel_id: [0u8; 32],
            id: 1,
            preimage,
        });

        let next = sm.lcss_next().unwrap();
        assert_eq!(next.local_balance_msat, 100_000);
        assert_eq!(next.incoming_htlcs.len(), 0);
        assert_eq!(next.local_updates, 1);
    }

    #[test]
    fn fulfill_wrong_preimage_fails() {
        let preimage = [0x42u8; 32];
        let wrong_preimage = [0x99u8; 32];
        let payment_hash = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(preimage);
            h.finalize()
        };
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&payment_hash);

        let mut lcss = make_lcss(90_000, 10_000);
        lcss.incoming_htlcs.push(make_htlc(1, 10_000, hash_arr));
        lcss.remote_updates = 1;
        let mut sm = StateManager::new(lcss);

        sm.add_local(PendingUpdate::Fulfill {
            channel_id: [0u8; 32],
            id: 1,
            preimage: wrong_preimage,
        });

        assert!(sm.lcss_next().is_err());
    }

    #[test]
    fn fail_incoming_htlc_refunds_remote() {
        let mut lcss = make_lcss(90_000, 10_000);
        lcss.incoming_htlcs.push(make_htlc(1, 10_000, [0xAA; 32]));
        lcss.remote_updates = 1;
        let mut sm = StateManager::new(lcss);

        sm.add_local(PendingUpdate::Fail {
            channel_id: [0u8; 32],
            id: 1,
            reason: Bytes::new(),
        });

        let next = sm.lcss_next().unwrap();
        assert_eq!(next.local_balance_msat, 90_000);
        assert_eq!(next.remote_balance_msat, 20_000);
        assert_eq!(next.incoming_htlcs.len(), 0);
    }

    #[test]
    fn fail_outgoing_htlc_refunds_local() {
        let mut lcss = make_lcss(90_000, 10_000);
        lcss.outgoing_htlcs.push(make_htlc(1, 10_000, [0xBB; 32]));
        lcss.local_updates = 1;
        let mut sm = StateManager::new(lcss);

        sm.add_remote(PendingUpdate::Fail {
            channel_id: [0u8; 32],
            id: 1,
            reason: Bytes::new(),
        });

        let next = sm.lcss_next().unwrap();
        assert_eq!(next.local_balance_msat, 100_000);
        assert_eq!(next.remote_balance_msat, 10_000);
        assert_eq!(next.outgoing_htlcs.len(), 0);
    }

    #[test]
    fn multiple_updates_fold_correctly() {
        let lcss = make_lcss(100_000, 100_000);
        let mut sm = StateManager::new(lcss);

        // Local adds an HTLC
        sm.add_local(PendingUpdate::Add {
            htlc: make_htlc(1, 10_000, [0xAA; 32]),
        });
        // Remote adds an HTLC
        sm.add_remote(PendingUpdate::Add {
            htlc: make_htlc(1, 20_000, [0xBB; 32]),
        });
        // Remote fails our HTLC
        sm.add_remote(PendingUpdate::Fail {
            channel_id: [0u8; 32],
            id: 1,
            reason: Bytes::new(),
        });

        let next = sm.lcss_next().unwrap();
        // Local: 100k - 10k (add) + 10k (fail refund) = 100k
        assert_eq!(next.local_balance_msat, 100_000);
        // Remote: 100k - 20k (add) = 80k
        assert_eq!(next.remote_balance_msat, 80_000);
        assert_eq!(next.outgoing_htlcs.len(), 0);
        assert_eq!(next.incoming_htlcs.len(), 1);
        assert_eq!(next.local_updates, 1);
        assert_eq!(next.remote_updates, 2);
    }

    #[test]
    fn commit_clears_uncommitted() {
        let lcss = make_lcss(100_000, 100_000);
        let mut sm = StateManager::new(lcss);

        sm.add_local(PendingUpdate::Add {
            htlc: make_htlc(1, 10_000, [0xAA; 32]),
        });

        let next = sm.lcss_next().unwrap();
        sm.commit(next);

        assert!(sm.uncommitted.is_empty());
        assert_eq!(sm.lcss.local_updates, 1);
    }
}
