//! OP_RETURN preimage scanner.
//!
//! Scans new blocks for OP_RETURN outputs that publish payment preimages
//! of in-flight HTLCs (per bLIP-17 "Dealing with problems"). This protects
//! host funds when a client fulfills an HTLC on-chain instead of through
//! the normal protocol.

use crate::node::NodeActions;
use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::consensus::encode::deserialize;
use bitcoin::{Block, ScriptBuf};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};

/// Scan a block's transactions for OP_RETURN-published preimages.
///
/// Returns the set of preimages found (32-byte values).
pub fn scan_block_for_preimages(
    block_hex: &str,
    inflight_hashes: &HashSet<[u8; 32]>,
) -> Vec<[u8; 32]> {
    let Ok(bytes) = hex::decode(block_hex) else {
        return Vec::new();
    };
    let Ok(block) = deserialize::<Block>(&bytes) else {
        return Vec::new();
    };

    let mut found = Vec::new();
    for tx in block.txdata {
        for output in tx.output {
            scan_script_for_preimages(&output.script_pubkey, inflight_hashes, &mut found);
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

fn scan_script_for_preimages(
    script: &ScriptBuf,
    inflight_hashes: &HashSet<[u8; 32]>,
    found: &mut Vec<[u8; 32]>,
) {
    if script.as_bytes().first().copied() != Some(OP_RETURN.to_u8()) {
        return;
    }
    for candidate in pushed_32_byte_values(&script.as_bytes()[1..]) {
        let hash: [u8; 32] = Sha256::digest(candidate).into();
        if inflight_hashes.contains(&hash) {
            let mut preimage = [0u8; 32];
            preimage.copy_from_slice(candidate);
            found.push(preimage);
        }
    }
}

fn pushed_32_byte_values(mut script: &[u8]) -> Vec<&[u8]> {
    let mut values = Vec::new();
    while let Some((&opcode, rest)) = script.split_first() {
        script = rest;
        let len = match opcode {
            0x01..=0x4b => opcode as usize,
            0x4c => {
                let Some((&len, rest)) = script.split_first() else {
                    break;
                };
                script = rest;
                len as usize
            }
            0x4d => {
                if script.len() < 2 {
                    break;
                }
                let len = u16::from_le_bytes([script[0], script[1]]) as usize;
                script = &script[2..];
                len
            }
            0x4e => {
                if script.len() < 4 {
                    break;
                }
                let len = u32::from_le_bytes([script[0], script[1], script[2], script[3]]) as usize;
                script = &script[4..];
                len
            }
            _ => continue,
        };
        if script.len() < len {
            break;
        }
        let data = &script[..len];
        script = &script[len..];
        if data.len() == 32 {
            values.push(data);
        } else if data.len().is_multiple_of(32) {
            values.extend(data.chunks_exact(32));
        }
    }
    values
}

/// The preimage scanner periodically polls for new blocks and scans them.
pub struct PreimageScanner {
    pub node: std::sync::Arc<dyn NodeActions>,
    pub last_scanned_height: AtomicU32,
    pub inflight_hashes: std::sync::Mutex<HashSet<[u8; 32]>>,
}

impl PreimageScanner {
    pub fn new(node: std::sync::Arc<dyn NodeActions>) -> Self {
        Self {
            node,
            last_scanned_height: AtomicU32::new(0),
            inflight_hashes: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// Register a payment hash to watch for.
    pub fn watch(&self, payment_hash: [u8; 32]) {
        self.inflight_hashes.lock().unwrap().insert(payment_hash);
    }

    /// Unregister a payment hash.
    pub fn unwatch(&self, payment_hash: &[u8; 32]) {
        self.inflight_hashes.lock().unwrap().remove(payment_hash);
    }

    /// Run one scan iteration.
    pub async fn scan_once(&self) -> Vec<[u8; 32]> {
        let current_height = match self.node.get_block_height().await {
            Ok(h) => h,
            Err(_) => return vec![],
        };

        let last_scanned_height = self.last_scanned_height.load(Ordering::Relaxed);
        if current_height <= last_scanned_height {
            return vec![];
        }

        let inflight_hashes = self.inflight_hashes.lock().unwrap().clone();
        let mut found = Vec::new();
        for height in last_scanned_height.saturating_add(1)..=current_height {
            let Ok(block_hex) = self.node.get_raw_block_by_height(height).await else {
                break;
            };
            found.extend(scan_block_for_preimages(&block_hex, &inflight_hashes));
            self.last_scanned_height.store(height, Ordering::Relaxed);
        }
        found.sort_unstable();
        found.dedup();
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::blockdata::script::Builder;
    use bitcoin::blockdata::transaction;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::hashes::Hash;
    use bitcoin::{
        Amount, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode,
        TxOut, Witness,
    };

    #[test]
    fn scan_empty_block() {
        let hashes = HashSet::new();
        let result = scan_block_for_preimages("00000000", &hashes);
        assert!(result.is_empty());
    }

    #[test]
    fn scan_op_return_preimage() {
        let preimage = [0x42u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        let mut hashes = HashSet::new();
        hashes.insert(hash);
        let block = block_with_op_return(&preimage);

        let result = scan_block_for_preimages(&serialize_hex(&block), &hashes);

        assert_eq!(result, vec![preimage]);
    }

    #[tokio::test]
    async fn scan_once_fetches_new_blocks() {
        let secp = secp256k1::Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let node = std::sync::Arc::new(crate::node::MockNode::new(0, pk, "regtest"));
        let scanner = PreimageScanner::new(node.clone());
        let preimage = [0x24u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        scanner.watch(hash);
        node.set_raw_block(1, serialize_hex(&block_with_op_return(&preimage)));
        node.set_block_height(1);

        let result = scanner.scan_once().await;

        assert_eq!(result, vec![preimage]);
        assert_eq!(scanner.last_scanned_height.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn watch_and_unwatch() {
        let secp = secp256k1::Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let node = std::sync::Arc::new(crate::node::MockNode::new(700_000, pk, "regtest"));
        let scanner = PreimageScanner::new(node);

        let hash = [0xAAu8; 32];
        scanner.watch(hash);
        assert!(scanner.inflight_hashes.lock().unwrap().contains(&hash));

        scanner.unwatch(&hash);
        assert!(!scanner.inflight_hashes.lock().unwrap().contains(&hash));
    }

    fn block_with_op_return(preimage: &[u8; 32]) -> Block {
        let script_pubkey = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(preimage)
            .into_script();
        Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![Transaction {
                version: transaction::Version(2),
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::ZERO,
                    script_pubkey,
                }],
            }],
        }
    }
}
