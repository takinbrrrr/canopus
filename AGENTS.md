# AGENTS.md

Guide for AI agents working on the `canopusd` codebase.

## What This Project Is

`canopusd` is a Rust plugin for Core Lightning (CLN) that implements the **HOST** side of [bLIP-17 Hosted Channels](https://github.com/lightning/blips/blob/master/blip-0017.md). It is wire-compatible with clients like [cliche](https://github.com/nbd-wtf/cliche) and the Scala-based reference host [poncho](https://github.com/nbd-wtf/poncho).

Hosted channels are custodial Lightning channels where the client trusts the host. The host signs channel state with its node key; the client verifies against the node's public key. There is no on-chain funding transaction — state is tracked entirely off-chain via signed `last_cross_signed_state` (LCSS) messages.

## Build & Test Commands

```bash
cargo build                              # debug build
cargo build --release                    # release binary at target/release/canopusd
cargo test                               # all 104 tests (84 lib + 2 main + 18 integration)
cargo test --test integration            # integration tests only
cargo clippy --all-targets -- -D warnings  # lint (must be zero warnings)
cargo audit                              # vulnerability scan
```

No `lightningd`, `bitcoind`, or JVM is available in the sandbox. All tests are mock-based (in-memory store + mock node). Real-world interop testing requires a regtest environment — see the README manual testing guide.

## Code Conventions

- **No comments in code** unless explicitly requested. Comments exist only in module-level doc-comments (`//!`) and on non-obvious protocol-specific logic (sighash field order, reversal semantics, etc.).
- **Clippy is law**: `cargo clippy --all-targets -- -D warnings` must pass with zero warnings before any commit.
- **Checked arithmetic**: all millisatoshi (`u64`) operations use `checked_add`/`checked_sub` — never bare `+`/`-` on amounts. Overflow returns an error.
- **Persist before side effects**: channel state is written to the datastore (with generation CAS) *before* sending any messages or resolving HTLCs. This is the most critical safety invariant.
- **Tests use `Arc<MockNode>`**: the `MockNode` records all sent messages, sent onions, HTLC resolutions, and notifications for later inspection. When asserting on `MockNode` fields, scope the `MutexGuard` in a block to avoid holding it across `.await` points (clippy catches this, but be aware).
- **`Bytes` from the `bytes` crate**: used for all binary data. It doesn't implement `PartialEq<[u8; N]>`, so use `.as_ref()` for comparisons in tests.
- **Serde for `[u8; N]` arrays**: arrays like `[u8; 32]` and `[u8; 64]` don't auto-derive `Serialize`/`Deserialize`. Use the custom `serde_bytes_hex` (in `wire/codecs.rs`) for `Bytes` fields and `serde_array_hex_32`/`serde_array_hex_64` (in `wire/lcss.rs` and `store.rs`) for fixed arrays.

## Architecture

```
src/
  lib.rs          Library root (re-exports all modules for integration tests)
  main.rs         Binary entry: cln-plugin Builder, options, hooks, RPC methods, PluginState
  config.rs       Config, ChannelPolicy, Branding, ChannelSecret (one-time, constant-time compare)
  keys.rs         NodeKeys: reads hsm_secret, HKDF-SHA256(salt=0x00, info="nodeid") → node keypair
  channel_id.rs   Deterministic channel_id (SHA256 of sorted pubkey concat) and fake scid
  state.rs        StateManager: pure-functional fold of uncommitted updates → next LCSS
  store.rs        Store trait (object-safe) + MemoryStore + free functions (get_json, cas_json, etc.)
  cln_node.rs     CLN RPC-backed NodeActions implementation
  cln_store.rs    CLN datastore-backed Store implementation
  gossip.rs       Signed BOLT-7 channel_update construction for hosted fake scids
  node.rs         NodeActions trait (send_custom_msg, send_onion, resolve_htlc, raw blocks, etc.) + MockNode
  channel.rs      ChannelController: the main state machine (establishment, reconnect, HTLC, errors, override)
  wire/
    mod.rs        HostedMessage enum, tag dispatch, all message structs
    codecs.rs     Primitive read/write (BE for wire, LE for sighash), UpdateAddHtlc, serde helpers
    lcss.rs       LastCrossSignedState: encode/decode, reverse(), hosted_sig_hash(), sign/verify
  sphinx.rs       BOLT-4 Sphinx: peel_onion, wrap_failure, TLV parsing, ECDH, ChaCha20, blinding
  htlc.rs         HtlcManager: htlc_accepted hook → channel dispatch, sendpay result → upstream resolve
  ledger.rs       LedgerManager: append-only event log in datastore + custom notifications
  scanner.rs      PreimageScanner: raw block OP_RETURN preimage scanning
tests/
  integration.rs  18 tests covering full channel lifecycle with mock node + memory store
```

## Key Design Decisions (confirmed with user)

1. **Node key access**: reads `hsm_secret` directly and derives the node key via HKDF. Plain, mnemonic, and passphrase-protected CLN secret formats are supported. Passphrase-protected secrets start the plugin locked; unlock with `canopusd-unlock passphrase_file=...` or the less secure direct `passphrase=...`. No CLN RPC can produce the needed signatures. The key/passphrase buffers are zeroized where practical.
2. **Secrets**: one-time use, persisted in datastore, consumed atomically via generation CAS. Per-secret capacity and initial balance. Constant-time comparison to prevent timing attacks.
3. **Accounting**: own append-only ledger in the datastore (not CLN's bookkeeper, which can't ingest plugin HTLCs). Emits custom notifications (`canopusd_htlc_settled`, etc.) for other plugins.
4. **Datastore generation CAS**: all writes use read(generation) → modify → update(must-replace, generation). The `cas_json` free function retries on `GenerationMismatch` up to 10 times.
5. **Feature bits**: init = {257}, node = {257}. Legacy hosted-channel feature bit 32973 is intentionally not advertised. Do not call `Builder::dynamic()`; CLN requires `dynamic: false` for plugins that advertise custom feature bits, and `cln-plugin` defaults to non-dynamic.
6. **Preimage scanner**: raw blocks are fetched through `NodeActions::get_raw_block_by_height`, deserialized with the `bitcoin` crate, and scanned for `OP_RETURN <32-byte-preimage>` pushes matching watched payment hashes.
7. **Direct `pay` interception**: the `rpc_command` hook parses BOLT11 invoices, detects single-hop hosted route hints, sends direct hosted HTLCs, and returns a CLN-compatible pay result when the hosted peer fulfills. It still needs live cliche/CLN validation.

## Sighash Algorithm (critical for interop)

The `hosted_sig_hash` in `wire/lcss.rs` must match the scoin reference (`HostedChannelMessages.scala`) exactly. The signed material is the concatenation of:

1. `refund_scriptpubkey` (raw bytes, no length prefix)
2. `channel_capacity_msat` (u64 **little-endian**)
3. `initial_client_balance_msat` (u64 LE)
4. `block_day` (u32 LE)
5. `local_balance_msat` (u64 LE)
6. `remote_balance_msat` (u64 LE)
7. `local_updates` (u32 LE)
8. `remote_updates` (u32 LE)
9. concat of each incoming HTLC encoded as BOLT-2 `update_add_htlc` body (**big-endian** wire encoding)
10. concat of each outgoing HTLC (same encoding)
11. 1 byte `hostFlag` (1 if `is_host`, else 0)

Then `SHA256(material)`. Signatures are compact 64-byte ECDSA (non-recoverable). You sign the **reverse** of your view (the peer's view). Verify checks the peer's signature over **your** view.

## What's Complete

- Wire codecs for all bLIP-17 message types plus poncho-compatible `resize_channel`, preimage query/reply, and legacy `tag || len || body` inbound framing (tested)
- LCSS with `reverse()`, `hosted_sig_hash()`, `sign()`, `verify_remote_sig()` (cross-sign consistency tested)
- Node key derivation from hsm_secret (HKDF-SHA256, legacy plain, mnemonic passphrase/no-passphrase tested; legacy encrypted needs live CLN fixture validation)
- Datastore with generation CAS + retry + `Arc<T>` blanket impl (tested)
- StateManager: folds add/fulfill/fail/fail_malformed updates, checked arithmetic, preimage verification (tested)
- ChannelController: establishment, reconnect LCSS reconciliation, normal operation, sendpay result handling, hosted-to-hosted forwarding, errors, `state_override` reset, poncho-compatible resize authorization, runtime policy persistence, preimage query/reply, secrets (add/consume/remove/list), branding, list channels, HTLC add from hook (tested)
- Sphinx onion: peel, failure wrap, ECDH, blinding, TLV parsing, varint (unit tested)
- HtlcManager: htlc_accepted dispatch, persisted forward links with payment hash/shared secret, payment result resolution, startup grace period
- LedgerManager: record events, list by peer, balance computation (tested)
- PreimageScanner: raw block deserialization and OP_RETURN preimage matching (tested)
- ClnStore and ClnNode: production CLN RPC/datastore adapters compile and are exercised through abstractions in mock tests; live CLN validation still required
- Plugin bootstrap: 14 CLN options, feature bits, hooks (custommsg, htlc_accepted, rpc_command), sendpay subscriptions, RPC methods, connect/disconnect subscriptions
- Integration tests: 18 tests covering full lifecycle

## What's Incomplete / Production Validation

No `TODO` or `stub` markers are expected in `src/`. Current known gaps are external validation or deliberately scoped features:

1. **Live CLN/regtest validation**: `ClnStore`, `ClnNode`, production handler wiring, hook request/response JSON shapes, notifications, and datastore generation behavior compile but still need testing against real `lightningd`/`bitcoind`.
2. **Full direct hosted `pay` interception**: `rpc_command` is registered and returns `continue` for `pay`. Full poncho-style direct hosted payments require BOLT11 parsing, route-hint matching, final-hop onion creation, and direct hosted HTLC result handling.
3. **Interop hardening**: run against `cliche` and/or poncho-compatible clients to validate legacy framing, resize semantics, channel updates, failure wrapping, and HTLC replay behavior on restart.
4. **Hosted-to-hosted forwarding edge cases**: persisted `ForwardLink`s include payment hash and optional shared secret, and mock tests cover basic resolution/failure wrapping. More restart and multi-channel tests should be added when live interop is available.

## Testing Patterns

- **Unit tests** live in `#[cfg(test)] mod tests` at the bottom of each module. They test pure logic (codecs, sighash, state folding, config validation).
- **Integration tests** live in `tests/integration.rs`. They use `make_harness()` which creates a `ChannelController` with `MemoryStore` + `MockNode`, and a fresh keypair for a simulated client.
- The `establish_channel()` helper in integration tests performs the full invoke → init → state_update handshake and returns the host's LCSS. Reuse it.
- To inspect messages sent to the peer, use `node.sent_messages.lock().unwrap()` — always scope in a block to avoid holding the guard across `.await`.
- To simulate payment results, use `node.set_payment_result(label, PaymentStatus::Succeeded { preimage })`.
