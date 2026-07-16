# AGENTS.md

Guide for AI agents working on the `canopus` codebase.

This file is intended to carry hard-won project context forward between sessions. Keep it accurate when behavior changes. The most important rule is to preserve protocol compatibility and funds-safety invariants before making code look cleaner.

## What This Project Is

`canopus` is a Rust plugin for Core Lightning (CLN) that implements the HOST side of bLIP-17 Hosted Channels. It is designed to interoperate with cliche, immortan, and the Scala reference host poncho.

Hosted channels are custodial Lightning-like channels. There is no on-chain funding transaction. The client trusts the host for custody, but both sides maintain an auditable off-chain state called `last_cross_signed_state` (LCSS). The host signs channel state with the CLN node key, and the client verifies against the host node pubkey.

`canopus` is not a generic Lightning node implementation. It is a CLN plugin that bridges hosted-channel peers to CLN functionality: custom messages, datastore, `htlc_accepted`, `sendonion`, `sendpay_success`/`sendpay_failure`, raw blocks, and plugin RPC methods.

## Build And Test Commands

Run these from `/workspace/canopus`.

```bash
cargo build
cargo build --release
cargo test
cargo test --test integration
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo audit
```

Current expected test shape after the latest work is approximately:

- 131 library unit tests
- 8 binary unit tests
- 43 integration tests

The exact count may change, but all tests and clippy must pass before handing off code changes. The sandbox does not provide `lightningd`, `bitcoind`, or a JVM. All normal tests are mock-based with `MemoryStore` and `MockNode`. Live cliche/immortan/poncho/CLN interop requires an external regtest environment.

## General Engineering Rules

- Clippy is law: `cargo clippy --all-targets -- -D warnings` must pass with zero warnings.
- Formatting is required: run `cargo fmt` or at least `cargo fmt --check` before finalizing.
- Use checked arithmetic for millisatoshi values. Avoid bare `+`/`-` on balances, capacities, fees, and HTLC amounts. Use `checked_add`, `checked_sub`, or saturating arithmetic only when the protocol behavior explicitly wants saturation.
- Persist state before side effects. Channel state must be written to the datastore before sending messages, resolving CLN HTLC hooks, or depending on payment outcomes.
- Prefer minimal changes. Do not introduce new abstractions unless they reduce real duplication or make a protocol rule safer.
- Do not add backward-compatibility code unless there is persisted data, shipped behavior, or external interoperability at stake. In this repo, persisted CLN datastore JSON is a real compatibility concern.
- Avoid code comments unless the protocol detail is non-obvious. Module docs and short comments around sighash/reversal/wire-compat details are acceptable.
- Never hold a `MutexGuard` across `.await` in tests. Scope `node.sent_messages.lock().unwrap()` and similar guards tightly.
- `Bytes` from the `bytes` crate is used for binary payloads. Compare with `.as_ref()` when needed.
- Serde does not directly handle fixed `[u8; N]` arrays the way this project needs. Use existing serde helpers such as `serde_bytes_hex`, `serde_array_hex_32`, and `serde_array_hex_64`.

## Architecture Map

```text
src/
  lib.rs          Library root; re-exports modules for integration tests.
  main.rs         CLN plugin bootstrap: options, hooks, RPCs, subscriptions, runtime lock/unlock.
  config.rs       Config, ChannelPolicy, Branding, one-time ChannelSecret.
  keys.rs         Reads hsm_secret and derives the CLN node key with HKDF-SHA256.
  channel_id.rs   Deterministic hosted channel_id and fake short_channel_id helpers.
  state.rs        Pure StateManager fold from LCSS + uncommitted updates to next LCSS.
  store.rs        Store trait, MemoryStore, CAS JSON helpers, persisted data structs.
  cln_store.rs    CLN datastore-backed Store implementation.
  cln_node.rs     CLN RPC-backed NodeActions implementation.
  node.rs         NodeActions trait, MockNode, payment statuses, HTLC resolutions.
  gossip.rs       Signed BOLT-7/PHC channel_update construction for fake hosted scids.
  channel.rs      ChannelController: establishment, reconnect, HTLCs, policy, override, errors.
  htlc.rs         htlc_accepted manager and sendpay result manager.
  sphinx.rs       BOLT-4 onion peel/create/failure wrap helpers.
  ledger.rs       Append-only accounting ledger and custom notifications.
  scanner.rs      OP_RETURN preimage scanner.
  wire/
    mod.rs        HostedMessage enum, tag dispatch, message structs, PHC ChannelUpdate.
    codecs.rs     Primitive codecs, BOLT-2 update_add_htlc codec, TLV validation.
    lcss.rs       InitHostedChannel and LastCrossSignedState encode/sign/reverse/verify.
tests/
  integration.rs  Full lifecycle tests with MemoryStore and MockNode.
```

## CLN Plugin Surface

`main.rs` registers:

- `custommsg` hook for bLIP-17 hosted-channel messages.
- `htlc_accepted` hook for forwarding real CLN incoming HTLCs into hosted channels.
- `rpc_command` hook for direct hosted `pay` interception.
- `sendpay_success` and `sendpay_failure` subscriptions for downstream real-LN payment results.
- `connect` and `disconnect` subscriptions.
- RPC methods documented below.

The plugin advertises custom feature bit 257 in init and node announcements. Do not call `Builder::dynamic()`; CLN requires non-dynamic plugins for custom feature bits, and `cln-plugin` defaults to non-dynamic.

The plugin can start locked if the CLN `hsm_secret` requires a passphrase. While locked, hooks remain safe/no-op/continue. Unlock with `canopus-unlock passphrase_file=...` or direct `passphrase=...`.

## RPC Argument Parsing

All canopus RPC handlers either take no args or support named arguments.

CLN plugin RPC methods are not interactive. A handler receives a single JSON-RPC request and returns one result or error; it cannot safely prompt because plugin stdin/stdout are reserved for the CLN plugin protocol. Require values as parameters, use explicit confirmation flags such as `force=true`, prefer `*_file` parameters for sensitive input, or split operations into prepare/confirm RPCs.

The helper behavior in `main.rs` is:

- `param(request, key)` checks a top-level key and `params.key`.
- `arg(request, index, key)` checks the named key first, then a positional array fallback.

Examples:

```bash
lightning-cli canopus-channel peerid=02...
lightning-cli canopus-channel 02...
lightning-cli canopus-setchannel peerid=02... feebase_msat=2000 feeppm=500
```

Registered RPC methods:

- `canopus-status`: no args. Shows locked/unlocked runtime state.
- `canopus-unlock`: supports `passphrase=...` or `passphrase_file=...` and requires exactly one.
- `canopus-list`: no args. Lists known hosted channels and derived status.
- `canopus-channel`: supports `peerid=...`; returns full persisted channel data.
- `canopus-removehc`: supports `peerid=...` and `force=...`; refuses removal with in-flight/pending HTLCs unless forced.
- `canopus-addsecret`: supports `secret=...`, `capacity_msat=...`, `initial_balance_msat=...`.
- `canopus-removesecret`: supports `secret=...`.
- `canopus-listsecrets`: no args.
- `canopus-reset`: supports `peerid=...`, optional `new_local_balance_msat=...`; recovery command for errored/overriding channels.
- `canopus-policy`: supports named policy fields; updates global defaults used for new channels.
- `canopus-setchannel`: supports `peerid=...` plus optional per-channel fields; see the channel policy section.
- `canopus-events`: supports optional `peerid=...`.

The public `canopus-resize` RPC was replaced by `canopus-setchannel`. The wire-level poncho `resize_channel` custom message still exists and is handled internally for client-driven resize compatibility.

## Persisted Data Model

All production persistence goes through CLN datastore via `ClnStore`; tests use `MemoryStore`. Data is JSON encoded under the `canopus` namespace.

Important keys:

- `canopus/channels/<peer_pubkey_hex>` -> `ChannelData`
- `canopus/policy` -> global `ChannelPolicy`
- `canopus/secrets/<secret_hex>` -> one-time `ChannelSecret`
- `canopus/htlc_forwards/<scid>/<htlc_id>` -> `ForwardLink`
- `canopus/preimages/<payment_hash_hex>` -> preimage hex
- `canopus/ledger/<seq>` -> ledger event
- `canopus/meta` -> ledger sequence metadata

Datastore deletion is exact-key only. `Store::list(prefix)` returns immediate child keys, not every descendant, so subtree cleanup must recursively walk children and delete leaves before deleting the root. Prefer CLN `listdatastore`/`deldatastore` or the `Store` abstraction over direct DB edits. If direct SQLite cleanup is unavoidable, stop `lightningd`, back up the database, and remember CLN encodes datastore keys as NUL-separated BLOB parts: `canopus` is hex `63616E6F707573`, descendants start with `63616E6F70757300`; the old pre-rename `canopusd` root is `63616E6F70757364`, descendants start with `63616E6F7075736400`.

`ChannelData` contains:

- `lcss`: the committed cross-signed hosted state.
- `uncommitted`: local/remote updates not yet folded into committed LCSS.
- `local_errors` and `remote_errors`: error state markers.
- `suspended`: administrative suspended flag.
- `proposed_override`: pending LCSS override awaiting peer acceptance.
- `last_refund_scriptpubkey`: last refund script received from client.
- `established`: whether the opening exchange completed.
- `accepting_resize_sat`: legacy/poncho wire resize authorization.
- `routing_policy`: optional per-channel routing policy not covered by LCSS.
- `channel_update_pending`: durable flag indicating a PHC channel_update should be sent when possible.

`routing_policy` is optional for migration. Old stored channels will load with `None`; code derives a fallback from current global `effective_policy()` when needed. New channels store `Some(ChannelRoutingPolicy::from_policy(effective_policy))` at creation.

## Global Policy Versus Per-Channel Policy

There are two policy concepts now. Do not conflate them.

Global policy:

- Type: `ChannelPolicy` in `config.rs`.
- Stored at `canopus/policy` when changed by `canopus-policy`.
- Loaded by `effective_policy()`; falls back to startup config/defaults if not persisted.
- Used for new channel creation and secret-derived effective policy.
- Updating it does not mutate existing channels.

Default startup policy for new channels:

- `channel_capacity_msat = 100_000_000`
- `initial_client_balance_msat = 0`
- `max_htlc_value_in_flight_msat = 100_000_000`
- `htlc_minimum_msat = 1_000`
- `max_accepted_htlcs = 12`
- `fee_base_msat = 0`
- `fee_proportional_millionths = 1_000`
- `cltv_expiry_delta = 6`
- `htlc_maximum_msat` is derived from channel capacity for new routing policy.

Per-channel state and routing policy:

- LCSS-backed fields live inside `LastCrossSignedState.init_hosted_channel` and are signed:
  - `channel_capacity_msat`
  - `initial_client_balance_msat`
  - `max_htlc_value_in_flight_msat`
  - `htlc_minimum_msat`
  - `max_accepted_htlcs`
- Non-LCSS routing fields live in `ChannelData.routing_policy`:
  - `fee_base_msat`
  - `fee_proportional_millionths`
  - `cltv_expiry_delta`
  - `htlc_maximum_msat`

`htlc_minimum_msat` is an LCSS field because it is part of `InitHostedChannel`, which is embedded in the signed LCSS. Changing it for an existing channel requires a state-override-style flow.

`htlc_maximum_msat` is a BOLT channel_update routing field, not an LCSS field. Historically it was derived from channel capacity; it is now stored per channel in `ChannelRoutingPolicy`.

## `canopus-setchannel` Semantics

`canopus-setchannel peerid` with no optional fields is read-only and returns the current channel parameters. It is allowed even if HTLCs are in flight.

Optional fields update only when specified:

- `channel_capacity_msat`
- `initial_client_balance_msat`
- `feebase_msat` (alias accepted: `fee_base_msat`)
- `feeppm` (alias accepted: `fee_proportional_millionths`)
- `cltv_expiry_delta`
- `htlc_minimum_msat`
- `htlc_maximum_msat`
- `maxhtlcs` (alias accepted: `max_accepted_htlcs`)

Any update is rejected if the channel has committed in-flight HTLCs or uncommitted updates. Specifically, updates are refused when `incoming_htlcs`, `outgoing_htlcs`, or `uncommitted` is non-empty.

Routing-only updates:

- Update `ChannelData.routing_policy` directly.
- Set `channel_update_pending = true`.
- Try to send PHC channel_update immediately.
- Clear `channel_update_pending` only after successful send.

LCSS-affecting updates:

- Affect `channel_capacity_msat`, `initial_client_balance_msat`, `htlc_minimum_msat`, or `maxhtlcs`.
- Are rejected by `canopus-setchannel` for active channels. cliche/immortan only records incoming `state_override` proposals after the hosted channel is already errored, so active administrative overrides are not interoperable.
- With explicit `force=true` or `--force`, `canopus-setchannel` first persists a local error and `proposed_override`, then sends hosted `error` followed by `state_override`. The channel status becomes `Overriding`; reconnect replays LCSS, local error, and the proposal if the peer was offline.
- If the channel is already `Overriding`, `canopus-setchannel` updates `ChannelData.proposed_override` without requiring force and sends the latest `state_override` again. Reconnect must only replay the last persisted proposal.
- Use `canopus-reset` on an errored/overriding channel for state-override recovery.

Balance semantics for setchannel and reset:

- In host-side LCSS, `local_balance_msat` is host balance and `remote_balance_msat` is client balance.
- `canopus-reset peerid new_local_balance_msat` is different: it takes host/local balance and computes client/remote balance as `capacity - new_local_balance_msat`.

Keep `canopus-reset` as a separate emergency recovery command. It only works in `Errored` or `Overriding` status and clears HTLCs as part of reset. `canopus-setchannel` is an administrative configuration command for healthy active channels and rejects in-flight HTLCs.

## Channel Updates

Hosted channel updates are PHC-wrapped BOLT-7 `channel_update` bodies sent as `HostedMessage::PhcChannelUpdate` with tag `64507` (`TAG_PHC_CHANNEL_UPDATE_SYNC`). cliche/immortan expect this PHC sync tag for direct peer updates, not standard tag `258`.

`send_channel_update(peerid)` builds the advertised policy from:

- LCSS/init fields for capacity, max in-flight, HTLC minimum, and max accepted HTLC count.
- `ChannelData.routing_policy` for fee base, fee ppm, CLTV delta, and HTLC maximum.

Channel updates are currently sent:

- after initial channel establishment completes;
- after accepted `state_override`;
- after wire-level hosted `resize_channel` acceptance;
- after successful routing-only `canopus-setchannel` updates;
- on active hosted reconnect or CLN connect when `channel_update_pending` is true.

If sending a channel_update fails, leave `channel_update_pending = true`. Do not clear it before a successful send.

## LCSS And Sighash Rules

`LastCrossSignedState` is the core signed object. The `hosted_sig_hash` in `wire/lcss.rs` must match the scoin reference exactly.

Signed material order:

1. `refund_scriptpubkey` raw bytes, no length prefix.
2. `channel_capacity_msat` as u64 little-endian.
3. `initial_client_balance_msat` as u64 little-endian.
4. `block_day` as u32 little-endian.
5. `local_balance_msat` as u64 little-endian.
6. `remote_balance_msat` as u64 little-endian.
7. `local_updates` as u32 little-endian.
8. `remote_updates` as u32 little-endian.
9. Concatenated incoming HTLCs encoded as BOLT-2 `update_add_htlc` bodies, using big-endian wire encoding.
10. Concatenated outgoing HTLCs encoded the same way.
11. One byte `hostFlag`: `1` if `is_host`, otherwise `0`.

Then `SHA256(material)` is signed with compact 64-byte ECDSA.

Important direction rules:

- `reverse()` swaps local/remote fields and incoming/outgoing HTLCs.
- You sign the peer's view, which is usually `your_view.reverse()`.
- You verify the peer signature over your view.
- Do not casually change `reverse()`, sighash ordering, endian choices, or HTLC body encoding. These are interop-critical.

Status derivation:

- `Suspended` if `suspended`.
- `Overriding` if `proposed_override.is_some()`.
- `Errored` if local or remote errors exist.
- `Opening` before establishment.
- `Active` otherwise.

## Reconnect And Replay Behavior

Active reconnect sends the stored LCSS, replays uncommitted local updates exactly as persisted, and sends a matching `state_update` if uncommitted updates exist.

Errored/overriding reconnect sends the stored LCSS, sends a local error if present, and resends `state_override` if `proposed_override` exists.

Committed HTLC recovery is best-effort and runs after startup/unlock plus per-channel on active hosted reconnect and CLN peer connect. Recovery must not fail `custommsg` hook handling.

Committed incoming hosted HTLCs are redriven from stored `ForwardLink` state: success/failure is resolved when known, pending work is left alone, and missing/unknown downstream work is redriven.

Committed outgoing hosted HTLCs must not be replayed as duplicate `update_add_htlc` messages on reconnect. If a preimage is known, resolve with `update_fulfill_htlc`; otherwise send `query_preimages` for the committed outgoing payment hashes.

Pending channel updates are durable via `channel_update_pending`. Active reconnect and CLN connect attempt to flush them. This is required so routing-only `canopus-setchannel` changes made while a client is offline are delivered on next connection.

The disconnect handler clears legacy session wire encoding. It otherwise relies on persisted state and reconnect reconciliation.

## Wire Compatibility And Framing

Wire codecs are intentionally strict, but inbound custom message framing auto-detects:

- strict `tag || body`
- legacy cliche/immortan `tag || len || body`

Outbound framing follows the per-session encoding detected for that peer. Do not remove this unless all target clients are proven to have moved to strict framing.

Encoding notes:

- `uint64overflow` values reject values >= 2^63.
- Onion packets must be exactly 1366 bytes when encoded as `update_add_htlc`.
- TLV streams must be canonical: monotonic types, no duplicates, unknown even types below the high range rejected.
- `HostedChannelBranding.contact_info` must be valid UTF-8.
- The repo carries poncho-compatible extension messages such as `resize_channel`, `announcement_signature`, preimage query/reply, public hosted channel query/reply, and PHC channel updates.

## HTLC State Machine

StateManager is pure and folds `lcss + uncommitted` to produce the next LCSS. It does not send messages or persist. ChannelController owns persistence and side effects.

Direction from host perspective:

- Local add: host adds an outgoing HTLC to the client/hosted channel. Host local balance decreases and `outgoing_htlcs` grows.
- Remote add: client adds an incoming HTLC to the host. Client/remote balance decreases and `incoming_htlcs` grows.
- Local fulfill/fail resolves incoming HTLCs.
- Remote fulfill/fail resolves outgoing HTLCs.

All peer-originated add/fail/fulfill/fail_malformed updates are persisted as uncommitted first. Side effects for newly committed hosted-origin incoming HTLCs happen only after the peer commits them with a valid state update.

Known preimages are checked for idempotency. Preimages are persisted before relaying fulfills upstream.

## Hosted-Origin Routing Behavior

Hosted-origin means the client sends an `update_add_htlc` into canopus, and after commit canopus peels the onion and forwards either to another hosted channel or to real Lightning via CLN `sendonion`.

Basic checks always apply before forwarding:

- The incoming hosted HTLC must satisfy the source channel's LCSS limits: HTLC minimum, max accepted HTLCs, max in-flight.
- The onion must peel successfully with BOLT-4 rules using the HTLC `payment_hash` as associated data.
- The incoming amount must be at least the peeled `amt_to_forward`.

For hosted-origin to real-LN forwarding:

- Do not enforce host fee base, fee ppm, or host CLTV spread.
- CLN validates the real outgoing channel constraints when `sendonion` is called.
- canopus still persists a `ForwardLink` before calling `sendonion`.
- The `sendonion` label is `<outgoing_scid>/<outgoing_htlc_id>`.
- `group_id` is `outgoing_scid / 100`; `part_id` is the outgoing HTLC id.
- `sendonion` first-hop params must not pin `first_hop.channel` or `direction`; let CLN resolve the actual outgoing channel from gossip/listchannels.

For hosted-origin to hosted-destination forwarding:

- Resolve the destination hosted peer by fake hosted short_channel_id.
- Use the destination channel's stored per-channel routing policy for fee and CLTV checks.
- Required fee is based on destination `fee_base_msat` and `fee_proportional_millionths`.
- CLTV spread uses destination `cltv_expiry_delta`.
- Destination `channel_handle_htlc_add` enforces destination HTLC minimum, HTLC maximum, max HTLC count, max in-flight, and balance.
- Do not forward back to the same hosted channel; that is invalid.

For hosted-to-hosted settlement:

- `ForwardLink` stores incoming scid/HTLC id, outgoing scid/HTLC id, payment hash, and optional shared secret.
- Fulfill/fail from the downstream hosted channel is resolved upstream after commit.
- Failure wrapping uses the stored shared secret when available.
- Forward links are cleaned after settlement/failure resolution.

## Real CLN HTLCs Routed Into Hosted Channels

The CLN `htlc_accepted` hook can route real incoming LN HTLCs into a hosted channel.

Important behavior:

- `HtlcManager` parses the hook payload, determines target hosted peer, and calls `channel_handle_htlc_add`.
- `channel_handle_htlc_add` persists a `ForwardLink` before sending `update_add_htlc` to the hosted peer.
- The hook does not immediately return final success/failure. It waits for an async resolution, matching poncho-style behavior.
- Startup grace period avoids resolving hooks too early while hosted channel state is being reconciled.
- If a known preimage exists, the hook resolves immediately.

## BOLT-4 Sphinx Onion Rules

The Sphinx code in `sphinx.rs` is BOLT-4-sensitive. Key rules:

- Payment onions for `update_add_htlc` authenticate with associated data equal to the HTLC `payment_hash`.
- `peel_onion(node_privkey, onion, associated_data)` must be passed `&htlc.payment_hash` for payment HTLCs.
- ECDH shared secret is `SHA256(compressed ECDH point)`.
- HMAC verification is `HMAC256(mu, hop_payloads || associated_data)`.
- HMAC comparison is constant-time.
- Payloads use variable-length BigSize/TLV parsing.
- `next_hmac` is extracted immediately and forwarded in the constructed next onion.
- Final-hop payloads have no short_channel_id and produce an empty next onion.
- Forwarded onions use the truncated unwrapped payloads and extracted next HMAC.

Tests cover associated-data authentication and two-hop relay onion roundtrip. If changing Sphinx logic, add or update onion tests; do not rely only on integration tests.

## Failure Handling

Malformed hosted-origin onion peel:

- Send `update_fail_malformed_htlc` upstream after commit.
- Use the SHA256 of the original onion and failure code `0xc005`.

Normal forwarding policy/amount failures:

- Use local failure onion/wrapped failure helpers and `update_fail_htlc`.

Downstream real-LN sendpay failure:

- Look up `ForwardLink` by label/scid/id.
- Wrap the failure onion for the hosted source if a shared secret exists.
- Use `onionreply`/`erroronion` when present; otherwise fall back to a two-byte `failcode` payload.
- Send failure upstream and delete the forward link.

Outgoing payment inspection uses `listsendpays { payment_hash }` and filters labels locally. `PaymentStatus::Unknown` means no matching labeled payment result was found and should generally be treated as no-op/pending, not as a failure.

Downstream fulfill:

- Verify/persist preimage.
- Resolve upstream hosted or CLN HTLC.
- Delete forward link.

Empty hosted `update_fail_htlc.reason` from a peer is treated as an error condition.

## Channel Resize And Override

There are two different mechanisms:

- Public admin `canopus-setchannel` for per-channel configuration.
- Wire-level poncho `resize_channel` extension for client-driven hosted capacity changes.

Wire `resize_channel` behavior:

- Requires prior `accepting_resize_sat` authorization.
- Verifies client signature.
- Refuses inactive channels and capacity above authorization.
- Updates LCSS capacity and max in-flight to the new capacity.
- Adjusts host/local balance by the capacity delta while preserving client/remote balance.
- Updates routing `htlc_maximum_msat` to the new capacity.
- Persists, sends `state_update`, records a resize ledger event, and sends/pends channel_update.

Admin setchannel rejects LCSS-backed changes for active channels unless explicitly forced with `force=true` or `--force`. Forced setchannel changes deliberately put the channel in errored/overriding state before proposing `state_override`. Use `canopus-reset` for ordinary errored-channel state override recovery, or the wire-level resize flow for client-driven hosted capacity changes.

Override/reset behavior:

- `canopus-reset` only works for `Errored` or `Overriding` channels.
- It proposes a new LCSS with no HTLCs.
- It increments both update counters.
- If `new_local_balance_msat` is supplied, remote/client balance becomes `capacity - new_local_balance_msat`.

## Secrets And Provisioning

Secrets are one-time 32-byte values represented as 64-character hex strings.

`canopus-addsecret secret capacity_msat initial_balance_msat` stores a `ChannelSecret`. On invoke, if the client presents the secret:

- The secret must be exactly 32 raw bytes after hex decode.
- It is consumed atomically with datastore generation CAS.
- The secret is then deleted.
- Capacity and initial client balance override global policy for that channel's effective creation policy.
- Other policy values come from current `effective_policy()`.
- The new channel captures routing policy from that effective creation policy.

If `require_secret=true`, invokes without a valid secret are silently ignored with a warning. If `require_secret=false`, a valid supplied secret still applies custom capacity/balance; invalid/nonexistent secrets fall back to default policy.

## Direct Hosted `pay` Interception

The `rpc_command` hook watches `pay` calls, parses BOLT11 invoices, detects single-hop hosted route hints, and sends a direct hosted HTLC.

Important notes:

- If no matching hosted invoice target is found, the hook returns `continue` and CLN handles payment normally.
- If a preimage is already stored, it returns a CLN-compatible success response immediately.
- Final CLTV currently uses current height + invoice min final CLTV + global `effective_policy().cltv_expiry_delta`.
- This path still needs live cliche/CLN validation.

## Node Key Handling

`keys.rs` reads CLN `hsm_secret` directly and derives the node key. This is necessary because no CLN RPC provides the signatures required for hosted channel state.

Supported formats:

- Legacy plain secret.
- Mnemonic without passphrase.
- Mnemonic with passphrase.

Passphrase-protected secrets start locked. `canopus-unlock` rebuilds runtime with the passphrase, then zeroizes the passphrase buffer. Be careful not to log secrets or passphrases.

## Ledger And Accounting

The plugin maintains its own append-only ledger because CLN's bookkeeper cannot ingest plugin-managed hosted HTLCs as normal channel activity.

Ledger behavior:

- Channel open, resize, override, HTLC forwarded, HTLC fulfilled, and HTLC failed events are recorded.
- `record_once` provides idempotency by event id.
- `canopus-events [peerid]` lists events.
- Custom notifications are emitted for consumers.

When adding new balance-affecting behavior, add ledger coverage or explicitly explain why no event should be recorded.

## Preimage Scanner

The scanner watches blocks for `OP_RETURN <32-byte-preimage>` pushes matching watched payment hashes.

It uses `NodeActions::get_raw_block_by_height`, deserializes with the `bitcoin` crate, and stores discovered preimages through `NodeActions::store_preimage`.

The scanner is a host-protection mechanism: if a client publishes a preimage on-chain, canopus can learn it and settle/fail appropriately.

## Testing Patterns

Unit tests live in `#[cfg(test)] mod tests` at the bottom of modules. Integration tests live in `tests/integration.rs`.

Integration helpers:

- `make_harness(require_secret)` creates a `ChannelController`, `Arc<MockNode>`, client secret, and client pubkey.
- `establish_channel()` performs invoke -> init -> state_update and returns host LCSS.
- `establish_channel_with_secret()` provisions and establishes a secret-backed channel.
- `commit_peer_updates()` folds uncommitted channel updates and sends the peer state_update in tests.
- `last_sent_message()` decodes the last custom message emitted by `MockNode`.

`MockNode` records:

- `sent_messages`
- `sent_onions`
- `htlc_resolutions`
- `notifications`
- `payment_results`
- `preimages`

When asserting sent messages, filter by peer and message type. Many tests clear `sent_messages` after setup to avoid matching establishment messages.

When testing override acceptance, build `accepted = override_lcss.reverse()`, sign with the client secret, and pass its counters/signature back via `StateUpdate`.

## Live Interop And Validation Gaps

The code compiles and mock tests cover a large surface, but production validation remains necessary for:

- CLN RPC/datastore payload shapes and generation behavior.
- CLN `sendonion` behavior with hosted-origin real-LN forwarding.
- cliche/immortan/poncho wire framing and channel_update expectations.
- Direct hosted `pay` interception against real invoices and route hints.
- Reconnect behavior with offline clients receiving pending channel updates and overrides.
- Legacy encrypted hsm_secret fixtures.

No `TODO` or `stub` markers are expected in `src/` unless deliberately introduced as part of a tracked follow-up. Prefer adding tests for discovered edge cases immediately.

## Common Pitfalls

- Do not use global `effective_policy()` for existing hosted-channel fee checks unless the code is explicitly about global defaults. Existing channel routing uses `ChannelData.routing_policy`.
- Do not mutate LCSS-backed fields silently. Active `canopus-setchannel` LCSS changes are rejected unless explicitly forced; forced changes must persist/send local error before `state_override` because cliche/immortan only accepts override proposals after an error.
- Do not clear `channel_update_pending` before a channel_update send succeeds.
- Do not treat `htlc_minimum_msat` as a routing-only field. It is signed in LCSS.
- Do not treat `htlc_maximum_msat` as signed LCSS. It is advertised routing policy.
- Do not enforce hosted fee/CLTV spread for hosted-origin real-LN forwarding. CLN validates real outgoing channel constraints.
- Do not fail hosted-origin HTLCs before commit when the failure is a side effect of a committed add. Commit-then-fail is intentional.
- Do not delete forward links before upstream resolution is safely persisted/sent.
- Do not replay remote errors as local errors on reconnect.
- Do not replay committed outgoing hosted HTLCs as fresh `update_add_htlc` messages on reconnect; use known preimages or `query_preimages`.
- Do not allow repeated remote fulfill/fail/fail_malformed updates to accumulate duplicate uncommitted resolutions. Duplicate remote resolutions are idempotent and should be deduplicated before state folding/reconnect replay.
- Do not let hosted `custommsg` processing errors escape as plugin JSON-RPC errors; log channel errors and return hook `continue` unless the hook payload itself is malformed enough to ignore.
- Do not collapse strict and legacy framing behavior.
- Do not modify sighash or endian details without comparing against scoin/poncho.
- Do not introduce persistence schema fields without serde defaults or migration handling for existing CLN datastore entries.
