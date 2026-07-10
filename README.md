# canopusd

A bLIP-17 Hosted Channels HOST plugin for Core Lightning, written in Rust.

See [`ROADMAP.md`](ROADMAP.md) for production validation, hardening, and future compatibility work.

## Overview

`canopusd` implements the HOST side of the [Hosted Channels specification (bLIP-17)](https://github.com/lightning/blips/blob/master/blip-0017.md). Hosted channels are auditable Lightning-like channels backed by trust from a client in a host, providing an improvement over traditional custodial wallets.

### Features

- **Full bLIP-17 protocol**: channel establishment, state updates, HTLC forwarding, reconnection reconciliation, error states, and `state_override` reset
- **CLN datastore integration**: all channel state persisted via CLN's datastore RPC with `generation`-based compare-and-swap (CAS) for safe concurrent access
- **Feature bits**: advertises current hosted-channels support (bit 257) in init and node announcements
- **Secret-based provisioning**: one-time secrets with per-secret channel capacity and initial balance
- **Branding**: contact URL, hex color, and PNG logo
- **Accounting ledger**: append-only per-channel ledger with custom notification emission
- **OP_RETURN preimage scanner**: monitors blocks for client-published preimages to protect host funds
- **Sphinx onion processing**: BOLT-4 onion peeling for HTLC forwarding
- **Direct hosted pay interception**: detects single-hop hosted route hints in `pay` invoices and sends direct hosted HTLCs
- **Single binary**: compiled as a single Rust binary that runs as a CLN plugin

## Building

```bash
cargo build --release
```

The binary will be at `target/release/canopusd`.

## Installation

Add to your `lightningd` config:

```ini
plugin=/path/to/canopusd
```

Or start lightningd with:

```bash
lightningd --plugin=/path/to/canopusd
```

### Requirements

- Core Lightning 23.02+ (for datastore generation support)
- Access to CLN's `hsm_secret`; plain, mnemonic, and passphrase-protected formats are supported

## Configuration

All options can be set in the CLN config file or on the command line:

### Branding

| Option | Type | Description |
|--------|------|-------------|
| `canopusd-contact-url` | string | URL for human contact (enables branding replies) |
| `canopusd-color` | string | Hex color for branding (e.g. `#ff0000`) |
| `canopusd-logo` | string | Path to PNG logo file (max 65535 bytes) |

### Channel Policy

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `canopusd-capacity-msat` | int | 100000000 | Default channel capacity in millisatoshi |
| `canopusd-initial-balance-msat` | int | 0 | Default initial client balance |
| `canopusd-fee-base-msat` | int | 1000 | Base fee for forwarding |
| `canopusd-fee-ppm` | int | 1000 | Proportional fee (parts per million) |
| `canopusd-cltv-delta` | int | 137 | CLTV expiry delta |
| `canopusd-htlc-min-msat` | int | 1000 | Minimum HTLC amount |
| `canopusd-max-htlcs` | int | 12 | Max accepted HTLCs per channel |
| `canopusd-max-inflight-msat` | int | 50000000 | Max HTLC value in flight |

### Other

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `canopusd-require-secret` | bool | false | Require a secret for channel invocation |
| `canopusd-preimage-scan` | bool | true | Scan blocks for OP_RETURN-published preimages |

### Example

```ini
plugin=/path/to/canopusd
canopusd-contact-url=https://my-host.example.com
canopusd-color=#0066cc
canopusd-logo=/etc/lightning/logo.png
canopusd-capacity-msat=500000000
canopusd-require-secret=true
```

## RPC Commands

### `canopusd-status`

Show whether the plugin runtime is unlocked. If CLN's `hsm_secret` needs a passphrase, hosted-channel hooks stay in safe no-op/continue mode until unlock succeeds.

```bash
lightning-cli canopusd-status
```

### `canopusd-unlock passphrase_file=...`

Unlock a passphrase-protected CLN `hsm_secret`.

```bash
lightning-cli canopusd-unlock passphrase_file=/run/secrets/canopusd-hsm-passphrase
```

Direct passphrase passing is supported but less secure because shell history, process listings, or logs may expose it. Prefer `passphrase_file`, or capture a shell prompt into a protected temporary file before invoking `lightning-cli`.

```bash
lightning-cli canopusd-unlock passphrase='correct horse battery staple'
```

### `canopusd-list`

List all hosted channels.

```bash
lightning-cli canopusd-list
```

### `canopusd-channel peerid`

Get detailed information about a specific channel.

```bash
lightning-cli canopusd-channel 028789... 
```

### `canopusd-addsecret secret capacity_msat initial_balance_msat`

Add a one-time channel provisioning secret. When a client invokes with this secret, they get a channel with the specified capacity and initial balance. The secret is consumed atomically on use.

```bash
lightning-cli canopusd-addsecret my-secret-123 500000000 100000000
```

### `canopusd-removesecret secret`

Remove an unused secret.

```bash
lightning-cli canopusd-removesecret my-secret-123
```

### `canopusd-listsecrets`

List all secrets (hex-encoded, redacted).

```bash
lightning-cli canopusd-listsecrets
```

### `canopusd-reset peerid [new_local_balance_msat]`

Reset an errored channel by proposing a `state_override`. Uses the last known counterparty-signed cross-signed state. Optionally specify a new local balance.

```bash
lightning-cli canopusd-reset 028789... 80000000
```

### `canopusd-policy [fields...]`

Get or update the default hosted-channel policy used for new channels and channel updates. Supported fields are `channel_capacity_msat`, `initial_client_balance_msat`, `max_htlc_value_in_flight_msat`, `htlc_minimum_msat`, `max_accepted_htlcs`, `fee_base_msat`, `fee_proportional_millionths`, and `cltv_expiry_delta`.

```bash
lightning-cli canopusd-policy fee_base_msat=2000 fee_proportional_millionths=500 htlc_minimum_msat=1000 max_accepted_htlcs=24 cltv_expiry_delta=144
```

### `canopusd-resize peerid capacity_sat`

Allow a poncho-compatible hosted channel resize up to `capacity_sat`. Use `0` to cancel a pending resize authorization.

```bash
lightning-cli canopusd-resize 028789... 150000
```

### `canopusd-events [peerid]`

List accounting events, optionally filtered by peer.

```bash
lightning-cli canopusd-events 028789...
```

## Architecture

```
src/
  main.rs         Plugin bootstrap: options, hooks, featurebits, RPC methods
  lib.rs          Library root (for integration tests)
  config.rs       Configuration: options, branding, secrets, validation
  keys.rs         Node key derivation from hsm_secret (HKDF-SHA256)
  channel.rs      Per-peer state machine: establishment, reconnect, HTLC, errors, override
  channel_id.rs   Deterministic channel ID and fake short_channel_id derivation
  state.rs        Pure-functional state manager: folds uncommitted updates into next LCSS
  store.rs        Datastore abstraction with generation CAS (MemoryStore + CLN datastore)
  node.rs         Node interface trait (sendcustommsg, sendonion, etc.) + MockNode
  wire/
    mod.rs        bLIP-17 message types, tag dispatch, encode/decode
    codecs.rs     Low-level byte codecs (BE wire, LE sighash, BOLT-2 update_add_htlc)
    lcss.rs       LastCrossSignedState: encode, reverse(), hosted_sig_hash(), sign/verify
  sphinx.rs       BOLT-4 Sphinx onion: peel, failure wrap/unwrap
  htlc.rs         HTLC forwarding: htlc_accepted hook, sendonion, settlement
  ledger.rs       Append-only accounting ledger with custom notifications
  scanner.rs      OP_RETURN preimage scanner for block monitoring
tests/
  integration.rs  Full lifecycle tests using mock node + memory store
```

### Funds Safety Measures

1. **Persist before ack**: all state changes are written to the datastore (with generation CAS) before any side effects (sending messages, resolving HTLCs)
2. **Preimage persistence**: preimages are stored before relaying fulfills, ensuring crash recovery
3. **Signature verification**: every `last_cross_signed_state` and `state_update` is verified
4. **Checked arithmetic**: all millisatoshi operations use checked arithmetic (no silent overflow)
5. **Block day validation**: ±1 tolerance at channel open, exact match at commit
6. **HTLC expiry monitoring**: expired outgoing HTLCs trigger error state + upstream failure
7. **Restart idempotency**: htlc-forwards map + preimage cache prevent duplicate processing
8. **Startup grace period**: HTLC processing delayed during first 10 seconds to allow channel re-establishment
9. **OP_RETURN scanner**: monitors for client-published preimages to protect host funds
10. **Constant-time secret comparison**: prevents timing attacks on provisioning secrets
11. **Secret zeroization**: node private key bytes are zeroized on drop

## Testing

### Unit Tests

```bash
cargo test
```

Covers:
- Wire codec round-trips for all bLIP-17 message types
- LCSS encoding, `reverse()`, `hosted_sig_hash()`, sign/verify
- State manager: update folding, balance checks, preimage verification
- Datastore: generation CAS, conflict retry, CRUD operations
- Channel state machine: establishment, reconnect, errors, override, secrets, branding
- Sphinx: key derivation, blinding, varint, failure wrapping
- HSM secret formats: legacy plain, mnemonic no-passphrase, mnemonic with passphrase, wrong passphrase
- Direct single-hop hosted onion construction
- Feature bits encoding
- Configuration validation

### Integration Tests

```bash
cargo test --test integration
```

Tests the full channel lifecycle using a mock node (in-memory) and memory store:
- Channel establishment (invoke → init → state_update exchange)
- Secret-based provisioning (correct, wrong, consumed)
- Chain hash mismatch rejection
- Error state and `state_override` reset
- Reconnection LCSS reconciliation
- HTLC add to active channel
- HTLC resolution with known preimage (idempotency)
- Runtime policy persistence
- Preimage query/reply
- Ledger event recording
- Datastore generation CAS
- Sphinx key derivation

### Clippy

```bash
cargo clippy --all-targets -- -D warnings
```

## Manual Testing with Real CLN + cliche

Since the sandbox environment doesn't have lightningd, bitcoind, or cliche installed, here's a guide for manual testing on a real setup:

### Prerequisites

1. Install [Core Lightning](https://github.com/ElementsProject/lightning) (v23.02+)
2. Install [cliche](https://github.com/nbd-wtf/cliche) (bLIP-17 client)
3. Build canopusd: `cargo build --release`

### Setup (regtest)

1. Start bitcoind in regtest mode:
   ```bash
   bitcoind -regtest -daemon
   ```

2. Start lightningd with canopusd:
   ```bash
   lightningd --network=regtest \
     --plugin=./target/release/canopusd \
     --canopusd-contact-url=https://example.com \
     --canopusd-color=#ff0000 \
     --canopusd-require-secret=true
   ```

3. Add a provisioning secret:
   ```bash
   lightning-cli canopusd-addsecret test-secret 1000000000 500000000
   ```

4. Start cliche, configured to connect to your lightningd node.

5. From cliche, invoke a hosted channel using the secret.

6. Verify the channel is established:
   ```bash
   lightning-cli canopusd-list
   ```

7. Send a payment through the hosted channel and verify it forwards correctly.

8. Test error recovery:
   ```bash
   # Force an error (e.g., disconnect mid-payment)
   lightning-cli canopusd-reset <peerid>
   ```

9. Verify accounting:
   ```bash
   lightning-cli canopusd-events <peerid>
   ```

### Interop Notes

- The sighash algorithm matches the scoin reference implementation exactly (little-endian numeric fields, BOLT-2 HTLC encoding, hostFlag byte).
- Feature bit 257 (optional hosted channels) is advertised. Legacy hosted-channel bit 32973 is intentionally not advertised.
- The plugin is `dynamic: false` because custom feature bits require non-dynamic plugins in CLN.
- The `hsm_secret` must be unencrypted (the plugin reads it directly to derive the node key via HKDF-SHA256, matching CLN's internal derivation).

## License

CC0-1.0
