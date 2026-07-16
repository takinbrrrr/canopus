# Roadmap

This file tracks production validation, hardening, and future compatibility work for `canopus`.

## Production Validation

- Build an automated regtest harness with `bitcoind`, Core Lightning, `canopus`, and a hosted-channel client such as `cliche`.
- Validate CLN hook payload shapes for `custommsg`, `htlc_accepted`, `sendpay_success`, `sendpay_failure`, and `rpc_command` against real `lightningd`.
- Validate direct hosted `pay` interception against real `lightningd` and `cliche` invoices.
- Validate CLN datastore generation/CAS semantics against real `lightningd`.
- Test channel open, reconnect, send, receive, fail, fulfill, resize, restart recovery, and OP_RETURN preimage recovery end to end.
- Test plugin startup/shutdown behavior, subscriptions, hooks, and RPC methods across supported CLN versions.

## Protocol Hardening

- Validate BOLT-7 `channel_update` messages against real hosted-channel clients.
- Validate BOLT-4 failure onion wrapping with real routed failures and hosted-to-hosted failures.
- Consider replacing hand-rolled onion logic with a battle-tested Rust Lightning/onion library if a suitable dependency fits the plugin.
- Add fuzzing for `HostedMessage::decode_legacy_aware`, `LastCrossSignedState` decoding, and onion parsing.
- Add property tests for random state-transition sequences and balance invariants.

## Missing Features

- Hosted channel removal:
  - Add an operator RPC to remove or archive hosted channels.
  - Define safety rules for active channels, pending HTLCs, ledger retention, and datastore cleanup.
  - Decide whether removal means suspend, soft-delete/archive, or full datastore deletion.
  - Expected implementation areas: `src/channel.rs`, `src/main.rs`, `src/store.rs`, `src/ledger.rs`, and operator docs.
- Poncho/scoin extension messages not currently implemented:
  - `announcement_signature`
  - public hosted channel query/reply
  - PHC gossip/sync messages

## Reliability

- Add restart-recovery tests that reuse persisted `MemoryStore` across a new controller instance.
- Cover pending CLN HTLC replay after plugin restart.
- Cover pending hosted fulfill/fail replay after peer reconnect.
- Cover known preimage recovery and existing `ForwardLink` reconciliation.
- Audit ledger event idempotency so every economic event is recorded exactly once.

## Operations

- Add explicit `hsm_secret` ownership and permission checks with clear startup errors.
- Document backup and restore procedures for `canopus` datastore keys.
- Document an errored-channel recovery playbook.
- Add a compatibility matrix for bLIP-17, poncho, cliche, and CLN versions.
- Add structured operational logging guidance for peer id, scid, HTLC id, payment hash, datastore generation, and side-effect actions.
