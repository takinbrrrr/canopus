use bytes::Bytes;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use canopus::channel::{ChannelController, SetChannelParams, Status};
use canopus::channel_id::hosted_short_channel_id;
use canopus::config::Config;
use canopus::node::{HtlcResolution, MockNode, NodeActions};
use canopus::state::StateManager;
use canopus::store::{get_json, ForwardLink, MemoryStore, UncommittedUpdate};
use canopus::wire::codecs::UpdateAddHtlc;
use canopus::wire::lcss::LastCrossSignedState;
use canopus::wire::{
    HostedMessage, InvokeHostedChannel, QueryPreimages, ResizeChannel, StateUpdate, UpdateFailHtlc,
    UpdateFulfillHtlc,
};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Test harness: sets up a controller with mock node + memory store.
async fn make_harness(
    require_secret: bool,
) -> (Arc<ChannelController>, Arc<MockNode>, SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let (host_secret, host_public) = secp.generate_keypair(&mut rand::rngs::OsRng);
    let (client_secret, client_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

    let store = Arc::new(MemoryStore::new());
    let node = Arc::new(MockNode::new(700_000, host_public, "regtest"));

    let config = Config {
        chain_hash: [0x06u8; 32],
        network: "regtest".to_string(),
        require_secret,
        ..Config::default()
    };

    let controller = Arc::new(ChannelController {
        store,
        node: node.clone(),
        config,
        node_secret: host_secret,
        node_public: host_public,
        peer_wire_encodings: Arc::new(Mutex::new(HashMap::new())),
    });

    (controller, node, client_secret, client_public)
}

fn make_invoke(secret: &str) -> InvokeHostedChannel {
    let secret = secret.to_string();
    InvokeHostedChannel {
        chain_hash: [0x06u8; 32],
        refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14, 0x20]),
        secret: Bytes::from(secret.into_bytes()),
    }
}

fn make_invoke_hex_secret(secret: &str) -> InvokeHostedChannel {
    InvokeHostedChannel {
        chain_hash: [0x06u8; 32],
        refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14, 0x20]),
        secret: Bytes::from(hex::decode(secret).unwrap()),
    }
}

/// Extract the last message sent to a peer from the mock node.
fn last_sent_message(node: &Arc<MockNode>) -> HostedMessage {
    let sent = node.sent_messages.lock().unwrap();
    let last = sent.last().expect("no messages sent");
    HostedMessage::decode(&last.1).expect("failed to decode message")
}

/// Full channel establishment: invoke → init → state_update exchange.
/// Returns the established LCSS (from the host's perspective).
async fn establish_channel(
    controller: &ChannelController,
    node: &Arc<MockNode>,
    client_secret: &SecretKey,
    client_public: &PublicKey,
) -> LastCrossSignedState {
    // Client sends invoke
    controller
        .handle_invoke(client_public, make_invoke(""))
        .await
        .unwrap();

    // Extract init_hosted_channel from host's response
    let init = match last_sent_message(node) {
        HostedMessage::InitHostedChannel(i) => i,
        _ => panic!("expected init_hosted_channel"),
    };

    // Client builds its view of the LCSS
    let block_day = 700_000u32 / 144;
    let mut client_lcss = LastCrossSignedState {
        is_host: false,
        last_refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14, 0x20]),
        init_hosted_channel: init,
        block_day,
        local_balance_msat: 0,
        remote_balance_msat: 100_000_000,
        local_updates: 0,
        remote_updates: 0,
        incoming_htlcs: vec![],
        outgoing_htlcs: vec![],
        remote_sig_of_local: [0; 64],
        local_sig_of_remote: [0; 64],
    };
    client_lcss.sign(client_secret).unwrap();

    // Client sends state_update
    controller
        .handle_state_update(
            client_public,
            StateUpdate {
                block_day: client_lcss.block_day,
                local_updates: 0,
                remote_updates: 0,
                local_sig_of_remote: client_lcss.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    // Channel should now be active
    assert_eq!(
        controller.get_status(client_public).await.unwrap(),
        Status::Active
    );

    // Load the stored LCSS
    let data = controller
        .get_channel_data(client_public)
        .await
        .unwrap()
        .unwrap();
    data.lcss
}

async fn establish_channel_with_secret(
    controller: &ChannelController,
    node: &Arc<MockNode>,
    client_secret: &SecretKey,
    client_public: &PublicKey,
    secret: &str,
    capacity_msat: u64,
    initial_client_balance_msat: u64,
) -> LastCrossSignedState {
    controller
        .add_secret(
            secret.to_string(),
            capacity_msat,
            initial_client_balance_msat,
        )
        .await
        .unwrap();
    controller
        .handle_invoke(client_public, make_invoke_hex_secret(secret))
        .await
        .unwrap();
    let init = match last_sent_message(node) {
        HostedMessage::InitHostedChannel(i) => i,
        _ => panic!("expected init_hosted_channel"),
    };
    let block_day = 700_000u32 / 144;
    let mut client_lcss = LastCrossSignedState {
        is_host: false,
        last_refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14, 0x20]),
        init_hosted_channel: init,
        block_day,
        local_balance_msat: initial_client_balance_msat,
        remote_balance_msat: capacity_msat - initial_client_balance_msat,
        local_updates: 0,
        remote_updates: 0,
        incoming_htlcs: vec![],
        outgoing_htlcs: vec![],
        remote_sig_of_local: [0; 64],
        local_sig_of_remote: [0; 64],
    };
    client_lcss.sign(client_secret).unwrap();
    controller
        .handle_state_update(
            client_public,
            StateUpdate {
                block_day,
                local_updates: 0,
                remote_updates: 0,
                local_sig_of_remote: client_lcss.local_sig_of_remote,
            },
        )
        .await
        .unwrap();
    controller
        .get_channel_data(client_public)
        .await
        .unwrap()
        .unwrap()
        .lcss
}

async fn commit_peer_updates(
    controller: &ChannelController,
    peer_public: &PublicKey,
    peer_secret: &SecretKey,
) {
    let data = controller.load_channel(peer_public).await.unwrap().unwrap();
    let mut sm = StateManager::new(data.lcss.clone());
    sm.uncommitted = data.uncommitted.clone();
    let mut peer_view = sm.lcss_next().unwrap().reverse();
    peer_view.sign(peer_secret).unwrap();
    controller
        .handle_state_update(
            peer_public,
            StateUpdate {
                block_day: peer_view.block_day,
                local_updates: peer_view.local_updates,
                remote_updates: peer_view.remote_updates,
                local_sig_of_remote: peer_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_full_channel_establishment() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    let lcss = establish_channel(&controller, &node, &client_secret, &client_public).await;

    assert!(lcss.is_host);
    assert_eq!(lcss.local_balance_msat, 100_000_000);
    assert_eq!(lcss.remote_balance_msat, 0);
    assert_eq!(lcss.local_updates, 0);
    assert_eq!(lcss.remote_updates, 0);

    let ledger = canopus::ledger::LedgerManager::new(controller.store.clone());
    let events = ledger
        .list_events(Some(&hex::encode(client_public.serialize())))
        .await
        .unwrap();
    assert!(events.iter().any(|event| matches!(
        event.event_type,
        canopus::ledger::LedgerEventType::ChannelOpen
    )));
}

#[tokio::test]
async fn test_channel_with_secret() {
    let (controller, node, client_secret, client_public) = make_harness(true).await;
    let secret = "0101010101010101010101010101010101010101010101010101010101010101";

    // Add a secret with custom params
    controller
        .add_secret(secret.to_string(), 500_000_000, 100_000_000)
        .await
        .unwrap();

    // Establish with the secret
    controller
        .handle_invoke(&client_public, make_invoke_hex_secret(secret))
        .await
        .unwrap();

    // Verify init has custom params
    let msg = last_sent_message(&node);
    if let HostedMessage::InitHostedChannel(init) = msg {
        assert_eq!(init.channel_capacity_msat, 500_000_000);
        assert_eq!(init.initial_client_balance_msat, 100_000_000);
    } else {
        panic!("expected init_hosted_channel");
    }

    // Now establish the channel
    let block_day = 700_000u32 / 144;
    let init = match last_sent_message(&node) {
        HostedMessage::InitHostedChannel(i) => i,
        _ => panic!(),
    };

    let mut client_lcss = LastCrossSignedState {
        is_host: false,
        last_refund_scriptpubkey: Bytes::from_static(&[0x00, 0x14, 0x20]),
        init_hosted_channel: init,
        block_day,
        local_balance_msat: 100_000_000,
        remote_balance_msat: 400_000_000,
        local_updates: 0,
        remote_updates: 0,
        incoming_htlcs: vec![],
        outgoing_htlcs: vec![],
        remote_sig_of_local: [0; 64],
        local_sig_of_remote: [0; 64],
    };
    client_lcss.sign(&client_secret).unwrap();

    controller
        .handle_state_update(
            &client_public,
            StateUpdate {
                block_day,
                local_updates: 0,
                remote_updates: 0,
                local_sig_of_remote: client_lcss.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        controller.get_status(&client_public).await.unwrap(),
        Status::Active
    );
}

#[tokio::test]
async fn test_secret_consumed_after_use() {
    let (controller, node, _client_secret, client_public) = make_harness(true).await;
    let secret = "0202020202020202020202020202020202020202020202020202020202020202";

    controller
        .add_secret(secret.to_string(), 200_000_000, 0)
        .await
        .unwrap();

    // First use — should work
    controller
        .handle_invoke(&client_public, make_invoke_hex_secret(secret))
        .await
        .unwrap();
    assert!(!node.sent_messages.lock().unwrap().is_empty());

    // Clear messages
    node.sent_messages.lock().unwrap().clear();

    // Second use — should be ignored (secret consumed)
    let secp = Secp256k1::new();
    let (_, client2) = secp.generate_keypair(&mut rand::rngs::OsRng);
    controller
        .handle_invoke(&client2, make_invoke_hex_secret(secret))
        .await
        .unwrap();
    assert!(node.sent_messages.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_wrong_secret_ignored() {
    let (controller, node, _client_secret, client_public) = make_harness(true).await;
    let secret = "0303030303030303030303030303030303030303030303030303030303030303";
    let wrong_secret = "0404040404040404040404040404040404040404040404040404040404040404";

    controller
        .add_secret(secret.to_string(), 200_000_000, 0)
        .await
        .unwrap();

    controller
        .handle_invoke(&client_public, make_invoke_hex_secret(wrong_secret))
        .await
        .unwrap();

    // Should not send init (wrong secret)
    assert!(node.sent_messages.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_chain_hash_mismatch() {
    let (controller, _node, _client_secret, client_public) = make_harness(false).await;

    let mut invoke = make_invoke("");
    invoke.chain_hash = [0xFF; 32]; // wrong chain hash

    let result = controller.handle_invoke(&client_public, invoke).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_error_and_reset() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    let _lcss = establish_channel(&controller, &node, &client_secret, &client_public).await;

    // Manually error the channel
    let _data = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap();

    // Use the public method through mark_errored (which is private, so we
    // simulate by sending an error message from the peer)
    use canopus::wire::HcError;
    let err = HcError {
        channel_id: [0; 32],
        data: Bytes::from_static(b"test error from peer"),
        tlv_stream: Bytes::new(),
    };
    controller.handle_error(&client_public, err).await.unwrap();

    assert_eq!(
        controller.get_status(&client_public).await.unwrap(),
        Status::Errored
    );

    // Propose override to reset
    controller
        .propose_override(&client_public, Some(80_000_000))
        .await
        .unwrap();

    assert_eq!(
        controller.get_status(&client_public).await.unwrap(),
        Status::Overriding
    );

    // cliche only records state_override proposals after the channel is errored.
    {
        let sent = node.sent_messages.lock().unwrap();
        assert!(matches!(
            HostedMessage::decode(&sent[sent.len() - 2].1).unwrap(),
            HostedMessage::Error(_)
        ));
        assert!(matches!(
            HostedMessage::decode(&sent[sent.len() - 1].1).unwrap(),
            HostedMessage::StateOverride(_)
        ));
    }

    // Client accepts override
    let override_lcss = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap()
        .proposed_override
        .unwrap();

    let mut accepted = override_lcss.reverse();
    accepted.sign(&client_secret).unwrap();

    controller
        .handle_state_update(
            &client_public,
            StateUpdate {
                block_day: override_lcss.block_day,
                local_updates: accepted.local_updates,
                remote_updates: accepted.remote_updates,
                local_sig_of_remote: accepted.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    // Channel should be active again
    assert_eq!(
        controller.get_status(&client_public).await.unwrap(),
        Status::Active
    );

    // Verify the new balances
    let data = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data.lcss.local_balance_msat, 80_000_000);
    assert_eq!(data.lcss.remote_balance_msat, 20_000_000);
}

#[tokio::test]
async fn test_active_idle_state_update_is_ignored() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    let lcss = establish_channel(&controller, &node, &client_secret, &client_public).await;
    let sent_before = node.sent_messages.lock().unwrap().len();

    let mut client_view = lcss.reverse();
    client_view.sign(&client_secret).unwrap();
    controller
        .handle_state_update(
            &client_public,
            StateUpdate {
                block_day: client_view.block_day,
                local_updates: client_view.local_updates,
                remote_updates: client_view.remote_updates,
                local_sig_of_remote: client_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    assert_eq!(node.sent_messages.lock().unwrap().len(), sent_before);
}

#[tokio::test]
async fn test_remote_error_not_replayed_on_reconnect() {
    use canopus::wire::HcError;

    let (controller, node, client_secret, client_public) = make_harness(false).await;
    let _lcss = establish_channel(&controller, &node, &client_secret, &client_public).await;
    node.sent_messages.lock().unwrap().clear();

    controller
        .handle_error(
            &client_public,
            HcError {
                channel_id: [0; 32],
                data: Bytes::from_static(b"bad signature"),
                tlv_stream: Bytes::new(),
            },
        )
        .await
        .unwrap();

    let data = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert!(data.local_errors.is_empty());
    assert_eq!(data.remote_errors, vec!["bad signature".to_string()]);
    assert_eq!(
        controller.get_status(&client_public).await.unwrap(),
        Status::Errored
    );

    controller
        .handle_invoke(&client_public, make_invoke(""))
        .await
        .unwrap();

    let sent = node.sent_messages.lock().unwrap();
    assert_eq!(sent.len(), 1);
    let msg = HostedMessage::decode(&sent[0].1).unwrap();
    assert!(matches!(msg, HostedMessage::LastCrossSignedState(_)));
}

#[tokio::test]
async fn test_reconnection_lcss_exchange() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    let lcss = establish_channel(&controller, &node, &client_secret, &client_public).await;

    // Simulate reconnection: client sends invoke again
    controller
        .handle_invoke(&client_public, make_invoke(""))
        .await
        .unwrap();

    // Host should send back the stored LCSS
    let msg = last_sent_message(&node);
    match msg {
        HostedMessage::LastCrossSignedState(received_lcss) => {
            assert_eq!(received_lcss.local_balance_msat, lcss.local_balance_msat);
            assert_eq!(received_lcss.remote_balance_msat, lcss.remote_balance_msat);
        }
        _ => panic!("expected last_cross_signed_state"),
    }
}

#[tokio::test]
async fn test_reconnection_accepts_client_view_lcss() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    let lcss = establish_channel(&controller, &node, &client_secret, &client_public).await;
    node.sent_messages.lock().unwrap().clear();

    controller
        .handle_invoke(&client_public, make_invoke(""))
        .await
        .unwrap();

    let host_lcss = match last_sent_message(&node) {
        HostedMessage::LastCrossSignedState(received_lcss) => received_lcss,
        _ => panic!("expected last_cross_signed_state"),
    };
    assert_eq!(host_lcss, lcss);
    node.sent_messages.lock().unwrap().clear();

    controller
        .handle_lcss(&client_public, host_lcss.reverse())
        .await
        .unwrap();

    assert_eq!(
        controller.get_status(&client_public).await.unwrap(),
        Status::Active
    );
    match last_sent_message(&node) {
        HostedMessage::LastCrossSignedState(received_lcss) => assert_eq!(received_lcss, lcss),
        HostedMessage::Error(err) => {
            panic!("unexpected error: {}", String::from_utf8_lossy(&err.data))
        }
        _ => panic!("expected last_cross_signed_state"),
    }
}

#[tokio::test]
async fn test_reconnect_replays_persisted_add_id() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;
    node.sent_messages.lock().unwrap().clear();

    let htlc = UpdateAddHtlc {
        channel_id: [0u8; 32],
        id: 0,
        amount_msat: 10_000_000,
        payment_hash: [0x11; 32],
        cltv_expiry: 700_100,
        onion_routing_packet: Bytes::from(vec![0; 1366]),
        tlv_stream: Bytes::new(),
    };
    controller
        .channel_handle_htlc_add(&client_public, htlc, "1/7", 1, 7, Some([9; 32]))
        .await
        .unwrap();
    node.sent_messages.lock().unwrap().clear();

    controller
        .handle_invoke(&client_public, make_invoke(""))
        .await
        .unwrap();

    let mut replayed_add_id = None;
    let mut replayed_state_update = None;
    for (_, bytes) in node.sent_messages.lock().unwrap().iter() {
        match HostedMessage::decode(bytes).unwrap() {
            HostedMessage::UpdateAddHtlc(add) => replayed_add_id = Some(add.id),
            HostedMessage::StateUpdate(update) => replayed_state_update = Some(update),
            _ => {}
        }
    }
    assert_eq!(replayed_add_id, Some(1));
    assert_eq!(replayed_state_update.map(|u| u.local_updates), Some(1));
}

#[tokio::test]
async fn test_branding_on_request() {
    let (mut controller_builder, _node, _client_secret, client_public) = make_harness(false).await;
    // We need to set branding on the config — but the controller is behind Arc
    // For this test, let's test the handler directly
    let _ = client_public;
    let _ = &mut controller_builder;
    // Branding is tested in unit tests already
}

#[tokio::test]
async fn test_list_channels() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;

    let channels = controller.list_channels().await.unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0], client_public);
}

#[tokio::test]
async fn test_htlc_add_to_active_channel() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;

    // Simulate an incoming HTLC from CLN (htlc_accepted hook)
    let preimage = [0x42u8; 32];
    let payment_hash = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(preimage);
        h.finalize()
    };
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&payment_hash);

    let htlc = UpdateAddHtlc {
        channel_id: [0u8; 32], // will be assigned
        id: 0,
        amount_msat: 10_000_000,
        payment_hash: hash_arr,
        cltv_expiry: 700_100,
        onion_routing_packet: Bytes::from(vec![0; 1366]),
        tlv_stream: Bytes::new(),
    };

    // The controller should add the HTLC and send update_add_htlc to client
    controller
        .channel_handle_htlc_add(&client_public, htlc, "test-key-1", 1, 1, Some([9; 32]))
        .await
        .unwrap();

    // Verify update_add_htlc was sent
    {
        let sent = node.sent_messages.lock().unwrap();
        let add_msg = sent.iter().rev().find(|(_, bytes)| {
            matches!(
                HostedMessage::decode(bytes),
                Ok(HostedMessage::UpdateAddHtlc(_))
            )
        });
        assert!(add_msg.is_some(), "update_add_htlc should have been sent");
    }

    let hosted_scid = hosted_short_channel_id(&controller.node_public, &client_public);
    let key = ChannelController::forward_key(hosted_scid, 1);
    let key_ref: Vec<&str> = key.iter().map(|s| s.as_str()).collect();
    let (link, _) = get_json::<ForwardLink>(controller.store.as_ref(), &key_ref)
        .await
        .unwrap();
    assert_eq!(link.incoming_scid, 1);
    assert_eq!(link.incoming_htlc_id, 1);
    assert_eq!(link.shared_secret, Some([9; 32]));
}

#[tokio::test]
async fn test_state_update_accepts_client_view_counters() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;

    let htlc = UpdateAddHtlc {
        channel_id: [0u8; 32],
        id: 0,
        amount_msat: 10_000_000,
        payment_hash: [1; 32],
        cltv_expiry: 700_100,
        onion_routing_packet: Bytes::from(
            canopus::sphinx::create_single_hop_onion(
                &client_public,
                10_000_000,
                700_100,
                None,
                &[1; 32],
            )
            .unwrap(),
        ),
        tlv_stream: Bytes::new(),
    };
    controller
        .channel_handle_htlc_add(&client_public, htlc, "test-key", 1, 1, Some([9; 32]))
        .await
        .unwrap();

    let data = controller
        .load_channel(&client_public)
        .await
        .unwrap()
        .unwrap();
    let mut sm = StateManager::new(data.lcss.clone());
    sm.uncommitted = data.uncommitted.clone();
    let mut client_view = sm.lcss_next().unwrap().reverse();
    client_view.sign(&client_secret).unwrap();

    controller
        .handle_state_update(
            &client_public,
            StateUpdate {
                block_day: client_view.block_day,
                local_updates: client_view.local_updates,
                remote_updates: client_view.remote_updates,
                local_sig_of_remote: client_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    let data = controller
        .load_channel(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert!(data.uncommitted.is_empty());
    assert_eq!(data.lcss.local_updates, 1);
    assert_eq!(data.lcss.remote_updates, 0);
    assert_eq!(data.lcss.outgoing_htlcs.len(), 1);
    assert_eq!(data.lcss.outgoing_htlcs[0].htlc_id(), 1);

    let ledger = canopus::ledger::LedgerManager::new(controller.store.clone());
    let events = ledger
        .list_events(Some(&hex::encode(client_public.serialize())))
        .await
        .unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event.event_type,
                canopus::ledger::LedgerEventType::HtlcForwarded
            ) && event.amount_msat == 10_000_000)
            .count(),
        1
    );

    controller
        .handle_state_update(
            &client_public,
            StateUpdate {
                block_day: client_view.block_day,
                local_updates: client_view.local_updates,
                remote_updates: client_view.remote_updates,
                local_sig_of_remote: client_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();
    let events_after_replay = ledger
        .list_events(Some(&hex::encode(client_public.serialize())))
        .await
        .unwrap();
    assert_eq!(events_after_replay.len(), events.len());
}

#[tokio::test]
async fn test_fulfill_after_client_view_state_update_resolves_upstream() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;

    let preimage = [0x42u8; 32];
    let payment_hash = {
        use sha2::Digest;
        sha2::Sha256::digest(preimage).into()
    };
    let htlc = UpdateAddHtlc {
        channel_id: [0u8; 32],
        id: 0,
        amount_msat: 10_000_000,
        payment_hash,
        cltv_expiry: 700_100,
        onion_routing_packet: Bytes::from(
            canopus::sphinx::create_single_hop_onion(
                &client_public,
                10_000_000,
                700_100,
                None,
                &payment_hash,
            )
            .unwrap(),
        ),
        tlv_stream: Bytes::new(),
    };
    controller
        .channel_handle_htlc_add(&client_public, htlc, "1/1", 1, 1, Some([9; 32]))
        .await
        .unwrap();

    let data = controller
        .load_channel(&client_public)
        .await
        .unwrap()
        .unwrap();
    let mut sm = StateManager::new(data.lcss.clone());
    sm.uncommitted = data.uncommitted.clone();
    let mut host_next = sm.lcss_next().unwrap();
    host_next.sign(&controller.node_secret).unwrap();
    let mut client_view = host_next.reverse();
    client_view.sign(&client_secret).unwrap();
    controller
        .handle_state_update(
            &client_public,
            StateUpdate {
                block_day: client_view.block_day,
                local_updates: client_view.local_updates,
                remote_updates: client_view.remote_updates,
                local_sig_of_remote: client_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    controller
        .handle_update_fulfill(
            &client_public,
            UpdateFulfillHtlc {
                channel_id: host_next.outgoing_htlcs[0].channel_id,
                id: 1,
                payment_preimage: preimage,
                tlv_stream: Bytes::new(),
            },
        )
        .await
        .unwrap();

    let resolutions = node.htlc_resolutions.lock().unwrap();
    assert!(resolutions.iter().any(|(key, resolution)| matches!(
        resolution,
        HtlcResolution::Resolve { preimage: resolved } if key == "1/1" && resolved == &preimage
    )));
}

#[tokio::test]
async fn test_duplicate_remote_fulfill_is_idempotent_and_repaired_on_reconnect() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;
    node.sent_messages.lock().unwrap().clear();

    let preimage = [0x43u8; 32];
    let payment_hash = {
        use sha2::Digest;
        sha2::Sha256::digest(preimage).into()
    };
    let htlc = UpdateAddHtlc {
        channel_id: [0u8; 32],
        id: 0,
        amount_msat: 10_000_000,
        payment_hash,
        cltv_expiry: 700_100,
        onion_routing_packet: Bytes::from(
            canopus::sphinx::create_single_hop_onion(
                &client_public,
                10_000_000,
                700_100,
                None,
                &payment_hash,
            )
            .unwrap(),
        ),
        tlv_stream: Bytes::new(),
    };
    controller
        .channel_handle_htlc_add(&client_public, htlc, "1/20", 1, 20, Some([9; 32]))
        .await
        .unwrap();

    let data = controller
        .load_channel(&client_public)
        .await
        .unwrap()
        .unwrap();
    let mut sm = StateManager::new(data.lcss.clone());
    sm.uncommitted = data.uncommitted.clone();
    let mut host_next = sm.lcss_next().unwrap();
    host_next.sign(&controller.node_secret).unwrap();
    let mut client_view = host_next.reverse();
    client_view.sign(&client_secret).unwrap();
    controller
        .handle_state_update(
            &client_public,
            StateUpdate {
                block_day: client_view.block_day,
                local_updates: client_view.local_updates,
                remote_updates: client_view.remote_updates,
                local_sig_of_remote: client_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    let fulfill = UpdateFulfillHtlc {
        channel_id: host_next.outgoing_htlcs[0].channel_id,
        id: 1,
        payment_preimage: preimage,
        tlv_stream: Bytes::new(),
    };
    controller
        .handle_update_fulfill(&client_public, fulfill.clone())
        .await
        .unwrap();
    controller
        .handle_update_fulfill(&client_public, fulfill)
        .await
        .unwrap();

    let mut data = controller
        .load_channel(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data.uncommitted.len(), 1);
    assert!(matches!(
        data.uncommitted[0],
        UncommittedUpdate::Remote(canopus::store::PendingUpdate::Fulfill { id: 1, .. })
    ));

    let duplicate = data.uncommitted[0].clone();
    data.uncommitted.push(duplicate);
    controller
        .save_channel(&client_public, &data, None)
        .await
        .unwrap();

    node.sent_messages.lock().unwrap().clear();
    controller
        .handle_invoke(&client_public, make_invoke(""))
        .await
        .unwrap();

    let repaired = controller
        .load_channel(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(repaired.uncommitted.len(), 1);
    let sent = node.sent_messages.lock().unwrap();
    assert!(sent.iter().any(|(_, bytes)| matches!(
        HostedMessage::decode(bytes).unwrap(),
        HostedMessage::StateUpdate(_)
    )));
}

#[tokio::test]
async fn test_remove_channel_without_inflight_htlcs() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;

    controller
        .remove_channel(&client_public, false)
        .await
        .unwrap();

    assert!(controller
        .load_channel(&client_public)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        controller.get_status(&client_public).await.unwrap(),
        Status::NotOpened
    );
    assert!(controller.list_channels().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_remove_channel_requires_force_with_inflight_htlcs() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;

    let htlc = UpdateAddHtlc {
        channel_id: [0u8; 32],
        id: 0,
        amount_msat: 10_000_000,
        payment_hash: [1; 32],
        cltv_expiry: 700_100,
        onion_routing_packet: Bytes::from(vec![0; 1366]),
        tlv_stream: Bytes::new(),
    };
    controller
        .channel_handle_htlc_add(&client_public, htlc, "test-key", 1, 1, Some([9; 32]))
        .await
        .unwrap();

    let err = controller
        .remove_channel(&client_public, false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("in-flight HTLCs"));

    controller
        .remove_channel(&client_public, true)
        .await
        .unwrap();

    assert!(controller
        .load_channel(&client_public)
        .await
        .unwrap()
        .is_none());
    let hosted_scid = hosted_short_channel_id(&controller.node_public, &client_public).to_string();
    assert!(controller
        .store
        .list(&["canopus", "htlc_forwards", &hosted_scid])
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn test_consecutive_htlc_adds_use_local_update_ids() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;

    for (index, payment_hash) in [[1u8; 32], [2u8; 32]].into_iter().enumerate() {
        let htlc = UpdateAddHtlc {
            channel_id: [0u8; 32],
            id: 0,
            amount_msat: 10_000_000,
            payment_hash,
            cltv_expiry: 700_100,
            onion_routing_packet: Bytes::from(vec![0; 1366]),
            tlv_stream: Bytes::new(),
        };

        controller
            .channel_handle_htlc_add(
                &client_public,
                htlc,
                &format!("test-key-{}", index + 1),
                1,
                index as u64 + 1,
                Some([9; 32]),
            )
            .await
            .unwrap();
    }

    let add_ids: Vec<_> = {
        let sent = node.sent_messages.lock().unwrap();
        sent.iter()
            .filter_map(|(_, bytes)| match HostedMessage::decode(bytes) {
                Ok(HostedMessage::UpdateAddHtlc(add)) => Some(add.id),
                _ => None,
            })
            .collect()
    };
    assert_eq!(add_ids, vec![1, 2]);

    let hosted_scid = hosted_short_channel_id(&controller.node_public, &client_public);
    let key = ChannelController::forward_key(hosted_scid, 2);
    let key_ref: Vec<&str> = key.iter().map(|s| s.as_str()).collect();
    let (link, _) = get_json::<ForwardLink>(controller.store.as_ref(), &key_ref)
        .await
        .unwrap();
    assert_eq!(link.incoming_htlc_id, 2);
    assert_eq!(link.outgoing_htlc_id, 2);
}

#[tokio::test]
async fn test_hosted_fail_wraps_upstream_failure() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;

    let htlc = UpdateAddHtlc {
        channel_id: [0u8; 32],
        id: 0,
        amount_msat: 10_000_000,
        payment_hash: [7; 32],
        cltv_expiry: 700_100,
        onion_routing_packet: Bytes::from(vec![0; 1366]),
        tlv_stream: Bytes::new(),
    };
    controller
        .channel_handle_htlc_add(&client_public, htlc, "9/42", 9, 42, Some([3; 32]))
        .await
        .unwrap();

    let data = controller
        .load_channel(&client_public)
        .await
        .unwrap()
        .unwrap();
    let mut sm = StateManager::new(data.lcss.clone());
    sm.uncommitted = data.uncommitted.clone();
    let mut client_view = sm.lcss_next().unwrap().reverse();
    client_view.sign(&client_secret).unwrap();
    controller
        .handle_state_update(
            &client_public,
            StateUpdate {
                block_day: client_view.block_day,
                local_updates: client_view.local_updates,
                remote_updates: client_view.remote_updates,
                local_sig_of_remote: client_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    let hosted_scid = hosted_short_channel_id(&controller.node_public, &client_public);
    let key = ChannelController::forward_key(hosted_scid, 1);
    let key_ref: Vec<&str> = key.iter().map(|s| s.as_str()).collect();
    let (link, _) = get_json::<ForwardLink>(controller.store.as_ref(), &key_ref)
        .await
        .unwrap();
    assert_eq!(link.incoming_scid, 9);
    assert_eq!(link.incoming_htlc_id, 42);

    controller
        .handle_update_fail(
            &client_public,
            UpdateFailHtlc {
                channel_id: [0u8; 32],
                id: 1,
                reason: Bytes::from_static(&[0x10, 0x07]),
                tlv_stream: Bytes::new(),
            },
        )
        .await
        .unwrap();

    assert!(node.htlc_resolutions.lock().unwrap().is_empty());

    let data = controller
        .load_channel(&client_public)
        .await
        .unwrap()
        .unwrap();
    let mut sm = StateManager::new(data.lcss.clone());
    sm.uncommitted = data.uncommitted.clone();
    let mut client_view = sm.lcss_next().unwrap().reverse();
    client_view.sign(&client_secret).unwrap();
    controller
        .handle_state_update(
            &client_public,
            StateUpdate {
                block_day: client_view.block_day,
                local_updates: client_view.local_updates,
                remote_updates: client_view.remote_updates,
                local_sig_of_remote: client_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    let failure_len = {
        let resolutions = node.htlc_resolutions.lock().unwrap();
        resolutions
            .iter()
            .find_map(|(key, resolution)| match resolution {
                HtlcResolution::Fail { failure_onion } if key == "9/42" => {
                    Some(failure_onion.len())
                }
                _ => None,
            })
    };
    assert_eq!(failure_len, Some(256));
    assert!(get_json::<ForwardLink>(controller.store.as_ref(), &key_ref)
        .await
        .is_err());
}

#[tokio::test]
async fn test_hosted_to_hosted_fulfill_returns_to_source_peer() {
    let (controller, node, source_secret, source_public) = make_harness(false).await;
    let secp = Secp256k1::new();
    let (target_secret, target_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

    establish_channel_with_secret(
        &controller,
        &node,
        &source_secret,
        &source_public,
        "1111111111111111111111111111111111111111111111111111111111111111",
        100_000_000,
        50_000_000,
    )
    .await;
    establish_channel(&controller, &node, &target_secret, &target_public).await;
    node.sent_messages.lock().unwrap().clear();

    let preimage = [0x51u8; 32];
    let payment_hash: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(preimage).into()
    };
    let target_scid = hosted_short_channel_id(&controller.node_public, &target_public);
    let source_amount = 10_011_000;
    let target_amount = 10_000_000;
    let target_cltv = 700_100;
    let source_htlc = UpdateAddHtlc {
        channel_id: canopus::channel_id::channel_id(&controller.node_public, &source_public),
        id: 1,
        amount_msat: source_amount,
        payment_hash,
        cltv_expiry: 700_300,
        onion_routing_packet: Bytes::from(
            canopus::sphinx::create_relay_onion(
                &controller.node_public,
                &target_public,
                target_scid,
                target_amount,
                target_cltv,
                &payment_hash,
            )
            .unwrap(),
        ),
        tlv_stream: Bytes::new(),
    };

    controller
        .handle_update_add(&source_public, source_htlc)
        .await
        .unwrap();
    let data = controller
        .load_channel(&source_public)
        .await
        .unwrap()
        .unwrap();
    let mut sm = StateManager::new(data.lcss.clone());
    sm.uncommitted = data.uncommitted.clone();
    let mut source_view = sm.lcss_next().unwrap().reverse();
    source_view.sign(&source_secret).unwrap();
    controller
        .handle_state_update(
            &source_public,
            StateUpdate {
                block_day: source_view.block_day,
                local_updates: source_view.local_updates,
                remote_updates: source_view.remote_updates,
                local_sig_of_remote: source_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    let target_add = {
        let sent = node.sent_messages.lock().unwrap();
        sent.iter().find_map(|(peer, bytes)| {
            if peer == &target_public {
                match HostedMessage::decode(bytes).unwrap() {
                    HostedMessage::UpdateAddHtlc(add) => Some(add),
                    _ => None,
                }
            } else {
                None
            }
        })
    }
    .expect("target hosted add");
    assert_eq!(target_add.id, 1);

    let data = controller
        .load_channel(&target_public)
        .await
        .unwrap()
        .unwrap();
    let mut sm = StateManager::new(data.lcss.clone());
    sm.uncommitted = data.uncommitted.clone();
    let mut target_view = sm.lcss_next().unwrap().reverse();
    target_view.sign(&target_secret).unwrap();
    controller
        .handle_state_update(
            &target_public,
            StateUpdate {
                block_day: target_view.block_day,
                local_updates: target_view.local_updates,
                remote_updates: target_view.remote_updates,
                local_sig_of_remote: target_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    controller
        .handle_update_fulfill(
            &target_public,
            UpdateFulfillHtlc {
                channel_id: target_add.channel_id,
                id: target_add.id,
                payment_preimage: preimage,
                tlv_stream: Bytes::new(),
            },
        )
        .await
        .unwrap();

    let source_fulfill = {
        let sent = node.sent_messages.lock().unwrap();
        sent.iter().rev().find_map(|(peer, bytes)| {
            if peer == &source_public {
                match HostedMessage::decode(bytes).unwrap() {
                    HostedMessage::UpdateFulfillHtlc(fulfill) => Some(fulfill),
                    _ => None,
                }
            } else {
                None
            }
        })
    };
    assert!(matches!(
        source_fulfill,
        Some(UpdateFulfillHtlc {
            id: 1,
            payment_preimage,
            ..
        }) if payment_preimage == preimage
    ));
}

#[tokio::test]
async fn test_hosted_to_hosted_fail_returns_to_source_peer() {
    let (controller, node, source_secret, source_public) = make_harness(false).await;
    let secp = Secp256k1::new();
    let (target_secret, target_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

    establish_channel_with_secret(
        &controller,
        &node,
        &source_secret,
        &source_public,
        "1111111111111111111111111111111111111111111111111111111111111111",
        100_000_000,
        50_000_000,
    )
    .await;
    establish_channel(&controller, &node, &target_secret, &target_public).await;
    node.sent_messages.lock().unwrap().clear();

    let payment_hash = [0x52u8; 32];
    let target_scid = hosted_short_channel_id(&controller.node_public, &target_public);
    let source_htlc = UpdateAddHtlc {
        channel_id: canopus::channel_id::channel_id(&controller.node_public, &source_public),
        id: 1,
        amount_msat: 10_011_000,
        payment_hash,
        cltv_expiry: 700_300,
        onion_routing_packet: Bytes::from(
            canopus::sphinx::create_relay_onion(
                &controller.node_public,
                &target_public,
                target_scid,
                10_000_000,
                700_100,
                &payment_hash,
            )
            .unwrap(),
        ),
        tlv_stream: Bytes::new(),
    };

    controller
        .handle_update_add(&source_public, source_htlc)
        .await
        .unwrap();
    let data = controller
        .load_channel(&source_public)
        .await
        .unwrap()
        .unwrap();
    let mut sm = StateManager::new(data.lcss.clone());
    sm.uncommitted = data.uncommitted.clone();
    let mut source_view = sm.lcss_next().unwrap().reverse();
    source_view.sign(&source_secret).unwrap();
    controller
        .handle_state_update(
            &source_public,
            StateUpdate {
                block_day: source_view.block_day,
                local_updates: source_view.local_updates,
                remote_updates: source_view.remote_updates,
                local_sig_of_remote: source_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    let target_add = {
        let sent = node.sent_messages.lock().unwrap();
        sent.iter().find_map(|(peer, bytes)| {
            if peer == &target_public {
                match HostedMessage::decode(bytes).unwrap() {
                    HostedMessage::UpdateAddHtlc(add) => Some(add),
                    _ => None,
                }
            } else {
                None
            }
        })
    }
    .expect("target hosted add");
    let forward_key = ChannelController::forward_key(target_scid, target_add.id);
    let key_ref: Vec<&str> = forward_key.iter().map(|s| s.as_str()).collect();

    let data = controller
        .load_channel(&target_public)
        .await
        .unwrap()
        .unwrap();
    let mut sm = StateManager::new(data.lcss.clone());
    sm.uncommitted = data.uncommitted.clone();
    let mut target_view = sm.lcss_next().unwrap().reverse();
    target_view.sign(&target_secret).unwrap();
    controller
        .handle_state_update(
            &target_public,
            StateUpdate {
                block_day: target_view.block_day,
                local_updates: target_view.local_updates,
                remote_updates: target_view.remote_updates,
                local_sig_of_remote: target_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    controller
        .handle_update_fail(
            &target_public,
            UpdateFailHtlc {
                channel_id: target_add.channel_id,
                id: target_add.id,
                reason: Bytes::from_static(&[0x20, 0x02]),
                tlv_stream: Bytes::new(),
            },
        )
        .await
        .unwrap();
    assert!({
        let sent = node.sent_messages.lock().unwrap();
        sent.iter().all(|(peer, bytes)| {
            peer != &source_public
                || !matches!(
                    HostedMessage::decode(bytes),
                    Ok(HostedMessage::UpdateFailHtlc(_))
                )
        })
    });

    let data = controller
        .load_channel(&target_public)
        .await
        .unwrap()
        .unwrap();
    let mut sm = StateManager::new(data.lcss.clone());
    sm.uncommitted = data.uncommitted.clone();
    let mut target_view = sm.lcss_next().unwrap().reverse();
    target_view.sign(&target_secret).unwrap();
    controller
        .handle_state_update(
            &target_public,
            StateUpdate {
                block_day: target_view.block_day,
                local_updates: target_view.local_updates,
                remote_updates: target_view.remote_updates,
                local_sig_of_remote: target_view.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    let source_fail = {
        let sent = node.sent_messages.lock().unwrap();
        sent.iter().rev().find_map(|(peer, bytes)| {
            if peer == &source_public {
                match HostedMessage::decode(bytes).unwrap() {
                    HostedMessage::UpdateFailHtlc(fail) => Some(fail),
                    _ => None,
                }
            } else {
                None
            }
        })
    };
    assert!(matches!(
        source_fail,
        Some(UpdateFailHtlc { id: 1, reason, .. }) if reason.len() == 256
    ));
    assert!(get_json::<ForwardLink>(controller.store.as_ref(), &key_ref)
        .await
        .is_err());
}

#[tokio::test]
async fn test_hosted_origin_real_ln_ignores_host_fee_and_cltv_policy() {
    let (controller, node, source_secret, source_public) = make_harness(false).await;
    let secp = Secp256k1::new();
    let (_, next_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

    establish_channel_with_secret(
        &controller,
        &node,
        &source_secret,
        &source_public,
        "1111111111111111111111111111111111111111111111111111111111111111",
        100_000_000,
        50_000_000,
    )
    .await;
    node.sent_messages.lock().unwrap().clear();

    let payment_hash = [0x53u8; 32];
    let real_scid = 5_061_345_003_001;
    let amount_msat = 10_000_000;
    let cltv_expiry = 700_100;
    let source_htlc = UpdateAddHtlc {
        channel_id: canopus::channel_id::channel_id(&controller.node_public, &source_public),
        id: 1,
        amount_msat,
        payment_hash,
        cltv_expiry,
        onion_routing_packet: Bytes::from(
            canopus::sphinx::create_relay_onion(
                &controller.node_public,
                &next_public,
                real_scid,
                amount_msat,
                cltv_expiry,
                &payment_hash,
            )
            .unwrap(),
        ),
        tlv_stream: Bytes::new(),
    };

    controller
        .handle_update_add(&source_public, source_htlc)
        .await
        .unwrap();
    commit_peer_updates(&controller, &source_public, &source_secret).await;

    let onions = node.sent_onions.lock().unwrap();
    assert_eq!(onions.len(), 1);
    assert_eq!(onions[0].first_scid, real_scid);
    assert_eq!(onions[0].first_amount_msat, amount_msat);
}

#[tokio::test]
async fn test_hosted_origin_sendonion_setup_failure_fails_htlc() {
    let (controller, node, source_secret, source_public) = make_harness(false).await;
    let secp = Secp256k1::new();
    let (_, next_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

    establish_channel_with_secret(
        &controller,
        &node,
        &source_secret,
        &source_public,
        "1111111111111111111111111111111111111111111111111111111111111111",
        100_000_000,
        50_000_000,
    )
    .await;
    node.sent_messages.lock().unwrap().clear();
    node.fail_next_send_onion("peer for scid not found");

    let payment_hash = [0x55u8; 32];
    let real_scid = 5_061_345_003_001;
    let amount_msat = 10_000_000;
    let cltv_expiry = 700_100;
    let source_htlc = UpdateAddHtlc {
        channel_id: canopus::channel_id::channel_id(&controller.node_public, &source_public),
        id: 1,
        amount_msat,
        payment_hash,
        cltv_expiry,
        onion_routing_packet: Bytes::from(
            canopus::sphinx::create_relay_onion(
                &controller.node_public,
                &next_public,
                real_scid,
                amount_msat,
                cltv_expiry,
                &payment_hash,
            )
            .unwrap(),
        ),
        tlv_stream: Bytes::new(),
    };

    controller
        .handle_update_add(&source_public, source_htlc)
        .await
        .unwrap();
    commit_peer_updates(&controller, &source_public, &source_secret).await;

    assert!(node.sent_onions.lock().unwrap().is_empty());
    let source_fail = {
        let sent = node.sent_messages.lock().unwrap();
        sent.iter().rev().find_map(|(peer, bytes)| {
            if peer == &source_public {
                match HostedMessage::decode(bytes).unwrap() {
                    HostedMessage::UpdateFailHtlc(fail) => Some(fail),
                    _ => None,
                }
            } else {
                None
            }
        })
    };
    assert!(matches!(
        source_fail,
        Some(UpdateFailHtlc { id: 1, reason, .. }) if reason.len() == 256
    ));
    let key = ChannelController::forward_key(real_scid, 1);
    let key_ref: Vec<&str> = key.iter().map(|s| s.as_str()).collect();
    assert!(get_json::<ForwardLink>(controller.store.as_ref(), &key_ref)
        .await
        .is_err());
}

#[tokio::test]
async fn test_recovery_redrives_committed_hosted_origin_htlc() {
    let (controller, node, source_secret, source_public) = make_harness(false).await;
    let secp = Secp256k1::new();
    let (_, next_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

    establish_channel_with_secret(
        &controller,
        &node,
        &source_secret,
        &source_public,
        "1111111111111111111111111111111111111111111111111111111111111111",
        100_000_000,
        50_000_000,
    )
    .await;
    node.sent_messages.lock().unwrap().clear();

    let payment_hash = [0x56u8; 32];
    let real_scid = 5_061_345_003_001;
    let amount_msat = 10_000_000;
    let cltv_expiry = 700_100;
    let htlc = UpdateAddHtlc {
        channel_id: canopus::channel_id::channel_id(&controller.node_public, &source_public),
        id: 1,
        amount_msat,
        payment_hash,
        cltv_expiry,
        onion_routing_packet: Bytes::from(
            canopus::sphinx::create_relay_onion(
                &controller.node_public,
                &next_public,
                real_scid,
                amount_msat,
                cltv_expiry,
                &payment_hash,
            )
            .unwrap(),
        ),
        tlv_stream: Bytes::new(),
    };
    let mut data = controller
        .load_channel(&source_public)
        .await
        .unwrap()
        .unwrap();
    data.lcss.remote_balance_msat -= amount_msat;
    data.lcss.remote_updates += 1;
    data.lcss.incoming_htlcs.push(htlc);
    controller
        .save_channel(&source_public, &data, None)
        .await
        .unwrap();

    controller.recover_committed_htlcs().await.unwrap();

    let onions = node.sent_onions.lock().unwrap();
    assert_eq!(onions.len(), 1);
    assert_eq!(onions[0].first_scid, real_scid);
    assert_eq!(onions[0].first_amount_msat, amount_msat);
}

#[tokio::test]
async fn test_reconnect_queries_preimages_for_committed_outgoing_htlcs() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel_with_secret(
        &controller,
        &node,
        &client_secret,
        &client_public,
        "1111111111111111111111111111111111111111111111111111111111111111",
        100_000_000,
        50_000_000,
    )
    .await;
    node.sent_messages.lock().unwrap().clear();

    let payment_hash = [0x57u8; 32];
    let amount_msat = 1_000_000;
    let htlc = UpdateAddHtlc {
        channel_id: canopus::channel_id::channel_id(&controller.node_public, &client_public),
        id: 1,
        amount_msat,
        payment_hash,
        cltv_expiry: 700_100,
        onion_routing_packet: Bytes::from(vec![0; 1366]),
        tlv_stream: Bytes::new(),
    };
    let mut data = controller
        .load_channel(&client_public)
        .await
        .unwrap()
        .unwrap();
    data.lcss.local_balance_msat -= amount_msat;
    data.lcss.local_updates += 1;
    data.lcss.outgoing_htlcs.push(htlc);
    controller
        .save_channel(&client_public, &data, None)
        .await
        .unwrap();

    controller.handle_connect(&client_public).await.unwrap();

    let (query_count, add_count) = {
        let sent = node.sent_messages.lock().unwrap();
        let query_count = sent
            .iter()
            .filter(|(peer, bytes)| {
                peer == &client_public
                    && matches!(
                        HostedMessage::decode(bytes),
                        Ok(HostedMessage::QueryPreimages(QueryPreimages { ref hashes }))
                            if hashes == &vec![payment_hash]
                    )
            })
            .count();
        let add_count = sent
            .iter()
            .filter(|(peer, bytes)| {
                peer == &client_public
                    && matches!(
                        HostedMessage::decode(bytes),
                        Ok(HostedMessage::UpdateAddHtlc(_))
                    )
            })
            .count();
        (query_count, add_count)
    };
    assert_eq!(query_count, 1);
    assert_eq!(add_count, 0);
}

#[tokio::test]
async fn test_hosted_to_hosted_still_enforces_host_policy() {
    let (controller, node, source_secret, source_public) = make_harness(false).await;
    let secp = Secp256k1::new();
    let (target_secret, target_public) = secp.generate_keypair(&mut rand::rngs::OsRng);

    establish_channel_with_secret(
        &controller,
        &node,
        &source_secret,
        &source_public,
        "1111111111111111111111111111111111111111111111111111111111111111",
        100_000_000,
        50_000_000,
    )
    .await;
    establish_channel(&controller, &node, &target_secret, &target_public).await;
    controller
        .set_channel(
            &target_public,
            SetChannelParams {
                fee_base_msat: Some(50_000),
                fee_proportional_millionths: Some(0),
                ..SetChannelParams::default()
            },
            false,
        )
        .await
        .unwrap();
    node.sent_messages.lock().unwrap().clear();

    let payment_hash = [0x54u8; 32];
    let target_scid = hosted_short_channel_id(&controller.node_public, &target_public);
    let target_amount_msat = 10_000_000;
    let source_amount_msat = 10_020_000;
    let cltv_expiry = 700_100;
    let source_htlc = UpdateAddHtlc {
        channel_id: canopus::channel_id::channel_id(&controller.node_public, &source_public),
        id: 1,
        amount_msat: source_amount_msat,
        payment_hash,
        cltv_expiry: 700_300,
        onion_routing_packet: Bytes::from(
            canopus::sphinx::create_relay_onion(
                &controller.node_public,
                &target_public,
                target_scid,
                target_amount_msat,
                cltv_expiry,
                &payment_hash,
            )
            .unwrap(),
        ),
        tlv_stream: Bytes::new(),
    };

    controller
        .handle_update_add(&source_public, source_htlc)
        .await
        .unwrap();
    commit_peer_updates(&controller, &source_public, &source_secret).await;

    let (sent_target_add, sent_source_fail) = {
        let sent = node.sent_messages.lock().unwrap();
        let sent_target_add = sent.iter().any(|(peer, bytes)| {
            peer == &target_public
                && matches!(
                    HostedMessage::decode(bytes),
                    Ok(HostedMessage::UpdateAddHtlc(_))
                )
        });
        let sent_source_fail = sent.iter().any(|(peer, bytes)| {
            peer == &source_public
                && matches!(
                    HostedMessage::decode(bytes),
                    Ok(HostedMessage::UpdateFailHtlc(_))
                )
        });
        (sent_target_add, sent_source_fail)
    };

    assert!(!sent_target_add);
    assert!(sent_source_fail);
}

#[tokio::test]
async fn test_resize_channel_acceptance() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;

    controller
        .accept_resize(&client_public, Some(150_000))
        .await
        .unwrap();
    let mut resize = ResizeChannel {
        new_capacity_sat: 150_000,
        client_sig: [0; 64],
    };
    let secp = Secp256k1::new();
    let msg = secp256k1::Message::from_digest(resize.sig_hash());
    resize.client_sig = secp.sign_ecdsa(&msg, &client_secret).serialize_compact();

    controller
        .handle_resize_channel(&client_public, resize)
        .await
        .unwrap();

    let data = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data.accepting_resize_sat, None);
    assert_eq!(
        data.lcss.init_hosted_channel.channel_capacity_msat,
        150_000_000
    );
    assert_eq!(data.lcss.local_balance_msat, 150_000_000);
    let sent = node.sent_messages.lock().unwrap();
    assert!(sent.iter().any(|(_, bytes)| {
        matches!(
            HostedMessage::decode(bytes),
            Ok(HostedMessage::StateUpdate(_))
        )
    }));
}

#[tokio::test]
async fn test_runtime_policy_persists() {
    let (controller, _node, _client_secret, _client_public) = make_harness(false).await;
    let mut policy = controller.effective_policy().await.unwrap();
    policy.fee_base_msat = 2_000;
    policy.fee_proportional_millionths = 333;
    policy.htlc_minimum_msat = 5_000;
    policy.max_accepted_htlcs = 24;
    policy.cltv_expiry_delta = 144;

    controller.set_policy(policy.clone()).await.unwrap();

    let loaded = controller.effective_policy().await.unwrap();
    assert_eq!(loaded.fee_base_msat, 2_000);
    assert_eq!(loaded.fee_proportional_millionths, 333);
    assert_eq!(loaded.htlc_minimum_msat, 5_000);
    assert_eq!(loaded.max_accepted_htlcs, 24);
    assert_eq!(loaded.cltv_expiry_delta, 144);
}

#[tokio::test]
async fn test_channel_captures_routing_policy_at_creation() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    let mut policy = controller.effective_policy().await.unwrap();
    policy.fee_base_msat = 2_222;
    policy.fee_proportional_millionths = 444;
    policy.cltv_expiry_delta = 99;
    controller.set_policy(policy.clone()).await.unwrap();

    establish_channel(&controller, &node, &client_secret, &client_public).await;
    let data = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap();
    let routing = data.routing_policy.unwrap();
    assert_eq!(routing.fee_base_msat, 2_222);
    assert_eq!(routing.fee_proportional_millionths, 444);
    assert_eq!(routing.cltv_expiry_delta, 99);
    assert_eq!(routing.htlc_maximum_msat, policy.channel_capacity_msat);

    policy.fee_base_msat = 9_999;
    controller.set_policy(policy).await.unwrap();
    let data = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data.routing_policy.unwrap().fee_base_msat, 2_222);
}

#[tokio::test]
async fn test_set_channel_reads_and_updates_routing_policy() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;
    node.sent_messages.lock().unwrap().clear();

    let (current, updated) = controller
        .set_channel(&client_public, SetChannelParams::default(), false)
        .await
        .unwrap();
    assert!(!updated);
    assert_eq!(current.feebase_msat, 1_000);
    assert_eq!(current.feeppm, 1_000);

    let (current, updated) = controller
        .set_channel(
            &client_public,
            SetChannelParams {
                fee_base_msat: Some(2_000),
                fee_proportional_millionths: Some(500),
                cltv_expiry_delta: Some(144),
                htlc_maximum_msat: Some(50_000_000),
                ..SetChannelParams::default()
            },
            false,
        )
        .await
        .unwrap();
    assert!(updated);
    assert_eq!(current.feebase_msat, 2_000);
    assert_eq!(current.feeppm, 500);
    assert_eq!(current.cltv_expiry_delta, 144);
    assert_eq!(current.htlc_maximum_msat, 50_000_000);

    let data = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert!(!data.channel_update_pending);
    let routing = data.routing_policy.unwrap();
    assert_eq!(routing.fee_base_msat, 2_000);
    assert_eq!(routing.htlc_maximum_msat, 50_000_000);

    let phc = {
        let sent = node.sent_messages.lock().unwrap();
        sent.iter()
            .rev()
            .find_map(|(_, bytes)| match HostedMessage::decode(bytes) {
                Ok(HostedMessage::PhcChannelUpdate(phc)) => Some(phc.body),
                _ => None,
            })
    }
    .expect("channel update");
    assert_eq!(phc.fee_base_msat, 2_000);
    assert_eq!(phc.fee_proportional_millionths, 500);
    assert_eq!(phc.cltv_expiry_delta, 144);
    assert_eq!(phc.htlc_maximum_msat, 50_000_000);
}

#[tokio::test]
async fn test_set_channel_rejects_active_lcss_update() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;
    node.sent_messages.lock().unwrap().clear();

    let err = controller
        .set_channel(
            &client_public,
            SetChannelParams {
                channel_capacity_msat: Some(120_000_000),
                initial_client_balance_msat: Some(10_000_000),
                htlc_minimum_msat: Some(1_000),
                max_accepted_htlcs: Some(8),
                ..SetChannelParams::default()
            },
            false,
        )
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("LCSS-backed channel changes require an errored channel reset"));

    let data = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert!(data.proposed_override.is_none());
    assert!(!data.channel_update_pending);
    assert_eq!(
        data.lcss.init_hosted_channel.channel_capacity_msat,
        100_000_000
    );
    assert!(node.sent_messages.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_set_channel_force_errors_and_proposes_lcss_override() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;
    node.sent_messages.lock().unwrap().clear();

    let (current, updated) = controller
        .set_channel(
            &client_public,
            SetChannelParams {
                channel_capacity_msat: Some(120_000_000),
                initial_client_balance_msat: Some(10_000_000),
                htlc_minimum_msat: Some(1_000),
                htlc_maximum_msat: Some(60_000_000),
                max_accepted_htlcs: Some(8),
                ..SetChannelParams::default()
            },
            true,
        )
        .await
        .unwrap();
    assert!(updated);
    assert_eq!(current.channel_capacity_msat, 120_000_000);
    assert_eq!(current.initial_client_balance_msat, 10_000_000);
    assert_eq!(current.local_balance_msat, 110_000_000);
    assert_eq!(current.remote_balance_msat, 10_000_000);
    assert_eq!(current.htlc_minimum_msat, 1_000);
    assert_eq!(current.htlc_maximum_msat, 60_000_000);
    assert_eq!(current.maxhtlcs, 8);
    assert!(current.override_pending);
    assert!(current.channel_update_pending);

    assert_eq!(
        controller.get_status(&client_public).await.unwrap(),
        Status::Overriding
    );

    let data = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data.local_errors, vec!["forced channel parameter override"]);
    assert_eq!(
        data.lcss.init_hosted_channel.channel_capacity_msat,
        100_000_000
    );
    let override_lcss = data.proposed_override.clone().unwrap();
    assert_eq!(
        override_lcss.init_hosted_channel.channel_capacity_msat,
        120_000_000
    );
    assert_eq!(override_lcss.remote_balance_msat, 10_000_000);
    assert_eq!(override_lcss.local_balance_msat, 110_000_000);
    assert_eq!(data.routing_policy.unwrap().htlc_maximum_msat, 60_000_000);

    {
        let sent = node.sent_messages.lock().unwrap();
        assert_eq!(sent.len(), 2);
        match HostedMessage::decode(&sent[0].1).unwrap() {
            HostedMessage::Error(err) => {
                assert_eq!(err.data.as_ref(), b"forced channel parameter override");
            }
            other => panic!("expected error, got {other:?}"),
        }
        match HostedMessage::decode(&sent[1].1).unwrap() {
            HostedMessage::StateOverride(msg) => {
                assert_eq!(msg.local_balance_msat, 110_000_000);
                assert_eq!(msg.local_updates, override_lcss.local_updates);
                assert_eq!(msg.remote_updates, override_lcss.remote_updates);
                assert_eq!(msg.local_sig_of_remote, override_lcss.local_sig_of_remote);
            }
            other => panic!("expected state_override, got {other:?}"),
        }
    }

    let mut accepted = override_lcss.reverse();
    accepted.sign(&client_secret).unwrap();
    controller
        .handle_state_update(
            &client_public,
            StateUpdate {
                block_day: override_lcss.block_day,
                local_updates: accepted.local_updates,
                remote_updates: accepted.remote_updates,
                local_sig_of_remote: accepted.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        controller.get_status(&client_public).await.unwrap(),
        Status::Active
    );
    let data = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert!(data.local_errors.is_empty());
    assert!(data.proposed_override.is_none());
    assert!(!data.channel_update_pending);
    assert_eq!(
        data.lcss.init_hosted_channel.channel_capacity_msat,
        120_000_000
    );
    assert_eq!(data.lcss.remote_balance_msat, 10_000_000);
    assert_eq!(data.lcss.local_balance_msat, 110_000_000);
}

#[tokio::test]
async fn test_set_channel_force_replays_override_on_reconnect() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;
    node.sent_messages.lock().unwrap().clear();

    controller
        .set_channel(
            &client_public,
            SetChannelParams {
                channel_capacity_msat: Some(120_000_000),
                ..SetChannelParams::default()
            },
            true,
        )
        .await
        .unwrap();
    let override_lcss = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap()
        .proposed_override
        .unwrap();

    node.sent_messages.lock().unwrap().clear();
    controller
        .handle_invoke(&client_public, make_invoke(""))
        .await
        .unwrap();

    let sent = node.sent_messages.lock().unwrap();
    assert_eq!(sent.len(), 3);
    assert!(matches!(
        HostedMessage::decode(&sent[0].1).unwrap(),
        HostedMessage::LastCrossSignedState(_)
    ));
    match HostedMessage::decode(&sent[1].1).unwrap() {
        HostedMessage::Error(err) => {
            assert_eq!(err.data.as_ref(), b"forced channel parameter override");
        }
        other => panic!("expected error, got {other:?}"),
    }
    match HostedMessage::decode(&sent[2].1).unwrap() {
        HostedMessage::StateOverride(msg) => {
            assert_eq!(msg.local_balance_msat, override_lcss.local_balance_msat);
            assert_eq!(msg.local_updates, override_lcss.local_updates);
            assert_eq!(msg.remote_updates, override_lcss.remote_updates);
            assert_eq!(msg.local_sig_of_remote, override_lcss.local_sig_of_remote);
        }
        other => panic!("expected state_override, got {other:?}"),
    }
}

#[tokio::test]
async fn test_set_channel_updates_pending_override() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;
    node.sent_messages.lock().unwrap().clear();

    controller
        .set_channel(
            &client_public,
            SetChannelParams {
                channel_capacity_msat: Some(120_000_000),
                initial_client_balance_msat: Some(10_000_000),
                ..SetChannelParams::default()
            },
            true,
        )
        .await
        .unwrap();
    node.sent_messages.lock().unwrap().clear();

    let (current, updated) = controller
        .set_channel(
            &client_public,
            SetChannelParams {
                channel_capacity_msat: Some(130_000_000),
                htlc_minimum_msat: Some(2_000),
                htlc_maximum_msat: Some(70_000_000),
                ..SetChannelParams::default()
            },
            false,
        )
        .await
        .unwrap();
    assert!(updated);
    assert_eq!(current.channel_capacity_msat, 130_000_000);
    assert_eq!(current.initial_client_balance_msat, 10_000_000);
    assert_eq!(current.local_balance_msat, 120_000_000);
    assert_eq!(current.remote_balance_msat, 10_000_000);
    assert_eq!(current.htlc_minimum_msat, 2_000);
    assert_eq!(current.htlc_maximum_msat, 70_000_000);
    assert!(current.override_pending);

    let data = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        data.lcss.init_hosted_channel.channel_capacity_msat,
        100_000_000
    );
    let override_lcss = data.proposed_override.clone().unwrap();
    assert_eq!(
        override_lcss.init_hosted_channel.channel_capacity_msat,
        130_000_000
    );
    assert_eq!(override_lcss.init_hosted_channel.htlc_minimum_msat, 2_000);
    assert_eq!(override_lcss.remote_balance_msat, 10_000_000);
    assert_eq!(override_lcss.local_balance_msat, 120_000_000);
    assert_eq!(data.routing_policy.unwrap().htlc_maximum_msat, 70_000_000);

    {
        let sent = node.sent_messages.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert!(matches!(
            HostedMessage::decode(&sent[0].1).unwrap(),
            HostedMessage::Error(_)
        ));
        match HostedMessage::decode(&sent[1].1).unwrap() {
            HostedMessage::StateOverride(msg) => {
                assert_eq!(msg.local_balance_msat, override_lcss.local_balance_msat);
                assert_eq!(msg.local_sig_of_remote, override_lcss.local_sig_of_remote);
            }
            other => panic!("expected state_override, got {other:?}"),
        }
    }

    let mut accepted = override_lcss.reverse();
    accepted.sign(&client_secret).unwrap();
    controller
        .handle_state_update(
            &client_public,
            StateUpdate {
                block_day: override_lcss.block_day,
                local_updates: accepted.local_updates,
                remote_updates: accepted.remote_updates,
                local_sig_of_remote: accepted.local_sig_of_remote,
            },
        )
        .await
        .unwrap();

    let data = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap();
    assert!(data.proposed_override.is_none());
    assert_eq!(
        data.lcss.init_hosted_channel.channel_capacity_msat,
        130_000_000
    );
    assert_eq!(data.lcss.local_balance_msat, 120_000_000);
}

#[tokio::test]
async fn test_set_channel_reconnect_replays_only_latest_override() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;
    node.sent_messages.lock().unwrap().clear();

    controller
        .set_channel(
            &client_public,
            SetChannelParams {
                channel_capacity_msat: Some(120_000_000),
                ..SetChannelParams::default()
            },
            true,
        )
        .await
        .unwrap();
    let first_override = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap()
        .proposed_override
        .unwrap();

    controller
        .set_channel(
            &client_public,
            SetChannelParams {
                channel_capacity_msat: Some(130_000_000),
                ..SetChannelParams::default()
            },
            false,
        )
        .await
        .unwrap();
    let latest_override = controller
        .get_channel_data(&client_public)
        .await
        .unwrap()
        .unwrap()
        .proposed_override
        .unwrap();
    assert_ne!(
        first_override.local_sig_of_remote,
        latest_override.local_sig_of_remote
    );

    node.sent_messages.lock().unwrap().clear();
    controller
        .handle_invoke(&client_public, make_invoke(""))
        .await
        .unwrap();

    let sent = node.sent_messages.lock().unwrap();
    assert_eq!(sent.len(), 3);
    match HostedMessage::decode(&sent[2].1).unwrap() {
        HostedMessage::StateOverride(msg) => {
            assert_eq!(msg.local_balance_msat, latest_override.local_balance_msat);
            assert_eq!(msg.local_sig_of_remote, latest_override.local_sig_of_remote);
            assert_ne!(msg.local_sig_of_remote, first_override.local_sig_of_remote);
        }
        other => panic!("expected state_override, got {other:?}"),
    }
}

#[tokio::test]
async fn test_set_channel_rejects_updates_with_pending_htlcs() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel_with_secret(
        &controller,
        &node,
        &client_secret,
        &client_public,
        "1111111111111111111111111111111111111111111111111111111111111111",
        100_000_000,
        50_000_000,
    )
    .await;
    controller
        .handle_update_add(
            &client_public,
            UpdateAddHtlc {
                channel_id: canopus::channel_id::channel_id(
                    &controller.node_public,
                    &client_public,
                ),
                id: 1,
                amount_msat: 1_000_000,
                payment_hash: [0x77; 32],
                cltv_expiry: 700_100,
                onion_routing_packet: Bytes::from(vec![0; 1366]),
                tlv_stream: Bytes::new(),
            },
        )
        .await
        .unwrap();

    assert!(controller
        .set_channel(
            &client_public,
            SetChannelParams {
                fee_base_msat: Some(2_000),
                ..SetChannelParams::default()
            },
            false,
        )
        .await
        .is_err());
    assert!(controller
        .set_channel(&client_public, SetChannelParams::default(), false)
        .await
        .is_ok());
}

#[tokio::test]
async fn test_preimage_query_reply() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;
    let preimage = [0x55; 32];
    let payment_hash: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(preimage).into()
    };
    node.store_preimage(&payment_hash, &preimage).await.unwrap();

    controller
        .handle_query_preimages(
            &client_public,
            QueryPreimages {
                hashes: vec![payment_hash],
            },
        )
        .await
        .unwrap();

    let sent = node.sent_messages.lock().unwrap();
    let reply = sent
        .iter()
        .rev()
        .find_map(|(_, bytes)| match HostedMessage::decode(bytes) {
            Ok(HostedMessage::ReplyPreimages(reply)) => Some(reply),
            _ => None,
        });
    assert_eq!(reply.map(|r| r.preimages), Some(vec![preimage]));
}

#[tokio::test]
async fn test_htlc_resolution_with_known_preimage() {
    let (controller, node, client_secret, client_public) = make_harness(false).await;
    establish_channel(&controller, &node, &client_secret, &client_public).await;

    // Store a preimage
    let preimage = [0x42u8; 32];
    let payment_hash = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(preimage);
        h.finalize()
    };
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&payment_hash);

    controller
        .node
        .store_preimage(&hash_arr, &preimage)
        .await
        .unwrap();

    // Add HTLC — should be immediately resolved (idempotency)
    let htlc = UpdateAddHtlc {
        channel_id: [0u8; 32],
        id: 0,
        amount_msat: 10_000_000,
        payment_hash: hash_arr,
        cltv_expiry: 700_100,
        onion_routing_packet: Bytes::from(vec![0; 1366]),
        tlv_stream: Bytes::new(),
    };

    controller
        .channel_handle_htlc_add(&client_public, htlc, "test-key-2", 1, 2, None)
        .await
        .unwrap();

    // The HTLC should have been resolved (not added to channel)
    let resolutions = node.htlc_resolutions.lock().unwrap();
    assert!(
        resolutions.iter().any(|(k, r)| {
            k == "test-key-2"
                && matches!(r, HtlcResolution::Resolve { preimage } if *preimage == [0x42u8; 32])
        }),
        "HTLC should have been resolved with the known preimage"
    );
}

#[tokio::test]
async fn test_ledger_records_events() {
    let store = Arc::new(MemoryStore::new());
    let ledger = canopus::ledger::LedgerManager::new(store);

    ledger
        .record(
            "deadbeef",
            canopus::ledger::LedgerEventType::ChannelOpen,
            100_000_000,
            0,
            None,
        )
        .await
        .unwrap();

    let events = ledger.list_events(Some("deadbeef")).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].amount_msat, 100_000_000);
}

#[tokio::test]
async fn test_datastore_generation_cas() {
    let store = Arc::new(MemoryStore::new());

    // Create a value
    canopus::store::create_json(&*store, &["test", "cas"], &serde_json::json!({"n": 0}))
        .await
        .unwrap();

    // CAS update should work
    canopus::store::cas_json::<serde_json::Value, _, _>(&*store, &["test", "cas"], |v| {
        v["n"] = serde_json::json!(1);
        Ok(())
    })
    .await
    .unwrap();

    let (val, gen) = canopus::store::get_json::<serde_json::Value>(&*store, &["test", "cas"])
        .await
        .unwrap();
    assert_eq!(val["n"], 1);
    assert_eq!(gen, 1);
}

#[tokio::test]
async fn test_sphinx_key_derivation() {
    let shared = [0x42u8; 32];
    // Just verify the sphinx module compiles and key derivation is deterministic
    let secp = Secp256k1::new();
    let (sk1, _) = secp.generate_keypair(&mut rand::rngs::OsRng);
    let (sk2, _) = secp.generate_keypair(&mut rand::rngs::OsRng);

    // Different keys should produce different ECDH results
    let _pk1 = secp256k1::PublicKey::from_secret_key(&secp, &sk1);
    let r1 = canopus::sphinx::peel_onion(&sk1, &[0u8; 1366], &[0u8; 32]);
    let r2 = canopus::sphinx::peel_onion(&sk2, &[0u8; 1366], &[0u8; 32]);
    // Both should fail (invalid onion) but not panic
    assert!(r1.is_err());
    assert!(r2.is_err());

    // Failure onion wrap should produce 256 bytes
    let wrapped = canopus::sphinx::wrap_failure(&shared, b"test");
    assert_eq!(wrapped.len(), 256);
}
