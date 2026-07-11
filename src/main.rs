use canopusd::channel;
use canopusd::cln_node::ClnNode;
use canopusd::cln_store::ClnStore;
use canopusd::config::Config;
use canopusd::keys::NodeKeys;
use canopusd::ledger::LedgerManager;
use canopusd::wire::{
    TAG_ANNOUNCEMENT_SIGNATURE, TAG_ASK_BRANDING_INFO, TAG_ERROR, TAG_HOSTED_CHANNEL_BRANDING,
    TAG_INIT_HOSTED_CHANNEL, TAG_INVOKE_HOSTED_CHANNEL, TAG_LAST_CROSS_SIGNED_STATE,
    TAG_PHC_CHANNEL_UPDATE_GOSSIP, TAG_PHC_CHANNEL_UPDATE_SYNC, TAG_QUERY_PREIMAGES,
    TAG_QUERY_PUBLIC_HOSTED_CHANNELS, TAG_REPLY_PREIMAGES, TAG_REPLY_PUBLIC_HOSTED_CHANNELS_END,
    TAG_RESIZE_CHANNEL, TAG_STATE_OVERRIDE, TAG_STATE_UPDATE, TAG_UPDATE_ADD_HTLC,
    TAG_UPDATE_FAIL_HTLC, TAG_UPDATE_FAIL_MALFORMED_HTLC, TAG_UPDATE_FULFILL_HTLC,
};
use cln_plugin::options::Value;
use cln_plugin::options::{BooleanConfigOption, ConfigOption};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Plugin state shared across handlers.
#[derive(Clone)]
pub struct PluginState {
    runtime: Arc<RwLock<RuntimeState>>,
    pub config: Config,
    rpc_path: PathBuf,
    hsm_secret_path: PathBuf,
}

pub enum RuntimeState {
    Locked {
        reason: String,
    },
    Unlocked {
        controller: Arc<channel::ChannelController>,
        cln_node: Arc<ClnNode>,
        ledger: Arc<LedgerManager>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let builder = cln_plugin::Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(ConfigOption::new_str_no_default(
            "canopusd-contact-url",
            "URL for human contact (branding)",
        ))
        .option(ConfigOption::new_str_no_default(
            "canopusd-color",
            "Hex color for branding (e.g. #ff0000)",
        ))
        .option(ConfigOption::new_str_no_default(
            "canopusd-logo",
            "Path to PNG logo file for branding (max 65535 bytes)",
        ))
        .option(ConfigOption::new_i64_no_default(
            "canopusd-capacity-msat",
            "Default channel capacity in millisatoshi",
        ))
        .option(ConfigOption::new_i64_no_default(
            "canopusd-initial-balance-msat",
            "Default initial client balance in millisatoshi",
        ))
        .option(ConfigOption::new_i64_no_default(
            "canopusd-fee-base-msat",
            "Base fee in millisatoshi for forwarding",
        ))
        .option(ConfigOption::new_i64_no_default(
            "canopusd-fee-ppm",
            "Proportional fee in parts per million",
        ))
        .option(ConfigOption::new_i64_no_default(
            "canopusd-cltv-delta",
            "CLTV expiry delta for forwarded HTLCs",
        ))
        .option(ConfigOption::new_i64_no_default(
            "canopusd-htlc-min-msat",
            "Minimum HTLC amount in millisatoshi",
        ))
        .option(ConfigOption::new_i64_no_default(
            "canopusd-max-htlcs",
            "Maximum accepted HTLCs per channel",
        ))
        .option(ConfigOption::new_i64_no_default(
            "canopusd-max-inflight-msat",
            "Maximum HTLC value in flight per channel",
        ))
        .option(BooleanConfigOption::new_bool_no_default(
            "canopusd-require-secret",
            "Require a secret for channel invocation",
        ))
        .option(BooleanConfigOption::new_bool_no_default(
            "canopusd-preimage-scan",
            "Scan blocks for OP_RETURN-published preimages",
        ))
        .featurebits(
            cln_plugin::FeatureBitsKind::Init,
            compute_feature_bits_hex(&[257]),
        )
        .featurebits(
            cln_plugin::FeatureBitsKind::Node,
            compute_feature_bits_hex(&[257]),
        )
        .subscribe("connect", handler::handle_connect)
        .subscribe("disconnect", handler::handle_disconnect)
        .subscribe("sendpay_success", handler::handle_sendpay_success)
        .subscribe("sendpay_failure", handler::handle_sendpay_failure)
        .custommessages(vec![
            TAG_INVOKE_HOSTED_CHANNEL,
            TAG_INIT_HOSTED_CHANNEL,
            TAG_LAST_CROSS_SIGNED_STATE,
            TAG_STATE_UPDATE,
            TAG_STATE_OVERRIDE,
            TAG_HOSTED_CHANNEL_BRANDING,
            TAG_ANNOUNCEMENT_SIGNATURE,
            TAG_RESIZE_CHANNEL,
            TAG_QUERY_PUBLIC_HOSTED_CHANNELS,
            TAG_REPLY_PUBLIC_HOSTED_CHANNELS_END,
            TAG_QUERY_PREIMAGES,
            TAG_REPLY_PREIMAGES,
            TAG_ASK_BRANDING_INFO,
            TAG_UPDATE_ADD_HTLC,
            TAG_UPDATE_FULFILL_HTLC,
            TAG_UPDATE_FAIL_HTLC,
            TAG_UPDATE_FAIL_MALFORMED_HTLC,
            TAG_ERROR,
            TAG_PHC_CHANNEL_UPDATE_GOSSIP,
            TAG_PHC_CHANNEL_UPDATE_SYNC,
        ])
        .hook("custommsg", handler::handle_custommsg)
        .hook("htlc_accepted", handler::handle_htlc_accepted)
        .hook("rpc_command", handler::handle_rpc_command)
        .rpcmethod_from_builder(
            cln_plugin::RpcMethodBuilder::new("canopusd-list", handler::handle_list)
                .usage("")
                .description("List all hosted channels known to canopusd, returning each peer id and derived channel status."),
        )
        .rpcmethod_from_builder(
            cln_plugin::RpcMethodBuilder::new("canopusd-channel", handler::handle_channel)
                .usage("peerid")
                .description("Show the full persisted hosted-channel state for peerid, including the current status and channel data. Returns null if no channel is known for that peer."),
        )
        .rpcmethod_from_builder(
            cln_plugin::RpcMethodBuilder::new("canopusd-addsecret", handler::handle_add_secret)
                .usage("secret capacity_msat initial_balance_msat")
                .description("Create a one-time channel provisioning secret. A client invoking a hosted channel with this secret receives the supplied total channel capacity and initial client balance, both in millisatoshi."),
        )
        .rpcmethod_from_builder(
            cln_plugin::RpcMethodBuilder::new(
                "canopusd-removesecret",
                handler::handle_remove_secret,
            )
            .usage("secret")
            .description("Remove an unused channel provisioning secret so it can no longer be consumed by a hosted-channel client."),
        )
        .rpcmethod_from_builder(
            cln_plugin::RpcMethodBuilder::new("canopusd-listsecrets", handler::handle_list_secrets)
                .usage("")
                .description("List configured channel provisioning secrets with secret values redacted. Use this to audit available one-time hosted-channel invitations."),
        )
        .rpcmethod_from_builder(
            cln_plugin::RpcMethodBuilder::new("canopusd-reset", handler::handle_reset)
                .usage("peerid [new_local_balance_msat]")
                .description("Propose a state_override for an errored hosted channel. If new_local_balance_msat is provided, the override uses that local balance; otherwise canopusd proposes a reset from current state."),
        )
        .rpcmethod_from_builder(
            cln_plugin::RpcMethodBuilder::new("canopusd-resize", handler::handle_resize)
                .usage("peerid capacity_sat")
                .description("Authorize a hosted-channel resize requested by peerid up to capacity_sat. Set capacity_sat to 0 to cancel a previously authorized resize."),
        )
        .rpcmethod_from_builder(
            cln_plugin::RpcMethodBuilder::new("canopusd-policy", handler::handle_policy)
                .usage("[channel_capacity_msat] [initial_client_balance_msat] [max_htlc_value_in_flight_msat] [htlc_minimum_msat] [max_accepted_htlcs] [fee_base_msat] [fee_proportional_millionths] [cltv_expiry_delta]")
                .description("Show or update the default hosted-channel policy. Omitted fields keep their current values. These defaults apply to new channels and to invocations that do not consume a provisioning secret."),
        )
        .rpcmethod_from_builder(
            cln_plugin::RpcMethodBuilder::new("canopusd-events", handler::handle_events)
                .usage("[peerid]")
                .description("List canopusd accounting events. When peerid is supplied, only events for that hosted-channel peer are returned."),
        )
        .rpcmethod_from_builder(
            cln_plugin::RpcMethodBuilder::new("canopusd-status", handler::handle_status)
                .usage("")
                .description("Show whether canopusd is locked or unlocked. When locked, the response includes the reason and hsm_secret path; when unlocked, it includes the node id."),
        )
        .rpcmethod_from_builder(
            cln_plugin::RpcMethodBuilder::new("canopusd-unlock", handler::handle_unlock)
                .usage("passphrase | passphrase_file")
                .description("Unlock canopusd when the CLN hsm_secret requires a passphrase. Provide exactly one of passphrase or passphrase_file. Prefer passphrase_file because direct passphrase arguments may be visible in shell history or process lists."),
        );

    let Some(configured) = builder.configure().await? else {
        return Ok(());
    };
    let plugin_config = configured.configuration();
    let rpc_path = PathBuf::from(&plugin_config.lightning_dir).join(&plugin_config.rpc_file);
    let hsm_secret_path = PathBuf::from(&plugin_config.lightning_dir).join("hsm_secret");

    let mut config = config_from_options(&configured)?;
    config.network = plugin_config.network.clone();
    config.chain_hash = chain_hash_for_network(&plugin_config.network)?;
    config.hsm_secret_path = hsm_secret_path.clone();

    let runtime = match build_runtime(&config, &rpc_path, &hsm_secret_path, None).await {
        Ok(runtime) => runtime,
        Err(err) if requires_unlock(&err) => RuntimeState::Locked {
            reason: err.to_string(),
        },
        Err(err) => return Err(err),
    };

    let plugin = configured
        .start(PluginState {
            runtime: Arc::new(RwLock::new(runtime)),
            config,
            rpc_path,
            hsm_secret_path,
        })
        .await?;

    tracing::info!("canopusd plugin started");
    plugin.join().await?;

    Ok(())
}

async fn build_runtime(
    config: &Config,
    rpc_path: &std::path::Path,
    hsm_secret_path: &std::path::Path,
    passphrase: Option<&str>,
) -> anyhow::Result<RuntimeState> {
    let keys = NodeKeys::from_file_with_passphrase(hsm_secret_path, passphrase)?;
    let node_public = keys.public;
    let cln_store = Arc::new(ClnStore::new(rpc_path).await?);
    let cln_node = Arc::new(ClnNode::new(rpc_path, node_public).await?);
    let ledger = Arc::new(LedgerManager::new(cln_store.clone()));
    let controller = Arc::new(channel::ChannelController {
        store: cln_store,
        node: cln_node.clone(),
        config: config.clone(),
        node_secret: keys.secret,
        node_public,
        peer_wire_encodings: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
    });
    Ok(RuntimeState::Unlocked {
        controller,
        cln_node,
        ledger,
    })
}

fn requires_unlock(err: &anyhow::Error) -> bool {
    err.downcast_ref::<canopusd::keys::KeyError>()
        .is_some_and(|e| matches!(e, canopusd::keys::KeyError::PassphraseRequired(_)))
}

fn config_from_options<S, I, O>(
    plugin: &cln_plugin::ConfiguredPlugin<S, I, O>,
) -> anyhow::Result<Config>
where
    S: Clone + Send + Sync + 'static,
    I: tokio::io::AsyncRead + Send + Unpin + 'static,
    O: Send + tokio::io::AsyncWrite + Unpin + 'static,
{
    let mut config = Config::default();
    if let Some(Value::String(v)) = plugin.option_str("canopusd-contact-url")? {
        config.branding.contact_url = Some(v);
    }
    if let Some(Value::String(v)) = plugin.option_str("canopusd-color")? {
        config.branding.color = Some(v);
    }
    if let Some(Value::String(v)) = plugin.option_str("canopusd-logo")? {
        config.branding.logo_path = Some(PathBuf::from(v));
    }
    if let Some(Value::Integer(v)) = plugin.option_str("canopusd-capacity-msat")? {
        config.policy.channel_capacity_msat = v as u64;
    }
    if let Some(Value::Integer(v)) = plugin.option_str("canopusd-initial-balance-msat")? {
        config.policy.initial_client_balance_msat = v as u64;
    }
    if let Some(Value::Integer(v)) = plugin.option_str("canopusd-fee-base-msat")? {
        config.policy.fee_base_msat = v as u32;
    }
    if let Some(Value::Integer(v)) = plugin.option_str("canopusd-fee-ppm")? {
        config.policy.fee_proportional_millionths = v as u32;
    }
    if let Some(Value::Integer(v)) = plugin.option_str("canopusd-cltv-delta")? {
        config.policy.cltv_expiry_delta = v as u16;
    }
    if let Some(Value::Integer(v)) = plugin.option_str("canopusd-htlc-min-msat")? {
        config.policy.htlc_minimum_msat = v as u64;
    }
    if let Some(Value::Integer(v)) = plugin.option_str("canopusd-max-htlcs")? {
        config.policy.max_accepted_htlcs = v as u16;
    }
    if let Some(Value::Integer(v)) = plugin.option_str("canopusd-max-inflight-msat")? {
        config.policy.max_htlc_value_in_flight_msat = v as u64;
    }
    if let Some(Value::Boolean(v)) = plugin.option_str("canopusd-require-secret")? {
        config.require_secret = v;
    }
    if let Some(Value::Boolean(v)) = plugin.option_str("canopusd-preimage-scan")? {
        config.preimage_scan = v;
    }
    config.validate()?;
    Ok(config)
}

fn chain_hash_for_network(network: &str) -> anyhow::Result<[u8; 32]> {
    // scoin/poncho uses Block.hash (raw double-SHA256 of the genesis header),
    // which is the reverse of the display-order block hash.
    let hex = match network {
        "bitcoin" | "mainnet" => "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        "testnet" => "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000",
        "signet" => "48164da60c7fbf8c3c79114e940b0b4b7c9ff9f01f2c4225e973988108000000",
        "regtest" => "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
        other => anyhow::bail!("unsupported network {other}"),
    };
    let bytes = hex::decode(hex)?;
    Ok(bytes.try_into().expect("chain hashes are 32 bytes"))
}

/// Compute the feature bits hex bitmask from a list of bit positions.
fn compute_feature_bits_hex(bits: &[u64]) -> String {
    if bits.is_empty() {
        return "00".to_string();
    }
    let max_bit = *bits.iter().max().unwrap_or(&0) as usize;
    let byte_len = max_bit / 8 + 1;
    let mut bytes = vec![0u8; byte_len];
    for &bit in bits {
        let byte_idx = byte_len - 1 - (bit as usize / 8);
        let bit_idx = bit as usize % 8;
        bytes[byte_idx] |= 1 << bit_idx;
    }
    hex::encode(&bytes)
}

/// Plugin handlers — bridge CLN plugin messages to the channel controller.
mod handler {
    use super::{build_runtime, PluginState, RuntimeState};
    use bytes::Bytes;
    use canopusd::channel_id::hosted_short_channel_id;
    use canopusd::node::{HtlcResolution, PaymentStatus};
    use canopusd::wire::codecs::UpdateAddHtlc;
    use canopusd::wire::HostedMessage;
    use cln_plugin::Plugin;
    use lightning_invoice::Bolt11Invoice;
    use secp256k1::PublicKey;
    use serde_json::{json, Value};
    use std::str::FromStr;
    use zeroize::Zeroize;

    async fn controller(
        plugin: &Plugin<PluginState>,
    ) -> Result<std::sync::Arc<canopusd::channel::ChannelController>, cln_plugin::Error> {
        match &*plugin.state().runtime.read().await {
            RuntimeState::Unlocked { controller, .. } => Ok(controller.clone()),
            RuntimeState::Locked { reason } => Err(anyhow::anyhow!("canopusd locked: {reason}")),
        }
    }

    async fn cln_node(
        plugin: &Plugin<PluginState>,
    ) -> Result<std::sync::Arc<canopusd::cln_node::ClnNode>, cln_plugin::Error> {
        match &*plugin.state().runtime.read().await {
            RuntimeState::Unlocked { cln_node, .. } => Ok(cln_node.clone()),
            RuntimeState::Locked { reason } => Err(anyhow::anyhow!("canopusd locked: {reason}")),
        }
    }

    async fn ledger(
        plugin: &Plugin<PluginState>,
    ) -> Result<std::sync::Arc<canopusd::ledger::LedgerManager>, cln_plugin::Error> {
        match &*plugin.state().runtime.read().await {
            RuntimeState::Unlocked { ledger, .. } => Ok(ledger.clone()),
            RuntimeState::Locked { reason } => Err(anyhow::anyhow!("canopusd locked: {reason}")),
        }
    }

    async fn is_locked(plugin: &Plugin<PluginState>) -> bool {
        matches!(
            *plugin.state().runtime.read().await,
            RuntimeState::Locked { .. }
        )
    }

    async fn locked_reason(plugin: &Plugin<PluginState>) -> Option<String> {
        match &*plugin.state().runtime.read().await {
            RuntimeState::Locked { reason } => Some(reason.clone()),
            RuntimeState::Unlocked { .. } => None,
        }
    }

    fn trim_one_trailing_newline(s: &mut String) {
        if s.ends_with('\n') {
            s.pop();
            if s.ends_with('\r') {
                s.pop();
            }
        }
    }

    fn unlock_passphrase(request: &Value) -> Result<String, cln_plugin::Error> {
        let passphrase = arg(request, 0, "passphrase").and_then(|v| v.as_str());
        let passphrase_file = arg(request, 1, "passphrase_file").and_then(|v| v.as_str());
        match (passphrase, passphrase_file) {
            (Some(_), Some(_)) => {
                anyhow::bail!("provide exactly one of passphrase or passphrase_file")
            }
            (None, None) => anyhow::bail!("provide exactly one of passphrase or passphrase_file"),
            (Some(passphrase), None) => Ok(passphrase.to_string()),
            (None, Some(path)) => {
                let mut passphrase = std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("cannot read passphrase_file {path}: {e}"))?;
                trim_one_trailing_newline(&mut passphrase);
                Ok(passphrase)
            }
        }
    }

    fn param<'a>(request: &'a Value, key: &str) -> Option<&'a Value> {
        request
            .get(key)
            .or_else(|| request.get("params").and_then(|p| p.get(key)))
    }

    fn arg<'a>(request: &'a Value, index: usize, key: &str) -> Option<&'a Value> {
        param(request, key).or_else(|| request.as_array().and_then(|a| a.get(index)))
    }

    fn parse_peer(s: &str) -> Result<PublicKey, cln_plugin::Error> {
        PublicKey::from_str(s).map_err(|e| anyhow::anyhow!(e))
    }

    fn parse_msat(value: &Value) -> Option<u64> {
        if let Some(n) = value.as_u64() {
            return Some(n);
        }
        let s = value.as_str()?;
        s.strip_suffix("msat").unwrap_or(s).parse::<u64>().ok()
    }

    fn parse_32_hex(s: &str) -> Result<[u8; 32], cln_plugin::Error> {
        let bytes = hex::decode(s)?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32-byte hex value"))
    }

    fn resolution_to_json(resolution: HtlcResolution) -> Value {
        match resolution {
            HtlcResolution::Resolve { preimage } => {
                json!({ "result": "resolve", "payment_key": hex::encode(preimage) })
            }
            HtlcResolution::Fail { failure_onion } => {
                json!({ "result": "fail", "failure_onion": hex::encode(failure_onion) })
            }
            HtlcResolution::FailMessage { code, data } => {
                let mut message = Vec::with_capacity(2 + data.len());
                message.extend_from_slice(&code.to_be_bytes());
                message.extend_from_slice(&data);
                json!({ "result": "fail", "failure_message": hex::encode(message) })
            }
            HtlcResolution::Continue => json!({ "result": "continue" }),
        }
    }

    fn parse_forward_label(label: &str) -> Option<(u64, u64)> {
        if let Some((scid, id)) = label.split_once('/') {
            return Some((scid.parse().ok()?, id.parse().ok()?));
        }
        let value: Value = serde_json::from_str(label).ok()?;
        let arr = value.as_array()?;
        let scid = arr.first()?.as_str()?.parse().ok()?;
        let id = arr.get(1)?.as_u64()?;
        Some((scid, id))
    }

    fn nested<'a>(request: &'a Value, key: &str) -> &'a Value {
        request.get(key).unwrap_or(request)
    }

    fn rpc_param<'a>(request: &'a Value, key: &str, index: usize) -> Option<&'a Value> {
        let params = request
            .get("rpc_command")
            .and_then(|v| v.get("params"))
            .or_else(|| request.get("params"))?;
        params
            .get(key)
            .or_else(|| params.as_array().and_then(|a| a.get(index)))
    }

    async fn hosted_invoice_target(
        controller: &canopusd::channel::ChannelController,
        invoice: &Bolt11Invoice,
    ) -> Result<Option<PublicKey>, cln_plugin::Error> {
        for route in invoice.route_hints() {
            if route.0.len() != 1 {
                continue;
            }
            let hop = &route.0[0];
            let Ok(src) = secp256k1::PublicKey::from_slice(&hop.src_node_id.serialize()) else {
                continue;
            };
            if src != controller.node_public {
                continue;
            }
            for peer in controller.list_channels().await? {
                if hosted_short_channel_id(&controller.node_public, &peer) == hop.short_channel_id {
                    return Ok(Some(peer));
                }
            }
        }
        Ok(None)
    }

    fn hosted_pay_success(
        peer_id: &PublicKey,
        payment_hash: &[u8; 32],
        amount_msat: u64,
        preimage: [u8; 32],
    ) -> Value {
        json!({
            "return": {
                "result": {
                    "destination": peer_id.to_string(),
                    "payment_hash": hex::encode(payment_hash),
                    "parts": 1,
                    "amount_msat": amount_msat,
                    "msatoshi_sent": amount_msat,
                    "payment_preimage": hex::encode(preimage),
                    "status": "complete"
                }
            }
        })
    }

    pub async fn handle_connect(
        plugin: Plugin<PluginState>,
        _request: Value,
    ) -> Result<(), cln_plugin::Error> {
        if is_locked(&plugin).await {
            return Ok(());
        }
        let _ = controller(&plugin).await?;
        Ok(())
    }

    pub async fn handle_disconnect(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<(), cln_plugin::Error> {
        if let Some(peer) = param(&request, "id").and_then(|v| v.as_str()) {
            if is_locked(&plugin).await {
                return Ok(());
            }
            let peer = parse_peer(peer)?;
            controller(&plugin).await?.handle_disconnect(&peer).await?;
        }
        Ok(())
    }

    pub async fn handle_sendpay_success(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<(), cln_plugin::Error> {
        let payload = nested(&request, "sendpay_success");
        let Some((scid, htlc_id)) = payload
            .get("label")
            .and_then(|v| v.as_str())
            .and_then(parse_forward_label)
        else {
            return Ok(());
        };
        if is_locked(&plugin).await {
            return Ok(());
        }
        let preimage = payload
            .get("payment_preimage")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("sendpay_success missing payment_preimage"))
            .and_then(parse_32_hex)?;
        controller(&plugin)
            .await?
            .handle_outgoing_payment_result(scid, htlc_id, PaymentStatus::Succeeded { preimage })
            .await?;
        Ok(())
    }

    pub async fn handle_sendpay_failure(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<(), cln_plugin::Error> {
        let payload = nested(nested(&request, "sendpay_failure"), "data");
        let Some((scid, htlc_id)) = payload
            .get("label")
            .and_then(|v| v.as_str())
            .and_then(parse_forward_label)
        else {
            return Ok(());
        };
        if payload.get("status").and_then(|v| v.as_str()) == Some("pending") {
            return Ok(());
        }
        if is_locked(&plugin).await {
            return Ok(());
        }
        let onion = payload
            .get("onionreply")
            .or_else(|| payload.get("erroronion"))
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok())
            .unwrap_or_default();
        controller(&plugin)
            .await?
            .handle_outgoing_payment_result(
                scid,
                htlc_id,
                PaymentStatus::Failed {
                    failure_onion: Bytes::from(onion),
                },
            )
            .await?;
        Ok(())
    }

    pub async fn handle_custommsg(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        if is_locked(&plugin).await {
            return Ok(json!({ "result": "continue" }));
        }
        let peer_id = request
            .get("peer_id")
            .or_else(|| request.get("node_id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("custommsg missing peer_id"))?;
        let message = request
            .get("message")
            .or_else(|| request.get("payload"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("custommsg missing message"))?;
        let peer_id = parse_peer(peer_id)?;
        let bytes = hex::decode(message)?;
        let decoded = match HostedMessage::decode_legacy_aware(&bytes) {
            Ok(decoded) => decoded,
            Err(err) => {
                let tag = bytes
                    .get(..2)
                    .map(|raw| u16::from_be_bytes([raw[0], raw[1]]));
                tracing::warn!(
                    %peer_id,
                    ?tag,
                    message_len = bytes.len(),
                    error_type = "decode_error",
                    error_message = %err,
                    "failed to decode custommsg"
                );
                return Ok(json!({ "result": "continue" }));
            }
        };
        let controller = controller(&plugin).await?;
        controller
            .note_peer_wire_encoding(&peer_id, decoded.encoding)
            .await;
        let msg = decoded.message;
        match msg {
            HostedMessage::InvokeHostedChannel(m) => controller.handle_invoke(&peer_id, m).await?,
            HostedMessage::LastCrossSignedState(m) => controller.handle_lcss(&peer_id, m).await?,
            HostedMessage::StateUpdate(m) => controller.handle_state_update(&peer_id, m).await?,
            HostedMessage::UpdateAddHtlc(m) => controller.handle_update_add(&peer_id, m).await?,
            HostedMessage::UpdateFulfillHtlc(m) => {
                controller.handle_update_fulfill(&peer_id, m).await?
            }
            HostedMessage::UpdateFailHtlc(m) => controller.handle_update_fail(&peer_id, m).await?,
            HostedMessage::UpdateFailMalformedHtlc(m) => {
                controller.handle_update_fail_malformed(&peer_id, m).await?
            }
            HostedMessage::ResizeChannel(m) => {
                controller.handle_resize_channel(&peer_id, m).await?
            }
            HostedMessage::QueryPreimages(m) => {
                controller.handle_query_preimages(&peer_id, m).await?
            }
            HostedMessage::ReplyPreimages(m) => {
                controller.handle_reply_preimages(&peer_id, m).await?
            }
            HostedMessage::Error(m) => controller.handle_error(&peer_id, m).await?,
            HostedMessage::AskBrandingInfo(m) => {
                controller.handle_ask_branding(&peer_id, m).await?
            }
            HostedMessage::StateOverride(_)
            | HostedMessage::InitHostedChannel(_)
            | HostedMessage::HostedChannelBranding(_)
            | HostedMessage::AnnouncementSignature(_)
            | HostedMessage::QueryPublicHostedChannels(_)
            | HostedMessage::ReplyPublicHostedChannelsEnd(_)
            | HostedMessage::PhcChannelUpdate(_) => {}
        }
        Ok(json!({ "result": "continue" }))
    }

    pub async fn handle_htlc_accepted(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        if is_locked(&plugin).await {
            return Ok(json!({ "result": "continue" }));
        }
        let controller = controller(&plugin).await?;
        let cln_node = cln_node(&plugin).await?;
        let htlc = request
            .get("htlc")
            .ok_or_else(|| anyhow::anyhow!("htlc_accepted missing htlc"))?;
        let onion = request
            .get("onion")
            .ok_or_else(|| anyhow::anyhow!("htlc_accepted missing onion"))?;
        let Some(target_scid) = onion
            .get("short_channel_id")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
        else {
            return Ok(json!({ "result": "continue" }));
        };
        let Some(peer_id) = controller
            .list_channels()
            .await?
            .into_iter()
            .find(|peer| hosted_short_channel_id(&controller.node_public, peer) == target_scid)
        else {
            return Ok(json!({ "result": "continue" }));
        };
        let incoming_amount_msat = htlc
            .get("amount_msat")
            .and_then(parse_msat)
            .ok_or_else(|| anyhow::anyhow!("htlc missing amount_msat"))?;
        let amount_msat = onion
            .get("forward_amount")
            .or_else(|| onion.get("forward_msat"))
            .and_then(parse_msat)
            .unwrap_or(incoming_amount_msat);
        let payment_hash = htlc
            .get("payment_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("htlc missing payment_hash"))
            .and_then(parse_32_hex)?;
        let incoming_cltv_expiry =
            htlc.get("cltv_expiry")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("htlc missing cltv_expiry"))? as u32;
        let cltv_expiry = onion
            .get("outgoing_cltv_value")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(incoming_cltv_expiry);
        let next_onion = onion
            .get("next_onion")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("onion missing next_onion"))?;
        let htlc_id = htlc.get("id").and_then(|v| v.as_u64()).unwrap_or_default();
        let incoming_scid = htlc
            .get("short_channel_id")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(target_scid);
        let result_key = format!("{incoming_scid}/{htlc_id}");
        let shared_secret = onion
            .get("shared_secret")
            .and_then(|v| v.as_str())
            .map(parse_32_hex)
            .transpose()?;
        let htlc = UpdateAddHtlc {
            channel_id: [0u8; 32],
            id: 0,
            amount_msat,
            payment_hash,
            cltv_expiry,
            onion_routing_packet: Bytes::from(hex::decode(next_onion)?),
            tlv_stream: Bytes::new(),
        };
        controller
            .channel_handle_htlc_add(
                &peer_id,
                htlc,
                &result_key,
                incoming_scid,
                htlc_id,
                shared_secret,
            )
            .await?;
        for _ in 0..600 {
            if let Some(resolution) = cln_node.take_resolution(&result_key).await {
                return Ok(resolution_to_json(resolution));
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Ok(json!({ "result": "fail", "failure_message": "1007" }))
    }

    pub async fn handle_rpc_command(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        let method = request
            .get("rpc_command")
            .and_then(|v| v.get("method"))
            .or_else(|| request.get("method"))
            .and_then(|v| v.as_str());
        if is_locked(&plugin).await {
            return Ok(json!({ "result": "continue" }));
        }
        let controller = controller(&plugin).await?;
        if method == Some("pay") {
            let Some(bolt11) = rpc_param(&request, "bolt11", 0).and_then(|v| v.as_str()) else {
                return Ok(json!({ "result": "continue" }));
            };
            let Ok(invoice) = bolt11.parse::<Bolt11Invoice>() else {
                return Ok(json!({ "result": "continue" }));
            };
            let amount_msat = rpc_param(&request, "amount_msat", 1)
                .or_else(|| rpc_param(&request, "msatoshi", 1))
                .and_then(parse_msat)
                .or_else(|| invoice.amount_milli_satoshis());
            let Some(amount_msat) = amount_msat else {
                return Ok(json!({ "result": "continue" }));
            };
            let Some(peer_id) = hosted_invoice_target(&controller, &invoice).await? else {
                return Ok(json!({ "result": "continue" }));
            };
            let payment_hash = parse_32_hex(&format!("{:x}", invoice.payment_hash()))?;
            if let Ok(Some(preimage)) = controller.node.lookup_preimage(&payment_hash).await {
                return Ok(hosted_pay_success(
                    &peer_id,
                    &payment_hash,
                    amount_msat,
                    preimage,
                ));
            }
            let current_height = controller.node.get_block_height().await.unwrap_or_default();
            let final_cltv = current_height
                .saturating_add(invoice.min_final_cltv_expiry_delta() as u32)
                .saturating_add(controller.effective_policy().await?.cltv_expiry_delta as u32);
            controller
                .send_direct_payment(
                    &peer_id,
                    amount_msat,
                    payment_hash,
                    final_cltv,
                    Some(invoice.payment_secret().0),
                )
                .await?;
            for _ in 0..600 {
                if let Ok(Some(preimage)) = controller.node.lookup_preimage(&payment_hash).await {
                    return Ok(hosted_pay_success(
                        &peer_id,
                        &payment_hash,
                        amount_msat,
                        preimage,
                    ));
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            tracing::info!("direct hosted payment timed out");
            return Ok(json!({
                "return": {
                    "error": {
                        "message": "direct hosted payment timed out"
                    }
                }
            }));
        }
        Ok(json!({ "result": "continue" }))
    }

    pub async fn handle_list(
        plugin: Plugin<PluginState>,
        _request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        let controller = controller(&plugin).await?;
        let mut channels = Vec::new();
        for peer in controller.list_channels().await? {
            let status = controller.get_status(&peer).await?.to_string();
            channels.push(json!({ "peer_id": peer.to_string(), "status": status }));
        }
        Ok(json!({ "channels": channels }))
    }

    pub async fn handle_channel(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        let peer = arg(&request, 0, "peerid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing peerid"))?;
        let peer = parse_peer(peer)?;
        let controller = controller(&plugin).await?;
        let Some(data) = controller.get_channel_data(&peer).await? else {
            return Ok(json!({ "channel": null }));
        };
        Ok(
            json!({ "peer_id": peer.to_string(), "status": controller.get_status(&peer).await?.to_string(), "data": data }),
        )
    }

    pub async fn handle_add_secret(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        let secret = arg(&request, 0, "secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing secret"))?
            .to_string();
        let capacity = arg(&request, 1, "capacity_msat")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("missing capacity_msat"))?;
        let initial = arg(&request, 2, "initial_balance_msat")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("missing initial_balance_msat"))?;
        controller(&plugin)
            .await?
            .add_secret(secret, capacity, initial)
            .await?;
        Ok(json!({ "ok": true }))
    }

    pub async fn handle_remove_secret(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        let secret = arg(&request, 0, "secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing secret"))?;
        controller(&plugin).await?.remove_secret(secret).await?;
        Ok(json!({ "ok": true }))
    }

    pub async fn handle_list_secrets(
        plugin: Plugin<PluginState>,
        _request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        let secrets = controller(&plugin).await?.list_secrets().await?;
        Ok(json!({ "secrets": secrets }))
    }

    pub async fn handle_reset(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        let peer = arg(&request, 0, "peerid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing peerid"))?;
        let peer = parse_peer(peer)?;
        let balance = arg(&request, 1, "new_local_balance_msat").and_then(|v| v.as_u64());
        controller(&plugin)
            .await?
            .propose_override(&peer, balance)
            .await?;
        Ok(json!({ "ok": true }))
    }

    pub async fn handle_events(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        let peer = arg(&request, 0, "peerid").and_then(|v| v.as_str());
        let ledger = ledger(&plugin).await?;
        let events = ledger.list_events(peer).await?;
        Ok(json!({ "events": events }))
    }

    pub async fn handle_policy(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        let controller = controller(&plugin).await?;
        let mut policy = controller.effective_policy().await?;
        let mut changed = false;

        if let Some(v) = param(&request, "channel_capacity_msat").and_then(|v| v.as_u64()) {
            policy.channel_capacity_msat = v;
            changed = true;
        }
        if let Some(v) = param(&request, "initial_client_balance_msat").and_then(|v| v.as_u64()) {
            policy.initial_client_balance_msat = v;
            changed = true;
        }
        if let Some(v) = param(&request, "max_htlc_value_in_flight_msat").and_then(|v| v.as_u64()) {
            policy.max_htlc_value_in_flight_msat = v;
            changed = true;
        }
        if let Some(v) = param(&request, "htlc_minimum_msat").and_then(|v| v.as_u64()) {
            policy.htlc_minimum_msat = v;
            changed = true;
        }
        if let Some(v) = param(&request, "max_accepted_htlcs").and_then(|v| v.as_u64()) {
            policy.max_accepted_htlcs = v
                .try_into()
                .map_err(|_| anyhow::anyhow!("max_accepted_htlcs exceeds u16"))?;
            changed = true;
        }
        if let Some(v) = param(&request, "fee_base_msat").and_then(|v| v.as_u64()) {
            policy.fee_base_msat = v
                .try_into()
                .map_err(|_| anyhow::anyhow!("fee_base_msat exceeds u32"))?;
            changed = true;
        }
        if let Some(v) = param(&request, "fee_proportional_millionths").and_then(|v| v.as_u64()) {
            policy.fee_proportional_millionths = v
                .try_into()
                .map_err(|_| anyhow::anyhow!("fee_proportional_millionths exceeds u32"))?;
            changed = true;
        }
        if let Some(v) = param(&request, "cltv_expiry_delta").and_then(|v| v.as_u64()) {
            policy.cltv_expiry_delta = v
                .try_into()
                .map_err(|_| anyhow::anyhow!("cltv_expiry_delta exceeds u16"))?;
            changed = true;
        }

        if policy.initial_client_balance_msat > policy.channel_capacity_msat {
            anyhow::bail!("initial_client_balance_msat exceeds channel_capacity_msat");
        }
        if changed {
            controller.set_policy(policy.clone()).await?;
        }
        Ok(json!({ "policy": policy, "updated": changed }))
    }

    pub async fn handle_resize(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        let peer = arg(&request, 0, "peerid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing peerid"))?;
        let peer = parse_peer(peer)?;
        let capacity_sat = arg(&request, 1, "capacity_sat")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("missing capacity_sat"))?;
        let capacity = if capacity_sat == 0 {
            None
        } else {
            Some(capacity_sat)
        };
        controller(&plugin)
            .await?
            .accept_resize(&peer, capacity)
            .await?;
        Ok(json!({ "ok": true }))
    }

    pub async fn handle_status(
        plugin: Plugin<PluginState>,
        _request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        match &*plugin.state().runtime.read().await {
            RuntimeState::Locked { reason } => Ok(json!({
                "status": "locked",
                "locked": true,
                "reason": reason,
                "hsm_secret_path": plugin.state().hsm_secret_path.display().to_string(),
            })),
            RuntimeState::Unlocked { controller, .. } => Ok(json!({
                "status": "unlocked",
                "locked": false,
                "node_id": controller.node_public.to_string(),
            })),
        }
    }

    pub async fn handle_unlock(
        plugin: Plugin<PluginState>,
        request: Value,
    ) -> Result<Value, cln_plugin::Error> {
        if locked_reason(&plugin).await.is_none() {
            anyhow::bail!("canopusd is already unlocked");
        }

        let mut passphrase = unlock_passphrase(&request)?;
        let runtime = build_runtime(
            &plugin.state().config,
            &plugin.state().rpc_path,
            &plugin.state().hsm_secret_path,
            Some(&passphrase),
        )
        .await;
        passphrase.zeroize();
        let runtime = runtime?;

        let node_id = match &runtime {
            RuntimeState::Unlocked { controller, .. } => controller.node_public.to_string(),
            RuntimeState::Locked { .. } => {
                unreachable!("build_runtime only returns unlocked runtime")
            }
        };
        *plugin.state().runtime.write().await = runtime;
        Ok(json!({ "status": "unlocked", "locked": false, "node_id": node_id }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn featurebits_hex_encoding() {
        let hex = compute_feature_bits_hex(&[257]);
        assert!(!hex.is_empty());
        let bytes = hex::decode(&hex).unwrap();
        assert_eq!(bytes.len(), 33);
        assert_eq!(bytes[0] & 0x02, 0x02);

        let hex2 = compute_feature_bits_hex(&[33175, 257]);
        let bytes2 = hex::decode(&hex2).unwrap();
        assert_eq!(bytes2.len(), 4147);

        assert_eq!(bytes2[0] & 0x80, 0x80);
        assert_eq!(bytes2[4114] & 0x02, 0x02);
    }

    #[test]
    fn featurebits_empty() {
        let hex = compute_feature_bits_hex(&[]);
        assert_eq!(hex, "00");
    }
}
