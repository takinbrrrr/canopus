//! Configuration for the canopus plugin.
//!
//! Options are accepted from the CLN config file or command line.
//! The CLN plugin framework parses them and passes them to us in the
//! `init` message.

use bytes::Bytes;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

static HEX_COLOR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^#[0-9a-fA-F]{6}$").unwrap());

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid color '{0}': expected #rrggbb")]
    InvalidColor(String),
    #[error("logo file '{0}' is too large ({1} bytes, max 65535)")]
    LogoTooLarge(String, usize),
    #[error("cannot read logo file '{0}': {1}")]
    LogoReadError(String, std::io::Error),
    #[error("invalid contact URL: {0}")]
    InvalidContactUrl(String),
    #[error("initial balance {0} exceeds capacity {1}")]
    BalanceExceedsCapacity(u64, u64),
}

/// Channel policy parameters (can be overridden per-secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPolicy {
    pub channel_capacity_msat: u64,
    pub initial_client_balance_msat: u64,
    pub max_htlc_value_in_flight_msat: u64,
    pub htlc_minimum_msat: u64,
    pub max_accepted_htlcs: u16,
    pub fee_base_msat: u32,
    pub fee_proportional_millionths: u32,
    pub cltv_expiry_delta: u16,
}

impl Default for ChannelPolicy {
    fn default() -> Self {
        Self {
            channel_capacity_msat: 100_000_000, // 100k sats
            initial_client_balance_msat: 0,
            max_htlc_value_in_flight_msat: 100_000_000, // 100k sats
            htlc_minimum_msat: 1_000,
            max_accepted_htlcs: 12,
            fee_base_msat: 0,
            fee_proportional_millionths: 1_000,
            cltv_expiry_delta: 6,
        }
    }
}

/// Branding configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Branding {
    pub contact_url: Option<String>,
    pub color: Option<String>,
    pub logo_path: Option<PathBuf>,
}

/// Top-level plugin configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub policy: ChannelPolicy,
    pub branding: Branding,
    pub require_secret: bool,
    pub preimage_scan: bool,
    /// Path to the hsm_secret file (set at init from lightning-dir).
    #[serde(skip)]
    pub hsm_secret_path: PathBuf,
    /// Chain hash (set at init from getinfo).
    #[serde(skip)]
    pub chain_hash: [u8; 32],
    /// Network name (bitcoin, testnet, regtest, signet).
    #[serde(skip)]
    pub network: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            policy: ChannelPolicy::default(),
            branding: Branding::default(),
            require_secret: true,
            preimage_scan: true,
            hsm_secret_path: PathBuf::new(),
            chain_hash: [0u8; 32],
            network: String::new(),
        }
    }
}

impl Config {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.policy.initial_client_balance_msat > self.policy.channel_capacity_msat {
            return Err(ConfigError::BalanceExceedsCapacity(
                self.policy.initial_client_balance_msat,
                self.policy.channel_capacity_msat,
            ));
        }
        if let Some(color) = &self.branding.color {
            if !HEX_COLOR_RE.is_match(color) {
                return Err(ConfigError::InvalidColor(color.clone()));
            }
        }
        if let Some(url) = &self.branding.contact_url {
            if url::Url::parse(url).is_err() {
                return Err(ConfigError::InvalidContactUrl(url.clone()));
            }
        }
        if let Some(path) = &self.branding.logo_path {
            let metadata = std::fs::metadata(path)
                .map_err(|e| ConfigError::LogoReadError(path.to_string_lossy().to_string(), e))?;
            if metadata.len() > 65535 {
                return Err(ConfigError::LogoTooLarge(
                    path.to_string_lossy().to_string(),
                    metadata.len() as usize,
                ));
            }
        }
        Ok(())
    }

    /// Parse the RGB color into a 3-byte array.
    pub fn rgb_color(&self) -> Option<[u8; 3]> {
        let color = self.branding.color.as_ref()?;
        let hex = &color[1..]; // skip '#'
        let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
        let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
        let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
        Some([r, g, b])
    }

    /// Load the PNG logo bytes (if configured and readable).
    pub fn logo_bytes(&self) -> Option<Bytes> {
        let path = self.branding.logo_path.as_ref()?;
        let data = std::fs::read(path).ok()?;
        if data.len() > 65535 {
            return None;
        }
        Some(Bytes::from(data))
    }
}

/// A pre-configured secret for channel provisioning.
///
/// Each secret grants exactly one channel with the given parameters.
/// Secrets are consumed atomically when a client invokes with them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSecret {
    pub secret: String,
    pub capacity_msat: u64,
    pub initial_balance_msat: u64,
    pub consumed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cliche_compatible_defaults() {
        let config = Config::default();
        assert!(config.require_secret);
        assert_eq!(config.policy.max_htlc_value_in_flight_msat, 100_000_000);
        assert_eq!(config.policy.htlc_minimum_msat, 1_000);
        assert_eq!(config.policy.fee_base_msat, 0);
        assert_eq!(config.policy.cltv_expiry_delta, 6);
    }

    #[test]
    fn valid_color() {
        let mut config = Config::default();
        config.branding.color = Some("#ff0000".to_string());
        assert!(config.validate().is_ok());
        assert_eq!(config.rgb_color(), Some([0xff, 0x00, 0x00]));
    }

    #[test]
    fn invalid_color() {
        let mut config = Config::default();
        config.branding.color = Some("red".to_string());
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_color_format() {
        let mut config = Config::default();
        config.branding.color = Some("#ff00".to_string());
        assert!(config.validate().is_err());
    }

    #[test]
    fn balance_exceeds_capacity() {
        let mut config = Config::default();
        config.policy.channel_capacity_msat = 1_000_000;
        config.policy.initial_client_balance_msat = 2_000_000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn valid_contact_url() {
        let mut config = Config::default();
        config.branding.contact_url = Some("https://example.com".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn invalid_contact_url() {
        let mut config = Config::default();
        config.branding.contact_url = Some("not a url".to_string());
        assert!(config.validate().is_err());
    }
}
