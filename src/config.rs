//! Proxy configuration (`proxy.toml`).

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardingMode {
    #[default]
    Velocity,
    Bungee,
    None,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct ProxyConfig {
    pub bind_address: String,
    pub motd: String,
    pub max_players: usize,
    pub max_connections: usize,
    pub connections_per_ip_per_sec: u32,
    pub read_timeout_secs: u64,
    pub forwarding: ForwardingMode,
    pub forwarding_secret: String,
    pub log_language: String,
    pub metrics_bind: Option<String>,
    pub servers: HashMap<String, String>,
    pub priorities: Vec<String>,
    pub forced_hosts: HashMap<String, String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        let mut servers = HashMap::new();
        servers.insert("lobby".into(), "127.0.0.1:25565".into());
        Self {
            bind_address: "0.0.0.0:25577".into(),
            motd: "FerriteProxy — High-Speed Rust Minecraft Proxy".into(),
            max_players: 1000,
            max_connections: 4096,
            connections_per_ip_per_sec: 12,
            read_timeout_secs: 10,
            forwarding: ForwardingMode::Velocity,
            forwarding_secret: "change-me-velocity-secret".into(),
            log_language: "auto".into(),
            metrics_bind: Some("127.0.0.1:9100".into()),
            servers,
            priorities: vec!["lobby".into()],
            forced_hosts: HashMap::new(),
        }
    }
}

pub const DEFAULT_CONFIG: &str = r#"# FerriteProxy configuration

bind-address = "0.0.0.0:25577"
motd = "FerriteProxy — High-Speed Rust Minecraft Proxy"
max-players = 1000
max-connections = 4096
connections-per-ip-per-sec = 12
read-timeout-secs = 10

# Forwarding mode: "velocity" (HMAC-SHA256), "bungee" (legacy), or "none"
forwarding = "velocity"
forwarding-secret = "change-me-velocity-secret"

# Log language: "auto", "en", "ko", "ja", "zh"
log-language = "auto"

# Optional Prometheus /metrics and /healthz HTTP endpoint (comment out to disable)
metrics-bind = "127.0.0.1:9100"

# Backend fallback order
priorities = ["lobby"]

[servers]
lobby = "127.0.0.1:25565"

[forced-hosts]
# "survival.mc.example.com" = "survival"
"#;

impl ProxyConfig {
    pub fn load_or_create(path: &Path) -> Result<(Self, bool)> {
        if !path.exists() {
            std::fs::write(path, DEFAULT_CONFIG)
                .with_context(|| format!("writing default {}", path.display()))?;
            let cfg: Self = toml::from_str(DEFAULT_CONFIG)?;
            return Ok((cfg, true));
        }
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Self =
            toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        Ok((cfg, false))
    }

    /// Resolves candidate backend names in priority order for the given virtual host.
    pub fn route_candidates(&self, raw_host: &str) -> Vec<(String, String)> {
        let host = raw_host
            .split('\0')
            .next()
            .unwrap_or(raw_host)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let mut order = Vec::new();
        if let Some(forced) = self.forced_hosts.get(&host) {
            order.push(forced.clone());
        }
        for name in &self.priorities {
            if !order.contains(name) {
                order.push(name.clone());
            }
        }
        for name in self.servers.keys() {
            if !order.contains(name) {
                order.push(name.clone());
            }
        }
        order
            .into_iter()
            .filter_map(|name| self.servers.get(&name).map(|addr| (name, addr.clone())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_host_takes_priority_before_fallback_list() {
        let mut cfg = ProxyConfig::default();
        cfg.servers
            .insert("survival".into(), "127.0.0.1:25566".into());
        cfg.forced_hosts
            .insert("surv.example.com".into(), "survival".into());
        let routes = cfg.route_candidates("surv.example.com.");
        assert_eq!(routes[0].0, "survival");
        assert_eq!(routes[1].0, "lobby");
    }
}
