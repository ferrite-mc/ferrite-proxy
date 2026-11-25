# FerriteProxy

High-performance Rust Minecraft Java 26.3 (Protocol 777) Waterfall/Velocity-style reverse proxy.

## Features
- **Zero-copy async TCP relay** (`tokio::io::copy_bidirectional` + `mimalloc`)
- **Server List Ping (SLP)** handled at the edge with live online player count
- **Multi-backend routing**: `forced-hosts` virtual host routing + `priorities` fallback list
- **Forwarding**:
  - Velocity modern forwarding (`velocity:player_info`, HMAC-SHA256)
  - BungeeCord / Waterfall legacy forwarding (`<host>\0<ip>\0<uuid>`)
  - Direct (`none`)
- **DDoS & Bot-Flood Protection**: Per-IP connection rate limiter, max connection semaphore, handshake/login timeouts, bounded frame lengths
- **Observability**: Prometheus `/metrics` & `/healthz` HTTP endpoint (`127.0.0.1:9100`)

## Quick Start
```sh
cargo build --release
./target/release/ferrite-proxy
```
Edit `proxy.toml` to configure `bind-address`, `[servers]`, `forwarding = "velocity"`, and `forwarding-secret`.
