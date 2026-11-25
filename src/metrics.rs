//! Prometheus `/metrics` and `/healthz` HTTP server.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
pub struct ProxyMetrics {
    pub active_connections: AtomicUsize,
    pub online_players: AtomicUsize,
    pub total_connections: AtomicU64,
    pub slp_pings: AtomicU64,
    pub rate_limited: AtomicU64,
    pub backend_failures: AtomicU64,
    pub bytes_to_backend: AtomicU64,
    pub bytes_to_client: AtomicU64,
}

impl ProxyMetrics {
    pub fn render_prometheus(&self) -> String {
        format!(
            "# HELP ferrite_proxy_active_connections Current open TCP connections\n\
             # TYPE ferrite_proxy_active_connections gauge\n\
             ferrite_proxy_active_connections {}\n\
             # HELP ferrite_proxy_online_players Current players in Play state\n\
             # TYPE ferrite_proxy_online_players gauge\n\
             ferrite_proxy_online_players {}\n\
             # HELP ferrite_proxy_connections_total Total accepted TCP connections\n\
             # TYPE ferrite_proxy_connections_total counter\n\
             ferrite_proxy_connections_total {}\n\
             # HELP ferrite_proxy_slp_pings_total Total Server List Ping requests\n\
             # TYPE ferrite_proxy_slp_pings_total counter\n\
             ferrite_proxy_slp_pings_total {}\n\
             # HELP ferrite_proxy_rate_limited_total Connections rejected by IP rate limiter\n\
             # TYPE ferrite_proxy_rate_limited_total counter\n\
             ferrite_proxy_rate_limited_total {}\n\
             # HELP ferrite_proxy_backend_failures_total Failed backend connection attempts\n\
             # TYPE ferrite_proxy_backend_failures_total counter\n\
             ferrite_proxy_backend_failures_total {}\n\
             # HELP ferrite_proxy_bytes_to_backend_total Bytes relayed client -> backend\n\
             # TYPE ferrite_proxy_bytes_to_backend_total counter\n\
             ferrite_proxy_bytes_to_backend_total {}\n\
             # HELP ferrite_proxy_bytes_to_client_total Bytes relayed backend -> client\n\
             # TYPE ferrite_proxy_bytes_to_client_total counter\n\
             ferrite_proxy_bytes_to_client_total {}\n",
            self.active_connections.load(Ordering::Relaxed),
            self.online_players.load(Ordering::Relaxed),
            self.total_connections.load(Ordering::Relaxed),
            self.slp_pings.load(Ordering::Relaxed),
            self.rate_limited.load(Ordering::Relaxed),
            self.backend_failures.load(Ordering::Relaxed),
            self.bytes_to_backend.load(Ordering::Relaxed),
            self.bytes_to_client.load(Ordering::Relaxed),
        )
    }
}

pub async fn serve_metrics(bind: String, metrics: Arc<ProxyMetrics>) {
    let Ok(listener) = TcpListener::bind(&bind).await else {
        tracing::warn!(%bind, "failed to bind metrics HTTP endpoint");
        return;
    };
    tracing::info!(%bind, "Prometheus /metrics endpoint listening");
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let Ok(n) = sock.read(&mut buf).await else {
                return;
            };
            let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
            let (status, ctype, body) = if req.starts_with("GET /healthz") {
                ("200 OK", "text/plain", "ok\n".to_owned())
            } else {
                (
                    "200 OK",
                    "text/plain; version=0.0.4; charset=utf-8",
                    metrics.render_prometheus(),
                )
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}
