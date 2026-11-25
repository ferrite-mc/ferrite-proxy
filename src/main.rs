//! FerriteProxy — High-performance Rust Waterfall/Velocity-style Minecraft 26.3 proxy.

mod config;
mod forwarding;
mod metrics;
mod proto;
mod security;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use config::{ForwardingMode, ProxyConfig};
use metrics::ProxyMetrics;
use proto::{
    Handshake, LoginStart, decode_varint, encode_login_disconnect, encode_status_response,
    encode_varint, read_raw_frame, write_raw_frame,
};
use security::IpRateLimiter;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let (cfg, created) = ProxyConfig::load_or_create(Path::new("proxy.toml"))?;
    if created {
        tracing::info!("created default proxy.toml");
    }
    let cfg = Arc::new(cfg);
    let metrics = Arc::new(ProxyMetrics::default());
    let limiter = Arc::new(IpRateLimiter::new(cfg.connections_per_ip_per_sec));
    let conn_permits = Arc::new(Semaphore::new(cfg.max_connections.max(1)));

    if let Some(metrics_bind) = cfg.metrics_bind.clone() {
        tokio::spawn(metrics::serve_metrics(metrics_bind, Arc::clone(&metrics)));
    }

    let listener = TcpListener::bind(&cfg.bind_address)
        .await
        .with_context(|| format!("binding {}", cfg.bind_address))?;
    tracing::info!(
        address = %cfg.bind_address,
        forwarding = ?cfg.forwarding,
        backends = cfg.servers.len(),
        "FerriteProxy listening (Minecraft 26.3 / Protocol 777)"
    );

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down FerriteProxy");
                break;
            }
            accepted = listener.accept() => {
                let (client, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(%err, "accept error");
                        continue;
                    }
                };
                if !limiter.allow(peer.ip()) {
                    metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let Ok(permit) = Arc::clone(&conn_permits).try_acquire_owned() else {
                    continue;
                };
                let _ = client.set_nodelay(true);
                let cfg = Arc::clone(&cfg);
                let metrics = Arc::clone(&metrics);
                tokio::spawn(async move {
                    let _permit = permit;
                    metrics.total_connections.fetch_add(1, Ordering::Relaxed);
                    metrics.active_connections.fetch_add(1, Ordering::Relaxed);
                    if let Err(err) = handle_client(client, peer, &cfg, &metrics).await {
                        tracing::debug!(%peer, %err, "proxy session ended");
                    }
                    metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
                });
            }
        }
    }
    Ok(())
}

async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    cfg: &ProxyConfig,
    metrics: &ProxyMetrics,
) -> Result<()> {
    let timeout = Duration::from_secs(cfg.read_timeout_secs.max(1));
    let hs_frame = tokio::time::timeout(timeout, read_raw_frame(&mut client))
        .await
        .context("handshake timeout")??;
    let hs = Handshake::decode(&hs_frame)?;

    match hs.next_state {
        1 => handle_status(&mut client, cfg, metrics, timeout).await,
        2 | 3 => handle_login_and_relay(client, peer, hs, cfg, metrics, timeout).await,
        other => bail!("unsupported handshake next_state {other}"),
    }
}

async fn handle_status(
    client: &mut TcpStream,
    cfg: &ProxyConfig,
    metrics: &ProxyMetrics,
    timeout: Duration,
) -> Result<()> {
    metrics.slp_pings.fetch_add(1, Ordering::Relaxed);
    let _req = tokio::time::timeout(timeout, read_raw_frame(client))
        .await
        .context("status request timeout")??;
    let online = metrics.online_players.load(Ordering::Relaxed);
    let resp = encode_status_response(&cfg.motd, cfg.max_players, online);
    write_raw_frame(client, &resp).await?;

    // Optional SLP ping packet (0x01 + 8-byte timestamp) -> echo back
    if let Ok(Ok(ping)) = tokio::time::timeout(timeout, read_raw_frame(client)).await {
        let _ = write_raw_frame(client, &ping).await;
    }
    Ok(())
}

async fn handle_login_and_relay(
    mut client: TcpStream,
    peer: SocketAddr,
    hs: Handshake,
    cfg: &ProxyConfig,
    metrics: &ProxyMetrics,
    timeout: Duration,
) -> Result<()> {
    let login_frame = tokio::time::timeout(timeout, read_raw_frame(&mut client))
        .await
        .context("login start timeout")??;
    let login = LoginStart::decode(&login_frame)?;

    let candidates = cfg.route_candidates(&hs.server_address);
    if candidates.is_empty() {
        let _ = write_raw_frame(
            &mut client,
            &encode_login_disconnect("No backend servers configured"),
        )
        .await;
        bail!("no backend servers configured");
    }

    let mut connected: Option<(String, TcpStream)> = None;
    for (name, addr) in candidates {
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                connected = Some((name, stream));
                break;
            }
            Ok(Err(err)) => {
                metrics.backend_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(backend = %name, %addr, %err, "backend connect failed");
            }
            Err(_) => {
                metrics.backend_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(backend = %name, %addr, "backend connect timed out");
            }
        }
    }

    let Some((backend_name, mut backend)) = connected else {
        let _ = write_raw_frame(
            &mut client,
            &encode_login_disconnect("All backend servers are currently offline."),
        )
        .await;
        bail!("all backend servers offline");
    };

    // Forward handshake (with BungeeCord legacy host injection if configured)
    let mut forwarded_hs = hs.clone();
    if cfg.forwarding == ForwardingMode::Bungee {
        forwarded_hs.server_address =
            forwarding::build_bungee_host(&hs.server_address, peer.ip(), login.uuid);
    }
    write_raw_frame(&mut backend, &forwarded_hs.encode()).await?;
    write_raw_frame(&mut backend, &login.encode()).await?;

    // Handle Velocity CustomQuery (0x04) in Login state if configured, otherwise relay login frames
    if cfg.forwarding == ForwardingMode::Velocity {
        let mut comp_thresh: Option<usize> = None;
        loop {
            let frame = tokio::time::timeout(timeout, read_raw_frame(&mut backend))
                .await
                .context("backend login response timeout")??;
            let decoded = decompress_if_needed(&frame, comp_thresh)?;
            let mut slice = decoded.as_slice();
            let pid = decode_varint(&mut slice)?;
            if pid == 0x03 {
                // SetCompression: forward to client and remember threshold
                comp_thresh = Some(decode_varint(&mut slice)?.max(0) as usize);
                write_raw_frame(&mut client, &frame).await?;
            } else if pid == 0x04 {
                // LoginPluginRequest (CustomQuery): answer Velocity forwarding directly!
                let msg_id = decode_varint(&mut slice)?;
                let channel = proto::decode_string(&mut slice, 32767)?;
                if channel == forwarding::VELOCITY_CHANNEL {
                    let payload = forwarding::build_velocity_payload(
                        cfg.forwarding_secret.as_bytes(),
                        peer.ip(),
                        login.uuid,
                        &login.name,
                    )?;
                    let mut resp = Vec::with_capacity(16 + payload.len());
                    encode_varint(0x02, &mut resp); // CustomQueryAnswer
                    encode_varint(msg_id, &mut resp);
                    resp.push(1); // present = true
                    resp.extend_from_slice(&payload);
                    write_compressed_or_raw(&mut backend, &resp, comp_thresh).await?;
                } else {
                    let mut resp = Vec::with_capacity(8);
                    encode_varint(0x02, &mut resp);
                    encode_varint(msg_id, &mut resp);
                    resp.push(0);
                    write_compressed_or_raw(&mut backend, &resp, comp_thresh).await?;
                }
            } else {
                // Forward LoginFinished (0x02), LoginDisconnect (0x00), etc. to client and enter relay
                write_raw_frame(&mut client, &frame).await?;
                break;
            }
        }
    }

    tracing::info!(
        player = %login.name,
        %peer,
        backend = %backend_name,
        "player connected through FerriteProxy"
    );
    metrics.online_players.fetch_add(1, Ordering::Relaxed);
    let res = tokio::io::copy_bidirectional(&mut client, &mut backend).await;
    metrics.online_players.fetch_sub(1, Ordering::Relaxed);
    if let Ok((c2b, b2c)) = res {
        metrics.bytes_to_backend.fetch_add(c2b, Ordering::Relaxed);
        metrics.bytes_to_client.fetch_add(b2c, Ordering::Relaxed);
    }
    Ok(())
}

fn decompress_if_needed(frame: &[u8], comp_thresh: Option<usize>) -> Result<Vec<u8>> {
    if comp_thresh.is_none() {
        return Ok(frame.to_vec());
    }
    let mut slice = frame;
    let ulen = decode_varint(&mut slice)?;
    if ulen == 0 {
        return Ok(slice.to_vec());
    }
    let ulen = usize::try_from(ulen).context("negative uncompressed len")?;
    anyhow::ensure!(ulen <= proto::MAX_FRAME_LEN, "uncompressed frame too large");
    use std::io::Read;
    let mut dec = flate2::read::ZlibDecoder::new(slice);
    let mut out = Vec::with_capacity(ulen);
    dec.read_to_end(&mut out)?;
    Ok(out)
}

async fn write_compressed_or_raw(
    stream: &mut TcpStream,
    raw: &[u8],
    comp_thresh: Option<usize>,
) -> Result<()> {
    let Some(_thresh) = comp_thresh else {
        return write_raw_frame(stream, raw).await;
    };
    let mut inner = Vec::with_capacity(1 + raw.len());
    encode_varint(0, &mut inner); // uncompressed inside compressed frame (< threshold)
    inner.extend_from_slice(raw);
    write_raw_frame(stream, &inner).await
}
