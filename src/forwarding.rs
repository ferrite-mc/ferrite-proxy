//! Velocity modern forwarding (HMAC-SHA256) and BungeeCord/Waterfall legacy forwarding.

use std::net::IpAddr;

use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::proto::{encode_string, encode_varint};

pub const VELOCITY_CHANNEL: &str = "velocity:player_info";
pub const VELOCITY_VERSION_MODERN: i32 = 1;

/// Builds a signed Velocity `velocity:player_info` payload (HMAC-SHA256 over version + IP + UUID + name + properties=0).
pub fn build_velocity_payload(
    secret: &[u8],
    client_ip: IpAddr,
    uuid: Uuid,
    name: &str,
) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(64 + name.len());
    encode_varint(VELOCITY_VERSION_MODERN, &mut data);
    encode_string(&client_ip.to_string(), &mut data);
    data.extend_from_slice(uuid.as_bytes());
    encode_string(name, &mut data);
    encode_varint(0, &mut data); // 0 properties

    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(&data);
    let tag = mac.finalize().into_bytes();

    let mut payload = Vec::with_capacity(32 + data.len());
    payload.extend_from_slice(&tag);
    payload.extend_from_slice(&data);
    Ok(payload)
}

/// Builds a BungeeCord/Waterfall legacy handshake host string: `<host>\0<ip>\0<undashed_uuid>`.
pub fn build_bungee_host(original_host: &str, client_ip: IpAddr, uuid: Uuid) -> String {
    let clean_host = original_host.split('\0').next().unwrap_or(original_host);
    format!("{clean_host}\0{client_ip}\0{}", uuid.simple())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn velocity_payload_has_valid_32_byte_hmac() {
        let secret = b"super-secret";
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let uid = Uuid::from_u128(42);
        let payload = build_velocity_payload(secret, ip, uid, "Tester").unwrap();
        assert!(payload.len() > 32);
        let (sig, data) = payload.split_at(32);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(data);
        mac.verify_slice(sig).unwrap();
    }

    #[test]
    fn bungee_host_formats_undashed_uuid() {
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let uid = Uuid::from_u128(0x01020304);
        let h = build_bungee_host("mc.example.com", ip, uid);
        assert!(h.starts_with("mc.example.com\x0010.0.0.5\0"));
        assert!(!h.contains('-'));
    }
}
