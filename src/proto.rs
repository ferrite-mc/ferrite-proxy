//! Minimal, bounds-checked Minecraft Java 26.3 (Protocol 777) wire framing and handshake/login codecs.

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

/// Protocol version for Minecraft Java 26.3.
pub const PROTOCOL_VERSION: i32 = 777;
/// Maximum allowed wire frame length (2 MiB) to prevent memory exhaustion.
pub const MAX_FRAME_LEN: usize = 2 * 1024 * 1024;

pub fn encode_varint(mut value: i32, out: &mut Vec<u8>) {
    let mut v = value as u32;
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    let _ = &mut value;
}

pub fn decode_varint(buf: &mut &[u8]) -> Result<i32> {
    let mut val = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        ensure!(!buf.is_empty(), "unexpected EOF in VarInt");
        let b = buf[0];
        *buf = &buf[1..];
        val |= u32::from(b & 0x7f) << shift;
        if (b & 0x80) == 0 {
            return Ok(val as i32);
        }
        shift += 7;
    }
    bail!("VarInt too long")
}

pub fn encode_string(s: &str, out: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    encode_varint(bytes.len() as i32, out);
    out.extend_from_slice(bytes);
}

pub fn decode_string(buf: &mut &[u8], max_bytes: usize) -> Result<String> {
    let len = decode_varint(buf)?;
    let len = usize::try_from(len).context("negative string length")?;
    ensure!(
        len <= max_bytes,
        "string exceeds max length ({len} > {max_bytes})"
    );
    ensure!(buf.len() >= len, "unexpected EOF in string");
    let s = std::str::from_utf8(&buf[..len]).context("invalid UTF-8")?;
    *buf = &buf[len..];
    Ok(s.to_owned())
}

pub async fn read_raw_frame<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Vec<u8>> {
    let mut len = 0u32;
    let mut shift = 0u32;
    for i in 0..5 {
        let mut b = [0u8; 1];
        stream
            .read_exact(&mut b)
            .await
            .context("reading frame length")?;
        len |= u32::from(b[0] & 0x7f) << shift;
        if (b[0] & 0x80) == 0 {
            break;
        }
        if i == 4 {
            bail!("frame length VarInt too long");
        }
        shift += 7;
    }
    let len = len as usize;
    ensure!(len <= MAX_FRAME_LEN, "frame too large: {len}");
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .context("reading frame body")?;
    Ok(buf)
}

pub async fn write_raw_frame<W: AsyncWrite + Unpin>(stream: &mut W, payload: &[u8]) -> Result<()> {
    let mut out = Vec::with_capacity(5 + payload.len());
    encode_varint(payload.len() as i32, &mut out);
    out.extend_from_slice(payload);
    stream.write_all(&out).await?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: i32,
}

impl Handshake {
    pub fn decode(mut body: &[u8]) -> Result<Self> {
        let pid = decode_varint(&mut body)?;
        ensure!(pid == 0x00, "expected handshake packet 0x00, got {pid:#x}");
        let protocol_version = decode_varint(&mut body)?;
        let server_address = decode_string(&mut body, 255 * 4)?;
        ensure!(body.len() >= 2, "truncated handshake port");
        let server_port = u16::from_be_bytes([body[0], body[1]]);
        body = &body[2..];
        let next_state = decode_varint(&mut body)?;
        Ok(Self {
            protocol_version,
            server_address,
            server_port,
            next_state,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.server_address.len());
        encode_varint(0x00, &mut out);
        encode_varint(self.protocol_version, &mut out);
        encode_string(&self.server_address, &mut out);
        out.extend_from_slice(&self.server_port.to_be_bytes());
        encode_varint(self.next_state, &mut out);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginStart {
    pub name: String,
    pub uuid: Uuid,
}

impl LoginStart {
    pub fn decode(mut body: &[u8]) -> Result<Self> {
        let pid = decode_varint(&mut body)?;
        ensure!(pid == 0x00, "expected login start 0x00, got {pid:#x}");
        let name = decode_string(&mut body, 16 * 4)?;
        ensure!(body.len() >= 16, "truncated login start UUID");
        let uuid = Uuid::from_slice(&body[..16])?;
        Ok(Self { name, uuid })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24 + self.name.len());
        encode_varint(0x00, &mut out);
        encode_string(&self.name, &mut out);
        out.extend_from_slice(self.uuid.as_bytes());
        out
    }
}

pub fn encode_login_disconnect(reason_text: &str) -> Vec<u8> {
    let json = serde_json::json!({ "text": reason_text }).to_string();
    let mut out = Vec::with_capacity(8 + json.len());
    encode_varint(0x00, &mut out);
    encode_string(&json, &mut out);
    out
}

pub fn encode_status_response(motd: &str, max_players: usize, online_players: usize) -> Vec<u8> {
    let json = serde_json::json!({
        "version": {
            "name": "26.3",
            "protocol": PROTOCOL_VERSION
        },
        "players": {
            "max": max_players,
            "online": online_players,
            "sample": []
        },
        "description": {
            "text": motd
        }
    })
    .to_string();
    let mut out = Vec::with_capacity(8 + json.len());
    encode_varint(0x00, &mut out);
    encode_string(&json, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_round_trips() {
        let hs = Handshake {
            protocol_version: PROTOCOL_VERSION,
            server_address: "mc.yxshadxw.dev".into(),
            server_port: 25565,
            next_state: 2,
        };
        let bytes = hs.encode();
        let decoded = Handshake::decode(&bytes).unwrap();
        assert_eq!(hs, decoded);
    }

    #[test]
    fn login_start_round_trips() {
        let ls = LoginStart {
            name: "PlayerOne".into(),
            uuid: Uuid::from_u128(0x1234_5678_9abc_def0),
        };
        let bytes = ls.encode();
        let decoded = LoginStart::decode(&bytes).unwrap();
        assert_eq!(ls, decoded);
    }
}
