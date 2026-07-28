//! WebSocket ↔ TCP bridge for browser Reticulum nodes.
//!
//! Browsers cannot open raw TCP, so the WASM node speaks HDLC frames over a
//! WebSocket. This binary relays those frames verbatim between each WebSocket
//! client and a Reticulum `TCPServerInterface`. It is a dumb byte relay — no
//! framing, no crypto — the exact behaviour of the reference `bridge.py`,
//! packaged as one deployable edge binary next to an RNS node.
//!
//! Usage:
//!   reticulum-bridge [--listen HOST:PORT] [--target HOST:PORT]
//! Defaults: --listen 127.0.0.1:8765  --target 127.0.0.1:42428
//! Env fallback: RETICULUM_BRIDGE_LISTEN, RETICULUM_BRIDGE_TARGET

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

struct Config {
    listen: String,
    target: String,
}

fn parse_config() -> Config {
    let mut listen =
        std::env::var("RETICULUM_BRIDGE_LISTEN").unwrap_or_else(|_| "127.0.0.1:8765".to_string());
    let mut target =
        std::env::var("RETICULUM_BRIDGE_TARGET").unwrap_or_else(|_| "127.0.0.1:42428".to_string());
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                if let Some(value) = args.next() {
                    listen = value;
                }
            }
            "--target" => {
                if let Some(value) = args.next() {
                    target = value;
                }
            }
            "-h" | "--help" => {
                println!(
                    "reticulum-bridge [--listen HOST:PORT] [--target HOST:PORT]\n\
                     defaults: --listen 127.0.0.1:8765 --target 127.0.0.1:42428"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    Config { listen, target }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(parse_config());
    let listener = TcpListener::bind(&config.listen).await?;
    println!(
        "WS_BRIDGE_READY ws://{} -> {}",
        listener.local_addr()?,
        config.target
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                eprintln!("accept error: {error}");
                continue;
            }
        };
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, &config.target).await {
                eprintln!("connection {peer} closed: {error}");
            }
        });
    }
}

async fn serve_connection(
    stream: TcpStream,
    target: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    stream.set_nodelay(true).ok();
    let websocket = tokio_tungstenite::accept_async(stream).await?;
    let tcp = TcpStream::connect(target).await?;
    tcp.set_nodelay(true).ok();

    let (mut ws_sink, mut ws_stream) = websocket.split();
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    // WebSocket -> TCP: relay binary frames verbatim; reject text.
    let ws_to_tcp = async {
        while let Some(message) = ws_stream.next().await {
            match message? {
                Message::Binary(data) => tcp_write.write_all(&data).await?,
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Text(_) => {
                    return Err::<(), Box<dyn std::error::Error + Send + Sync>>(
                        "binary frames required".into(),
                    );
                }
                Message::Frame(_) => {}
            }
        }
        Ok(())
    };

    // TCP -> WebSocket: forward each read chunk as a binary frame.
    let tcp_to_ws = async {
        let mut buffer = [0u8; 65536];
        loop {
            let read = tcp_read.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            ws_sink
                .send(Message::Binary(buffer[..read].to_vec()))
                .await?;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    // Finish when either direction ends; dropping the futures tears down both.
    tokio::select! {
        result = ws_to_tcp => result,
        result = tcp_to_ws => result,
    }
}
