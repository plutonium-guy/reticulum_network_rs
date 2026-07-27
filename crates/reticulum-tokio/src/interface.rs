use std::io;

use async_trait::async_trait;

/// Object-safe async packet interface used by the runtime driver.
///
/// Implementations own transport framing. Callers always exchange complete,
/// unframed Reticulum packets.
#[async_trait]
pub trait AsyncInterface: Send {
    fn id(&self) -> u16;

    async fn recv_packet(&mut self) -> io::Result<Option<Vec<u8>>>;

    async fn send_packet(&mut self, raw: &[u8]) -> io::Result<()>;
}
