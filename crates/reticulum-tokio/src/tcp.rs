use async_trait::async_trait;
use reticulum_interface::{
    Framing, Interface,
    hdlc::{FLAG, deframe, frame},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const READ_CHUNK: usize = 4096;
const MAX_BUFFER: usize = 512 * 1024;

/// TCP client carrying raw RNS packets in the HDLC framing used by RNS 1.4.1.
pub struct TcpClientInterface {
    id: u16,
    stream: TcpStream,
    read_buffer: Vec<u8>,
}

impl TcpClientInterface {
    pub async fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(Self::from_stream(stream))
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        Self {
            id: 0,
            stream,
            read_buffer: Vec::new(),
        }
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    pub async fn send_packet(&mut self, raw: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(&frame(raw)).await
    }

    pub async fn recv_packet(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(packet) = self.take_packet() {
                return Ok(Some(packet));
            }

            let mut chunk = [0u8; READ_CHUNK];
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(None);
            }
            self.read_buffer.extend_from_slice(&chunk[..read]);
            if self.read_buffer.len() > MAX_BUFFER {
                self.read_buffer.clear();
            }
        }
    }

    fn take_packet(&mut self) -> Option<Vec<u8>> {
        loop {
            let start = self.read_buffer.iter().position(|byte| *byte == FLAG)?;
            if start > 0 {
                self.read_buffer.drain(..start);
            }

            let end = self.read_buffer[1..]
                .iter()
                .position(|byte| *byte == FLAG)
                .map(|offset| offset + 1)?;
            let framed = self.read_buffer[..=end].to_vec();
            // Retain the closing flag. RNS accepts it as the opening flag for
            // a following frame, while also tolerating the usual doubled flag.
            self.read_buffer.drain(..end);
            if framed.len() == 2 {
                continue;
            }
            if let Some(packet) = deframe(&framed) {
                return Some(packet);
            }
        }
    }
}

impl Interface for TcpClientInterface {
    const FRAMING: Framing = Framing::Hdlc;
    const HW_MTU: usize = 262_144;
}

#[async_trait]
impl crate::interface::AsyncInterface for TcpClientInterface {
    fn id(&self) -> u16 {
        self.id
    }

    async fn recv_packet(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Self::recv_packet(self).await
    }

    async fn send_packet(&mut self, raw: &[u8]) -> std::io::Result<()> {
        Self::send_packet(self, raw).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn framed_roundtrip_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut interface = TcpClientInterface::from_stream(stream);
            let packet = interface.recv_packet().await.unwrap().unwrap();
            interface.send_packet(&packet).await.unwrap();
        });

        let mut client = TcpClientInterface::connect(&addr).await.unwrap();
        let payload = vec![0x7E, 0x11, 0x7D, 0x22, 0x7E, 0x00];
        client.send_packet(&payload).await.unwrap();
        let echoed = client.recv_packet().await.unwrap().unwrap();
        assert_eq!(echoed, payload);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn receives_two_back_to_back_packets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut interface = TcpClientInterface::from_stream(stream);
            interface.send_packet(b"first").await.unwrap();
            interface.send_packet(b"second").await.unwrap();
        });

        let mut client = TcpClientInterface::connect(&addr).await.unwrap();
        assert_eq!(client.recv_packet().await.unwrap().unwrap(), b"first");
        assert_eq!(client.recv_packet().await.unwrap().unwrap(), b"second");
        server.await.unwrap();
    }
}
