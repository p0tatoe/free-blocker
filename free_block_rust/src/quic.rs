use quinn::{ClientConfig, Endpoint, Connection};
use std::sync::Arc;

use std::os::fd::AsRawFd;

/// Long-lived QUIC endpoint that owns the UDP socket.
/// Created once per proxy lifetime; reused across DoQ reconnections
/// to prevent file-descriptor leaks.
pub struct DoqEndpoint {
    endpoint: Endpoint,
    socket_fd: i32,
}

impl DoqEndpoint {
    pub fn new_v4() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::new_with_bind("0.0.0.0:0")
    }

    pub fn new_v6() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::new_with_bind("[::]:0")
    }

    fn new_with_bind(bind_addr: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"doq".to_vec()];

        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));

        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        let socket_fd = socket.as_raw_fd();
        
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint, socket_fd })
    }

    pub fn get_socket_fd(&self) -> i32 {
        self.socket_fd
    }

    /// Creates a new QUIC connection on the existing endpoint.
    /// Only the connection is replaced on reconnect — the socket stays open.
    pub async fn connect(&self, server: &str, sni: &str) -> Result<DoqClient, Box<dyn std::error::Error + Send + Sync>> {
        // Because server is now passed as an IP address string (e.g. "94.140.14.14"),
        // lookup_host will immediately parse it without doing a DNS resolution.
        let addr = tokio::net::lookup_host(format!("{}:853", server))
            .await?.next().ok_or("No address found")?;
        let connection = self.endpoint.connect(addr, sni)?.await?;
        Ok(DoqClient { connection })
    }
}

/// A single DoQ (DNS over QUIC) session.
/// Lightweight — only holds the connection, not the socket.
pub struct DoqClient {
    connection: Connection,
}

impl Drop for DoqClient {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"App Teardown");
    }
}

impl Drop for DoqEndpoint {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"Endpoint Teardown");
    }
}

impl DoqClient {
    pub fn is_alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    pub async fn send_query(&self, payload: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let (mut send, mut recv) = self.connection.open_bi().await?;

        let len = (payload.len() as u16).to_be_bytes();
        send.write_all(&len).await?;
        send.write_all(payload).await?;
        send.finish()?;

        let mut len_buf = [0u8; 2];
        recv.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let safe_len = std::cmp::min(resp_len, 8192);

        let mut resp_buf = vec![0u8; safe_len];
        recv.read_exact(&mut resp_buf).await?;

        Ok(resp_buf)
    }
}
