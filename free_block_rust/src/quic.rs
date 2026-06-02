use quinn::{ClientConfig, Endpoint, Connection};
use std::sync::Arc;

pub struct DoqClient {
    #[allow(dead_code)]
    // held to keep the QUIC endpoint alive until drop
    endpoint: Endpoint,
    connection: Connection,
}

impl DoqClient {
    pub fn is_alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    pub async fn connect(server: &str, sni: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        
        crypto.alpn_protocols = vec![b"doq".to_vec()];

        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
        ));

        let addr = tokio::net::lookup_host(format!("{}:853", server))
            .await?.next().ok_or("No address found")?;
            
        let bind_addr: std::net::SocketAddr = if addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_config);
        
        let connection = endpoint.connect(addr, sni)?.await?;
        Ok(Self { endpoint, connection })
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
        
        let mut resp_buf = vec![0u8; resp_len];
        recv.read_exact(&mut resp_buf).await?;
        
        Ok(resp_buf)
    }
}
