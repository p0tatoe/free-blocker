#[path = "../quic.rs"]
pub mod quic;

use quic::DoqEndpoint;

#[tokio::main]
async fn main() {
    println!("Connecting to DoQ...");
    let endpoint = DoqEndpoint::new_v4().unwrap();
    let doq = endpoint.connect("1.1.1.1", "cloudflare-dns.com").await.unwrap();
    println!("Connected! Sending query...");

    // Query for example.com A record
    let query: [u8; 29] = [
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags
        0x00, 0x01, // Questions
        0x00, 0x00, // Answer RRs
        0x00, 0x00, // Authority RRs
        0x00, 0x00, // Additional RRs
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
    ];

    let len = (query.len() as u16).to_be_bytes();
    let mut payload = Vec::new();
    payload.extend_from_slice(&len);
    payload.extend_from_slice(&query);

    let resp = doq.send_query(&payload).await.unwrap();
    println!("Received response: {} bytes", resp.len());
    println!("{:?}", resp);
}
