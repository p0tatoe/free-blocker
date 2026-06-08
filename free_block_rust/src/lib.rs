uniffi::setup_scaffolding!();

mod proxy;
mod quic;

use proxy::{extract_dns_name, to_lowercase_wire_format, to_trie_key, create_null_response, create_forwarded_response, create_tcp_rst, create_servfail_response};
use quic::{DoqEndpoint, DoqClient};
use radix_trie::Trie;
use std::sync::{Arc, RwLock, OnceLock};
use tokio::runtime::Runtime;
use tokio::sync::Mutex as TokioMutex;
use std::num::NonZeroUsize;
use tokio::sync::mpsc;
use std::time::{Instant, Duration};
use tokio_util::sync::CancellationToken;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime")
    })
}

struct CacheEntry {
    payload: Vec<u8>,
    expires_at: Instant,
}

fn get_min_ttl(payload: &[u8]) -> Option<u32> {
    if payload.len() < 12 { return None; }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let mut idx = 12;
    for _ in 0..qdcount {
        while idx < payload.len() {
            let len = payload[idx] as usize;
            if len == 0 { idx += 1; break; }
            if len & 0xC0 == 0xC0 { idx += 2; break; }
            idx += len + 1;
        }
        idx += 4;
    }
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        if idx >= payload.len() { break; }
        if payload[idx] & 0xC0 == 0xC0 {
            idx += 2;
        } else {
            while idx < payload.len() {
                let len = payload[idx] as usize;
                if len == 0 { idx += 1; break; }
                if len & 0xC0 == 0xC0 { idx += 2; break; }
                idx += len + 1;
            }
        }
        if idx + 10 > payload.len() { break; }
        let ttl = u32::from_be_bytes([payload[idx+4], payload[idx+5], payload[idx+6], payload[idx+7]]);
        if ttl < min_ttl { min_ttl = ttl; }
        let rdlength = u16::from_be_bytes([payload[idx+8], payload[idx+9]]) as usize;
        idx += 10 + rdlength;
    }
    if min_ttl == u32::MAX { None } else { Some(min_ttl) }
}

#[derive(uniffi::Object)]
pub struct DnsProxy {
    tun_fd: i32,
    quic_fd_v4: Option<i32>,
    quic_fd_v6: Option<i32>,
    upstream_v4: Option<String>,
    upstream_v6: Option<String>,
    sni_hostname: String,
    blocklist: Arc<RwLock<Trie<Vec<u8>, ()>>>,
    cancel_token: CancellationToken,
    doq_endpoint_v4: Option<Arc<DoqEndpoint>>,
    doq_endpoint_v6: Option<Arc<DoqEndpoint>>,
}

#[uniffi::export]
impl DnsProxy {
    #[uniffi::constructor]
    pub fn new(tun_fd: i32, upstream_v4: Option<String>, upstream_v6: Option<String>, sni_hostname: String) -> Arc<Self> {
        let _guard = get_runtime().enter();
        let doq_endpoint_v4 = upstream_v4.as_ref().map(|_| Arc::new(DoqEndpoint::new_v4().expect("Failed to create DoQ IPv4 endpoint")));
        let quic_fd_v4 = doq_endpoint_v4.as_ref().map(|e| e.get_socket_fd());
        
        let doq_endpoint_v6 = upstream_v6.as_ref().map(|_| Arc::new(DoqEndpoint::new_v6().expect("Failed to create DoQ IPv6 endpoint")));
        let quic_fd_v6 = doq_endpoint_v6.as_ref().map(|e| e.get_socket_fd());

        Arc::new(Self {
            tun_fd,
            quic_fd_v4,
            quic_fd_v6,
            upstream_v4,
            upstream_v6,
            sni_hostname,
            blocklist: Arc::new(RwLock::new(Trie::new())),
            cancel_token: CancellationToken::new(),
            doq_endpoint_v4,
            doq_endpoint_v6,
        })
    }

    pub fn get_quic_fd_v4(&self) -> Option<i32> {
        self.quic_fd_v4
    }

    pub fn get_quic_fd_v6(&self) -> Option<i32> {
        self.quic_fd_v6
    }

    pub fn stop(&self) {
        self.cancel_token.cancel();
    }

    pub fn start(&self) {
        let tun_fd = self.tun_fd;
        let upstream_v4 = self.upstream_v4.clone();
        let upstream_v6 = self.upstream_v6.clone();
        let sni_hostname = self.sni_hostname.clone();
        let blocklist = self.blocklist.clone();
        let cancel_token = self.cancel_token.child_token();
        let doq_endpoint_v4 = self.doq_endpoint_v4.clone();
        let doq_endpoint_v6 = self.doq_endpoint_v6.clone();

        get_runtime().spawn(async move {
            run_proxy(tun_fd, upstream_v4, upstream_v6, sni_hostname, blocklist, cancel_token, doq_endpoint_v4, doq_endpoint_v6).await;
        });
    }
    
    pub fn update_blocklist(&self, domains: Vec<String>) {
        let mut trie = Trie::new();
        for domain in domains {
            let wire_format = domain_to_wire_format(&domain);
            trie.insert(wire_format, ());
        }
        let mut lock = self.blocklist.write().unwrap_or_else(|e| e.into_inner());
        *lock = trie;
    }
}

/// Convert a domain string to a reversed, lowercased wire-format key for the trie.
/// "example.com" → \x03com\x07example  (no trailing \x00)
///
/// Reversed so that `get_ancestor_value` can match subdomains:
/// blocking "example.com" (key: \x03com\x07example) will match
/// a query for "ads.example.com" (key: \x03com\x07example\x03ads)
/// because the parent key is a byte-prefix of the child key.
fn domain_to_wire_format(domain: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let parts: Vec<&str> = domain.split('.').filter(|p| !p.is_empty()).collect();
    for part in parts.iter().rev() {
        out.push(part.len() as u8);
        out.extend_from_slice(part.to_ascii_lowercase().as_bytes());
    }
    out
}

use std::fs::OpenOptions;
use std::io::Write;

fn log_trace(_msg: &str) {
    // Logging disabled to prevent synchronous I/O blocking
    // if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("/data/data/dev.michaelylee.freeblocker/cache/rust.log") {
    //     let _ = writeln!(f, "{}", msg);
    // }
}

async fn run_proxy(
    tun_fd: i32,
    upstream_v4: Option<String>,
    upstream_v6: Option<String>,
    sni_hostname: String,
    blocklist: Arc<RwLock<Trie<Vec<u8>, ()>>>,
    cancel_token: CancellationToken,
    doq_endpoint_v4: Option<Arc<DoqEndpoint>>,
    doq_endpoint_v6: Option<Arc<DoqEndpoint>>,
) {
    log_trace("run_proxy started");
    let mut buf = vec![0u8; 65536];
    let mut async_fd_opt = None;
    for _ in 0..50 {
        match tokio::io::unix::AsyncFd::new(tun_fd) {
            Ok(fd) => {
                async_fd_opt = Some(fd);
                break;
            }
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(e) => {
                log_trace(&format!("AsyncFd::new failed: {}", e));
                return;
            }
        }
    }
    
    let async_fd = match async_fd_opt {
        Some(fd) => fd,
        None => {
            log_trace("AsyncFd::new failed with EEXIST after 500ms");
            return;
        }
    };
    
    let semaphore = Arc::new(tokio::sync::Semaphore::new(100));
    unsafe {
        let flags = libc::fcntl(tun_fd, libc::F_GETFL);
        libc::fcntl(tun_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let doq_conn: Arc<TokioMutex<(Option<Arc<DoqClient>>, std::time::Instant)>> = Arc::new(TokioMutex::new((None, std::time::Instant::now() - std::time::Duration::from_secs(10))));
    let cache = Arc::new(TokioMutex::new(lru::LruCache::<Vec<u8>, CacheEntry>::new(NonZeroUsize::new(1000).unwrap())));

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1000);

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                break;
            }
            Some(packet) = rx.recv() => {
                let _ = unsafe { libc::write(tun_fd, packet.as_ptr() as *mut libc::c_void, packet.len()) };
            }
            res = async_fd.readable() => {
                let mut guard = match res {
                    Ok(g) => g,
                    Err(_) => continue,
                };
        
        match unsafe { libc::read(tun_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) } {
            n if n > 0 => {
                let n = n as usize;
                let pkt = &buf[..n];
                
                if let Ok(sliced) = etherparse::SlicedPacket::from_ip(pkt) {
                    if let Some(etherparse::TransportSlice::Udp(udp)) = sliced.transport.as_ref() {
                        if udp.destination_port() == 53 {
                            let payload = udp.payload();
                            if let Some(qname) = extract_dns_name(payload) {
                                log_trace(&format!("Received DNS query for {}", String::from_utf8_lossy(qname)));
                                // Lowercased forward key for cache lookups
                                let mut cache_key = to_lowercase_wire_format(qname);
                                let mut idx = 12;
                                while idx < payload.len() {
                                    let len = payload[idx] as usize;
                                    if len == 0 { idx += 1; break; }
                                    idx += len + 1;
                                }
                                let full_cache_key = if idx + 2 <= payload.len() {
                                    cache_key.extend_from_slice(&payload[idx..idx+2]);
                                    Some(cache_key)
                                } else { None };

                                // Reversed key for blocklist trie lookups
                                let trie_key = to_trie_key(qname);
                                
                                let blocked = {
                                    let lock = blocklist.read().unwrap_or_else(|e| e.into_inner());
                                    lock.get_ancestor_value(&trie_key).is_some()
                                };
                                
                                if blocked {
                                    if let Some(resp) = create_null_response(&sliced, payload) {
                                        let _ = tx.try_send(resp);
                                    }
                                } else {
                                    // Check cache
                                    let mut cache_lock = cache.lock().await;
                                    let mut use_cache = false;
                                    if let Some(ck) = &full_cache_key {
                                        if let Some(cached_entry) = cache_lock.get(ck) {
                                            if Instant::now() < cached_entry.expires_at {
                                                if let Some(resp) = create_forwarded_response(&sliced, payload, &cached_entry.payload) {
                                                    let _ = tx.try_send(resp);
                                                }
                                                use_cache = true;
                                            }
                                        }
                                    }
                                    if use_cache {
                                        continue;
                                    }
                                    drop(cache_lock);
                                                                       // Forward via DoQ
                                    let doq_conn = doq_conn.clone();
                                    let doq_endpoint_v4 = doq_endpoint_v4.clone();
                                    let doq_endpoint_v6 = doq_endpoint_v6.clone();
                                    let payload_vec = payload.to_vec();
                                    let req_ip = pkt.to_vec();
                                    let cache_key = full_cache_key;
                                    let cache_clone = cache.clone();
                                    let upstream_v4_clone = upstream_v4.clone();
                                    let upstream_v6_clone = upstream_v6.clone();
                                    let tx_clone = tx.clone();
                                    let sni_clone = sni_hostname.clone();
                                    let task_token = cancel_token.clone();
                                    
                                    if let Ok(permit) = semaphore.clone().try_acquire_owned() {
                                        tokio::spawn(async move {
                                            let _permit = permit;
                                            tokio::select! {
                                                _ = task_token.cancelled() => {}
                                                _ = async {
                                            let mut retries = 30; // Max 3 seconds of waiting (30 * 100ms)
                                            while retries > 0 {
                                                retries -= 1;
                                                
                                                let doq = {
                                                    let mut lock = doq_conn.lock().await;
                                                    if let Some(c) = lock.0.as_ref().filter(|c| c.is_alive()) {
                                                        Some(c.clone())
                                                    } else {
                                                        let now = std::time::Instant::now();
                                                        if now.duration_since(lock.1) < std::time::Duration::from_secs(10) {
                                                            log_trace("Debouncing DoQ connection");
                                                            None
                                                        } else {
                                                            lock.1 = now;
                                                            drop(lock); // Drop lock while connecting to prevent blocking other queries!
                                                            log_trace(&format!("Attempting to connect DoQ (Happy Eyeballs) with SNI {}", sni_clone));
                                                            
                                                            let fut_v6 = async {
                                                                if let (Some(ep), Some(ip)) = (&doq_endpoint_v6, &upstream_v6_clone) {
                                                                    ep.connect(ip, &sni_clone).await
                                                                } else {
                                                                    Err("No IPv6 upstream".into())
                                                                }
                                                            };
                                                            let fut_v4 = async {
                                                                if let (Some(ep), Some(ip)) = (&doq_endpoint_v4, &upstream_v4_clone) {
                                                                    ep.connect(ip, &sni_clone).await
                                                                } else {
                                                                    Err("No IPv4 upstream".into())
                                                                }
                                                            };

                                                            let connect_future = async {
                                                                if upstream_v6_clone.is_some() && upstream_v4_clone.is_some() {
                                                                    let mut fut6 = std::pin::pin!(fut_v6);
                                                                    let mut fut4 = std::pin::pin!(fut_v4);
                                                                    tokio::select! {
                                                                        res = &mut fut6 => {
                                                                            if res.is_ok() { return res; }
                                                                            fut4.await
                                                                        }
                                                                        _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                                                                            tokio::select! {
                                                                                res = &mut fut6 => {
                                                                                    if res.is_ok() { return res; }
                                                                                    fut4.await
                                                                                }
                                                                                res = &mut fut4 => {
                                                                                    if res.is_ok() { return res; }
                                                                                    fut6.await
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                } else if upstream_v6_clone.is_some() {
                                                                    fut_v6.await
                                                                } else {
                                                                    fut_v4.await
                                                                }
                                                            };
                                                            
                                                            match tokio::time::timeout(std::time::Duration::from_secs(10), connect_future).await {
                                                                Ok(Ok(c)) => {
                                                                    log_trace("DoQ connection established");
                                                                    let arc = Arc::new(c);
                                                                    let mut lock = doq_conn.lock().await;
                                                                    lock.0 = Some(arc.clone());
                                                                    lock.1 = std::time::Instant::now() - std::time::Duration::from_secs(10); // Reset debounce
                                                                    Some(arc)
                                                                }
                                                                Ok(Err(e)) => {
                                                                    log_trace(&format!("DoQ Connect Error: {}", e));
                                                                    let mut lock = doq_conn.lock().await;
                                                                    lock.1 = std::time::Instant::now() - std::time::Duration::from_secs(10);
                                                                    None
                                                                }
                                                                Err(_) => {
                                                                    log_trace("DoQ Connect Timeout");
                                                                    let mut lock = doq_conn.lock().await;
                                                                    lock.1 = std::time::Instant::now() - std::time::Duration::from_secs(10);
                                                                    None
                                                                }
                                                            }
                                                        }
                                                    }
                                                };
                                                
                                                if let Some(doq) = doq {
                                                    log_trace("Sending query via DoQ...");
                                                    let query_future = doq.send_query(&payload_vec);
                                                    match tokio::time::timeout(std::time::Duration::from_secs(3), query_future).await {
                                                        Ok(Ok(resp_payload)) => {
                                                            log_trace(&format!("Received DoQ response! len={}", resp_payload.len()));
                                                            if resp_payload.len() >= 12 {
                                                                let rcode = resp_payload[3] & 0x0F;
                                                                let ancount = u16::from_be_bytes([resp_payload[6], resp_payload[7]]);
                                                                log_trace(&format!("DoQ response RCODE={}, ANCOUNT={}", rcode, ancount));
                                                            }
                                                            log_trace(&format!("REQ HEX: {:02x?}", payload_vec));
                                                            log_trace(&format!("RSP HEX: {:02x?}", resp_payload));
                                                            if let Ok(sliced) = etherparse::SlicedPacket::from_ip(&req_ip) {
                                                                if let Some(resp) = create_forwarded_response(&sliced, &payload_vec, &resp_payload) {
                                                                    log_trace("Sending response to TUN channel");
                                                                    let _ = tx_clone.try_send(resp);
                                                                    if let Some(ck) = cache_key {
                                                                        if let Some(ttl) = get_min_ttl(&resp_payload) {
                                                                            if ttl > 0 {
                                                                                let mut lock = cache_clone.lock().await;
                                                                                lock.put(ck, CacheEntry {
                                                                                    payload: resp_payload,
                                                                                    expires_at: std::time::Instant::now() + std::time::Duration::from_secs(ttl as u64),
                                                                                });
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            break;
                                                        }
                                                        _ => {
                                                            log_trace("send_query failed or timed out");
                                                            // Timeout or Error from DoQ
                                                            let mut lock = doq_conn.lock().await;
                                                            lock.0 = None;
                                                            // Loop continues to retry connection
                                                        }
                                                    }
                                                } else {
                                                    // Failed to connect, or waiting for another query to finish connecting
                                                    if retries == 0 {
                                                        if let Ok(sliced) = etherparse::SlicedPacket::from_ip(&req_ip) {
                                                            if let Some(resp) = create_servfail_response(&sliced, &payload_vec) {
                                                                let _ = tx_clone.try_send(resp);
                                                            }
                                                        }
                                                        break; // We've waited 3 seconds. Send SERVFAIL and give up.
                                                    }
                                                    
                                                    // Sleep 100ms and check again to see if the connection is ready!
                                                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                                }
                                            }
                                                } => {}
                                            }
                                        });
                                    } else {
                                        // Semaphore full: Return SERVFAIL immediately to prevent app hang
                                        if let Ok(sliced) = etherparse::SlicedPacket::from_ip(&req_ip) {
                                            if let Some(resp) = create_servfail_response(&sliced, &payload_vec) {
                                                let _ = tx_clone.try_send(resp);
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            // Drop non-DNS UDP packets to prevent ICMP amplification
                        }
                    } else if let Some(etherparse::TransportSlice::Tcp(_)) = sliced.transport.as_ref() {
                        if let Some(resp) = create_tcp_rst(&sliced) {
                            let _ = tx.try_send(resp);
                        }
                    }
                }
            }
            n if n < 0 => {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                } else {
                    log_trace(&format!("Read error: {}", err));
                    break;
                }
            }
            _ => {
                log_trace("TUN closed / EOF");
                break;
            }
        }
            } // end res = async_fd.readable()
        } // end tokio::select!
    } // end loop
}
