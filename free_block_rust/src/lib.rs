uniffi::setup_scaffolding!();

mod proxy;
mod quic;

use proxy::{extract_dns_name, to_lowercase_wire_format, to_trie_key, create_null_response, create_forwarded_response};
use quic::DoqClient;
use radix_trie::Trie;
use std::sync::{Arc, RwLock};
use tokio::runtime::Runtime;
use tokio::sync::Mutex as TokioMutex;
use lru::LruCache;
use std::num::NonZeroUsize;

#[derive(uniffi::Object)]
pub struct DnsProxy {
    tun_fd: i32,
    upstream_host: String,
    sni_hostname: String,
    blocklist: Arc<RwLock<Trie<Vec<u8>, ()>>>,
    rt: Runtime,
}

#[uniffi::export]
impl DnsProxy {
    #[uniffi::constructor]
    pub fn new(tun_fd: i32, upstream_host: String, sni_hostname: String) -> Arc<Self> {
        Arc::new(Self {
            tun_fd,
            upstream_host,
            sni_hostname,
            blocklist: Arc::new(RwLock::new(Trie::new())),
            rt: tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        })
    }

    pub fn start(&self) {
        let tun_fd = self.tun_fd;
        let upstream = self.upstream_host.clone();
        let sni_hostname = self.sni_hostname.clone();
        let blocklist = self.blocklist.clone();

        self.rt.spawn(async move {
            run_proxy(tun_fd, upstream, sni_hostname, blocklist).await;
        });
    }

    pub fn update_blocklist(&self, domains: Vec<String>) {
        let mut trie = Trie::new();
        for domain in domains {
            let wire_format = domain_to_wire_format(&domain);
            trie.insert(wire_format, ());
        }
        if let Ok(mut lock) = self.blocklist.write() {
            *lock = trie;
        }
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

async fn run_proxy(tun_fd: i32, upstream: String, sni_hostname: String, blocklist: Arc<RwLock<Trie<Vec<u8>, ()>>>) {
    unsafe {
        let flags = libc::fcntl(tun_fd, libc::F_GETFL);
        libc::fcntl(tun_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    
    let async_fd = match tokio::io::unix::AsyncFd::new(tun_fd) {
        Ok(fd) => fd,
        Err(_) => return,
    };
    
    let doq_pool: Arc<TokioMutex<Option<Arc<DoqClient>>>> = Arc::new(TokioMutex::new(None));
    let cache = Arc::new(TokioMutex::new(LruCache::<Vec<u8>, Vec<u8>>::new(NonZeroUsize::new(1000).unwrap())));
    let mut buf = [0u8; 65536];

    loop {
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(_) => continue,
        };
        
        match unsafe { libc::read(tun_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) } {
            n if n > 0 => {
                guard.retain_ready();
                let n = n as usize;
                let pkt = &buf[..n];
                
                if let Ok(sliced) = etherparse::SlicedPacket::from_ip(pkt) {
                    if let Some(etherparse::TransportSlice::Udp(udp)) = sliced.transport.as_ref() {
                        if udp.destination_port() == 53 {
                            let payload = udp.payload();
                            if let Some(qname) = extract_dns_name(payload) {
                                // Lowercased forward key for cache lookups
                                let mut cache_key = to_lowercase_wire_format(qname);
                                let mut idx = 12;
                                while idx < payload.len() {
                                    let len = payload[idx] as usize;
                                    if len == 0 { idx += 1; break; }
                                    idx += len + 1;
                                }
                                if idx + 2 <= payload.len() {
                                    cache_key.extend_from_slice(&payload[idx..idx+2]);
                                }

                                // Reversed key for blocklist trie lookups
                                let trie_key = to_trie_key(qname);
                                
                                let blocked = {
                                    if let Ok(lock) = blocklist.read() {
                                        lock.get_ancestor_value(&trie_key).is_some()
                                    } else {
                                        false
                                    }
                                };
                                
                                if blocked {
                                    if let Some(resp) = create_null_response(&sliced, payload) {
                                        let _ = unsafe { libc::write(tun_fd, resp.as_ptr() as *const libc::c_void, resp.len()) };
                                    }
                                } else {
                                    // Check cache (keyed on forward-order lowercased qname + qtype)
                                    let mut cache_lock = cache.lock().await;
                                    if let Some(cached_resp) = cache_lock.get(&cache_key) {
                                        if let Some(resp) = create_forwarded_response(&sliced, payload, cached_resp) {
                                            let _ = unsafe { libc::write(tun_fd, resp.as_ptr() as *const libc::c_void, resp.len()) };
                                        }
                                        continue;
                                    }
                                    drop(cache_lock);
                                    
                                    // Forward via DoQ
                                    let doq_pool = doq_pool.clone();
                                    let req_ip = pkt.to_vec();
                                    let payload_vec = payload.to_vec();
                                    let cache_key = cache_key;  // move into closure
                                    let cache_clone = cache.clone();
                                    let upstream_clone = upstream.clone();
                                    let sni_clone = sni_hostname.clone();
                                    
                                    tokio::spawn(async move {
                                        let mut retries = 2;
                                        while retries > 0 {
                                            retries -= 1;
                                            
                                            let doq_opt = doq_pool.lock().await.as_ref().filter(|c| c.is_alive()).cloned();
                                            let doq = if let Some(c) = doq_opt {
                                                c
                                            } else {
                                                if let Ok(c) = DoqClient::connect(&upstream_clone, &sni_clone).await {
                                                    let arc = Arc::new(c);
                                                    *doq_pool.lock().await = Some(arc.clone());
                                                    arc
                                                } else {
                                                    break;
                                                }
                                            };
                                            
                                            let query_future = doq.send_query(&payload_vec);
                                            match tokio::time::timeout(std::time::Duration::from_secs(3), query_future).await {
                                                Ok(Ok(resp_payload)) => {
                                                    cache_clone.lock().await.put(cache_key, resp_payload.clone());
                                                    if let Ok(sliced) = etherparse::SlicedPacket::from_ip(&req_ip) {
                                                        if let Some(resp) = create_forwarded_response(&sliced, &payload_vec, &resp_payload) {
                                                            let _ = unsafe { libc::write(tun_fd, resp.as_ptr() as *const libc::c_void, resp.len()) };
                                                        }
                                                    }
                                                    break;
                                                }
                                                _ => {
                                                    // Timeout or Error from DoQ
                                                    let mut lock = doq_pool.lock().await;
                                                    *lock = None;
                                                }
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }
                }
            }
            n if n < 0 => {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                } else {
                    break;
                }
            }
            _ => break, // n == 0: EOF / TUN closed
        }
    }
}
