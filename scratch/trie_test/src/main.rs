use radix_trie::Trie;

fn to_trie_key(name: &[u8]) -> Vec<u8> {
    let mut labels: Vec<(usize, usize)> = Vec::new();
    let mut idx = 0;
    while idx < name.len() {
        let len = name[idx] as usize;
        if len == 0 { break; }
        labels.push((idx, 1 + len));
        idx += 1 + len;
    }
    labels.reverse();
    let mut out = Vec::with_capacity(name.len());
    for (start, size) in labels {
        out.push(name[start]); // length byte
        for i in 1..size {
            out.push(name[start + i].to_ascii_lowercase());
        }
    }
    out
}

fn domain_to_wire_format(domain: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let parts: Vec<&str> = domain.split('.').filter(|p| !p.is_empty()).collect();
    for part in parts.iter().rev() {
        out.push(part.len() as u8);
        out.extend_from_slice(part.to_ascii_lowercase().as_bytes());
    }
    out
}

fn extract_dns_name(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < 12 { return None; }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 { return None; }

    let mut idx = 12;
    let start = idx;
    while idx < payload.len() {
        let len = payload[idx] as usize;
        if len == 0 {
            idx += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            return None;
        }
        if len > 63 { return None; }
        idx += len + 1;
    }

    if idx <= payload.len() {
        Some(&payload[start..idx])
    } else {
        None
    }
}

fn main() {
    let mut trie = Trie::new();
    let blocklist = vec!["google.com", "doubleclick.net"];
    for domain in blocklist {
        trie.insert(domain_to_wire_format(domain), ());
    }
    
    // Wire format for a DNS query for "www.google.com"
    let req_payload: Vec<u8> = vec![
        0x00, 0x01, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        // QNAME: www.google.com
        3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        // QTYPE, QCLASS
        0x00, 0x01, 0x00, 0x01
    ];
    
    let qname = extract_dns_name(&req_payload).unwrap();
    let trie_key = to_trie_key(qname);
    
    println!("Extracted QNAME: {:?}", qname);
    println!("Trie Key: {:?}", trie_key);
    println!("Wire Format Google: {:?}", domain_to_wire_format("google.com"));
    
    let is_blocked = trie.get_ancestor_value(&trie_key).is_some();
    println!("Is blocked: {}", is_blocked);
}
