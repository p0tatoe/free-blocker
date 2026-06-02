use etherparse::{PacketBuilder, SlicedPacket, NetSlice, TransportSlice};

// Quick zero-copy DNS name extractor
pub fn extract_dns_name(payload: &[u8]) -> Option<&[u8]> {
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
            // Not supporting pointers in question section for blocklist
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

/// Lowercase a wire-format DNS name, preserving label structure and trailing null.
pub fn to_lowercase_wire_format(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    let mut idx = 0;
    while idx < name.len() {
        let len = name[idx];
        out.push(len);
        if len == 0 { break; }
        for i in 0..len as usize {
            if idx + 1 + i < name.len() {
                out.push(name[idx + 1 + i].to_ascii_lowercase());
            }
        }
        idx += 1 + len as usize;
    }
    out
}

/// Convert a wire-format DNS name to a trie lookup key: lowercased and label-reversed.
/// Input:  \x07example\x03com\x00  (forward wire format from DNS packet)
/// Output: \x03com\x07example      (reversed, no trailing \x00, for prefix matching)
///
/// Reversing makes TLD-first so `get_ancestor_value` finds parent domains.
/// Omitting the trailing \x00 ensures a stored parent is a byte-level prefix of children.
pub fn to_trie_key(name: &[u8]) -> Vec<u8> {
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

pub fn create_null_response(sliced: &SlicedPacket, req_payload: &[u8]) -> Option<Vec<u8>> {
    if req_payload.len() < 12 { return None; }

    // Walk past the QNAME to locate QTYPE
    let mut idx = 12;
    while idx < req_payload.len() {
        let len = req_payload[idx] as usize;
        if len == 0 { idx += 1; break; }
        idx += len + 1;
    }
    if idx + 2 > req_payload.len() { return None; }
    let qtype = u16::from_be_bytes([req_payload[idx], req_payload[idx + 1]]);

    let builder = match sliced.net.as_ref()? {
        NetSlice::Ipv4(ipv4) => {
            PacketBuilder::ipv4(ipv4.header().destination(), ipv4.header().source(), 64)
        }
        NetSlice::Ipv6(ipv6) => {
            PacketBuilder::ipv6(ipv6.header().destination(), ipv6.header().source(), 64)
        }
    };

    let udp = match sliced.transport.as_ref()? {
        TransportSlice::Udp(udp) => udp,
        _ => return None,
    };

    let builder = builder.udp(udp.destination_port(), udp.source_port());

    // Build DNS response (Standard query response, No error)
    let mut dns_resp = req_payload.to_vec();
    dns_resp[2] |= 0x80; // QR = 1 (Response)

    match qtype {
        1 => {
            // Type A — answer with 0.0.0.0
            dns_resp[6] = 0;
            dns_resp[7] = 1; // ANCOUNT = 1
            dns_resp.extend_from_slice(&[
                0xC0, 0x0C,             // Name pointer to question
                0x00, 0x01,             // Type A
                0x00, 0x01,             // Class IN
                0x00, 0x00, 0x01, 0x2C, // TTL 300
                0x00, 0x04,             // RDLENGTH 4
                0, 0, 0, 0,             // 0.0.0.0
            ]);
        }
        28 => {
            // Type AAAA — answer with ::
            dns_resp[6] = 0;
            dns_resp[7] = 1; // ANCOUNT = 1
            dns_resp.extend_from_slice(&[
                0xC0, 0x0C,             // Name pointer to question
                0x00, 0x1C,             // Type AAAA
                0x00, 0x01,             // Class IN
                0x00, 0x00, 0x01, 0x2C, // TTL 300
                0x00, 0x10,             // RDLENGTH 16
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, // ::
            ]);
        }
        _ => {
            // Other types — empty answer (NOERROR, no records)
            dns_resp[6] = 0;
            dns_resp[7] = 0; // ANCOUNT = 0
        }
    }

    let mut result = Vec::with_capacity(builder.size(dns_resp.len()));
    builder.write(&mut result, &dns_resp).ok()?;

    Some(result)
}

pub fn create_forwarded_response(sliced: &SlicedPacket, req_payload: &[u8], dns_resp: &[u8]) -> Option<Vec<u8>> {
    let builder = match sliced.net.as_ref()? {
        NetSlice::Ipv4(ipv4) => {
            PacketBuilder::ipv4(ipv4.header().destination(), ipv4.header().source(), 64)
        }
        NetSlice::Ipv6(ipv6) => {
            PacketBuilder::ipv6(ipv6.header().destination(), ipv6.header().source(), 64)
        }
    };

    let udp = match sliced.transport.as_ref()? {
        TransportSlice::Udp(udp) => udp,
        _ => return None,
    };

    let builder = builder.udp(udp.destination_port(), udp.source_port());

    let mut patched_resp = dns_resp.to_vec();
    if patched_resp.len() >= 2 && req_payload.len() >= 2 {
        patched_resp[0] = req_payload[0];
        patched_resp[1] = req_payload[1];
    }

    let mut result = Vec::with_capacity(builder.size(patched_resp.len()));
    builder.write(&mut result, &patched_resp).ok()?;

    Some(result)
}
