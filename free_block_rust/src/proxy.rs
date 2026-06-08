use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};

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

    let mut idx = 12;
    while idx < req_payload.len() {
        let len = req_payload[idx] as usize;
        if len == 0 { idx += 1; break; }
        idx += len + 1;
    }
    if idx + 4 > req_payload.len() { return None; }

    let builder = match sliced.net.as_ref()? {
        etherparse::InternetSlice::Ipv4(ipv4) => {
            PacketBuilder::ipv4(ipv4.header().destination(), ipv4.header().source(), 64)
        }
        etherparse::InternetSlice::Ipv6(ipv6) => {
            PacketBuilder::ipv6(ipv6.header().destination(), ipv6.header().source(), 64)
        }
        _ => return None,
    };

    let udp = match sliced.transport.as_ref()? {
        TransportSlice::Udp(udp) => udp,
        _ => return None,
    };

    let builder = builder.udp(udp.destination_port(), udp.source_port());

    // Copy only Header + Question to avoid invalidating the packet if it had OPT records
    let mut dns_resp = req_payload[0..idx+4].to_vec();

    // Set Flags: QR=1 (Response), AA=1 (Authoritative)
    dns_resp[2] |= 0x84; 
    // Set Flags: RA=1 (Recursion Available), RCODE=3 (NXDOMAIN)
    dns_resp[3] |= 0x83;

    // ANCOUNT = 0
    dns_resp[6] = 0; dns_resp[7] = 0;
    // NSCOUNT = 1 (SOA)
    dns_resp[8] = 0; dns_resp[9] = 1;
    // ARCOUNT = 0
    dns_resp[10] = 0; dns_resp[11] = 0;

    // Append SOA record
    dns_resp.extend_from_slice(&[
        0xC0, 0x0C,             // Name (Pointer to Question)
        0x00, 0x06,             // Type SOA
        0x00, 0x01,             // Class IN
        0x00, 0x00, 0x00, 0x01, // TTL 1 second
        0x00, 0x16,             // RDLENGTH 22 bytes
        0x00,                   // MNAME (root)
        0x00,                   // RNAME (root)
        0x00, 0x00, 0x00, 0x00, // Serial
        0x00, 0x00, 0x00, 0x00, // Refresh
        0x00, 0x00, 0x00, 0x00, // Retry
        0x00, 0x00, 0x00, 0x00, // Expire
        0x00, 0x00, 0x00, 0x01, // Minimum TTL 1 second
    ]);

    let mut result = Vec::with_capacity(builder.size(dns_resp.len()));
    builder.write(&mut result, &dns_resp).ok()?;

    Some(result)
}

pub fn create_servfail_response(sliced: &etherparse::SlicedPacket, req_payload: &[u8]) -> Option<Vec<u8>> {
    let builder = match sliced.net.as_ref()? {
        etherparse::InternetSlice::Ipv4(ipv4) => {
            etherparse::PacketBuilder::ipv4(ipv4.header().destination(), ipv4.header().source(), 64)
        }
        etherparse::InternetSlice::Ipv6(ipv6) => {
            etherparse::PacketBuilder::ipv6(ipv6.header().destination(), ipv6.header().source(), 64)
        }
        _ => return None,
    };

    let udp = match sliced.transport.as_ref()? {
        etherparse::TransportSlice::Udp(udp) => udp,
        _ => return None,
    };

    let builder = builder.udp(udp.destination_port(), udp.source_port());

    if req_payload.len() < 12 {
        return None;
    }

    let mut dns_resp = req_payload.to_vec();
    // Set QR=1 (response), leave Opcode unchanged, set RCODE=2 (SERVFAIL)
    dns_resp[2] = (dns_resp[2] | 0x80) & 0xFB; // QR=1, AA=0, TC=0, RD=RD
    dns_resp[3] = (dns_resp[3] & 0x70) | 0x02; // RA=0, RCODE=2

    // Clear ANCOUNT, NSCOUNT, ARCOUNT
    for i in 6..12 {
        dns_resp[i] = 0;
    }

    // Keep only the question section
    let mut idx = 12;
    while idx < dns_resp.len() {
        let len = dns_resp[idx] as usize;
        if len == 0 {
            idx += 1;
            break;
        }
        if (dns_resp[idx] & 0xC0) == 0xC0 {
            idx += 2;
            break;
        }
        idx += len + 1;
    }
    idx += 4; // QTYPE and QCLASS
    if idx <= dns_resp.len() {
        dns_resp.truncate(idx);
    } else {
        return None; // Malformed query
    }

    let mut result = Vec::with_capacity(builder.size(dns_resp.len()));
    builder.write(&mut result, &dns_resp).ok()?;

    Some(result)
}

pub fn create_forwarded_response(sliced: &SlicedPacket, req_payload: &[u8], dns_resp: &[u8]) -> Option<Vec<u8>> {
    let builder = match sliced.net.as_ref()? {
        etherparse::InternetSlice::Ipv4(ipv4) => {
            PacketBuilder::ipv4(ipv4.header().destination(), ipv4.header().source(), 64)
        }
        etherparse::InternetSlice::Ipv6(ipv6) => {
            PacketBuilder::ipv6(ipv6.header().destination(), ipv6.header().source(), 64)
        }
        _ => return None,
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

pub fn create_tcp_rst(sliced: &SlicedPacket) -> Option<Vec<u8>> {
    use etherparse::{Ipv4Header, Ipv6Header, TcpHeader, InternetSlice, TransportSlice};
    
    let tcp = match sliced.transport.as_ref()? {
        TransportSlice::Tcp(tcp) => tcp,
        _ => return None,
    };

    let mut tcp_resp = TcpHeader::new(tcp.destination_port(), tcp.source_port(), 0, 0);
    tcp_resp.rst = true;

    if tcp.ack() {
        tcp_resp.sequence_number = tcp.acknowledgment_number();
        tcp_resp.ack = false;
    } else {
        tcp_resp.acknowledgment_number = tcp.sequence_number().wrapping_add(1);
        tcp_resp.ack = true;
    }

    let mut buf = Vec::with_capacity(128);
    match sliced.net.as_ref()? {
        InternetSlice::Ipv4(ipv4) => {
            let ipv4_resp = Ipv4Header::new(
                tcp_resp.header_len() as u16,
                64,
                etherparse::IpNumber::TCP,
                ipv4.header().destination(),
                ipv4.header().source(),
            ).ok()?;
            ipv4_resp.write(&mut buf).ok()?;
            tcp_resp.checksum = tcp_resp.calc_checksum_ipv4(&ipv4_resp, &[]).unwrap_or(0);
        }
        InternetSlice::Ipv6(ipv6) => {
            let ipv6_resp = Ipv6Header {
                traffic_class: 0,
                flow_label: etherparse::Ipv6FlowLabel::ZERO,
                payload_length: tcp_resp.header_len() as u16,
                next_header: etherparse::IpNumber::TCP,
                hop_limit: 64,
                source: ipv6.header().destination(),
                destination: ipv6.header().source(),
            };
            ipv6_resp.write(&mut buf).ok()?;
            tcp_resp.checksum = tcp_resp.calc_checksum_ipv6(&ipv6_resp, &[]).unwrap_or(0);
        }
        _ => return None,
    }
    
    tcp_resp.write(&mut buf).ok()?;
    Some(buf)
}

#[allow(dead_code)]
pub fn create_icmp_unreachable(sliced: &SlicedPacket, raw_packet: &[u8]) -> Option<Vec<u8>> {
    use etherparse::{Ipv4Header, Ipv6Header, Icmpv4Header, Icmpv4Type, icmpv4, Icmpv6Header, Icmpv6Type, icmpv6, InternetSlice};
    
    let payload_len = std::cmp::min(raw_packet.len(), 576);
    let original_bytes = &raw_packet[..payload_len];
    
    let mut buf = Vec::with_capacity(payload_len + 64);
    
    match sliced.net.as_ref()? {
        InternetSlice::Ipv4(ipv4) => {
            let icmp = Icmpv4Header {
                icmp_type: Icmpv4Type::DestinationUnreachable(icmpv4::DestUnreachableHeader::Port),
                checksum: 0,
            };
            let mut icmp_bytes = icmp.to_bytes();
            let cksum = etherparse::checksum::Sum16BitWords::new()
                .add_slice(&icmp_bytes)
                .add_slice(original_bytes)
                .ones_complement();
            let cksum_bytes = cksum.to_be_bytes();
            icmp_bytes[2] = cksum_bytes[0];
            icmp_bytes[3] = cksum_bytes[1];
            
            let ipv4_resp = Ipv4Header::new(
                (icmp_bytes.len() + original_bytes.len()) as u16,
                64,
                etherparse::IpNumber::ICMP,
                ipv4.header().destination(),
                ipv4.header().source(),
            ).ok()?;
            ipv4_resp.write(&mut buf).ok()?;
            buf.extend_from_slice(&icmp_bytes);
            buf.extend_from_slice(original_bytes);
        }
        InternetSlice::Ipv6(ipv6) => {
            let icmp = Icmpv6Header {
                icmp_type: Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::Port),
                checksum: 0,
            };
            
            let ipv6_resp = Ipv6Header {
                traffic_class: 0,
                flow_label: etherparse::Ipv6FlowLabel::ZERO,
                payload_length: (8 + original_bytes.len()) as u16,
                next_header: etherparse::IpNumber::IPV6_ICMP,
                hop_limit: 64,
                source: ipv6.header().destination(),
                destination: ipv6.header().source(),
            };
            
            let mut icmp_bytes = icmp.to_bytes();
            let cksum = etherparse::checksum::Sum16BitWords::new()
                .add_16bytes(ipv6_resp.source)
                .add_16bytes(ipv6_resp.destination)
                .add_4bytes((ipv6_resp.payload_length as u32).to_be_bytes())
                .add_2bytes([0, 0])
                .add_2bytes([0, etherparse::IpNumber::IPV6_ICMP.0])
                .add_slice(&icmp_bytes)
                .add_slice(original_bytes)
                .ones_complement();
                
            let cksum_bytes = cksum.to_be_bytes();
            icmp_bytes[2] = cksum_bytes[0];
            icmp_bytes[3] = cksum_bytes[1];
            
            ipv6_resp.write(&mut buf).ok()?;
            buf.extend_from_slice(&icmp_bytes);
            buf.extend_from_slice(original_bytes);
        }
        _ => return None,
    }
    Some(buf)
}
