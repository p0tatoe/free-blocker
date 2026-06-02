use radix_trie::Trie;

fn domain_to_wire_format(domain: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let parts: Vec<&str> = domain.split('.').filter(|p| !p.is_empty()).collect();
    for part in parts.iter().rev() {
        out.push(part.len() as u8);
        out.extend_from_slice(part.to_ascii_lowercase().as_bytes());
    }
    out
}

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
        out.push(name[start]);
        for i in 1..size {
            out.push(name[start + i].to_ascii_lowercase());
        }
    }
    out
}

// Simulates DNS wire format qname (forward order with trailing \x00)
fn make_qname(domain: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for part in domain.split('.') {
        if !part.is_empty() {
            out.push(part.len() as u8);
            out.extend_from_slice(part.as_bytes());
        }
    }
    out.push(0);
    out
}

#[test]
fn test_exact_match() {
    let mut trie = Trie::new();
    let key = domain_to_wire_format("example.com");
    println!("Insertion key for 'example.com': {:?}", key);
    trie.insert(key.clone(), ());

    let qname = make_qname("example.com");
    let lookup = to_trie_key(&qname);
    println!("Lookup key for 'example.com': {:?}", lookup);
    println!("Keys equal: {}", key == lookup);

    let result = trie.get_ancestor_value(&lookup);
    println!("get_ancestor_value exact match: {:?}", result.is_some());
    assert!(result.is_some(), "Exact match should work");
}

#[test]
fn test_subdomain_match() {
    let mut trie = Trie::new();
    let key = domain_to_wire_format("example.com");
    println!("Insertion key for 'example.com': {:?}", key);
    trie.insert(key, ());

    let qname = make_qname("ads.example.com");
    let lookup = to_trie_key(&qname);
    println!("Lookup key for 'ads.example.com': {:?}", lookup);

    let result = trie.get_ancestor_value(&lookup);
    println!("get_ancestor_value subdomain match: {:?}", result.is_some());
    assert!(result.is_some(), "Subdomain should match parent");
}

#[test]
fn test_no_false_positive() {
    let mut trie = Trie::new();
    trie.insert(domain_to_wire_format("example.com"), ());

    let qname = make_qname("notexample.com");
    let lookup = to_trie_key(&qname);
    println!("Lookup key for 'notexample.com': {:?}", lookup);

    let result = trie.get_ancestor_value(&lookup);
    println!("get_ancestor_value false positive test: {:?}", result.is_some());
    assert!(result.is_none(), "notexample.com should NOT match example.com");
}

#[test]
fn test_no_cross_domain() {
    let mut trie = Trie::new();
    trie.insert(domain_to_wire_format("example.com"), ());

    let qname = make_qname("google.com");
    let lookup = to_trie_key(&qname);

    let result = trie.get_ancestor_value(&lookup);
    println!("get_ancestor_value cross-domain test: {:?}", result.is_some());
    assert!(result.is_none(), "google.com should NOT match example.com");
}
