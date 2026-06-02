use quinn::Endpoint;

async fn test(send: &mut quinn::SendStream) {
    let _ = send.finish();
}
