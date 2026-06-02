use quinn::RecvStream;

async fn test(recv: &mut RecvStream) {
    let buf: Vec<u8> = recv.read_to_end(65536).await.unwrap();
}
