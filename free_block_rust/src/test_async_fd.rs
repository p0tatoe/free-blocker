use tokio::io::unix::AsyncFd;

fn main() {
    let fd: i32 = 1;
    let _ = AsyncFd::new(fd);
}
