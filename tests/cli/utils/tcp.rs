//! TCP-level test support.

use std::time::Duration;

use tokio::{io::AsyncWriteExt as _, net::TcpListener};

/// Sentinel string the host-side TCP stub writes to any client.
/// Picked to be obviously unique so a `contains` check is reliable.
pub const SENTINEL: &str = "redoubtful-sandbox-leak-sentinel-v1";

/// Spawn a single-shot TCP listener on `127.0.0.1:0` that accepts
/// one connection, writes [`SENTINEL`], and closes. Returns the
/// allocated port.
///
/// The runtime is kept alive on a dedicated background OS thread
/// (rather than `tokio::main` on the test, which would block the
/// `assert_cmd` invocation that needs to run on the same thread).
pub fn spawn_sentinel_listener() -> u16 {
    let (port_tx, port_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind 127.0.0.1:0");
            let port = listener.local_addr().expect("local_addr").port();
            port_tx.send(port).expect("send port");
            // Accept one client, write the sentinel, hang up.
            // Multiple clients per test would force ordering; one is
            // enough for both the positive control and the in-sandbox
            // probe (each test spawns its own listener).
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(SENTINEL.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
    });
    port_rx.recv().expect("listener never reported a port")
}

/// Read up to a few KB from a port (host-side) so the positive
/// control can assert the sentinel actually arrives end-to-end
/// before we trust the negative case.
pub fn read_sentinel_from_host(port: u16) -> String {
    use std::io::Read as _;
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .expect("host control connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("read sentinel");
    buf
}
