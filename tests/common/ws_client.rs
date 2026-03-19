use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// A WebSocket subscriber for test assertions.
/// Connects to /ws and collects broadcast JSON events.
pub struct WsClient {
    rx: mpsc::UnboundedReceiver<Value>,
    /// Keep the task alive
    _handle: tokio::task::JoinHandle<()>,
}

impl WsClient {
    /// Connect to `ws://{addr}/ws` and start collecting events.
    pub async fn connect(addr: std::net::SocketAddr) -> Self {
        let url = format!("ws://{}/ws", addr);
        let (ws_stream, _) = connect_async(&url).await.expect("WsClient: connect failed");
        let (mut _sink, mut stream) = ws_stream.split();
        let (tx, rx) = mpsc::unbounded_channel();

        let handle = tokio::spawn(async move {
            while let Some(Ok(msg)) = stream.next().await {
                if let Message::Text(text) = msg {
                    if let Ok(val) = serde_json::from_str::<Value>(&text) {
                        let _ = tx.send(val);
                    }
                }
            }
        });

        WsClient {
            rx,
            _handle: handle,
        }
    }

    /// Wait up to `timeout` for an event matching `predicate`.
    /// Returns `Some(event)` if found, `None` on timeout.
    pub async fn wait_for_event<F>(
        &mut self,
        predicate: F,
        timeout: std::time::Duration,
    ) -> Option<Value>
    where
        F: Fn(&Value) -> bool,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match tokio::time::timeout(remaining, self.rx.recv()).await {
                Ok(Some(event)) if predicate(&event) => return Some(event),
                Ok(Some(_)) => continue, // not the event we want, keep waiting
                Ok(None) => return None, // channel closed
                Err(_) => return None,   // timeout
            }
        }
    }

    /// Drain all currently buffered events (non-blocking).
    pub fn drain(&mut self) -> Vec<Value> {
        let mut events = Vec::new();
        while let Ok(val) = self.rx.try_recv() {
            events.push(val);
        }
        events
    }
}
