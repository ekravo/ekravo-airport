use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use airport_protocol::ConnectionKind;
use dashmap::DashMap;
use tokio::sync::{mpsc, Notify};

use crate::util::now_secs;

/// A live WebSocket connection.
pub struct ConnHandle {
    pub connection_id: String,
    pub kind: ConnectionKind,
    pub user_id: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    /// Long-term X25519 public key advertised by this peer, used by the other
    /// side to encrypt replies.
    public_key: Mutex<Option<String>>,
    /// Bounded outbound queue. `try_send` is used so a slow peer cannot make the
    /// server buffer without limit.
    pub tx: mpsc::Sender<String>,
    /// Wakes the connection loop so it can close promptly (revocation,
    /// replacement, shutdown).
    pub shutdown: Arc<Notify>,
    pub opened_at: i64,
    last_seen: AtomicI64,
}

impl ConnHandle {
    pub fn new(
        connection_id: String,
        kind: ConnectionKind,
        user_id: String,
        device_id: Option<String>,
        device_name: Option<String>,
        tx: mpsc::Sender<String>,
    ) -> Self {
        let now = now_secs();
        Self {
            connection_id,
            kind,
            user_id,
            device_id,
            device_name,
            public_key: Mutex::new(None),
            tx,
            shutdown: Arc::new(Notify::new()),
            opened_at: now,
            last_seen: AtomicI64::new(now),
        }
    }

    pub fn touch(&self) {
        self.last_seen.store(now_secs(), Ordering::Relaxed);
    }

    pub fn last_seen(&self) -> i64 {
        self.last_seen.load(Ordering::Relaxed)
    }

    pub fn set_public_key(&self, key: Option<String>) {
        let mut guard = self
            .public_key
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = key;
    }

    pub fn public_key(&self) -> Option<String> {
        self.public_key
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// All live connections, plus an index from device id to its active socket.
pub struct Registry {
    connections: DashMap<String, Arc<ConnHandle>>,
    devices: DashMap<String, Arc<ConnHandle>>,
    /// Reserved connection slots per account. Reserving before the socket is
    /// registered closes the race where many tickets are minted at once and
    /// every one of them connects.
    slots: DashMap<String, AtomicUsize>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            devices: DashMap::new(),
            slots: DashMap::new(),
        }
    }

    /// Reserve one connection slot for `user_id`, or return `None` when the
    /// account is at `limit`. The returned guard releases the slot on drop, so
    /// every early return is covered.
    pub fn try_reserve_user(self: &Arc<Self>, user_id: &str, limit: usize) -> Option<UserSlot> {
        let entry = self
            .slots
            .entry(user_id.to_string())
            .or_insert_with(|| AtomicUsize::new(0));
        let after = entry.value().fetch_add(1, Ordering::AcqRel) + 1;
        if after > limit {
            entry.value().fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(UserSlot {
            registry: Arc::clone(self),
            user_id: user_id.to_string(),
        })
    }

    fn release_user_slot(&self, user_id: &str) {
        if let Some(entry) = self.slots.get(user_id) {
            // Use a compare-exchange loop rather than `fetch_update`: the latter
            // is deprecated on newer Rust releases (renamed to `try_update`),
            // while `try_update` is not available on the 1.89 MSRV.
            let count = entry.value();
            let mut current = count.load(Ordering::Acquire);
            while current > 0 {
                match count.compare_exchange_weak(
                    current,
                    current - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(observed) => current = observed,
                }
            }
        }
        self.slots
            .remove_if(user_id, |_, count| count.load(Ordering::Acquire) == 0);
    }

    /// Insert a connection. Returns the previous socket for the same device, if
    /// any: one device may have only one active session.
    pub fn register(&self, handle: Arc<ConnHandle>) -> Option<Arc<ConnHandle>> {
        self.connections
            .insert(handle.connection_id.clone(), handle.clone());
        match &handle.device_id {
            Some(device_id) => self.devices.insert(device_id.clone(), handle.clone()),
            None => None,
        }
    }

    pub fn unregister(&self, connection_id: &str) {
        let Some((_, handle)) = self.connections.remove(connection_id) else {
            return;
        };
        if let Some(device_id) = &handle.device_id {
            // Only remove the device index if it still points at this socket.
            self.devices.remove_if(device_id, |_, current| {
                current.connection_id == handle.connection_id
            });
        }
    }

    pub fn get(&self, connection_id: &str) -> Option<Arc<ConnHandle>> {
        self.connections
            .get(connection_id)
            .map(|entry| entry.clone())
    }

    pub fn device(&self, device_id: &str) -> Option<Arc<ConnHandle>> {
        self.devices.get(device_id).map(|entry| entry.clone())
    }

    pub fn is_device_online(&self, device_id: &str) -> bool {
        self.devices.contains_key(device_id)
    }

    /// Best-effort delivery to one connection. `false` means the queue is full
    /// or the connection is gone; the caller decides whether that is an error
    /// or a queued state.
    pub fn send(&self, connection_id: &str, frame: &str) -> bool {
        match self.connections.get(connection_id) {
            Some(handle) => handle.tx.try_send(frame.to_string()).is_ok(),
            None => false,
        }
    }

    pub fn send_device(&self, device_id: &str, frame: &str) -> bool {
        match self.devices.get(device_id) {
            Some(handle) => handle.tx.try_send(frame.to_string()).is_ok(),
            None => false,
        }
    }

    /// Fan out to every client connection of a user, optionally skipping one.
    pub fn broadcast_clients(&self, user_id: &str, frame: &str, except: Option<&str>) -> usize {
        let mut delivered = 0;
        for entry in self.connections.iter() {
            let handle = entry.value();
            if handle.user_id != user_id || handle.kind != ConnectionKind::Client {
                continue;
            }
            if except == Some(handle.connection_id.as_str()) {
                continue;
            }
            if handle.tx.try_send(frame.to_string()).is_ok() {
                delivered += 1;
            }
        }
        delivered
    }

    pub fn count_user_connections(&self, user_id: &str) -> usize {
        self.connections
            .iter()
            .filter(|entry| entry.value().user_id == user_id)
            .count()
    }

    /// Snapshot of online device ids for one user. Used by the device list.
    pub fn online_devices(&self, user_id: &str) -> Vec<String> {
        self.devices
            .iter()
            .filter(|entry| entry.value().user_id == user_id)
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

/// Releases an account's connection slot when the socket task ends.
pub struct UserSlot {
    registry: Arc<Registry>,
    user_id: String,
}

impl Drop for UserSlot {
    fn drop(&mut self) {
        self.registry.release_user_slot(&self.user_id);
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(id: &str, device: Option<&str>) -> (Arc<ConnHandle>, mpsc::Receiver<String>) {
        let (tx, rx) = mpsc::channel(4);
        (
            Arc::new(ConnHandle::new(
                id.into(),
                if device.is_some() {
                    ConnectionKind::Device
                } else {
                    ConnectionKind::Client
                },
                "usr_1".into(),
                device.map(str::to_string),
                None,
                tx,
            )),
            rx,
        )
    }

    #[tokio::test]
    async fn replacing_a_device_returns_the_old_socket() {
        let registry = Registry::new();
        let (first, _first_rx) = handle("conn_1", Some("dev_1"));
        let (second, _second_rx) = handle("conn_2", Some("dev_1"));
        assert!(registry.register(first).is_none());
        let replaced = registry.register(second).expect("old socket");
        assert_eq!(replaced.connection_id, "conn_1");
        assert_eq!(registry.device("dev_1").unwrap().connection_id, "conn_2");
    }

    #[tokio::test]
    async fn unregister_keeps_the_newer_device_index() {
        let registry = Registry::new();
        let (first, _first_rx) = handle("conn_1", Some("dev_1"));
        let (second, _second_rx) = handle("conn_2", Some("dev_1"));
        registry.register(first);
        registry.register(second);
        registry.unregister("conn_1");
        assert_eq!(registry.device("dev_1").unwrap().connection_id, "conn_2");
    }

    #[tokio::test]
    async fn connection_slots_are_bounded_and_released() {
        let registry = Arc::new(Registry::new());
        let first = registry.try_reserve_user("usr_1", 1).expect("first slot");
        assert!(registry.try_reserve_user("usr_1", 1).is_none());
        drop(first);
        assert!(registry.try_reserve_user("usr_1", 1).is_some());
        assert!(registry.try_reserve_user("usr_2", 1).is_some());
    }

    #[tokio::test]
    async fn broadcast_skips_the_sender() {
        let registry = Registry::new();
        let (a, mut a_rx) = handle("conn_a", None);
        let (b, _b_rx) = handle("conn_b", None);
        registry.register(a);
        registry.register(b);
        assert_eq!(registry.broadcast_clients("usr_1", "{}", Some("conn_a")), 1);
        assert!(a_rx.try_recv().is_err());
    }
}
