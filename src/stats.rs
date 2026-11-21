//! Packet counters, dumped on SIGUSR1 (wave 2) — pure atomics, no locks in
//! the datapath.

use std::sync::atomic::AtomicU64;

#[derive(Default)]
pub struct Stats {
    pub received: AtomicU64,
    pub forwarded: AtomicU64,
    pub dropped_echo: AtomicU64,
    pub dropped_not_managed: AtomicU64,
    pub send_errors: AtomicU64,
}
