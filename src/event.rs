//! Netlink route-socket events (Linux) and the hot-plug decision logic.
//!
//! `parse` decodes RTM_NEWLINK/DELLINK/NEWADDR/DELADDR messages from the
//! kernel; `decide` is the pure, unit-tested policy: given the requested
//! `--dev` list and the current managed table, which actions to take.
//! The relay loop executes actions (probe + raw socket + multicast joins).

use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    LinkNew,
    LinkDel,
    AddrNew,
    AddrDel,
}

#[derive(Debug, Clone)]
pub struct NetEvent {
    pub kind: Kind,
    pub ifindex: i32,
    /// Interface name when present (link events carry IFLA_IFNAME).
    pub name: Option<String>,
    /// IFF_UP state when known (link events).
    pub up: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Probe + create the raw socket + join multicast groups.
    Add(String),
    /// Drop the interface from the managed set (socket closed, memberships
    /// released by the kernel).
    Remove(i32),
}

/// Snapshot of one managed interface used by the decision function.
#[derive(Debug, Clone)]
pub struct ManagedInfo {
    pub name: String,
}

const NLMSG_HDR: usize = 16;
const IFINFOMSG: usize = 16;
const IFADDRMSG: usize = 8;

/// Parse a netlink datagram into route events. Unknown message types are
/// skipped; truncated/malformed messages stop the scan (same as NLMSG_OK).
pub fn parse(buf: &[u8]) -> Vec<NetEvent> {
    let mut events = Vec::new();
    let mut off = 0usize;
    while off + NLMSG_HDR <= buf.len() {
        let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
        if len < NLMSG_HDR || off + len > buf.len() {
            break;
        }
        let mtype = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
        let body = &buf[off + NLMSG_HDR..off + len];
        match mtype {
            t if t == libc::RTM_NEWLINK => parse_link(body, Kind::LinkNew, &mut events),
            t if t == libc::RTM_DELLINK => parse_link(body, Kind::LinkDel, &mut events),
            t if t == libc::RTM_NEWADDR => parse_addr(body, Kind::AddrNew, &mut events),
            t if t == libc::RTM_DELADDR => parse_addr(body, Kind::AddrDel, &mut events),
            _ => {}
        }
        off += align4(len);
    }
    events
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn parse_link(body: &[u8], kind: Kind, events: &mut Vec<NetEvent>) {
    if body.len() < IFINFOMSG {
        return;
    }
    // struct ifinfomsg: family, pad, type, index, flags, change
    let ifindex = i32::from_ne_bytes([body[4], body[5], body[6], body[7]]);
    let flags = u32::from_ne_bytes([body[8], body[9], body[10], body[11]]);
    let mut name = None;
    let mut off = IFINFOMSG;
    while off + 4 <= body.len() {
        let rta_len = u16::from_ne_bytes([body[off], body[off + 1]]) as usize;
        let rta_type = u16::from_ne_bytes([body[off + 2], body[off + 3]]);
        if rta_len < 4 || off + rta_len > body.len() {
            break;
        }
        if rta_type == libc::IFLA_IFNAME {
            let bytes = &body[off + 4..off + rta_len];
            let end = bytes.iter().position(|c| *c == 0).unwrap_or(bytes.len());
            name = Some(String::from_utf8_lossy(&bytes[..end]).into_owned());
        }
        off += align4(rta_len);
    }
    events.push(NetEvent {
        kind,
        ifindex,
        name,
        up: Some((flags & libc::IFF_UP as u32) != 0),
    });
}

fn parse_addr(body: &[u8], kind: Kind, events: &mut Vec<NetEvent>) {
    if body.len() < IFADDRMSG {
        return;
    }
    // struct ifaddrmsg: family, prefixlen, flags, scope, index
    let family = body[0] as i32;
    let ifindex = u32::from_ne_bytes([body[4], body[5], body[6], body[7]]) as i32;
    if family != libc::AF_INET {
        return; // IPv6 addresses ride their own interface set in wave 5
    }
    let _ = family;
    events.push(NetEvent {
        kind,
        ifindex,
        name: None,
        up: None,
    });
}

/// The hot-plug policy. Pure function over the event stream.
pub fn decide(devs: &[String], managed: &BTreeMap<i32, ManagedInfo>, ev: &NetEvent) -> Vec<Action> {
    match ev.kind {
        Kind::LinkNew => match managed.get(&ev.ifindex) {
            Some(_) => {
                // A managed interface came (back) up — its address state is
                // carried by AddrNew; nothing to do on LinkNew.
                vec![]
            }
            None => {
                let matches = ev
                    .name
                    .as_deref()
                    .is_some_and(|n| devs.iter().any(|d| d == n));
                if matches && ev.up.unwrap_or(false) {
                    vec![Action::Add(ev.name.clone().unwrap_or_default())]
                } else {
                    vec![]
                }
            }
        },
        Kind::LinkDel => {
            if managed.contains_key(&ev.ifindex) {
                vec![Action::Remove(ev.ifindex)]
            } else {
                vec![]
            }
        }
        Kind::AddrNew | Kind::AddrDel => match managed.get(&ev.ifindex) {
            Some(info) => vec![Action::Remove(ev.ifindex), Action::Add(info.name.clone())],
            None => vec![],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> BTreeMap<i32, ManagedInfo> {
        let mut m = BTreeMap::new();
        m.insert(
            2,
            ManagedInfo {
                name: "dummy0".into(),
            },
        );
        m
    }

    #[test]
    fn link_new_unmanaged_matching_adds() {
        let ev = NetEvent {
            kind: Kind::LinkNew,
            ifindex: 9,
            name: Some("wlan0".into()),
            up: Some(true),
        };
        assert_eq!(
            decide(&["dummy0".into(), "wlan0".into()], &table(), &ev),
            vec![Action::Add("wlan0".into())]
        );
        // not requested
        assert!(decide(&["dummy0".into()], &table(), &ev).is_empty());
        // requested but down
        let ev_down = NetEvent {
            kind: Kind::LinkNew,
            ifindex: 9,
            name: Some("wlan0".into()),
            up: Some(false),
        };
        assert!(decide(&["wlan0".into()], &table(), &ev_down).is_empty());
    }

    #[test]
    fn link_new_managed_is_noop() {
        let ev = NetEvent {
            kind: Kind::LinkNew,
            ifindex: 2,
            name: Some("dummy0".into()),
            up: Some(true),
        };
        assert!(decide(&["dummy0".into()], &table(), &ev).is_empty());
    }

    #[test]
    fn link_del_managed_removes() {
        let ev = NetEvent {
            kind: Kind::LinkDel,
            ifindex: 2,
            name: Some("dummy0".into()),
            up: None,
        };
        assert_eq!(
            decide(&["dummy0".into()], &table(), &ev),
            vec![Action::Remove(2)]
        );
        let ev = NetEvent {
            kind: Kind::LinkDel,
            ifindex: 42,
            name: Some("x".into()),
            up: None,
        };
        assert!(decide(&["dummy0".into()], &table(), &ev).is_empty());
    }

    #[test]
    fn addr_change_on_managed_rebuilds() {
        let ev = NetEvent {
            kind: Kind::AddrNew,
            ifindex: 2,
            name: None,
            up: None,
        };
        assert_eq!(
            decide(&["dummy0".into()], &table(), &ev),
            vec![Action::Remove(2), Action::Add("dummy0".into())]
        );
        let ev = NetEvent {
            kind: Kind::AddrDel,
            ifindex: 2,
            name: None,
            up: None,
        };
        assert_eq!(
            decide(&["dummy0".into()], &table(), &ev),
            vec![Action::Remove(2), Action::Add("dummy0".into())]
        );
    }

    #[test]
    fn addr_change_on_unmanaged_ignored() {
        let ev = NetEvent {
            kind: Kind::AddrNew,
            ifindex: 77,
            name: None,
            up: None,
        };
        assert!(decide(&["dummy0".into()], &table(), &ev).is_empty());
    }
}
