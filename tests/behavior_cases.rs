//! Zero-dependency behavior-case runner for CI (ADR-006/ADR-009).
//!
//! Runs every recorded case in `tests/app-cases/` against this repo's binary
//! and compares stdout / stderr / exit code byte-for-byte. The cases were
//! recorded with rust-anything `app record` from the C original
//! (207 deterministic CLI cases: usage, validation errors, argument traps).
//! The only normalization, applied to both sides, is the argv[0] wildcard
//! `[..]` in the usage line (the original was recorded as
//! `usage: ./udp-broadcast-relay-redux …`).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Minimal TOML-subset reader for the recorded case files:
/// handles `args = ["…", …]` (basic escapes) and `status.code = N`.
fn parse_case(text: &str) -> (Vec<String>, Option<i32>) {
    let mut args = Vec::new();
    let mut code = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("args = [") {
            let rest = rest.strip_suffix(']').unwrap_or(rest);
            let mut cur = String::new();
            let mut in_str = false;
            let mut esc = false;
            for c in rest.chars() {
                if esc {
                    esc = false;
                    match c {
                        'n' => cur.push('\n'),
                        't' => cur.push('\t'),
                        'r' => cur.push('\r'),
                        '0' => cur.push('\0'),
                        other => cur.push(other),
                    }
                    continue;
                }
                match c {
                    '"' => {
                        in_str = !in_str;
                        if !in_str {
                            args.push(std::mem::take(&mut cur));
                        }
                    }
                    '\\' if in_str => esc = true,
                    ',' | ' ' | '\t' if !in_str => {}
                    c if in_str => cur.push(c),
                    _ => {}
                }
            }
        } else if let Some(rest) = line.strip_prefix("status.code = ") {
            code = rest.trim().parse::<i32>().ok();
        }
    }
    (args, code)
}

/// Replace `usage: <argv0>` with the recorded `[..]` wildcard.
/// Operates on bytes so multi-byte UTF-8 in echoed arguments can't split.
fn normalize(s: &str) -> String {
    let b = s.as_bytes();
    let needle = b"usage: ";
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i..].starts_with(needle) {
            // The recorder's normalizer replaced `usage: <argv0>` wholesale
            // with `[..]` (prefix included) — match that exactly.
            i += needle.len();
            while i < b.len() && !b[i].is_ascii_whitespace() {
                i += 1;
            }
            out.extend_from_slice(b"[..]");
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_dir_sorted(dir: &Path, ext: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some(ext) {
                let name = p
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                if let Ok(body) = fs::read_to_string(&p) {
                    m.insert(name, body);
                }
            }
        }
    }
    m
}

#[test]
fn recorded_behavior_cases_match_the_original() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/app-cases");
    let tomls = read_dir_sorted(&dir, "toml");
    let stdouts = read_dir_sorted(&dir, "stdout");
    let stderrs = read_dir_sorted(&dir, "stderr");
    assert!(
        tomls.len() >= 200,
        "expected the recorded case suite, found {}",
        tomls.len()
    );

    let bin = env!("CARGO_BIN_EXE_udp-broadcast-relay-redux");
    let mut failures = Vec::new();
    for (name, toml) in &tomls {
        let (args, want_code) = parse_case(toml);
        let mut child = Command::new(bin)
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn");
        // Guard against environment drift: a case that hangs means the
        // sandbox no longer matches the recording setup (e.g. dummy0 must
        // exist, be up, and have no IPv4 address).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let out = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut o = child.stdout.take().unwrap();
                    let mut e = child.stderr.take().unwrap();
                    use std::io::Read;
                    let mut ob = Vec::new();
                    let mut eb = Vec::new();
                    let _ = o.read_to_end(&mut ob);
                    let _ = e.read_to_end(&mut eb);
                    break (status, ob, eb);
                }
                Ok(None) => {
                    if std::time::Instant::now() > deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!(
                            "case {name} hung for 10s — recording environment drifted \
                               (dummy0 must exist, be UP, and have no IPv4 address)"
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => panic!("case {name}: {e}"),
            }
        };
        let (status, out_bytes, err_bytes) = out;
        let got_code = status.code();
        let got_out = normalize(&String::from_utf8_lossy(&out_bytes));
        let got_err = normalize(&String::from_utf8_lossy(&err_bytes));
        let want_out = stdouts.get(name).map(|s| normalize(s)).unwrap_or_default();
        let want_err = stderrs.get(name).map(|s| normalize(s)).unwrap_or_default();
        if got_code != want_code || got_out != want_out || got_err != want_err {
            let out_diff = if got_out == want_out {
                "none".to_string()
            } else {
                format!("{got_out:?} vs {want_out:?}")
            };
            let err_diff = if got_err == want_err {
                "none".to_string()
            } else {
                "above".to_string()
            };
            failures.push(format!(
                "case {name} (args={args:?})\n  exit: got {got_code:?}, want {want_code:?}\n  stdout diff: {out_diff}\n  stderr diff: {err_diff}\n  -- got stderr --\n{got_err}\n  -- want stderr --\n{want_err}",
            ));
        }
    }
    if !failures.is_empty() {
        panic!(
            "{} behavior case(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
    println!("{} behavior cases passed", tomls.len());
}
