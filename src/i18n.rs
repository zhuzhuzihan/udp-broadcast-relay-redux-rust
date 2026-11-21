//! i18n: embedded en/zh catalogs (ADR-005).
//!
//! English strings are byte-identical to the C original (behavior parity);
//! Chinese is a translated superset. Resolution: `--lang en|zh` flag first,
//! then LC_ALL → LC_MESSAGES → LANG (a value starting with "zh" selects
//! Chinese, everything else English). See docs/i18n.md to add a language.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    En,
    Zh,
}

impl Lang {
    fn parse(v: &str) -> Option<Lang> {
        match v {
            "en" => Some(Lang::En),
            "zh" => Some(Lang::Zh),
            _ => None,
        }
    }

    /// Locale string (LC_ALL / LC_MESSAGES / LANG) → language: a value whose
    /// first two ASCII characters are "zh" selects Chinese.
    fn from_locale(v: &str) -> Lang {
        if v.as_bytes().get(0..2) == Some(b"zh") {
            Lang::Zh
        } else {
            Lang::En
        }
    }
}

/// The whole human-facing message catalog.
pub struct I18n {
    pub lang: Lang,
}

/// Result of the `--lang` pre-scan: the resolved language plus the argument
/// list with the `--lang`/value pair removed (the faithful parser never sees
/// it, so original flags keep their exact semantics).
pub struct LangScan {
    pub lang: Lang,
    /// argv[0] (program name), used for the usage line.
    pub program: String,
    /// Arguments with the lang pair removed.
    pub args: Vec<String>,
}

/// Pre-scan argv for `--lang`, resolve the language, and strip the pair.
/// An invalid `--lang` value is a fatal error (exit 1), independent of
/// position, mirroring how the tool would reject an unknown flag.
pub fn scan_lang(argv: &[String]) -> Result<LangScan, String> {
    let program = argv
        .first()
        .cloned()
        .unwrap_or_else(|| "udp-broadcast-relay-redux".to_string());
    let args: Vec<String> = argv.iter().skip(1).cloned().collect();

    let mut flag_lang: Option<Lang> = None;
    let mut remove_at: Option<usize> = None;
    let mut invalid: Option<String> = None;
    for (i, a) in args.iter().enumerate() {
        if a == "--lang" {
            let v = args.get(i + 1);
            match v.and_then(|v| Lang::parse(v)) {
                Some(l) => {
                    flag_lang = Some(l);
                    remove_at = Some(i);
                }
                None => {
                    invalid = Some(v.cloned().unwrap_or_default());
                }
            }
            break;
        }
    }
    if let Some(v) = invalid {
        let t = I18n { lang: Lang::En };
        return Err(t.invalid_lang(&v));
    }
    if let Some(i) = remove_at {
        let mut args = args;
        args.remove(i); // the value
        args.remove(i); // the flag itself
        return Ok(LangScan {
            lang: flag_lang.unwrap_or(Lang::En),
            program,
            args,
        });
    }

    let lang = flag_lang.unwrap_or_else(|| {
        for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Ok(v) = std::env::var(key) {
                if !v.is_empty() {
                    return Lang::from_locale(&v);
                }
            }
        }
        Lang::En
    });
    Ok(LangScan {
        lang,
        program,
        args,
    })
}

/// English usage body, byte-identical to the C original (including its
/// double spaces and the trailing blank line).
const USAGE_EN_BODY: &str = concat!(
    "This program listens for broadcast  packets  on the  specified UDP port\n",
    "and then forwards them to each other given interface.  Packets are sent\n",
    "such that they appear to have come from the original broadcaster, resp.\n",
    "from the spoofing IP in case -s is used.  When using multiple instances\n",
    "for the same port on the same network, they must have a different id.\n",
    "\n",
    "    -d      enables debugging\n",
    "    -f      forces forking to background\n",
    "    -s IP   sets the source IP of forwarded packets; otherwise the\n",
    "            original sender's address is used.\n",
    "            Setting to 1.1.1.1 uses outgoing interface address and broadcast port.\n",
    "            (helps in some rare cases)\n",
    "            Setting to 1.1.1.2 uses outgoing interface address and source port.\n",
    "            (helps in some rare cases)\n",
    "    -t      sets the destination IP of forwarded packets; otherwise the\n",
    "            original target is used.\n",
    "            Setting to 255.255.255.255 uses the broadcast address of the\n",
    "            outgoing interface.\n",
    "\n",
);

/// Chinese usage body (translated superset, same structure).
const USAGE_ZH_BODY: &str = concat!(
    "本程序在指定的 UDP 端口上监听广播数据包，并转发到其他给定的接口。\n",
    "转发时伪造来源地址，使数据包看起来仍来自最初的广播者；\n",
    "若使用 -s 则显示为伪造的 IP。在同一网络上对同一端口运行多个\n",
    "实例时，必须为它们指定不同的 id。\n",
    "\n",
    "    -d      启用调试输出\n",
    "    -f      强制 fork 到后台运行\n",
    "    -s IP   设置转发数据包的源 IP；否则使用原始发送者的地址。\n",
    "            设为 1.1.1.1 时使用出接口地址和广播端口。\n",
    "            （某些特殊场景下有帮助）\n",
    "            设为 1.1.1.2 时使用出接口地址和原始源端口。\n",
    "            （某些特殊场景下有帮助）\n",
    "    -t      设置转发数据包的目的 IP；否则使用原始目标地址。\n",
    "            设为 255.255.255.255 时使用出接口的广播地址。\n",
    "\n",
);

/// `a.b.c.d` from the numeric (host-assembled) form `a<<24 | b<<16 | c<<8 | d`.
pub fn ipv4_str(v: u32) -> String {
    let b = v.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

impl I18n {
    pub fn new(lang: Lang) -> Self {
        Self { lang }
    }

    /// `-h/--help` output: the original usage text plus the new-flag section
    /// (the bare usage stays byte-identical to the original, so only help
    /// documents the additions).
    pub fn extended_usage(&self, program: &str) -> String {
        let base = self.usage(program);
        match self.lang {
            Lang::En => format!(
                "{base}\nNew options:\n    -h, --help            show this help and exit\n    --version             show version and exit\n    --lang en|zh          user-facing message language (default: locale)\n    --list-interfaces     enumerate interfaces and exit (no root needed)\n    --log TARGET          error/log channel: stderr, syslog, file=PATH (default: stderr)\n\n"
            ),
            Lang::Zh => format!(
                "{base}\n新增选项:\n    -h, --help            显示本帮助并退出\n    --version             显示版本号并退出\n    --lang en|zh          用户可见消息的语言（默认：跟随 locale）\n    --list-interfaces     枚举接口后退出（无需 root）\n    --log TARGET          错误/日志通道：stderr、syslog、file=PATH（默认 stderr）\n\n"
            ),
        }
    }

    pub fn invalid_log(&self, v: &str) -> String {
        match self.lang {
            Lang::En => format!("invalid log target: {v} (expected: stderr, syslog, file=PATH)\n"),
            Lang::Zh => format!("无效的日志目标：{v}（可选：stderr、syslog、file=PATH）\n"),
        }
    }

    pub fn list_header(&self) -> String {
        match self.lang {
            Lang::En => {
                "name         idx  address        broadcast       state      selected\n".to_string()
            }
            Lang::Zh => {
                "名称         序号  地址           广播/对端        状态       已选\n".to_string()
            }
        }
    }

    /// Data-heavy table rows keep their format in every language.
    pub fn list_row(
        &self,
        name: &str,
        idx: i32,
        addr: &str,
        dst: &str,
        state: &str,
        selected: &str,
    ) -> String {
        format!("{name:<12} {idx:<4} {addr:<14} {dst:<15} {state:<10} {selected}\n")
    }

    pub fn stats_dump(
        &self,
        received: u64,
        forwarded: u64,
        dropped_echo: u64,
        dropped_nm: u64,
        send_errors: u64,
    ) -> String {
        match self.lang {
            Lang::En => format!(
                "stats: received={received} forwarded={forwarded} dropped_echo={dropped_echo} dropped_not_managed={dropped_nm} send_errors={send_errors}\n"
            ),
            Lang::Zh => format!(
                "统计：收到={received} 转发={forwarded} 回声丢弃={dropped_echo} 非托管丢弃={dropped_nm} 发送失败={send_errors}\n"
            ),
        }
    }

    pub fn stats_iface(&self, name: &str, sent: u64) -> String {
        match self.lang {
            Lang::En => format!("stats: iface {name} sent={sent}\n"),
            Lang::Zh => format!("统计：接口 {name} 已发送={sent}\n"),
        }
    }

    pub fn invalid_lang(&self, v: &str) -> String {
        match self.lang {
            Lang::En => format!("invalid language: {v} (expected: en, zh)\n"),
            Lang::Zh => format!("无效的语言：{v}（可选：en、zh）\n"),
        }
    }

    pub fn usage(&self, program: &str) -> String {
        // concat! keeps the original's exact spacing (a trailing backslash in a
        // string literal would swallow the next line's leading whitespace).
        match self.lang {
            Lang::En => format!("usage: {program} [-d] [-f] [-s IP] [-t IP] [--id id] [--port udp-port] [--dev dev1]... [--multicast ip]...\n\n{}", USAGE_EN_BODY),
            Lang::Zh => format!("用法: {program} [-d] [-f] [-s IP] [-t IP] [--id id] [--port udp-port] [--dev dev1]... [--multicast ip]...\n\n{}", USAGE_ZH_BODY),
        }
    }

    pub fn invalid_source_ip(&self, v: &str) -> String {
        match self.lang {
            Lang::En => format!("invalid source IP address: {v}\n"),
            Lang::Zh => format!("无效的源 IP 地址：{v}\n"),
        }
    }

    pub fn invalid_target_ip(&self, v: &str) -> String {
        match self.lang {
            Lang::En => format!("invalid target IP address: {v}\n"),
            Lang::Zh => format!("无效的目标 IP 地址：{v}\n"),
        }
    }

    pub fn unknown_arg(&self, v: &str) -> String {
        match self.lang {
            Lang::En => format!("Unknown arg: {v}\n"),
            Lang::Zh => format!("未知参数：{v}\n"),
        }
    }

    pub fn id_not_between(&self, id: u32) -> String {
        match self.lang {
            Lang::En => format!("ID argument {id} not between 1 and 99\n"),
            Lang::Zh => format!("ID 参数 {id} 不在 1 到 99 之间\n"),
        }
    }

    pub fn port_not_valid(&self) -> String {
        match self.lang {
            Lang::En => "Port argument not valid\n".to_string(),
            Lang::Zh => "端口参数无效\n".to_string(),
        }
    }

    pub fn must_be_root(&self) -> String {
        match self.lang {
            Lang::En => "You must be root to create a raw socket\n".to_string(),
            Lang::Zh => "必须以 root 权限运行才能创建 raw socket\n".to_string(),
        }
    }

    pub fn rcv_bind(&self) -> String {
        match self.lang {
            Lang::En => "rcv bind\n".to_string(),
            Lang::Zh => "接收端口 bind 失败\n".to_string(),
        }
    }

    pub fn invalid_id(&self, v: &str) -> String {
        match self.lang {
            Lang::En => format!("invalid id: {v} (expected 1-99)\n"),
            Lang::Zh => format!("无效的 id：{v}（应为 1-99）\n"),
        }
    }

    pub fn invalid_port(&self, v: &str) -> String {
        match self.lang {
            Lang::En => format!("invalid port: {v} (expected 1-65535)\n"),
            Lang::Zh => format!("无效的端口：{v}（应为 1-65535）\n"),
        }
    }

    pub fn no_interfaces(&self) -> String {
        match self.lang {
            Lang::En => "no usable interfaces found\n".to_string(),
            Lang::Zh => "未发现可用的网络接口\n".to_string(),
        }
    }

    pub fn dup_dev(&self, v: &str) -> String {
        match self.lang {
            Lang::En => format!("duplicate --dev ignored: {v}\n"),
            Lang::Zh => format!("忽略重复的 --dev：{v}\n"),
        }
    }

    pub fn dup_iface(&self, v: &str, idx: i32) -> String {
        match self.lang {
            Lang::En => format!("duplicate interface index ignored: {v} (ifindex {idx})\n"),
            Lang::Zh => format!("忽略重复的接口序号：{v}（ifindex {idx}）\n"),
        }
    }

    pub fn dup_membership(&self, group: &str, ifaddr: &str) -> String {
        match self.lang {
            Lang::En => format!("duplicate multicast membership ignored: {group} on {ifaddr}\n"),
            Lang::Zh => format!("忽略重复的组播成员：{group} @ {ifaddr}\n"),
        }
    }

    pub fn iface_added(&self, name: &str) -> String {
        match self.lang {
            Lang::En => format!("interface added: {name}\n"),
            Lang::Zh => format!("接口已加入：{name}\n"),
        }
    }

    pub fn iface_removed(&self, name: &str) -> String {
        match self.lang {
            Lang::En => format!("interface removed: {name}\n"),
            Lang::Zh => format!("接口已移除：{name}\n"),
        }
    }

    pub fn shutdown(&self) -> String {
        match self.lang {
            Lang::En => "shutting down\n".to_string(),
            Lang::Zh => "正在退出\n".to_string(),
        }
    }

    pub fn debug_forking(&self) -> String {
        match self.lang {
            Lang::En => "Forking Mode enabled\n".to_string(),
            Lang::Zh => "后台 fork 模式已启用\n".to_string(),
        }
    }

    pub fn debug_source_ip(&self, v: &str) -> String {
        match self.lang {
            Lang::En => format!("Outgoing source IP set to {v}\n"),
            Lang::Zh => format!("出站源 IP 已设置为 {v}\n"),
        }
    }

    pub fn debug_target_ip(&self, v: &str) -> String {
        match self.lang {
            Lang::En => format!("Outgoing target IP set to {v}\n"),
            Lang::Zh => format!("出站目标 IP 已设置为 {v}\n"),
        }
    }

    pub fn debug_id_set(&self, id: u32) -> String {
        match self.lang {
            Lang::En => format!("ID set to {id}\n"),
            Lang::Zh => format!("ID 已设置为 {id}\n"),
        }
    }

    pub fn debug_port_set(&self, p: u32) -> String {
        match self.lang {
            Lang::En => format!("Port set to {p}\n"),
            Lang::Zh => format!("端口已设置为 {p}\n"),
        }
    }

    pub fn debug_id_ttl_port(&self, id: u32, ttl: u32, p: u32) -> String {
        match self.lang {
            Lang::En => format!("ID: {id} (ttl: {ttl}), Port {p}\n"),
            Lang::Zh => format!("ID：{id}（ttl：{ttl}），端口 {p}\n"),
        }
    }

    /// Data-heavy log lines keep their original format in every language.
    pub fn debug_iface(&self, name: &str, ifindex: i32, ifaddr: &str, dstaddr: &str) -> String {
        format!("{name}: {ifindex} / {ifaddr} / {dstaddr}\n")
    }

    pub fn debug_found(&self, n: usize) -> String {
        match self.lang {
            Lang::En => format!("found {n} interfaces total\n"),
            Lang::Zh => format!("共找到 {n} 个接口\n"),
        }
    }

    pub fn debug_add_membership(&self, ifaddr: &str, mcast: &str) -> String {
        format!("IP_ADD_MEMBERSHIP:\t\t{ifaddr} {mcast}\n")
    }

    pub fn debug_done(&self) -> String {
        match self.lang {
            Lang::En => "Done Initializing\n\n".to_string(),
            Lang::Zh => "初始化完成\n\n".to_string(),
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the original's printf argument list"
    )]
    pub fn debug_recv(
        &self,
        fa: &str,
        fp: u32,
        ta: &str,
        tp: u32,
        iface: i32,
        len: usize,
        ttl: i32,
    ) -> String {
        format!("<- [ {fa}:{fp} -> {ta}:{tp} (iface={iface} len={len} ttl={ttl})\n")
    }

    pub fn debug_send(&self, fa: &str, fp: u32, ta: &str, tp: u32, iface: i32) -> String {
        format!("-> [ {fa}:{fp} -> {ta}:{tp} (iface={iface})\n")
    }

    pub fn debug_echo(&self) -> String {
        match self.lang {
            Lang::En => "Echo (Ignored)\n\n".to_string(),
            Lang::Zh => "回声包（已忽略）\n\n".to_string(),
        }
    }

    pub fn debug_not_managed(&self) -> String {
        match self.lang {
            Lang::En => "Not from managed iface\n\n".to_string(),
            Lang::Zh => "来源非托管接口\n\n".to_string(),
        }
    }

    /// perror prefixes. The original embeds a trailing `\n` inside the prefix,
    /// so the printed error spans two lines; that quirk is preserved verbatim.
    pub fn perr_source_ip_missing(&self) -> &'static str {
        match self.lang {
            Lang::En => "Source IP not found on incoming packet\n",
            Lang::Zh => "未在入站数据包中找到源 IP\n",
        }
    }

    pub fn perr_iface_missing(&self) -> &'static str {
        match self.lang {
            Lang::En => "Interface not found on incoming packet\n",
            Lang::Zh => "未在入站数据包中找到接口\n",
        }
    }

    pub fn perr_ttl_missing(&self) -> &'static str {
        match self.lang {
            Lang::En => "TTL not found on incoming packet\n",
            Lang::Zh => "未在入站数据包中找到 TTL\n",
        }
    }
}
