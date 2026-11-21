# udp-broadcast-relay-redux-rust

[udp-broadcast-relay-redux](https://github.com/udp-redux/udp-broadcast-relay-redux) 的 Rust 移植版
—— 将 UDP 广播数据包转发到其他网络，并伪造发送者地址。

与 C 原版行为一致、命令行一致、线上报文格式一致——通过 207 个录制行为用例与双网卡抓包对比测试验证。
在此之上新增了国际化支持（中文与英文）。

> English documentation: [README.md](README.md)。

## 项目背景

原版是一个常用于 OpenWrt/pfSense/DD-WRT 等路由器的小型 C 守护进程，用于让 UDP 广播类协议
（如 Chromecast / HDHomeRun 发现协议）跨子网工作。本仓库使用 Rust 重新实现，运行时仅依赖
`libc`，在保留原版零依赖部署体验的同时，获得内存安全、现代 CI 与国际化能力。

## 用法

```
usage: udp-broadcast-relay-redux [-d] [-f] [-s IP] [-t IP] [--id id] [--port udp-port] [--dev dev1]... [--multicast ip]...
```

程序在指定的 UDP 端口上监听广播数据包，并转发到其他给定的接口。转发时伪造来源地址，使数据包
看起来仍来自最初的广播者；若使用 `-s` 则显示为伪造的 IP。在同一网络上对同一端口运行多个实例时，
必须为它们指定不同的 id。

| 参数 | 说明 |
|------|------|
| `-d` | 启用调试输出 |
| `-f` | 强制 fork 到后台运行 |
| `-s IP` | 设置转发数据包的源 IP；否则使用原始发送者地址。设为 `1.1.1.1` 使用出接口地址和广播端口；设为 `1.1.1.2` 使用出接口地址和原始源端口。 |
| `-t IP` | 设置转发数据包的目的 IP；否则使用原始目标地址。设为 `255.255.255.255` 使用出接口的广播地址。 |
| `--id id` | 实例 id（1–99），编码为 IP TTL `64+id`，用于识别中继回声 |
| `--port udp-port` | 监听的 UDP 端口 |
| `--dev dev1` | 托管的接口（可重复） |
| `--multicast ip` | 在所有托管接口上加入的组播组（可重复） |
| `--lang en\|zh` | 用户可见消息的语言（见[国际化](#国际化)） |
| `--log stderr\|syslog\|file=PATH` | 错误/日志通道（默认 stderr，与原版逐字节一致） |
| `--ipv6` | 同时中继 IPv6 组播组（同端口双栈） |
| `--list-interfaces` | 枚举候选接口后退出（无需 root） |
| `-h`/`--help`、`--version` | 双语帮助与版本号 |

需要 root 权限（raw socket）。HDHomeRun 示例：

```
udp-broadcast-relay-redux --id 1 --port 65001 --dev eth0 --dev wlan0 --multicast 239.255.255.250
```

## 1.1 版本新特性

- **可靠性修复**：重复的 `--dev`/组播 join 不再重复转发或因 `EADDRINUSE` 崩溃；
  无可用接口时快速报错退出，不再产生僵尸守护进程；SIGTERM/SIGINT 优雅退出。
- **接口热插拔（Linux）**：运行期间出现/消失/变址的 `--dev` 匹配接口由 netlink
  自动跟随加入或释放。
- **`--ipv6`**：同端口双栈中继 IPv6 组播（UDP 校验和本地计算，hop limit 64+id 识别回声）。
- **严格解析**：`--id`/`--port` 超出 1–99 / 1–65535 时给出明确报错，不再静默截断。
- **运维能力**：`--log syslog|file=`、SIGUSR1 包计数、双语 `--help`、man 页与 shell 补全。

## 国际化

用户可见消息（用法、错误、调试日志）提供英文与中文两种语言。语言按以下顺序决定：

1. `--lang en` / `--lang zh` 命令行参数（最高优先级），
2. 环境变量 `LC_ALL` → `LC_MESSAGES` → `LANG`（以 `zh` 开头的 locale 选择中文），
3. 默认英文。

英文输出与 C 原版逐字节一致。如何新增语言见 [docs/i18n.md](docs/i18n.md)。

## 安装

每个 GitHub Release 附带预编译二进制（linux x86_64/aarch64 gnu+musl、macOS aarch64）、
Debian 包、man 页与 shell 补全；也可从源码构建：

```
cargo build --release
```

- Debian：`dpkg -i udp-broadcast-relay-redux_<version>_amd64.deb`
- AUR：使用 `packaging/PKGBUILD`（发布步骤见文件头注释）
- Homebrew：用 `packaging/homebrew/udp-broadcast-relay-redux.rb` 建 tap
- crates.io：配置 `CARGO_REGISTRY_TOKEN` secret 后 release CI 会自动
  `cargo publish`，随后即可 `cargo install udp-broadcast-relay-redux`

Docker：

```
docker build -t udp-broadcast-relay-redux .
docker run --rm --net=host udp-broadcast-relay-redux --id 1 --port 65001 --dev eth0 --dev wlan0
```

## 行为保证

移植过程由 [rust-anything](https://github.com/erkamyaman/rust-anything) 驱动：

- **207 个录制 CLI 用例**（用法输出、参数校验、参数陷阱、ioctl 错误路径）从 C 原版捕获
  —— Rust 二进制 207/207 重放通过，stdout/stderr 与退出码逐字节一致。该套件在 CI 中运行
  （`tests/behavior_cases.rs`）。
- **真实中继一致性对比**：在双接口实验环境（`dummy0` + `dummy1`）中，用 AF_PACKET 抓取
  Rust 移植版与 C 原版发出的伪造报文，在广播、单播、组播、源地址伪造、目标地址改写等场景下
  逐字段（源/目的地址、端口、TTL、载荷）对比——完全一致。同样的电池已固化在
  `tests/relay_e2e.rs` 并在 CI 中运行（v4 全量，v6 在支持 IPv6 的 runner 上）。
- 忠实保留的原版怪癖包括：`Debugging Mode enabled` 永远不输出（原版 DPRINT 在设置 `debug`
  之前求值）、glibc 的 `atoi`/`inet_addr` 语义（含八进制/十六进制/溢出处理）、参数的
  u8/u16 截断、以"最后一个匹配接口"为准的查找、基于 TTL 的回声识别、perror 标签等。

细节、决策与实测探针数据见 [docs/PORTING.md](docs/PORTING.md)。

## 平台支持

- **Linux**（主要目标；CI 覆盖 gnu + musl、x86_64 + aarch64）
- **macOS**（Apple 分支：`if_nametoindex`、`IP_RECVIF` 系列套接字选项；CI 编译检查，未做运行时测试）
- FreeBSD：原版有 FreeBSD 分支；本移植对其编译 Apple 路径（缺失的 ioctl 常量按文档化的
  `_IOWR` 编码补齐），但未纳入 CI 测试——见 docs/PORTING.md。

## 许可证

GPL-2.0-or-later，与原版一致。Copyright (c) 2017 UDP Broadcast Relay Redux Contributors；
(c) 2003 Joachim Breitner；(C) 2002 Nathan O'Sullivan——见 [LICENSE](LICENSE)。
