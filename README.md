# VPN Connect

A lightweight, open-source macOS client for FortiGate SSL-VPN and Check Point VPN, with a GUI and a CLI.

![VPN Connect](docs/screenshots/vpnconnect.png)

## Why?

If you've ever used the official FortiClient on macOS, you know the pain: bloated, buggy, and unreliable. Constant crashes, broken updates, and features you never asked for getting in the way of the one thing you need — a VPN connection.

I got tired of depending on it. So I built **VPN Connect** — a minimal, native macOS client with its own Fortinet and Check Point engines, written in Rust. No telemetry, no bloat, no surprises. Just a clean interface to manage your VPN profiles and connect.

The UI is inspired by [OpenVPN Connect](https://openvpn.net/client/) — simple, focused, and easy to use. Built with native macOS vibrancy for a modern frosted glass look that blends with your desktop.

## Features

- **Two engines** — Fortinet SSL VPN and Check Point (SSL tunnel); each Profile picks its engine when it is created
- **Multiple VPN profiles** — save and switch between different VPN connections
- **SAML authentication** — full support for SSO/SAML login flows (Fortinet), and the identity provider login in the browser (Check Point)
- **Password auth** — Fortinet only; credentials stored securely in the macOS Keychain
- **Certificate trust management** — pin server certificates by SHA256 digest
- **Native macOS look** — vibrancy blur, overlay title bar, system tray integration
- **System tray** — connect/disconnect and switch profiles without opening the app
- **Real-time logs** — monitor connection logs and bandwidth
- **CLI** — the `vpnconnect` command covers what the window does (connect, status, Profiles, settings), with `--json` output
- **Dead tunnel and expiry handling** — the network is restored as soon as the tunnel drops or the session expires, with a notification
- **Lightweight** — small binary, minimal resource usage

## Installation

### Homebrew (recommended)

```bash
brew tap walcew/tap
brew install --cask vpnconnect
```

### Manual

Download the `.dmg` for your architecture from [Releases](https://github.com/walcew/vpnconnect/releases):

- **Apple Silicon (M1/M2/M3/M4):** `VPN.Connect_x.x.x_aarch64.dmg`
- **Intel:** `VPN.Connect_x.x.x_x64.dmg`

### First run and upgrades

On first run, the app installs its privileged Helper with a single admin password prompt. The Helper owns the VPN session: it logs in to the gateway, opens the tunnel and applies routes and DNS. There is nothing else to install.

Upgrading from 0.3.x or earlier? Reinstall the Helper once, when the app asks for it: the installer also removes the previous Helper. Extra openfortivpn options saved in a profile (`extra_args`) no longer apply; the app logs a warning when you connect such a profile.

## Check Point

The Check Point engine speaks the SSL tunnel of the gateway and signs in through the identity provider (IdP), in the browser. It covers:

- SSL tunnel with the IdP login in the browser
- Split routes from the gateway network ranges
- Split DNS, keepalive, session expiry (with a warning before it) and network change handling
- A Profile with a fixed engine, and `vpnconnect profile add --engine checkpoint` on the CLI

Not supported: IPsec/IKEv2, password, certificate and OTP login, the Mobile Access portal, posture checks and full tunnel.

If the internal names live outside the DNS suffixes the gateway announces, set the Profile DNS domains (`--dns-domain` on the CLI): that list replaces the gateway's.

The protocol the engines speak is documented in [docs/fortinet-protocol.md](docs/fortinet-protocol.md) and [docs/checkpoint-protocol.md](docs/checkpoint-protocol.md).

## Prerequisites

- macOS 12 (Monterey) or later

## Building from Source

### Requirements

- [Rust](https://rustup.rs/) (1.77.2+; CI uses 1.99)
- [Node.js](https://nodejs.org/) (18+)
- [Tauri CLI](https://tauri.app/)
- Xcode Command Line Tools (`xcode-select --install`)

### Build

```bash
npm install
cargo tauri build
```

The built `.app` will be in `src-tauri/target/release/bundle/macos/`.

### Development

```bash
cargo tauri dev
```

## Tech Stack

- **Backend:** [Tauri v2](https://tauri.app/) + Rust
- **Frontend:** React 19 + TypeScript + Tailwind CSS v4
- **VPN engines:** Fortinet SSL VPN client in Rust (rustls, utun, PPP) and Check Point SSL tunnel client in Rust (rustls, utun), both running in the privileged Helper
- **Security:** macOS Keychain for credential storage
- **DNS:** Native macOS `scutil` integration

## Credits

- [OpenVPN Connect](https://openvpn.net/client/) — UI inspiration for the clean, profile-based interface
- [Tauri](https://tauri.app/) — the framework powering this native desktop app

## Disclaimer

This project is **not affiliated with, endorsed by, or associated with Fortinet, FortiClient, FortiGate, FortiVPN, or Check Point Software Technologies** in any way. These are registered trademarks of their owners. This is an independent, open-source project.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

**Wallacy Santos Ferreira** — [@walcew](https://github.com/walcew)
