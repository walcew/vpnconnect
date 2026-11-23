---
name: vpnconnect
description: "Operate the VPN Connect VPN (FortiGate SSL VPN and Check Point on macOS) with the vpnconnect CLI: connect and disconnect a VPN, read the VPN status, follow the session live, manage Profiles (add, edit, remove, saved password, trusted certificates), change the app settings and check or install the Helper. Use when the user asks to connect or disconnect the VPN, whether the VPN is up, why the internal network, a cluster or an internal host is unreachable, or to create or change a VPN Profile."
---

# vpnconnect

`vpnconnect` is the command line of VPN Connect. It is the app's own executable, so the app window and the CLI are equal clients of the same VPN session, which lives in the Helper (a root daemon). A session started by one shows in the other, and it stays up after the command returns or the terminal closes.

This skill ships inside the binary. `vpnconnect skill install` installs or refreshes it for every agent on this Mac; run it again after the app updates.

## Learn the current CLI

The installed binary is the authority for syntax and flags. Read the help of the command you are about to run:

```bash
vpnconnect --help
vpnconnect connect --help
vpnconnect profile add --help
```

Help and version exit with 0. The long descriptions say how flags combine and what `--json` prints. This skill adds only what the help cannot say: who does what, the order, and the rules.

## Console user only

The Helper answers only root and the user logged in at the Mac's console. Over SSH, or from any other session, every command that talks to the Helper fails with `HELPER_UNAUTHORIZED` (exit 255). Report it and stop; retrying cannot help. Profile, settings and `skill` commands do not need the Helper.

## What is human

Ask the human, then wait. Never guess or work around these:

- SAML login, and every Check Point login: the human signs in on the gateway or identity provider page in the browser.
- OTP: the human reads the code from their authenticator; codes are single-use and short-lived.
- FortiToken push: the human approves on the phone.
- Trusting a certificate (`profile trust`, `--auto-trust`): the human decides after checking the digest.
- The administrator password of the Helper install: typed by the human in the macOS dialog.
- The Profile's password: it comes from the human or from a secret store you are allowed to read.
- Full tunnel or not: which networks go through the VPN (`--route`, `--clear-routes`). It decides what the organization behind the VPN can see, and its policy may require full tunnel.

## Connect

```bash
vpnconnect connect <profile> --json
vpnconnect connect <profile> --otp <code> --json
vpnconnect connect <profile> --no-browser --timeout 300
```

`<profile>` is an id or an exact name (see Profiles). `connect` blocks until the session is up (exit 0, prints the status) or has failed (exit 1 or 255 with an error code). The default `--timeout` is 120 s; at the limit it cancels the pending login and exits `TIMEOUT`.

1. Run `vpnconnect status --json` first. A session already active, whoever started it, is not yours to replace: `connect` refuses with `SESSION_ACTIVE`. If it is the Profile you need, use it; otherwise tell the human.
2. A password Profile needs `has_password: true` (`profile show`). The CLI reads the password from the Keychain without a prompt. Without it, `CREDENTIALS_MISSING`: ask the human for the password and save it (see Profiles).
3. An OTP Profile (`otp_required: true`) needs `--otp <code>`. Ask the human for a fresh code just before you run the command. Without it, `OTP_REQUIRED`. A Check Point Profile takes no OTP: `--otp` on it is refused with `INVALID_ARGUMENT`.
4. A SAML or Check Point Profile prints the login URL on stderr and opens the default browser. With `--no-browser` it only prints. A FortiToken push prints on stderr that it waits for the phone. Run `connect` in the background, read stderr, tell the human what to do (show the URL, ask for the approval) and wait for the exit.
5. On `CERT_UNTRUSTED` the error carries `cert_digest`. Show the human the digest and the command `vpnconnect profile trust <profile> <digest>`, then stop. The human verifies the certificate and runs it. Run it yourself only when the human, having seen this digest, tells you to.
6. `HELPER_NOT_INSTALLED` and `HELPER_OUTDATED` mean the Helper needs `vpnconnect helper install`; tell the human (see Helper).
7. If the session comes up in full tunnel, `connect` still exits 0 and prints a warning on stderr. Tell the human (see Full tunnel).

Ctrl-C or SIGINT during `connect` cancels the pending login and exits 130. After a successful `connect` there is nothing to keep running.

## Status

```bash
vpnconnect status --json
```

Prints the Helper's state as-is plus `profile` (`{"id","name"}`, or `null` without a session; `name` is `null` if the Profile no longer exists here). `state` is `disconnected`, `connecting`, `waiting-saml` (with `url`), `waiting-push` or `connected`. A connected session has `ip`, `since`, `expires_at`, `dns_servers`, `dns_suffixes` and `full_tunnel`. After a drop, `disconnected` carries `reason` and `cause` (`tunnel-dropped`, `expired`); a login the gateway refused also ends in `disconnected` with `reason` and `cause` `login-failed`.

When an internal host is unreachable, read `status` before anything else:

- `connected`: the VPN is up; the problem is the host, the route or the DNS, so say so.
- `connected` with `full_tunnel: true` and public sites or names failing too: the gateway sends all traffic through the VPN and may block the internet or public DNS. See Full tunnel.
- `disconnected`: report `reason` and `cause`, then ask the human whether to connect.
- `waiting-saml` or `waiting-push`: a login is pending and needs the human.
- `HELPER_NOT_INSTALLED`, `HELPER_OUTDATED` or `HELPER_UNAVAILABLE`: run `vpnconnect helper status` (see Helper).

`vpnconnect disconnect` ends the session or cancels a pending login, whoever started it, and exits 0 when there is none. Run it only when the human asks you to disconnect, or to cancel a login your own `connect` started.

## Full tunnel

`full_tunnel: true` in `status`, `connect` and `watch` means all of this machine's traffic goes through the VPN, not only the internal networks. This is a privacy matter: the organization behind the VPN can see and log all of it, personal traffic included. The gateway can switch to full tunnel without notice.

- Whenever you see `full_tunnel: true`, tell the human in plain words that all of the machine's traffic is going through the VPN.
- In full tunnel the VPN DNS resolves every name (`dns_suffixes` is empty in `status`): the split-DNS domains would send the other names to a public resolver that the gateway may block. Split DNS comes back with `--route`.
- To send only some networks through the VPN, the Profile takes `--route <CIDR>` (repeat for several): then only those networks use the tunnel and the gateway's routes, full tunnel included, are ignored. The DNS goes back to split DNS: the gateway's suffixes, or the Profile's `--dns-domain`. If there are neither (`dns_suffixes` empty in `status`), the VPN DNS still resolves every name, public ones included; to keep those away from it, ask the human for the internal domains and set `--dns-domain`. Which networks, and whether to leave full tunnel at all, is the human's call: ask for the networks (often internal ranges like `10.0.0.0/8`), never guess them, and say that the organization's policy may require full tunnel.
- The new routes apply on the next connect. Disconnect and connect again only when the human asks.
- `--clear-routes` gives the routing back to the gateway.

## Follow the session

```bash
vpnconnect watch
```

`watch` is always NDJSON on stdout, with or without `--json`: one object per line, each with an `event` field (`state`, `log`, `bandwidth`, `expiring`, `reconnecting`). The first line is the current state; nothing from the past is replayed. `--help` lists the events.

- `reconnecting` (with `in_ms`) is not an error: the Helper is unreachable, as in a restart, and `watch` retries by itself and streams again.
- It runs until stopped. Start it in the background and read its output; stop it with SIGINT (exit 130) or by killing the process. Stop it when you no longer need it.
- Only `HELPER_UNAUTHORIZED` (255) ends it by itself (see Console user only).

## Profiles

A Profile is a saved gateway: engine (`fortinet` or `checkpoint`), host, port, authentication (`password` or `saml`), username, realm, OTP flag, trusted certificates, split-DNS domains, networks through the VPN (`routes`). A Profile saved before engines existed is `fortinet`.

```bash
vpnconnect profile ls --json
vpnconnect profile show <profile> --json
vpnconnect profile add --name <name> --host <host> --auth password --username <user> --dns-domain corp.example.com
vpnconnect profile add --engine checkpoint --name <name> --host <host> --realm <login-option>
vpnconnect profile edit <profile> --port 443
vpnconnect profile edit <profile> --route 10.0.0.0/8 --route 172.16.0.0/12
vpnconnect profile rm <profile>
vpnconnect profile set-password <profile> --password-stdin
vpnconnect profile clear-password <profile>
vpnconnect profile trust <profile> <sha256>
vpnconnect profile untrust <profile> <sha256>
```

- Target a Profile by id or exact name. A partial or ambiguous name is refused (`PROFILE_NOT_FOUND`, `PROFILE_AMBIGUOUS`); take the id from `profile ls`.
- `profile add` and `profile edit` take the same flags, and `edit` changes only the flags passed. `--dns-domain` repeats and replaces the whole list; `--clear-dns-domains` empties it. `--route` and `--clear-routes` work the same way for the networks (see Full tunnel).
- `--engine fortinet|checkpoint` is a `profile add` flag only: the engine is chosen at creation and `profile edit` cannot change it. Fortinet is the default. Ask the human which one the gateway is; there is no detection.
- A Check Point Profile always signs in through the identity provider, in the browser, with port 443 as the default. `--auth` is optional and only takes `saml`; `--username`, `--otp-required`, `--auth password` and `profile set-password` are refused with `INVALID_ARGUMENT`, on `add` and on `edit`. `--realm` holds the login option id (the gateway's id for its identity provider login); leave it out when the gateway offers a single option, and ask the human for the id when `connect` fails because the gateway offers several. No command lists the options.
- A Check Point gateway announces DNS suffixes, and only names under them go to the VPN DNS. If the internal names fall outside those suffixes (an internal host does not resolve although `status` is `connected`), the Profile needs `--dns-domain` for each domain: `profile edit <profile> --dns-domain corp.example.com`. The Profile list replaces the gateway's, so include every domain you still need. Ask the human which domains; do not guess them.
- The password goes in through stdin only, never as an argument: `printf '%s' "$PW" | vpnconnect profile set-password <profile> --password-stdin`. Read `$PW` from the human or a secret store into the pipe, not into a file. `profile show` reports `has_password`; no command prints the password.
- `profile rm` asks nothing and deletes the saved password too. Run it only when the human asks, naming the Profile.
- `--auto-trust` accepts whatever certificate the gateway presents. Set it only when the human asks for it for that Profile.

## Settings

```bash
vpnconnect settings show --json
vpnconnect settings set dns-fallback on
```

`dns-fallback` lets names the VPN DNS cannot resolve fall back to the system DNS. Change a setting only when the human asks.

## Helper

```bash
vpnconnect helper status --json
vpnconnect helper install
vpnconnect helper uninstall
```

`helper status` prints `installed`, `running`, `version` and `needs_update`, and exits 0 even when the Helper is down. `helper install` installs or updates it, `helper uninstall` removes it. Both open the macOS administrator dialog for the human to type the password, so run them only when the human asks and tell them the dialog is coming. `HELPER_INSTALL_CANCELLED` means the human declined: do not retry.

## Output and exit codes

Without `--json`, stdout is for people. With `--json`, stdout carries only JSON, on one line (`watch` is NDJSON either way). Progress, warnings and the SAML URL go to stderr. Errors go to stderr as `{"error":{"code","message"}}`, plus `cert_digest` for `CERT_UNTRUSTED`. The CLI never prompts, even with a terminal. Branch on `code`, not on the message.

| Exit | Meaning |
|---|---|
| 0 | success |
| 1 | refused by the Helper, the gateway or a pre-connect check; the Helper install was cancelled or failed |
| 255 | CLI failure: bad argument, Helper unavailable |
| 130 | interrupted (Ctrl-C) |

| Code | Exit | What it means and what to do |
|---|---|---|
| `HELPER_REFUSED` | 1 | The Helper refused the request; read the message and report it |
| `PROFILE_NOT_FOUND` | 1 | No Profile with that id or exact name; check `profile ls` |
| `PROFILE_AMBIGUOUS` | 1 | The name matches several Profiles; use the id |
| `PROFILE_NAME_TAKEN` | 1 | Profile names are unique; pick another |
| `INVALID_DNS_DOMAIN` | 1 | A `--dns-domain` the app would reject; fix the value |
| `INVALID_ROUTE` | 1 | A `--route` that is not an IPv4 network in CIDR (`10.0.0.0/8`), is `0.0.0.0/0` or one of too many; fix the value |
| `INVALID_CERT_DIGEST` | 1 | Not a sha256 (64 hex characters); copy it again |
| `OTP_REQUIRED` | 1 | The Profile needs an OTP; ask the human for a code, pass `--otp` |
| `CREDENTIALS_MISSING` | 1 | No saved password; ask the human, then `profile set-password` |
| `SESSION_ACTIVE` | 1 | A session is already up; keep it (see Connect) |
| `CERT_UNTRUSTED` | 1 | The gateway certificate is unknown; show `cert_digest` to the human |
| `LOGIN_FAILED` | 1 | The gateway rejected the login (password, OTP, push or the browser login, SAML/IdP); ask the human, do not loop |
| `CONNECT_FAILED` | 1 | The session failed after login; report the message |
| `CONNECT_CANCELLED` | 1 | The login ended before the session came up; ask whether to retry |
| `TIMEOUT` | 1 | No session within `--timeout`; the login was cancelled. Ask the human, retry once |
| `HELPER_INSTALL_CANCELLED` | 1 | The human closed the administrator dialog; do not retry |
| `HELPER_INSTALL_FAILED` | 1 | The install failed; report the message |
| `INVALID_ARGUMENT` | 255 | An unknown or missing flag, a bad value or flag combination (`--username`, `--otp-required`, `--auth password`, `--otp` or `set-password` on a Check Point Profile); read `--help` of the command |
| `CLI_ERROR` | 255 | An unexpected CLI failure (IO, closed output); report the message |
| `HELPER_UNAVAILABLE` | 255 | The Helper does not answer; `helper status`, then the human |
| `HELPER_UNAUTHORIZED` | 255 | Not the console user, as over SSH; report and stop |
| `HELPER_NOT_INSTALLED` | 255 | No Helper; the human runs `vpnconnect helper install` |
| `HELPER_OUTDATED` | 255 | The Helper is older than the app; the human runs `vpnconnect helper install` |

## Safety rules

- Leave the decision to trust a certificate to the human: show the digest, wait.
- Keep the password off command lines, `echo`, files and logs: stdin only.
- Leave a session the human opened as it is: no `disconnect`, no replacing it with `connect`, unless they ask.
- Treat `profile rm`, `helper uninstall`, `--auto-trust`, `--route`, `--clear-routes` and settings changes as the human's calls; run them on request.
- Never let a full tunnel go unmentioned: tell the human whenever `full_tunnel` is true.
- Ask the human for every OTP and every approval; never reuse an old code.
- Stop at `HELPER_UNAUTHORIZED`, `HELPER_INSTALL_CANCELLED` and `LOGIN_FAILED`; report instead of retrying.
