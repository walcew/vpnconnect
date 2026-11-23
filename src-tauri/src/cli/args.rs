//! A linha de comando. Nomes de comando e de opção em inglês e estáveis; help só em inglês.

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "vpnconnect",
    version,
    about = "Control the VPN Connect VPN session from the terminal",
    long_about = "Control the VPN Connect VPN session from the terminal.\n\n\
        The session lives in the Helper, so the app window and this CLI see and control the same \
        session. Only root and the user logged in at the console can talk to the Helper.\n\n\
        Exit codes: 0 success; 1 refused by the Helper or the gateway, or the Helper install was \
        cancelled or failed; 255 CLI failure (bad argument, Helper unavailable); 130 interrupted \
        (Ctrl-C).",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Print only JSON on stdout, in one line; errors go to stderr as {"error":{"code","message"}}
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Show the VPN session: state, IP, connected since, expiry, DNS and Profile
    #[command(long_about = "Show the VPN session: state, IP, connected since, expiry, DNS servers and \
        suffixes, and the Profile. After a disconnect, shows the reason and the cause (tunnel-dropped, \
        expired, login-failed).\n\n\
        Full tunnel: when the session sends all of this machine's traffic through the VPN, the text says \
        so in a warning line and the JSON has \"full_tunnel\": true (false in a split session). The \
        organization behind the VPN can then see all of this traffic; only a human decides whether to \
        keep it or limit the Profile with `profile edit --route`.\n\n\
        With --json, prints the Helper's state as-is (state, profile_id, ip, since, expires_at, \
        dns_servers, dns_suffixes, full_tunnel, url, reason, cause, cert_digest; only the fields of the current \
        state) plus \"profile\": {\"id\", \"name\"}, or null when no session is active. \"name\" is \
        null when the Profile no longer exists on this Mac.")]
    Status,
    /// Connect a Profile and wait until the session is up or has failed
    #[command(long_about = "Connect a Profile and wait until the session is up (exit 0, prints the \
        status, same format as `status`) or has failed (exit 1 and the error code). The session \
        lives in the Helper: it stays up after this command returns or the terminal closes.\n\n\
        Runs the same checks as the app: the password comes from the Keychain (no prompt, there is \
        no password flag), an OTP Profile needs --otp (else OTP_REQUIRED), --otp on a Check Point \
        Profile is refused with INVALID_ARGUMENT, extra_args only print a warning, and the DNS fallback setting applies. Refused with SESSION_ACTIVE when a session \
        is already active.\n\n\
        If the session comes up in full tunnel (all of this machine's traffic through the VPN), a warning \
        goes to stderr; the exit code is still 0.\n\n\
        SAML and Check Point: opens the login URL in the default browser and prints it on stderr; \
        --no-browser only prints it. The login at the identity provider is a human step. FortiToken push: stderr says it waits for the approval on the phone.\n\n\
        After --timeout seconds without a session, or on Ctrl-C, the pending login is cancelled \
        (exit 1 TIMEOUT, or 130). An untrusted certificate fails with CERT_UNTRUSTED and the \
        digest in the error JSON (\"cert_digest\"); only a human may decide to trust it.")]
    Connect {
        /// Profile id or exact name; partial or ambiguous names are refused
        profile: String,
        /// One-time password, for a Fortinet Profile that requires OTP
        #[arg(long, value_name = "CODE")]
        otp: Option<String>,
        /// Seconds to wait for the session before cancelling the login
        #[arg(long, value_name = "SECONDS", default_value_t = 120)]
        timeout: u64,
        /// Print the SAML login URL without opening the browser
        #[arg(long)]
        no_browser: bool,
    },
    /// End the session or cancel a pending login (SAML, push), from the app or the CLI
    #[command(long_about = "End the VPN session, connected or still logging in (SAML, push), \
        whether the app or the CLI started it. Waits until the Helper reports disconnected and \
        prints the status. Without a session it is not an error: exits 0 and says so on stderr.")]
    Disconnect,
    /// Stream the Helper events as NDJSON until Ctrl-C
    #[command(
        long_about = "Stream the Helper events as NDJSON (one JSON object per line on stdout, always, with or \
            without --json) until Ctrl-C, which exits 130. It follows the same session the app shows, \
            whoever started it. Nothing is read from the past: the first line is the current state.\n\n\
            If the Helper is not running, or the socket closes (the Helper restarted), it emits a \"reconnecting\" \
            event and retries with a growing wait (1 s to 15 s), then streams again, starting with the \
            current state. It never gives up for a missing Helper. If the Helper refuses this user it exits \
            255 (HELPER_UNAUTHORIZED), since retrying would not help.",
        after_help = "Each line has an \"event\" field that says which one it is:\n\
            \x20 {\"event\":\"state\",\"state\":\"connected\",\"profile_id\":\"…\",\"ip\":\"10.0.0.2\",\"since\":\"…\",\"expires_at\":\"…\",\"dns_servers\":[…],\"dns_suffixes\":[…],\"full_tunnel\":false,\"profile\":{\"id\":\"…\",\"name\":\"…\"}}\n\
            \x20   the session state, the same fields as `status --json` plus \"event\"; the other states are \"connecting\",\n\
            \x20   \"waiting-saml\" (with \"url\"), \"waiting-push\" and \"disconnected\" (with \"reason\", \"cause\" (tunnel-dropped, expired, login-failed) or \"cert_digest\" when they apply)\n\
            \x20 {\"event\":\"log\",\"line\":\"…\"}                                  a line of the Helper's session log\n\
            \x20 {\"event\":\"bandwidth\",\"rx_bytes\":1024,\"tx_bytes\":512}      session totals in IP bytes, every few seconds\n\
            \x20 {\"event\":\"expiring\",\"expires_at\":\"…\"}                      the session expires soon (once per session)\n\
            \x20 {\"event\":\"reconnecting\",\"in_ms\":1000}                      the Helper is unreachable; retrying in in_ms"
    )]
    Watch,
    /// Manage the saved Profiles, their passwords and trusted certificates
    #[command(subcommand, long_about = "Manage the saved Profiles, the same ones the app shows. Every command \
        takes <profile> as the Profile id or its exact name; partial or ambiguous names are refused. \
        --json prints a Profile as {\"id\", \"name\", \"engine\" (fortinet|checkpoint), \"host\", \"port\", \"auth\" (password|saml), \"username\", \
        \"realm\", \"otp_required\", \"auto_trust\", \"trusted_certs\", \"dns_domains\", \"routes\", \"has_password\"}; the \
        password itself is never printed. `ls` prints an array of them.\n\n\
        \"routes\" are the networks that go through the VPN (--route). Empty, the gateway decides, and it may send \
        everything through the VPN (full tunnel). Set, only those networks use the tunnel, whatever the gateway sends.\n\n\
        Profile names are unique. Refusals (exit 1): PROFILE_NAME_TAKEN, INVALID_DNS_DOMAIN, INVALID_ROUTE, \
        INVALID_CERT_DIGEST. Bad usage (exit 255): INVALID_ARGUMENT.")]
    Profile(ProfileCmd),
    /// Show or change the app settings
    #[command(subcommand, long_about = "Show or change the app settings, stored in the same file the app uses. \
        --json prints {\"dns_fallback\", \"helper_install_declined\"}. Changing one setting keeps the others.")]
    Settings(SettingsCmd),
    /// Show, install or uninstall the Helper, the root daemon the VPN runs in
    #[command(subcommand, long_about = "Show, install or uninstall the Helper. The same installer as the app. \
        `install` and `uninstall` open the macOS administrator dialog: the password is typed there, never \
        in the terminal. Cancelling the dialog exits 1 with HELPER_INSTALL_CANCELLED; other failures exit 1 \
        with HELPER_INSTALL_FAILED.")]
    Helper(HelperCmd),
    /// Print the agent skill that teaches this CLI, or install it for the agents on this Mac
    #[command(long_about = "Print the agent skill (SKILL.md) embedded in this binary, so it always \
        matches the installed version. `skill install` writes it to ~/.agents/skills/vpnconnect/ and \
        links it from the skills folder of Claude Code ($CLAUDE_CONFIG_DIR or ~/.claude), Windsurf, \
        Goose and Kiro, only for the agents whose folder exists. Run it again after updating the app.")]
    Skill {
        #[command(subcommand)]
        cmd: Option<SkillCmd>,
    },
}

#[derive(Subcommand)]
pub enum SkillCmd {
    /// Install the skill in ~/.agents/skills/vpnconnect/ and link it for the agents present
    Install,
}

#[derive(Subcommand)]
pub enum HelperCmd {
    /// Show whether the Helper is installed and running, its version and whether it needs an update
    #[command(long_about = "Show whether the Helper is installed and running, its version and whether it needs \
        an update (running with another version than this app's). With --json, prints \
        {\"installed\", \"running\", \"version\", \"needs_update\"}; version is null when the Helper is not \
        running. Exits 0 even when the Helper is not running.")]
    Status,
    /// Install the Helper, or update it to this app's version
    #[command(long_about = "Install the Helper, or update it to this app's version, from the app bundle. \
        Prints the status after the install.")]
    Install,
    /// Remove the Helper, and what the 0.3.0 Helper left behind
    #[command(long_about = "Remove the Helper and the files of the 0.3.0 Helper. Prints the status after the removal.")]
    Uninstall,
}

#[derive(Subcommand)]
pub enum ProfileCmd {
    /// List the Profiles
    Ls,
    /// Show every field of a Profile and whether it has a saved password
    Show {
        /// Profile id or exact name
        profile: String,
    },
    /// Create a Profile and print it
    #[command(long_about = "Create a Profile and print it. --name and --host are required and the name must be \
        unique. Defaults are the app's: Fortinet engine, port 8443, password authentication, no OTP, no \
        DNS domains. The password is not set here: pipe it to `profile set-password --password-stdin`.\n\n\
        --engine checkpoint makes a Check Point Profile: it always signs in through the identity \
        provider, in the browser (a human step), so --auth is optional and only accepts saml, and the \
        default port is 443. --username, --otp-required and --auth password are refused with \
        INVALID_ARGUMENT, and so is `profile set-password` on it. --realm holds the login option id; \
        leave it out when the gateway offers a single option. The engine is fixed after creation.")]
    Add {
        /// Profile name, unique among Profiles
        #[arg(long)]
        name: String,
        /// Gateway host name or address
        #[arg(long)]
        host: String,
        /// VPN engine, fixed after creation: fortinet (default) or checkpoint
        #[arg(long, value_enum, default_value = "fortinet")]
        engine: Engine,
        #[command(flatten)]
        fields: Fields,
    },
    /// Change only the fields passed and print the Profile
    #[command(long_about = "Change only the fields passed and print the resulting Profile. Fields not passed, \
        including trusted certificates, keep their value. --dns-domain replaces the whole list; \
        --clear-dns-domains empties it. --route replaces the whole list of networks; --clear-routes \
        empties it. An empty --username or --realm clears it. The engine cannot \
        be changed. On a Check Point Profile, --username, --otp-required and --auth password are refused \
        with INVALID_ARGUMENT; --realm is the login option.")]
    Edit {
        /// Profile id or exact name
        profile: String,
        /// New name, unique among Profiles
        #[arg(long)]
        name: Option<String>,
        /// New gateway host name or address
        #[arg(long)]
        host: Option<String>,
        #[command(flatten)]
        fields: Fields,
    },
    /// Delete a Profile and its saved password; asks nothing
    Rm {
        /// Profile id or exact name
        profile: String,
    },
    /// Save the password read from stdin
    #[command(long_about = "Save the Profile's password in the Keychain. It is read from stdin only (there is no \
        password argument, so it never reaches `ps` or the shell history): one trailing newline is \
        dropped and an empty password is refused. Never prompts: with a terminal on stdin it fails \
        instead of waiting.\n\nExample: printf '%s' \"$PASSWORD\" | vpnconnect profile set-password Corp --password-stdin")]
    SetPassword {
        /// Profile id or exact name
        profile: String,
        /// Read the password from stdin
        #[arg(long, required = true)]
        password_stdin: bool,
    },
    /// Remove the saved password
    ClearPassword {
        /// Profile id or exact name
        profile: String,
    },
    /// Trust a certificate (sha256 digest) for a Profile
    #[command(long_about = "Add a certificate digest to the Profile's trusted certificates, as the app's \
        \"Trust & Reconnect\" does. The digest is 64 hex characters (sha256 of the certificate); \
        upper case and `:` separators are accepted and normalized. Adding a digest already trusted \
        succeeds. Only a human decides whether to trust a certificate.")]
    Trust {
        /// Profile id or exact name
        profile: String,
        /// sha256 digest of the certificate, 64 hex characters
        digest: String,
    },
    /// Stop trusting a certificate (sha256 digest) for a Profile
    Untrust {
        /// Profile id or exact name
        profile: String,
        /// sha256 digest of the certificate, 64 hex characters
        digest: String,
    },
}

/// Os campos de `profile add` e `profile edit` que não são obrigatórios.
#[derive(Args)]
pub struct Fields {
    /// Gateway port (default 8443, or 443 for Check Point)
    #[arg(long)]
    pub port: Option<u16>,
    /// Authentication method; saml never asks for an OTP; Check Point only accepts saml
    #[arg(long, value_enum)]
    pub auth: Option<Auth>,
    /// User name, for password authentication (refused for Check Point)
    #[arg(long)]
    pub username: Option<String>,
    /// Realm of the gateway login; for Check Point, the login option id (optional)
    #[arg(long)]
    pub realm: Option<String>,
    /// Ask for an OTP on every connect (Fortinet password authentication only)
    #[arg(long, conflicts_with = "no_otp_required")]
    pub otp_required: bool,
    /// Do not ask for an OTP
    #[arg(long)]
    pub no_otp_required: bool,
    /// Trust whatever certificate the gateway presents, like the app's "Ignore certificate errors"; only for gateways you control
    #[arg(long, conflicts_with = "no_auto_trust")]
    pub auto_trust: bool,
    /// Do not trust certificates automatically
    #[arg(long)]
    pub no_auto_trust: bool,
    /// Split-DNS domain that uses the VPN DNS; repeat for several. Without any, the gateway's DNS suffixes apply.
    /// In full tunnel the VPN DNS resolves every name and these are only search domains
    #[arg(long = "dns-domain", value_name = "DOMAIN", conflicts_with = "clear_dns_domains")]
    pub dns_domains: Vec<String>,
    /// Empty the DNS domains list
    #[arg(long)]
    pub clear_dns_domains: bool,
    /// Network that goes through the VPN, in CIDR (10.0.0.0/8; an address alone is a /32); repeat for several.
    /// When set, only these networks use the tunnel and the gateway's routes, full tunnel included, are ignored.
    /// Without any, the gateway's routes apply
    #[arg(long = "route", value_name = "CIDR", conflicts_with = "clear_routes")]
    pub routes: Vec<String>,
    /// Empty the networks list: the gateway's routes apply again
    #[arg(long)]
    pub clear_routes: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Engine {
    Fortinet,
    Checkpoint,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Auth {
    Password,
    Saml,
}

#[derive(Subcommand)]
pub enum SettingsCmd {
    /// Show the settings
    Show,
    /// Change one setting
    #[command(subcommand)]
    Set(SettingCmd),
}

#[derive(Subcommand)]
pub enum SettingCmd {
    /// Use the system DNS as a fallback for names the VPN DNS cannot resolve
    DnsFallback {
        /// on or off
        #[arg(value_enum)]
        value: Toggle,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Toggle {
    On,
    Off,
}
