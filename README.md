# SecureWrapper

**A credential firewall for LLM agents and MCP servers.** Stores encrypted connection profiles bound to the local machine. Lets AI agents, MCP servers, and automation tools execute authenticated commands without ever seeing the underlying credentials — SSH passwords, API keys, database credentials, or Windows administrator accounts never leave the vault.

## Why This Exists

### LLM Agents and MCP Servers

Modern AI workflows connect language models to real infrastructure through tool calls and MCP servers. Every tool that can run a command or call an API is a potential credential exposure point — tool-use logs, conversation transcripts, context windows, and MCP server processes all become attack surface the moment you put a real password in them.

SecureWrapper removes credentials from that surface entirely. Instead of embedding passwords in your MCP server config or passing API tokens through an agent's context, you give the agent a single **auth key** and let the wrapper authenticate on its behalf.

The agent (and every log it produces) sees only:
- Connection **names** (`prod-db`, `jumpbox`, `billing-api`, …)
- **Command output** from the remote system

The agent never sees:
- Passwords
- API tokens
- SSH private keys or passphrases
- TOTP secrets
- Database credentials

**If a conversation transcript leaks, a context window is compromised, an MCP server process is dumped, or a tool-use log ends up somewhere it shouldn't:** the leaked information is useless. An attacker with the full transcript cannot reconstruct your credentials from it — the agent never held them.

To cut off access entirely, **revoke the auth key** (seconds, one TUI command) or **wipe the vault** (kill switch). Compromise becomes a revocation problem, not a credential-rotation problem.

Scope each auth key to a specific subset of connections, so one compromised agent or MCP server can't reach your whole infrastructure.

### Local by Design — No Cloud, No Trust Transfer

Cloud secrets managers like **Keeper Secrets Manager** address part of this: they mask secrets by default and require confirmation before a value is revealed, so an agent can use a credential without leaving it exposed. But the secrets still live in — and sync through — a third-party cloud service you have to trust, depend on, and pay for. You've moved your credentials off your own machine and onto someone else's infrastructure: another account, another subscription, another external dependency that can be breached, locked out, billed, or taken offline.

SecureWrapper takes the opposite approach. **The vault never leaves your machine.** There is no cloud account, no subscription, no third party in the trust path, and nothing that reaches out over the network. It is **fully local, 100% under your control, and free and open source (MIT)** — the credentials stay on hardware you own, encrypted to that specific machine and binary.

## Features

- **Three-factor encryption** — vault passphrase + machine hardware fingerprint + binary self-hash
- **Machine-bound** — vault won't decrypt on different hardware
- **Binary-bound** — encryption key derived from the binary's own SHA-256 hash. No stored secrets. If the binary is modified, the vault breaks.
- **Auth keys** — automated callers use auth keys to execute connections without the vault passphrase. Auth keys survive binary upgrades.
- **Multi-mode passthrough** — SSH, SCP, SFTP, Rsync, REST API, database (PostgreSQL / MySQL / SQL Server), and WinRM / PowerShell Remoting through a single vault entry
- **Three-flag CLI** — `--sys`, `--mode`, and auth key (via env var). Everything after is raw passthrough.
- **TOFU host key verification** — SSH connections verify host keys (Trust On First Use). Rejects changed keys.
- **BBS-style TUI** — interactive vault management with a retro terminal interface
- **In-app upgrades** — check for updates, download, verify checksum, migrate vault automatically
- **Connection sharing** — SSH-based calls reuse one authenticated connection per profile (the native-client equivalent of OpenSSH ControlMaster), so bursts of calls don't trip fail2ban / rate limits on the server
- **SSH tunneling** — DB and WinRM connections can be routed through any stored SSH connection (bastion / jumphost pattern) with one config field
- **Hardware migration** — passphrase + one-time code export with 24-hour network-time-verified fuse, carries connections to a new machine
- **Passphrase policy** — minimum length, character-class diversity, and common-password blocklist enforced at creation and rotation, with a live strength meter
- **Tiered lockout** — failed passphrase attempts trigger escalating lockouts: 5 → 5 min, 10 → 1 hr, 15 → 8 hr, 20 → 48 hr, 25 → permanent lock (recover via portable backup restore). No auto-wipe.
- **Brute-force protection** — persistent attempt counter with per-attempt exponential backoff within each block
- **Local-only** — remote calls are rejected

## Quick Start

```bash
# Build (requires Go 1.24+)
./build.sh

# First run — create vault, add connections, generate auth keys
./wrapper

# Automated use — auth key via environment variable (preferred)
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --ssh "uptime"
```

## Usage

### Interactive Mode
```
./wrapper
```
Launches the vault management TUI. Create connections, manage auth keys, test connectivity, check for updates.

### Connection Mode

Auth key + system name + mode. Everything after the mode flag is raw passthrough:

```bash
# Preferred — auth key via environment variable (not visible in ps)
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys <name> --<mode> [passthrough args...]

# Alternative — auth key from file
./wrapper --key-file /path/to/keyfile --sys <name> --<mode> [passthrough args...]
```

### Modes

| Mode | Purpose | Example |
|------|---------|---------|
| `--ssh` | Run a command on a remote host | `--ssh "df -h"` |
| `--scp` | Copy files to/from remote | `--scp file.txt :/remote/path/` |
| `--sftp` | Interactive file transfer | `--sftp` |
| `--rsync` | Sync files over SSH | `--rsync -av /local/ :/remote/` |
| `--api` | HTTP API request | `--api GET /endpoint` |
| `--db` | Run a SQL query (Postgres/MySQL/SQL Server) | `--db "SELECT version()"` |
| `--winrm` | Run a PowerShell command against a Windows host | `--winrm "Get-Service wuauserv"` |
| `--test` | Test connectivity | `--test` |
| `--mux-status` | Is a shared SSH master running? | `--mux-status` |
| `--mux-stop` | Retire the shared master (running calls finish) | `--mux-stop` |

### Examples

```bash
# SSH — run a command
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --ssh "uptime"

# SSH — interactive session
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --ssh

# SCP — copy file to remote (: prefix = remote path)
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --scp file.txt :/remote/path/

# SCP — copy from remote
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --scp :/remote/file.txt ./

# Rsync — sync directory
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --rsync -av /local/ :/remote/

# API — GET request
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myapi --api GET /endpoint

# API — POST with body
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myapi --api POST /endpoint '{"key":"value"}'

# Database — SELECT (output is tab-separated with a header line)
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys mydb --db "SELECT id, name FROM users LIMIT 10"

# Database — non-query (returns "N rows affected")
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys mydb --db "UPDATE jobs SET status='done' WHERE id=42"

# WinRM — run PowerShell, stdout returned
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys mywinhost --winrm "Get-Service wuauserv"

# Auth key from file
./wrapper --key-file ~/.secrets/wrapper.key --sys myserver --ssh "hostname"

# Test a connection
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --test

# List connections (shows only what the auth key has access to)
WRAPPER_AUTH_KEY=swk_xxx ./wrapper --list
```

### Remote Paths

For SCP and Rsync, prefix remote paths with `:` — the wrapper automatically prepends `user@host` from the connection profile:

```
:/path/to/file  →  user@host:/path/to/file
```

### Other Flags

| Flag | Purpose |
|------|---------|
| `--help` | Built-in user guide |
| `--version` | Version, build date, machine and binary fingerprints |
| `--list` | List connection names (works with auth key — shows only accessible connections) |
| `--key-file` | Read auth key from file (safer than `--key`) |
| `--show-fingerprint` | Print the full machine fingerprint string and exit (no vault needed) |

## Security Model

### Three-Factor Vault Encryption
1. **Passphrase** — something you provide (admin access)
2. **Machine fingerprint** — CPU, machine-id / platform UUID, architecture (MAC addresses, disk serial, and hostname are deliberately excluded — they change too easily and would lock a vault on a NIC/disk swap or rebuild)
3. **Binary self-hash** — SHA-256 of the compiled binary itself

All three must match to decrypt the main vault. Auth key access uses 2-factor (auth key + machine fingerprint) so keys survive binary upgrades.

### Auth Keys
- Multiple named keys — one per calling system for individual revocation
- Shown once at creation, stored as Argon2id hashes
- Two-tier access: passphrase = admin (full vault management), auth key = operator (execute connections only)
- Usage tracking per key
- Provided via `WRAPPER_AUTH_KEY` env var (preferred) or `--key-file` to avoid process list exposure

### SSH Host Key Verification
- Trust On First Use (TOFU) — first connection stores the host key in `~/.secure-wrapper/known_hosts`
- Subsequent connections verify against stored key
- Changed host keys are rejected with a warning

### Brute-Force Protection
- Persistent attempt counter across sessions (survives process restarts)
- Exponential backoff between attempts (2^n seconds, capped at 30s)
- 5 cumulative failures wipes the vault (backup preserved)

### Backup & Restore
- **Portable backup** — 2-factor encrypted (passphrase + machine fingerprint, no binary hash). Survives binary upgrades.
- **Restore** — decrypts portable backup with passphrase, re-encrypts for current binary
- **Raw backup + saved binary** — before an upgrade, restore, migration import or wipe, `vault.enc` is copied to `vault.enc.backup` and the binary that opens it is saved beside it as `wrapper-v<version>-<binary fingerprint>.backup`. A raw backup only decrypts with its exact binary. Every vault file records that fingerprint in plain text (`binary_fp` in its header), so any vault copy can be matched to its binary by name. Saved binaries are never deleted automatically, since copies kept elsewhere may still need them. The portable and FIDO2 backups also save the binary for the live `vault.enc`, so a copy of the whole vault folder always carries what it needs
- Also offered at login when vault is incompatible with current binary
- Vault wipe preserves backup files and known_hosts
- **Important:** Portable backups are encrypted with 2 factors (no binary hash). Store them securely — anyone with the passphrase and access to the same machine can restore them. Delete old backups when no longer needed.

### Connection Sharing

Every SSH-based mode (`--ssh`, `--scp`, `--sftp`, `--rsync`, and SSH tunnels
for DB / WinRM) shares one upstream login per connection profile. The first
call starts a detached master process that holds the authenticated SSH
connection; later calls attach to it over a unix socket and open their own
channels on it. The server sees one login, not one per call.

- **Idle lifetime:** 10 minutes after the last call (`WRAPPER_MUX_PERSIST=30m`
  to change). The master also exits if the server drops the connection
  (30-second keepalive).
- **Opt out:** `WRAPPER_MUX=off` dials directly on every call.
- **Self-healing:** a dead or stale master is replaced on the next call. A
  client killed mid-command only loses its own channel.
- **Failed logins are not retried:** if the master cannot log in, that error
  is returned as-is, so one call never costs the server two failed attempts.
- **Socket security:** sockets live in `~/.secure-wrapper/mux/` (mode 0700),
  and attaching requires a token derived from the stored credentials, so a
  same-user process without vault access cannot use an open master.
  Credentials go to the master over a pipe, never argv or the environment.
- **`--mux-stop`** removes the socket immediately; calls already running
  finish, and the next call starts a fresh master.
- **Platform:** Linux and macOS. On Windows every call dials directly.

### SSH Tunneling

Databases and Windows hosts are often behind bastion / jumphost infrastructure and only reachable through SSH. Every DB and WinRM connection accepts a `Tunnel via SSH` field — name any SSH-type connection already stored in the vault. At execution:

1. An SSH session is opened to the tunnel host using the stored profile
2. A local TCP listener is bound to an ephemeral port on `127.0.0.1`
3. The DB or WinRM client dials `127.0.0.1:<port>`; every byte is forwarded through the SSH session to the real target
4. The tunnel and SSH session are torn down when the command finishes

The TUI shows a picker of available SSH connections while editing the tunnel field. Leave blank / type `none` to disable tunneling for a connection.

**Note:** when tunneling, SSH already provides encryption end-to-end to the jumphost. You may want to set the DB's SSL mode to `disable` (Postgres / MySQL) or `encrypt=disable` (SQL Server) since TLS on the inner link would see `127.0.0.1` as the hostname — useful only if the DB server has a cert for its own internal name and you want belt-and-suspenders encryption.

### Hardware Migration
Moving the vault to new hardware (CPU swap, motherboard replacement, new host) is a distinct flow from same-machine backup because the machine fingerprint has to change.

- From the TUI, Config → **Export for Hardware Migration** writes `vault.hwmigration` next to the binary, encrypted with your passphrase plus a fresh 9-character one-time code displayed as `XXX-XXX-XXX`
- The code is shown exactly once — admin writes it down
- The file expires 24 hours after export, verified against **network-trusted time** (HTTPS `Date` headers from multiple providers with consensus, SNTP fallback). The local system clock cannot bypass the fuse.
- The expiry timestamp is bound into the AES-GCM additional-authenticated-data, so tampering with the on-disk value fails authentication rather than extending the window
- On the destination machine, launching the wrapper with `vault.hwmigration` next to it triggers the import wizard automatically — requires passphrase + one-time code + (optional) new passphrase for this machine
- **Auth keys are not migrated** — their per-key derived keys are machine-bound. Regenerate on the destination.
- The migration file is zero-filled and removed on successful import

### Passphrase Policy
Enforced at vault creation and rotation (not at open, not at backup restore — those passphrases were already set under the policy):

- Minimum 12 characters
- Must contain an uppercase letter, a lowercase letter, a digit, and a special character
- Must not appear in the built-in blocklist of well-known weak variants (e.g. character-class-compliant but widely breached)
- Advisory strength meter (weak / fair / good / strong / very strong) rendered live during entry, based on length, class diversity, and unique-character ratio

### Upgrade Security
- SHA256SUMS checksum file included in every release
- Downloaded binary hash verified before replacement
- Vault backed up before upgrade
- Migration file encrypted, user prompted before deletion if stale
- Refuses to start the update when it cannot write to the binary's folder, before any backup or export runs

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Caller reads credentials from source | Binary is compiled, no source on target system |
| Caller reads vault file | Encrypted with three-factor key derivation |
| Caller reads binary to extract key | No key stored — derived from binary's own hash |
| Binary patched to dump credentials | Hash changes, vault won't decrypt |
| Binary copied to another machine | Machine fingerprint mismatch |
| Auth key visible in process list | Use env var or key file, not CLI arg |
| Unauthorized caller | Auth key required |
| Remote caller | Local-only enforcement |
| Passphrase brute force | Argon2id + tiered lockout (5 min → 1 hr → 8 hr → 48 hr → permanent) + per-attempt exponential backoff |
| MITM on SSH connections | TOFU host key verification |
| Compromised update download | SHA-256 checksum verification |
| Shell injection via remote paths | All remote paths shell-escaped |
| Weak passphrase at creation | Policy enforcement: length, class diversity, common-password blocklist |
| Stolen hardware migration file | Requires passphrase + one-time code + import within 24h verified by network time |
| Clock manipulation to bypass migration fuse | Expiry verified against HTTPS `Date` header consensus (TLS-authenticated), not local clock |
| Tampered migration expiry on disk | Expiry bound into AES-GCM AAD — tampering fails authentication |

### Recommended Deployment
The in-app updater replaces the binary in place, so install it in a folder you own:

```bash
install -m 700 wrapper ~/.local/bin/wrapper     # ~/.local/bin must be on PATH
```

Don't run the wrapper with `sudo`: sudo switches to root's home folder, where your vault isn't. The wrapper detects this and exits with an explanation. If scripts call an absolute path such as `/usr/local/bin/wrapper`, make that path a symlink to the copy you own.

For a shared, locked-down host where callers must not read or copy the binary, it can be root-owned and execute-only (`chown root:root`, `chmod 711`). Updates then have to be installed by hand, since the in-app updater cannot replace it.

## Docker Deployment

SecureWrapper can run inside a Docker container and authenticate against a vault stored on the host. Because the vault is machine-bound, containers have a different hardware fingerprint than their host. The `WRAPPER_MACHINE_FP` environment variable lets the container present the host's fingerprint so auth key decryption succeeds.

**The vault file is not a secret** — it is AES-256-GCM encrypted and useless without the auth key. It is safe to mount read-only into the container.

### Setup

**1. Get the host machine fingerprint**

On the host where the vault lives:

```bash
wrapper --show-fingerprint
# → 9c5e3e36300a9ea24d15c85face453c0d6390e73f36386cd1c0b90cd836c3492
```

**2. Create a scoped auth key**

In the wrapper TUI → Config → Auth Keys, create a key scoped only to the connections the container needs. This limits blast radius if the container is compromised.

**3. Copy the wrapper binary into your image**

```dockerfile
# In your Dockerfile — copy from build context or a prior build stage
COPY wrapper-linux-amd64 /usr/local/bin/wrapper
RUN chmod 755 /usr/local/bin/wrapper
```

**4. Mount the vault and pass credentials as environment variables**

```yaml
# docker-compose.yml
services:
  myapp:
    image: myapp:latest
    volumes:
      - /home/user/.secure-wrapper/vault.enc:/root/.secure-wrapper/vault.enc:ro
    environment:
      WRAPPER_AUTH_KEY: swk_xxxxxxxxxxxxx
      WRAPPER_MACHINE_FP: 9c5e3e36300a9ea24d15c85face453c0d6390e73f36386cd1c0b90cd836c3492
```

Or with `docker run`:

```bash
docker run \
  -v /home/user/.secure-wrapper/vault.enc:/root/.secure-wrapper/vault.enc:ro \
  -e WRAPPER_AUTH_KEY=swk_xxxxxxxxxxxxx \
  -e WRAPPER_MACHINE_FP=9c5e3e36300a9ea24d15c85face453c0d6390e73f36386cd1c0b90cd836c3492 \
  myapp:latest
```

**5. Fetch secrets at container startup**

Use `--creds` mode in your entrypoint to pull credentials into the process environment without storing them in the image or config:

```bash
#!/bin/sh
# docker-entrypoint.sh

# Pull secrets from wrapper — credentials never written to disk or image
JWT_SECRET=$(wrapper --sys myapp-jwt --api GET / | jq -r '.auth_value')
DB_PASSWORD=$(wrapper --sys myapp-db --creds | jq -r '.password')
API_TOKEN=$(wrapper --sys billing-api --creds | jq -r '.auth_value')

export JWT_SECRET DB_PASSWORD API_TOKEN

exec "$@"
```

The `--creds` flag outputs a JSON object with the stored credentials for a connection:

```json
{
  "name": "myapp-db",
  "type": "db-postgres",
  "host": "db.internal",
  "port": "5432",
  "username": "app",
  "password": "s3cr3t",
  "database": "myapp",
  "ssl_mode": "require"
}
```

### Security Notes

- `WRAPPER_AUTH_KEY` is the actual secret — treat it like a password. Use Docker secrets or your platform's secret management rather than plain environment variables in production.
- `WRAPPER_MACHINE_FP` only affects **auth-key access** (2-factor: key + fingerprint). Passphrase-based vault operations always use real hardware — the override cannot be used to open the vault interactively on a different machine.
- A warning is printed to stderr whenever `WRAPPER_MACHINE_FP` is active: `[wrapper] WARNING: WRAPPER_MACHINE_FP override active — auth-key fingerprint bypassed`
- Scope auth keys to the minimum set of connections the container needs.
- The vault file itself can be shared across containers on the same host — each container uses its own scoped auth key.

## Architecture

```
wrapper (Go, single static binary)
  ├── main.go            — Entry point, CLI routing, attempt tracking
  ├── vault.go           — Vault CRUD, AES-256-GCM, Argon2id KDF
  ├── binarykey.go       — Binary self-hash key derivation
  ├── fingerprint.go     — Cross-platform machine fingerprint
  ├── fingerprint_*.go   — Platform-specific fingerprint sources
  ├── migration.go       — Hardware migration export/import (passphrase + one-time code + 24h fuse)
  ├── timecheck.go       — Network-trusted time (HTTPS Date consensus, SNTP fallback)
  ├── passphrase.go      — Passphrase policy (length, classes, blocklist) + strength scoring
  ├── cli.go             — Interactive menu, connection execution
  ├── tui*.go            — BBS-style terminal UI (Bubbletea + Lipgloss)
  ├── help.go            — Built-in user guide
  ├── upgrade.go         — GitHub release checking, vault migration, checksum verification
  ├── tls_*.go           — Platform-specific TLS certificate handling
  └── connections/
      ├── ssh.go         — SSH, SCP, Rsync (Go native x/crypto/ssh)
      ├── api.go         — REST API (key, bearer, basic auth)
      ├── ftp.go         — SFTP (Go native SSH)
      ├── db.go          — PostgreSQL / MySQL / SQL Server via database/sql
      ├── winrm.go       — WinRM / PowerShell Remoting
      ├── hostkeys.go    — TOFU known_hosts management
      └── types.go       — Result type
```

## Building

```bash
./build.sh
```

Cross-compiles for all supported platforms. Produces static binaries with no runtime dependencies. Auto-increments build version. Generates SHA256SUMS for release verification.

Each build produces a unique binary hash — the passphrase path to existing vaults will require migration. Auth keys are unaffected.

## Connection Types

| Type | Auth Methods | Modes Supported |
|------|-------------|-----------------|
| SSH (password) | Go native SSH client | ssh, scp, sftp, rsync* |
| SSH (key) | Key file + optional passphrase | ssh, scp, rsync |
| API | API key, Bearer token, Basic auth | api |
| SFTP | Go native SSH client | sftp |
| Database (PostgreSQL) | Username + password over TLS | db |
| Database (MySQL / MariaDB) | Username + password with configurable TLS | db |
| Database (SQL Server) | SQL Auth, configurable encryption | db |
| WinRM / PowerShell | Basic auth over HTTP(5985) or HTTPS(5986) | winrm |

*All connection types including rsync use Go's built-in SSH client. Rsync calls the wrapper itself as its SSH transport (via `--ssh-proxy` mode). The wrapper authenticates natively, then bridges stdin/stdout between rsync and the remote session. Credentials never leave Go's memory — no `sshpass`, no environment variable leaks, no process list exposure. This works with both password and key auth.

## Supported Platforms

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `wrapper-linux-amd64` |
| Linux ARM64 | `wrapper-linux-arm64` |
| macOS Intel | `wrapper-darwin-amd64` |
| macOS Apple Silicon | `wrapper-darwin-arm64` |
| Windows x86_64 | `wrapper-windows-amd64.exe` |

## Requirements

- **Build:** Go 1.24+
- **Runtime:** None — single static binary, no external dependencies for any connection type

## License

MIT
