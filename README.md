# SecureWrapper

A compiled credential vault and connection wrapper. Stores encrypted connection profiles bound to the local machine. Designed to let automation tools execute authenticated commands without ever seeing the credentials.

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
- **Hardware migration** — passphrase + one-time code export with 24-hour network-time-verified fuse, carries connections to a new machine
- **Passphrase policy** — minimum length, character-class diversity, and common-password blocklist enforced at creation and rotation, with a live strength meter
- **Self-destructing** — 5 failed attempts (persistent across sessions) silently wipes the vault
- **Brute-force protection** — persistent attempt counter with exponential backoff
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

## Security Model

### Three-Factor Vault Encryption
1. **Passphrase** — something you provide (admin access)
2. **Machine fingerprint** — CPU, MAC addresses, disk serial, machine-id
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
- Also offered at login when vault is incompatible with current binary
- Vault wipe preserves backup files and known_hosts
- **Important:** Portable backups are encrypted with 2 factors (no binary hash). Store them securely — anyone with the passphrase and access to the same machine can restore them. Delete old backups when no longer needed.

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
| Passphrase brute force | Argon2id + persistent counter + exponential backoff + silent wipe |
| MITM on SSH connections | TOFU host key verification |
| Compromised update download | SHA-256 checksum verification |
| Shell injection via remote paths | All remote paths shell-escaped |
| Weak passphrase at creation | Policy enforcement: length, class diversity, common-password blocklist |
| Stolen hardware migration file | Requires passphrase + one-time code + import within 24h verified by network time |
| Clock manipulation to bypass migration fuse | Expiry verified against HTTPS `Date` header consensus (TLS-authenticated), not local clock |
| Tampered migration expiry on disk | Expiry bound into AES-GCM AAD — tampering fails authentication |

### Recommended Deployment
```bash
# Owned by root, execute-only — callers can run it but can't read or copy it
sudo chown root:root wrapper
sudo chmod 711 wrapper
```

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
