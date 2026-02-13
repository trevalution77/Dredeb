# CLAUDE.md - Dredeb Project Guide

## Project Overview

Dredeb is a Debian system hardening and security automation toolkit. It consists of Bash scripts that aggressively harden Debian-based Linux systems by removing dangerous packages, disabling unnecessary services, enforcing strict access controls, and implementing protections against GTFOBins exploitation techniques.

**Target environment:** Fresh Debian installations on security-focused or air-gapped systems.

## Repository Structure

```
Dredeb/
├── CLAUDE.md          # This file - AI assistant guide
├── README.md          # User-facing documentation
├── sec.sh             # Main system hardening script (~1,222 lines)
├── gtfobin.sh         # GTFOBins exploitation mitigation script (~1,520 lines)
└── preseed.cfg        # Debian installer preseed configuration (~208 lines)
```

There are no subdirectories, build artifacts, or compiled outputs. The project is purely Bash scripts and configuration.

## Language and Tooling

- **Language:** Bash (100% of codebase)
- **Shell safety:** All scripts use `set -euo pipefail`
- **No build system** - scripts are executed directly with `sudo bash <script>.sh`
- **No test framework** - no automated tests exist
- **No linter configuration** - no shellcheck or similar tooling configured
- **No CI/CD** - no GitHub Actions or other pipelines
- **No package manager** - APT is invoked inline within the scripts

## File Descriptions

### `sec.sh` - Main Hardening Script

The primary hardening script. Must be run as root. Executes sequentially through these sections:

| Lines | Section | Description |
|-------|---------|-------------|
| 1-28 | APT Hardening | Configures `/etc/apt/apt.conf.d/99-hardening`, creates package deny list at `/etc/apt/preferences.d/deny.pref` blocking 1000+ packages |
| 30-221 | Service Disabling | Disables and masks 180+ systemd services (cloud, containers, network, desktop, remote access) |
| 223-235 | Package Removal | Purges risky packages matching an extensive glob list |
| 237-266 | Firewall | Configures iptables (IPv4: INPUT/FORWARD DROP, OUTPUT ACCEPT; IPv6: all DROP) |
| 269-288 | Package Installation | Installs GNOME/Wayland desktop, LibreWolf browser, OpenSnitch, PipeWire |
| 290-317 | Accounts/Groups | Removes dangerous system users/groups, adds `dev` user to required groups |
| 319-332 | User Audit | Audits UID 0 accounts, duplicate UIDs, empty passwords, SSH keys |
| 334-508 | PAM/U2F | Comprehensive PAM configuration with U2F (YubiKey) auth, faillock, password lockout |
| 510-581 | Misc Hardening | login.defs, umask, host.conf, access.conf, limits.conf, core dump disabling |
| 583-590 | GRUB | Kernel command-line hardening (mitigations, IOMMU, ASLR, IPv6 disable) |
| 592-661 | Sysctl | Kernel parameter hardening (~60 sysctl settings covering kernel, VM, network, filesystem) |
| 663-870 | Modules | Blacklists and blocks 100+ kernel modules (wireless, bluetooth, USB, filesystems, network protocols) |
| 871-960 | File Permissions | Tightens permissions on /home, /etc, /boot, /var/log, removes world-writable files |
| 961-998 | OpenSnitch | Installs and configures OpenSnitch application firewall, clones Respect-My-Internet rules |
| 999-1105 | Polkit & Sudo | Restrictive polkit rules, sudoers configuration limiting `dev` to specific commands only |
| 1107-1129 | Capability Stripping | Strips Linux capabilities from 250+ binaries, cross-references GTFOBins list |
| 1131-1157 | Placeholder Blockers | Creates immutable empty files at dangerous binary paths to prevent reinstallation |
| 1160-1168 | SUID/SGID Lockdown | Strips all setuid/setgid bits system-wide except `/usr/bin/sudo` |
| 1170-1222 | Immutable Flags | Sets `chattr +i` on critical system files (/etc/passwd, /etc/shadow, PAM, sysctl, /boot, /usr) |

### `gtfobin.sh` - GTFOBins Protection Module

A modular, function-based script with proper logging. Targets ~400+ known GTFOBins exploitation techniques. Structure:

| Function | Description |
|----------|-------------|
| `preflight_checks()` | Verifies root, creates backup dir, initializes logging |
| `remove_dangerous_packages()` | Tiered removal: TIER1 (networking/exploitation), TIER2 (dev tools/languages), TIER3 (individual binaries) |
| `block_package_installation()` | Configures APT preferences to deny reinstallation |
| `strip_suid_sgid()` | Removes setuid/setgid bits from risky binaries |
| `strip_capabilities()` | Removes Linux capabilities from interpreters and utilities |
| `configure_sudo_restrictions()` | Creates sudoers rules blocking GTFOBins via sudo |
| `create_placeholder_blockers()` | Creates immutable empty files at dangerous binary paths |
| `main()` | Orchestrates all functions in sequence |

Key details:
- **Logging:** Color-coded console output + file logging to `/var/log/gtfobins-hardening.log`
- **Backups:** Creates timestamped backups at `/var/backups/gtfobins-hardening-<timestamp>/`
- **Hardcoded user:** `PRIMARY_USER="dev"` (line 13)

### `preseed.cfg` - Debian Installer Preseed

Automates Debian installation with security-hardened defaults:

- **Network:** Static IP (192.168.88.190), IPv6 disabled
- **Disk:** Full LUKS encryption with LVM, separate partitions for /, /var, /var/log, /var/log/audit, /home, /opt, /usr
- **Mount options:** noexec on /home, /opt, /var/log; read-only on /boot and /usr; nosuid/nodev widely applied
- **Packages:** Minimal set - sudo, nano, git, ufw, cryptsetup, libpam-u2f
- **User:** Single non-root user `dev` with sudo group

## Key Conventions

### Hardcoded Values
- **Username:** `dev` is hardcoded throughout all scripts and preseed config
- **Network:** Static IP `192.168.88.190`, gateway `192.168.88.1`
- **Desktop:** GNOME on Wayland with LibreWolf browser

### Error Handling Pattern
- Scripts use `set -euo pipefail` for strict error handling
- Individual commands that may fail use `|| true` or `2>/dev/null || true` to suppress non-critical errors
- `gtfobin.sh` uses structured logging functions (`log_info`, `log_success`, `log_warn`, `log_error`)

### Security Philosophy
- **Deny-all-by-default:** Firewall drops all inbound; package deny list blocks by default
- **Prevention over detection:** Blocks dangerous binaries rather than monitoring their use
- **Defense in depth:** Multiple overlapping protections (package removal + capability stripping + SUID removal + placeholder blockers + immutable flags)
- **Minimal attack surface:** Removes dev tools, scripting languages, network utilities, containers

### Script Execution Order
The intended workflow for a fresh Debian install:
1. Use `preseed.cfg` during Debian installation for secure partitioning
2. Run `sudo bash sec.sh` for comprehensive system hardening
3. Run `sudo bash gtfobin.sh` for GTFOBins-specific protections

## Development Guidelines

### When Modifying Scripts

1. **Do not run these scripts** in non-disposable environments - they make irreversible system changes (immutable flags, package removal, SUID stripping)
2. **Maintain `set -euo pipefail`** at the top of all scripts
3. **Use `|| true`** for commands that may legitimately fail (e.g., removing packages that may not be installed)
4. **Follow existing patterns:** `sec.sh` uses inline sequential blocks; `gtfobin.sh` uses modular functions with logging
5. **Keep the deny list alphabetically sorted** in both the APT preferences and package arrays
6. **Test in a VM** - the preseed.cfg is designed for automated VM provisioning with LUKS

### Adding New Hardening Rules

- **New packages to block:** Add to both the `deny.pref` section in `sec.sh` (line 23) and the `REMOVE` array (line 224)
- **New services to disable:** Add to the `DISABLE` array (line 31)
- **New kernel modules to blacklist:** Add to `/etc/modprobe.d/harden.conf` section (line 664), using both `blacklist` and `install /bin/false`
- **New sysctl parameters:** Add to the sysctl block (line 595)
- **New GTFOBins entries:** Add to `ALL_GTFOBINS` array in `sec.sh` (line 1112) and relevant tier arrays in `gtfobin.sh`
- **New capabilities to strip:** Add paths to `STRIP_CAPS` array in `sec.sh` (line 1108)
- **New binaries to block:** Add to `dangerous_paths` array in `sec.sh` (line 1132) and `gtfobin.sh`

### Important Warnings

- SSH is fully blocked via PAM (`/etc/pam.d/sshd` denies all auth) - remote access is intentionally disabled
- Password changes are blocked via PAM (`pam_deny.so` in common-password) - authentication is U2F-only
- `/usr` and `/boot` are made immutable with `chattr +i` - package installation will fail after hardening
- There is no rollback mechanism - to undo changes, you must reinstall the OS
- IPv6 is disabled at multiple layers (kernel params, sysctl, iptables, preseed)
