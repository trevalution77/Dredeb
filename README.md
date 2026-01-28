# Dredeb - Debian Hardening Scripts

A collection of security hardening scripts for Debian-based systems.

## Contents

- **sec.sh** - Main Debian system hardening script that includes:
  - Systemd service hardening (disabling unnecessary services)
  - Package removal of risky software
  - Firewall configuration (iptables)
  - PAM/U2F authentication setup
  - Sudo restrictions
  - Sysctl kernel hardening
  - Kernel module blacklisting
  - File permission hardening
  - OpenSnitch firewall daemon setup
  - Polkit rule configuration
  - Immutable file flags

- **gtfobin.sh** - GTFOBins protection script that:
  - Removes dangerous packages
  - Blocks package reinstallation
  - Strips SUID/SGID bits from risky binaries
  - Strips capabilities from interpreters
  - Configures sudo restrictions

- **preseed.cfg** - Debian preseed configuration for automated secure installation with:
  - Full disk encryption (LUKS)
  - Secure partition layout
  - Minimal package selection
  - Hardened mount options

## Usage

> **Warning**: These scripts make significant changes to your system. Review them carefully before running and test in a non-production environment first.

```bash
# Run the main hardening script (requires root)
sudo bash sec.sh

# Run the GTFOBins protection script (requires root)
sudo bash gtfobin.sh
```

## Requirements

- Debian or Debian-based distribution
- Root privileges
- Hardware security key (YubiKey) for U2F authentication (optional but recommended)