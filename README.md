# Debian Testing/Forky Privacy, Security, and Hardening Guide

**Version:** 2.0
**Target:** Debian Testing (Forky) - Desktop Workstation
**Security Framework References:** GCHQ End User Device Guidance, UK MoD JSP 440, CIS Benchmarks, STIG

---

## Table of Contents

1. [Initial System Setup and Updates](#i-initial-system-setup-and-updates)
2. [Network Security](#ii-network-security)
3. [System Hardening](#iii-system-hardening)
4. [Authentication and Access Control](#iv-authentication-and-access-control)
5. [Privacy Enhancements](#v-privacy-enhancements)
6. [GCHQ/UK MoD Best Practices](#vi-gchquk-mod-best-practices)
7. [GTFOBins Protection](#vii-gtfobins-protection)
8. [Maintenance and Auditing](#viii-maintenance-and-auditing)

---

## I. Initial System Setup and Updates

### A. Automated Secure Installation (Preseed)

Use the provided `preseed.cfg` for automated installation with security defaults:

```bash
# Boot installer with preseed
# Add to kernel command line:
auto=true priority=critical url=http://your-server/preseed.cfg
```

**Key preseed security features:**
- LUKS full-disk encryption with LVM
- Separate partitions for `/`, `/home`, `/var`, `/var/log`, `/var/log/audit`, `/opt`, `/usr`
- Mount options: `noatime`, `nodev`, `nosuid`, `noexec` where appropriate
- `/boot` and `/usr` mounted read-only
- IPv6 disabled at kernel level
- UFW firewall enabled with deny-by-default policy
- Restrictive umask (077) configured system-wide
- Root login disabled; single unprivileged user with sudo

### B. System Updates

Always update before hardening:

```bash
# Update package lists and upgrade all packages
apt update && apt full-upgrade -y

# Remove orphaned packages
apt autoremove -y && apt autoclean
```

### C. APT Security Hardening

Create `/etc/apt/apt.conf.d/99-hardening`:

```
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::AutoRemove::RecommendsImportant "false";
APT::AutoRemove::SuggestsImportant "false";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "0";
APT::Sandbox::Seccomp "true";
```

**Explanation:**
- Prevents installation of unsigned/insecure packages
- Disables recommends/suggests to minimize attack surface
- Enables APT sandboxing with seccomp
- Disables unattended upgrades (manual control preferred for testing branch)

### D. User Account Security

**Restrict valid shells** - Edit `/etc/shells`:

```
/bin/bash
```

**Configure login defaults** - Edit `/etc/login.defs`:

```bash
# Use strong password hashing
ENCRYPT_METHOD YESCRYPT

# Restrict UID range
UID_MIN 1000
UID_MAX 60000

# Set restrictive umask
UMASK 077
```

**Set default shell for new users** - Edit `/etc/default/useradd`:

```
SHELL=/usr/sbin/nologin
```

**Configure session limits** - Create `/etc/security/limits.d/limits.conf`:

```
*           hard    nproc         2048
*            -      maxlogins     1
*            -      maxsyslogins  1
dev          -      maxlogins     1
dev          -      maxsyslogins  1
root         -      maxlogins     1
root         -      maxsyslogins  1
root        hard    nproc         65536
*           hard    core          0
```

**Auto-logout idle sessions** - Create `/etc/profile.d/autologout.sh`:

```bash
TMOUT=600
readonly TMOUT
export TMOUT
```

---

## II. Network Security

### A. Firewall Configuration (iptables)

Install required packages:

```bash
apt install -y iptables iptables-persistent netfilter-persistent
apt purge -y nftables
systemctl enable netfilter-persistent
```

**Complete iptables ruleset:**

```bash
#!/bin/bash
# Flush existing rules
iptables -F
iptables -X
iptables -Z
iptables -t nat -F
iptables -t nat -X
iptables -t nat -Z
iptables -t mangle -F
iptables -t mangle -X
iptables -t mangle -Z

# Default policies - DROP everything
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established/related connections
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Final drop rule
iptables -A INPUT -j DROP

# IPv6 - Complete lockdown
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
netfilter-persistent save
```

**Explanation:**
- Default DROP policy for all inbound traffic
- Only established connections allowed in (stateful inspection)
- IPv6 completely disabled at firewall level
- No inbound services exposed

### B. Application Firewall (OpenSnitch)

OpenSnitch provides per-application egress filtering:

```bash
apt install -y opensnitch python3-opensnitch-ui
```

**Configure systemd service** - Create `/etc/systemd/system/opensnitchd.service`:

```ini
[Unit]
Description=OpenSnitch Firewall Daemon
After=network.target
After=netfilter-persistent.service
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/opensnitchd -rules-path /etc/opensnitchd/rules -log-file /var/log/opensnitchd.log
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
mkdir -p /etc/opensnitchd/rules
chmod 750 /etc/opensnitchd
chmod 750 /etc/opensnitchd/rules
systemctl daemon-reload
systemctl enable --now opensnitchd.service
```

### C. TCP Wrappers

Configure host-based access control.

**Edit `/etc/hosts.allow`:**

```
ALL: LOCAL, 127.0.0.1
```

**Edit `/etc/hosts.deny`:**

```
ALL: ALL
```

```bash
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny
```

### D. Network Kernel Parameters

These are applied via sysctl (see Section III.A):

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `net.ipv4.icmp_echo_ignore_all` | 1 | Ignore ping requests |
| `net.ipv4.conf.all.rp_filter` | 1 | Reverse path filtering |
| `net.ipv4.conf.all.accept_redirects` | 0 | Ignore ICMP redirects |
| `net.ipv4.conf.all.send_redirects` | 0 | Don't send redirects |
| `net.ipv4.conf.all.accept_source_route` | 0 | Disable source routing |
| `net.ipv4.tcp_syncookies` | 1 | SYN flood protection |
| `net.ipv4.tcp_rfc1337` | 1 | TIME-WAIT assassination protection |
| `net.ipv4.ip_forward` | 0 | Disable routing |
| `net.ipv6.conf.all.disable_ipv6` | 1 | Disable IPv6 |

---

## III. System Hardening

### A. Kernel Hardening (Sysctl)

Create `/usr/lib/sysctl.d/sysctl.conf`:

```ini
# Kernel pointer/symbol protection
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1

# Disable dangerous kernel features
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
kernel.io_uring_disabled = 2

# Process isolation
kernel.yama.ptrace_scope = 3

# Core dump prevention
kernel.core_uses_pid = 1
kernel.suid_dumpable = 0
kernel.core_pattern = |/bin/false

# ASLR and exploit mitigations
kernel.randomize_va_space = 2
kernel.panic_on_oops = 1

# Performance event restrictions
kernel.perf_event_paranoid = 3
kernel.perf_cpu_time_max_percent = 1
kernel.perf_event_max_sample_rate = 1

# Memory protections
vm.mmap_min_addr = 65536
vm.unprivileged_userfaultfd = 0

# Filesystem protections
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 2

# Disable user namespaces (prevents container escapes)
kernel.unprivileged_userns_clone = 0

# TTY security
dev.tty.legacy_tiocsti = 0
dev.tty.ldisc_autoload = 0

# BPF JIT hardening
net.core.bpf_jit_enable = 0
net.core.bpf_jit_harden = 2

# Network hardening (see Section II.D for full list)
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```

Apply settings:

```bash
sysctl --system
```

### B. GRUB Bootloader Hardening

Edit `/etc/default/grub`:

```bash
GRUB_CMDLINE_LINUX_DEFAULT="mitigations=auto,nosmt spectre_v2=on spec_store_bypass_disable=on l1tf=full,force mds=full,nosmt tsx=off tsx_async_abort=full,nosmt mmio_stale_data=full,nosmt retbleed=auto,nosmt srbds=on gather_data_sampling=force reg_file_data_sampling=on intel_iommu=on iommu=force iommu.passthrough=0 iommu.strict=1 efi=disable_early_pci_dma lockdown=confidentiality init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on slab_nomerge vsyscall=none debugfs=off oops=panic module.sig_enforce=1 ipv6.disable=1 nosmt nowatchdog nmi_watchdog=0"
```

**CPU Vulnerability Mitigations Explained:**

| Parameter | Protection Against |
|-----------|-------------------|
| `mitigations=auto,nosmt` | Auto-enable all mitigations, disable SMT |
| `spectre_v2=on` | Spectre Variant 2 (Branch Target Injection) |
| `spec_store_bypass_disable=on` | Spectre Variant 4 |
| `l1tf=full,force` | L1 Terminal Fault (Foreshadow) |
| `mds=full,nosmt` | Microarchitectural Data Sampling |
| `tsx=off` | Disable TSX (ZombieLoad mitigation) |
| `tsx_async_abort=full,nosmt` | TSX Asynchronous Abort |
| `mmio_stale_data=full,nosmt` | MMIO Stale Data |
| `retbleed=auto,nosmt` | Retbleed |
| `srbds=on` | Special Register Buffer Data Sampling |
| `gather_data_sampling=force` | Downfall vulnerability |
| `reg_file_data_sampling=on` | Register File Data Sampling |

**Other Security Parameters:**

| Parameter | Purpose |
|-----------|---------|
| `intel_iommu=on iommu=force` | DMA attack protection |
| `lockdown=confidentiality` | Kernel lockdown mode |
| `init_on_alloc=1 init_on_free=1` | Zero memory on allocation/free |
| `page_alloc.shuffle=1` | Randomize page allocator |
| `randomize_kstack_offset=on` | Randomize kernel stack offset |
| `slab_nomerge` | Prevent slab merging |
| `vsyscall=none` | Disable vsyscall |
| `debugfs=off` | Disable debugfs |
| `module.sig_enforce=1` | Require signed kernel modules |

Apply changes:

```bash
update-grub
chmod 640 /etc/default/grub
chown root:root /etc/default/grub
```

### C. Kernel Module Blacklisting

Create `/etc/modprobe.d/harden.conf`:

```
# Wireless/Bluetooth (attack surface reduction)
blacklist bluetooth
install bluetooth /bin/false
blacklist btusb
install btusb /bin/false
blacklist cfg80211
install cfg80211 /bin/false
blacklist mac80211
install mac80211 /bin/false
blacklist iwlwifi
install iwlwifi /bin/false

# Firewire (DMA attacks)
blacklist firewire-core
install firewire-core /bin/false
blacklist firewire-ohci
install firewire-ohci /bin/false

# Thunderbolt (DMA attacks)
blacklist thunderbolt
install thunderbolt /bin/false

# USB Storage (data exfiltration)
blacklist usb_storage
install usb_storage /bin/false
blacklist uas
install uas /bin/false

# Virtualization (not needed on workstation)
blacklist kvm
install kvm /bin/false
blacklist kvm_intel
install kvm_intel /bin/false
blacklist kvm_amd
install kvm_amd /bin/false
blacklist vhost
install vhost /bin/false

# Deprecated/dangerous protocols
blacklist dccp
install dccp /bin/false
blacklist sctp
install sctp /bin/false
blacklist tipc
install tipc /bin/false
blacklist rds
install rds /bin/false
blacklist ax25
install ax25 /bin/false
blacklist netrom
install netrom /bin/false
blacklist x25
install x25 /bin/false
blacklist rose
install rose /bin/false
blacklist decnet
install decnet /bin/false
blacklist econet
install econet /bin/false

# Uncommon filesystems
blacklist cramfs
install cramfs /bin/false
blacklist freevxfs
install freevxfs /bin/false
blacklist hfs
install hfs /bin/false
blacklist hfsplus
install hfsplus /bin/false
blacklist jffs2
install jffs2 /bin/false
blacklist udf
install udf /bin/false
blacklist squashfs
install squashfs /bin/false

# Intel ME (if not needed)
blacklist mei
install mei /bin/false
blacklist mei_me
install mei_me /bin/false

# IPv6
blacklist ipv6
install ipv6 /bin/false

# Webcam (privacy)
blacklist uvcvideo
install uvcvideo /bin/false
```

### D. Disable Unnecessary Services

```bash
SERVICES_TO_DISABLE=(
    "accounts-daemon.service"
    "avahi-daemon.service"
    "avahi-daemon.socket"
    "bluetooth.service"
    "bluetooth.target"
    "cups.service"
    "cups.socket"
    "cups-browsed.service"
    "ModemManager.service"
    "ssh.service"
    "ssh.socket"
    "sshd.service"
    "docker.service"
    "docker.socket"
    "containerd.service"
    "snapd.service"
    "snapd.socket"
    "fwupd.service"
    "geoclue.service"
    "packagekit.service"
    "power-profiles-daemon.service"
    "rtkit-daemon.service"
    "switcheroo-control.service"
    "tracker-miner-fs-3.service"
    "udisks2.service"
    "wpa_supplicant.service"
)

for svc in "${SERVICES_TO_DISABLE[@]}"; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true
done
```

### E. Filesystem Mount Hardening

Add to `/etc/fstab`:

```
proc     /proc      proc      noatime,nodev,nosuid,noexec,hidepid=2,gid=proc    0 0
tmpfs    /tmp       tmpfs     size=2G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /var/tmp   tmpfs     size=1G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /dev/shm   tmpfs     size=512M,noatime,nodev,nosuid,noexec,mode=1777   0 0
tmpfs    /run       tmpfs     size=512M,noatime,nodev,nosuid,mode=0755          0 0
```

**Mount options explained:**

| Option | Purpose |
|--------|---------|
| `nodev` | Prevent device files |
| `nosuid` | Ignore SUID/SGID bits |
| `noexec` | Prevent execution |
| `hidepid=2` | Hide other users' processes |
| `noatime` | Don't update access times (performance + privacy) |

Create proc group and add users:

```bash
groupadd -f proc
gpasswd -a root proc
```

### F. Core Dump Prevention

Edit `/etc/systemd/coredump.conf`:

```ini
[Coredump]
ProcessSizeMax=0
Storage=none
```

Add to `/etc/profile`:

```bash
ulimit -c 0
```

---

## IV. Authentication and Access Control

### A. PAM Configuration with U2F-Only Authentication

This configuration removes password authentication entirely, requiring a U2F hardware token for all authentication.

**Prerequisites:**

```bash
apt install -y libpam-u2f pamu2fcfg
```

**Register U2F device:**

```bash
# As the target user, insert U2F device and run:
pamu2fcfg -u dev > /etc/security/u2f_keys

# Set permissions
chmod 0400 /etc/security/u2f_keys
chown root:root /etc/security/u2f_keys
```

**Configure faillock** - Create `/etc/security/faillock.conf`:

```
deny = 3
unlock_time = 900
fail_interval = 900
silent
```

**Main authentication** - `/etc/pam.d/common-auth`:

```
#%PAM-1.0
auth      required    pam_faildelay.so delay=3000000
auth      required    pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth      [success=1 default=bad] pam_u2f.so authfile=/etc/security/u2f_keys cue
auth      [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
auth      sufficient  pam_faillock.so authsucc deny=3 unlock_time=900 fail_interval=900
```

**Account management** - `/etc/pam.d/common-account`:

```
#%PAM-1.0
account   required    pam_faillock.so
account   required    pam_unix.so
```

**Disable password changes** - `/etc/pam.d/common-password`:

```
#%PAM-1.0
# Password changes disabled - U2F only system
password  requisite   pam_deny.so
```

**Session configuration** - `/etc/pam.d/common-session`:

```
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_unix.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
```

**Sudo with U2F** - `/etc/pam.d/sudo`:

```
#%PAM-1.0
auth      required    pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth      [success=1 default=bad] pam_u2f.so authfile=/etc/security/u2f_keys cue
auth      [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
auth      sufficient  pam_faillock.so authsucc deny=3 unlock_time=900 fail_interval=900
account   required    pam_faillock.so
account   include     common-account
session   required    pam_limits.so
session   include     common-session
```

**Deny SSH** - `/etc/pam.d/sshd`:

```
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
```

**Deny polkit** - `/etc/pam.d/polkit-1`:

```
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
```

**Catch-all deny** - `/etc/pam.d/other`:

```
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
```

### B. Sudo Hardening

Create `/etc/sudoers` (use `visudo`):

```
Defaults env_reset
Defaults !setenv
Defaults always_set_home
Defaults timestamp_timeout=0
Defaults passwd_timeout=0
Defaults passwd_tries=1
Defaults use_pty
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
Defaults logfile="/var/log/sudo.log"
Defaults log_input,log_output
Defaults editor=/bin/false
Defaults !env_editor

dev  ALL=(ALL) /usr/sbin/, /usr/bin/
```

**Explanation:**
- `timestamp_timeout=0` - Require authentication every time
- `passwd_tries=1` - Only one attempt allowed
- `use_pty` - Allocate PTY (prevents TTY hijacking)
- `log_input,log_output` - Full audit logging
- `editor=/bin/false` - Prevent editor-based escapes
- Limited to `/usr/sbin/` and `/usr/bin/` commands

### C. Access Control

**Restrict TTY access** - Create `/etc/security/access.conf`:

```
+:dev:tty1 tty2
-:ALL EXCEPT dev:tty1 tty2 tty3 tty4 tty5 tty6
-:ALL EXCEPT dev:LOCAL
-:dev:ALL EXCEPT LOCAL
-:root:ALL
-:ALL:REMOTE
-:ALL:ALL
```

**Empty securetty** - Clear `/etc/securetty`:

```bash
echo "" > /etc/securetty
chmod 600 /etc/securetty
```

**Restrict cron/at** - Only allow specific user:

```bash
echo "dev" > /etc/cron.allow
echo "dev" > /etc/at.allow
chmod 600 /etc/cron.allow
chmod 600 /etc/at.allow
```

### D. Polkit Lockdown

Create `/etc/polkit-1/rules.d/00-deny-all.rules`:

```javascript
// Deny all polkit requests - hardened system
polkit.addRule(function(action, subject) {
    return polkit.Result.NO;
});
```

---

## V. Privacy Enhancements

### A. DNS Privacy (DNS over HTTPS)

Use Librewolf browser with built-in DoH, or configure systemd-resolved:

**Install Librewolf (privacy-focused Firefox fork):**

```bash
apt install -y extrepo
extrepo enable librewolf
apt update
apt install -y librewolf --no-install-recommends
```

**Alternative: systemd-resolved with DoT:**

Edit `/etc/systemd/resolved.conf`:

```ini
[Resolve]
DNS=9.9.9.9#dns.quad9.net
DNSOverTLS=yes
DNSSEC=yes
FallbackDNS=
Cache=no-negative
```

### B. Data Encryption (LUKS Full Disk Encryption)

The preseed configuration creates:

```
/dev/nvme0n1p1 - 512MB - EFI System Partition
/dev/nvme0n1p2 - 1GB   - /boot (ext4, noexec, nosuid, nodev, ro)
/dev/nvme0n1p3 - LUKS encrypted LVM containing:
  ├─ lvg-root         - 20GB  - /         (ext4, nodev)
  ├─ lvg-var          - 10GB  - /var      (ext4, nodev, nosuid)
  ├─ lvg-var_log      - 5GB   - /var/log  (ext4, nodev, nosuid, noexec)
  ├─ lvg-var_log_audit- 5GB   - /var/log/audit (ext4, nodev, nosuid, noexec)
  ├─ lvg-home         - 2GB   - /home     (ext4, nodev, nosuid)
  ├─ lvg-opt          - 5GB   - /opt      (ext4, nodev, nosuid, noexec)
  └─ lvg-usr          - 20GB+ - /usr      (ext4, nodev, ro)
```

**Partition rationale:**
- Separate `/var/log` prevents log flooding DoS
- Separate `/var/log/audit` protects audit logs
- `/home` with `nosuid` prevents SUID attacks
- `/usr` read-only prevents binary tampering
- `/tmp` and `/var/tmp` as tmpfs (cleared on reboot)

### C. Browser Privacy (Librewolf)

Librewolf includes:
- uBlock Origin pre-installed
- Tracking protection enabled
- Telemetry disabled
- WebRTC leak protection
- Fingerprinting resistance

### D. Metadata Protection

**Disable file access time updates** (in fstab):

```
noatime
```

**Clear bash history:**

```bash
# Add to ~/.bashrc
unset HISTFILE
HISTSIZE=0
HISTFILESIZE=0
```

### E. Process Privacy

Hide other users' processes with `hidepid=2` in fstab:

```
proc  /proc  proc  hidepid=2,gid=proc  0 0
```

---

## VI. GCHQ/UK MoD Best Practices

### A. Principle of Least Privilege

**Implementation in this guide:**

1. **User accounts**: Single non-root user with sudo for specific paths only
2. **Services**: Masked unnecessary services, minimal packages installed
3. **Filesystem**: `noexec` on `/tmp`, `/var/tmp`, `/dev/shm`
4. **Capabilities**: Stripped from interpreters and GTFOBins
5. **SUID/SGID**: Removed except where absolutely necessary (sudo only)

**Sudo path restriction:**

```
dev  ALL=(ALL) /usr/sbin/, /usr/bin/
```

This limits sudo to system binaries only, preventing execution of arbitrary scripts.

### B. Defense in Depth

**Multiple security layers implemented:**

| Layer | Implementation |
|-------|----------------|
| Physical | LUKS encryption, no USB storage |
| Network | iptables (deny inbound), OpenSnitch (egress filtering) |
| Host | Kernel hardening, module blacklisting, sysctl |
| Application | Package denial list, GTFOBins protection |
| Authentication | U2F hardware tokens, faillock |
| Monitoring | Sudo logging, rsyslog, audit logs |

### C. Minimize Attack Surface

**Packages removed or blocked:**

```bash
# Categories blocked via apt preferences:
# - Development tools (gcc, g++, make, gdb, strace, ltrace)
# - Scripting languages (perl, python, ruby, php, lua, nodejs)
# - Network tools (netcat, nmap, tcpdump, wireshark, curl, wget)
# - Container/VM (docker, podman, lxc, qemu, virtualbox)
# - Remote access (ssh, telnet, rsh, vnc)
# - Wireless/Bluetooth (all drivers and utilities)
```

See `/etc/apt/preferences.d/deny.pref` for the complete list.

### D. Secure Configuration Management

**Immutable system files:**

```bash
# Critical files made immutable with chattr +i
# This prevents modification even by root without first removing the flag

chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow
chattr +i /etc/sudoers
chattr -R +i /etc/sudoers.d
chattr -R +i /etc/pam.d
chattr -R +i /etc/security
chattr -R +i /etc/sysctl.d
chattr -R +i /etc/modprobe.d
chattr -R +i /etc/iptables
chattr -R +i /etc/polkit-1
chattr -R +i /boot
chattr -R +i /usr
```

To modify protected files:

```bash
chattr -i /path/to/file
# Make changes
chattr +i /path/to/file
```

### E. Audit and Accountability

**Sudo logging:**

All sudo commands logged to `/var/log/sudo.log` with full input/output recording.

**Syslog:**

```bash
apt install -y rsyslog
systemctl enable rsyslog
```

**OpenSnitch logging:**

Application network activity logged to `/var/log/opensnitchd.log`.

---

## VII. GTFOBins Protection

GTFOBins are Unix binaries that can be exploited for privilege escalation, file operations, or shell escapes when given elevated privileges.

### A. Package Removal

The `gtfobin.sh` script removes packages containing dangerous binaries:

**Tier 1 (Highly Dangerous):**
- Network tools: nmap, netcat, socat, tcpdump, wireshark
- Attack tools: hydra, medusa, john, hashcat, sqlmap, nikto
- Remote access: telnet, rsh, ftp, tor, proxychains
- Containers: docker, podman, lxc, lxd, snapd, flatpak

**Tier 2 (High Risk):**
- Interpreters: ruby, php, lua, nodejs
- Debuggers: gdb, strace, ltrace, valgrind
- Compilers: gcc, g++, clang, make, rustc, cargo, golang
- Development: build-essential, cmake, meson

### B. SUID/SGID Bit Removal

```bash
# Find and remove SUID/SGID bits from all GTFOBins
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec chmod a-s {} \; 2>/dev/null

# Restore only sudo
chmod u+s /usr/bin/sudo
```

### C. Capability Stripping

```bash
# Strip capabilities from interpreters
for interp in /usr/bin/python3 /usr/bin/perl /usr/bin/ruby; do
    if [[ -f "$interp" ]]; then
        setcap -r "$interp" 2>/dev/null || true
    fi
done
```

### D. Sudo Command Restrictions

The `gtfobin.sh` script creates `/etc/sudoers.d/gtfobins-deny` which prevents sudo access to dangerous binaries:

```
Cmnd_Alias GTFOBINS = /usr/bin/vim, /usr/bin/less, /usr/bin/man, /usr/bin/awk, ...

ALL ALL = (ALL) ALL, !GTFOBINS
```

### E. Package Installation Blocking

Create `/etc/apt/preferences.d/gtfobins-block` to prevent future installation of dangerous packages with `Pin-Priority: -1`.

### F. Binary Placeholders

For binaries that were removed, create immutable placeholder files to prevent accidental reinstallation:

```bash
for binary in /usr/bin/perl /usr/bin/python /usr/bin/nc /usr/bin/nmap; do
    if [[ ! -e "$binary" ]]; then
        touch "$binary"
        chmod 000 "$binary"
        chattr +i "$binary"
    fi
done
```

---

## VIII. Maintenance and Auditing

### A. Regular Security Checks

**Find world-writable files:**

```bash
find / -xdev -type f -perm -0002 ! -path "/tmp/*" ! -path "/var/tmp/*" ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null
```

**Find unowned files:**

```bash
find / -xdev \( -nouser -o -nogroup \) ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null
```

**Find SUID/SGID binaries:**

```bash
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null
```

**Check for binaries with capabilities:**

```bash
getcap -r /usr /bin /sbin 2>/dev/null
```

### B. Log Review

```bash
# Sudo log
cat /var/log/sudo.log

# Authentication failures
cat /var/log/auth.log | grep -i fail

# OpenSnitch blocks
cat /var/log/opensnitchd.log | grep -i deny
```

### C. Unlocking Files for Updates

Before system updates:

```bash
# Unlock system directories
chattr -R -i /usr
chattr -R -i /boot
chattr -R -i /etc/apt

# Perform updates
apt update && apt full-upgrade -y

# Re-lock
chattr -R +i /usr
chattr -R +i /boot
chattr -R +i /etc/apt
```

### D. Backup U2F Keys

Store backup U2F keys in a secure location. Register multiple devices:

```bash
# Add additional key
pamu2fcfg -u dev -n >> /etc/security/u2f_keys
```

---

## Quick Start

1. **Fresh Install**: Boot with `preseed.cfg` for automated secure installation
2. **Post-Install Hardening**: Run `sec.sh` as root
3. **GTFOBins Protection**: Run `gtfobin.sh` as root
4. **Reboot**: Apply all changes with `systemctl reboot`

---

## File Reference

| File | Purpose |
|------|---------|
| `preseed.cfg` | Automated installer with LUKS, partitioning, UFW |
| `sec.sh` | Main hardening script (run post-install) |
| `gtfobin.sh` | GTFOBins protection module |

---

## Security Considerations

- **No remote access**: SSH is disabled and blocked. Physical access required.
- **No password auth**: U2F hardware token required for all authentication.
- **Read-only system**: `/usr` and `/boot` mounted read-only, critical files immutable.
- **No development tools**: Compilers, debuggers, and interpreters removed.
- **Egress filtering**: OpenSnitch prompts for all outbound connections.

This configuration is designed for high-security workstations where usability is secondary to security. Adjust based on your threat model and operational requirements.
