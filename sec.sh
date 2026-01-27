#!/bin/bash

set -euo pipefail
#!/usr/bin/env bash
#
# ============================================================================
#                        ULTRA-HARDENING SCRIPT 
# ============================================================================

set -euo pipefail

# ==============================================================================
# PAM HARDENING MODULE
# ==============================================================================

PRIMARY_USER="dev"
U2F_KEYS_DIR="/etc/security/u2f_keys"
BACKUP_DIR="/etc/pam.d.bak.$(date +%Y%m%d%H%M%S)"

# ------------------------------------------------------------------------------
# PREFLIGHT CHECKS
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root"
    exit 1
fi

if ! id "$PRIMARY_USER" &>/dev/null; then
    echo "[FATAL] User '$PRIMARY_USER' does not exist"
    exit 1
fi

if ! dpkg -l libpam-u2f &>/dev/null; then
    echo "[FATAL] libpam-u2f not installed. Run: apt install libpam-u2f"
    exit 1
fi

if [[ ! -f "${U2F_KEYS_DIR}/${PRIMARY_USER}" ]]; then
    echo "[FATAL] U2F key mapping not found at ${U2F_KEYS_DIR}/${PRIMARY_USER}"
    echo "        Register key first: pamu2fcfg -u${PRIMARY_USER} > ${U2F_KEYS_DIR}/${PRIMARY_USER}"
    exit 1
fi

# ------------------------------------------------------------------------------
# BACKUP EXISTING PAM CONFIG
# ------------------------------------------------------------------------------

echo "[*] Backing up /etc/pam.d to ${BACKUP_DIR}"
cp -a /etc/pam.d "${BACKUP_DIR}"

# ------------------------------------------------------------------------------
# PAM: U2F CONFIGURATION
# ------------------------------------------------------------------------------

echo "[*] Configuring U2F authfile permissions"
chmod 700 "$U2F_KEYS_DIR"
chmod 600 "${U2F_KEYS_DIR}/${PRIMARY_USER}"
chown root:root "$U2F_KEYS_DIR"
chown root:root "${U2F_KEYS_DIR}/${PRIMARY_USER}"

# ------------------------------------------------------------------------------
# PAM: common-auth (U2F-only, no password)
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/pam.d/common-auth"
cat > /etc/pam.d/common-auth << 'EOF'
# U2F-only authentication - no password fallback
auth    required                        pam_faildelay.so    delay=3000000
auth    required                        pam_faillock.so     preauth silent deny=3 unlock_time=900 fail_interval=900
auth    [success=1 default=ignore]      pam_u2f.so          authfile=/etc/security/u2f_keys/%u cue nouserok
auth    requisite                       pam_deny.so
auth    required                        pam_faillock.so     authfail deny=3 unlock_time=900 fail_interval=900
auth    required                        pam_permit.so
EOF

# ------------------------------------------------------------------------------
# PAM: common-account
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/pam.d/common-account"
cat > /etc/pam.d/common-account << 'EOF'
# Strict account controls
account required                        pam_access.so       accessfile=/etc/security/access.conf
account required                        pam_faillock.so
account required                        pam_nologin.so
account required                        pam_permit.so
EOF

# ------------------------------------------------------------------------------
# PAM: common-session
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/pam.d/common-session"
cat > /etc/pam.d/common-session << 'EOF'
# Hardened session configuration
session required                        pam_namespace.so
session required                        pam_limits.so
session required                        pam_umask.so        umask=0077
session required                        pam_env.so          readenv=1 user_readenv=0
session required                        pam_unix.so
session optional                        pam_systemd.so
EOF

# ------------------------------------------------------------------------------
# PAM: common-password (disabled - U2F only)
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/pam.d/common-password"
cat > /etc/pam.d/common-password << 'EOF'
# Password changes disabled - U2F-only system
password requisite                      pam_deny.so
EOF

# ------------------------------------------------------------------------------
# PAM: login
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/pam.d/login"
cat > /etc/pam.d/login << 'EOF'
# TTY login - U2F required
auth       required     pam_securetty.so
auth       required     pam_nologin.so
auth       include      common-auth
account    include      common-account
session    required     pam_loginuid.so
session    include      common-session
EOF

# ------------------------------------------------------------------------------
# PAM: sudo
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/pam.d/sudo"
cat > /etc/pam.d/sudo << 'EOF'
# sudo - U2F required, no password
auth       required     pam_u2f.so      authfile=/etc/security/u2f_keys/%u cue
auth       required     pam_faillock.so preauth silent deny=3 unlock_time=900
account    include      common-account
session    required     pam_limits.so
session    include      common-session
EOF

# ------------------------------------------------------------------------------
# PAM: su (locked down to wheel group only)
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/pam.d/su"
cat > /etc/pam.d/su << 'EOF'
# su - restricted to wheel group only, U2F required
# NOTE: Do NOT add 'deny' option - it reverses the logic
auth       required     pam_wheel.so    use_uid group=wheel
auth       sufficient   pam_rootok.so
auth       include      common-auth
account    include      common-account
session    include      common-session
EOF

# ------------------------------------------------------------------------------
# PAM: sshd (locked even if service disabled)
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/pam.d/sshd"
cat > /etc/pam.d/sshd << 'EOF'
# SSH - deny all (service should be disabled)
auth       requisite    pam_deny.so
account    requisite    pam_deny.so
session    requisite    pam_deny.so
EOF

# ------------------------------------------------------------------------------
# SECURITY: /etc/security/access.conf (single user only)
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/security/access.conf"
cat > /etc/security/access.conf << EOF
# Single-user access control
# Allow only 'dev' from local TTYs and console
+ : ${PRIMARY_USER} : LOCAL
+ : root : LOCAL
# Deny everyone else
- : ALL : ALL
EOF

chmod 644 /etc/security/access.conf

# ------------------------------------------------------------------------------
# SECURITY: /etc/security/limits.conf (strict limits)
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/security/limits.conf"
cat > /etc/security/limits.conf << EOF
# Strict resource limits - single user system

# Max logins and processes
${PRIMARY_USER}    hard    maxlogins       1
${PRIMARY_USER}    hard    maxsyslogins    1
${PRIMARY_USER}    hard    nproc           512
*                  hard    maxlogins       1
*                  hard    maxsyslogins    1

# Core dumps disabled
*                  hard    core            0

# Memory limits (adjust based on your 32GB/64GB RAM)
${PRIMARY_USER}    soft    as              16000000
${PRIMARY_USER}    hard    as              24000000

# File limits
${PRIMARY_USER}    soft    nofile          4096
${PRIMARY_USER}    hard    nofile          8192

# Priority limits
${PRIMARY_USER}    hard    nice            0
${PRIMARY_USER}    hard    rtprio          0

# Prevent forkbombs
*                  hard    nproc           256
root               hard    nproc           unlimited
EOF

chmod 644 /etc/security/limits.conf

# ------------------------------------------------------------------------------
# SECURITY: /etc/security/namespace.conf (polyinstantiation)
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/security/namespace.conf"
cat > /etc/security/namespace.conf << 'EOF'
# Polyinstantiated directories - private per session
/tmp        /tmp/.inst/         level       root,adm
/var/tmp    /var/tmp/.inst/     level       root,adm
EOF

chmod 644 /etc/security/namespace.conf

# Create polyinstantiation parent dirs
mkdir -p /tmp/.inst /var/tmp/.inst
chmod 000 /tmp/.inst /var/tmp/.inst

# ------------------------------------------------------------------------------
# SECURITY: /etc/security/namespace.init (initialize polyinst dirs)
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/security/namespace.init"
cat > /etc/security/namespace.init << 'EOF'
#!/bin/bash
# Initialize polyinstantiated directory
/bin/mount -t tmpfs -o size=256M,mode=1777,noexec,nosuid,nodev tmpfs "$1"
EOF

chmod 755 /etc/security/namespace.init

# ------------------------------------------------------------------------------
# SECURITY: /etc/securetty (restrict root TTYs)
# ------------------------------------------------------------------------------

echo "[*] Writing /etc/securetty"
cat > /etc/securetty << 'EOF'
# Root login only allowed on tty1 (emergency only)
tty1
EOF

chmod 600 /etc/securetty

# ------------------------------------------------------------------------------
# WHEEL GROUP: Ensure it exists and add primary user
# ------------------------------------------------------------------------------

echo "[*] Configuring wheel group"
if ! getent group wheel &>/dev/null; then
    groupadd wheel
fi
usermod -aG wheel "$PRIMARY_USER"

# ------------------------------------------------------------------------------
# FAILLOCK DIRECTORY
# ------------------------------------------------------------------------------

echo "[*] Creating faillock directory"
mkdir -p /var/run/faillock
chmod 755 /var/run/faillock

# ------------------------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------------------------

echo ""
echo "[+] PAM hardening complete"
echo ""
echo "    CRITICAL: Test authentication in a separate TTY before logging out!"
echo "    1. Switch to TTY2: Ctrl+Alt+F2"
echo "    2. Attempt login as '${PRIMARY_USER}' with your U2F key"
echo "    3. Verify sudo works: sudo whoami"
echo ""
echo "    Backup location: ${BACKUP_DIR}"
echo "    To rollback: cp -a ${BACKUP_DIR}/* /etc/pam.d/"
echo ""


# Kernel Parameters Hardening Module
# Target: Debian 12+ / ThinkPad P16s Gen 2 / Intel 13th Gen
# Policy: Maximum lockdown while preserving Mullvad VPN, OpenSnitch, browser A/V
#


SYSCTL_HARDENED="/etc/sysctl.d/99-hardened.conf"
MODPROBE_BLACKLIST="/etc/modprobe.d/blacklist-hardened.conf"
GRUB_HARDENED="/etc/default/grub.d/99-hardened.cfg"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

# ------------------------------------------------------------------------------
# PREFLIGHT
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root"
    exit 1
fi

# ------------------------------------------------------------------------------
# BACKUP
# ------------------------------------------------------------------------------

echo "[*] Backing up existing configs"
[[ -f /etc/default/grub ]] && cp /etc/default/grub "/etc/default/grub${BACKUP_SUFFIX}"
[[ -f "$SYSCTL_HARDENED" ]] && cp "$SYSCTL_HARDENED" "${SYSCTL_HARDENED}${BACKUP_SUFFIX}"
[[ -f "$MODPROBE_BLACKLIST" ]] && cp "$MODPROBE_BLACKLIST" "${MODPROBE_BLACKLIST}${BACKUP_SUFFIX}"

# ------------------------------------------------------------------------------
# GRUB: Kernel Boot Parameters
# ------------------------------------------------------------------------------

echo "[*] Writing ${GRUB_HARDENED}"
mkdir -p /etc/default/grub.d

cat > "$GRUB_HARDENED" << 'EOF'
# Hardened kernel boot parameters
# ThinkPad P16s Gen 2 / Intel 13th Gen

GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX \
    # CPU vulnerability mitigations (paranoid) \
    mitigations=auto,nosmt \
    spectre_v2=on \
    spec_store_bypass_disable=on \
    l1tf=full,force \
    mds=full,nosmt \
    tsx=off \
    tsx_async_abort=full,nosmt \
    mmio_stale_data=full,nosmt \
    retbleed=auto,nosmt \
    srbds=on \
    gather_data_sampling=force \
    reg_file_data_sampling=on \
    \
    # IOMMU / DMA protection \
    intel_iommu=on \
    iommu=force \
    iommu.passthrough=0 \
    iommu.strict=1 \
    efi=disable_early_pci_dma \
    \
    # Kernel lockdown \
    lockdown=confidentiality \
    \
    # Memory protections \
    init_on_alloc=1 \
    init_on_free=1 \
    page_alloc.shuffle=1 \
    randomize_kstack_offset=on \
    slab_nomerge \
    \
    # Disable dangerous features \
    vsyscall=none \
    debugfs=off \
    oops=panic \
    \
    # Module hardening \
    module.sig_enforce=1 \
    \
    # IPv6 disabled entirely \
    ipv6.disable=1 \
    \
    # Disable legacy/unnecessary \
    nosmt \
    nmi_watchdog=0 \
    nowatchdog \
    quiet \
    loglevel=0"
EOF

# Clean up the multiline for GRUB (remove comments and collapse)
echo "[*] Generating clean GRUB config"
cat > "$GRUB_HARDENED" << 'EOF'
# Hardened kernel boot parameters - ThinkPad P16s Gen 2 / Intel 13th Gen
GRUB_CMDLINE_LINUX_DEFAULT="quiet loglevel=0"
GRUB_CMDLINE_LINUX="mitigations=auto,nosmt spectre_v2=on spec_store_bypass_disable=on l1tf=full,force mds=full,nosmt tsx=off tsx_async_abort=full,nosmt mmio_stale_data=full,nosmt retbleed=auto,nosmt srbds=on gather_data_sampling=force reg_file_data_sampling=on intel_iommu=on iommu=force iommu.passthrough=0 iommu.strict=1 efi=disable_early_pci_dma lockdown=confidentiality init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on slab_nomerge vsyscall=none debugfs=off oops=panic module.sig_enforce=1 ipv6.disable=1 nosmt nowatchdog nmi_watchdog=0"
EOF

# ------------------------------------------------------------------------------
# SYSCTL: Runtime Kernel Parameters
# ------------------------------------------------------------------------------

echo "[*] Writing ${SYSCTL_HARDENED}"
cat > "$SYSCTL_HARDENED" << 'EOF'
# =============================================================================
# HARDENED SYSCTL - Runtime Kernel Parameters
# ThinkPad P16s Gen 2 / Intel 13th Gen
# Policy: Maximum security, single-user, local-only, Mullvad+OpenSnitch compat
# =============================================================================

# -----------------------------------------------------------------------------
# KERNEL: Core Security
# -----------------------------------------------------------------------------

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict dmesg to root only
kernel.dmesg_restrict = 1

# Restrict perf_event (performance counters - side-channel risk)
kernel.perf_event_paranoid = 3

# Disable kexec (loading new kernel at runtime)
kernel.kexec_load_disabled = 1

# Restrict eBPF to CAP_BPF (root)
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Disable SysRq (magic keys)
kernel.sysrq = 0

# Restrict ptrace to parent processes only (breaks some debuggers, but secure)
kernel.yama.ptrace_scope = 2

# ASLR: Full randomization
kernel.randomize_va_space = 2

# Restrict user namespaces (browser sandboxing - keep enabled but restricted)
# Note: Chromium/Firefox need this for sandboxing, so we allow but log
kernel.unprivileged_userns_clone = 1

# Core dumps: disabled
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0

# -----------------------------------------------------------------------------
# FILESYSTEM: Protections
# -----------------------------------------------------------------------------

# Symlink/hardlink protections
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# FIFO/regular file protections (prevent attacks via shared dirs)
fs.protected_fifos = 2
fs.protected_regular = 2

# -----------------------------------------------------------------------------
# NETWORK: IPv4 Hardening (IPv6 disabled at boot)
# -----------------------------------------------------------------------------

# Disable IP forwarding (not a router)
net.ipv4.ip_forward = 0

# Disable source routing (prevent spoofed packets)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirects (MITM prevention)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable reverse path filtering (strict mode - anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log martian packets (impossible addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP echo requests (ping)
net.ipv4.icmp_echo_ignore_all = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

# TIME-WAIT assassination protection
net.ipv4.tcp_rfc1337 = 1

# Disable TCP timestamps (fingerprinting prevention)
net.ipv4.tcp_timestamps = 0

# Disable SACK (potential vulnerabilities, minor perf hit)
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0

# Restrict local port range (reduce fingerprinting)
net.ipv4.ip_local_port_range = 32768 60999

# Restrict unprivileged ports
net.ipv4.ip_unprivileged_port_start = 1024

# -----------------------------------------------------------------------------
# NETWORK: IPv6 Disabled (belt and suspenders with boot param)
# -----------------------------------------------------------------------------

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# -----------------------------------------------------------------------------
# NETWORK: Netfilter (OpenSnitch compatibility)
# -----------------------------------------------------------------------------

# Connection tracking max (adjust if needed for heavy browsing)
net.netfilter.nf_conntrack_max = 131072

# Timeout tuning (security vs usability balance)
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60

# -----------------------------------------------------------------------------
# MEMORY: Hardening
# -----------------------------------------------------------------------------

# Restrict mmap minimum address (NULL deref protection)
vm.mmap_min_addr = 65536

# Randomize mmap base
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16

# Restrict kernel logs in console
kernel.printk = 3 3 3 3

# Disable magic sysrq completely
kernel.sysrq = 0

# OOM killer: prefer killing processes over system panic
vm.panic_on_oom = 0
vm.oom_kill_allocating_task = 1

# Swappiness: minimize swap usage (reduce data leakage to disk)
vm.swappiness = 1

# Dirty ratio: limit dirty pages (reduce data in RAM waiting to write)
vm.dirty_ratio = 5
vm.dirty_background_ratio = 3

EOF

chmod 600 "$SYSCTL_HARDENED"

# ------------------------------------------------------------------------------
# MODPROBE: Blacklist Dangerous/Unnecessary Modules
# ------------------------------------------------------------------------------

echo "[*] Writing ${MODPROBE_BLACKLIST}"
cat > "$MODPROBE_BLACKLIST" << 'EOF'
# =============================================================================
# MODULE BLACKLIST - Hardened System
# Disable dangerous, legacy, and unnecessary kernel modules
# =============================================================================

# -----------------------------------------------------------------------------
# NETWORK: Dangerous/Legacy Protocols
# -----------------------------------------------------------------------------

# Datagram Congestion Control Protocol (rarely used, attack surface)
install dccp /bin/false
blacklist dccp

# Stream Control Transmission Protocol
install sctp /bin/false
blacklist sctp

# Reliable Datagram Sockets
install rds /bin/false
blacklist rds

# Transparent Inter-Process Communication
install tipc /bin/false
blacklist tipc

# Asynchronous Transfer Mode
install atm /bin/false
blacklist atm

# DECnet
install decnet /bin/false
blacklist decnet

# Econet
install econet /bin/false
blacklist econet

# AppleTalk
install appletalk /bin/false
blacklist appletalk

# IPX
install ipx /bin/false
blacklist ipx

# NetROM / AX.25 (amateur radio)
install netrom /bin/false
install ax25 /bin/false
install rose /bin/false
blacklist netrom
blacklist ax25
blacklist rose

# PSNAP / P8022 / LLC2
install psnap /bin/false
install p8022 /bin/false
install p8023 /bin/false
blacklist psnap
blacklist p8022
blacklist p8023

# CAN bus
install can /bin/false
blacklist can

# -----------------------------------------------------------------------------
# FILESYSTEMS: Uncommon/Legacy
# -----------------------------------------------------------------------------

install cramfs /bin/false
blacklist cramfs

install freevxfs /bin/false
blacklist freevxfs

install jffs2 /bin/false
blacklist jffs2

install hfs /bin/false
blacklist hfs

install hfsplus /bin/false
blacklist hfsplus

install udf /bin/false
blacklist udf

install squashfs /bin/false
blacklist squashfs

install f2fs /bin/false
blacklist f2fs

install gfs2 /bin/false
blacklist gfs2

install cifs /bin/false
blacklist cifs

install nfs /bin/false
blacklist nfs

install nfsv3 /bin/false
blacklist nfsv3

install nfsv4 /bin/false
blacklist nfsv4

install ksmbd /bin/false
blacklist ksmbd

# -----------------------------------------------------------------------------
# HARDWARE: FireWire (DMA attacks)
# -----------------------------------------------------------------------------

install firewire-core /bin/false
install firewire-ohci /bin/false
install firewire-sbp2 /bin/false
install firewire-net /bin/false
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2
blacklist firewire-net
blacklist ohci1394
blacklist sbp2
blacklist dv1394
blacklist raw1394
blacklist video1394

# -----------------------------------------------------------------------------
# HARDWARE: Thunderbolt (DMA attacks - uncomment if you don't use TB)
# -----------------------------------------------------------------------------

# Uncomment these if you don't use Thunderbolt devices:
# install thunderbolt /bin/false
# blacklist thunderbolt

# -----------------------------------------------------------------------------
# HARDWARE: Bluetooth (disabled - not needed for local-only system)
# -----------------------------------------------------------------------------

install bluetooth /bin/false
install btusb /bin/false
install btrtl /bin/false
install btbcm /bin/false
install btintel /bin/false
blacklist bluetooth
blacklist btusb
blacklist btrtl
blacklist btbcm
blacklist btintel
blacklist bnep
blacklist hidp
blacklist rfcomm

# -----------------------------------------------------------------------------
# HARDWARE: Webcam (disable if not needed)
# -----------------------------------------------------------------------------

# Uncomment to disable webcam:
# install uvcvideo /bin/false
# blacklist uvcvideo

# -----------------------------------------------------------------------------
# HARDWARE: Legacy/Unnecessary
# -----------------------------------------------------------------------------

# Floppy
install floppy /bin/false
blacklist floppy

# PC speaker (beep)
install pcspkr /bin/false
blacklist pcspkr

# Intel Management Engine (reduce attack surface)
install mei /bin/false
install mei_me /bin/false
blacklist mei
blacklist mei_me

# -----------------------------------------------------------------------------
# VIRTUALIZATION: Disable if not used
# -----------------------------------------------------------------------------

install kvm /bin/false
install kvm_intel /bin/false
blacklist kvm
blacklist kvm_intel

install vboxdrv /bin/false
install vboxnetflt /bin/false
install vboxnetadp /bin/false
blacklist vboxdrv
blacklist vboxnetflt
blacklist vboxnetadp

# -----------------------------------------------------------------------------
# INPUT: Disable unused input drivers
# -----------------------------------------------------------------------------

# Joystick (unless you use one)
install joydev /bin/false
blacklist joydev

# PC speaker via input
install snd_pcsp /bin/false
blacklist snd_pcsp

# -----------------------------------------------------------------------------
# IPv6 Module (belt and suspenders)
# -----------------------------------------------------------------------------

install ipv6 /bin/false
blacklist ipv6

# -----------------------------------------------------------------------------
# MISC: Rarely needed, attack surface
# -----------------------------------------------------------------------------

# Vivid (virtual video test driver)
install vivid /bin/false
blacklist vivid

# USB gadget (OTG mode - not needed on laptop)
install usb_gadget /bin/false
blacklist usb_gadget

# CDROM
install cdrom /bin/false
install sr_mod /bin/false
blacklist cdrom
blacklist sr_mod

EOF

chmod 600 "$MODPROBE_BLACKLIST"

# ------------------------------------------------------------------------------
# APPLY SYSCTL NOW
# ------------------------------------------------------------------------------

echo "[*] Applying sysctl parameters"
sysctl --system

# ------------------------------------------------------------------------------
# UPDATE GRUB
# ------------------------------------------------------------------------------

echo "[*] Updating GRUB configuration"
update-grub

# ------------------------------------------------------------------------------
# UPDATE INITRAMFS (to pick up module blacklists)
# ------------------------------------------------------------------------------

echo "[*] Updating initramfs"
update-initramfs -u -k all

# ------------------------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------------------------

echo ""
echo "[+] Kernel hardening complete"
echo ""
echo "    REQUIRED: Reboot to apply boot parameters"
echo ""
echo "    Post-reboot verification:"
echo "      cat /proc/cmdline                    # Check boot params"
echo "      sysctl kernel.kptr_restrict          # Should be 2"
echo "      sysctl kernel.dmesg_restrict         # Should be 1"
echo "      lsmod | grep -E 'dccp|sctp|bluetooth' # Should be empty"
echo "      cat /sys/kernel/security/lockdown   # Should show 'confidentiality'"
echo ""
echo "    If Mullvad fails after reboot, verify wireguard module loads:"
echo "      modprobe wireguard && lsmod | grep wireguard"
echo ""
echo "    If OpenSnitch fails, verify nfnetlink modules:"
echo "      lsmod | grep nf"
echo ""

#

# Filesystem Hardening Module
# Target: Debian 12+ / ThinkPad P16s Gen 2
# Policy: Restrictive mounts, tight permissions, single-user (dev)
#


PRIMARY_USER="dev"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

# ------------------------------------------------------------------------------
# PREFLIGHT
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root"
    exit 1
fi

if ! id "$PRIMARY_USER" &>/dev/null; then
    echo "[FATAL] User '$PRIMARY_USER' does not exist"
    exit 1
fi

# ------------------------------------------------------------------------------
# BACKUP
# ------------------------------------------------------------------------------

echo "[*] Backing up /etc/fstab"
cp /etc/fstab "/etc/fstab${BACKUP_SUFFIX}"

# ------------------------------------------------------------------------------
# FSTAB: Hardened mount options
# ------------------------------------------------------------------------------

echo "[*] Configuring hardened mount options in /etc/fstab"

# Function to add/update mount options for a given mount point
update_fstab_options() {
    local mount_point="$1"
    local new_options="$2"
    
    if grep -qE "^[^#].*\s${mount_point}\s" /etc/fstab; then
        echo "    [+] Updating options for ${mount_point}"
        # This is complex - we'll handle it via separate tmpfs entries instead
    else
        echo "    [*] ${mount_point} not in fstab, will add if needed"
    fi
}

# Create hardened fstab entries for tmpfs mounts
# These override or supplement existing entries

cat >> /etc/fstab << 'EOF'

# =============================================================================
# HARDENED MOUNT OPTIONS - Added by filesystem hardening script
# =============================================================================

# /tmp - tmpfs with noexec, nosuid, nodev (size limit prevents RAM exhaustion)
tmpfs   /tmp        tmpfs   defaults,noexec,nosuid,nodev,size=2G,mode=1777   0 0

# /var/tmp - tmpfs with noexec, nosuid, nodev
tmpfs   /var/tmp    tmpfs   defaults,noexec,nosuid,nodev,size=1G,mode=1777   0 0

# /dev/shm - restrict shared memory
tmpfs   /dev/shm    tmpfs   defaults,noexec,nosuid,nodev,size=1G            0 0

# /run - already tmpfs but ensure options
tmpfs   /run        tmpfs   defaults,nosuid,nodev,size=512M,mode=0755       0 0

EOF

# ------------------------------------------------------------------------------
# FSTAB: Harden existing mount points via remount options
# We'll create a systemd unit to apply these at boot
# ------------------------------------------------------------------------------

echo "[*] Creating systemd service for mount hardening"

cat > /etc/systemd/system/mount-hardening.service << 'EOF'
[Unit]
Description=Apply hardened mount options
After=local-fs.target
Before=sysinit.target

[Service]
Type=oneshot
RemainAfterExit=yes

# Remount /boot as read-only with noexec (if separate partition)
ExecStart=/bin/bash -c 'mountpoint -q /boot && mount -o remount,ro,noexec,nosuid,nodev /boot || true'

# Remount /home with noexec if you want maximum restriction
# Comment out if you need to run scripts from home
# ExecStart=/bin/bash -c 'mountpoint -q /home && mount -o remount,nosuid,nodev /home || true'

# Remount /var with nosuid,nodev
ExecStart=/bin/bash -c 'mountpoint -q /var && mount -o remount,nosuid,nodev /var || true'

# Remount /var/log with noexec,nosuid,nodev
ExecStart=/bin/bash -c 'mountpoint -q /var/log && mount -o remount,noexec,nosuid,nodev /var/log || true'

# Ensure /proc is restricted
ExecStart=/bin/mount -o remount,hidepid=2 /proc

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mount-hardening.service

# ------------------------------------------------------------------------------
# PROC: Hide process information from other users
# ------------------------------------------------------------------------------

echo "[*] Restricting /proc visibility"

# Add hidepid option for /proc
if ! grep -q "hidepid=2" /etc/fstab; then
    cat >> /etc/fstab << 'EOF'

# /proc - hide process info from non-owners
proc    /proc       proc    defaults,hidepid=2,gid=0                        0 0
EOF
fi

# ------------------------------------------------------------------------------
# PERMISSIONS: /root
# ------------------------------------------------------------------------------

echo "[*] Hardening /root permissions"
chmod 700 /root
chown root:root /root

# ------------------------------------------------------------------------------
# PERMISSIONS: /home/dev
# ------------------------------------------------------------------------------

echo "[*] Hardening /home/${PRIMARY_USER} permissions"
chmod 700 "/home/${PRIMARY_USER}"
chown "${PRIMARY_USER}:${PRIMARY_USER}" "/home/${PRIMARY_USER}"

# Remove world-readable from all files in home
find "/home/${PRIMARY_USER}" -type f -exec chmod o-rwx {} \; 2>/dev/null || true
find "/home/${PRIMARY_USER}" -type d -exec chmod o-rwx {} \; 2>/dev/null || true

# ------------------------------------------------------------------------------
# PERMISSIONS: /etc sensitive files
# ------------------------------------------------------------------------------

echo "[*] Hardening /etc sensitive file permissions"

# Shadow and gshadow - root only
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chown root:root /etc/shadow
chown root:root /etc/gshadow

# passwd and group - readable but not writable
chmod 644 /etc/passwd
chmod 644 /etc/group
chown root:root /etc/passwd
chown root:root /etc/group

# sudoers and sudoers.d
chmod 440 /etc/sudoers
chown root:root /etc/sudoers
chmod 750 /etc/sudoers.d
chown root:root /etc/sudoers.d
find /etc/sudoers.d -type f -exec chmod 440 {} \;

# PAM configuration
chmod 644 /etc/pam.d/*
chown root:root /etc/pam.d/*

# Security directory
chmod 600 /etc/security/access.conf
chmod 600 /etc/security/limits.conf
chmod 600 /etc/security/namespace.conf
chown root:root /etc/security/*

# SSH directory (even if service disabled)
if [[ -d /etc/ssh ]]; then
    chmod 700 /etc/ssh
    chmod 600 /etc/ssh/*_key 2>/dev/null || true
    chmod 644 /etc/ssh/*.pub 2>/dev/null || true
    chmod 644 /etc/ssh/sshd_config 2>/dev/null || true
    chown -R root:root /etc/ssh
fi

# Cron directories
chmod 700 /etc/cron.d 2>/dev/null || true
chmod 700 /etc/cron.daily 2>/dev/null || true
chmod 700 /etc/cron.hourly 2>/dev/null || true
chmod 700 /etc/cron.weekly 2>/dev/null || true
chmod 700 /etc/cron.monthly 2>/dev/null || true
chmod 600 /etc/crontab 2>/dev/null || true

# AT deny - if at is installed, deny non-root
if [[ -f /etc/at.deny ]]; then
    chmod 600 /etc/at.deny
fi

# ------------------------------------------------------------------------------
# PERMISSIONS: /boot
# ------------------------------------------------------------------------------

echo "[*] Hardening /boot permissions"
chmod 755 /boot
chown root:root /boot

# Restrict kernel and initramfs
find /boot -type f -name "vmlinuz*" -exec chmod 600 {} \;
find /boot -type f -name "initrd*" -exec chmod 600 {} \;
find /boot -type f -name "System.map*" -exec chmod 600 {} \;
find /boot -type f -name "config-*" -exec chmod 600 {} \;

# GRUB config
if [[ -f /boot/grub/grub.cfg ]]; then
    chmod 600 /boot/grub/grub.cfg
    chown root:root /boot/grub/grub.cfg
fi

# ------------------------------------------------------------------------------
# PERMISSIONS: World-writable files audit and fix
# ------------------------------------------------------------------------------

echo "[*] Checking for world-writable files (excluding /tmp, /var/tmp, /proc, /sys)"
WORLD_WRITABLE=$(find / -xdev -type f -perm -0002 \
    ! -path "/tmp/*" \
    ! -path "/var/tmp/*" \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    2>/dev/null || true)

if [[ -n "$WORLD_WRITABLE" ]]; then
    echo "[!] Found world-writable files:"
    echo "$WORLD_WRITABLE"
    echo "[*] Removing world-writable bit from these files"
    echo "$WORLD_WRITABLE" | xargs -r chmod o-w
fi

# ------------------------------------------------------------------------------
# PERMISSIONS: Unowned files audit
# ------------------------------------------------------------------------------

echo "[*] Checking for unowned files"
UNOWNED=$(find / -xdev \( -nouser -o -nogroup \) \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    2>/dev/null || true)

if [[ -n "$UNOWNED" ]]; then
    echo "[!] Found unowned files (review manually):"
    echo "$UNOWNED"
fi

# ------------------------------------------------------------------------------
# PERMISSIONS: SUID/SGID audit
# ------------------------------------------------------------------------------

echo "[*] Auditing SUID/SGID binaries"
SUID_SGID_FILE="/var/lib/suid-sgid-audit.txt"

find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    2>/dev/null > "$SUID_SGID_FILE"

echo "[*] SUID/SGID binaries saved to ${SUID_SGID_FILE}"
echo "[*] Review and remove unnecessary SUID/SGID bits with: chmod u-s <file> or chmod g-s <file>"

# Common SUID binaries to consider removing (uncomment if you don't need them)
echo "[*] Optionally disable unnecessary SUID binaries:"

# Disable mount/umount for non-root (uncomment if not needed)
# chmod u-s /usr/bin/mount 2>/dev/null || true
# chmod u-s /usr/bin/umount 2>/dev/null || true

# Disable chfn/chsh (change finger info/shell - rarely needed)
chmod u-s /usr/bin/chfn 2>/dev/null || true
chmod u-s /usr/bin/chsh 2>/dev/null || true

# Disable newgrp (change group - rarely needed)
chmod u-s /usr/bin/newgrp 2>/dev/null || true

# Disable wall (write to all users - rarely needed on single-user)
chmod g-s /usr/bin/wall 2>/dev/null || true

# ------------------------------------------------------------------------------
# CORE DUMPS: Filesystem-level prevention
# ------------------------------------------------------------------------------

echo "[*] Disabling core dumps at filesystem level"

# Create directory that prevents core dumps
mkdir -p /var/crash
chmod 0000 /var/crash

# Systemd coredump config
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

# ------------------------------------------------------------------------------
# STICKY BIT: Ensure on world-writable dirs
# ------------------------------------------------------------------------------

echo "[*] Ensuring sticky bit on world-writable directories"
find / -xdev -type d -perm -0002 \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    -exec chmod +t {} \; 2>/dev/null || true

# ------------------------------------------------------------------------------
# IMMUTABLE FLAGS: Critical configs (optional - uncomment to enable)
# WARNING: These prevent ANY modification, including by root, until removed
# ------------------------------------------------------------------------------

echo "[*] Immutable flags (optional section - review before enabling)"

# Uncomment these lines to make configs immutable:
# echo "    [+] Making /etc/passwd immutable"
# chattr +i /etc/passwd

# echo "    [+] Making /etc/shadow immutable"  
# chattr +i /etc/shadow

# echo "    [+] Making /etc/group immutable"
# chattr +i /etc/group

# echo "    [+] Making /etc/gshadow immutable"
# chattr +i /etc/gshadow

# echo "    [+] Making /etc/sudoers immutable"
# chattr +i /etc/sudoers

# echo "    [+] Making /boot/grub/grub.cfg immutable"
# chattr +i /boot/grub/grub.cfg

# To remove immutable flag later: chattr -i <file>

# ------------------------------------------------------------------------------
# UMASK: System-wide restrictive default
# ------------------------------------------------------------------------------

echo "[*] Setting restrictive system-wide umask"

# /etc/profile.d drop-in
cat > /etc/profile.d/umask.sh << 'EOF'
# Restrictive umask - files created with 600, dirs with 700
umask 077
EOF

chmod 644 /etc/profile.d/umask.sh

# Also set in /etc/login.defs
if [[ -f /etc/login.defs ]]; then
    sed -i 's/^UMASK.*/UMASK 077/' /etc/login.defs
fi

# ------------------------------------------------------------------------------
# RESTRICT COMPILERS (optional - uncomment if not needed)
# ------------------------------------------------------------------------------

# Uncomment to restrict access to compilers (prevents local exploit compilation)
# echo "[*] Restricting compiler access"
# if [[ -f /usr/bin/gcc ]]; then
#     chmod 700 /usr/bin/gcc
#     chown root:root /usr/bin/gcc
# fi
# if [[ -f /usr/bin/g++ ]]; then
#     chmod 700 /usr/bin/g++
#     chown root:root /usr/bin/g++
# fi
# if [[ -f /usr/bin/make ]]; then
#     chmod 700 /usr/bin/make
#     chown root:root /usr/bin/make
# fi

# ------------------------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------------------------

echo ""
echo "[+] Filesystem hardening complete"
echo ""
echo "    REQUIRED: Reboot to apply mount changes"
echo ""
echo "    Post-reboot verification:"
echo "      mount | grep -E 'tmp|shm'       # Check noexec,nosuid,nodev"
echo "      mount | grep /boot              # Check ro,noexec"
echo "      ls -la /root                    # Should be drwx------"
echo "      ls -la /home/${PRIMARY_USER}    # Should be drwx------"
echo "      cat /proc/self/mountinfo | grep hidepid  # Should show hidepid=2"
echo ""
echo "    SUID/SGID audit saved to: ${SUID_SGID_FILE}"
echo "    Review and remove unnecessary setuid bits as needed"
echo ""
echo "    If /boot remount fails (not separate partition), edit:"
echo "      /etc/systemd/system/mount-hardening.service"
echo ""
echo "    Immutable flags section is commented out - enable manually if desired"
echo ""

# ==============================================================================
# SERVICES HARDENING MODULE
# ==============================================================================
# Target: Debian 12+ / GNOME Wayland / ThinkPad P16s Gen 2
# Policy: Minimal attack surface, disable everything non-essential
#

BACKUP_DIR="/root/services-backup-$(date +%Y%m%d%H%M%S)"

# ------------------------------------------------------------------------------
# PREFLIGHT
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root"
    exit 1
fi

# ------------------------------------------------------------------------------
# BACKUP: Current service states
# ------------------------------------------------------------------------------

echo "[*] Backing up current service states to ${BACKUP_DIR}"
mkdir -p "$BACKUP_DIR"
systemctl list-unit-files --type=service > "${BACKUP_DIR}/services-before.txt"
systemctl list-unit-files --type=socket > "${BACKUP_DIR}/sockets-before.txt"
systemctl list-unit-files --type=timer > "${BACKUP_DIR}/timers-before.txt"
dpkg --get-selections > "${BACKUP_DIR}/packages-before.txt"

# ------------------------------------------------------------------------------
# ESSENTIAL SERVICES - DO NOT DISABLE
# ------------------------------------------------------------------------------

# Reference list of services we MUST keep:
#
# SYSTEM CORE:
#   systemd-journald, systemd-udevd, systemd-logind, systemd-tmpfiles-*
#   dbus, polkit
#
# GNOME WAYLAND:
#   gdm (display manager)
#   gnome-shell (via user session)
#   gvfs-* (file management - some components)
#   xdg-desktop-portal, xdg-desktop-portal-gnome (sandboxed app access)
#   gnome-keyring (credential storage - needed for NetworkManager secrets)
#
# NETWORKING:
#   NetworkManager, wg-quick@wg0
#
# AUDIO:
#   pipewire, pipewire-pulse, wireplumber
#
# SECURITY:
#   opensnitchd, escalation-monitor.timer, iptables-restore
#   pcscd (if using U2F - smart card daemon)

# ------------------------------------------------------------------------------
# PACKAGES: Remove unnecessary software
# ------------------------------------------------------------------------------

echo "[*] Removing unnecessary packages"

# List of packages to purge (adjust based on what's installed)
PACKAGES_TO_REMOVE=(
    # SSH server (keep client if you need it)
    "openssh-server"
    
    # Printing
    "cups"
    "cups-daemon"
    "cups-browsed"
    "cups-client"
    "printer-driver-*"
    "system-config-printer"
    
    # Bluetooth
    "bluez"
    "bluez-firmware"
    "bluetooth"
    "gnome-bluetooth"
    "gnome-bluetooth-3-common"
    
    # Avahi/mDNS (zeroconf discovery)
    "avahi-daemon"
    "avahi-autoipd"
    "avahi-utils"
    "libnss-mdns"
    
    # ModemManager (cellular modems)
    "modemmanager"
    
    # Remote desktop
    "xrdp"
    "tightvncserver"
    "tigervnc-standalone-server"
    "gnome-remote-desktop"
    
    # Mail servers
    "postfix"
    "exim4"
    "exim4-base"
    "exim4-daemon-light"
    "sendmail"
    
    # Samba/NFS
    "samba"
    "samba-common"
    "smbclient"
    "nfs-common"
    "nfs-kernel-server"
    "rpcbind"
    
    # Telnet/rsh (legacy insecure)
    "telnet"
    "telnetd"
    "rsh-client"
    "rsh-server"
    
    # FTP
    "ftp"
    "vsftpd"
    "proftpd-basic"
    
    # TFTP
    "tftp"
    "tftpd"
    "tftpd-hpa"
    
    # SNMP
    "snmp"
    "snmpd"
    
    # NIS (legacy)
    "nis"
    "yp-tools"
    
    # Talk (legacy chat)
    "talk"
    "talkd"
    
    # Finger
    "finger"
    "fingerd"
    
    # Games (if installed)
    "gnome-games"
    "aisleriot"
    "gnome-mines"
    "gnome-sudoku"
    
    # Snapd (unless you use snaps)
    "snapd"
    
    # Flatpak (uncomment if you don't use it)
    # "flatpak"
    
    # Tracker (file indexing - privacy concern, resource hog)
    "tracker"
    "tracker-miner-fs"
    "tracker-extract"
    
    # Evolution data server (if not using Evolution/GNOME contacts)
    # "evolution-data-server"  # Careful - some GNOME apps depend on this
    
    # Geoclue (location services - privacy)
    "geoclue-2.0"
    
    # Whoopsie (Ubuntu error reporting)
    "whoopsie"
    "apport"
    
    # Popularity contest
    "popularity-contest"
)

echo "[*] Attempting to remove packages (errors for non-installed packages are OK)"
for pkg in "${PACKAGES_TO_REMOVE[@]}"; do
    apt-get purge -y "$pkg" 2>/dev/null || true
done

# Clean up orphaned packages
apt-get autoremove -y --purge
apt-get clean

# ------------------------------------------------------------------------------
# SERVICES: Disable unnecessary services
# ------------------------------------------------------------------------------

echo "[*] Disabling unnecessary services"

SERVICES_TO_DISABLE=(
    # SSH
    "ssh.service"
    "sshd.service"
    
    # Printing
    "cups.service"
    "cups-browsed.service"
    "cups.socket"
    "cups.path"
    
    # Bluetooth
    "bluetooth.service"
    "bluetooth.target"
    
    # Avahi
    "avahi-daemon.service"
    "avahi-daemon.socket"
    
    # ModemManager
    "ModemManager.service"
    
    # Remote desktop
    "xrdp.service"
    "gnome-remote-desktop.service"
    
    # Mail
    "postfix.service"
    "exim4.service"
    "sendmail.service"
    
    # Samba/NFS
    "smbd.service"
    "nmbd.service"
    "nfs-server.service"
    "nfs-client.target"
    "rpcbind.service"
    "rpcbind.socket"
    
    # iSCSI (storage)
    "iscsid.service"
    "open-iscsi.service"
    
    # Multipath (SAN storage)
    "multipathd.service"
    
    # LVM event monitoring (unless you need dynamic LVM)
    # "lvm2-lvmpolld.service"
    # "lvm2-lvmpolld.socket"
    
    # Fwupd (firmware updates - enable temporarily when needed)
    "fwupd.service"
    "fwupd-refresh.timer"
    
    # Packagekit (GUI package management - use apt directly)
    "packagekit.service"
    
    # Accounts service (user account management GUI)
    # "accounts-daemon.service"  # GNOME might need this
    
    # Geoclue (location)
    "geoclue.service"
    
    # Tracker (file indexing)
    "tracker-miner-fs-3.service"
    "tracker-miner-rss-3.service"
    "tracker-extract-3.service"
    "tracker-writeback-3.service"
    
    # Speech dispatcher (text-to-speech)
    "speech-dispatcher.service"
    
    # Brltty (braille display)
    "brltty.service"
    
    # UPower (battery - keep on laptop actually)
    # "upower.service"
    
    # Colord (color management - usually not needed)
    "colord.service"
    
    # Switcheroo (GPU switching - unless you have hybrid graphics)
    "switcheroo-control.service"
    
    # Thermald (Intel thermal - keep on ThinkPad actually)
    # "thermald.service"
    
    # Cron (replaced by systemd timers)
    "cron.service"
    
    # Anacron
    "anacron.service"
    "anacron.timer"
    
    # Apport/Whoopsie (crash reporting)
    "apport.service"
    "whoopsie.service"
    
    # Unattended upgrades (uncomment to keep)
    # "unattended-upgrades.service"
    # "apt-daily.timer"
    # "apt-daily-upgrade.timer"
    
    # Snapd
    "snapd.service"
    "snapd.socket"
    "snapd.seeded.service"
    
    # GNOME software auto-refresh (manual updates preferred)
    "gnome-software-service.service"
)

for svc in "${SERVICES_TO_DISABLE[@]}"; do
    echo "    [-] Disabling ${svc}"
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true
done

# ------------------------------------------------------------------------------
# SERVICES: Ensure essential services are enabled
# ------------------------------------------------------------------------------

echo "[*] Ensuring essential services are enabled"

SERVICES_TO_ENABLE=(
    # System core
    "systemd-journald.service"
    "systemd-udevd.service"
    "systemd-logind.service"
    "dbus.service"
    "polkit.service"
    
    # GNOME display manager
    "gdm.service"
    
    # Networking
    "NetworkManager.service"
    "NetworkManager-wait-online.service"
    
    # WireGuard VPN
    "wg-quick@wg0.service"
    
    # Audio (user services, but ensure socket is available)
    "pipewire.socket"
    "pipewire-pulse.socket"
    "wireplumber.service"
    
    # Security
    "opensnitchd.service"
    "iptables-restore.service"
    "escalation-monitor.timer"
    
    # U2F smart card (if using hardware keys)
    "pcscd.service"
    "pcscd.socket"
    
    # Firewall (if using firewalld instead of raw iptables)
    # "firewalld.service"
    
    # Time sync (pick one)
    "systemd-timesyncd.service"
    # "chrony.service"
    
    # Power management (laptop)
    "upower.service"
    "thermald.service"
    
    # Lid/power button handling
    "systemd-logind.service"
    
    # XDG portals (sandboxed app permissions)
    # These are user services, but ensure they're not masked
)

for svc in "${SERVICES_TO_ENABLE[@]}"; do
    echo "    [+] Enabling ${svc}"
    systemctl unmask "$svc" 2>/dev/null || true
    systemctl enable "$svc" 2>/dev/null || true
done

# ------------------------------------------------------------------------------
# SOCKETS: Disable unnecessary listening sockets
# ------------------------------------------------------------------------------

echo "[*] Disabling unnecessary sockets"

SOCKETS_TO_DISABLE=(
    "cups.socket"
    "avahi-daemon.socket"
    "rpcbind.socket"
    "ssh.socket"
    "sshd.socket"
    "snapd.socket"
    "iscsid.socket"
)

for sock in "${SOCKETS_TO_DISABLE[@]}"; do
    echo "    [-] Disabling ${sock}"
    systemctl stop "$sock" 2>/dev/null || true
    systemctl disable "$sock" 2>/dev/null || true
    systemctl mask "$sock" 2>/dev/null || true
done

# ------------------------------------------------------------------------------
# TIMERS: Disable unnecessary timers
# ------------------------------------------------------------------------------

echo "[*] Disabling unnecessary timers"

TIMERS_TO_DISABLE=(
    "apt-daily.timer"
    "apt-daily-upgrade.timer"
    "anacron.timer"
    "fwupd-refresh.timer"
    "motd-news.timer"
    "snapd.refresh.timer"
)

for timer in "${TIMERS_TO_DISABLE[@]}"; do
    echo "    [-] Disabling ${timer}"
    systemctl stop "$timer" 2>/dev/null || true
    systemctl disable "$timer" 2>/dev/null || true
    systemctl mask "$timer" 2>/dev/null || true
done

# Ensure our security timer is enabled
systemctl enable escalation-monitor.timer 2>/dev/null || true
systemctl start escalation-monitor.timer 2>/dev/null || true

# ------------------------------------------------------------------------------
# NETWORK: Harden NetworkManager
# ------------------------------------------------------------------------------

echo "[*] Hardening NetworkManager configuration"

mkdir -p /etc/NetworkManager/conf.d

cat > /etc/NetworkManager/conf.d/99-hardening.conf << 'EOF'
[main]
# Disable connectivity checking (phones home to detect captive portals)
connectivity=disabled

# Use systemd-resolved or none (we use Mullvad DNS via WireGuard)
dns=none

# Disable hostname broadcasting
hostname-mode=none

[connection]
# IPv6 disabled by default for all connections
ipv6.method=disabled

# Disable WiFi MAC randomization (or enable for privacy - your choice)
# wifi.cloned-mac-address=random

# Connection timeout
connection.auth-timeout=30

[device]
# WiFi power saving (1=disable, 2=enable - disable for stability)
wifi.powersave=1

# Disable WiFi background scanning when connected
wifi.scan-rand-mac-address=yes
EOF

# Restart NetworkManager to apply
systemctl restart NetworkManager

# ------------------------------------------------------------------------------
# GNOME: Disable unnecessary user services via dconf
# ------------------------------------------------------------------------------

echo "[*] Creating dconf profile to disable GNOME telemetry/tracking"

mkdir -p /etc/dconf/profile
cat > /etc/dconf/profile/user << 'EOF'
user-db:user
system-db:local
EOF

mkdir -p /etc/dconf/db/local.d

cat > /etc/dconf/db/local.d/00-hardening << 'EOF'
# Disable location services
[org/gnome/system/location]
enabled=false

# Disable automatic problem reporting
[org/gnome/desktop/privacy]
report-technical-problems=false
send-software-usage-stats=false

# Disable recent files tracking
[org/gnome/desktop/privacy]
remember-recent-files=false
recent-files-max-age=0

# Disable file history
[org/gnome/desktop/privacy]
remove-old-temp-files=true
remove-old-trash-files=true
old-files-age=7

# Screen lock settings
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=0
idle-activation-enabled=true

[org/gnome/desktop/session]
idle-delay=300

# Disable remote desktop
[org/gnome/desktop/remote-desktop]
enabled=false

# Disable GNOME software auto-updates (manual preferred)
[org/gnome/software]
download-updates=false
download-updates-notify=false

# Disable tracker/file indexing
[org/freedesktop/tracker/miner/files]
enable-monitors=false
crawling-interval=-2
EOF

# Lock down certain settings (prevent user override)
mkdir -p /etc/dconf/db/local.d/locks

cat > /etc/dconf/db/local.d/locks/hardening << 'EOF'
/org/gnome/system/location/enabled
/org/gnome/desktop/privacy/report-technical-problems
/org/gnome/desktop/privacy/send-software-usage-stats
/org/gnome/desktop/remote-desktop/enabled
EOF

# Update dconf database
dconf update

# ------------------------------------------------------------------------------
# SYSTEMD: Harden systemd defaults
# ------------------------------------------------------------------------------

echo "[*] Hardening systemd configuration"

mkdir -p /etc/systemd/system.conf.d

cat > /etc/systemd/system.conf.d/hardening.conf << 'EOF'
[Manager]
# Dump core to journal, not files
DumpCore=no

# Crash shell disabled
CrashShell=no

# Limit default capabilities for services
DefaultLimitCORE=0
DefaultLimitNOFILE=1024
DefaultLimitNPROC=512

# Default timeout for stopping services
DefaultTimeoutStopSec=30s
EOF

mkdir -p /etc/systemd/user.conf.d

cat > /etc/systemd/user.conf.d/hardening.conf << 'EOF'
[Manager]
DefaultLimitCORE=0
DefaultLimitNOFILE=1024
DefaultLimitNPROC=256
EOF

# ------------------------------------------------------------------------------
# JOURNALD: Configure logging
# ------------------------------------------------------------------------------

echo "[*] Configuring journald"

mkdir -p /etc/systemd/journald.conf.d

cat > /etc/systemd/journald.conf.d/hardening.conf << 'EOF'
[Journal]
# Persistent storage (survives reboot)
Storage=persistent

# Limit journal size
SystemMaxUse=500M
SystemMaxFileSize=50M
RuntimeMaxUse=100M

# Compress logs
Compress=yes

# Forward to syslog if needed
ForwardToSyslog=no

# Rate limiting
RateLimitInterval=30s
RateLimitBurst=1000
EOF

# Create journal directory with proper permissions
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald

# ------------------------------------------------------------------------------
# GDM: Harden display manager
# ------------------------------------------------------------------------------

echo "[*] Hardening GDM configuration"

mkdir -p /etc/gdm3

# Disable user list on login screen
cat > /etc/gdm3/greeter.dconf-defaults << 'EOF'
[org/gnome/login-screen]
# Disable user list (require username entry)
disable-user-list=true

# Disable restart buttons on login screen (prevent bypass)
disable-restart-buttons=false

# Banner message (optional)
banner-message-enable=true
banner-message-text='Authorized users only. All activity is monitored.'
EOF

# Ensure Wayland is enforced (not X11 fallback)
if [[ -f /etc/gdm3/custom.conf ]]; then
    sed -i 's/^#WaylandEnable=.*/WaylandEnable=true/' /etc/gdm3/custom.conf
    sed -i 's/^WaylandEnable=.*/WaylandEnable=true/' /etc/gdm3/custom.conf
else
    cat > /etc/gdm3/custom.conf << 'EOF'
[daemon]
WaylandEnable=true
AutomaticLoginEnable=false

[security]

[xdmcp]

[chooser]

[debug]
EOF
fi

# ------------------------------------------------------------------------------
# POLKIT: Rules for GNOME desktop operations
# ------------------------------------------------------------------------------

echo "[*] Configuring polkit rules for GNOME"

mkdir -p /etc/polkit-1/rules.d

# Allow primary user to perform desktop operations
cat > /etc/polkit-1/rules.d/50-gnome-allow.rules << 'POLKIT_EOF'
// Allow specific user to perform GNOME desktop operations
polkit.addRule(function(action, subject) {
    if (subject.user == "dev") {
        // Power management
        if (action.id == "org.freedesktop.login1.suspend" ||
            action.id == "org.freedesktop.login1.hibernate" ||
            action.id == "org.freedesktop.login1.reboot" ||
            action.id == "org.freedesktop.login1.power-off" ||
            action.id == "org.freedesktop.login1.reboot-multiple-sessions" ||
            action.id == "org.freedesktop.login1.power-off-multiple-sessions") {
            return polkit.Result.YES;
        }
        
        // GNOME settings and system
        if (action.id.indexOf("org.gnome") == 0) {
            return polkit.Result.YES;
        }
        
        // Color profiles (for display calibration)
        if (action.id == "org.freedesktop.color-manager.create-device" ||
            action.id == "org.freedesktop.color-manager.create-profile" ||
            action.id == "org.freedesktop.color-manager.modify-device" ||
            action.id == "org.freedesktop.color-manager.modify-profile") {
            return polkit.Result.YES;
        }
        
        // Network management
        if (action.id.indexOf("org.freedesktop.NetworkManager") == 0) {
            return polkit.Result.YES;
        }
        
        // Timezone
        if (action.id == "org.freedesktop.timedate1.set-timezone" ||
            action.id == "org.freedesktop.timedate1.set-time") {
            return polkit.Result.YES;
        }
    }
    
    // Deny everything else by default
    return polkit.Result.NO;
});
POLKIT_EOF

chmod 644 /etc/polkit-1/rules.d/50-gnome-allow.rules

echo "[+] Polkit rules installed"

# ------------------------------------------------------------------------------
# AUDIT: Final service state
# ------------------------------------------------------------------------------

echo "[*] Generating final service audit"

systemctl list-unit-files --type=service --state=enabled > "${BACKUP_DIR}/services-after-enabled.txt"
systemctl list-unit-files --type=service --state=masked > "${BACKUP_DIR}/services-after-masked.txt"
systemctl list-sockets --all > "${BACKUP_DIR}/sockets-after.txt"

# Show listening ports (should be minimal)
echo "[*] Currently listening ports:"
ss -tulpn | tee "${BACKUP_DIR}/listening-ports.txt"

# ------------------------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------------------------

echo ""
echo "[+] Services hardening complete"
echo ""
echo "    Backup location: ${BACKUP_DIR}"
echo ""
echo "    Post-reboot verification:"
echo "      systemctl list-units --type=service --state=running"
echo "      ss -tulpn                        # Should show minimal listening ports"
echo "      systemctl status opensnitchd    # Should be active"
echo "      systemctl status wg-quick@wg0   # Should be active"
echo ""
echo "    GNOME-specific:"
echo "      echo \$XDG_SESSION_TYPE          # Should say 'wayland'"
echo "      gsettings get org.gnome.system.location enabled  # Should be false"
echo ""
echo "    If something breaks, review masked services:"
echo "      systemctl list-unit-files --state=masked"
echo "      systemctl unmask <service>       # To re-enable"
echo ""
echo "    To temporarily enable firmware updates:"
echo "      systemctl unmask fwupd.service && systemctl start fwupd"

# Audit Framework Hardening Module (auditd)
# Target: Debian 12+ / GNOME Wayland / ThinkPad P16s Gen 2
# Policy: Comprehensive logging of security-relevant events
#

set -euo pipefail

AUDIT_RULES="/etc/audit/rules.d/99-hardening.rules"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

# ------------------------------------------------------------------------------
# PREFLIGHT
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root"
    exit 1
fi

# ------------------------------------------------------------------------------
# INSTALL: auditd if not present
# ------------------------------------------------------------------------------

echo "[*] Ensuring auditd is installed"
if ! command -v auditctl &>/dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# ------------------------------------------------------------------------------
# BACKUP
# ------------------------------------------------------------------------------

echo "[*] Backing up existing audit configuration"
[[ -f /etc/audit/auditd.conf ]] && cp /etc/audit/auditd.conf "/etc/audit/auditd.conf${BACKUP_SUFFIX}"
[[ -d /etc/audit/rules.d ]] && cp -a /etc/audit/rules.d "/etc/audit/rules.d${BACKUP_SUFFIX}"

# ------------------------------------------------------------------------------
# AUDITD.CONF: Main daemon configuration
# ------------------------------------------------------------------------------

echo "[*] Configuring auditd daemon"

cat > /etc/audit/auditd.conf << 'EOF'
#
# Hardened auditd configuration
#

# Log file location
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50

# Log file rotation
num_logs = 10
max_log_file = 50
max_log_file_action = ROTATE

# Disk space handling
space_left = 100
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND

# Priority boost (keep audit daemon running)
priority_boost = 4

# Name format (include hostname)
name_format = HOSTNAME

# Local events
local_events = yes
write_logs = yes

# Dispatcher (for sending to remote or processing)
dispatcher = /sbin/audispd

# Network listener (disabled - local only)
tcp_listen_queue = 5
tcp_max_per_addr = 1
use_libwrap = yes
tcp_client_max_idle = 0

# Overflow action
overflow_action = SYSLOG
EOF

# ------------------------------------------------------------------------------
# AUDIT RULES: Comprehensive security monitoring
# ------------------------------------------------------------------------------

echo "[*] Writing hardened audit rules to ${AUDIT_RULES}"

cat > "$AUDIT_RULES" << 'EOF'
# =============================================================================
# HARDENED AUDIT RULES
# Target: Single-user hardened workstation
# =============================================================================

# Remove any existing rules
-D

# Set buffer size (adjust if you get backlog warnings)
-b 8192

# Failure mode: 1=printk, 2=panic (use 1 for workstation)
-f 1

# Rate limit (0=unlimited, set higher if needed)
-r 100

# -----------------------------------------------------------------------------
# SELF-AUDITING: Audit the audit system itself
# -----------------------------------------------------------------------------

# Changes to audit configuration
-w /etc/audit/ -p wa -k audit_config
-w /etc/libaudit.conf -p wa -k audit_config
-w /etc/audisp/ -p wa -k audit_config

# Audit tools
-w /sbin/auditctl -p x -k audit_tools
-w /sbin/auditd -p x -k audit_tools
-w /usr/sbin/augenrules -p x -k audit_tools

# -----------------------------------------------------------------------------
# TIME: System time changes (forensic timeline integrity)
# -----------------------------------------------------------------------------

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# -----------------------------------------------------------------------------
# IDENTITY: User/group modifications
# -----------------------------------------------------------------------------

-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# User management commands
-w /usr/sbin/useradd -p x -k user_mgmt
-w /usr/sbin/userdel -p x -k user_mgmt
-w /usr/sbin/usermod -p x -k user_mgmt
-w /usr/sbin/groupadd -p x -k user_mgmt
-w /usr/sbin/groupdel -p x -k user_mgmt
-w /usr/sbin/groupmod -p x -k user_mgmt
-w /usr/bin/chfn -p x -k user_mgmt
-w /usr/bin/chsh -p x -k user_mgmt

# -----------------------------------------------------------------------------
# AUTHENTICATION: Login and authentication events
# -----------------------------------------------------------------------------

# PAM configuration
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/security/ -p wa -k pam_config

# Login configuration
-w /etc/login.defs -p wa -k login_config
-w /etc/securetty -p wa -k login_config

# Faillock
-w /var/run/faillock/ -p wa -k faillock

# SSH (even if disabled, monitor for tampering)
-w /etc/ssh/ -p wa -k ssh_config

# U2F keys
-w /etc/security/u2f_keys/ -p wa -k u2f_config

# -----------------------------------------------------------------------------
# AUTHORIZATION: Sudo and privilege escalation
# -----------------------------------------------------------------------------

# Sudoers files
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Sudo execution
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/su -p x -k privilege_escalation
-w /usr/bin/pkexec -p x -k privilege_escalation

# Privilege escalation syscalls
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -S setresuid -S setresgid -k privilege_escalation
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -S setresuid -S setresgid -k privilege_escalation

# Capability changes
-a always,exit -F arch=b64 -S capset -k privilege_escalation
-a always,exit -F arch=b32 -S capset -k privilege_escalation

# -----------------------------------------------------------------------------
# NETWORK: Configuration changes
# -----------------------------------------------------------------------------

# Network config files
-w /etc/hosts -p wa -k network_config
-w /etc/hostname -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/NetworkManager/ -p wa -k network_config

# Firewall rules
-w /etc/iptables/ -p wa -k firewall_config
-w /etc/nftables.conf -p wa -k firewall_config

# WireGuard
-w /etc/wireguard/ -p wa -k vpn_config

# OpenSnitch
-w /etc/opensnitchd/ -p wa -k opensnitch_config

# Network commands
-w /sbin/iptables -p x -k firewall_cmd
-w /sbin/ip6tables -p x -k firewall_cmd
-w /sbin/nft -p x -k firewall_cmd
-w /usr/bin/wg -p x -k vpn_cmd

# -----------------------------------------------------------------------------
# KERNEL: Module and kernel parameter changes
# -----------------------------------------------------------------------------

# Module loading
-a always,exit -F arch=b64 -S init_module -S finit_module -k kernel_module
-a always,exit -F arch=b32 -S init_module -S finit_module -k kernel_module
-a always,exit -F arch=b64 -S delete_module -k kernel_module
-a always,exit -F arch=b32 -S delete_module -k kernel_module

# Modprobe config
-w /etc/modprobe.d/ -p wa -k modprobe_config

# Sysctl
-w /etc/sysctl.conf -p wa -k sysctl_config
-w /etc/sysctl.d/ -p wa -k sysctl_config

# Kernel command line (boot params)
-w /etc/default/grub -p wa -k boot_config
-w /etc/default/grub.d/ -p wa -k boot_config
-w /boot/grub/grub.cfg -p wa -k boot_config

# -----------------------------------------------------------------------------
# FILESYSTEM: Critical file access and modifications
# -----------------------------------------------------------------------------

# Boot directory
-w /boot/ -p wa -k boot_files

# Cron (even if disabled)
-w /etc/cron.d/ -p wa -k cron_config
-w /etc/cron.daily/ -p wa -k cron_config
-w /etc/cron.hourly/ -p wa -k cron_config
-w /etc/cron.weekly/ -p wa -k cron_config
-w /etc/cron.monthly/ -p wa -k cron_config
-w /etc/crontab -p wa -k cron_config
-w /var/spool/cron/ -p wa -k cron_config

# Systemd
-w /etc/systemd/ -p wa -k systemd_config
-w /usr/lib/systemd/ -p wa -k systemd_config
-w /lib/systemd/ -p wa -k systemd_config

# At (scheduled tasks)
-w /etc/at.deny -p wa -k at_config
-w /etc/at.allow -p wa -k at_config
-w /var/spool/atjobs/ -p wa -k at_config

# Fstab
-w /etc/fstab -p wa -k fstab_config

# LD preload (library injection)
-w /etc/ld.so.conf -p wa -k ld_config
-w /etc/ld.so.conf.d/ -p wa -k ld_config
-w /etc/ld.so.preload -p wa -k ld_preload

# Shell configs (persistence mechanisms)
-w /etc/profile -p wa -k shell_config
-w /etc/profile.d/ -p wa -k shell_config
-w /etc/bashrc -p wa -k shell_config
-w /etc/bash.bashrc -p wa -k shell_config
-w /etc/shells -p wa -k shell_config

# Init scripts
-w /etc/init.d/ -p wa -k init_config
-w /etc/rc.local -p wa -k init_config

# -----------------------------------------------------------------------------
# BINARIES: Critical system binaries
# -----------------------------------------------------------------------------

# Shells
-w /bin/bash -p wa -k binary_tampering
-w /bin/sh -p wa -k binary_tampering
-w /bin/dash -p wa -k binary_tampering
-w /usr/bin/bash -p wa -k binary_tampering

# Core utilities (subset - most critical)
-w /usr/bin/passwd -p x -k passwd_cmd
-w /usr/bin/chage -p x -k passwd_cmd
-w /usr/bin/gpasswd -p x -k passwd_cmd

# Package management
-w /usr/bin/apt -p x -k package_mgmt
-w /usr/bin/apt-get -p x -k package_mgmt
-w /usr/bin/dpkg -p x -k package_mgmt

# -----------------------------------------------------------------------------
# MOUNT: Filesystem mount operations
# -----------------------------------------------------------------------------

-a always,exit -F arch=b64 -S mount -S umount2 -k mount_ops
-a always,exit -F arch=b32 -S mount -S umount2 -k mount_ops

# -----------------------------------------------------------------------------
# EXECUTION: Process and execution monitoring
# -----------------------------------------------------------------------------

# Execve (all program execution) - VERY verbose, use sparingly
# Uncomment if you want full execution logging (impacts performance)
# -a always,exit -F arch=b64 -S execve -k exec
# -a always,exit -F arch=b32 -S execve -k exec

# Execution from suspicious locations
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k exec_tmp
-a always,exit -F arch=b32 -S execve -F dir=/tmp -k exec_tmp
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k exec_tmp
-a always,exit -F arch=b32 -S execve -F dir=/var/tmp -k exec_tmp
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k exec_shm
-a always,exit -F arch=b32 -S execve -F dir=/dev/shm -k exec_shm

# -----------------------------------------------------------------------------
# PTRACE: Debugging and process injection
# -----------------------------------------------------------------------------

-a always,exit -F arch=b64 -S ptrace -k ptrace
-a always,exit -F arch=b32 -S ptrace -k ptrace
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k ptrace_injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k ptrace_injection

# -----------------------------------------------------------------------------
# SPECIAL FILES: Device and special file access
# -----------------------------------------------------------------------------

# /dev access (subset)
-w /dev/null -p r -k dev_null_read
-w /dev/zero -p r -k dev_zero_read

# Kernel memory (should be blocked by lockdown, but audit anyway)
-w /dev/mem -p rwa -k dev_mem
-w /dev/kmem -p rwa -k dev_kmem
-w /dev/port -p rwa -k dev_port

# -----------------------------------------------------------------------------
# UNSUCCESSFUL ACCESS ATTEMPTS
# -----------------------------------------------------------------------------

# Failed file access (permission denied)
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b32 -S open -S openat -S creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EPERM -k access_denied
-a always,exit -F arch=b32 -S open -S openat -S creat -F exit=-EPERM -k access_denied

# -----------------------------------------------------------------------------
# POWER: Shutdown and reboot events
# -----------------------------------------------------------------------------

-w /sbin/shutdown -p x -k power
-w /sbin/reboot -p x -k power
-w /sbin/halt -p x -k power
-w /sbin/poweroff -p x -k power

# -----------------------------------------------------------------------------
# MAKE RULES IMMUTABLE (uncomment for production)
# This prevents rules from being changed until reboot
# -----------------------------------------------------------------------------

# -e 2

EOF

chmod 600 "$AUDIT_RULES"

# ------------------------------------------------------------------------------
# AUDITD SERVICE: Enable and configure
# ------------------------------------------------------------------------------

echo "[*] Enabling auditd service"

# Ensure auditd starts before most other services
systemctl daemon-reload
systemctl enable auditd
systemctl restart auditd

# Load the rules
echo "[*] Loading audit rules"
augenrules --load

# ------------------------------------------------------------------------------
# LOG ROTATION: Ensure audit logs are protected
# ------------------------------------------------------------------------------

echo "[*] Configuring audit log permissions"
chmod 700 /var/log/audit
chmod 600 /var/log/audit/* 2>/dev/null || true
chown -R root:adm /var/log/audit

# ------------------------------------------------------------------------------
# HELPER SCRIPTS: Create useful audit analysis scripts
# ------------------------------------------------------------------------------

echo "[*] Creating audit analysis helper scripts"

# Script to view recent authentication events
cat > /usr/local/bin/audit-auth << 'EOF'
#!/bin/bash
# View recent authentication-related audit events
ausearch -k pam_config -k login_config -k identity -k faillock -ts recent 2>/dev/null | aureport -i --summary
echo ""
echo "Detailed events:"
ausearch -k pam_config -k login_config -k identity -k faillock -ts recent 2>/dev/null | head -100
EOF
chmod 700 /usr/local/bin/audit-auth

# Script to view privilege escalation attempts
cat > /usr/local/bin/audit-priv << 'EOF'
#!/bin/bash
# View privilege escalation events
ausearch -k privilege_escalation -k sudoers -ts recent 2>/dev/null | aureport -i --summary
echo ""
echo "Sudo commands:"
ausearch -k privilege_escalation -c sudo -ts recent 2>/dev/null | aureport -i -f
EOF
chmod 700 /usr/local/bin/audit-priv

# Script to view execution from tmp/shm
cat > /usr/local/bin/audit-exec-tmp << 'EOF'
#!/bin/bash
# View execution attempts from /tmp, /var/tmp, /dev/shm
ausearch -k exec_tmp -k exec_shm -ts recent 2>/dev/null | aureport -i -x
EOF
chmod 700 /usr/local/bin/audit-exec-tmp

# Script to view all failed access attempts
cat > /usr/local/bin/audit-denied << 'EOF'
#!/bin/bash
# View failed access attempts
ausearch -k access_denied -ts recent 2>/dev/null | aureport -i -f --summary
echo ""
echo "Recent denials:"
ausearch -k access_denied -ts recent 2>/dev/null | tail -50
EOF
chmod 700 /usr/local/bin/audit-denied

# Script to view config changes
cat > /usr/local/bin/audit-config << 'EOF'
#!/bin/bash
# View configuration file changes
ausearch -k audit_config -k network_config -k firewall_config -k sysctl_config -k systemd_config -ts recent 2>/dev/null | aureport -i -f
EOF
chmod 700 /usr/local/bin/audit-config

# Master audit summary script
cat > /usr/local/bin/audit-summary << 'EOF'
#!/bin/bash
# Daily audit summary

echo "=========================================="
echo "AUDIT SUMMARY - $(date)"
echo "=========================================="
echo ""

echo "=== Authentication Events ==="
aureport -au -ts today --summary 2>/dev/null
echo ""

echo "=== Failed Logins ==="
aureport --failed -ts today 2>/dev/null | head -20
echo ""

echo "=== Privilege Escalation ==="
ausearch -k privilege_escalation -ts today 2>/dev/null | aureport -i --summary
echo ""

echo "=== File Modifications ==="
aureport -f -ts today --summary 2>/dev/null
echo ""

echo "=== Anomaly Events ==="
aureport --anomaly -ts today 2>/dev/null
echo ""

echo "=== Execution from /tmp or /dev/shm ==="
ausearch -k exec_tmp -k exec_shm -ts today 2>/dev/null | wc -l
echo "events (run audit-exec-tmp for details)"
echo ""

echo "=== Access Denied ==="
ausearch -k access_denied -ts today 2>/dev/null | wc -l
echo "events (run audit-denied for details)"
EOF
chmod 700 /usr/local/bin/audit-summary

# ------------------------------------------------------------------------------
# SYSTEMD TIMER: Daily audit summary (optional)
# ------------------------------------------------------------------------------

echo "[*] Creating daily audit summary timer"

cat > /etc/systemd/system/audit-summary.service << 'EOF'
[Unit]
Description=Daily Audit Summary

[Service]
Type=oneshot
ExecStart=/usr/local/bin/audit-summary
StandardOutput=journal
EOF

cat > /etc/systemd/system/audit-summary.timer << 'EOF'
[Unit]
Description=Run audit summary daily

[Timer]
OnCalendar=*-*-* 06:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable audit-summary.timer
systemctl start audit-summary.timer

# ------------------------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------------------------

echo ""
echo "[+] Audit framework hardening complete"
echo ""
echo "    Service status:"
systemctl status auditd --no-pager | head -5
echo ""
echo "    Active rules:"
auditctl -l | wc -l
echo "    rules loaded"
echo ""
echo "    Helper scripts installed:"
echo "      audit-auth        - Authentication events"
echo "      audit-priv        - Privilege escalation"
echo "      audit-exec-tmp    - Execution from /tmp, /dev/shm"
echo "      audit-denied      - Access denied events"
echo "      audit-config      - Configuration changes"
echo "      audit-summary     - Daily summary (also runs via timer)"
echo ""
echo "    Quick commands:"
echo "      ausearch -ts recent           # Recent events"
echo "      aureport --summary            # Overall summary"
echo "      ausearch -k privilege_escalation -i  # Privilege events"
echo ""
echo "    Log location: /var/log/audit/audit.log"
echo ""
echo "    To make rules immutable (prevents changes until reboot):"
echo "      Uncomment '-e 2' at end of ${AUDIT_RULES}"
echo "      Then: augenrules --load"

# AppArmor Hardening Module
# Target: Debian 12+ / GNOME Wayland / ThinkPad P16s Gen 2
# Policy: Enforce profiles for browser, applications, system services
#

set -euo pipefail

PRIMARY_USER="dev"
APPARMOR_DIR="/etc/apparmor.d"
BACKUP_DIR="/root/apparmor-backup-$(date +%Y%m%d%H%M%S)"

# ------------------------------------------------------------------------------
# PREFLIGHT
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root"
    exit 1
fi

# ------------------------------------------------------------------------------
# INSTALL: AppArmor utilities if not present
# ------------------------------------------------------------------------------

echo "[*] Ensuring AppArmor packages are installed"
apt-get update
apt-get install -y \
    apparmor \
    apparmor-utils \
    apparmor-profiles \
    apparmor-profiles-extra \
    auditd

# ------------------------------------------------------------------------------
# BACKUP
# ------------------------------------------------------------------------------

echo "[*] Backing up existing AppArmor configuration"
mkdir -p "$BACKUP_DIR"
cp -a "$APPARMOR_DIR" "$BACKUP_DIR/"
aa-status > "${BACKUP_DIR}/aa-status-before.txt" 2>&1 || true

# ------------------------------------------------------------------------------
# VERIFY: AppArmor is enabled at boot
# ------------------------------------------------------------------------------

echo "[*] Verifying AppArmor is enabled at boot"

# Check kernel command line
if ! grep -q "apparmor=1" /proc/cmdline; then
    echo "[*] Adding AppArmor boot parameters"
    
    # Add to GRUB config
    if [[ -f /etc/default/grub.d/99-hardening.cfg ]]; then
        # Append to existing hardening config
        sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor /' /etc/default/grub.d/99-hardening.cfg
    else
        mkdir -p /etc/default/grub.d
        cat > /etc/default/grub.d/99-apparmor.cfg << 'EOF'
# AppArmor boot parameters
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX apparmor=1 security=apparmor"
EOF
    fi
    
    update-grub
    echo "[!] Reboot required to fully enable AppArmor"
fi

# ------------------------------------------------------------------------------
# PROFILE: Librewolf / Firefox (browser hardening)
# ------------------------------------------------------------------------------

echo "[*] Creating Librewolf/Firefox AppArmor profile"

cat > "${APPARMOR_DIR}/usr.bin.librewolf" << 'EOF'
# AppArmor profile for Librewolf browser
# Also works for Firefox with symlink

abi <abi/3.0>,

include <tunables/global>

@{librewolf_exec} = /usr/bin/librewolf /usr/lib/librewolf/librewolf /opt/librewolf/librewolf
@{firefox_exec} = /usr/bin/firefox /usr/lib/firefox/firefox /usr/lib/firefox-esr/firefox-esr

profile librewolf @{librewolf_exec} flags=(attach_disconnected) {
    include <abstractions/base>
    include <abstractions/audio>
    include <abstractions/dbus-session-strict>
    include <abstractions/dbus-accessibility-strict>
    include <abstractions/fonts>
    include <abstractions/freedesktop.org>
    include <abstractions/gnome>
    include <abstractions/mesa>
    include <abstractions/nameservice>
    include <abstractions/opencl-intel>
    include <abstractions/ssl_certs>
    include <abstractions/user-download-strict>
    include <abstractions/vulkan>
    include <abstractions/wayland>

    # Capabilities
    capability sys_admin,      # For sandboxing namespaces
    capability sys_chroot,     # For sandboxing
    capability sys_ptrace,     # For crash reporter (can remove if not needed)

    # Network access
    network inet stream,
    network inet dgram,
    network inet6 stream,
    network inet6 dgram,
    network netlink raw,

    # Deny dangerous capabilities
    deny capability dac_override,
    deny capability dac_read_search,
    deny capability net_admin,
    deny capability sys_module,
    deny capability sys_rawio,

    # Browser executables
    @{librewolf_exec} mrix,
    /usr/lib/librewolf/** mrix,
    /opt/librewolf/** mrix,

    # User profile directory
    owner @{HOME}/.librewolf/ rw,
    owner @{HOME}/.librewolf/** rwk,
    owner @{HOME}/.mozilla/ rw,
    owner @{HOME}/.mozilla/** rwk,

    # Cache
    owner @{HOME}/.cache/librewolf/ rw,
    owner @{HOME}/.cache/librewolf/** rwk,
    owner @{HOME}/.cache/mozilla/ rw,
    owner @{HOME}/.cache/mozilla/** rwk,

    # Downloads directory (read/write)
    owner @{HOME}/Downloads/ rw,
    owner @{HOME}/Downloads/** rw,

    # Deny access to sensitive directories
    deny @{HOME}/.gnupg/** rw,
    deny @{HOME}/.ssh/** rw,
    deny @{HOME}/.pki/** rw,
    deny @{HOME}/.cert/** rw,
    deny @{HOME}/.password-store/** rw,
    deny @{HOME}/.local/share/keyrings/** rw,
    deny @{HOME}/.config/gnome-keyring/** rw,
    deny /etc/shadow r,
    deny /etc/gshadow r,
    deny /etc/security/** rw,
    deny /etc/sudoers r,
    deny /etc/sudoers.d/** r,
    deny /etc/pam.d/** rw,
    deny /etc/wireguard/** rw,

    # System libraries and resources
    /usr/share/** r,
    /usr/lib/** rm,
    /lib/** rm,
    /etc/fonts/** r,
    /etc/ssl/** r,
    /etc/ca-certificates/** r,
    /etc/mime.types r,
    /etc/mailcap r,
    /etc/machine-id r,
    /etc/localtime r,
    /etc/passwd r,
    /etc/group r,
    /etc/nsswitch.conf r,
    /etc/resolv.conf r,
    /etc/host.conf r,
    /etc/hosts r,
    /etc/gai.conf r,

    # Proc filesystem (limited)
    @{PROC}/@{pid}/** r,
    @{PROC}/sys/kernel/random/uuid r,
    @{PROC}/sys/kernel/osrelease r,
    @{PROC}/sys/fs/inotify/max_user_watches r,
    owner @{PROC}/@{pid}/fd/ r,
    owner @{PROC}/@{pid}/task/ r,
    owner @{PROC}/@{pid}/mountinfo r,
    owner @{PROC}/@{pid}/cgroup r,
    owner @{PROC}/@{pid}/oom_score_adj rw,

    # Sys filesystem
    /sys/bus/ r,
    /sys/class/ r,
    /sys/devices/** r,
    /sys/fs/cgroup/** r,
    deny /sys/kernel/security/** rw,

    # Device access
    /dev/ r,
    /dev/null rw,
    /dev/zero r,
    /dev/random r,
    /dev/urandom r,
    /dev/shm/ r,
    owner /dev/shm/org.chromium.* rw,
    owner /dev/shm/org.mozilla.* rw,
    /dev/dri/** rw,
    /dev/video* rw,

    # PipeWire/Audio
    owner /run/user/@{uid}/pipewire-* rw,
    owner /run/user/@{uid}/pulse/ rw,
    owner /run/user/@{uid}/pulse/** rw,

    # Wayland
    owner /run/user/@{uid}/wayland-* rw,

    # D-Bus
    owner /run/user/@{uid}/bus rw,
    owner /run/user/@{uid}/dconf/ rw,
    owner /run/user/@{uid}/dconf/** rw,

    # XDG portals
    owner /run/user/@{uid}/doc/ r,
    owner /run/user/@{uid}/doc/** rw,
    owner /run/user/@{uid}/.flatpak-helper/** rw,

    # Temp directories (sandboxed)
    owner /tmp/librewolf*/ rw,
    owner /tmp/librewolf*/** rwk,
    owner /tmp/mozilla*/ rw,
    owner /tmp/mozilla*/** rwk,
    owner /tmp/Temp-*/ rw,
    owner /tmp/Temp-*/** rwk,
    owner /var/tmp/** rwk,

    # Deny access to other users' data
    deny /home/*/** rw,
    deny /root/** rw,

    # Deny raw network sockets (can't do packet capture)
    deny network raw,
    deny network packet,

    # Child profile for content processes
    profile librewolf-content flags=(attach_disconnected) {
        include <abstractions/base>
        include <abstractions/fonts>
        include <abstractions/mesa>
        include <abstractions/wayland>

        /usr/lib/librewolf/** rm,
        /opt/librewolf/** rm,
        /usr/share/** r,

        owner @{HOME}/.librewolf/** rw,
        owner @{HOME}/.cache/librewolf/** rw,

        deny network,
        deny @{HOME}/.ssh/** rw,
        deny @{HOME}/.gnupg/** rw,
    }
}
EOF

# ------------------------------------------------------------------------------
# PROFILE: Evince (PDF viewer)
# ------------------------------------------------------------------------------

echo "[*] Creating Evince PDF viewer profile"

cat > "${APPARMOR_DIR}/usr.bin.evince" << 'EOF'
# AppArmor profile for Evince document viewer

abi <abi/3.0>,

include <tunables/global>

profile evince /usr/bin/evince flags=(attach_disconnected) {
    include <abstractions/base>
    include <abstractions/dbus-session-strict>
    include <abstractions/fonts>
    include <abstractions/freedesktop.org>
    include <abstractions/gnome>
    include <abstractions/nameservice>
    include <abstractions/wayland>

    # No network needed for document viewing
    deny network,

    # Evince binary
    /usr/bin/evince mr,
    /usr/lib/evince/** mr,
    /usr/libexec/evince/** mr,

    # User documents (read-only by default)
    owner @{HOME}/ r,
    owner @{HOME}/Documents/ r,
    owner @{HOME}/Documents/** r,
    owner @{HOME}/Downloads/ r,
    owner @{HOME}/Downloads/** r,

    # Evince config
    owner @{HOME}/.config/evince/ rw,
    owner @{HOME}/.config/evince/** rw,
    owner @{HOME}/.local/share/evince/ rw,
    owner @{HOME}/.local/share/evince/** rw,

    # Thumbnails
    owner @{HOME}/.cache/thumbnails/** rw,

    # System resources
    /usr/share/** r,
    /etc/fonts/** r,

    # Deny sensitive areas
    deny @{HOME}/.ssh/** rw,
    deny @{HOME}/.gnupg/** rw,
    deny /etc/shadow r,
    deny /etc/wireguard/** r,

    # Proc/sys (minimal)
    @{PROC}/@{pid}/fd/ r,
    owner @{PROC}/@{pid}/mountinfo r,

    # Wayland/D-Bus
    owner /run/user/@{uid}/wayland-* rw,
    owner /run/user/@{uid}/bus rw,
    owner /run/user/@{uid}/dconf/ rw,
    owner /run/user/@{uid}/dconf/** rw,

    # Temp files
    owner /tmp/evince-*/** rw,
}
EOF

# ------------------------------------------------------------------------------
# PROFILE: GNOME Terminal
# ------------------------------------------------------------------------------

echo "[*] Creating GNOME Terminal profile"

cat > "${APPARMOR_DIR}/usr.bin.gnome-terminal-server" << 'EOF'
# AppArmor profile for GNOME Terminal

abi <abi/3.0>,

include <tunables/global>

profile gnome-terminal /usr/libexec/gnome-terminal-server flags=(attach_disconnected) {
    include <abstractions/base>
    include <abstractions/bash>
    include <abstractions/dbus-session-strict>
    include <abstractions/fonts>
    include <abstractions/gnome>
    include <abstractions/nameservice>
    include <abstractions/wayland>

    # Network for terminal apps that need it
    network inet stream,
    network inet dgram,
    network unix stream,

    # Terminal server
    /usr/libexec/gnome-terminal-server mr,
    /usr/bin/gnome-terminal mr,

    # Shells
    /bin/bash Ux,
    /bin/sh Ux,
    /bin/dash Ux,
    /usr/bin/bash Ux,
    /usr/bin/zsh Ux,

    # User home (for shell)
    owner @{HOME}/ r,
    owner @{HOME}/** rwkl,

    # Terminal config
    owner @{HOME}/.config/gnome-terminal/** rw,
    owner @{HOME}/.local/share/gnome-terminal/** rw,

    # Shell configs
    owner @{HOME}/.bashrc r,
    owner @{HOME}/.bash_profile r,
    owner @{HOME}/.profile r,
    owner @{HOME}/.bash_history rw,
    owner @{HOME}/.bash_logout r,

    # System
    /etc/** r,
    /usr/share/** r,
    /usr/lib/** rm,
    /usr/bin/** mrix,
    /bin/** mrix,

    # Proc
    @{PROC}/** r,

    # Wayland/D-Bus
    owner /run/user/@{uid}/** rw,

    # PTY
    /dev/ptmx rw,
    /dev/pts/* rw,
}
EOF

# ------------------------------------------------------------------------------
# PROFILE: OpenSnitch UI
# ------------------------------------------------------------------------------

echo "[*] Creating OpenSnitch UI profile"

cat > "${APPARMOR_DIR}/usr.bin.opensnitch-ui" << 'EOF'
# AppArmor profile for OpenSnitch UI

abi <abi/3.0>,

include <tunables/global>

profile opensnitch-ui /usr/bin/opensnitch-ui flags=(attach_disconnected) {
    include <abstractions/base>
    include <abstractions/dbus-session-strict>
    include <abstractions/fonts>
    include <abstractions/gnome>
    include <abstractions/nameservice>
    include <abstractions/python>
    include <abstractions/wayland>

    # Local network only (for daemon communication)
    network unix stream,
    network inet stream,
    network inet dgram,
    deny network inet6,

    # OpenSnitch binaries
    /usr/bin/opensnitch-ui mr,
    /usr/bin/python3* ix,
    /usr/lib/python3/** mr,

    # OpenSnitch config
    owner @{HOME}/.config/opensnitch/ rw,
    owner @{HOME}/.config/opensnitch/** rw,
    /etc/opensnitchd/** r,

    # System resources
    /usr/share/** r,
    /etc/fonts/** r,

    # Proc (for process info)
    @{PROC}/ r,
    @{PROC}/@{pid}/** r,
    @{PROC}/sys/kernel/** r,

    # Wayland/D-Bus
    owner /run/user/@{uid}/wayland-* rw,
    owner /run/user/@{uid}/bus rw,

    # Deny sensitive
    deny @{HOME}/.ssh/** rw,
    deny @{HOME}/.gnupg/** rw,
    deny /etc/shadow r,
}
EOF

# ------------------------------------------------------------------------------
# PROFILE: OpenSnitch Daemon (strict)
# ------------------------------------------------------------------------------

echo "[*] Creating OpenSnitch daemon profile"

cat > "${APPARMOR_DIR}/usr.bin.opensnitchd" << 'EOF'
# AppArmor profile for OpenSnitch daemon

abi <abi/3.0>,

include <tunables/global>

profile opensnitchd /usr/bin/opensnitchd flags=(attach_disconnected) {
    include <abstractions/base>
    include <abstractions/nameservice>

    # Capabilities needed for packet inspection
    capability net_admin,
    capability net_raw,
    capability sys_ptrace,

    # Deny dangerous capabilities
    deny capability sys_module,
    deny capability sys_rawio,
    deny capability dac_override,

    # Network (full access needed for firewall)
    network inet stream,
    network inet dgram,
    network inet raw,
    network inet6 stream,
    network inet6 dgram,
    network netlink raw,
    network unix stream,
    network unix dgram,

    # OpenSnitch binary
    /usr/bin/opensnitchd mr,

    # Configuration
    /etc/opensnitchd/ r,
    /etc/opensnitchd/** rw,

    # Rules
    /etc/opensnitchd/rules/ rw,
    /etc/opensnitchd/rules/** rw,

    # Log
    /var/log/opensnitchd.log rw,

    # Proc (required for process identification)
    @{PROC}/ r,
    @{PROC}/@{pid}/** r,
    @{PROC}/sys/kernel/** r,
    @{PROC}/sys/net/** r,

    # System info
    /etc/hosts r,
    /etc/resolv.conf r,
    /etc/passwd r,
    /etc/group r,
    /etc/machine-id r,

    # Socket for UI communication
    /run/opensnitchd/ rw,
    /run/opensnitchd/** rw,
    owner /tmp/osui.sock rw,

    # Libraries
    /usr/lib/** rm,
    /lib/** rm,

    # Deny sensitive files
    deny /etc/shadow r,
    deny /etc/gshadow r,
    deny @{HOME}/.ssh/** rw,
    deny @{HOME}/.gnupg/** rw,
}
EOF

# ------------------------------------------------------------------------------
# PROFILE: WireGuard tools
# ------------------------------------------------------------------------------

echo "[*] Creating WireGuard tools profile"

cat > "${APPARMOR_DIR}/usr.bin.wg" << 'EOF'
# AppArmor profile for WireGuard tools

abi <abi/3.0>,

include <tunables/global>

profile wg /usr/bin/wg flags=(attach_disconnected) {
    include <abstractions/base>

    # Capabilities
    capability net_admin,

    # WireGuard binaries
    /usr/bin/wg mr,
    /usr/bin/wg-quick mrix,

    # WireGuard config (read-only for wg show, etc.)
    /etc/wireguard/ r,
    /etc/wireguard/*.conf r,

    # Network interfaces
    @{PROC}/sys/net/** r,

    # Required for wg show
    /sys/class/net/ r,
    /sys/devices/** r,

    # Deny everything else
    deny @{HOME}/** rw,
    deny /etc/shadow r,
}

profile wg-quick /usr/bin/wg-quick flags=(attach_disconnected) {
    include <abstractions/base>
    include <abstractions/bash>

    # Capabilities
    capability net_admin,
    capability sys_admin,

    # Binaries
    /usr/bin/wg-quick mr,
    /bin/bash ix,
    /usr/bin/wg px -> wg,
    /sbin/ip mrix,
    /usr/bin/resolvconf mrix,
    /usr/sbin/resolvconf mrix,

    # WireGuard config
    /etc/wireguard/ r,
    /etc/wireguard/*.conf r,

    # Resolv.conf for DNS
    /etc/resolv.conf rw,
    /run/resolvconf/** rw,

    # Proc/sys
    @{PROC}/sys/net/** rw,

    # Network interfaces
    /sys/class/net/ r,
    /sys/devices/** r,
}
EOF

# ------------------------------------------------------------------------------
# PROFILE: System utilities (restrict dangerous tools)
# ------------------------------------------------------------------------------

echo "[*] Creating restricted profile for dangerous utilities"

cat > "${APPARMOR_DIR}/sbin.insmod" << 'EOF'
# Restrict kernel module loading tools

abi <abi/3.0>,

include <tunables/global>

profile insmod /sbin/insmod flags=(attach_disconnected) {
    include <abstractions/base>

    # This profile intentionally restricts module loading
    # Remove or modify if legitimate module loading is needed

    capability sys_module,

    /sbin/insmod mr,
    /lib/modules/** r,

    # Audit all module loads
    audit /lib/modules/** r,

    # Deny network
    deny network,
}

profile modprobe /sbin/modprobe flags=(attach_disconnected) {
    include <abstractions/base>

    capability sys_module,

    /sbin/modprobe mr,
    /etc/modprobe.d/** r,
    /lib/modules/** r,

    audit /lib/modules/** r,

    deny network,
}
EOF

# ------------------------------------------------------------------------------
# ENABLE: All profiles in enforce mode
# ------------------------------------------------------------------------------

echo "[*] Loading and enforcing AppArmor profiles"

# Parse all profiles
apparmor_parser -r "${APPARMOR_DIR}/usr.bin.librewolf" 2>/dev/null || true
apparmor_parser -r "${APPARMOR_DIR}/usr.bin.evince" 2>/dev/null || true
apparmor_parser -r "${APPARMOR_DIR}/usr.bin.gnome-terminal-server" 2>/dev/null || true
apparmor_parser -r "${APPARMOR_DIR}/usr.bin.opensnitch-ui" 2>/dev/null || true
apparmor_parser -r "${APPARMOR_DIR}/usr.bin.opensnitchd" 2>/dev/null || true
apparmor_parser -r "${APPARMOR_DIR}/usr.bin.wg" 2>/dev/null || true
apparmor_parser -r "${APPARMOR_DIR}/sbin.insmod" 2>/dev/null || true

# Enforce existing profiles from apparmor-profiles package
echo "[*] Enforcing system profiles from apparmor-profiles package"

# List of common profiles to enforce
PROFILES_TO_ENFORCE=(
    "usr.bin.man"
    "usr.sbin.cups-browsed"
    "usr.sbin.cupsd"
    "usr.sbin.rsyslogd"
    "usr.sbin.tcpdump"
)

for profile in "${PROFILES_TO_ENFORCE[@]}"; do
    if [[ -f "${APPARMOR_DIR}/${profile}" ]]; then
        aa-enforce "${APPARMOR_DIR}/${profile}" 2>/dev/null || true
    fi
done

# Set all loaded profiles to enforce (not complain)
echo "[*] Setting all profiles to enforce mode"
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# ------------------------------------------------------------------------------
# ENSURE: AppArmor service enabled
# ------------------------------------------------------------------------------

echo "[*] Enabling AppArmor service"
systemctl enable apparmor
systemctl restart apparmor

# ------------------------------------------------------------------------------
# AUDIT LOG INTEGRATION
# ------------------------------------------------------------------------------

echo "[*] Ensuring AppArmor denials are logged to audit"

# AppArmor uses audit subsystem automatically when auditd is running
# Just verify auditd is running
if systemctl is-active --quiet auditd; then
    echo "[+] auditd is running - AppArmor denials will be logged"
else
    echo "[!] auditd is not running - start it for full logging"
fi

# ------------------------------------------------------------------------------
# HELPER SCRIPTS
# ------------------------------------------------------------------------------

echo "[*] Creating AppArmor helper scripts"

# Script to check for denials
cat > /usr/local/bin/aa-denials << 'EOF'
#!/bin/bash
# Show recent AppArmor denials
echo "=== Recent AppArmor Denials ==="
dmesg | grep -i "apparmor.*denied" | tail -50
echo ""
echo "=== From audit log ==="
ausearch -m AVC -ts recent 2>/dev/null | grep apparmor | tail -30
EOF
chmod 700 /usr/local/bin/aa-denials

# Script to generate profile from log
cat > /usr/local/bin/aa-genprof-helper << 'EOF'
#!/bin/bash
# Helper to generate AppArmor profile for an application
if [[ -z "$1" ]]; then
    echo "Usage: aa-genprof-helper /path/to/binary"
    exit 1
fi
echo "Starting profile generation for: $1"
echo "Run the application and exercise all features, then press 'S' to scan logs"
aa-genprof "$1"
EOF
chmod 700 /usr/local/bin/aa-genprof-helper

# Script to temporarily disable a profile
cat > /usr/local/bin/aa-temp-disable << 'EOF'
#!/bin/bash
# Temporarily disable an AppArmor profile (put in complain mode)
if [[ -z "$1" ]]; then
    echo "Usage: aa-temp-disable <profile-name>"
    echo "Available profiles:"
    aa-status --enabled 2>/dev/null | grep -v "^[0-9]"
    exit 1
fi
aa-complain "$1"
echo "Profile $1 set to complain mode (logging only, not blocking)"
echo "To re-enforce: aa-enforce $1"
EOF
chmod 700 /usr/local/bin/aa-temp-disable

# ------------------------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------------------------

echo ""
echo "[+] AppArmor hardening complete"
echo ""
echo "    Status:"
aa-status --verbose 2>/dev/null | head -20
echo ""
echo "    Custom profiles created:"
echo "      - Librewolf/Firefox (browser sandbox)"
echo "      - Evince (PDF viewer - no network)"
echo "      - GNOME Terminal"
echo "      - OpenSnitch UI"
echo "      - OpenSnitch daemon"
echo "      - WireGuard tools"
echo "      - Module loading tools (insmod/modprobe)"
echo ""
echo "    Helper scripts:"
echo "      aa-denials          - View recent AppArmor denials"
echo "      aa-genprof-helper   - Generate profile for new app"
echo "      aa-temp-disable     - Temporarily disable a profile"
echo ""
echo "    If an app misbehaves:"
echo "      1. Check denials: aa-denials"
echo "      2. Temp disable: aa-temp-disable /path/to/binary"
echo "      3. Fix profile and re-enforce: aa-enforce /etc/apparmor.d/profile"
echo ""
echo "    Logs:"
echo "      dmesg | grep -i apparmor"
echo "      ausearch -m AVC | grep apparmor"

# Sudoers Hardening Module
# Target: Debian 12+ / GNOME Wayland / ThinkPad P16s Gen 2
# Policy: Strict sudo configuration, logging, command restrictions
#

set -euo pipefail

PRIMARY_USER="dev"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

# ------------------------------------------------------------------------------
# PREFLIGHT
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root"
    exit 1
fi

if ! id "$PRIMARY_USER" &>/dev/null; then
    echo "[FATAL] User '$PRIMARY_USER' does not exist"
    exit 1
fi

# ------------------------------------------------------------------------------
# BACKUP
# ------------------------------------------------------------------------------

echo "[*] Backing up sudoers configuration"
cp /etc/sudoers "/etc/sudoers${BACKUP_SUFFIX}"
cp -a /etc/sudoers.d "/etc/sudoers.d${BACKUP_SUFFIX}"

# ------------------------------------------------------------------------------
# MAIN SUDOERS: Hardened configuration
# ------------------------------------------------------------------------------

echo "[*] Writing hardened /etc/sudoers"

cat > /etc/sudoers << 'EOF'
# =============================================================================
# HARDENED SUDOERS CONFIGURATION
# Target: Single-user workstation (dev)
# Policy: Strict defaults, full logging, secure paths
# =============================================================================

# -----------------------------------------------------------------------------
# DEFAULTS: Security settings
# -----------------------------------------------------------------------------

# AUTHENTICATION: Use PAM for auth (required for U2F)
# Do NOT use !authenticate - that would bypass PAM entirely!
Defaults        authenticate
Defaults        !rootpw
Defaults        !runaspw
Defaults        !targetpw

# Password/auth timeout
Defaults        timestamp_timeout=5
Defaults        passwd_timeout=60
Defaults        passwd_tries=3

# Require TTY (prevents cron/script sudo abuse)
Defaults        requiretty

# Use PTY for all commands (isolates output, prevents escape sequences)
Defaults        use_pty

# Restrict environment variables (prevent LD_PRELOAD attacks, etc.)
Defaults        env_reset
Defaults        env_delete += "CDPATH"
Defaults        env_delete += "ENV"
Defaults        env_delete += "BASH_ENV"
Defaults        env_delete += "KRB5_CONFIG"
Defaults        env_delete += "KRB5_KTNAME"
Defaults        env_delete += "LD_*"
Defaults        env_delete += "_RLD_*"
Defaults        env_delete += "SHLIB_PATH"
Defaults        env_delete += "LIBPATH"
Defaults        env_delete += "DYLD_*"
Defaults        env_delete += "PERL5LIB"
Defaults        env_delete += "PERL5OPT"
Defaults        env_delete += "PERL5DB"
Defaults        env_delete += "PERLLIB"
Defaults        env_delete += "PERL_DEBUG"
Defaults        env_delete += "PYTHONPATH"
Defaults        env_delete += "PYTHONHOME"
Defaults        env_delete += "PYTHONINSPECT"
Defaults        env_delete += "RUBYLIB"
Defaults        env_delete += "RUBYOPT"

# Keep minimal safe environment variables
Defaults        env_keep += "LANG"
Defaults        env_keep += "LANGUAGE"
Defaults        env_keep += "LC_*"
Defaults        env_keep += "TERM"
Defaults        env_keep += "TZ"
Defaults        env_keep += "HOME"
Defaults        env_keep += "MAIL"
Defaults        env_keep += "USER"
Defaults        env_keep += "LOGNAME"

# Secure PATH (no . or writable directories)
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Logging: Log all sudo activity
Defaults        logfile="/var/log/sudo.log"
Defaults        log_input
Defaults        log_output
Defaults        iolog_dir="/var/log/sudo-io"
Defaults        iolog_file="%{user}/%{runas_user}/%{command}_%Y%m%d_%H%M%S"

# Log hostname and tty
Defaults        log_host
Defaults        log_year

# Mail alerts for bad sudo attempts (uncomment if mail is configured)
# Defaults      mail_badpass
# Defaults      mail_no_user
# Defaults      mail_no_perms
# Defaults      mailto="root"

# Don't allow sudo to be used to run shell escapes
Defaults        noexec

# Lecture user on first sudo use
Defaults        lecture=always
Defaults        lecture_file=/etc/sudoers.d/lecture

# Insults off (don't draw attention to failed attempts)
Defaults        !insults

# Don't cache credentials per-tty (single auth session)
Defaults        timestamp_type=global

# Prevent privilege escalation via sudo -e (sudoedit)
Defaults        !env_editor
Defaults        editor=/usr/bin/nano:/usr/bin/vim.tiny

# Umask for sudo commands
Defaults        umask=0027

# Prevent running sudo from non-standard locations
Defaults        ignore_dot
Defaults        ignore_local_sudoers

# Set syslog facility
Defaults        syslog=auth
Defaults        syslog_badpri=alert
Defaults        syslog_goodpri=notice

# -----------------------------------------------------------------------------
# HOST ALIASES
# -----------------------------------------------------------------------------

Host_Alias      LOCAL = localhost, 127.0.0.1

# -----------------------------------------------------------------------------
# USER ALIASES
# -----------------------------------------------------------------------------

User_Alias      ADMIN = dev

# -----------------------------------------------------------------------------
# COMMAND ALIASES: Dangerous commands that need extra restriction
# -----------------------------------------------------------------------------

# Shells - extremely dangerous, can escape any restriction
Cmnd_Alias      SHELLS = /bin/sh, /bin/bash, /bin/dash, /bin/zsh, \
                         /usr/bin/sh, /usr/bin/bash, /usr/bin/dash, /usr/bin/zsh, \
                         /bin/csh, /bin/tcsh, /usr/bin/csh, /usr/bin/tcsh, \
                         /usr/bin/fish

# Commands that spawn shells or allow escapes
Cmnd_Alias      SHELL_ESCAPES = /usr/bin/vim, /usr/bin/vi, /usr/bin/nvim, \
                                /usr/bin/nano, /usr/bin/emacs, /usr/bin/less, \
                                /usr/bin/more, /usr/bin/man, /usr/bin/ftp, \
                                /usr/bin/gdb, /usr/bin/python*, /usr/bin/perl, \
                                /usr/bin/ruby, /usr/bin/lua*, /usr/bin/irb, \
                                /usr/bin/awk, /usr/bin/nawk, /usr/bin/mawk, \
                                /usr/bin/gawk, /usr/bin/find, /usr/bin/xargs

# SU command (use sudo directly, not su through sudo)
Cmnd_Alias      SU = /bin/su, /usr/bin/su

# Password/user modification
Cmnd_Alias      PASSWD = /usr/bin/passwd, /usr/sbin/useradd, /usr/sbin/userdel, \
                         /usr/sbin/usermod, /usr/sbin/groupadd, /usr/sbin/groupdel, \
                         /usr/sbin/groupmod, /usr/sbin/vipw, /usr/sbin/vigr

# Sudoers modification
Cmnd_Alias      SUDOERS = /usr/sbin/visudo, /usr/bin/sudoedit /etc/sudoers*, \
                          /bin/cat /etc/sudoers*, /bin/nano /etc/sudoers*, \
                          /usr/bin/vim /etc/sudoers*

# Network tools that could exfiltrate or attack
Cmnd_Alias      NETWORK_DANGER = /usr/bin/nc, /usr/bin/ncat, /usr/bin/netcat, \
                                  /usr/bin/socat, /usr/bin/curl, /usr/bin/wget, \
                                  /usr/bin/ssh, /usr/bin/scp, /usr/bin/sftp, \
                                  /usr/bin/rsync, /usr/bin/telnet, /usr/bin/ftp

# Disk/filesystem tools that could destroy data
Cmnd_Alias      DISK_DANGER = /sbin/fdisk, /sbin/parted, /sbin/mkfs*, \
                               /sbin/mke2fs, /sbin/mkswap, /sbin/wipefs, \
                               /bin/dd, /sbin/hdparm, /sbin/badblocks

# Kernel/module tools
Cmnd_Alias      KERNEL = /sbin/insmod, /sbin/rmmod, /sbin/modprobe, \
                         /sbin/sysctl, /usr/bin/dmesg

# System control
Cmnd_Alias      SYSTEM = /sbin/shutdown, /sbin/reboot, /sbin/halt, \
                         /sbin/poweroff, /sbin/init, /bin/systemctl

# Package management
Cmnd_Alias      PACKAGES = /usr/bin/apt, /usr/bin/apt-get, /usr/bin/aptitude, \
                            /usr/bin/dpkg, /usr/bin/snap, /usr/bin/flatpak

# Security tools that could leak info or modify security
Cmnd_Alias      SECURITY = /usr/sbin/iptables*, /usr/sbin/ip6tables*, \
                            /usr/sbin/nft, /usr/bin/aa-*, /usr/sbin/aa-*, \
                            /usr/sbin/auditctl, /usr/sbin/aureport, /usr/sbin/ausearch

# Allowed system administration commands
Cmnd_Alias      ADMIN_CMDS = /bin/systemctl status *, \
                              /bin/systemctl start *, \
                              /bin/systemctl stop *, \
                              /bin/systemctl restart *, \
                              /bin/journalctl, \
                              /usr/bin/apt update, \
                              /usr/bin/apt upgrade, \
                              /usr/bin/apt install *, \
                              /usr/bin/apt remove *, \
                              /sbin/ip addr, \
                              /sbin/ip route, \
                              /usr/bin/wg show, \
                              /usr/bin/wg-quick up *, \
                              /usr/bin/wg-quick down *, \
                              /usr/sbin/iptables -L *, \
                              /usr/sbin/iptables-save, \
                              /usr/local/bin/audit-*, \
                              /usr/local/bin/aa-*

# -----------------------------------------------------------------------------
# USER PRIVILEGES
# -----------------------------------------------------------------------------

# Root can do everything (emergency)
root    ALL=(ALL:ALL) ALL

# Primary user: full access but with restrictions and logging
# NOEXEC prevents shell escapes from most commands
dev     ALL=(ALL:ALL) ALL, NOEXEC: SHELL_ESCAPES, !SU, !SUDOERS

# Alternative stricter config (uncomment to use instead of above):
# Only allow specific admin commands, deny dangerous ones explicitly
# dev   ALL=(ALL:ALL) ADMIN_CMDS, !SHELLS, !SU, !SUDOERS, !DISK_DANGER

# -----------------------------------------------------------------------------
# INCLUDE DIRECTORY
# -----------------------------------------------------------------------------

# Include additional configuration from /etc/sudoers.d/
# Files must not contain . or ~ and must be mode 0440
@includedir /etc/sudoers.d
EOF

# Set proper permissions
chmod 440 /etc/sudoers
chown root:root /etc/sudoers

# ------------------------------------------------------------------------------
# SUDOERS.D: Additional drop-in configs
# ------------------------------------------------------------------------------

echo "[*] Creating sudoers.d configurations"

# Clean out any existing configs (backup already made)
rm -f /etc/sudoers.d/*

# Lecture file
cat > /etc/sudoers.d/lecture << 'EOF'

    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║   WARNING: You are about to execute a privileged command.        ║
    ║                                                                  ║
    ║   All sudo activity is logged and monitored.                     ║
    ║   Unauthorized access attempts will be investigated.             ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝

EOF
chmod 440 /etc/sudoers.d/lecture

# OpenSnitch: Allow managing without password for convenience (optional)
cat > /etc/sudoers.d/10-opensnitch << 'EOF'
# Allow dev to manage OpenSnitch service
dev     ALL=(root) NOPASSWD: /bin/systemctl status opensnitchd, \
                             /bin/systemctl start opensnitchd, \
                             /bin/systemctl stop opensnitchd, \
                             /bin/systemctl restart opensnitchd
EOF
chmod 440 /etc/sudoers.d/10-opensnitch

# WireGuard: Allow managing VPN
cat > /etc/sudoers.d/11-wireguard << 'EOF'
# Allow dev to manage WireGuard VPN
dev     ALL=(root) NOPASSWD: /usr/bin/wg show, \
                             /usr/bin/wg-quick up wg0, \
                             /usr/bin/wg-quick down wg0
EOF
chmod 440 /etc/sudoers.d/11-wireguard

# Audit tools: Allow viewing audit logs
cat > /etc/sudoers.d/12-audit << 'EOF'
# Allow dev to run audit analysis tools
dev     ALL=(root) NOPASSWD: /usr/local/bin/audit-*, \
                             /usr/sbin/aureport, \
                             /usr/sbin/ausearch
EOF
chmod 440 /etc/sudoers.d/12-audit

# AppArmor: Allow status checks
cat > /etc/sudoers.d/13-apparmor << 'EOF'
# Allow dev to check AppArmor status
dev     ALL=(root) NOPASSWD: /usr/sbin/aa-status, \
                             /usr/local/bin/aa-denials
EOF
chmod 440 /etc/sudoers.d/13-apparmor

# System monitoring: Allow non-sensitive monitoring
cat > /etc/sudoers.d/14-monitoring << 'EOF'
# Allow dev to view system status
dev     ALL=(root) NOPASSWD: /bin/journalctl, \
                             /bin/systemctl status *, \
                             /usr/bin/iotop, \
                             /usr/bin/nethogs
EOF
chmod 440 /etc/sudoers.d/14-monitoring

# Escalation monitor: Allow running manually
cat > /etc/sudoers.d/15-escalation-monitor << 'EOF'
# Allow dev to run escalation monitor
dev     ALL=(root) NOPASSWD: /usr/local/bin/escalation-monitor
EOF
chmod 440 /etc/sudoers.d/15-escalation-monitor

# ------------------------------------------------------------------------------
# LOGGING: Create directories and configure
# ------------------------------------------------------------------------------

echo "[*] Setting up sudo logging"

# Create sudo log file
touch /var/log/sudo.log
chmod 600 /var/log/sudo.log
chown root:root /var/log/sudo.log

# Create I/O log directory
mkdir -p /var/log/sudo-io
chmod 700 /var/log/sudo-io
chown root:root /var/log/sudo-io

# Logrotate config for sudo logs
cat > /etc/logrotate.d/sudo << 'EOF'
/var/log/sudo.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 600 root root
}

/var/log/sudo-io/*/* {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    maxage 30
}
EOF

# ------------------------------------------------------------------------------
# PAM: Ensure sudo uses our hardened PAM config
# ------------------------------------------------------------------------------

echo "[*] Verifying sudo PAM configuration"

# Our PAM module from earlier should handle this, but verify
if ! grep -q "pam_u2f.so" /etc/pam.d/sudo; then
    echo "[!] Warning: sudo PAM config may not be using U2F"
    echo "    Verify /etc/pam.d/sudo includes pam_u2f.so"
fi

# ------------------------------------------------------------------------------
# VALIDATION: Check sudoers syntax
# ------------------------------------------------------------------------------

echo "[*] Validating sudoers configuration"

if visudo -c; then
    echo "[+] Sudoers syntax is valid"
else
    echo "[FATAL] Sudoers syntax error! Restoring backup..."
    cp "/etc/sudoers${BACKUP_SUFFIX}" /etc/sudoers
    cp -a "/etc/sudoers.d${BACKUP_SUFFIX}"/* /etc/sudoers.d/
    exit 1
fi

# ------------------------------------------------------------------------------
# HELPER SCRIPTS
# ------------------------------------------------------------------------------

echo "[*] Creating sudo helper scripts"

# Script to view sudo logs
cat > /usr/local/bin/sudo-log << 'EOF'
#!/bin/bash
# View recent sudo activity
echo "=== Recent Sudo Commands ==="
tail -100 /var/log/sudo.log 2>/dev/null || echo "No sudo log found"
echo ""
echo "=== Failed Sudo Attempts ==="
grep -i "NOT" /var/log/sudo.log 2>/dev/null | tail -20 || echo "No failures found"
echo ""
echo "=== From auth.log ==="
grep -i sudo /var/log/auth.log 2>/dev/null | tail -20 || echo "No auth.log entries"
EOF
chmod 700 /usr/local/bin/sudo-log

# Script to view I/O logs (what was typed/output)
cat > /usr/local/bin/sudo-replay << 'EOF'
#!/bin/bash
# Replay a sudo session (requires session ID)
if [[ -z "$1" ]]; then
    echo "Usage: sudo-replay <session-id>"
    echo ""
    echo "Available sessions:"
    find /var/log/sudo-io -name "log" -type f 2>/dev/null | head -20
    exit 1
fi
sudoreplay -d /var/log/sudo-io "$1"
EOF
chmod 700 /usr/local/bin/sudo-replay

# Script to check sudo configuration
cat > /usr/local/bin/sudo-check << 'EOF'
#!/bin/bash
# Check sudo configuration and status
echo "=== Sudoers Syntax Check ==="
visudo -c
echo ""
echo "=== Current User Privileges ==="
sudo -l 2>/dev/null || echo "Cannot determine privileges"
echo ""
echo "=== Sudo Defaults ==="
sudo -V | grep -A 50 "Sudoers policy plugin"
EOF
chmod 700 /usr/local/bin/sudo-check

# ------------------------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------------------------

echo ""
echo "[+] Sudoers hardening complete"
echo ""
echo "    Configuration:"
echo "      - Timestamp timeout: 5 minutes"
echo "      - Requires TTY (no cron/script abuse)"
echo "      - Uses PTY isolation"
echo "      - Environment sanitized (LD_PRELOAD, etc. stripped)"
echo "      - Secure PATH enforced"
echo "      - NOEXEC on shell escape commands"
echo "      - SU command denied through sudo"
echo "      - Sudoers self-modification denied"
echo ""
echo "    Logging:"
echo "      - All commands logged to /var/log/sudo.log"
echo "      - Full I/O logging to /var/log/sudo-io/"
echo "      - Syslog integration (auth facility)"
echo ""
echo "    NOPASSWD shortcuts for dev:"
echo "      - OpenSnitch service control"
echo "      - WireGuard VPN control"
echo "      - Audit log viewing"
echo "      - AppArmor status"
echo "      - System monitoring"
echo "      - Escalation monitor"
echo ""
echo "    Helper scripts:"
echo "      sudo-log      - View sudo activity"
echo "      sudo-replay   - Replay sudo session I/O"
echo "      sudo-check    - Verify sudo configuration"
echo ""
echo "    Test with:"
echo "      sudo -l                    # List your privileges"
echo "      sudo whoami                # Should require U2F"
echo "      sudo cat /etc/shadow       # Should work"
echo "      sudo su                    # Should be DENIED"
echo ""


#
# GRUB Bootloader Hardening Module
# Target: Debian 12+ / ThinkPad P16s Gen 2
# Policy: Password-protect bootloader, prevent single-user bypass, secure config
#
set -euo pipefail

BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"
GRUB_DIR="/etc/grub.d"
GRUB_DEFAULT="/etc/default/grub"
GRUB_CUSTOM="${GRUB_DIR}/40_custom"
GRUB_PASSWORD_CFG="${GRUB_DIR}/01_password"

# ------------------------------------------------------------------------------
# PREFLIGHT
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root"
    exit 1
fi

# Check for GRUB
if ! command -v grub-mkpasswd-pbkdf2 &>/dev/null; then
    echo "[FATAL] GRUB utilities not found. Install grub-common."
    exit 1
fi

# ------------------------------------------------------------------------------
# BACKUP
# ------------------------------------------------------------------------------

echo "[*] Backing up GRUB configuration"
[[ -f "$GRUB_DEFAULT" ]] && cp "$GRUB_DEFAULT" "${GRUB_DEFAULT}${BACKUP_SUFFIX}"
[[ -f /boot/grub/grub.cfg ]] && cp /boot/grub/grub.cfg "/boot/grub/grub.cfg${BACKUP_SUFFIX}"
cp -a "$GRUB_DIR" "${GRUB_DIR}${BACKUP_SUFFIX}"

# ------------------------------------------------------------------------------
# PASSWORD: Generate GRUB password
# ------------------------------------------------------------------------------

echo ""
echo "=============================================="
echo "GRUB PASSWORD SETUP"
echo "=============================================="
echo ""
echo "This password protects the bootloader from:"
echo "  - Editing boot parameters (e.g., init=/bin/bash)"
echo "  - Booting into single-user/recovery mode"
echo "  - Accessing GRUB command line"
echo ""
echo "IMPORTANT: Store this password securely!"
echo "If lost, you'll need a live USB to recover."
echo ""

# Generate password interactively or use provided one
if [[ -t 0 ]]; then
    # Interactive mode
    echo "Enter a GRUB bootloader password:"
    GRUB_PASS_HASH=$(grub-mkpasswd-pbkdf2 | grep "grub.pbkdf2" | awk '{print $NF}')
else
    # Non-interactive - generate random password
    RANDOM_PASS=$(openssl rand -base64 24)
    echo "[*] Non-interactive mode: generating random password"
    echo "[!] GRUB PASSWORD: ${RANDOM_PASS}"
    echo "[!] SAVE THIS PASSWORD - YOU WILL NEED IT TO MODIFY BOOT"
    echo ""
    GRUB_PASS_HASH=$(echo -e "${RANDOM_PASS}\n${RANDOM_PASS}" | grub-mkpasswd-pbkdf2 | grep "grub.pbkdf2" | awk '{print $NF}')
fi

if [[ -z "$GRUB_PASS_HASH" ]]; then
    echo "[FATAL] Failed to generate GRUB password hash"
    exit 1
fi

echo "[+] Password hash generated successfully"

# ------------------------------------------------------------------------------
# GRUB PASSWORD CONFIG: Create password protection script
# ------------------------------------------------------------------------------

echo "[*] Creating GRUB password configuration"

cat > "$GRUB_PASSWORD_CFG" << EOF
#!/bin/sh
# GRUB Password Protection
# Generated by hardening script

cat << 'GRUB_PASSWORD_EOF'
# Superuser for GRUB (required to edit entries or access command line)
set superusers="admin"
password_pbkdf2 admin ${GRUB_PASS_HASH}
GRUB_PASSWORD_EOF
EOF

chmod 755 "$GRUB_PASSWORD_CFG"
chown root:root "$GRUB_PASSWORD_CFG"

# ------------------------------------------------------------------------------
# GRUB CONFIG: Modify 10_linux to require password for dangerous options
# ------------------------------------------------------------------------------

echo "[*] Configuring boot entry restrictions"

# Create wrapper script that modifies menu entries
cat > "${GRUB_DIR}/09_password_policy" << 'EOF'
#!/bin/sh
# Password policy for boot entries

cat << 'POLICY_EOF'
# Require password for all entries by default
# Individual entries can override with --unrestricted

# Export function to check for recovery mode
set check_signatures=no
POLICY_EOF
EOF

chmod 755 "${GRUB_DIR}/09_password_policy"

# ------------------------------------------------------------------------------
# MODIFY 10_LINUX: Restrict recovery mode entries
# ------------------------------------------------------------------------------

echo "[*] Modifying boot entry generation for restricted access"

# Patch 10_linux to add --users "" for normal boot (unrestricted)
# but keep recovery mode restricted (requires password)

LINUX_SCRIPT="${GRUB_DIR}/10_linux"

if [[ -f "$LINUX_SCRIPT" ]]; then
    # Backup original
    cp "$LINUX_SCRIPT" "${LINUX_SCRIPT}${BACKUP_SUFFIX}"
    
    # Add --unrestricted to normal boot entries only
    # Recovery entries remain password-protected
    
    # Check if already patched
    if ! grep -q "unrestricted" "$LINUX_SCRIPT"; then
        echo "[*] Patching 10_linux for restricted recovery mode"
        
        # This sed command adds --unrestricted to normal menuentry lines
        # but NOT to recovery/single-user entries
        sed -i "s/menuentry '\$(echo \"\$title\" | grub_quote)' \${CLASS}/menuentry '\$(echo \"\$title\" | grub_quote)' \${CLASS} --unrestricted/g" "$LINUX_SCRIPT"
        sed -i "s/menuentry '\$(echo \"\$os\" | grub_quote)' \${CLASS}/menuentry '\$(echo \"\$os\" | grub_quote)' \${CLASS} --unrestricted/g" "$LINUX_SCRIPT"
    else
        echo "[*] 10_linux already patched"
    fi
fi

# ------------------------------------------------------------------------------
# GRUB DEFAULTS: Harden default configuration
# ------------------------------------------------------------------------------

echo "[*] Hardening GRUB defaults"

# Read current config and modify
if [[ -f "$GRUB_DEFAULT" ]]; then
    # Remove existing hardening-related lines to avoid duplicates
    sed -i '/^GRUB_TIMEOUT=/d' "$GRUB_DEFAULT"
    sed -i '/^GRUB_TIMEOUT_STYLE=/d' "$GRUB_DEFAULT"
    sed -i '/^GRUB_DISABLE_RECOVERY=/d' "$GRUB_DEFAULT"
    sed -i '/^GRUB_DISABLE_SUBMENU=/d' "$GRUB_DEFAULT"
    sed -i '/^GRUB_TERMINAL=/d' "$GRUB_DEFAULT"
    sed -i '/^GRUB_RECORDFAIL_TIMEOUT=/d' "$GRUB_DEFAULT"
fi

cat >> "$GRUB_DEFAULT" << 'EOF'

# =============================================================================
# HARDENED GRUB SETTINGS
# =============================================================================

# Boot timeout (seconds) - short but visible
GRUB_TIMEOUT=3

# Timeout style: menu (shows menu), countdown, hidden
# Use 'menu' so you can see if something tries to modify boot
GRUB_TIMEOUT_STYLE=menu

# Disable recovery mode entries entirely (optional - more secure)
# Comment out if you want recovery mode available (but password protected)
GRUB_DISABLE_RECOVERY=true

# Disable submenu (all entries at top level)
GRUB_DISABLE_SUBMENU=y

# Recordfail timeout (after failed boot)
GRUB_RECORDFAIL_TIMEOUT=3

# Terminal output (console only, no serial)
GRUB_TERMINAL=console

EOF

# ------------------------------------------------------------------------------
# GRUB CUSTOM: Add security notice
# ------------------------------------------------------------------------------

echo "[*] Adding security banner to GRUB"

cat > "$GRUB_CUSTOM" << 'EOF'
#!/bin/sh
exec tail -n +3 $0

# Custom menu entry to show security notice
menuentry '[ SECURITY NOTICE: Bootloader is password protected ]' --unrestricted {
    echo "This system's bootloader is password protected."
    echo "Editing boot parameters or accessing recovery mode requires authentication."
    echo ""
    echo "Press any key to continue..."
    sleep --interruptible 9999
}
EOF

chmod 755 "$GRUB_CUSTOM"

# ------------------------------------------------------------------------------
# PERMISSIONS: Lock down GRUB files
# ------------------------------------------------------------------------------

echo "[*] Setting restrictive permissions on GRUB files"

# GRUB directory
chmod 700 /boot/grub
chown root:root /boot/grub

# GRUB config files
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chown root:root /boot/grub/grub.cfg 2>/dev/null || true

# GRUB configuration directory
chmod 700 "$GRUB_DIR"
chown root:root "$GRUB_DIR"
chmod 700 "${GRUB_DIR}"/*
chown root:root "${GRUB_DIR}"/*

# Default config
chmod 600 "$GRUB_DEFAULT"
chown root:root "$GRUB_DEFAULT"

# Password config (especially important)
chmod 700 "$GRUB_PASSWORD_CFG"
chown root:root "$GRUB_PASSWORD_CFG"

# ------------------------------------------------------------------------------
# IMMUTABLE: Prevent tampering (optional)
# ------------------------------------------------------------------------------

echo "[*] Setting immutable flags on critical GRUB files"

# Make password config immutable
chattr +i "$GRUB_PASSWORD_CFG" 2>/dev/null || true

# Note: Don't make grub.cfg immutable as it needs to be regenerated
# when kernels are updated

# ------------------------------------------------------------------------------
# UEFI SECURE BOOT: Check status and advise
# ------------------------------------------------------------------------------

echo "[*] Checking Secure Boot status"

if [[ -d /sys/firmware/efi ]]; then
    echo "[+] System is booted in UEFI mode"
    
    if command -v mokutil &>/dev/null; then
        SB_STATE=$(mokutil --sb-state 2>/dev/null || echo "Unknown")
        echo "    Secure Boot: ${SB_STATE}"
        
        if echo "$SB_STATE" | grep -qi "disabled"; then
            echo ""
            echo "[!] RECOMMENDATION: Enable Secure Boot in BIOS/UEFI settings"
            echo "    This prevents unsigned bootloaders/kernels from loading"
            echo "    Combined with GRUB password, provides strong boot security"
        fi
    else
        echo "    Install mokutil to check Secure Boot status: apt install mokutil"
    fi
else
    echo "[*] System is booted in Legacy BIOS mode"
    echo "    Consider switching to UEFI with Secure Boot for better security"
fi

# ------------------------------------------------------------------------------
# REGENERATE GRUB CONFIG
# ------------------------------------------------------------------------------

echo "[*] Regenerating GRUB configuration"

update-grub

if [[ $? -eq 0 ]]; then
    echo "[+] GRUB configuration updated successfully"
else
    echo "[FATAL] GRUB update failed! Restoring backup..."
    cp "${GRUB_DEFAULT}${BACKUP_SUFFIX}" "$GRUB_DEFAULT"
    cp -a "${GRUB_DIR}${BACKUP_SUFFIX}"/* "$GRUB_DIR/"
    update-grub
    exit 1
fi

# ------------------------------------------------------------------------------
# FINAL PERMISSIONS CHECK
# ------------------------------------------------------------------------------

echo "[*] Final permissions check on /boot/grub/grub.cfg"
chmod 600 /boot/grub/grub.cfg
chown root:root /boot/grub/grub.cfg

# ------------------------------------------------------------------------------
# BIOS/UEFI RECOMMENDATIONS
# ------------------------------------------------------------------------------

echo ""
echo "=============================================="
echo "BIOS/UEFI SETTINGS RECOMMENDATIONS"
echo "=============================================="
echo ""
echo "For complete boot security, configure in BIOS/UEFI:"
echo ""
echo "  1. Set BIOS/UEFI admin password"
echo "  2. Disable boot from USB/CD (or set password)"
echo "  3. Enable Secure Boot (if using UEFI)"
echo "  4. Set boot order to internal drive only"
echo "  5. Disable network boot (PXE)"
echo "  6. Enable chassis intrusion detection (if available)"
echo ""
echo "ThinkPad-specific (BIOS → Security):"
echo "  - Supervisor Password: SET THIS"
echo "  - Power-On Password: Optional (U2F handles login)"
echo "  - Secure Boot: Enable"
echo "  - Boot Device Guard: Enable"
echo "  - Device Guard: Enable"
echo ""

# ------------------------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------------------------

echo ""
echo "[+] GRUB hardening complete"
echo ""
echo "    Protection enabled:"
echo "      - Bootloader password required for:"
echo "          * Editing boot parameters"
echo "          * Accessing GRUB command line"
echo "          * Booting recovery mode (if enabled)"
echo "      - Normal boot: No password required"
echo "      - Recovery mode: Disabled entirely"
echo "      - Boot timeout: 3 seconds"
echo "      - GRUB files: Restricted permissions (600/700)"
echo ""
echo "    Password user: admin"
echo "    Password: (the one you just entered)"
echo ""
echo "    IMPORTANT:"
echo "      - Store the GRUB password securely"
echo "      - If forgotten, recovery requires live USB"
echo "      - Password config is immutable (chattr +i)"
echo ""
echo "    To test:"
echo "      1. Reboot"
echo "      2. At GRUB menu, press 'e' to edit"
echo "      3. Should prompt for username (admin) and password"
echo ""
echo "    To modify later:"
echo "      chattr -i ${GRUB_PASSWORD_CFG}"
echo "      (make changes)"
echo "      update-grub"
echo "      chattr +i ${GRUB_PASSWORD_CFG}"
echo ""
echo "    Backup location:"
echo "      ${GRUB_DEFAULT}${BACKUP_SUFFIX}"
echo "      ${GRUB_DIR}${BACKUP_SUFFIX}/"
echo "      /boot/grub/grub.cfg${BACKUP_SUFFIX}"

# USB Hardening Module (USBGuard)
# Target: Debian 12+ / ThinkPad P16s Gen 2
# Policy: Whitelist only keyboard, mouse, U2F key - block everything else
#

set -euo pipefail

PRIMARY_USER="dev"
BACKUP_DIR="/root/usbguard-backup-$(date +%Y%m%d%H%M%S)"

# ------------------------------------------------------------------------------
# PREFLIGHT
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root"
    exit 1
fi

# ------------------------------------------------------------------------------
# INSTALL: USBGuard
# ------------------------------------------------------------------------------

echo "[*] Installing USBGuard"
apt-get update
apt-get install -y usbguard usbutils

# ------------------------------------------------------------------------------
# BACKUP
# ------------------------------------------------------------------------------

echo "[*] Creating backup directory"
mkdir -p "$BACKUP_DIR"

if [[ -d /etc/usbguard ]]; then
    cp -a /etc/usbguard "$BACKUP_DIR/"
fi

# ------------------------------------------------------------------------------
# INITIAL POLICY: Generate from currently connected devices
# ------------------------------------------------------------------------------

echo "[*] Generating initial policy from connected devices"
echo ""
echo "    Currently connected USB devices:"
lsusb
echo ""

# Generate policy allowing currently connected devices
usbguard generate-policy > /etc/usbguard/rules.conf

echo "[*] Initial policy generated from connected devices"
echo ""

# ------------------------------------------------------------------------------
# USBGUARD: Add explicit rules for FIDO/U2F authenticators
# ------------------------------------------------------------------------------

echo "[*] Adding FIDO/U2F authenticator whitelist rules"

# FIDO/U2F devices use interface class 0x0b (Smart Card) or specific HID protocols
# These rules ensure U2F keys work even if not connected during policy generation
cat >> /etc/usbguard/rules.conf << 'EOF'

# =============================================================================
# FIDO/U2F Security Key Rules - Always allow authenticators
# =============================================================================

# Yubico devices (YubiKey)
allow with-interface one-of { 03:01:01 03:00:00 0b:*:* } if { id-vendor == "1050" }

# Google Titan Security Key
allow with-interface one-of { 03:01:01 03:00:00 0b:*:* } if { id-vendor == "18d1" }

# Feitian FIDO keys
allow with-interface one-of { 03:01:01 03:00:00 0b:*:* } if { id-vendor == "096e" }

# SoloKeys
allow with-interface one-of { 03:01:01 03:00:00 0b:*:* } if { id-vendor == "0483" }

# Thetis FIDO keys
allow with-interface one-of { 03:01:01 03:00:00 0b:*:* } if { id-vendor == "1ea8" }

# Nitrokey
allow with-interface one-of { 03:01:01 03:00:00 0b:*:* } if { id-vendor == "20a0" }

# Generic FIDO HID interface (fallback for other FIDO2/U2F devices)
# Interface 03:01:01 = HID, Boot Interface, Keyboard (used by FIDO)
# This is more permissive - comment out if you want strict vendor whitelisting
# allow with-interface equals { 03:01:01 }

EOF

echo "[+] FIDO/U2F rules added to /etc/usbguard/rules.conf"

# ------------------------------------------------------------------------------
# CONFIGURATION: USBGuard daemon settings
# ------------------------------------------------------------------------------

echo "[*] Configuring USBGuard daemon"

cat > /etc/usbguard/usbguard-daemon.conf << 'EOF'
# =============================================================================
# USBGuard Daemon Configuration
# Policy: Strict whitelist, block by default
# =============================================================================

# Rule file location
RuleFile=/etc/usbguard/rules.conf

# Implicit policy for devices not matching any rule
# block = block device
# reject = block and remove from system
# allow = allow device (DANGEROUS)
ImplicitPolicyTarget=block

# Policy for devices present at daemon startup
# apply-policy = apply rules from RuleFile
# keep = keep current authorization state
# allow = allow all (DANGEROUS)
PresentDevicePolicy=apply-policy

# Policy for controller devices (USB hubs, etc.)
PresentControllerPolicy=keep

# Insert devices rules in this position
# first = insert at beginning
# last = insert at end
# before = before specific rule
# after = after specific rule
InsertedDevicePolicy=apply-policy

# Authorization method
# AuthorizedDefault=none (block by default)
RestoreControllerDeviceState=false

# IPC: Who can interact with daemon
# Allow root and usbguard group
IPCAllowedUsers=root
IPCAllowedGroups=root usbguard

# IPC access control
IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/

# Device rules with audit
AuditBackend=LinuxAudit
AuditFilePath=/var/log/usbguard/usbguard-audit.log

# Device attributes hashing
DeviceManagerBackend=uevent
EOF

# ------------------------------------------------------------------------------
# IPC ACCESS CONTROL: Allow primary user to manage
# ------------------------------------------------------------------------------

echo "[*] Configuring IPC access control"

mkdir -p /etc/usbguard/IPCAccessControl.d

# Root full access
cat > /etc/usbguard/IPCAccessControl.d/root.conf << 'EOF'
# Root has full access
user=root
EOF

# Primary user can list and allow/block devices
cat > /etc/usbguard/IPCAccessControl.d/dev.conf << EOF
# Primary user can manage USB devices
user=${PRIMARY_USER} Devices=modify,list,listen Policy=list
EOF

# ------------------------------------------------------------------------------
# RULES: Create hardened rules file
# ------------------------------------------------------------------------------

echo "[*] Creating hardened USB rules"

# First, let's identify the currently connected devices we want to keep
echo "[*] Analyzing connected devices for whitelist..."

# Store the auto-generated policy
cp /etc/usbguard/rules.conf "${BACKUP_DIR}/rules-autogenerated.conf"

# Create new rules file with comments and structure
cat > /etc/usbguard/rules.conf << 'EOF'
# =============================================================================
# USBGuard Rules - Hardened USB Device Whitelist
# Target: ThinkPad P16s Gen 2
# Policy: Allow only essential devices, block all others
# =============================================================================
#
# Rule syntax:
#   allow|block|reject [rule conditions] [rule attributes]
#
# Common conditions:
#   id <vendor>:<product>    - Match by USB ID
#   hash "<hash>"            - Match by device hash (most secure)
#   name "<name>"            - Match by device name
#   serial "<serial>"        - Match by serial number
#   via-port "<port>"        - Match by physical port
#   with-interface <class>   - Match by interface class
#
# Interface classes:
#   03:*:* = HID (keyboard, mouse)
#   08:*:* = Mass storage
#   0e:*:* = Video (webcam)
#   0b:*:* = Smart card (U2F keys)
#   ff:*:* = Vendor-specific
#
# =============================================================================

# -----------------------------------------------------------------------------
# INTERNAL DEVICES: Allow built-in ThinkPad USB controllers/hubs
# -----------------------------------------------------------------------------

# Allow USB root hubs (internal controllers)
allow with-interface equals { 09:00:00 }

# -----------------------------------------------------------------------------
# HID DEVICES: Keyboards and mice
# -----------------------------------------------------------------------------

# Allow standard HID devices (keyboard, mouse, touchpad)
# Interface class 03 = HID
allow with-interface one-of { 03:00:01 03:01:01 03:01:02 }

# -----------------------------------------------------------------------------
# U2F / SECURITY KEYS
# -----------------------------------------------------------------------------

# YubiKey (all models)
allow id 1050:* name match /YubiKey/ with-interface one-of { 03:*:* 0b:*:* ff:*:* }

# Google Titan Security Key
allow id 18d1:5026 with-interface one-of { 03:*:* 0b:*:* }

# Feitian ePass FIDO
allow id 096e:* with-interface one-of { 03:*:* 0b:*:* }

# Thetis FIDO
allow id 1ea8:* with-interface one-of { 03:*:* 0b:*:* }

# SoloKeys
allow id 0483:a2ca with-interface one-of { 03:*:* 0b:*:* }

# Nitrokey
allow id 20a0:42* with-interface one-of { 03:*:* 0b:*:* }

# Generic FIDO/U2F (smart card interface)
allow with-interface equals { 0b:00:00 }

# -----------------------------------------------------------------------------
# AUDIO DEVICES (if using USB headset/DAC)
# -----------------------------------------------------------------------------

# Uncomment if you use USB audio devices
# allow with-interface one-of { 01:01:* 01:02:* 01:03:* }

# -----------------------------------------------------------------------------
# WEBCAM (built-in)
# -----------------------------------------------------------------------------

# Allow built-in webcam (video class)
# Uncomment if you use the webcam
# allow with-interface one-of { 0e:01:* 0e:02:* }

# -----------------------------------------------------------------------------
# MASS STORAGE: BLOCKED BY DEFAULT
# -----------------------------------------------------------------------------

# Block all mass storage devices by default (USB drives, external HDDs)
# This prevents data exfiltration and malicious USB attacks (BadUSB, etc.)
reject with-interface equals { 08:*:* }

# To temporarily allow a specific USB drive, use:
#   usbguard allow-device <device-id>
# Or add a hash-based rule for a specific trusted drive

# -----------------------------------------------------------------------------
# NETWORK ADAPTERS: BLOCKED
# -----------------------------------------------------------------------------

# Block USB network adapters (could be used to bypass network controls)
reject with-interface equals { 02:*:* }   # CDC (Communications)
reject with-interface equals { 0a:*:* }   # CDC-Data
reject with-interface equals { e0:*:* }   # Wireless controller

# -----------------------------------------------------------------------------
# PRINTERS: BLOCKED
# -----------------------------------------------------------------------------

# Block printers (local-only system, no printing)
reject with-interface equals { 07:*:* }

# -----------------------------------------------------------------------------
# CATCH-ALL: Block everything else
# -----------------------------------------------------------------------------

# Any device not matching above rules will be blocked by ImplicitPolicyTarget
# This is just an explicit reminder
# reject

EOF

# ------------------------------------------------------------------------------
# APPEND CURRENT DEVICE HASHES: For precise whitelisting
# ------------------------------------------------------------------------------

echo "[*] Appending hashes of currently connected devices"

cat >> /etc/usbguard/rules.conf << 'EOF'

# -----------------------------------------------------------------------------
# DEVICE-SPECIFIC RULES: Generated from currently connected devices
# These use hashes for precise identification
# -----------------------------------------------------------------------------

EOF

# Get hashes of current devices and append
usbguard generate-policy 2>/dev/null | while read -r line; do
    # Skip if it's just a hub
    if echo "$line" | grep -q "09:00:00"; then
        continue
    fi
    echo "# Auto-detected device"
    echo "$line"
done >> /etc/usbguard/rules.conf

# ------------------------------------------------------------------------------
# LOGGING: Create log directory
# ------------------------------------------------------------------------------

echo "[*] Setting up logging"

mkdir -p /var/log/usbguard
chmod 750 /var/log/usbguard
chown root:adm /var/log/usbguard

# Logrotate config
cat > /etc/logrotate.d/usbguard << 'EOF'
/var/log/usbguard/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF

# ------------------------------------------------------------------------------
# AUDIT INTEGRATION: Ensure USBGuard events go to auditd
# ------------------------------------------------------------------------------

echo "[*] Integrating with audit framework"

# Add audit rule for USB device authorization
cat >> /etc/audit/rules.d/99-hardening.rules << 'EOF'

# -----------------------------------------------------------------------------
# USB: USBGuard events
# -----------------------------------------------------------------------------

-w /etc/usbguard/ -p wa -k usbguard_config
-w /var/log/usbguard/ -p wa -k usbguard_log

EOF

# Reload audit rules
augenrules --load 2>/dev/null || true

# ------------------------------------------------------------------------------
# PERMISSIONS: Lock down USBGuard config
# ------------------------------------------------------------------------------

echo "[*] Setting restrictive permissions"

chmod 700 /etc/usbguard
chmod 600 /etc/usbguard/usbguard-daemon.conf
chmod 600 /etc/usbguard/rules.conf
chown -R root:root /etc/usbguard

# ------------------------------------------------------------------------------
# GROUP: Create usbguard group and add user
# ------------------------------------------------------------------------------

echo "[*] Setting up usbguard group"

if ! getent group usbguard &>/dev/null; then
    groupadd -r usbguard
fi

usermod -aG usbguard "$PRIMARY_USER"

# ------------------------------------------------------------------------------
# HELPER SCRIPTS
# ------------------------------------------------------------------------------

echo "[*] Creating USB management helper scripts"

# Script to list current USB devices
cat > /usr/local/bin/usb-list << 'EOF'
#!/bin/bash
# List USB devices and their authorization status
echo "=== USB Devices (lsusb) ==="
lsusb
echo ""
echo "=== USBGuard Status ==="
usbguard list-devices 2>/dev/null || echo "USBGuard not running"
EOF
chmod 755 /usr/local/bin/usb-list

# Script to temporarily allow a device
cat > /usr/local/bin/usb-allow << 'EOF'
#!/bin/bash
# Temporarily allow a blocked USB device
if [[ -z "$1" ]]; then
    echo "Usage: usb-allow <device-number>"
    echo ""
    echo "Blocked devices:"
    usbguard list-devices | grep -i block
    exit 1
fi
sudo usbguard allow-device "$1"
echo "Device $1 allowed for this session"
echo "To make permanent, add rule to /etc/usbguard/rules.conf"
EOF
chmod 755 /usr/local/bin/usb-allow

# Script to block a device
cat > /usr/local/bin/usb-block << 'EOF'
#!/bin/bash
# Block a USB device
if [[ -z "$1" ]]; then
    echo "Usage: usb-block <device-number>"
    echo ""
    echo "Allowed devices:"
    usbguard list-devices | grep -i allow
    exit 1
fi
sudo usbguard block-device "$1"
echo "Device $1 blocked"
EOF
chmod 755 /usr/local/bin/usb-block

# Script to show blocked events
cat > /usr/local/bin/usb-blocked << 'EOF'
#!/bin/bash
# Show recently blocked USB devices
echo "=== Recently Blocked USB Devices ==="
journalctl -u usbguard --since "24 hours ago" | grep -i block | tail -30
echo ""
echo "=== USBGuard Audit Log ==="
tail -30 /var/log/usbguard/usbguard-audit.log 2>/dev/null || echo "No audit log yet"
EOF
chmod 755 /usr/local/bin/usb-blocked

# Script to generate hash rule for a specific device
cat > /usr/local/bin/usb-trust << 'EOF'
#!/bin/bash
# Generate a trust rule for a specific device (by hash)
if [[ -z "$1" ]]; then
    echo "Usage: usb-trust <device-number>"
    echo ""
    echo "This generates a hash-based rule for permanent trust"
    echo ""
    echo "Current devices:"
    usbguard list-devices
    exit 1
fi

DEVICE_INFO=$(usbguard list-devices -d "$1" 2>/dev/null)
if [[ -z "$DEVICE_INFO" ]]; then
    echo "Device $1 not found"
    exit 1
fi

echo "Device info:"
echo "$DEVICE_INFO"
echo ""
echo "To permanently trust this device, add this rule to /etc/usbguard/rules.conf:"
echo ""
usbguard generate-policy 2>/dev/null | grep -F "$(echo "$DEVICE_INFO" | grep -oP 'hash "\K[^"]+')" || \
    echo "allow $(echo "$DEVICE_INFO" | sed 's/^[0-9]*: //')"
EOF
chmod 755 /usr/local/bin/usb-trust

# ------------------------------------------------------------------------------
# SYSTEMD: Enable and start USBGuard
# ------------------------------------------------------------------------------

echo "[*] Enabling USBGuard service"

systemctl daemon-reload
systemctl enable usbguard
systemctl restart usbguard

# Check status
sleep 2
if systemctl is-active --quiet usbguard; then
    echo "[+] USBGuard is running"
else
    echo "[!] USBGuard failed to start - check: journalctl -u usbguard"
fi

# ------------------------------------------------------------------------------
# DBUS POLICY: Restrict USBGuard DBus access
# ------------------------------------------------------------------------------

echo "[*] Hardening DBus policy for USBGuard"

if [[ -d /etc/dbus-1/system.d ]]; then
    cat > /etc/dbus-1/system.d/org.usbguard.conf << EOF
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <!-- Only root and usbguard group can interact with USBGuard -->
  <policy user="root">
    <allow own="org.usbguard"/>
    <allow send_destination="org.usbguard"/>
    <allow receive_sender="org.usbguard"/>
  </policy>
  
  <policy group="usbguard">
    <allow send_destination="org.usbguard"/>
    <allow receive_sender="org.usbguard"/>
  </policy>
  
  <policy context="default">
    <deny own="org.usbguard"/>
    <deny send_destination="org.usbguard"/>
  </policy>
</busconfig>
EOF
fi

# ------------------------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------------------------

echo ""
echo "[+] USB hardening complete"
echo ""
echo "    USBGuard status:"
systemctl status usbguard --no-pager | head -5
echo ""
echo "    Current device authorizations:"
usbguard list-devices 2>/dev/null | head -10 || echo "    (service starting...)"
echo ""
echo "    Policy summary:"
echo "      - USB hubs/controllers: Allowed"
echo "      - HID (keyboard/mouse): Allowed"
echo "      - U2F security keys: Allowed (YubiKey, Titan, etc.)"
echo "      - Mass storage: BLOCKED (USB drives)"
echo "      - Network adapters: BLOCKED"
echo "      - Printers: BLOCKED"
echo "      - Everything else: BLOCKED"
echo ""
echo "    Helper scripts:"
echo "      usb-list      - Show USB devices and status"
echo "      usb-allow     - Temporarily allow blocked device"
echo "      usb-block     - Block a device"
echo "      usb-blocked   - Show blocked device events"
echo "      usb-trust     - Generate permanent trust rule"
echo ""
echo "    To allow a blocked USB drive temporarily:"
echo "      usb-list"
echo "      usb-allow <device-number>"
echo ""
echo "    To permanently trust a device:"
echo "      usb-trust <device-number>"
echo "      (copy output rule to /etc/usbguard/rules.conf)"
echo "      systemctl restart usbguard"
echo ""
echo "    Config files:"
echo "      /etc/usbguard/rules.conf        - Device whitelist"
echo "      /etc/usbguard/usbguard-daemon.conf - Daemon config"
echo ""
echo "    Logs:"
echo "      journalctl -u usbguard"
echo "      /var/log/usbguard/usbguard-audit.log"

#
# Banners and Legal Warnings Module
# Target: Debian 12+ / GNOME Wayland / ThinkPad P16s Gen 2
# Policy: Display warnings at all access points
#


BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

# ------------------------------------------------------------------------------
# PREFLIGHT
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root"
    exit 1
fi

# ------------------------------------------------------------------------------
# BACKUP
# ------------------------------------------------------------------------------

echo "[*] Backing up existing banner files"
[[ -f /etc/issue ]] && cp /etc/issue "/etc/issue${BACKUP_SUFFIX}"
[[ -f /etc/issue.net ]] && cp /etc/issue.net "/etc/issue.net${BACKUP_SUFFIX}"
[[ -f /etc/motd ]] && cp /etc/motd "/etc/motd${BACKUP_SUFFIX}"

# ------------------------------------------------------------------------------
# /etc/issue: Pre-login banner (local TTY)
# ------------------------------------------------------------------------------

echo "[*] Creating /etc/issue (pre-login local banner)"

cat > /etc/issue << 'EOF'

===============================================================================
                         AUTHORIZED ACCESS ONLY
===============================================================================

  This system is private property. Unauthorized access is prohibited.

  All activity is logged and monitored. By continuing, you consent to:
    - Monitoring of all system activity
    - Recording of all keystrokes and commands
    - Inspection of all files accessed

  Unauthorized users will be prosecuted to the fullest extent of the law.

  If you are not authorized to access this system, disconnect immediately.

===============================================================================

EOF

chmod 644 /etc/issue
chown root:root /etc/issue

# ------------------------------------------------------------------------------
# /etc/issue.net: Pre-login banner (network/SSH)
# ------------------------------------------------------------------------------

echo "[*] Creating /etc/issue.net (pre-login network banner)"

cat > /etc/issue.net << 'EOF'

===============================================================================
                         AUTHORIZED ACCESS ONLY
===============================================================================

  This system is private property. Unauthorized access is prohibited.

  All connections are logged with source IP, timestamp, and session data.
  
  Unauthorized access attempts will be reported to appropriate authorities.

  DISCONNECT IMMEDIATELY IF YOU ARE NOT AN AUTHORIZED USER.

===============================================================================

EOF

chmod 644 /etc/issue.net
chown root:root /etc/issue.net

# ------------------------------------------------------------------------------
# /etc/motd: Post-login message
# ------------------------------------------------------------------------------

echo "[*] Creating /etc/motd (post-login message)"

cat > /etc/motd << 'EOF'

  ╔═══════════════════════════════════════════════════════════════════════════╗
  ║                                                                           ║
  ║   Welcome to a hardened system.                                           ║
  ║                                                                           ║
  ║   Security controls active:                                               ║
  ║     • U2F authentication required                                         ║
  ║     • All commands logged (sudo, audit)                                   ║
  ║     • AppArmor mandatory access control                                   ║
  ║     • USB device whitelist enforced                                       ║
  ║     • Network traffic monitored (OpenSnitch)                              ║
  ║     • VPN kill switch active                                              ║
  ║                                                                           ║
  ║   Report security concerns immediately.                                   ║
  ║                                                                           ║
  ╚═══════════════════════════════════════════════════════════════════════════╝

EOF

chmod 644 /etc/motd
chown root:root /etc/motd

# ------------------------------------------------------------------------------
# DISABLE DYNAMIC MOTD: Prevent information leakage
# ------------------------------------------------------------------------------

echo "[*] Disabling dynamic MOTD scripts"

# Debian/Ubuntu use update-motd.d for dynamic content
if [[ -d /etc/update-motd.d ]]; then
    chmod -x /etc/update-motd.d/* 2>/dev/null || true
    echo "[+] Disabled dynamic MOTD scripts"
fi

# Disable MOTD news fetching (Ubuntu)
if [[ -f /etc/default/motd-news ]]; then
    sed -i 's/^ENABLED=.*/ENABLED=0/' /etc/default/motd-news
fi

# ------------------------------------------------------------------------------
# SSH BANNER: Configure if SSH config exists
# ------------------------------------------------------------------------------

echo "[*] Configuring SSH banner (if applicable)"

if [[ -f /etc/ssh/sshd_config ]]; then
    # Backup
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config${BACKUP_SUFFIX}"
    
    # Enable banner
    if grep -q "^#Banner" /etc/ssh/sshd_config; then
        sed -i 's/^#Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
    elif grep -q "^Banner" /etc/ssh/sshd_config; then
        sed -i 's/^Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
    else
        echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    fi
    
    # Disable printing of last login (information leakage)
    if grep -q "^#PrintLastLog" /etc/ssh/sshd_config; then
        sed -i 's/^#PrintLastLog.*/PrintLastLog no/' /etc/ssh/sshd_config
    elif grep -q "^PrintLastLog" /etc/ssh/sshd_config; then
        sed -i 's/^PrintLastLog.*/PrintLastLog no/' /etc/ssh/sshd_config
    else
        echo "PrintLastLog no" >> /etc/ssh/sshd_config
    fi
    
    # Disable MOTD via SSH (we show it via PAM instead)
    if grep -q "^#PrintMotd" /etc/ssh/sshd_config; then
        sed -i 's/^#PrintMotd.*/PrintMotd no/' /etc/ssh/sshd_config
    elif grep -q "^PrintMotd" /etc/ssh/sshd_config; then
        sed -i 's/^PrintMotd.*/PrintMotd no/' /etc/ssh/sshd_config
    else
        echo "PrintMotd no" >> /etc/ssh/sshd_config
    fi
    
    echo "[+] SSH banner configured"
fi

# ------------------------------------------------------------------------------
# GDM BANNER: Already configured in services module, verify
# ------------------------------------------------------------------------------

echo "[*] Verifying GDM banner configuration"

GDM_DCONF="/etc/gdm3/greeter.dconf-defaults"
if [[ -f "$GDM_DCONF" ]]; then
    if grep -q "banner-message-enable=true" "$GDM_DCONF"; then
        echo "[+] GDM banner already enabled"
    else
        cat >> "$GDM_DCONF" << 'EOF'

[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized users only. All activity is monitored.'
EOF
        echo "[+] GDM banner configured"
    fi
fi

# ------------------------------------------------------------------------------
# CONSOLE BANNER: /etc/profile.d script for post-login
# ------------------------------------------------------------------------------

echo "[*] Creating shell login banner"

cat > /etc/profile.d/security-banner.sh << 'EOF'
#!/bin/bash
# Display security reminder on interactive shell login

# Only show for interactive shells
if [[ $- == *i* ]]; then
    # Don't show if already shown this session
    if [[ -z "${SECURITY_BANNER_SHOWN:-}" ]]; then
        export SECURITY_BANNER_SHOWN=1
        
        echo ""
        echo "  ┌─────────────────────────────────────────────────────────────┐"
        echo "  │ Security reminder: All activity on this system is logged.  │"
        echo "  └─────────────────────────────────────────────────────────────┘"
        echo ""
    fi
fi
EOF

chmod 644 /etc/profile.d/security-banner.sh
chown root:root /etc/profile.d/security-banner.sh

# ------------------------------------------------------------------------------
# SUDO LECTURE: Already configured in sudoers module, verify
# ------------------------------------------------------------------------------

echo "[*] Verifying sudo lecture configuration"

if [[ -f /etc/sudoers.d/lecture ]]; then
    echo "[+] Sudo lecture already configured"
else
    cat > /etc/sudoers.d/lecture << 'EOF'

    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║   WARNING: You are about to execute a privileged command.        ║
    ║                                                                  ║
    ║   All sudo activity is logged and monitored.                     ║
    ║   Unauthorized access attempts will be investigated.             ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝

EOF
    chmod 440 /etc/sudoers.d/lecture
    echo "[+] Sudo lecture created"
fi

# ------------------------------------------------------------------------------
# LOCK SCREEN MESSAGE: GNOME dconf
# ------------------------------------------------------------------------------

echo "[*] Configuring lock screen message"

mkdir -p /etc/dconf/db/local.d

cat > /etc/dconf/db/local.d/01-banner << 'EOF'
[org/gnome/desktop/screensaver]
lock-enabled=true
user-switch-enabled=false

[org/gnome/desktop/lockdown]
disable-user-switching=true
EOF

# Update dconf database
dconf update 2>/dev/null || true

# ------------------------------------------------------------------------------
# REMOVE SYSTEM INFORMATION LEAKAGE
# ------------------------------------------------------------------------------

echo "[*] Removing system information from banners"

# Remove OS identification from issue
# Some systems add OS info automatically - we want minimal info
# Our static banners above don't include system info

# Prevent os-release from being shown
# (Our banners are static and don't include this)

# Remove/hide hostname from various places
# Already handled by NetworkManager config (hostname-mode=none)

# ------------------------------------------------------------------------------
# LEGAL DISCLAIMER FILE
# ------------------------------------------------------------------------------

echo "[*] Creating legal disclaimer file"

cat > /etc/security/legal-disclaimer.txt << 'EOF'
================================================================================
                            LEGAL NOTICE AND DISCLAIMER
================================================================================

This computer system is private property and is intended for authorized use
only. By using this system, you acknowledge and consent to the following:

1. MONITORING AND LOGGING
   All activity on this system is subject to monitoring, recording, and
   auditing. This includes but is not limited to:
   - Keystrokes and commands entered
   - Files accessed, created, modified, or deleted
   - Network connections and data transmitted
   - Authentication attempts (successful and failed)
   - Privilege escalation events

2. NO EXPECTATION OF PRIVACY
   Users of this system have no expectation of privacy. Any information
   stored, processed, or transmitted through this system may be disclosed
   to authorized personnel, law enforcement, or other parties as required.

3. UNAUTHORIZED ACCESS
   Unauthorized access to this system is strictly prohibited and may result
   in civil and criminal penalties under applicable laws including but not
   limited to:
   - Computer Fraud and Abuse Act (18 U.S.C. § 1030)
   - Electronic Communications Privacy Act
   - State computer crime laws

4. CONSENT
   By accessing this system, you represent that you are authorized to do so
   and consent to all terms described herein.

5. SECURITY INCIDENT REPORTING
   Any suspected security incidents, vulnerabilities, or policy violations
   must be reported immediately to the system administrator.

================================================================================
EOF

chmod 644 /etc/security/legal-disclaimer.txt
chown root:root /etc/security/legal-disclaimer.txt

# ------------------------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------------------------

echo ""
echo "[+] Banners and legal warnings complete"
echo ""
echo "    Banners configured:"
echo "      /etc/issue             - Pre-login TTY banner"
echo "      /etc/issue.net         - Pre-login network banner"
echo "      /etc/motd              - Post-login message"
echo "      /etc/profile.d/security-banner.sh - Shell login reminder"
echo "      /etc/sudoers.d/lecture - Sudo warning"
echo "      GDM login screen       - Graphical login banner"
echo ""
echo "    Legal disclaimer:"
echo "      /etc/security/legal-disclaimer.txt"
echo ""
echo "    Information leakage prevented:"
echo "      - Dynamic MOTD disabled"
echo "      - SSH last login disabled"
echo "      - System info removed from banners"
echo ""
echo "    Test by:"
echo "      cat /etc/issue          # Pre-login banner"
echo "      cat /etc/motd           # Post-login message"
echo "      Switch to TTY (Ctrl+Alt+F2) to see login banner"

#
# Package Minimization & Verification Module
# Target: Debian 12+ / GNOME Wayland / ThinkPad P16s Gen 2
# Policy: Remove unnecessary packages, verify integrity of installed packages
#


PRIMARY_USER="dev"
BACKUP_DIR="/root/packages-backup-$(date +%Y%m%d%H%M%S)"
LOG_FILE="/var/log/package-hardening.log"

# ------------------------------------------------------------------------------
# PREFLIGHT
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root"
    exit 1
fi

# ------------------------------------------------------------------------------
# BACKUP
# ------------------------------------------------------------------------------

echo "[*] Creating backup of package state"
mkdir -p "$BACKUP_DIR"

# Save current package list
dpkg --get-selections > "${BACKUP_DIR}/packages-installed.txt"
apt-mark showmanual > "${BACKUP_DIR}/packages-manual.txt"
apt-mark showauto > "${BACKUP_DIR}/packages-auto.txt"

# Save debsums state if available
if command -v debsums &>/dev/null; then
    debsums -s 2>/dev/null > "${BACKUP_DIR}/debsums-before.txt" || true
fi

echo "[+] Package state backed up to ${BACKUP_DIR}"

# ------------------------------------------------------------------------------
# INSTALL: Verification tools
# ------------------------------------------------------------------------------

echo "[*] Installing package verification tools"
apt-get update
apt-get install -y debsums apt-show-versions apt-listbugs needrestart

# ------------------------------------------------------------------------------
# PACKAGES TO REMOVE: Unnecessary/dangerous packages
# ------------------------------------------------------------------------------

echo "[*] Removing unnecessary packages"

# Packages to remove - grouped by category
PACKAGES_TO_REMOVE=(
    # -------------------------------------------------------------------------
    # REMOTE ACCESS / SERVERS (should not be on workstation)
    # -------------------------------------------------------------------------
    "openssh-server"
    "telnetd"
    "tftpd"
    "tftpd-hpa"
    "vsftpd"
    "proftpd-basic"
    "pure-ftpd"
    "atftpd"
    "rsh-server"
    "rsh-redone-server"
    "xinetd"
    "inetutils-inetd"
    "openbsd-inetd"
    "nis"
    "yp-tools"
    "ypbind"
    "ypserv"
    
    # -------------------------------------------------------------------------
    # MAIL SERVERS (not needed on workstation)
    # -------------------------------------------------------------------------
    "postfix"
    "exim4"
    "exim4-base"
    "exim4-daemon-light"
    "exim4-daemon-heavy"
    "sendmail"
    "sendmail-bin"
    "sendmail-base"
    "courier-mta"
    "nullmailer"
    
    # -------------------------------------------------------------------------
    # NETWORK SERVICES (attack surface)
    # -------------------------------------------------------------------------
    "avahi-daemon"
    "avahi-autoipd"
    "cups"
    "cups-daemon"
    "cups-browsed"
    "cups-client"
    "samba"
    "samba-common"
    "samba-common-bin"
    "smbclient"
    "cifs-utils"
    "nfs-common"
    "nfs-kernel-server"
    "rpcbind"
    "snmpd"
    "snmp"
    "ldap-utils"
    "slapd"
    
    # -------------------------------------------------------------------------
    # BLUETOOTH (disabled in kernel, remove userspace)
    # -------------------------------------------------------------------------
    "bluez"
    "bluez-firmware"
    "bluez-tools"
    "bluetooth"
    "gnome-bluetooth"
    "gnome-bluetooth-3-common"
    "pulseaudio-module-bluetooth"
    
    # -------------------------------------------------------------------------
    # MODEM / TELEPHONY
    # -------------------------------------------------------------------------
    "modemmanager"
    "mobile-broadband-provider-info"
    "usb-modeswitch"
    "usb-modeswitch-data"
    
    # -------------------------------------------------------------------------
    # REMOTE DESKTOP
    # -------------------------------------------------------------------------
    "xrdp"
    "tightvncserver"
    "tigervnc-standalone-server"
    "x11vnc"
    "gnome-remote-desktop"
    "vino"
    "remmina"
    
    # -------------------------------------------------------------------------
    # GAMES
    # -------------------------------------------------------------------------
    "gnome-games"
    "aisleriot"
    "gnome-mines"
    "gnome-sudoku"
    "gnome-mahjongg"
    "gnome-chess"
    "gnome-tetravex"
    "gnome-robots"
    "gnome-nibbles"
    "gnome-taquin"
    "quadrapassel"
    "swell-foop"
    "tali"
    "iagno"
    "lightsoff"
    "four-in-a-row"
    "five-or-more"
    "hitori"
    
    # -------------------------------------------------------------------------
    # DOCUMENTATION (optional - uncomment to remove)
    # -------------------------------------------------------------------------
    # "man-db"
    # "manpages"
    # "info"
    
    # -------------------------------------------------------------------------
    # DEVELOPMENT TOOLS (remove if not needed - security risk)
    # -------------------------------------------------------------------------
    # "gcc"
    # "g++"
    # "make"
    # "build-essential"
    # "gdb"
    # "strace"
    # "ltrace"
    
    # -------------------------------------------------------------------------
    # PRIVACY / TELEMETRY
    # -------------------------------------------------------------------------
    "popularity-contest"
    "apport"
    "whoopsie"
    "ubuntu-report"
    "kerneloops"
    "kerneloops-daemon"
    
    # -------------------------------------------------------------------------
    # SNAPD / FLATPAK (if not using)
    # -------------------------------------------------------------------------
    "snapd"
    
    # -------------------------------------------------------------------------
    # TRACKER (file indexing - privacy concern)
    # -------------------------------------------------------------------------
    "tracker"
    "tracker-miner-fs"
    "tracker-extract"
    "tracker-miner-fs-3"
    "tracker-extract-3"
    
    # -------------------------------------------------------------------------
    # GEOLOCATION (privacy)
    # -------------------------------------------------------------------------
    "geoclue-2.0"
    
    # -------------------------------------------------------------------------
    # LEGACY / UNNECESSARY
    # -------------------------------------------------------------------------
    "tcpd"
    "at"
    "talk"
    "talkd"
    "ntalk"
    "finger"
    "fingerd"
    "rlogin"
    "rcp"
    
    # -------------------------------------------------------------------------
    # POTENTIALLY DANGEROUS TOOLS
    # -------------------------------------------------------------------------
    "netcat"
    "netcat-openbsd"
    "netcat-traditional"
    "ncat"
    "nmap"
    "wireshark"
    "wireshark-qt"
    "tshark"
    "tcpdump"
    "dsniff"
    "ettercap-common"
    "ettercap-graphical"
    "aircrack-ng"
    "hydra"
    "john"
    "hashcat"
)

echo "[*] Attempting to remove packages (missing packages will be skipped)"

for pkg in "${PACKAGES_TO_REMOVE[@]}"; do
    if dpkg -l "$pkg" &>/dev/null 2>&1; then
        echo "    [-] Removing: $pkg"
        apt-get purge -y "$pkg" >> "$LOG_FILE" 2>&1 || true
    fi
done

# ------------------------------------------------------------------------------
# AUTOREMOVE: Clean up orphaned dependencies
# ------------------------------------------------------------------------------

echo "[*] Removing orphaned packages"
apt-get autoremove -y --purge >> "$LOG_FILE" 2>&1

# ------------------------------------------------------------------------------
# CLEAN: Remove cached packages
# ------------------------------------------------------------------------------

echo "[*] Cleaning package cache"
apt-get clean
apt-get autoclean

# ------------------------------------------------------------------------------
# APT CONFIGURATION: Harden package management
# ------------------------------------------------------------------------------

echo "[*] Hardening APT configuration"

mkdir -p /etc/apt/apt.conf.d

cat > /etc/apt/apt.conf.d/99-hardening << 'EOF'
// =============================================================================
// APT Hardening Configuration
// =============================================================================

// Always verify package signatures
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";

// Don't install recommended/suggested packages by default
APT::Install-Recommends "false";
APT::Install-Suggests "false";

// Automatically remove unused dependencies
APT::AutoRemove::RecommendsImportant "false";
APT::AutoRemove::SuggestsImportant "false";

// Check for package updates but don't auto-install
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "0";

// Sandbox APT operations
APT::Sandbox::Seccomp "true";
EOF

# ------------------------------------------------------------------------------
# DEBSUMS: Verify installed package integrity
# ------------------------------------------------------------------------------

echo "[*] Verifying package integrity with debsums"

# Run debsums and capture issues
echo "[*] Running debsums verification (this may take a while)..."

DEBSUMS_OUTPUT=$(debsums -s 2>&1 || true)

if [[ -n "$DEBSUMS_OUTPUT" ]]; then
    echo "[!] Debsums found modified files:"
    echo "$DEBSUMS_OUTPUT" | tee "${BACKUP_DIR}/debsums-modified.txt"
    echo ""
    echo "[!] Review ${BACKUP_DIR}/debsums-modified.txt for details"
    echo "    Some modifications may be legitimate (config files)"
else
    echo "[+] All package files verified - no modifications detected"
fi

# Generate full debsums report
debsums -a > "${BACKUP_DIR}/debsums-full.txt" 2>&1 || true

# ------------------------------------------------------------------------------
# APT-SHOW-VERSIONS: Check for security updates
# ------------------------------------------------------------------------------

echo "[*] Checking for available security updates"

apt-show-versions -u > "${BACKUP_DIR}/updates-available.txt" 2>&1 || true

SECURITY_UPDATES=$(grep -i security "${BACKUP_DIR}/updates-available.txt" 2>/dev/null | wc -l || echo "0")

if [[ "$SECURITY_UPDATES" -gt 0 ]]; then
    echo "[!] ${SECURITY_UPDATES} security updates available"
    echo "    Review: ${BACKUP_DIR}/updates-available.txt"
    echo "    Install with: apt-get upgrade"
else
    echo "[+] No pending security updates"
fi

# ------------------------------------------------------------------------------
# PACKAGE VERIFICATION SCRIPT
# ------------------------------------------------------------------------------

echo "[*] Creating package verification helper scripts"

# Script to verify all packages
cat > /usr/local/bin/pkg-verify << 'EOF'
#!/bin/bash
# Verify integrity of installed packages

echo "=== Package Integrity Verification ==="
echo ""

echo "[*] Running debsums (modified files)..."
MODIFIED=$(debsums -s 2>&1)
if [[ -n "$MODIFIED" ]]; then
    echo "[!] Modified files detected:"
    echo "$MODIFIED"
else
    echo "[+] All files match package checksums"
fi
echo ""

echo "[*] Checking for packages without checksums..."
debsums -l 2>/dev/null | head -20
echo ""

echo "[*] Security updates available:"
apt-show-versions -u 2>/dev/null | grep -i security || echo "None"
EOF
chmod 755 /usr/local/bin/pkg-verify

# Script to audit installed packages
cat > /usr/local/bin/pkg-audit << 'EOF'
#!/bin/bash
# Audit installed packages

echo "=== Package Audit ==="
echo ""

echo "Total packages installed: $(dpkg -l | grep '^ii' | wc -l)"
echo "Manually installed: $(apt-mark showmanual | wc -l)"
echo "Auto-installed: $(apt-mark showauto | wc -l)"
echo ""

echo "=== Potentially Dangerous Packages ==="
DANGEROUS_PKGS="gcc g++ make gdb strace ltrace nmap netcat wireshark tcpdump"
for pkg in $DANGEROUS_PKGS; do
    if dpkg -l "$pkg" &>/dev/null 2>&1; then
        echo "  [!] $pkg is installed"
    fi
done
echo ""

echo "=== Network Services Installed ==="
NETWORK_PKGS="openssh-server apache2 nginx mysql-server postgresql vsftpd proftpd samba"
for pkg in $NETWORK_PKGS; do
    if dpkg -l "$pkg" &>/dev/null 2>&1; then
        echo "  [!] $pkg is installed"
    fi
done
echo ""

echo "=== Listening Ports ==="
ss -tulpn | grep LISTEN
EOF
chmod 755 /usr/local/bin/pkg-audit

# Script to reinstall a package (fix corrupted files)
cat > /usr/local/bin/pkg-reinstall << 'EOF'
#!/bin/bash
# Reinstall a package to fix corrupted/modified files

if [[ -z "$1" ]]; then
    echo "Usage: pkg-reinstall <package-name>"
    echo "       pkg-reinstall --all-modified"
    exit 1
fi

if [[ "$1" == "--all-modified" ]]; then
    echo "[*] Finding packages with modified files..."
    MODIFIED_PKGS=$(debsums -s 2>/dev/null | awk -F: '{print $1}' | xargs -I{} dpkg -S {} 2>/dev/null | cut -d: -f1 | sort -u)
    
    if [[ -z "$MODIFIED_PKGS" ]]; then
        echo "[+] No packages with modified files found"
        exit 0
    fi
    
    echo "[*] Packages to reinstall:"
    echo "$MODIFIED_PKGS"
    echo ""
    read -p "Proceed? (y/N) " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        for pkg in $MODIFIED_PKGS; do
            echo "[*] Reinstalling $pkg..."
            apt-get install --reinstall -y "$pkg"
        done
    fi
else
    echo "[*] Reinstalling $1..."
    apt-get install --reinstall -y "$1"
fi
EOF
chmod 755 /usr/local/bin/pkg-reinstall

# ------------------------------------------------------------------------------
# SYSTEMD SERVICE: Periodic package verification
# ------------------------------------------------------------------------------

echo "[*] Creating periodic package verification service"

cat > /etc/systemd/system/pkg-verify.service << 'EOF'
[Unit]
Description=Package Integrity Verification

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pkg-verify
StandardOutput=journal
EOF

cat > /etc/systemd/system/pkg-verify.timer << 'EOF'
[Unit]
Description=Weekly package integrity verification

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable pkg-verify.timer
systemctl start pkg-verify.timer

# ------------------------------------------------------------------------------
# NEEDRESTART: Configure automatic restart checking
# ------------------------------------------------------------------------------

echo "[*] Configuring needrestart"

if [[ -f /etc/needrestart/needrestart.conf ]]; then
    # Set to list mode (show what needs restart, don't auto-restart)
    sed -i "s/^#\$nrconf{restart}.*$/\$nrconf{restart} = 'l';/" /etc/needrestart/needrestart.conf
fi

# ------------------------------------------------------------------------------
# KERNEL: Remove old kernels
# ------------------------------------------------------------------------------

echo "[*] Checking for old kernels"

CURRENT_KERNEL=$(uname -r)
echo "    Current kernel: ${CURRENT_KERNEL}"

OLD_KERNELS=$(dpkg -l 'linux-image-*' | grep '^ii' | awk '{print $2}' | grep -v "$CURRENT_KERNEL" | grep -v "linux-image-amd64" | grep -v "linux-image-generic" || true)

if [[ -n "$OLD_KERNELS" ]]; then
    echo "[*] Old kernels found:"
    echo "$OLD_KERNELS"
    echo ""
    echo "    To remove old kernels:"
    echo "    apt-get purge $OLD_KERNELS"
else
    echo "[+] No old kernels to remove"
fi

# ------------------------------------------------------------------------------
# AUDIT: Final package state
# ------------------------------------------------------------------------------

echo "[*] Generating final package audit"

# Save final package list
dpkg --get-selections > "${BACKUP_DIR}/packages-final.txt"

# Count packages removed
BEFORE=$(wc -l < "${BACKUP_DIR}/packages-installed.txt")
AFTER=$(wc -l < "${BACKUP_DIR}/packages-final.txt")
REMOVED=$((BEFORE - AFTER))

echo "[+] Removed approximately ${REMOVED} packages"

# List remaining listening services
echo "[*] Remaining listening services:"
ss -tulpn | grep LISTEN | tee "${BACKUP_DIR}/listening-services-final.txt"

# ------------------------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------------------------

echo ""
echo "[+] Package minimization & verification complete"
echo ""
echo "    Packages removed: ~${REMOVED}"
echo "    Backup location: ${BACKUP_DIR}"
echo ""
echo "    APT hardening:"
echo "      - Signature verification enforced"
echo "      - Recommends/suggests disabled"
echo "      - Sandbox enabled"
echo ""
echo "    Verification tools:"
echo "      pkg-verify    - Verify all package integrity"
echo "      pkg-audit     - Audit installed packages"
echo "      pkg-reinstall - Reinstall corrupted packages"
echo ""
echo "    Periodic verification:"
echo "      Weekly timer enabled (pkg-verify.timer)"
echo "      Check with: journalctl -u pkg-verify"
echo ""
echo "    Reports generated:"
echo "      ${BACKUP_DIR}/debsums-modified.txt  - Modified files"
echo "      ${BACKUP_DIR}/debsums-full.txt      - Full verification"
echo "      ${BACKUP_DIR}/updates-available.txt - Available updates"
echo ""
echo "    Next steps:"
echo "      1. Review debsums-modified.txt for unexpected changes"
echo "      2. Install security updates: apt-get upgrade"
echo "      3. Review pkg-audit output for unnecessary packages"

#
# Integrity Verification Module
# Target: Debian 12+ / GNOME Wayland / ThinkPad P16s Gen 2
# Policy: Comprehensive file integrity monitoring beyond debsums
#


PRIMARY_USER="dev"
INTEGRITY_DIR="/var/lib/integrity"
BASELINE_FILE="${INTEGRITY_DIR}/baseline.db"
CONFIG_FILE="/etc/integrity-monitor.conf"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

# ------------------------------------------------------------------------------
# PREFLIGHT
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root"
    exit 1
fi

# ------------------------------------------------------------------------------
# SETUP: Create directories
# ------------------------------------------------------------------------------

echo "[*] Setting up integrity monitoring infrastructure"

mkdir -p "$INTEGRITY_DIR"
chmod 700 "$INTEGRITY_DIR"
chown root:root "$INTEGRITY_DIR"

mkdir -p /var/log/integrity
chmod 700 /var/log/integrity
chown root:root /var/log/integrity

# ------------------------------------------------------------------------------
# CONFIGURATION: Define what to monitor
# ------------------------------------------------------------------------------

echo "[*] Creating integrity monitoring configuration"

cat > "$CONFIG_FILE" << 'EOF'
# =============================================================================
# Integrity Monitor Configuration
# =============================================================================

# Hash algorithm (sha256 or sha512)
HASH_ALGO="sha256"

# -----------------------------------------------------------------------------
# CRITICAL SYSTEM FILES
# Changes here indicate possible compromise
# -----------------------------------------------------------------------------

CRITICAL_FILES=(
    # Authentication
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/gshadow"
    "/etc/sudoers"
    "/etc/pam.d/common-auth"
    "/etc/pam.d/common-password"
    "/etc/pam.d/common-session"
    "/etc/pam.d/common-account"
    "/etc/pam.d/sudo"
    "/etc/pam.d/su"
    "/etc/pam.d/login"
    "/etc/pam.d/sshd"
    "/etc/security/access.conf"
    "/etc/security/limits.conf"
    "/etc/security/namespace.conf"
    "/etc/login.defs"
    "/etc/securetty"
    
    # SSH (even if disabled)
    "/etc/ssh/sshd_config"
    "/etc/ssh/ssh_config"
    
    # Network
    "/etc/hosts"
    "/etc/hosts.allow"
    "/etc/hosts.deny"
    "/etc/resolv.conf"
    "/etc/nsswitch.conf"
    
    # Firewall
    "/etc/iptables/rules.v4"
    "/etc/iptables/rules.v6"
    
    # Kernel
    "/etc/sysctl.conf"
    "/etc/default/grub"
    "/boot/grub/grub.cfg"
    
    # Cron
    "/etc/crontab"
    
    # Init
    "/etc/rc.local"
    "/etc/inittab"
    
    # Library preload (common persistence mechanism)
    "/etc/ld.so.preload"
    "/etc/ld.so.conf"
    
    # Shell configs
    "/etc/profile"
    "/etc/bash.bashrc"
    "/etc/environment"
    
    # AppArmor
    "/etc/apparmor/parser.conf"
    
    # USBGuard
    "/etc/usbguard/rules.conf"
    "/etc/usbguard/usbguard-daemon.conf"
    
    # Audit
    "/etc/audit/auditd.conf"
    
    # OpenSnitch
    "/etc/opensnitchd/default-config.json"
    
    # WireGuard
    "/etc/wireguard/wg0.conf"
)

# -----------------------------------------------------------------------------
# CRITICAL DIRECTORIES
# Monitor all files in these directories
# -----------------------------------------------------------------------------

CRITICAL_DIRS=(
    "/etc/sudoers.d"
    "/etc/pam.d"
    "/etc/security"
    "/etc/apparmor.d"
    "/etc/audit/rules.d"
    "/etc/systemd/system"
    "/etc/modprobe.d"
    "/etc/sysctl.d"
    "/etc/usbguard/IPCAccessControl.d"
    "/etc/profile.d"
    "/etc/cron.d"
    "/etc/cron.daily"
    "/etc/cron.hourly"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
)

# -----------------------------------------------------------------------------
# CRITICAL BINARIES
# These should NEVER change without package updates
# -----------------------------------------------------------------------------

CRITICAL_BINARIES=(
    # Shells
    "/bin/bash"
    "/bin/sh"
    "/bin/dash"
    "/usr/bin/bash"
    
    # Auth binaries
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/passwd"
    "/usr/bin/login"
    "/usr/sbin/unix_chkpwd"
    
    # System binaries
    "/usr/bin/ssh"
    "/usr/sbin/sshd"
    "/sbin/init"
    "/lib/systemd/systemd"
    
    # Security tools
    "/usr/sbin/auditd"
    "/usr/sbin/auditctl"
    "/usr/bin/opensnitchd"
    "/usr/bin/wg"
    "/usr/bin/wg-quick"
    
    # Network
    "/sbin/iptables"
    "/sbin/ip6tables"
    "/sbin/iptables-restore"
    
    # Module tools
    "/sbin/insmod"
    "/sbin/rmmod"
    "/sbin/modprobe"
)

# -----------------------------------------------------------------------------
# SUID/SGID BINARIES
# Track all setuid/setgid files
# -----------------------------------------------------------------------------

TRACK_SUID_SGID=true

# -----------------------------------------------------------------------------
# KERNEL MODULES
# Track installed kernel modules
# -----------------------------------------------------------------------------

TRACK_KERNEL_MODULES=true

# -----------------------------------------------------------------------------
# EXCLUSIONS
# Paths to exclude from monitoring
# -----------------------------------------------------------------------------

EXCLUSIONS=(
    "/etc/mtab"
    "/etc/resolv.conf.bak"
    "/etc/.pwd.lock"
    "/var/lib/integrity"
)
EOF

chmod 600 "$CONFIG_FILE"

# ------------------------------------------------------------------------------
# MAIN INTEGRITY SCRIPT
# ------------------------------------------------------------------------------

echo "[*] Creating integrity monitoring script"

cat > /usr/local/bin/integrity-monitor << 'SCRIPT_EOF'
#!/bin/bash
#
# Integrity Monitor - File integrity verification
#

set -euo pipefail

CONFIG_FILE="/etc/integrity-monitor.conf"
INTEGRITY_DIR="/var/lib/integrity"
BASELINE_FILE="${INTEGRITY_DIR}/baseline.db"
LOG_FILE="/var/log/integrity/integrity.log"
ALERT_FILE="/var/log/integrity/alerts.log"

# Load configuration
source "$CONFIG_FILE"

# ------------------------------------------------------------------------------
# FUNCTIONS
# ------------------------------------------------------------------------------

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

alert() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERT: $1" | tee -a "$ALERT_FILE" "$LOG_FILE"
    logger -t integrity-monitor -p auth.alert "$1"
}

hash_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        ${HASH_ALGO}sum "$file" 2>/dev/null | awk '{print $1}'
    else
        echo "MISSING"
    fi
}

get_perms() {
    local file="$1"
    if [[ -e "$file" ]]; then
        stat -c '%a:%U:%G' "$file" 2>/dev/null
    else
        echo "MISSING"
    fi
}

get_attrs() {
    local file="$1"
    if [[ -f "$file" ]]; then
        lsattr "$file" 2>/dev/null | awk '{print $1}' || echo "none"
    else
        echo "MISSING"
    fi
}

is_excluded() {
    local file="$1"
    for excl in "${EXCLUSIONS[@]}"; do
        if [[ "$file" == "$excl" ]]; then
            return 0
        fi
    done
    return 1
}

# ------------------------------------------------------------------------------
# CREATE BASELINE
# ------------------------------------------------------------------------------

create_baseline() {
    log "Creating integrity baseline..."
    
    local temp_baseline="${BASELINE_FILE}.tmp"
    
    # Remove immutable flag if exists
    chattr -i "$BASELINE_FILE" 2>/dev/null || true
    
    echo "# Integrity Baseline - Generated $(date)" > "$temp_baseline"
    echo "# Format: TYPE|PATH|HASH|PERMS|ATTRS" >> "$temp_baseline"
    
    # Critical files
    log "Processing critical files..."
    for file in "${CRITICAL_FILES[@]}"; do
        if is_excluded "$file"; then
            continue
        fi
        if [[ -f "$file" ]]; then
            hash=$(hash_file "$file")
            perms=$(get_perms "$file")
            attrs=$(get_attrs "$file")
            echo "FILE|${file}|${hash}|${perms}|${attrs}" >> "$temp_baseline"
        fi
    done
    
    # Critical directories
    log "Processing critical directories..."
    for dir in "${CRITICAL_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -type f 2>/dev/null | while read -r file; do
                if is_excluded "$file"; then
                    continue
                fi
                hash=$(hash_file "$file")
                perms=$(get_perms "$file")
                attrs=$(get_attrs "$file")
                echo "FILE|${file}|${hash}|${perms}|${attrs}" >> "$temp_baseline"
            done
        fi
    done
    
    # Critical binaries
    log "Processing critical binaries..."
    for file in "${CRITICAL_BINARIES[@]}"; do
        if is_excluded "$file"; then
            continue
        fi
        if [[ -f "$file" ]]; then
            hash=$(hash_file "$file")
            perms=$(get_perms "$file")
            attrs=$(get_attrs "$file")
            echo "BINARY|${file}|${hash}|${perms}|${attrs}" >> "$temp_baseline"
        fi
    done
    
    # SUID/SGID binaries
    if [[ "$TRACK_SUID_SGID" == "true" ]]; then
        log "Processing SUID/SGID binaries..."
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | while read -r file; do
            if is_excluded "$file"; then
                continue
            fi
            hash=$(hash_file "$file")
            perms=$(get_perms "$file")
            echo "SUID|${file}|${hash}|${perms}|none" >> "$temp_baseline"
        done
    fi
    
    # Kernel modules
    if [[ "$TRACK_KERNEL_MODULES" == "true" ]]; then
        log "Processing kernel modules..."
        find /lib/modules/$(uname -r) -name "*.ko*" -type f 2>/dev/null | while read -r file; do
            hash=$(hash_file "$file")
            echo "MODULE|${file}|${hash}|644:root:root|none" >> "$temp_baseline"
        done
    fi
    
    # Sort and finalize
    sort -t'|' -k2 "$temp_baseline" -o "$temp_baseline"
    mv "$temp_baseline" "$BASELINE_FILE"
    
    # Protect baseline
    chmod 600 "$BASELINE_FILE"
    chattr +i "$BASELINE_FILE"
    
    log "Baseline created with $(grep -c '^[A-Z]' "$BASELINE_FILE") entries"
}

# ------------------------------------------------------------------------------
# VERIFY INTEGRITY
# ------------------------------------------------------------------------------

verify_integrity() {
    if [[ ! -f "$BASELINE_FILE" ]]; then
        log "No baseline found, creating initial baseline..."
        create_baseline
        return 0
    fi
    
    log "Verifying integrity against baseline..."
    
    local violations=0
    local new_files=0
    local missing_files=0
    
    # Check existing baseline entries
    while IFS='|' read -r type path expected_hash expected_perms expected_attrs; do
        # Skip comments and empty lines
        [[ "$type" =~ ^# ]] && continue
        [[ -z "$type" ]] && continue
        
        if [[ ! -e "$path" ]]; then
            alert "MISSING: $path (was $type)"
            ((missing_files++))
            continue
        fi
        
        current_hash=$(hash_file "$path")
        current_perms=$(get_perms "$path")
        current_attrs=$(get_attrs "$path")
        
        # Check hash
        if [[ "$current_hash" != "$expected_hash" ]]; then
            alert "MODIFIED: $path - hash changed"
            ((violations++))
        fi
        
        # Check permissions
        if [[ "$current_perms" != "$expected_perms" ]]; then
            alert "PERMISSIONS: $path - was $expected_perms, now $current_perms"
            ((violations++))
        fi
        
        # Check attributes (for files that had them)
        if [[ "$expected_attrs" != "none" && "$current_attrs" != "$expected_attrs" ]]; then
            alert "ATTRIBUTES: $path - was $expected_attrs, now $current_attrs"
            ((violations++))
        fi
        
    done < "$BASELINE_FILE"
    
    # Check for new SUID/SGID files
    if [[ "$TRACK_SUID_SGID" == "true" ]]; then
        log "Checking for new SUID/SGID files..."
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | while read -r file; do
            if ! grep -q "|${file}|" "$BASELINE_FILE" 2>/dev/null; then
                alert "NEW SUID/SGID: $file"
                ((new_files++))
            fi
        done
    fi
    
    # Summary
    log "Verification complete: $violations violations, $missing_files missing, $new_files new"
    
    if [[ $violations -gt 0 || $missing_files -gt 0 || $new_files -gt 0 ]]; then
        return 1
    fi
    
    return 0
}

# ------------------------------------------------------------------------------
# GENERATE REPORT
# ------------------------------------------------------------------------------

generate_report() {
    echo "=============================================="
    echo "INTEGRITY VERIFICATION REPORT"
    echo "Generated: $(date)"
    echo "=============================================="
    echo ""
    
    echo "=== Baseline Info ==="
    if [[ -f "$BASELINE_FILE" ]]; then
        echo "Baseline file: $BASELINE_FILE"
        echo "Baseline date: $(stat -c '%y' "$BASELINE_FILE")"
        echo "Total entries: $(grep -c '^[A-Z]' "$BASELINE_FILE")"
        echo "  - Files: $(grep -c '^FILE|' "$BASELINE_FILE")"
        echo "  - Binaries: $(grep -c '^BINARY|' "$BASELINE_FILE")"
        echo "  - SUID/SGID: $(grep -c '^SUID|' "$BASELINE_FILE")"
        echo "  - Modules: $(grep -c '^MODULE|' "$BASELINE_FILE")"
    else
        echo "No baseline found!"
    fi
    echo ""
    
    echo "=== Recent Alerts ==="
    if [[ -f "$ALERT_FILE" ]]; then
        tail -20 "$ALERT_FILE"
    else
        echo "No alerts"
    fi
    echo ""
    
    echo "=== Current SUID/SGID Files ==="
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | wc -l
    echo "files with SUID/SGID bits"
    echo ""
    
    echo "=== Recently Modified Critical Files ==="
    for file in "${CRITICAL_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            mtime=$(stat -c '%Y' "$file")
            now=$(date +%s)
            age=$(( (now - mtime) / 86400 ))
            if [[ $age -lt 7 ]]; then
                echo "  $file (modified $age days ago)"
            fi
        fi
    done
}

# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------

case "${1:-verify}" in
    baseline|init|create)
        create_baseline
        ;;
    verify|check)
        verify_integrity
        ;;
    report|status)
        generate_report
        ;;
    *)
        echo "Usage: integrity-monitor {baseline|verify|report}"
        echo ""
        echo "Commands:"
        echo "  baseline  - Create new integrity baseline"
        echo "  verify    - Verify current state against baseline"
        echo "  report    - Generate integrity report"
        exit 1
        ;;
esac
SCRIPT_EOF

chmod 700 /usr/local/bin/integrity-monitor

# ------------------------------------------------------------------------------
# QUICK CHECK SCRIPT
# ------------------------------------------------------------------------------

echo "[*] Creating quick integrity check script"

cat > /usr/local/bin/integrity-quick << 'EOF'
#!/bin/bash
#
# Quick integrity check of most critical files
#

echo "=== Quick Integrity Check ==="
echo ""

CRITICAL=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/sudoers"
    "/etc/pam.d/common-auth"
    "/etc/pam.d/sudo"
    "/usr/bin/sudo"
    "/bin/bash"
    "/etc/ld.so.preload"
)

BASELINE="/var/lib/integrity/baseline.db"

if [[ ! -f "$BASELINE" ]]; then
    echo "[!] No baseline found - run: integrity-monitor baseline"
    exit 1
fi

violations=0

for file in "${CRITICAL[@]}"; do
    if [[ ! -f "$file" ]]; then
        if [[ "$file" == "/etc/ld.so.preload" ]]; then
            # This file usually doesn't exist - that's good
            echo "[+] $file - not present (OK)"
        else
            echo "[!] $file - MISSING"
            ((violations++))
        fi
        continue
    fi
    
    current=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
    expected=$(grep "|${file}|" "$BASELINE" 2>/dev/null | cut -d'|' -f3)
    
    if [[ -z "$expected" ]]; then
        echo "[?] $file - not in baseline"
    elif [[ "$current" == "$expected" ]]; then
        echo "[+] $file - OK"
    else
        echo "[!] $file - MODIFIED"
        ((violations++))
    fi
done

echo ""
if [[ $violations -eq 0 ]]; then
    echo "All critical files verified OK"
else
    echo "WARNING: $violations violations detected!"
    exit 1
fi
EOF

chmod 755 /usr/local/bin/integrity-quick

# ------------------------------------------------------------------------------
# SYSTEMD SERVICE: Periodic integrity verification
# ------------------------------------------------------------------------------

echo "[*] Creating periodic integrity verification service"

cat > /etc/systemd/system/integrity-monitor.service << 'EOF'
[Unit]
Description=Integrity Monitor Verification
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/integrity-monitor verify
StandardOutput=journal
EOF

cat > /etc/systemd/system/integrity-monitor.timer << 'EOF'
[Unit]
Description=Hourly integrity verification

[Timer]
OnCalendar=hourly
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable integrity-monitor.timer
systemctl start integrity-monitor.timer

# ------------------------------------------------------------------------------
# BOOT-TIME INTEGRITY CHECK
# ------------------------------------------------------------------------------

echo "[*] Creating boot-time integrity check service"

cat > /etc/systemd/system/integrity-boot.service << 'EOF'
[Unit]
Description=Boot-time Integrity Verification
After=local-fs.target
Before=display-manager.service gdm.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/integrity-quick
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable integrity-boot.service

# ------------------------------------------------------------------------------
# INTEGRATE WITH ESCALATION MONITOR
# ------------------------------------------------------------------------------

echo "[*] Creating integration hook for escalation monitor"

cat > /usr/local/bin/integrity-escalation-hook << 'EOF'
#!/bin/bash
#
# Hook called by escalation monitor on suspicious events
#

LOG="/var/log/integrity/escalation-triggered.log"

echo "[$(date)] Escalation event triggered integrity check" >> "$LOG"

# Run quick check
/usr/local/bin/integrity-quick >> "$LOG" 2>&1

# If quick check fails, run full verification
if [[ $? -ne 0 ]]; then
    echo "[$(date)] Quick check failed, running full verification" >> "$LOG"
    /usr/local/bin/integrity-monitor verify >> "$LOG" 2>&1
fi
EOF

chmod 700 /usr/local/bin/integrity-escalation-hook

# ------------------------------------------------------------------------------
# AUDIT INTEGRATION
# ------------------------------------------------------------------------------

echo "[*] Adding audit rules for integrity monitoring"

cat >> /etc/audit/rules.d/99-hardening.rules << 'EOF'

# -----------------------------------------------------------------------------
# INTEGRITY: Monitor integrity baseline and tools
# -----------------------------------------------------------------------------

-w /var/lib/integrity/ -p wa -k integrity_baseline
-w /usr/local/bin/integrity-monitor -p wa -k integrity_tools
-w /etc/integrity-monitor.conf -p wa -k integrity_config

EOF

augenrules --load 2>/dev/null || true

# ------------------------------------------------------------------------------
# CREATE INITIAL BASELINE
# ------------------------------------------------------------------------------

echo "[*] Creating initial integrity baseline"
/usr/local/bin/integrity-monitor baseline

# ------------------------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------------------------

echo ""
echo "[+] Integrity verification module complete"
echo ""
echo "    Components installed:"
echo "      /usr/local/bin/integrity-monitor  - Main integrity tool"
echo "      /usr/local/bin/integrity-quick    - Quick critical file check"
echo "      /var/lib/integrity/baseline.db    - Integrity baseline (immutable)"
echo "      /etc/integrity-monitor.conf       - Configuration"
echo ""
echo "    Monitoring coverage:"
echo "      - Critical system files (passwd, shadow, sudoers, PAM, etc.)"
echo "      - Critical directories (/etc/sudoers.d, /etc/pam.d, etc.)"
echo "      - Critical binaries (sudo, bash, ssh, etc.)"
echo "      - All SUID/SGID files"
echo "      - Kernel modules"
echo ""
echo "    Verification schedule:"
echo "      - Boot-time: Quick check of most critical files"
echo "      - Hourly: Full integrity verification"
echo ""
echo "    Commands:"
echo "      integrity-monitor baseline  - Create new baseline"
echo "      integrity-monitor verify    - Verify against baseline"
echo "      integrity-monitor report    - Generate status report"
echo "      integrity-quick             - Quick check critical files"
echo ""
echo "    Logs:"
echo "      /var/log/integrity/integrity.log  - General log"
echo "      /var/log/integrity/alerts.log     - Alerts only"
echo ""
echo "    To update baseline after legitimate changes:"
echo "      chattr -i /var/lib/integrity/baseline.db"
echo "      integrity-monitor baseline"
echo ""

# ==============================================================================
# SCRIPT COMPLETE
# ==============================================================================

echo ""
echo "=============================================================================="
echo " ULTRA-HARDENING SCRIPT COMPLETE"
echo "=============================================================================="
echo ""
echo " CRITICAL NEXT STEPS:"
echo ""
echo "   1. Ensure your U2F key is registered:"
echo "      ls -la /etc/security/u2f_keys/${PRIMARY_USER}"
echo ""
echo "   2. Test U2F authentication BEFORE rebooting:"
echo "      sudo whoami    # Should require U2F touch"
echo ""
echo "   3. If sudo works with U2F, reboot:"
echo "      sudo reboot"
echo ""
echo "   4. Have a live USB ready in case of issues"
echo ""
echo " RECOVERY INFO:"
echo ""
echo "   If locked out, boot with: init=/bin/bash"
echo "   Then: mount -o remount,rw /"
echo "   Restore PAM: cp -a /etc/pam.d.bak.*/* /etc/pam.d/"
echo ""
echo "=============================================================================="
echo ""
# Color output for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[x]${NC} $1"
}

# PRE-CONFIG 
log_info "Installing prerequisites..."
apt install -y extrepo iptables iptables-persistent netfilter-persistent git --no-install-recommends

log_info "Enabling Librewolf repository..."
extrepo enable librewolf
apt update
apt install -y librewolf --no-install-recommends

# SYSTEMD HARDENING
log_info "Disabling unnecessary systemd services..."
SERVICES_TO_DISABLE=(
"accounts-daemon.service"
"anacron.service"
"anacron.timer"
"apport.service"
"apt-daily-upgrade.timer"
"apt-daily.timer"
"avahi-daemon.service"
"avahi-daemon.socket"
"bluetooth.service"
"bluetooth.target"
"bluez"
"bolt.service"
"brltty.service"
"chef-client.service"
"cloud-config.service"
"cloud-final.service"
"cloud-init-local.service"
"cloud-init.service"
"cockpit.service"
"cockpit.socket"
"colord.service"
"containerd.service"
"cron.service"
"cups-browsed"
"cups-browsed.service"
"cups.path"
"cups.service"
"cups.socket"
"debug-shell.service"
"docker.service"
"docker.socket"
"e2scrub_all.timer"
"exim4.service"
"fprintd.service"
"fwupd-refresh.timer"
"fwupd.service"
"geoclue.service"
"gnome-remote-desktop.service"
"gnome-software-service.service"
"hv-fcopy-daemon.service"
"hv-kvp-daemon.service"
"hv-vss-daemon.service"
"iio-sensor-proxy.service"
"iscsi.service"
"iscsid.service"
"iscsid.socket"
"kerneloops.service"
"krb5-admin-server.service"
"krb5-kdc.service"
"libvirtd-admin.socket"
"libvirtd-ro.socket"
"libvirtd.service"
"libvirtd.socket"
"lvm2-lvmpolld.service"
"lvm2-lvmpolld.socket"
"lxc-net.service"
"lxc.service"
"lxd.service"
"lxd.socket"
"man-db.timer"
"ModemManager.service"
"motd-news.timer"
"multipassd.service"
"multipathd.service"
"nfs-client.target"
"nfs-common.service"
"nfs-mountd.service"
"nfs-server.service"
"nmbd.service"
"nscd.service"
"nslcd.service"
"nvmefc-boot-connections.service"
"nvmf-autoconnect.service"
"open-iscsi.service"
"packagekit.service"
"pcscd.socket"
"podman.service"
"podman.socket"
"postfix.service"
"power-profiles-daemon.service"
"proftpd.service"
"puppet.service"
"pure-ftpd.service"
"qemu-guest-agent.service"
"rpcbind.service"
"rpcbind.socket"
"rsync.service"
"rtkit-daemon.service"
"salt-minion.service"
"samba-ad-dc.service"
"samba.service"
"sendmail.service"
"serial-getty@*.service"
"smbd.service"
"snapd.seeded.service"
"snapd.service"
"snapd.socket"
"snmpd.service"
"snmptrapd.service"
"speech-dispatcher"
"speech-dispatcher.service"
"spice-vdagentd.service"
"spice-vdagentd.socket"
"ssh.service"
"ssh.socket"
"sshd.service"
"sssd.service"
"switcheroo-control.service"
"systemd-binfmt.service"
"systemd-journal-gatewayd.socket"
"systemd-journal-remote.socket"
"systemd-journal-upload.service"
"tigervnc.service"
"tracker-extract-3.service"
"tracker-miner-fs-3.service"
"tracker-miner-rss-3.service"
"tracker-writeback-3.service"
"udisks2.service"
"unattended-upgrades"
"unattended-upgrades.service"
"upower.service"
"usbmuxd.service"
"vboxautostart-service.service"
"vboxballoonctrl-service.service"
"vboxdrv.service"
"vboxweb-service.service"
"vino-server.service"
"virtlockd.service"
"virtlockd.socket"
"virtlogd.service"
"virtlogd.socket"
"vmtoolsd.service"
"vmware-vmblock-fuse.service"
"vsftpd.service"
"webmin.service"
"whoopsie.service"
"winbind.service"
"wpa_supplicant"
"x11vnc.service"
"xrdp-sesman.service"
"xrdp.service"
)

for svc in "${SERVICES_TO_DISABLE[@]}"; do
    echo "    [-] Disabling ${svc}"
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true
done

log_info "Configuring APT hardening..."
cat > /etc/apt/apt.conf.d/99-hardening << 'EOF'
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
EOF

# FIREWALL
log_info "Configuring iptables firewall..."
apt purge -y nftables 2>/dev/null || true
systemctl enable netfilter-persistent
service netfilter-persistent start

# Flush all rules
iptables -F
iptables -X
iptables -Z
iptables -t nat -F
iptables -t nat -X
iptables -t nat -Z
iptables -t mangle -F
iptables -t mangle -X
iptables -t mangle -Z

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Default drop
iptables -A INPUT -j DROP

# IPv6 lockdown
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

# PACKAGE REMOVAL/RESTRICTING
log_info "Removing unnecessary packages (this may take a while)..."
REMOVE_PKGS=(
    "anacron*" "cron*" "pp*" "perl" "python3" "zram*" "pci*" "pmount*"
    "avahi*" "bc" "bind9*" "dns*" "fastfetch" "fonts-noto*" "fprint*"
    "dhcp*" "lxc*" "docker*" "podman*" "xen*" "bochs*" "uml*" "vagrant*"
    "ssh*" "openssh*" "libssh*" "usb*" "acpi*" "samba*" "winbind*"
    "qemu*" "libvirt*" "virt*" "cup*" "print*" "rsync*" "nftables*"
    "virtual*" "sane*" "rpc*" "bind*" "nfs*" "blue*" "spee*" "espeak*"
    "mobile*" "wireless*" "inet*" "util-linux-locales" "tasksel*" "vim*"
    "os-prober*" "netcat*" "gcc" "g++" "gdb" "lldb" "strace*" "ltrace*"
    "build-essential" "automake" "autoconf" "libtool" "cmake"
    "ninja-build" "meson" "traceroute" "libavahi*" "libcup*"
)

for pkg in "${REMOVE_PKGS[@]}"; do
    apt purge -y "$pkg" 2>/dev/null || true
done

log_info "Creating package deny list..."
install -d /etc/apt/preferences.d
cat >/etc/apt/preferences.d/deny.pref <<'EOF'
Package: 7z aa-exec ab acpi* agetty aircrack-ng alpine anacron* ansible* aoss apache* ar aria2c arj arp* as ascii-xfr ascii85 ash aspell at atobm autoconf* automake* autopsy avahi* awk aws base32 base58 base64 basenc basez batcat bc bconsole beef* bettercap bind* binwalk blue* bochs* bochs* bpftrace bridge build-essential build* bundle bundler busctl byebug bzip2 c89 c99 cabal cabal-install cancel capsh cargo cdist certbot check_by_ssh check_cups check_log check_memory check_raid check_ssl_cert check_statusfile choom chroot clam* cmake* cmp cobc column comm composer container* courier* cowsay cowthink cp cpan cpio cpulimit crackmapexec crash crontab csh csplit csvtool cup* cup* curl cut dash date dc dd debugfs dhcp* dialog diff dig dirb distcc dma* dmesg dmidecode dmsetup dnf dns* docker* docker* dos2unix dosbox dotnet* dropbear* dsniff dstat dvips easy_install eb ed efax elixir elvish emacs* enscript enum4linux env eqn erlang espeak espeak* ettercap* ex exiftool exim* expand expect facter fastfetch finger fish flatpak flock fmt fold fonts-noto* foremost fping fprint* ftp g++* gawk gcc gcc* gcloud gcore gdb gdb* gem genie genisoimage ghc ghci ghostscript gimp ginsh gnustep* gobuster golang* grc grep gtester gzip hashcat hd head hexdump highlight hping3 hydra* iconv iftop imagemagick impacket-scripts inet* ionice irb ispell jjs joe john join jq jrunscript jtag julia knife ksh ksshell ksu kubectl latex latexmk ld.so ldconfig lftp lftp libtool libvirt* libvirt* links lldb lldb* ln loginctl logsave look lp ltrace ltrace* ltrace* lua* lualatex luatex lwp-download lwp-request lxc* lxc* lxd* macchanger mail make maltego man masscan mawk medusa meson metagoofil metasploit-framework minicom mitmproxy mobile* modemmanager* mono-complete more mosquitto msfconsole msgattrib msgcat msgconv msgfilter msgmerge msguniq mtr multitime mysql nano nasm nasm* nawk nbtscan nc ncat ncdu ncftp neofetch netcat* nfs* nft nftables* nice nikto ninja-build nl nm nmap node nodejs* nohup npm* nroff nsenter ntpdate octave od openssh* openssl openstego openvpn openvt opkg os-prober* outguess pandoc paste pax pci* pdb pdflatex pdftex perf perlbug pexec pg php* pic pico pidstat pip pkexec pkg pmount* podman* posh postfix* pp* pr print* proftpd-basic proxychains* pry psftp psql ptx puppet pure-ftpd pwsh qemu* qemu* r-base radare2 rake rc readelf recon-ng red redcarpet redis responder restic rev rlogin rlwrap rpc* rpm rpmdb rpmquery rpmverify rsh* rtorrent ruby* run-mailcap run-parts runscript rustc rview rvim samba* sane* sash scanmem scp screen script scrot sed sendmail* service set setarch setfacl setlock sftp sg shuf sleuthkit slsh smb* snap snapd socat social-engineer-toolkit socket soelim softlimit sort spee* spiderfoot split sql* ss ssh* sslstrip start-stop-daemon stdbuf steghide stegosuite strace* strings su systemd-resolve tac tail tar task tasksel* taskset tasksh tbl tcl tclsh tcpdump tdbtool tee telnet* terraform tex tftp* theharvester tic time timedatectl timeout tinyssh* tk tmate tmux top tor* traceroute* tripwire* troff tshark ul uml* uml* unexpand unicornscan uniq unshare unsquashfs unzip update-alternatives usb* util-linux-locales uuencode vagrant* valgrind varnishncsa view vigr vim* vimdiff vipw virsh virt* virt* virtual* volatility vsftpd w3m wall watch wc wfuzz wget whiptail whois winbind* wireless* wireless* wireshark* wish wpa* xargs xdg-user-dir xdotool xelatex xen* xetex xmodmap xmore xpad xxd xz yarn yash yasm* yelp yersinia yum zathura zip zmap zram* zsh zsoelim zypper
Pin: release *
Pin-Priority: -1
EOF

# PACKAGE INSTALLATION
log_info "Installing required packages..."
apt install -y rsyslog chrony libpam-tmpdir pavucontrol pipewire \
    pipewire-audio-client-libraries pipewire-pulse wireplumber unhide \
    fonts-liberation libxfce4ui-utils gnome-terminal xfce4-terminal \
    xfce4-session xfce4-settings xfwm4 xfdesktop4 gnome-brave-icon-theme \
    breeze-gtk-theme bibata* qt5ct gdebi-core opensnitch* python3-opensnitch*

# PAM/U2F
log_info "Configuring U2F authentication..."
log_warn "Please insert your U2F device and touch it when prompted..."

# Check if U2F device is available
if ! pamu2fcfg -u dev > /etc/security/u2f_keys 2>/dev/null; then
    log_error "U2F device not detected or timeout occurred"
    log_warn "Please ensure your U2F device is plugged in and try again"
    log_warn "Running pamu2fcfg with verbose output..."
    pamu2fcfg -u dev > /etc/security/u2f_keys
fi

chmod 0400 /etc/security/u2f_keys
chown root:root /etc/security/u2f_keys

log_info "Configuring faillock..."
mkdir -p /var/log/faillock
chmod 0700 /var/log/faillock
rm -f /etc/pam.d/remote 2>/dev/null || true
rm -f /etc/pam.d/cron 2>/dev/null || true

# Faillock configuration
cat > /etc/security/faillock.conf << 'EOF'
deny = 3
unlock_time = 900
fail_interval = 900
silent
EOF

# PAM CONFIGURATIONS
log_info "Configuring PAM modules..."
cat > /etc/pam.d/common-auth << 'EOF'
#%PAM-1.0
auth      required    pam_faildelay.so delay=3000000
auth      required    pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth      [success=1 default=bad] pam_u2f.so authfile=/etc/security/u2f_keys cue
auth      [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
auth      sufficient  pam_faillock.so authsucc deny=3 unlock_time=900 fail_interval=900
EOF

cat > /etc/pam.d/common-account << 'EOF'
#%PAM-1.0
account   required    pam_faillock.so
account   required    pam_unix.so
EOF

cat > /etc/pam.d/common-password << 'EOF'
#%PAM-1.0
# Password changes disabled - U2F only system
password  requisite   pam_deny.so
EOF

cat > /etc/pam.d/common-session << 'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_unix.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
EOF

cat > /etc/pam.d/common-session-noninteractive << 'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_unix.so
session   required    pam_env.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
EOF

cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0
auth      required    pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth      [success=1 default=bad] pam_u2f.so authfile=/etc/security/u2f_keys cue
auth      [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
auth      sufficient  pam_faillock.so authsucc deny=3 unlock_time=900 fail_interval=900
account   required    pam_faillock.so
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/sudo-i << 'EOF'
#%PAM-1.0
auth      required    pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth      [success=1 default=bad] pam_u2f.so authfile=/etc/security/u2f_keys cue
auth      [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
auth      sufficient  pam_faillock.so authsucc deny=3 unlock_time=900 fail_interval=900
account   required    pam_faillock.so
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/su << 'EOF'
#%PAM-1.0
auth      required    pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth      [success=1 default=bad] pam_u2f.so authfile=/etc/security/u2f_keys cue
auth      [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
auth      sufficient  pam_faillock.so authsucc deny=3 unlock_time=900 fail_interval=900
account   required    pam_faillock.so
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/su-l << 'EOF'
#%PAM-1.0
auth      required    pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth      [success=1 default=bad] pam_u2f.so authfile=/etc/security/u2f_keys cue
auth      [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
auth      sufficient  pam_faillock.so authsucc deny=3 unlock_time=900 fail_interval=900
account   required    pam_faillock.so
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/login << 'EOF'
#%PAM-1.0
auth      requisite   pam_nologin.so
auth      required    pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth      [success=1 default=bad] pam_u2f.so authfile=/etc/security/u2f_keys cue
auth      [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
auth      sufficient  pam_faillock.so authsucc deny=3 unlock_time=900 fail_interval=900
account   required    pam_faillock.so
account   required    pam_access.so
account   include     common-account
session   required    pam_limits.so
session   required    pam_loginuid.so
session   optional    pam_lastlog.so showfailed
session   include     common-session
EOF

cat > /etc/pam.d/chfn << 'EOF'
#%PAM-1.0
auth      sufficient  pam_rootok.so
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat > /etc/pam.d/chsh << 'EOF'
#%PAM-1.0
auth      required    pam_shells.so
auth      sufficient  pam_rootok.so
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat > /etc/pam.d/chpasswd << 'EOF'
#%PAM-1.0
password  requisite   pam_deny.so
EOF

cat > /etc/pam.d/newusers << 'EOF'
#%PAM-1.0
password  requisite   pam_deny.so
EOF

cat > /etc/pam.d/passwd << 'EOF'
#%PAM-1.0
password  requisite   pam_deny.so
EOF

cat > /etc/pam.d/runuser << 'EOF'
#%PAM-1.0
auth      sufficient  pam_rootok.so
session   required    pam_limits.so
session   required    pam_unix.so
EOF

cat > /etc/pam.d/runuser-l << 'EOF'
#%PAM-1.0
auth      include     runuser
session   include     runuser
EOF

cat > /etc/pam.d/sshd << 'EOF'
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF

cat > /etc/pam.d/other << 'EOF'
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF

cat > /usr/lib/pam.d/systemd-user << 'EOF'
#%PAM-1.0
account   include     common-account
session   required    pam_limits.so
session   required    pam_unix.so
session   required    pam_env.so user_readenv=0
session   optional    pam_systemd.so
EOF

cat > /usr/lib/pam.d/polkit-1 << 'EOF'
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF

chmod 644 /etc/pam.d/*
chown root:root /etc/pam.d/*

# SUDO
log_info "Configuring sudo..."
cat >/etc/sudoers <<'EOF'
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
EOF
chmod 0440 /etc/sudoers
chmod -R 0440 /etc/sudoers.d

# MISC HARDENING
log_info "Applying miscellaneous hardening..."
cat >/etc/shells <<'EOF'
/bin/bash
EOF

cat >/etc/host.conf <<'EOF'
multi on
order hosts
EOF

cat >/etc/security/limits.d/limits.conf <<'EOF'
*           hard    nproc         4096
*            -      maxlogins     1
*            -      maxsyslogins  1
dev          -      maxlogins     1
dev          -      maxsyslogins  1
root         -      maxlogins     1
root         -      maxsyslogin   1
root        hard    nproc         65536
*           hard    core          0
EOF

echo "ProcessSizeMax=0
Storage=none" >> /etc/systemd/coredump.conf
echo "ulimit -c 0" >> /etc/profile

sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs
sed -i 's/^UID_MIN.*/UID_MIN 1000/' /etc/login.defs
sed -i 's/^UID_MAX.*/UID_MAX 60000/' /etc/login.defs
sed -i 's/^SHELL=.*/SHELL=\/usr\/sbin\/nologin/' /etc/default/useradd
sed -i 's/^DSHELL=.*/DSHELL=\/usr\/sbin\/nologin/' /etc/adduser.conf
echo "UMASK 077" >> /etc/login.defs
echo "umask 077" >> /etc/profile
echo "umask 077" >> /etc/bash.bashrc
echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny

cat > /etc/profile.d/autologout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF

cat > /etc/security/access.conf << EOF
+:dev:tty1 tty2 
-:ALL EXCEPT dev:tty1 tty2 tty3 tty4 tty5 tty6
-:ALL EXCEPT dev:LOCAL
-:dev:ALL EXCEPT LOCAL
-:root:ALL
-:ALL:REMOTE
-:ALL:ALL
EOF
chmod 644 /etc/security/access.conf

# GRUB 
log_info "Hardening GRUB bootloader..."
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="mitigations=auto,nosmt spectre_v2=on spec_store_bypass_disable=on l1tf=full,force mds=full,nosmt tsx=off tsx_async_abort=full,nosmt mmio_stale_data=full,nosmt retbleed=auto,nosmt srbds=on gather_data_sampling=force reg_file_data_sampling=on intel_iommu=on iommu=force iommu.passthrough=0 iommu.strict=1 efi=disable_early_pci_dma lockdown=confidentiality init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on slab_nomerge vsyscall=none debugfs=off oops=panic module.sig_enforce=1 ipv6.disable=1 nosmt nowatchdog nmi_watchdog=0"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub

# SYSCTL 
log_info "Applying sysctl hardening..."
rm -rf /usr/lib/sysctl.d
mkdir -p /usr/lib/sysctl.d
cat > /usr/lib/sysctl.d/sysctl.conf << 'EOF'
# Restrict kernel pointer exposure
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1
kernel.yama.ptrace_scope = 3
kernel.sysrq = 0
kernel.watchdog = 0
kernel.core_uses_pid = 1
kernel.suid_dumpable = 0
kernel.core_pattern = |/bin/false
kernel.io_uring_disabled = 2
kernel.randomize_va_space = 2
kernel.panic_on_oops = 1
kernel.ctrl-alt-del = 0
kernel.acct = 1
kernel.perf_event_paranoid = 3
kernel.perf_cpu_time_max_percent = 1
kernel.perf_event_max_sample_rate = 1
vm.max_map_count = 1048576
vm.mmap_min_addr = 65536
vm.oom_kill_allocating_task = 1
vm.panic_on_oom = 1
vm.overcommit_memory = 2
vm.overcommit_ratio = 100
vm.swappiness = 1
vm.unprivileged_userfaultfd = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 2
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
net.ipv4.conf.all.shared_media = 0
net.ipv4.conf.default.shared_media = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_invalid_ratelimit = 500
net.ipv4.tcp_rfc1337 = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.core.netdev_max_backlog = 65535
net.core.somaxconn = 65535
net.core.rmem_max = 6291456
net.core.wmem_max = 6291456
net.core.optmem_max = 65535
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_loose = 0
net.core.bpf_jit_enable = 0
net.core.bpf_jit_harden = 2
kernel.unprivileged_userns_clone = 0
dev.tty.legacy_tiocsti = 0
dev.tty.ldisc_autoload = 0
EOF
sysctl --system

# MODULES
log_info "Blacklisting kernel modules..."
cat > /etc/modprobe.d/harden.conf << 'EOF'
blacklist af_802154
install af_802154 /bin/false
blacklist ath10k_pci
install ath10k_pci /bin/false
blacklist ath10k_sdio
install ath10k_sdio /bin/false
blacklist ath10k_usb
install ath10k_usb /bin/false
blacklist ath11k
install ath11k /bin/false
blacklist ath11k_pci
install ath11k_pci /bin/false
blacklist ath6kl_sdio
install ath6kl_sdio /bin/false
blacklist ath6kl_usb
install ath6kl_usb /bin/false
blacklist ath9k
install ath9k /bin/false
blacklist ath9k_htc
install ath9k_htc /bin/false
blacklist atm
install atm /bin/false
blacklist ax25
install ax25 /bin/false
blacklist bluetooth
install bluetooth /bin/false
blacklist brcmsmac
install brcmsmac /bin/false
blacklist brcmfmac
install brcmfmac /bin/false
blacklist btbcm
install btbcm /bin/false
blacklist btintel
install btintel /bin/false
blacklist btusb
install btusb /bin/false
blacklist btrtl
install btrtl /bin/false
blacklist can
install can /bin/false
blacklist cramfs
install cramfs /bin/false
blacklist cfg80211
install cfg80211 /bin/false
blacklist dccp
install dccp /bin/false
blacklist decnet
install decnet /bin/false
blacklist dvb_core
install dvb_core /bin/false
blacklist dvb_usb
install dvb_usb /bin/false
blacklist dvb_usb_v2
install dvb_usb_v2 /bin/false
blacklist econet
install econet /bin/false
blacklist firewire-core
install firewire-core /bin/false
blacklist firewire-ohci
install firewire-ohci /bin/false
blacklist floppy
install floppy /bin/false
blacklist freevxfs
install freevxfs /bin/false
blacklist garmin_gps
install garmin_gps /bin/false
blacklist gfs2
install gfs2 /bin/false
blacklist gnss
install gnss /bin/false
blacklist gnss-serial
install gnss-serial /bin/false
blacklist gnss-usb
install gnss-usb /bin/false
blacklist hfs
install hfs /bin/false
blacklist hfsplus
install hfsplus /bin/false
blacklist hamradio
install hamradio /bin/false
blacklist ipx
install ipx /bin/false
blacklist iwlwifi
install iwlwifi /bin/false
blacklist jffs2
install jffs2 /bin/false
blacklist joydev
install joydev /bin/false
blacklist jfs
install jfs /bin/false
blacklist kvm
install kvm /bin/false
blacklist kvm_amd
install kvm_amd /bin/false
blacklist kvm_intel
install kvm_intel /bin/false
blacklist lp
install lp /bin/false
blacklist mac80211
install mac80211 /bin/false
blacklist mt76
install mt76 /bin/false
blacklist mt76_usb
install mt76_usb /bin/false
blacklist mt76x0u
install mt76x0u /bin/false
blacklist mt76x2u
install mt76x2u /bin/false
blacklist mt7601u
install mt7601u /bin/false
blacklist mt7615e
install mt7615e /bin/false
blacklist mt7921e
install mt7921e /bin/false
blacklist netrom
install netrom /bin/false
blacklist p8022
install p8022 /bin/false
blacklist p8023
install p8023 /bin/false
blacklist parport
install parport /bin/false
blacklist ppdev
install ppdev /bin/false
blacklist psnap
install psnap /bin/false
blacklist r820t
install r820t /bin/false
blacklist rds
install rds /bin/false
blacklist reiserfs
install reiserfs /bin/false
blacklist rose
install rose /bin/false
blacklist rt2800lib
install rt2800lib /bin/false
blacklist rt2800pci
install rt2800pci /bin/false
blacklist rt2800usb
install rt2800usb /bin/false
blacklist rtl8188ee
install rtl8188ee /bin/false
blacklist rtl8192ce
install rtl8192ce /bin/false
blacklist rtl8192cu
install rtl8192cu /bin/false
blacklist rtl8192de
install rtl8192de /bin/false
blacklist rtl8192se
install rtl8192se /bin/false
blacklist rtl8723ae
install rtl8723ae /bin/false
blacklist rtl8723be
install rtl8723be /bin/false
blacklist rtl8821ae
install rtl8821ae /bin/false
blacklist rtl88x2bu
install rtl88x2bu /bin/false
blacklist rtl8xxxu
install rtl8xxxu /bin/false
blacklist rtl2830
install rtl2830 /bin/false
blacklist rtl2832
install rtl2832 /bin/false
blacklist rtl2832_sdr
install rtl2832_sdr /bin/false
blacklist rtl2838
install rtl2838 /bin/false
blacklist sctp
install sctp /bin/false
blacklist squashfs
install squashfs /bin/false
blacklist tipc
install tipc /bin/false
blacklist uas
install uas /bin/false
blacklist udf
install udf /bin/false
blacklist usb_storage
install usb_storage /bin/false
blacklist uvcvideo
install uvcvideo /bin/false
blacklist vboxdrv
install vboxdrv /bin/false
blacklist vboxnetadp
install vboxnetadp /bin/false
blacklist vboxnetflt
install vboxnetflt /bin/false
blacklist vhost
install vhost /bin/false
blacklist vhost_net
install vhost_net /bin/false
blacklist vhost_vsock
install vhost_vsock /bin/false
blacklist video1394
install video1394 /bin/false
blacklist vmmon
install vmmon /bin/false
blacklist vmw_vmci
install vmw_vmci /bin/false
blacklist xen
install xen /bin/false
blacklist x25
install x25 /bin/false
blacklist mei
install mei /bin/false
blacklist mei_me
install mei_me /bin/false
blacklist mei_hdcp
install mei_hdcp /bin/false
blacklist mei_pxp
install mei_pxp /bin/false
blacklist thunderbolt
install thunderbolt /bin/false
blacklist iwlmvm
install iwlmvm /bin/false
blacklist iwldvm
install iwldvm /bin/false
blacklist ipv6
install ipv6 /bin/false
EOF

# FSTAB 
log_info "Configuring filesystem mounts..."
cp /etc/fstab /etc/fstab.bak

# Only add if not already present
if ! grep -q "proc.*hidepid=2" /etc/fstab; then
    cat >> /etc/fstab << 'EOF'
proc     /proc      proc      noatime,nodev,nosuid,noexec,hidepid=2,gid=proc    0 0
tmpfs    /tmp       tmpfs     size=2G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /var/tmp   tmpfs     size=1G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /dev/shm   tmpfs     size=512M,noatime,nodev,nosuid,noexec,mode=1777   0 0
tmpfs    /run       tmpfs     size=512M,noatime,nodev,nosuid,mode=0755          0 0
tmpfs    /home/dev/.cache    tmpfs    size=1G,noatime,nodev,nosuid,noexec,mode=700,uid=1000,gid=1000    0 0
EOF
fi

groupadd -f proc
gpasswd -a root proc

# PERMISSIONS
log_info "Securing file permissions..."
chmod 700 /root
chown root:root /root
chmod 700 /home/dev
chown dev:dev /home/dev

# Remove world-readable from all files in home
find /home/dev -type f -exec chmod o-rwx {} \; 2>/dev/null || true
find /home/dev -type d -exec chmod o-rwx {} \; 2>/dev/null || true

chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chown root:root /etc/shadow
chown root:root /etc/gshadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chown root:root /etc/passwd
chown root:root /etc/group
chmod 440 /etc/sudoers
chown root:root /etc/sudoers
chmod 750 /etc/sudoers.d
chown root:root /etc/sudoers.d
find /etc/sudoers.d -type f -exec chmod 440 {} \; 2>/dev/null || true
chmod 644 /etc/pam.d/*
chown root:root /etc/pam.d/*
chmod 600 /etc/security/access.conf
chmod 600 /etc/security/limits.conf
chmod 600 /etc/security/namespace.conf 2>/dev/null || true
chown root:root /etc/security/* 2>/dev/null || true

if [[ -d /etc/ssh ]]; then
    chmod 700 /etc/ssh
    chmod 600 /etc/ssh/*_key 2>/dev/null || true
    chmod 644 /etc/ssh/*.pub 2>/dev/null || true
    chmod 644 /etc/ssh/sshd_config 2>/dev/null || true
    chown -R root:root /etc/ssh
fi

chmod 700 /etc/cron.d 2>/dev/null || true
chmod 700 /etc/cron.daily 2>/dev/null || true
chmod 700 /etc/cron.hourly 2>/dev/null || true
chmod 700 /etc/cron.weekly 2>/dev/null || true
chmod 700 /etc/cron.monthly 2>/dev/null || true
chmod 600 /etc/crontab 2>/dev/null || true

if [[ -f /etc/at.deny ]]; then
    chmod 600 /etc/at.deny
fi

chmod 700 /boot
chown root:root /boot
find /boot -type f -name "vmlinuz*" -exec chmod 600 {} \; 2>/dev/null || true
find /boot -type f -name "initrd*" -exec chmod 600 {} \; 2>/dev/null || true
find /boot -type f -name "System.map*" -exec chmod 600 {} \; 2>/dev/null || true
find /boot -type f -name "config-*" -exec chmod 600 {} \; 2>/dev/null || true

if [[ -f /boot/grub/grub.cfg ]]; then
    chmod 600 /boot/grub/grub.cfg
    chown root:root /boot/grub/grub.cfg
fi

log_info "Searching for world-writable files..."
WORLD_WRITABLE=$(find / -xdev -type f -perm -0002 \
    ! -path "/tmp/*" \
    ! -path "/var/tmp/*" \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    2>/dev/null || true)

if [[ -n "$WORLD_WRITABLE" ]]; then
    log_warn "Found world-writable files:"
    echo "$WORLD_WRITABLE"
    log_info "Removing world-writable bit from these files"
    echo "$WORLD_WRITABLE" | xargs -r chmod o-w
fi

log_info "Searching for unowned files..."
UNOWNED=$(find / -xdev \( -nouser -o -nogroup \) \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    2>/dev/null || true)

if [[ -n "$UNOWNED" ]]; then
    log_warn "Found unowned files (review manually):"
    echo "$UNOWNED"
fi

chown root:adm -R /var/log 2>/dev/null || true
chmod -R 0640 /var/log 2>/dev/null || true
chmod 0750 /var/log 2>/dev/null || true

# OPENSNITCH 
log_info "Configuring OpenSnitch application firewall..."
cat > /etc/systemd/system/opensnitchd.service << 'EOF'
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
EOF

# Create rules directory if it doesn't exist
mkdir -p /etc/opensnitchd/rules
chmod 750 /etc/opensnitchd
chmod 750 /etc/opensnitchd/rules

# Create log file with proper permissions
touch /var/log/opensnitchd.log
chmod 640 /var/log/opensnitchd.log

# Enable and start the daemon
systemctl daemon-reload
systemctl enable opensnitchd.service
systemctl start opensnitchd.service

# Install Blocklists
log_info "Installing OpenSnitch blocklists..."
git clone --depth 1 https://github.com/DXC-0/Respect-My-Internet.git
cd Respect-My-Internet
chmod +x install.sh
./install.sh
cd

# PRIVILEGE ESCALATION HARDENING
log_info "Hardening privilege escalation vectors..."
echo "" > /etc/securetty
chmod 600 /etc/securetty

# Restrict cron/at to dev only
echo "dev" > /etc/cron.allow
echo "dev" > /etc/at.allow
chmod 600 /etc/cron.allow
chmod 600 /etc/at.allow
echo "" > /etc/cron.deny 2>/dev/null || true
echo "" > /etc/at.deny 2>/dev/null || true

# Remove dangerous privilege escalation tools
rm -f /usr/bin/run0 2>/dev/null || true
rm -f /usr/bin/su 2>/dev/null || true

# Deny all polkit requests
mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/00-deny-all.rules << 'EOF'
// Deny all polkit requests - hardened system
polkit.addRule(function(action, subject) {
    return polkit.Result.NO;
});
EOF

chmod 0644 /etc/polkit-1/rules.d/00-deny-all.rules

# LOCKDOWN
log_info "Final lockdown phase - removing SUID/SGID bits..."
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec chmod a-s {} \; 2>/dev/null || true

# Restore sudo SUID
chmod u+s /usr/bin/sudo

log_info "Cleaning up packages..."
apt clean
apt autopurge -y

# Remove leftover config files
RC_PKGS=$(dpkg -l | grep '^rc' | awk '{print $2}' || true)
if [ -n "$RC_PKGS" ]; then
    apt purge -y $RC_PKGS 2>/dev/null || true
fi

# Make critical system files immutable
log_info "Setting immutable flags on critical system files..."
log_warn "This will prevent system updates from modifying core configs"
log_warn "Run 'chattr -i <file>' to unlock individual files if needed"

chattr +i /etc/conf 2>/dev/null || true
chattr +i /etc/passwd 2>/dev/null || true
chattr +i /etc/passwd- 2>/dev/null || true
chattr +i /etc/shadow 2>/dev/null || true
chattr +i /etc/shadow- 2>/dev/null || true
chattr +i /etc/group 2>/dev/null || true
chattr +i /etc/group- 2>/dev/null || true
chattr +i /etc/gshadow 2>/dev/null || true
chattr +i /etc/gshadow- 2>/dev/null || true
chattr +i /etc/login.defs 2>/dev/null || true
chattr +i /etc/shells 2>/dev/null || true
chattr +i /etc/securetty 2>/dev/null || true
chattr +i /etc/services 2>/dev/null || true
chattr +i /etc/fstab 2>/dev/null || true
chattr +i /etc/adduser.conf 2>/dev/null || true
chattr +i /etc/deluser.conf 2>/dev/null || true
chattr -R +i /etc/host.conf 2>/dev/null || true
chattr +i /etc/hosts 2>/dev/null || true
chattr +i /etc/hosts.allow 2>/dev/null || true
chattr +i /etc/hosts.deny 2>/dev/null || true
chattr -R +i /etc/default 2>/dev/null || true
chattr -R +i /etc/sudoers 2>/dev/null || true
chattr -R +i /etc/sudoers.d 2>/dev/null || true
chattr -R +i /etc/pam.d 2>/dev/null || true
chattr -R +i /usr/lib/pam.d 2>/dev/null || true
chattr -R +i /etc/security 2>/dev/null || true
chattr +i /usr/lib/sysctl.d/sysctl.conf 2>/dev/null || true
chattr -R +i /usr/lib/sysctl.d 2>/dev/null || true
chattr -R +i /etc/sysctl.conf 2>/dev/null || true
chattr -R +i /etc/sysctl.d 2>/dev/null || true
chattr -R +i /etc/modprobe.d 2>/dev/null || true
chattr -R +i /usr/lib/modprobe.d 2>/dev/null || true
chattr -R +i /etc/iptables 2>/dev/null || true
chattr -R +i /etc/profile 2>/dev/null || true
chattr -R +i /etc/profile.d 2>/dev/null || true
chattr -R +i /etc/bash.bashrc 2>/dev/null || true
chattr -R +i /etc/bashrc 2>/dev/null || true
chattr +i /root/.bashrc 2>/dev/null || true
chattr +i /home/dev/.bashrc 2>/dev/null || true
chattr -R +i /etc/cron.allow 2>/dev/null || true
chattr -R +i /etc/at.allow 2>/dev/null || true
chattr -R +i /etc/cron.d 2>/dev/null || true
chattr -R +i /etc/cron.daily 2>/dev/null || true
chattr -R +i /etc/cron.hourly 2>/dev/null || true
chattr -R +i /etc/cron.monthly 2>/dev/null || true
chattr -R +i /etc/cron.weekly 2>/dev/null || true
chattr -R +i /etc/polkit-1 2>/dev/null || true
chattr +i /etc/nsswitch.conf 2>/dev/null || true
chattr +i /etc/ld.so.conf 2>/dev/null || true
chattr -R +i /etc/ld.so.conf.d 2>/dev/null || true
chattr -R +i /lib/modules 2>/dev/null || true
chattr -R +i /usr 2>/dev/null || true
chattr -R +i /boot 2>/dev/null || true 

log_info "=========================================="
log_info "HARDENING COMPLETE"
log_info "=========================================="
log_warn "System will require U2F device for all authentication"
log_warn "Immutable files are locked - use 'chattr -i' to modify"
log_warn "Reboot recommended to apply all changes"
