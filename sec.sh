#!/bin/bash

set -euo pipefail

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

# AUDIT FRAMEWORK
setup_auditd() {
    log_info "Configuring audit framework..."
    
    apt install -y auditd audispd-plugins
    
    cat > /etc/audit/auditd.conf << 'EOF'
log_file = /var/log/audit/audit.log
log_format = ENRICHED
log_group = adm
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 50
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
distribute_network = no
q_depth = 2000
overflow_action = SYSLOG
max_restarts = 10
EOF

    cat > /etc/audit/audit.rules << 'EOF'
# Remove any existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 2

# Audit successful/unsuccessful unauthorized access attempts
-a always,exit -F arch=b64 -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Audit successful file creation
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=0 -F auid>=1000 -F auid!=4294967295 -k file_creation

# Audit successful file modification
-a always,exit -F arch=b64 -S rename -S renameat -S link -S symlink -F exit=0 -F auid>=1000 -F auid!=4294967295 -k file_modification

# Audit successful file deletion
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F exit=0 -F auid>=1000 -F auid!=4294967295 -k file_deletion

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-change
-a always,exit -F arch=b64 -S execve -k command-execution
-a always,exit -F arch=b64 -S kill -k process-termination
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege-escalation
-a always,exit -F arch=b64 -S chown -S fchown -S lchown -S fchownat -k permission-change
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k permission-change

# Monitor authentication files
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/gshadow -p wa -k gshadow_changes
-w /etc/security/ -p wa -k security_changes
-w /etc/pam.d/ -p wa -k pam_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_d_changes

# Monitor system configuration
-w /etc/sysctl.conf -p wa -k sysctl_changes
-w /etc/sysctl.d/ -p wa -k sysctl_d_changes
-w /etc/modprobe.d/ -p wa -k modprobe_changes
-w /etc/modules-load.d/ -p wa -k modules_load_changes
-w /etc/systemd/ -p wa -k systemd_changes
-w /boot/ -p wa -k boot_changes

# Monitor network configuration
-w /etc/hosts -p wa -k hosts_changes
-w /etc/hostname -p wa -k hostname_changes
-w /etc/network/ -p wa -k network_changes
-w /etc/netplan/ -p wa -k netplan_changes
-w /etc/iptables/ -p wa -k iptables_changes

# Monitor package management
-w /usr/bin/apt -p x -k package_management
-w /usr/bin/apt-get -p x -k package_management
-w /usr/bin/dpkg -p x -k package_management
-w /usr/bin/snap -p x -k package_management
-w /var/log/dpkg.log -p wa -k package_log

# Monitor suspicious activity
-w /tmp -p wa -k tmp_changes
-w /var/tmp -p wa -k vartmp_changes
-w /dev/shm -p wa -k shm_changes

# Monitor kernel module loading
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_modules
-a always,exit -F arch=b64 -S finit_module -k kernel_modules
-a always,exit -F arch=b64 -S create_module -k kernel_modules
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules

# Make configuration immutable
-e 2
EOF

    systemctl enable auditd
    systemctl start auditd
    
    # Configure log rotation
    cat > /etc/logrotate.d/audit << 'EOF'
/var/log/audit/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0600 root root
    sharedscripts
    postrotate
        /usr/sbin/service auditd rotate
    endscript
}
EOF
}

# INTEGRITY MONITORING
setup_aide() {
    log_info "Setting up AIDE integrity monitoring..."
    
    apt install -y aide aide-common
    
    cat > /etc/aide/aide.conf << 'EOF'
# AIDE configuration
database=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
gzip_dbout=yes
verbose=5
report_url=file:/var/log/aide/aide.log
report_url=stdout

# Rule definitions
NORMAL = p+i+n+u+g+s+m+c+a+S+md5+sha256
DIR = p+i+n+u+g
PERMS = p+u+g+acl+selinux+xattrs
LOG = p+u+g+n+S+acl+selinux+xattrs
CONTENT = sha256+md5
CONTENT_EX = sha256+md5+p+i+n+u+g+s+m+c+a+S
DATAONLY = p+n+u+g+s+acl+selinux+xattrs+sha256

# Directories to check
/boot CONTENT_EX
/bin CONTENT_EX
/sbin CONTENT_EX
/lib CONTENT_EX
/lib64 CONTENT_EX
/usr/bin CONTENT_EX
/usr/sbin CONTENT_EX
/usr/lib CONTENT_EX
/usr/lib64 CONTENT_EX
/etc CONTENT_EX
!/etc/mtab
!/etc/.*~
/root CONTENT_EX
!/root/.bash_history

# System configuration
/etc/passwd CONTENT_EX
/etc/shadow CONTENT_EX
/etc/group CONTENT_EX
/etc/gshadow CONTENT_EX
/etc/ssh/sshd_config CONTENT_EX
/etc/sudoers CONTENT_EX
/etc/sudoers.d CONTENT_EX
/etc/pam.d CONTENT_EX
/etc/security CONTENT_EX
/etc/systemd CONTENT_EX

# Logs (attributes only)
/var/log LOG
!/var/log/journal
!/var/log/audit/audit.log.*

# Exclude
!/proc
!/sys
!/dev
!/run
!/tmp
!/var/tmp
!/var/cache
!/var/lib/aide
!/var/lib/dpkg
!/var/lib/apt
EOF

    # Initialize AIDE database
    aideinit -y -f
    
    # Create daily check cron job
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --check | /usr/bin/mail -s "AIDE Daily Report $(hostname)" root
EOF
    chmod 755 /etc/cron.daily/aide-check
}

# MEMORY PROTECTION
setup_memory_protection() {
    log_info "Configuring advanced memory protection..."
    

# APPARMOR CONFIGURATION
setup_apparmor() {
    log_info "Configuring AppArmor..."
    
    apt install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
    
    # Enable AppArmor
    systemctl enable apparmor
    systemctl start apparmor
    
    # Set all profiles to enforce mode
    aa-enforce /etc/apparmor.d/*
    
    # Create custom profile for user shells
    cat > /etc/apparmor.d/usr.bin.bash << 'EOF'
#include <tunables/global>

/bin/bash {
  #include <abstractions/base>
  #include <abstractions/bash>
  
  capability setuid,
  capability setgid,
  
  /bin/bash mr,
  /etc/bash.bashrc r,
  /etc/profile r,
  /etc/profile.d/* r,
  /home/*/.bashrc r,
  /home/*/.bash_profile r,
  /home/*/.profile r,
  
  # Deny access to sensitive areas
  deny /etc/shadow rwx,
  deny /etc/gshadow rwx,
  deny /boot/** rwx,
  deny /sys/** w,
  deny /proc/sys/** w,
  deny /root/** rwx,
  
  # Restrict network access
  deny network raw,
  deny network packet,
}
EOF
    
    apparmor_parser -r /etc/apparmor.d/usr.bin.bash
}

# SYSTEMD SERVICE HARDENING
harden_systemd_services() {
    log_info "Hardening systemd services..."
    
    # Create override directory
    mkdir -p /etc/systemd/system/
    
    # Example: Harden chrony service
    mkdir -p /etc/systemd/system/chrony.service.d/
    cat > /etc/systemd/system/chrony.service.d/hardening.conf << 'EOF'
[Service]
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete
SystemCallArchitectures=native
ReadWritePaths=/var/lib/chrony /var/log/chrony
CapabilityBoundingSet=CAP_SYS_TIME
AmbientCapabilities=CAP_SYS_TIME
EOF

    # Apply to other critical services
    for service in rsyslog systemd-resolved systemd-networkd; do
        if systemctl list-units --all | grep -q "$service"; then
            mkdir -p "/etc/systemd/system/${service}.service.d/"
            cat > "/etc/systemd/system/${service}.service.d/hardening.conf" << 'EOF'
[Service]
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
EOF
        fi
    done
    
    systemctl daemon-reload
}

# ADVANCED IPTABLES RULES
setup_advanced_firewall() {
    log_info "Setting up advanced firewall rules..."
    
    cat > /etc/iptables/rules.v4 << 'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]

# Clear all rules
-F
-X
-Z

# Drop invalid packets
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A FORWARD -m conntrack --ctstate INVALID -j DROP
-A OUTPUT -m conntrack --ctstate INVALID -j DROP

# Loopback
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# Established connections
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Rate limiting
-A INPUT -p tcp -m conntrack --ctstate NEW -m recent --set
-A INPUT -p tcp -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 20 -j DROP

# SYN flood protection
-A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
-A INPUT -p tcp --syn -j DROP

# Port scanning protection
-N PORT_SCANNING
-A PORT_SCANNING -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
-A PORT_SCANNING -j DROP

# DDoS protection
-A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j ACCEPT
-A INPUT -p icmp -j DROP

# Block common attacks
-A INPUT -p tcp --tcp-flags ALL ALL -j DROP
-A INPUT -p tcp --tcp-flags ALL NONE -j DROP
-A INPUT -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
-A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
-A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
-A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP
-A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
-A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
-A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP

# Block fragments
-A INPUT -f -j DROP

# Block broadcast
-A INPUT -m pkttype --pkt-type broadcast -j DROP
-A INPUT -m pkttype --pkt-type multicast -j DROP

# Log and drop everything else
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-dropped: " --log-level 7
-A INPUT -j DROP

COMMIT

*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

# Disable connection tracking for performance
-A PREROUTING -p tcp --dport 80 -j NOTRACK
-A OUTPUT -p tcp --sport 80 -j NOTRACK

COMMIT

*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]

# Drop invalid packets
-A PREROUTING -m conntrack --ctstate INVALID -j DROP

# Block packets with bogus TCP flags
-A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
-A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
-A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

COMMIT
EOF

    iptables-restore < /etc/iptables/rules.v4
    netfilter-persistent save
}

# USB PROTECTION
setup_usb_protection() {
    log_info "Setting up USB protection..."
    
    # Create udev rules to block USB storage
    cat > /etc/udev/rules.d/10-usb-block.rules << 'EOF'
# Block all USB storage devices
ACTION=="add", SUBSYSTEMS=="usb", DRIVERS=="usb-storage", ATTR{authorized}="0"
ACTION=="add", ATTRS{idVendor}=="*", ATTRS{idProduct}=="*", DRIVERS=="usb-storage", ATTR{authorized}="0"

# Block new USB devices except HID
ACTION=="add", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", ATTRS{bDeviceClass}!="03", ATTR{authorized}="0"
EOF
    
    # Create USBGuard rules if available
    if command -v usbguard >/dev/null 2>&1; then
        apt install -y usbguard
        
     # Generate initial policy
        usbguard generate-policy > /etc/usbguard/rules.conf
        
     # Configure USBGuard
        cat > /etc/usbguard/usbguard-daemon.conf << 'EOF'
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=keep
InsertedDevicePolicy=apply-policy
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent
IPCAllowedUsers=root
IPCAllowedGroups=
DeviceRulesWithPort=false
AuditBackend=LinuxAudit
AuditFilePath=/var/log/usbguard/usbguard-audit.log
EOF
        
        systemctl enable usbguard
        systemctl start usbguard
    fi
    
    # Reload udev rules
    udevadm control --reload-rules
    udevadm trigger
}

# COMPILER REMOVAL
remove_compilers() {
    log_info "Removing compilers and development tools..."
    
    COMPILER_PACKAGES=(
        "gcc*" "g++*" "clang*" "llvm*" "make" "cmake" "automake" "autoconf"
        "build-essential" "libtool" "flex" "bison" "nasm" "yasm" "gdb"
        "valgrind" "strace" "ltrace" "binutils" "elfutils" "dwarfdump"
        "golang*" "rustc" "cargo" "nodejs" "npm" "python3-pip" "ruby"
        "perl" "php*" "openjdk*" "default-jdk" "default-jre"
    )
    
    for pkg in "${COMPILER_PACKAGES[@]}"; do
        apt purge -y $pkg 2>/dev/null || true
    done
    
    # Remove any remaining binaries
    COMPILER_BINARIES=(
        "/usr/bin/gcc" "/usr/bin/g++" "/usr/bin/cc" "/usr/bin/c++"
        "/usr/bin/clang" "/usr/bin/clang++" "/usr/bin/ld" "/usr/bin/as"
        "/usr/bin/make" "/usr/bin/cmake" "/usr/bin/automake" "/usr/bin/autoconf"
    )
    
    for binary in "${COMPILER_BINARIES[@]}"; do
        if [[ -f "$binary" ]]; then
            rm -f "$binary"
            # Create immutable placeholder
            touch "$binary"
            chmod 000 "$binary"
            chattr +i "$binary"
        fi
    done
}

# LOG HARDENING
harden_logging() {
    log_info "Hardening system logging..."
    
    # Configure rsyslog security
    cat > /etc/rsyslog.d/01-security.conf << 'EOF'
# Security-focused rsyslog configuration
$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0750
$Umask 0077
$PrivDropToUser syslog
$PrivDropToGroup syslog

# Rate limiting
$SystemLogRateLimitInterval 5
$SystemLogRateLimitBurst 50

# Reliable forwarding queue
$ActionQueueType LinkedList
$ActionQueueFileName fwdRule1
$ActionResumeRetryCount -1
$ActionQueueSaveOnShutdown on

# Enhanced logging
*.* /var/log/all.log
auth,authpriv.* /var/log/auth.log
kern.* /var/log/kern.log
mail.* /var/log/mail.log

# Log authentication failures prominently
auth.warning /var/log/auth-failures.log

# Suppress noisy messages
:msg, contains, "systemd" stop
:msg, contains, "UFW BLOCK" stop
EOF
    
    # Configure journald hardening
    cat > /etc/systemd/journald.conf.d/hardening.conf << 'EOF'
[Journal]
Storage=persistent
Compress=yes
Seal=yes
SplitMode=uid
ForwardToSyslog=yes
MaxFileSec=1day
MaxRetentionSec=1month
SystemMaxUse=500M
SystemKeepFree=100M
RuntimeMaxUse=50M
RuntimeKeepFree=20M
MaxLevelStore=info
MaxLevelSyslog=info
MaxLevelConsole=warning
RateLimitIntervalSec=30s
RateLimitBurst=1000
EOF
    
    systemctl restart rsyslog
    systemctl restart systemd-journald
}

# MANDATORY ACCESS CONTROL
setup_tomoyo() {
    log_info "Setting up TOMOYO Linux..."
    
    apt install -y tomoyo-tools
    
    # Initialize TOMOYO
    /usr/lib/tomoyo/init_policy
    
    # Configure TOMOYO
    cat > /etc/tomoyo/config << 'EOF'
TOMOYO_TRIGGER=/sbin/init
ACTIVATED_TOMOYO_LSM=y
TOMOYO_POLICY_LOADER=/usr/sbin/tomoyo-loadpolicy
TOMOYO_POLICY_DIR=/etc/tomoyo/
TOMOYO_PROFILE_VERSION=20110903
EOF
    
    # Add TOMOYO to GRUB
    if ! grep -q "security=tomoyo" /etc/default/grub; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="security=tomoyo /' /etc/default/grub
        update-grub
    fi
}

# MAIN EXECUTION
main() {
    log_info "Starting advanced hardening..."
    
    # Run your existing scripts first
    [[ -f sec.sh ]] && bash sec.sh
    [[ -f gtfobin.sh ]] && bash gtfobin.sh
    
    # Additional hardening
    setup_auditd
    setup_aide
    setup_memory_protection
    setup_apparmor
    harden_systemd_services
    advanced_network_hardening
    setup_advanced_firewall
    setup_usb_protection
    remove_compilers
    harden_logging
    setup_tomoyo
    
    # Final cleanup
    apt clean
    apt autoremove --purge -y
    
    # Clear history
    history -c
    history -w
    > ~/.bash_history
    > /home/dev/.bash_history
    
    log_info "=========================================="
    log_info "ADVANCED HARDENING COMPLETE"
    log_info "=========================================="
    log_warn "System requires reboot for all changes"
    log_warn "Review: $LOG_FILE"
}

main "$@"

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
    breeze-gtk-theme bibata* qt5ct gdebi-core opensnitch python3-opensnitch*

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

cat > /etc/pam.d/systemd-user << 'EOF'
#%PAM-1.0
account   include     common-account
session   required    pam_limits.so
session   required    pam_unix.so
session   required    pam_env.so user_readenv=0
session   optional    pam_systemd.so
EOF

cat > /etc/pam.d/polkit-1 << 'EOF'
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
*                -      maxlogins     1
*                -      maxsyslogins  1
dev              -      maxlogins     1
dev              -      maxsyslogins  1
root             -      maxlogins     1
root             -      maxsyslogin   1
root            hard    nproc         65536
root            hard    core          0
*               hard    core          0
*               hard    nproc         1024
*               soft    nproc         512
*               hard    nofile        65535
*               soft    nofile        8192
*               hard    memlock       65536
*               soft    memlock       65536
EOF

echo "ProcessSizeMax=0
Storage=none" >> /etc/systemd/coredump.conf
echo "ulimit -c 0" >> /etc/profile

cat >/etc/login.defs <<'EOF'
# Password aging controls
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_WARN_AGE   14
PASS_MIN_LEN    16

# Use SHA512 for password hashing (fallback)
ENCRYPT_METHOD  YESCRYPT
YESCRYPT_COST_FACTOR 11

# UID/GID ranges
UID_MIN         1000
UID_MAX         60000
GID_MIN         1000
GID_MAX         60000
SYS_UID_MIN     100
SYS_UID_MAX     999
SYS_GID_MIN     100
SYS_GID_MAX     999

# User private groups
USERGROUPS_ENAB yes

# Secure umask
UMASK           027

# Secure home directory permissions
HOME_MODE       0750

# Logging
LOG_OK_LOGINS   yes
LOG_UNKFAIL_ENAB yes
SYSLOG_SU_ENAB  yes
SYSLOG_SG_ENAB  yes

# Prevent access to su for non-wheel group
SU_WHEEL_ONLY   yes

# Login timeout
LOGIN_TIMEOUT   60

# Maximum login retries
LOGIN_RETRIES   3

# Delay after failed login (seconds)
FAIL_DELAY      4

# Secure TTY
DEFAULT_HOME    no
EOF

sed -i 's/^SHELL=.*/SHELL=\/usr\/sbin\/nologin/' /etc/default/useradd
sed -i 's/^DSHELL=.*/DSHELL=\/usr\/sbin\/nologin/' /etc/adduser.conf
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

cat >/etc/security/access.conf <<'EOF'
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

cat >/etc/ssl/openssl-hardened.cnf <<EOF
# OPENSSL
openssl_conf = openssl_init

[openssl_init]
ssl_conf = ssl_sect
providers = provider_sect

[provider_sect]
default = default_sect

[default_sect]
activate = 1

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
# Minimum TLS version
MinProtocol = TLSv1.2

# Disable weak ciphers
CipherSuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
CipherString = ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:! aNULL: !eNULL:! EXPORT:!DES:!RC4:!3DES:!MD5:!PSK:!RSA:!aRSA:!SHA1:!SHA256:!SHA384

# Strong curves only
Curves = X25519:secp384r1:secp256r1

# Signature algorithms
SignatureAlgorithms = ed25519:ed448:rsa_pss_pss_sha512:rsa_pss_pss_sha384:rsa_pss_pss_sha256:rsa_pss_rsae_sha512:rsa_pss_rsae_sha384:rsa_pss_rsae_sha256:ecdsa_secp384r1_sha384:ecdsa_secp256r1_sha256

# Options
Options = ServerPreference,PrioritizeChaCha,NoCompression
EOF

sudo cp /etc/ssl/openssl. cnf /etc/ssl/openssl. cnf.backup
sudo cp /etc/ssl/openssl-hardened.cnf /etc/ssl/openssl.cnf

cat >/etc/gnutls/config <<EOF
[global]
# Minimum TLS version
min-verification-profile = medium

[priorities]
SYSTEM = SECURE256:+SECURE128:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0:-VERS-DTLS1.2:-CIPHER-ALL:+AES-256-GCM:+AES-128-GCM:+CHACHA20-POLY1305:-MAC-ALL:+AEAD:-KX-ALL:+ECDHE-ECDSA: +ECDHE-RSA:+DHE-RSA:-CURVE-ALL:+CURVE-X25519:+CURVE-SECP384R1:+CURVE-SECP256R1:-SIGN-ALL: +SIGN-EDDSA-ED25519:+SIGN-ECDSA-SECP384R1-SHA384:+SIGN-ECDSA-SECP256R1-SHA256:+SIGN-RSA-PSS-RSAE-SHA512:+SIGN-RSA-PSS-RSAE-SHA384:+SIGN-RSA-PSS-RSAE-SHA256:%SAFE_RENEGOTIATION:%NO_SESSION_HASH
EOF

# SYSCTL 
rm -rf /usr/lib/sysctl.d
mkdir -p /usr/lib/sysctl.d
cat > /usr/lib/sysctl.d/sysctl.conf << 'EOF'
# Restrict kernel pointer exposure
dev.tty.ldisc_autoload = 0
dev.tty.legacy_tiocsti = 0
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_symlinks = 1
kernel.acct = 1
kernel.core_pattern = |/bin/false
kernel.core_uses_pid = 0
kernel.core_uses_pid = 1
kernel.ctrl-alt-del = 0
kernel.dmesg_restrict = 1
kernel.ftrace_enabled = 0
kernel.io_uring_disabled = 2
kernel.kallsyms_restrict = 1
kernel.kexec_load_disabled = 1
kernel.kptr_restrict = 2
kernel.modules_disabled = 1
kernel.nmi_watchdog = 0
kernel.panic_on_oops = 1
kernel.perf_cpu_time_max_percent = 1
kernel.perf_event_max_sample_rate = 1
kernel.perf_event_paranoid = 3
kernel.printk = 3 3 3 3
kernel.randomize_va_space = 2
kernel.stack_tracer_enabled = 0
kernel.suid_dumpable = 0
kernel.sysrq = 0
kernel.trace_options = 0
kernel.unprivileged_bpf_disabled = 1
kernel.unprivileged_userns_clone = 0
kernel.watchdog = 0
kernel.yama.ptrace_scope = 3
net.core.bpf_jit_enable = 0
net.core.bpf_jit_harden = 2
net.core.netdev_max_backlog = 5000
net.core.netdev_max_backlog = 65535
net.core.optmem_max = 65535
net.core.optmem_max = 65536
net.core.rmem_default = 262144
net.core.rmem_max = 4194304
net.core.rmem_max = 6291456
net.core.somaxconn = 1024
net.core.somaxconn = 65535
net.core.wmem_default = 262144
net.core.wmem_max = 4194304
net.core.wmem_max = 6291456
net.netfilter.nf_conntrack_helper = 0
net.netfilter.nf_conntrack_max = 100000
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_be_liberal = 0
net.netfilter.nf_conntrack_tcp_loose = 0
net.netfilter.nf_conntrack_tcp_max_retrans = 3
net.netfilter.nf_conntrack_tcp_timeout_close = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 20
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 20
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 20
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 20
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 10
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.arp_accept = 0
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.arp_filter = 1
net.ipv4.conf.all.arp_ignore = 2
net.ipv4.conf.all.arp_notify = 0
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.mc_forwarding = 0
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.shared_media = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.forwarding = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.mc_forwarding = 0
net.ipv4.conf.default.proxy_arp = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.shared_media = 0
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089
net.ipv4.ip_forward = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_invalid_ratelimit = 500
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_limit_output_bytes = 262144
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
vm.max_map_count = 1048576
vm.mmap_min_addr = 65536
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
vm.oom_kill_allocating_task = 1
vm.overcommit_memory = 2
vm.overcommit_ratio = 100
vm.panic_on_oom = 1
vm.swappiness = 1
vm.unprivileged_userfaultfd = 0
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
proc     /proc              proc      noatime,nodev,nosuid,noexec,hidepid=2,gid=proc                    0 0
tmpfs    /tmp               tmpfs     size=2G,noatime,nodev,nosuid,noexec,mode=1777                     0 0
tmpfs    /var/tmp           tmpfs     size=1G,noatime,nodev,nosuid,noexec,mode=1777                     0 0
tmpfs    /dev/shm           tmpfs     size=512M,noatime,nodev,nosuid,noexec,mode=1777                   0 0
tmpfs    /run               tmpfs     size=512M,noatime,nodev,nosuid,mode=0755                          0 0
tmpfs    /home/dev/.cache   tmpfs     size=1G,noatime,nodev,nosuid,noexec,mode=700,uid=1000,gid=1000    0 0
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
