#!/bin/bash

set -euo pipefail

# Ensure running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Define the primary user
PRIMARY_USER="dev"
PRIMARY_UID="1000"
PRIMARY_GID="1000"

# Install extrepo and add librewolf
apt update
apt install -y extrepo --no-install-recommends
extrepo enable librewolf
apt update
apt install -y librewolf --no-install-recommends

# SYSTEMD HARDENING
# Disable unnecessary services (ignore errors for non-existent services)
systemctl disable --now ssh.service ssh.socket vino-server.service x11vnc.service tigervnc.service xrdp.service xrdp-sesman.service serial-getty@*.service systemd-journal-remote.socket systemd-journal-gatewayd.socket systemd-journal-upload.service cockpit.socket cockpit.service webmin.service nfs-client.target nfs-common.service nfs-mountd.service nfs-server.service rpcbind.socket rpcbind.service iscsid.socket iscsid.service iscsi.service open-iscsi.service nvmf-autoconnect.service nvmefc-boot-connections.service smbd.service nmbd.service samba.service samba-ad-dc.service vsftpd.service proftpd.service pure-ftpd.service sssd.service krb5-kdc.service krb5-admin-server.service nslcd.service nscd.service winbind.service libvirtd.service libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket virtlogd.service virtlogd.socket virtlockd.service virtlockd.socket qemu-guest-agent.service vboxdrv.service vboxballoonctrl-service.service vboxautostart-service.service vboxweb-service.service vmtoolsd.service vmware-vmblock-fuse.service hv-fcopy-daemon.service hv-kvp-daemon.service hv-vss-daemon.service docker.service docker.socket containerd.service podman.socket podman.service lxd.socket lxd.service lxc.service lxc-net.service multipassd.service snmpd.service snmptrapd.service salt-minion.service puppet.service chef-client.service cloud-init.service cloud-init-local.service cloud-config.service cloud-final.service spice-vdagentd.service spice-vdagentd.socket usbmuxd.service ModemManager.service unattended-upgrades wpa_supplicant speech-dispatcher bluetooth.service bluez apport.service avahi-daemon.socket avahi-daemon.service cups-browsed cups.socket cups.path cups.service debug-shell.service accounts-daemon.service colord.service geoclue.service switcheroo-control.service power-profiles-daemon.service bolt.service fwupd.service packagekit.service rtkit-daemon.service iio-sensor-proxy.service apt-daily.timer apt-daily-upgrade.timer man-db.timer e2scrub_all.timer motd-news.timer kerneloops.service anacron.timer anacron.service cron.service rsync.service udisks2.service fprintd.service systemd-binfmt.service 2>/dev/null || true

# Mask services to prevent activation
systemctl mask ssh.service ssh.socket telnet.socket inetd.service xinetd.service vino-server.service x11vnc.service tigervnc.service xrdp.service xrdp-sesman.service xrdp.socket serial-getty@.service getty@ttyS0.service console-getty.service debug-shell.service systemd-journal-remote.socket systemd-journal-gatewayd.socket systemd-journal-upload.service cockpit.socket cockpit.service webmin.service nfs-client.target nfs-common.service nfs-mountd.service nfs-server.service nfs-blkmap.service nfs-idmapd.service rpcbind.socket rpcbind.service rpcbind.target iscsid.socket iscsid.service iscsi.service open-iscsi.service nvmf-autoconnect.service nvmefc-boot-connections.service smbd.service nmbd.service samba.service samba-ad-dc.service remote-fs.target remote-fs-pre.target remote-cryptsetup.target vsftpd.service proftpd.service pure-ftpd.service sssd.socket sssd-nss.socket sssd-pam.socket sssd-sudo.socket sssd-autofs.socket sssd-ssh.socket sssd-pac.socket sssd-kcm.socket krb5-kdc.service krb5-admin-server.service nslcd.service winbind.service libvirtd.service libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket virtlogd.service virtlogd.socket virtlockd.service virtlockd.socket libvirt-guests.service qemu-guest-agent.service vboxdrv.service vboxballoonctrl-service.service vboxautostart-service.service vboxweb-service.service vboxadd.service vboxadd-service.service vmtoolsd.service vmware-vmblock-fuse.service vmware-tools.service open-vm-tools.service hv-fcopy-daemon.service hv-kvp-daemon.service hv-vss-daemon.service hyperv-daemons.service docker.service docker.socket containerd.service podman.socket podman.service lxd.socket lxd.service lxc.service lxc-net.service systemd-nspawn@.service machines.target multipassd.service snmpd.service snmptrapd.service salt-minion.service puppet.service chef-client.service cloud-init.target cloud-init.service cloud-init-local.service cloud-config.service cloud-final.service spice-vdagentd.service spice-vdagentd.socket usbip.service usbipd.service usbmuxd.service usbmuxd.socket ModemManager.service ctrl-alt-del.target kexec.target systemd-kexec.service proc-sys-fs-binfmt_misc.mount proc-sys-fs-binfmt_misc.automount printer.target usb-gadget.target systemd-coredump.socket 2>/dev/null || true

cat > /etc/apt/apt.conf.d/99-hardening << 'EOF'
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::AutoRemove::RecommendsImportant "false";
APT::AutoRemove::SuggestsImportant "false";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "0";
APT::Sandbox::Seccomp "true";
EOF

# FIREWALL
apt purge -y ufw gufw nftables
apt install -y iptables iptables-persistent netfilter-persistent
systemctl enable netfilter-persistent
service netfilter-persistent start
iptables -F
iptables -X
iptables -Z
iptables -t nat -F
iptables -t nat -X
iptables -t nat -Z
iptables -t mangle -F
iptables -t mangle -X
iptables -t mangle -Z
iptables -N UDP
iptables -N TCP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -j DROP
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
iptables-save   > /etc/iptables/rules.v4
ip6tables-save  > /etc/iptables/rules.v6
netfilter-persistent save

# PACKAGE REMOVAL/RESTRICTING
apt purge -y anacron* cron* pp* perl python3 zram* pci* pmount* cron* avahi* bc bind9* dns* fastfetch fonts-noto* fprint* dhcp* lxc* docker* podman* xen* bochs* uml* vagrant* ssh* openssh* libssh* usb* acpi* samba* winbind* qemu* libvirt* virt* avahi* cup* print* rsync* nftables* virtual* sane* rpc* bind* nfs* blue* spee* espeak* mobile* wireless* inet* util-linux-locales tasksel* vim* os-prober* netcat* gcc g++ gdb lldb strace* ltrace* build-essential automake autoconf libtool cmake ninja-build meson traceroute libavahi* libcup* dhcp*

install -d /etc/apt/preferences.d
cat >/etc/apt/preferences.d/deny.pref <<'EOF'
mkdir -p /etc/apt/preferences.d

cat > /etc/apt/preferences.d/deny-dangerous.pref << 'EOF'
# Block installation of dangerous packages
Package: gcc g++ gdb lldb strace ltrace
Pin: release *
Pin-Priority: -1

Package: netcat netcat-openbsd netcat-traditional ncat nc socat
Pin: release *
Pin-Priority: -1

Package: nmap masscan hping3 fping
Pin: release *
Pin-Priority: -1

Package: perl ruby lua* tcl
Pin: release *
Pin-Priority: -1

Package: openssh-server openssh-client
Pin: release *
Pin-Priority: -1

Package: docker* podman* lxc* lxd* containerd*
Pin: release *
Pin-Priority: -1

Package: qemu* libvirt* virt-manager
Pin: release *
Pin-Priority: -1

Package: aircrack-ng hydra john hashcat metasploit* burpsuite nikto sqlmap wireshark*
Pin: release *
Pin-Priority: -1

Package: telnet telnetd rsh-client ftp tftp
Pin: release *
Pin-Priority: -1

Package: build-essential automake autoconf libtool cmake make meson ninja-build
Pin: release *
Pin-Priority: -1
EOF

# PACKAGE INSTALLATION
apt install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra pamu2fcfg libpam-u2f rsyslog chrony libpam-tmpdir rkhunter chkrootkit debsums alsa-utils pavucontrol pipewire pipewire-audio-client-libraries pipewire-pulse wireplumber lynis unhide fonts-liberation opensnitch python3-opensnitch* libxfce4ui-utils xfce4-panel xfce4-session xfce4-settings xfce4-terminal xfconf xfdesktop4 xfwm4 xinit xserver-xorg xserver-xorg-legacy xfce4-pulseaudio-plugin xfce4-whiskermenu-plugin timeshift gnome-terminal gnome-brave-icon-theme breeze-gtk-theme bibata-cursor-theme labwc swaybg

# apt install plasma-desktop sddm gdm3 gnome-shell gnome-session 

# PAM/U2F
# Generate U2F key for primary user
if [[ ! -f /etc/security/u2f_keys ]]; then
    echo "Please insert YubiKey and press enter..."
    read -r
    pamu2fcfg -u "$PRIMARY_USER" > /etc/security/u2f_keys
fi

chmod 0400 /etc/security/u2f_keys
chown root:root /etc/security/u2f_keys

# Setup faillock directory
mkdir -p /var/log/faillock
chmod 0700 /var/log/faillock

# Remove dangerous PAM files
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

# Set PAM permissions
chmod 644 /etc/pam.d/*
chown root:root /etc/pam.d/*

# SUDO
cat >/etc/sudoers <<'EOF'
Defaults env_reset
Defaults always_set_home
Defaults timestamp_timeout=0
Defaults passwd_timeout=0
Defaults passwd_tries=2
Defaults use_pty
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults logfile="/var/log/sudo.log"
Defaults log_input,log_output
Defaults editor=/bin/false
Defaults !env_editor
Defaults !visiblepw
Defaults lecture=always
dev  ALL=(ALL) /usr/sbin/, /usr/bin/
EOF

chmod 440 /etc/sudoers
chown root:root /etc/sudoers

# Lock down sudoers.d
rm -rf /etc/sudoers.d/*
cat > /etc/sudoers.d/.placeholder << 'EOF'
# This directory is intentionally empty
# All sudo rules must be in /etc/sudoers
EOF
chmod 0440 /etc/sudoers.d/.placeholder
chmod 0750 /etc/sudoers.d

# MISC HARDENING
cat >/etc/shells <<'EOF'
/bin/bash
EOF

cat >/etc/host.conf <<'EOF'
multi on
order hosts
EOF

cat > /etc/security/limits.d/hardening.conf << 'EOF'
# Root limits
root             -       nofile          65536
root             -       nproc           4096
root             -       memlock         unlimited

# Core dumps disabled
*                soft    core            0
*                hard    core            0

# Default user limits
*                soft    nofile          1024
*                hard    nofile          4096
*                soft    nproc           256
*                hard    nproc           512
*                soft    memlock         65536
*                hard    memlock         131072
*                -       maxlogins       1
*                -       maxsyslogins    1
*                soft    priority        0
*                hard    priority        0
*                -       rtprio          0
*                -       nice            0

# Primary user limits (more permissive)
dev              -       maxlogins       2
dev              -       maxsyslogins    2
dev              soft    nofile          4096
dev              hard    nofile          8192
dev              soft    nproc           1024
dev              hard    nproc           2048
dev              soft    memlock         131072
dev              hard    memlock         262144
EOF

chmod 644 /etc/security/limits.d/hardening.conf

mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs
sed -i 's/^UID_MIN.*/UID_MIN 1000/' /etc/login.defs
sed -i 's/^UID_MAX.*/UID_MAX 60000/' /etc/login.defs
sed -i 's/^GID_MIN.*/GID_MIN 1000/' /etc/login.defs
sed -i 's/^GID_MAX.*/GID_MAX 60000/' /etc/login.defs

# Set restrictive umask
grep -q "^UMASK.*077" /etc/login.defs || echo "UMASK 077" >> /etc/login.defs

# Default shell for new users
sed -i 's|^SHELL=.*|SHELL=/usr/sbin/nologin|' /etc/default/useradd
sed -i 's|^DSHELL=.*|DSHELL=/usr/sbin/nologin|' /etc/adduser.conf

# Umask in profile/bashrc
grep -q "umask 077" /etc/profile || echo "umask 077" >> /etc/profile
grep -q "umask 077" /etc/bash.bashrc || echo "umask 077" >> /etc/bash.bashrc


echo "ALL: LOCAL, 127.0.0.1" > /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny


cat > /etc/security/access.conf << 'EOF'
# Allow dev on local TTYs and pts (GUI terminals)
+:dev:tty1 tty2 tty3 tty4 tty5 tty6
+:dev:LOCAL

# Deny root everywhere
-:root:ALL

# Deny everyone else
-:ALL:ALL
EOF

chmod 644 /etc/security/access.conf

# GRUB 
GRUB_CMDLINE='slab_nomerge slab_debug=FZ init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on vsyscall=none pti=on debugfs=off kfence.sample_interval=100 efi_pstore.pstore_disable=1 iommu.strict=1 iommu=force amd_iommu=force_isolation intel_iommu=on efi=disable_early_pci_dma random.trust_bootloader=off random.trust_cpu=off extra_latent_entropy vdso32=0 page_alloc.shuffle=1 mitigations=auto,nosmt nosmt=force spectre_v2=on spectre_bhi=on spec_store_bypass_disable=on ssbd=force-on l1tf=full,force kvm-intel.vmentry_l1d_flush=always mds=full,nosmt tsx=off tsx_async_abort=full,nosmt retbleed=auto,nosmt kvm.nx_huge_pages=force l1d_flush=on mmio_stale_data=full,nosmt reg_file_data_sampling=on gather_data_sampling=force module.sig_enforce=1 lockdown=confidentiality ipv6.disable=1 loglevel=0 quiet apparmor=1 security=apparmor audit=1'

sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${GRUB_CMDLINE}\"|" /etc/default/grub

update-grub

chmod 640 /etc/default/grub
chown root:root /etc/default/grub

# SYSCTL 
rm -f /etc/sysctl.d/*.conf 2>/dev/null || true

cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# Kernel hardening
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1
kernel.yama.ptrace_scope = 3
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.suid_dumpable = 0
kernel.core_pattern = |/bin/false
kernel.io_uring_disabled = 2
kernel.randomize_va_space = 2
kernel.panic_on_oops = 1
kernel.ctrl-alt-del = 0
kernel.perf_event_paranoid = 3
kernel.perf_cpu_time_max_percent = 1
kernel.perf_event_max_sample_rate = 1

# Memory
vm.max_map_count = 1048576
vm.mmap_min_addr = 65536
vm.oom_kill_allocating_task = 1
vm.panic_on_oom = 1
vm.overcommit_memory = 2
vm.overcommit_ratio = 100
vm.swappiness = 1
vm.unprivileged_userfaultfd = 0

# Filesystem
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 2

# IPv4 hardening
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
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_invalid_ratelimit = 500
net.ipv4.tcp_rfc1337 = 1
net.ipv4.ip_forward = 0

# IPv6 disabled
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Network buffers
net.core.netdev_max_backlog = 65535
net.core.somaxconn = 65535
net.core.rmem_max = 6291456
net.core.wmem_max = 6291456
net.core.optmem_max = 65535

# BPF hardening
net.core.bpf_jit_enable = 0
net.core.bpf_jit_harden = 2

# Misc
kernel.unprivileged_userns_clone = 0
dev.tty.legacy_tiocsti = 0
dev.tty.ldisc_autoload = 0
EOF

sysctl --system

# MODULES
cat > /etc/modprobe.d/harden.conf << 'EOF'

cat > /etc/modprobe.d/hardening-blacklist.conf << 'EOF'
# Wireless (not needed - wired only)
blacklist cfg80211
blacklist mac80211
blacklist iwlwifi
blacklist iwlmvm
blacklist iwldvm
blacklist ath9k
blacklist ath9k_htc
blacklist ath10k_pci
blacklist ath10k_sdio
blacklist ath10k_usb
blacklist ath11k
blacklist ath11k_pci
blacklist ath6kl_sdio
blacklist ath6kl_usb
blacklist brcmsmac
blacklist brcmfmac
blacklist mt76
blacklist mt76_usb
blacklist mt76x0u
blacklist mt76x2u
blacklist mt7601u
blacklist mt7615e
blacklist mt7921e
blacklist rtl8188ee
blacklist rtl8192ce
blacklist rtl8192cu
blacklist rtl8192de
blacklist rtl8192se
blacklist rtl8723ae
blacklist rtl8723be
blacklist rtl8821ae
blacklist rtl88x2bu
blacklist rtl8xxxu
install cfg80211 /bin/false
install mac80211 /bin/false
install iwlwifi /bin/false

# Bluetooth
blacklist bluetooth
blacklist btbcm
blacklist btintel
blacklist btusb
blacklist btrtl
install bluetooth /bin/false

# Firewire
blacklist firewire-core
blacklist firewire-ohci
install firewire-core /bin/false

# Thunderbolt (attack surface)
blacklist thunderbolt
install thunderbolt /bin/false

# Virtualization
blacklist kvm
blacklist kvm_amd
blacklist kvm_intel
blacklist vboxdrv
blacklist vboxnetadp
blacklist vboxnetflt
blacklist vmmon
blacklist vmw_vmci
blacklist vhost
blacklist vhost_net
blacklist vhost_vsock
install kvm /bin/false
install vboxdrv /bin/false

# Uncommon filesystems
blacklist cramfs
blacklist freevxfs
blacklist hfs
blacklist hfsplus
blacklist jffs2
blacklist jfs
blacklist gfs2
blacklist reiserfs
blacklist squashfs
blacklist udf
install cramfs /bin/false
install squashfs /bin/false

# Uncommon network protocols
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
blacklist atm
blacklist ax25
blacklist netrom
blacklist x25
blacklist rose
blacklist decnet
blacklist econet
blacklist af_802154
blacklist ipx
blacklist p8022
blacklist p8023
blacklist psnap
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false

# USB storage (optional - uncomment if you need USB drives)
# blacklist usb_storage
# blacklist uas
# install usb_storage /bin/false

# Webcam
blacklist uvcvideo
install uvcvideo /bin/false

# Intel ME
blacklist mei
blacklist mei_me
blacklist mei_hdcp
blacklist mei_pxp
install mei /bin/false
install mei_me /bin/false

# Misc hardware
blacklist floppy
blacklist parport
blacklist ppdev
blacklist lp
blacklist joydev
blacklist garmin_gps
blacklist gnss
blacklist gnss-serial
blacklist gnss-usb
blacklist dvb_core
blacklist dvb_usb
blacklist dvb_usb_v2
blacklist r820t
blacklist rtl2830
blacklist rtl2832
blacklist rtl2832_sdr
blacklist video1394
install floppy /bin/false

# IPv6
blacklist ipv6
install ipv6 /bin/false
EOF

# FSTAB 
cp /etc/fstab /etc/fstab.bak

echo "proc     /proc      proc      noatime,nodev,nosuid,noexec,hidepid=2,gid=proc    0 0
tmpfs    /tmp       tmpfs     size=1G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /var/tmp   tmpfs     size=1G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /dev/shm   tmpfs     size=512M,noatime,nodev,nosuid,noexec,mode=1777   0 0
tmpfs    /run       tmpfs     size=512M,noatime,nodev,nosuid,mode=0755          0 0
tmpfs    /home/dev/.cache    tmpfs    size=1G,noatime,nodev,nosuid,noexec,mode=700,uid=1000,gid=1000    0 0" >> /etc/fstab

groupadd -f proc
gpasswd -a root proc

# PERMISSIONS
# Home directories
chmod 700 /root
chown root:root /root
chmod 700 /home/"$PRIMARY_USER"
chown "$PRIMARY_USER":"$PRIMARY_USER" /home/"$PRIMARY_USER"

# Remove world-readable from home
find /home/"$PRIMARY_USER" -type f -exec chmod o-rwx {} \; 2>/dev/null || true
find /home/"$PRIMARY_USER" -type d -exec chmod o-rwx {} \; 2>/dev/null || true

# Authentication files
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chown root:root /etc/shadow
chown root:root /etc/gshadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chown root:root /etc/passwd
chown root:root /etc/group

# Sudoers (already done but ensure)
chmod 440 /etc/sudoers
chown root:root /etc/sudoers

# PAM and security
chmod 644 /etc/pam.d/*
chown root:root /etc/pam.d/*
chmod 600 /etc/security/access.conf
chmod 644 /etc/security/limits.conf
chmod 600 /etc/security/faillock.conf
chown root:root /etc/security/*

# SSH (if directory exists)
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

# Boot directory
chmod 700 /boot
chown root:root /boot
find /boot -type f -name "vmlinuz*" -exec chmod 600 {} \;
find /boot -type f -name "initrd*" -exec chmod 600 {} \;
find /boot -type f -name "System.map*" -exec chmod 600 {} \;
find /boot -type f -name "config-*" -exec chmod 600 {} \;

if [[ -f /boot/grub/grub.cfg ]]; then
    chmod 600 /boot/grub/grub.cfg
    chown root:root /boot/grub/grub.cfg
fi

# Find world-writable files

WORLD_WRITABLE=$(find / -xdev -type f -perm -0002  ! -path "/tmp/*"  ! -path "/var/tmp/*"  ! -path "/proc/*"  ! -path "/sys/*"  ! -path "/run/*"  2>/dev/null || true)

if [[ -n "$WORLD_WRITABLE" ]]; then
    echo "[!] Found world-writable files:"
    echo "$WORLD_WRITABLE"
    echo "[*] Removing world-writable bit..."
    echo "$WORLD_WRITABLE" | xargs -r chmod o-w
fi

# Find unowned files

UNOWNED=$(find / -xdev \( -nouser -o -nogroup \)  ! -path "/proc/*"  ! -path "/sys/*"  2>/dev/null || true)

if [[ -n "$UNOWNED" ]]; then
    echo "[!] Found unowned files (review manually):"
    echo "$UNOWNED"
fi
chown root:adm -R /var/log
chmod -R 0640 /var/log
chmod 0750 /var/log


PACKAGES_TO_PURGE=(
    # Development tools & compilers
    "as86" "autoconf" "automake" "bin86" "binutils" "bison" "byacc"
    "cabal-install" "cargo" "chrpath" "clang" "clang-*" "cmake"
    "cpp" "cpp-*" "default-jdk" "default-jre" "dotnet-sdk-6.0"
    "dotnet-sdk-7.0" "dotnet-sdk-8.0" "dwarfdump" "elfutils" "elixir"
    "elixir*" "erlang" "erlang*" "execstack" "expect" "flex" "fpc"
    "g++" "g++*" "gap*" "gawk" "gcc" "gcc-*" "gdb" "gdb-*"
    "gfortran" "gfortran-*" "ghc" "ghc-*" "golang" "golang-*"
    "golang-go" "guile-*" "hexedit" "hopper*" "ida-*" "java-*"
    "julia" "libtool" "lldb" "lldb-*" "llvm" "llvm-*" "ltrace"
    "lua5.1" "lua5.3" "lua5.4" "lua*" "luajit" "m4" "make" "mawk"
    "maxima*" "meson" "mono-*" "mono-complete" "nasm" "ndisasm"
    "ninja-build" "node" "nodejs" "npm" "objdump" "octave" "octave*"
    "openjdk-*" "patchelf" "perl" "perl-base" "perl-modules"
    "php" "php-*" "php-cli" "php-common" "php*" "pike*" "prelink"
    "python-is-python*" "python2*" "r-base" "r-bash" "r-cran-*"
    "r2*" "racket*" "radare2" "readelf" "ruby" "ruby-*" "ruby-full"
    "rustc" "strace" "swig" "tcl" "tcl-*" "tk" "upx" "upx-ucl"
    "valgrind" "yasm"
    
    # Offensive security / pentesting tools
    "aircrack-ng*" "arping" "arpspoof" "arpwatch" "autopsy" "beef-xss"
    "bettercap" "binwalk" "bvi" "crackmapexec" "dirb" "dsniff"
    "enum4linux" "ettercap-common" "ettercap-graphical" "ettercap*"
    "exiftool" "foremost" "fping" "ftp" "ghidra" "gobuster" "hashcat"
    "hping3" "hydra" "hydra-gtk" "impacket-scripts" "john" "lftp"
    "macchanger" "maltego" "masscan" "medusa" "metagoofil"
    "metasploit-framework" "metasploit*" "mitmproxy" "msfvenom"
    "nbtscan" "nc" "ncat" "ncftp" "netcat" "netcat-*" "netcat-openbsd"
    "netcat-traditional" "nikto" "nmap" "openstego" "outguess"
    "proxychains" "proxychains4" "python3-impacket" "recon-ng"
    "responder" "scapy" "set" "sleuthkit" "smbclient" "smbmap"
    "social-engineer-toolkit" "socat" "spiderfoot" "sqlmap" "sslstrip"
    "steghide" "stegosuite" "tcpdump" "theharvester" "tshark"
    "unicornscan" "volatility" "wfuzz" "wireshark" "wireshark-*"
    "wireshark-gtk" "wireshark-qt" "xxd" "yersinia" "zenmap" "zmap"
    
    # Network services / remote access
    "proftpd-basic" "pure-ftpd" "rsh-client" "rsh-redone-client"
    "telnet" "telnetd" "tftp" "tftp-hpa" "tor" "torsocks" "vsftpd"
    
    # Container runtimes
    "containerd.io" "docker-ce" "docker-ce-cli" "docker.io"
    "flatpak" "lxc" "lxd" "lxd-client" "podman" "snapd"
    
    # Image manipulation (potential stego vectors)
    "ghostscript" "gimp" "imagemagick"
    
    # Alternative shells
    "ash" "busybox" "csh" "dash" "es" "fish" "ksh" "ksh93"
    "mksh" "pdksh" "rc" "sash" "tcsh" "yash" "zsh" "zsh-*"
)

apt purge -y "${PACKAGES_TO_PURGE[@]}" 2>/dev/null || true

apt autoremove -y --purge 2>/dev/null || true

DANGEROUS_BINARY_PATTERNS=(
    # Compilers & build tools
    '/usr/bin/gcc' '/usr/bin/g++' '/usr/bin/cc' '/usr/bin/c++'
    '/usr/bin/as' '/usr/bin/ld' '/usr/bin/ar' '/usr/bin/nm'
    '/usr/bin/make' '/usr/bin/cmake'
    
    # Scripting languages (globs)
    '/usr/bin/perl*'
    '/usr/bin/python' '/usr/bin/python2*'
    '/usr/bin/ruby*' '/usr/bin/irb' '/usr/bin/erb'
    '/usr/bin/lua' '/usr/bin/luac'
    '/usr/bin/node' '/usr/bin/nodejs' '/usr/bin/npm'
    '/usr/bin/php*'
    
    # Debuggers & RE tools
    '/usr/bin/gdb' '/usr/bin/lldb'
    '/usr/bin/strace' '/usr/bin/ltrace'
    '/usr/bin/xxd' '/usr/bin/hexdump'
    '/usr/bin/objdump' '/usr/bin/readelf'
    
    # Network tools
    '/usr/bin/nc' '/usr/bin/ncat' '/usr/bin/netcat'
    '/usr/bin/nmap' '/usr/bin/masscan'
    '/usr/bin/socat'
    '/usr/bin/arp*' '/usr/bin/trace*'
    
    # Privilege escalation vectors
    '/usr/bin/run0' '/usr/bin/su'
    '/usr/bin/sudoedit' '/usr/bin/sudoreplay'
    '/usr/bin/pkexec'
    
    # Alternative shells
    '/bin/sh' '/bin/dash' '/bin/zsh' '/bin/fish'
    '/bin/tcsh' '/bin/csh' '/bin/ksh' '/bin/ksh93'
    '/bin/mksh' '/bin/pdksh' '/bin/ash'
    '/bin/rc' '/bin/es' '/bin/sash' '/bin/yash'
    '/usr/bin/zsh' '/usr/bin/fish' '/usr/bin/tcsh'
    '/usr/bin/csh' '/usr/bin/ksh*'
)

for pattern in "${DANGEROUS_BINARY_PATTERNS[@]}"; do
    # shellcheck disable=SC2086
    rm -f $pattern 2>/dev/null || true
done

# Setup Opensnitch
touch /var/log/opensnitchd.log
chmod 640 /var/log/opensnitchd.log
chown root:adm /var/log/opensnitchd.log

systemctl daemon-reload
systemctl enable opensnitch
systemctl start opensnitch

# Clone and install rules if available
if command -v git &>/dev/null; then
    if [[ ! -d /tmp/Respect-My-Internet ]]; then
        git clone --depth 1 https://github.com/DXC-0/Respect-My-Internet.git /tmp/Respect-My-Internet || true
    fi
    if [[ -d /tmp/Respect-My-Internet ]]; then
        cd /tmp/Respect-My-Internet
        if [[ -x install.sh ]]; then
            chmod +x install.sh
            ./install.sh || true
        fi
        cd /
        rm -rf /tmp/Respect-My-Internet
    fi
fi

systemctl restart opensnitch

# PRIVILEGE ESCALATION HARDENING
echo "" > /etc/securetty
chmod 600 /etc/securetty

# Restrict cron/at to dev only
echo "dev" > /etc/cron.allow
echo "dev" > /etc/at.allow
chmod 600 /etc/cron.allow
chmod 600 /etc/at.allow
echo "" > /etc/cron.deny 2>/dev/null || true
echo "" > /etc/at.deny 2>/dev/null || true


mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/00-deny-all.rules << 'EOF'
// Deny all polkit requests - hardened system
polkit.addRule(function(action, subject) {
    return polkit.Result.NO;
});
EOF

chmod 0644 /etc/polkit-1/rules.d/00-deny-all.rules

# LOCKDOWN
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec chmod a-s {} \; 2>/dev/null || true
chmod u+s /usr/bin/sudo

apt clean
apt autopurge -y

# Remove residual configs
RC_PKGS=$(dpkg -l | grep '^rc' | awk '{print $2}' || true)
if [[ -n "$RC_PKGS" ]]; then
    echo "$RC_PKGS" | xargs apt purge -y
fi

# Authentication
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
chattr +i /etc/adduser.conf 2>/dev/null || true
chattr +i /etc/deluser.conf 2>/dev/null || true

# Network
chattr +i /etc/host.conf 2>/dev/null || true
chattr +i /etc/hosts 2>/dev/null || true
chattr +i /etc/hosts.allow 2>/dev/null || true
chattr +i /etc/hosts.deny 2>/dev/null || true

# Sudo/PAM/Security
chattr +i /etc/sudoers 2>/dev/null || true
chattr -R +i /etc/pam.d 2>/dev/null || true
chattr -R +i /etc/security 2>/dev/null || true

# Sysctl/Modules
chattr -R +i /etc/sysctl.d 2>/dev/null || true
chattr -R +i /etc/modprobe.d 2>/dev/null || true

# Firewall
chattr -R +i /etc/iptables 2>/dev/null || true

# Profile
chattr +i /etc/profile 2>/dev/null || true
chattr +i /etc/bash.bashrc 2>/dev/null || true
chattr +i /root/.bashrc 2>/dev/null || true
chattr +i /home/"$PRIMARY_USER"/.bashrc 2>/dev/null || true

# Cron
chattr +i /etc/cron.allow 2>/dev/null || true
chattr +i /etc/at.allow 2>/dev/null || true

# Polkit
chattr -R +i /etc/polkit-1 2>/dev/null || true

# Other
chattr +i /etc/fstab 2>/dev/null || true
chattr +i /etc/nsswitch.conf 2>/dev/null || true
chattr +i /etc/services 2>/dev/null || true
chattr -R +i /lib/modules 2>/dev/null || true
chattr -R +i /usr 2>/dev/null || true
chattr -R +i /boot 2>/dev/null || true 
chattr -R +i /boot/efi 2>/dev/null || true

echo “HARDENING COMPLETE”
