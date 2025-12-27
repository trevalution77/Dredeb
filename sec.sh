#!/bin/bash

###############-WARNING-#################
###-THIS THE SHIT THAT KILLED BELUSHI-###
#########-RUN HER LOW AND SLOW-##########

set -euo pipefail

# PRE-CONFIG 
apt install -y extrepo iptables iptables-persistent netfilter-persistent --no-install-recommends
extrepo enable librewolf
apt modernize-sources
apt update
apt install -y librewolf --no-install-recommends

# SYSTEMD HARDENING
systemctl disable --now ssh.service ssh.socket vino-server.service x11vnc.service tigervnc.service xrdp.service xrdp-sesman.service serial-getty@*.service systemd-journal-remote.socket systemd-journal-gatewayd.socket systemd-journal-upload.service cockpit.socket cockpit.service webmin.service nfs-client.target nfs-common.service nfs-mountd.service nfs-server.service rpcbind.socket rpcbind.service iscsid.socket iscsid.service iscsi.service open-iscsi.service nvmf-autoconnect.service nvmefc-boot-connections.service smbd.service nmbd.service samba.service samba-ad-dc.service vsftpd.service proftpd.service pure-ftpd.service sssd.service krb5-kdc.service krb5-admin-server.service nslcd.service nscd.service winbind.service libvirtd.service libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket virtlogd.service virtlogd.socket virtlockd.service virtlockd.socket qemu-guest-agent.service vboxdrv.service vboxballoonctrl-service.service vboxautostart-service.service vboxweb-service.service vmtoolsd.service vmware-vmblock-fuse.service hv-fcopy-daemon.service hv-kvp-daemon.service hv-vss-daemon.service docker.service docker.socket containerd.service podman.socket podman.service lxd.socket lxd.service lxc.service lxc-net.service multipassd.service snmpd.service snmptrapd.service salt-minion.service puppet.service chef-client.service cloud-init.service cloud-init-local.service cloud-config.service cloud-final.service spice-vdagentd.service spice-vdagentd.socket usbmuxd.service ModemManager.service unattended-upgrades wpa_supplicant speech-dispatcher bluez bluetooth.service apport.service avahi-daemon.socket avahi-daemon.service cups-browsed cups.socket cups.path cups.service debug-shell.service accounts-daemon.service colord.service geoclue.service switcheroo-control.service power-profiles-daemon.service bolt.service fwupd.service packagekit.service rtkit-daemon.service iio-sensor-proxy.service apt-daily.timer apt-daily-upgrade.timer man-db.timer e2scrub_all.timer motd-news.timer kerneloops.service anacron.timer anacron.service cron.service rsync.service pcscd.socket udisks2.service fprintd.service systemd-binfmt.service 2>/dev/null || true

systemctl mask ssh.service ssh.socket telnet.socket inetd.service xinetd.service vino-server.service x11vnc.service tigervnc.service xrdp.service xrdp-sesman.service xrdp.socket serial-getty@.service getty@ttyS0.service console-getty.service debug-shell.service systemd-journal-remote.socket systemd-journal-gatewayd.socket systemd-journal-upload.service cockpit.socket cockpit.service webmin.service nfs-client.target nfs-common.service nfs-mountd.service nfs-server.service nfs-blkmap.service nfs-idmapd.service rpcbind.socket rpcbind.service rpcbind.target iscsid.socket iscsid.service iscsi.service open-iscsi.service nvmf-autoconnect.service nvmefc-boot-connections.service smbd.service nmbd.service samba.service samba-ad-dc.service remote-fs.target remote-fs-pre.target remote-cryptsetup.target vsftpd.service proftpd.service pure-ftpd.service sssd.socket sssd-nss.socket sssd-pam.socket sssd-sudo.socket sssd-autofs.socket sssd-ssh.socket sssd-pac.socket sssd-kcm.socket krb5-kdc.service krb5-admin-server.service nslcd.service winbind.service libvirtd.service libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket virtlogd.service virtlogd.socket virtlockd.service virtlockd.socket libvirt-guests.service qemu-guest-agent.service vboxdrv.service vboxballoonctrl-service.service vboxautostart-service.service vboxweb-service.service vboxadd.service vboxadd-service.service vmtoolsd.service vmware-vmblock-fuse.service vmware-tools.service open-vm-tools.service hv-fcopy-daemon.service hv-kvp-daemon.service hv-vss-daemon.service hyperv-daemons.service docker.service docker.socket containerd.service podman.socket podman.service lxd.socket lxd.service lxc.service lxc-net.service systemd-nspawn@.service machines.target multipassd.service snmpd.service snmptrapd.service salt-minion.service puppet.service chef-client.service cloud-init.target cloud-init.service cloud-init-local.service cloud-config.service cloud-final.service spice-vdagentd.service spice-vdagentd.socket usbip.service usbipd.service usbmuxd.service usbmuxd.socket ModemManager.service debug-shell.service ctrl-alt-del.target kexec.target systemd-kexec.service proc-sys-fs-binfmt_misc.mount proc-sys-fs-binfmt_misc.automount printer.target remote-fs.target remote-cryptsetup.target usb-gadget.target systemd-coredump.socket 2>/dev/null || true

cat > /etc/apt/apt.conf.d/99-hardening << 'EOF'
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::AutoRemove::RecommendsImportant "false";
APT::AutoRemove::SuggestsImportant "false";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "0";
APT::Sandbox::Seccomp "true";
EOF

# FIREWALL
apt purge -y nftables
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
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
netfilter-persistent save

# PACKAGE REMOVAL/RESTRICTING
apt purge -y anacron* cron* pp* perl python3 zram* pci* pmount* cron* avahi* bc bind9* dns* fastfetch fonts-noto* fprint* dhcp* lxc* docker* podman* xen* bochs* uml* vagrant* ssh* openssh* libssh* usb* acpi* samba* winbind* qemu* libvirt* virt* avahi* cup* print* rsync* nftables* virtual* sane* rpc* bind* nfs* blue* spee* espeak* mobile* wireless* inet* util-linux-locales tasksel* vim* os-prober* netcat* gcc g++ gdb lldb strace* ltrace* build-essential automake autoconf libtool cmake ninja-build meson traceroute

install -d /etc/apt/preferences.d
cat >/etc/apt/preferences.d/deny.pref <<'EOF'
Package: openssh*
Pin: release *
Pin-Priority: -1

Package: dropbear*
Pin: release *
Pin-Priority: -1

Package: ssh*
Pin: release *
Pin-Priority: -1

Package: tinyssh*
Pin: release *
Pin-Priority: -1

Package: qemu*
Pin: release *
Pin-Priority: -1

Package: libvirt*
Pin: release *
Pin-Priority: -1

Package: uml*
Pin: release *
Pin-Priority: -1

Package: virt*
Pin: release *
Pin-Priority: -1

Package: courier*
Pin: release *
Pin-Priority: -1

Package: dma*
Pin: release *
Pin-Priority: -1

Package: tripwire*
Pin: release *
Pin-Priority: -1

Package: avahi*
Pin: release *
Pin-Priority: -1

#Package: samba*
#Pin: release *
#Pin-Priority: -1

Package: pmount*
Pin: release *
Pin-Priority: -1

Package: sane*
Pin: release *
Pin-Priority: -1

Package: netcat*
Pin: release *
Pin-Priority: -1

Package: os-prober*
Pin: release *
Pin-Priority: -1

Package: blue*
Pin: release *
Pin-Priority: -1

Package: mobile*
Pin: release *
Pin-Priority: -1

Package: rpc*
Pin: release *
Pin-Priority: -1

Package: nfs*
Pin: release *
Pin-Priority: -1

Package: cup*
Pin: release *
Pin-Priority: -1

Package: anacron*
Pin: release *
Pin-Priority: -1

Package: exim*
Pin: release *
Pin-Priority: -1

Package: postfix*
Pin: release *
Pin-Priority: -1

Package: sendmail*
Pin: release *
Pin-Priority: -1

Package: print*
Pin: release *
Pin-Priority: -1

Package: vagrant*
Pin: release *
Pin-Priority: -1

Package: lxc*
Pin: release *
Pin-Priority: -1

Package: docker*
Pin: release *
Pin-Priority: -1

Package: podman*
Pin: release *
Pin-Priority: -1

Package: xen*
Pin: release *
Pin-Priority: -1

Package: bochs*
Pin: release *
Pin-Priority: -1

Package: gnustep*
Pin: release *
Pin-Priority: -1

Package: modemmanager*
Pin: release *
Pin-Priority: -1

Package: wpa*
Pin: release *
Pin-Priority: -1

Package: wireless*
Pin: release *
Pin-Priority: -1

Package: inet*
Pin: release *
Pin-Priority: -1

Package: nftables*
Pin: release *
Pin-Priority: -1

Package: gcc*
Pin: release *
Pin-Priority: -1

Package: g++*
Pin: release *
Pin-Priority: -1

Package: gdb*
Pin: release *
Pin-Priority: -1

Package: lldb*
Pin: release *
Pin-Priority: -1

Package: strace*
Pin: release *
Pin-Priority: -1

Package: ltrace*
Pin: release *
Pin-Priority: -1

Package: build*
Pin: release *
Pin-Priority: -1

Package: automake*
Pin: release *
Pin-Priority: -1

Package: autoconf*
Pin: release *
Pin-Priority: -1

Package: cmake*
Pin: release *
Pin-Priority: -1

Package: nasm*
Pin: release *
Pin-Priority: -1

Package: yasm*
Pin: release *
Pin-Priority: -1

Package: nodejs*
Pin: release *
Pin-Priority: -1

Package: npm*
Pin: release *
Pin-Priority: -1

Package: php*
Pin: release *
Pin-Priority: -1

Package: ruby*
Pin: release *
Pin-Priority: -1

Package: traceroute*
Pin: release *
Pin-Priority: -1

Package: pp*
Pin: release *
Pin-Priority: -1
EOF

# PACKAGE INSTALLATION
apt install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra pamu2fcfg libpam-u2f rsyslog chrony libpam-tmpdir rkhunter chkrootkit debsums unzip patch alsa-utils pavucontrol pipewire pipewire-audio-client-libraries pipewire-pulse wireplumber lynis unhide fonts-liberation opensnitch python3-opensnitch libxfce4ui-utils xfce4-panel xfce4-session xfce4-settings xfce4-terminal xfconf xfdesktop4 xfwm4 xinit xserver-xorg-legacy xfce4-pulseaudio-plugin xfce4-whiskermenu-plugin timeshift gnome-terminal gnome-brave-icon-theme breeze-gtk-theme bibata-cursor-theme

# PAM/U2F
pamu2fcfg -u dev > /etc/security/u2f_keys
chmod 0400 /etc/security/u2f_keys
chown root:root /etc/security/u2f_keys
mkdir -p /var/log/faillock
chmod 0700 /var/log/faillock
rm -f /etc/pam.d/remote
rm -f /etc/pam.d/cron

cat > /etc/security/faillock.conf <<'EOF'
deny = 3
unlock_time = 900
silent
EOF

cat >/etc/pam.d/chfn <<'EOF'
#%PAM-1.0
auth      include    common-auth
account   include    common-account
session   include    common-session
EOF

cat >/etc/pam.d/chpasswd <<'EOF'
#%PAM-1.0
password  include    common-password
EOF

cat >/etc/pam.d/chsh <<'EOF'
#%PAM-1.0
auth      include    common-auth
account   include    common-account
session   include    common-session
EOF

cat > /etc/pam.d/common-auth <<'EOF'
#%PAM-1.0
auth      required   pam_faildelay.so delay=3000000
auth      required   pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth      [success=1 default=ignore] pam_u2f.so authfile=/etc/security/u2f_keys
auth      requisite  pam_deny.so
auth      required   pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
EOF

cat >/etc/pam.d/common-account <<'EOF'
#%PAM-1.0
account   required   pam_access.so accessfile=/etc/security/access.conf
account   required   pam_faillock.so
account   required   pam_nologin.so
EOF

cat >/etc/pam.d/common-password <<'EOF'
#%PAM-1.0
password  requisite  pam_deny.so
EOF

cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session   required   pam_limits.so
session   required   pam_umask.so umask=0077
session   required   pam_env.so readenv=1 user_readenv=0
session   required   pam_unix.so
session   optional   pam_tmpdir.so
session   optional   pam_systemd.so
EOF

cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session   required   pam_limits.so
session   required   pam_umask.so umask=0077
session   required   pam_env.so readenv=1 user_readenv=0
session   required   pam_unix.so
session   optional   pam_tmpdir.so
session   optional   pam_systemd.so
EOF

cat >/etc/pam.d/sudo <<'EOF'
#%PAM-1.0
auth      required   pam_u2f.so authfile=/etc/security/u2f_keys
auth      required   pam_faillock.so preauth silent deny=3 unlock_time=900
account   include    common-account
session   required   pam_limits.so
session   include    common-session
EOF

cat >/etc/pam.d/sudo-i <<'EOF'
#%PAM-1.0
auth      required   pam_u2f.so authfile=/etc/security/u2f_keys
auth      required   pam_faillock.so preauth silent deny=3 unlock_time=900
account   include    common-account
session   required   pam_limits.so
session   include    common-session
EOF

cat >/etc/pam.d/su <<'EOF'
#%PAM-1.0
auth      required   pam_wheel.so use_uid group=wheel deny
auth      required   pam_u2f.so authfile=/etc/security/u2f_keys
auth      include    common-auth
account   include    common-account
session   include    common-session
EOF

cat >/etc/pam.d/su-l <<'EOF'
#%PAM-1.0
auth      required   pam_wheel.so use_uid group=wheel deny
auth      required   pam_u2f.so authfile=/etc/security/u2f_keys
auth      include    common-auth
account   include    common-account
session   include    common-session
EOF

cat >/etc/pam.d/sshd <<'EOF'
#%PAM-1.0
auth      required   pam_deny.so
account   required   pam_deny.so
password  required   pam_deny.so
session   required   pam_deny.so
EOF

cat >/etc/pam.d/other <<'EOF'
#%PAM-1.0
auth      required   pam_deny.so
account   required   pam_deny.so
password  required   pam_deny.so
session   required   pam_deny.so
EOF

cat >/etc/pam.d/login <<'EOF'
#%PAM-1.0
auth      required   pam_securetty.so
auth      required   pam_nologin.so
auth      include    common-auth
account   required   pam_access.so
account   include    common-account
session   required   pam_limits.so
session   include    common-session
EOF

cat >/etc/pam.d/newusers <<'EOF'
#%PAM-1.0
password  include    common-password
EOF

cat >/etc/pam.d/passwd <<'EOF'
#%PAM-1.0
password  include    common-password
EOF

cat >/etc/pam.d/runuser <<'EOF'
#%PAM-1.0
auth      sufficient pam_u2f.so authfile=/etc/security/u2f_keys
session   required   pam_limits.so
session   required   pam_unix.so
EOF

cat >/etc/pam.d/runuser-l <<'EOF'
#%PAM-1.0
auth      include     runuser
session   include     runuser
EOF

# SUDO
cat >/etc/sudoers <<'EOF'
Defaults    env_reset
Defaults    secure_path="/usr/sbin:/usr/bin"
Defaults    always_set_home
Defaults    requiretty
Defaults    use_pty
Defaults    umask=077
Defaults    passwd_timeout=0
Defaults    timestamp_timeout=0
Defaults    passwd_tries=3
Defaults    badpass_message="Access denied"
Defaults    logfile=/var/log/sudo.log
Defaults    log_input
Defaults    log_output
Defaults    iolog_dir=/var/log/sudo-io
Defaults    iolog_file=%{user}/%{command}-%Y%m%d-%H%M%S
Defaults    !env_editor
Defaults    editor=/bin/false

dev ALL=(ALL) ALL
EOF
chmod 0440 /etc/sudoers
chmod -R 0440 /etc/sudoers.d

# MISC HARDENING
cat >/etc/shells <<'EOF'
/bin/bash
EOF

cat >/etc/host.conf <<'EOF'
multi on
order hosts
EOF

cat >/etc/security/limits.d/limits.conf <<'EOF'
*           hard    nproc         2048
*           hard    maxsyslogins  1
dev         hard    maxsyslogins  1
root        hard    maxsyslogins  1
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

cat > /etc/security/access.conf << EOF
+:dev:0 tty1 tty2
-:ALL EXCEPT dev:LOCAL
-:dev:ALL EXCEPT LOCAL
-:ALL EXCEPT dev:tty1 tty2
-:root:ALL
-:ALL:ALL
EOF
chmod 644 /etc/security/access.conf

# GRUB 
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="mitigations=auto,nosmt spectre_v2=on spec_store_bypass_disable=on l1tf=full,force mds=full,nosmt tsx=off tsx_async_abort=full,nosmt mmio_stale_data=full,nosmt retbleed=auto,nosmt srbds=on gather_data_sampling=force reg_file_data_sampling=on intel_iommu=on iommu=force iommu.passthrough=0 iommu.strict=1 efi=disable_early_pci_dma lockdown=confidentiality init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on slab_nomerge vsyscall=none debugfs=off oops=panic module.sig_enforce=1 ipv6.disable=1 nosmt nowatchdog nmi_watchdog=0"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub

# SYSCTL 
rm -rf /usr/lib/sysctl.d
mkdir -p /usr/lib/sysctl.d
cat > /usr/lib/sysctl.d/sysctl.conf << 'EOF'
dev.tty.ldisc_autoload=0
dev.tty.legacy_tiocsti=0
fs.protected_fifos=2
fs.protected_hardlinks=1
fs.protected_regular=2
fs.protected_symlinks=1
fs.suid_dumpable=0
kernel.acct=1
kernel.cap_last_cap=38
kernel.core_pattern=|/bin/false
kernel.core_uses_pid=1
kernel.ctrl-alt-del=0
kernel.dmesg_restrict=1
kernel.io_uring_disabled=2
kernel.kexec_load_disabled=1
kernel.keys.root_maxbytes=25000000
kernel.keys.root_maxkeys=1000000
kernel.kptr_restrict=2
kernel.panic_on_oops=1
kernel.perf_cpu_time_max_percent=1
kernel.perf_event_max_sample_rate=1
kernel.perf_event_paranoid=3
kernel.pid_max=65536
kernel.printk=3 3 3 3
kernel.randomize_va_space=2
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
kernel.unprivileged_userns_clone=0
kernel.watchdog=0
kernel.yama.ptrace_scope=3
net.core.bpf_jit_enable=1
net.core.bpf_jit_harden=2
net.core.default_qdisc=fq
net.core.netdev_max_backlog=65535
net.core.optmem_max=65535
net.core.rmem_max=6291456
net.core.somaxconn=65535
net.core.wmem_max=6291456
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.log_martians=0
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.default.shared_media=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_forward=0
net.ipv4.tcp_abort_on_overflow=1
net.ipv4.tcp_challenge_ack_limit=2147483647
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_invalid_ratelimit=500
net.ipv4.tcp_max_syn_backlog=4096
net.ipv4.tcp_orphan_retries=2
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_syn_retries=2
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_tw_reuse=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
net.netfilter.nf_conntrack_max=2000000
net.netfilter.nf_conntrack_tcp_loose=0
vm.max_map_count=1048576
vm.mmap_min_addr=65536
vm.oom_kill_allocating_task=1
vm.overcommit_memory=1
vm.panic_on_oom=1
vm.swappiness=1
vm.unprivileged_userfaultfd=0
EOF
sysctl --system

# MODULES
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
cp /etc/fstab /etc/fstab.bak

cp /etc/fstab /etc/fstab.bak
BOOT_LINE=$(grep -E '^\s*UUID=.*\s+/boot\s+' /etc/fstab || echo "")
BOOT_EFI_LINE=$(grep -E '^\s*UUID=.*\s+/boot/efi\s+' /etc/fstab || echo "")

if [ -n "$BOOT_LINE" ]; then
    BOOT_UUID=$(echo "$BOOT_LINE" | grep -oP 'UUID=[A-Za-z0-9-]+')
    echo "${BOOT_UUID}    /boot    ext4    noatime,nodev,nosuid,noexec,ro 0 2" >> /etc/fstab
fi
if [ -n "$BOOT_EFI_LINE" ]; then
    BOOT_EFI_UUID=$(echo "$BOOT_EFI_LINE" | grep -oP 'UUID=[A-Za-z0-9-]+')
    echo "${BOOT_EFI_UUID}    /boot/efi    vfat    noatime,nodev,nosuid,noexec,umask=0077,ro 0 2" >> /etc/fstab
fi

cat > /etc/fstab << 'EOF'
/dev/mapper/lvg-root       /              ext4    noatime,nodev,errors=remount-ro    0 1
/dev/mapper/lvg-usr        /usr           ext4    noatime,nodev,ro                   0 2
/dev/mapper/lvg-var        /var           ext4    noatime,nodev,nosuid               0 2
/dev/mapper/lvg-var_log    /var/log       ext4    noatime,nodev,nosuid,noexec        0 2
/dev/mapper/lvg-home       /home          ext4    noatime,nodev,nosuid,noexec        0 2
proc     /proc      proc      noatime,nodev,nosuid,noexec,hidepid=2,gid=proc    0 0
tmpfs    /tmp       tmpfs     size=1G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /var/tmp   tmpfs     size=1G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /dev/shm   tmpfs     size=512M,noatime,nodev,nosuid,noexec,mode=1777   0 0
tmpfs    /run       tmpfs     size=512M,noatime,nodev,nosuid,mode=0755          0 0
tmpfs    /home/dev/.cache    tmpfs    size=1G,noatime,nodev,nosuid,noexec,mode=700,uid=1000,gid=1000    0 0
EOF

groupadd -f proc
gpasswd -a root proc

# PERMISSIONS
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
find /etc/sudoers.d -type f -exec chmod 440 {} \;
chmod 644 /etc/pam.d/*
chown root:root /etc/pam.d/*
chmod 600 /etc/security/access.conf
chmod 600 /etc/security/limits.conf
chmod 600 /etc/security/namespace.conf
chown root:root /etc/security/*
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
find /boot -type f -name "vmlinuz*" -exec chmod 600 {} \;
find /boot -type f -name "initrd*" -exec chmod 600 {} \;
find /boot -type f -name "System.map*" -exec chmod 600 {} \;
find /boot -type f -name "config-*" -exec chmod 600 {} \;
if [[ -f /boot/grub/grub.cfg ]]; then
    chmod 600 /boot/grub/grub.cfg
    chown root:root /boot/grub/grub.cfg
fi

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

UNOWNED=$(find / -xdev \( -nouser -o -nogroup \) \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    2>/dev/null || true)

if [[ -n "$UNOWNED" ]]; then
    echo "[!] Found unowned files (review manually):"
    echo "$UNOWNED"
fi
chown root:adm -R /var/log
chmod -R 0640 /var/log
chmod 0750 /var/log

apt install -y libcap2-bin 2>/dev/null || true

# Remove ALL capabilities from dangerous binaries
# These should never need special privileges
STRIP_CAPS_BINARIES=(
    /usr/bin/perl
    /usr/bin/perl5*
    /usr/bin/python*
    /usr/bin/ruby*
    /usr/bin/lua*
    /usr/bin/node
    /usr/bin/nodejs
    /usr/bin/php*
    /usr/bin/awk
    /usr/bin/gawk
    /usr/bin/mawk
    /usr/bin/nawk
    /usr/bin/sed
    /usr/bin/ed
    /usr/bin/vi
    /usr/bin/vim*
    /usr/bin/nano
    /usr/bin/emacs*
    /usr/bin/tar
    /usr/bin/zip
    /usr/bin/unzip
    /usr/bin/gzip
    /usr/bin/bzip2
    /usr/bin/xz
    /usr/bin/7z*
    /usr/bin/curl
    /usr/bin/wget
    /usr/bin/nc
    /usr/bin/ncat
    /usr/bin/netcat
    /usr/bin/socat
    /usr/bin/telnet
    /usr/bin/ftp
    /usr/bin/ssh
    /usr/bin/scp
    /usr/bin/sftp
    /usr/bin/rsync
    /usr/bin/dd
    /usr/bin/xxd
    /usr/bin/od
    /usr/bin/hexdump
    /usr/bin/strings
    /usr/bin/objdump
    /usr/bin/readelf
    /usr/bin/nm
    /usr/bin/as
    /usr/bin/ld
    /usr/bin/ar
    /usr/sbin/tcpdump
    /usr/sbin/nmap
    /usr/bin/tshark
    /usr/bin/wireshark
)

for bin in "${STRIP_CAPS_BINARIES[@]}"; do
    for f in $bin; do
        if [ -f "$f" ]; then
            setcap -r "$f" 2>/dev/null || true
        fi
    done
done

# Set MINIMAL required capabilities on specific binaries
# ping needs net_raw only
if [ -f /usr/bin/ping ]; then
    setcap cap_net_raw+ep /usr/bin/ping 2>/dev/null || true
fi

# Remove capabilities from network tools entirely
for bin in /usr/bin/traceroute /usr/bin/mtr /usr/sbin/arping; do
    if [ -f "$bin" ]; then
        setcap -r "$bin" 2>/dev/null || true
    fi
done

# Compilers and build tools
COMPILER_PACKAGES=(
    gcc 
    gcc-* 
    g++ 
    g++-* 
    cpp 
    cpp-*
    clang 
    clang-* 
    llvm 
    llvm-*
    gfortran 
    gfortran-*
    rustc 
    cargo
    golang 
    golang-*
    ghc 
    ghc-*
    fpc
    nasm 
    yasm
    as86 
    bin86
    make 
    cmake 
    ninja-build 
    meson
    autoconf 
    automake 
    libtool
    bison 
    flex 
    byacc
    swig
    m4
)

# Interpreters that can execute arbitrary code
INTERPRETER_PACKAGES=(
    perl 
    perl-base 
    perl-modules
    python2* 
    python3* 
    python-is-python*
    ruby 
    ruby-*
    lua* 
    tcl tcl-*
    php* 
    php-*
    nodejs 
    node 
    npm
    openjdk-* 
    default-jdk 
    default-jre 
    java-*
    mono-* 
    libmono-*
    gawk 
    mawk
    guile-*
    pike*
    racket*
    erlang*
    elixir*
    julia
    octave*
    r-base 
    r-cran-*
    maxima*
    gap*
)

# Debuggers and injection tools
DEBUG_INJECT_PACKAGES=(
    gdb 
    gdb-*
    lldb 
    lldb-*
    strace 
    ltrace
    valgrind
    binutils
    elfutils
    patchelf
    execstack
    prelink
    chrpath
    dwarfdump
    objdump
    readelf
    radare2 
    r2*
    ghidra
    ida-*
    hopper*
    nasm 
    ndisasm
    xxd 
    hexedit 
    bvi
    binwalk
    upx 
    upx-ucl
    msfvenom 
    metasploit*
)

# Network injection/sniffing tools
NETWORK_INJECT_PACKAGES=(
    nmap zenmap
    masscan
    netcat 
    netcat-* 
    nc 
    ncat 
    socat
    hping3
    scapy
    ettercap*
    bettercap
    mitmproxy
    sslstrip
    tcpdump
    wireshark* 
    tshark
    dsniff
    arpspoof
    macchanger
    aircrack-ng*
)

echo "Purging compilers..."
for pkg in "${COMPILER_PACKAGES[@]}"; do
    apt purge -y $pkg 2>/dev/null || true
done

echo "Purging interpreters..."
for pkg in "${INTERPRETER_PACKAGES[@]}"; do
    apt purge -y $pkg 2>/dev/null || true
done

echo "Purging debuggers and injection tools..."
for pkg in "${DEBUG_INJECT_PACKAGES[@]}"; do
    apt purge -y $pkg 2>/dev/null || true
done

echo "Purging network injection tools..."
for pkg in "${NETWORK_INJECT_PACKAGES[@]}"; do
    apt purge -y $pkg 2>/dev/null || true
done

apt autoremove -y 2>/dev/null || true

# Remove any remaining binaries that weren't package-managed
DANGEROUS_BINARIES=(
    /usr/bin/gcc 
    /usr/bin/g++
    /usr/bin/cc 
    /usr/bin/c++
    /usr/bin/as 
    /usr/bin/ld 
    /usr/bin/ar 
    /usr/bin/nm
    /usr/bin/make 
    /usr/bin/cmake
    /usr/bin/perl
    /usr/bin/perl5*
    /usr/bin/python
    /usr/bin/python2*
    /usr/bin/python3*
    /usr/bin/ruby
    /usr/bin/irb
    /usr/bin/erb
    /usr/bin/lua 
    /usr/bin/luac
    /usr/bin/node
    /usr/bin/nodejs
    /usr/bin/npm
    /usr/bin/php
    /usr/bin/php-cgi
    /usr/bin/php-fpm
    /usr/bin/gdb 
    /usr/bin/lldb
    /usr/bin/strace
    /usr/bin/ltrace
    /usr/bin/nc 
    /usr/bin/ncat 
    /usr/bin/netcat
    /usr/bin/nmap 
    /usr/bin/masscan
    /usr/bin/socat
    /usr/bin/xxd 
    /usr/bin/hexdump
    /usr/bin/objdump
    /usr/bin/readelf
    /usr/bin/run0
    /usr/bin/su
)

echo "Removing remaining dangerous binaries..."
for bin in "${DANGEROUS_BINARIES[@]}"; do
    for f in $bin; do
        if [ -f "$f" ] && [ ! -L "$f" ]; then
            echo "Removing: $f"
            rm -f "$f" 2>/dev/null || true
        fi
    done
done

echo "[6/9] Compilers and injection tools removed."

# PURGE SHELLS
# Shells to remove
SHELL_PACKAGES=(
    zsh 
    zsh-*
    fish
    tcsh 
    csh
    ksh 
    ksh93  
    mksh 
    pdksh
    dash
    ash 
    busybox
    rc
    es
    sash
    yash
)

for pkg in "${SHELL_PACKAGES[@]}"; do
    apt purge -y $pkg 2>/dev/null || true
done

# Remove shell binaries
SHELL_BINARIES=(
    /bin/sh   
    /bin/dash
    /bin/zsh
    /bin/fish
    /bin/tcsh 
    /bin/csh
    /bin/ksh
    /bin/ksh93 
    /bin/mksh
    /bin/pdksh
    /bin/ash
    /bin/rc
    /bin/es
    /bin/sash
    /bin/yash
    /usr/bin/zsh
    /usr/bin/fish
    /usr/bin/tcsh
    /usr/bin/csh
    /usr/bin/ksh*
)

for shell in "${SHELL_BINARIES[@]}"; do
    if [ -f "$shell" ] && [ "$shell" != "/bin/bash" ]; then
        # Check if it's not bash
        if ! [ "$shell" -ef "/bin/bash" ]; then
            rm -f "$shell" 2>/dev/null || true
        fi
    fi
done

# Ensure /bin/sh points to bash (not dash)
if [ -L /bin/sh ]; then
    rm /bin/sh
fi
ln -sf /bin/bash /bin/sh

chmod 644 /etc/shells
chattr +i /etc/shells

# Ensure all users have bash as shell (except system accounts with nologin)
while IFS=: read -r username _ uid _ _ _ shell; do
    if [ "$uid" -ge 1000 ] && [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
        if [ "$shell" != "/bin/bash" ]; then
            echo "Changing shell for $username from $shell to /bin/bash"
            usermod -s /bin/bash "$username" 2>/dev/null || true
        fi
    fi
done < /etc/passwd

# Create log file with proper permissions
touch /var/log/opensnitchd.log
chmod 640 /var/log/opensnitchd.log

# Enable and start the daemon
systemctl daemon-reload
systemctl enable opensnitch
systemctl start opensnitch

# Install Blocklists
apt install git 
git clone --depth 1 https://github.com/DXC-0/Respect-My-Internet.git
cd Respect-My-Internet
chmod +x install.sh
./install.sh
systemctl restart opensnitch
cd

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
RC_PKGS=$(dpkg -l | grep '^rc' | awk '{print $2}' || true)
[ -n "$RC_PKGS" ] && apt purge -y $RC_PKGS || true

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
chattr -R +i /boot/efi 2>/dev/null || true
echo “HARDENING COMPLETE”
