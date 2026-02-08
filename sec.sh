#!/bin/bash

########----DEBIAN-HARDENING----########

set -euo pipefail

# APT HARDENING
cat > /etc/apt/apt.conf.d/99-hardening << 'EOF'
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

# PACKAGE DENY LIST
install -d /etc/apt/preferences.d
cat >/etc/apt/preferences.d/deny.pref <<'EOF'
Package: 7z* aircrack* alpine* anacron* ansible* aoss* apache* ar aria2c* arj* arp* as ascii* ash aspell* at atobm* autoconf* automake* autopsy* avahi* awk* aws* base32* base58* base64* basenc* basez* batcat* bc* bconsole* beef* bettercap* bind* bind9* binwalk* blue* bluetooth* bluez* bochs* bpf* bridge* build* build-essential* bundle* burp* busctl* byebug* bz* c89* c99* cabal* cancel capsh* cargo* cdist* certbot* check_by_ssh* check_cups* check_log* check_memory* check_raid* check_ssl_cert* check_statusfile* chef* choom* chroot* clam* cmake* cmp* cobc* cockpit* column comm composer* container* courier* cow* cowsay* cpan* cpio* cpulimit* crack* cron* crontab csh* csplit* csv* cup* curl* cut dash* date dc* dd* debug* dhcp* dialog* diff dig* dirb* distcc* dm* dma* dnf* dns* docker* dos2unix* dosbox* dotnet* dropbear* dsniff* dstat* dvips* easy_install* eb ed efax* elf* elixir* elvish* emacs* enscript* enum* enum4linux* env eqn* erlang* espeak* ettercap* ex exif* exim* expect* facter* fastfetch* finger* fish* flatpak* flock* fmt* fold fonts-noto* foremost* fortune* fping* fprint* ftp* fuzz* g++* gcc* gcloud* gcore* gdb* gem* genie* geniso* ghc* ghost* gimp* ginsh* gnustep* gobuster* golang* grc grep gtester gzip* hash* hashcat* hd* head hex* highlight* hping* hydra* iconv* iftop* image* imagemagick* impacket* inet* ionice* irb* ispell* iw* jjs*joe* john* join* jrunscript* jtag* julia* knife* ksh* ksshell* ksu* kube* latex* ld. so* ldconfig* lftp* libfprint* libsql* libssh* libtool* libvirt* lighttpd* links* lldb* ln* loginctl* logsave* look lp* ltrace* lua* lwp* lxc* lxd* macchanger* mail* make* maltego* man* masscan* medusa* meson* metagoofil* metasploit* minicom* mitm* mobile* modem* modemmanager* mono-complete* more mosquit* msg* msguniq* mtr* multitime* mysql* nasm* nawk* nbtscan* nc ncat* ncdu* nct* neofetch* netcat* nfs* nft* nftables* nginx* nice* nikto* ninja* nl nm nmap* node nodejs* nohup* npm* nroff* nsenter* ntpdate* octave* od open-vm* openssh* openssl* opensteg* openvpn* openvt* opkg* os-prober* outguess* pandoc* paste pax* pdb* pdf* perf perlbug pexec* pg php* pic pico* pip pkexec* pkg* pmount* podman* posh* postfix* pp* pr print* proftp* proftpd* proxy* proxychains* pry* psftp* psql* ptx* puppet* pure* pure-ftp* pwsh* qemu* r-base* radar* rake* rc* readelf* recon* red redcarpet* redis* responder* restic* rev rl* rlogin* rpc* rpm* rsh* rsync* rtorrent* ruby* run-mailcap* run-parts* runscript* rust* rview* rvim* samba* sane* sash* scalpel* scan* scp* screen* screenfetch* script* scrot* sed sendmail* service set setarch* setfacl* setlock* sftp* sg* shuf* sleuth* slsh* smb* snap* sniff* snmp* socat socat* social-engineer* socket* soelim* softlimit* sort spee* spice* spiderfoot* split sql* ss* ssh* ssl* sslstrip* stdb* steg* strace* strings* systemd-resolve* tac tail* tar task tasksel* taskset* tasksh* tbl* tcl* tcp* tdbtool* tee telnet* terraform* tex tftp* theharvester* tic tiger* timedatectl* timeout* tinyssh* tk* tmate* tmux* top tor* traceroute* tripwire* troff* tshark* ul uml* unattended* unexpand* unicornscan* uniq* unshare* unsquashfs* update-alternatives* util-linux-locales uuen* vagrant* valgrind* varnish* vbox* vigr* vim* vipw* virsh* virt* vmw* volatil* vsftp* w3m* wall watch* wc webmin* wfuzz* wget* whois* winbind* wireless* wireshark* wish* wpa* wpasupplicant* x11vnc* xargs* xdg-user-dir* xdotool* xelatex* xen* xetex* xinetd* xmod* xmore* xpad* xrdp* xxd* xz* yarn* yash* yasm* yum* zathura* zenmap* zip* zmap* zram* zsh* zsoelim* zypper*
Pin: release *
Pin-Priority: -1
EOF

# SERVICES
systemctl disable --now accounts-daemon.service anacron.service anacron.timer apport.service apt-daily-upgrade.timer apt-daily.timer avahi-daemon.service avahi-daemon.socket bluetooth.service bluez bolt.service chef-client.service cloud-config.service cloud-final.service cloud-init-local.service cloud-init.service cloud-init.target cockpit.service cockpit.socket colord.service console-getty.service containerd.service cron.service ctrl-alt-del.target cups-browsed cups.path cups.service cups.socket debug-shell.service docker.service docker.socket e2scrub_all.timer fprintd.service fwupd.service geoclue.service getty@ttyS0.service hv-fcopy-daemon.service hv-kvp-daemon.service hv-vss-daemon.service hyperv-daemons.service iio-sensor-proxy.service inetd.service iscsi.service iscsid.service iscsid.socket kerneloops.service kexec.target krb5-admin-server.service krb5-kdc.service libvirt-guests.service libvirtd-admin.socket libvirtd-ro.socket libvirtd.service libvirtd.socket lxc-net.service lxc.service lxd.service lxd.socket machines.target man-db.timer ModemManager.service motd-news.timer multipassd.service nfs-blkmap.service nfs-client.target nfs-common.service nfs-idmapd.service nfs-mountd.service nfs-server.service nmbd.service nscd.service nslcd.service nvmefc-boot-connections.service nvmf-autoconnect.service open-iscsi.service open-vm-tools.service packagekit.service pcscd.socket podman.service podman.socket power-profiles-daemon.service printer.target proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.mount proftpd.service puppet.service pure-ftpd.service qemu-guest-agent.service remote-cryptsetup.target remote-fs-pre.target remote-fs.target rpcbind.service rpcbind.socket rpcbind.target rsync.service rtkit-daemon.service salt-minion.service samba-ad-dc.service samba.service serial-getty@.service serial-getty@*.service smbd.service snmpd.service snmptrapd.service speech-dispatcher spice-vdagentd.service spice-vdagentd.socket ssh.service ssh.socket sssd-autofs.socket sssd-kcm.socket sssd-nss.socket sssd-pac.socket sssd-pam.socket sssd-ssh.socket sssd-sudo.socket sssd.service sssd.socket switcheroo-control.service systemd-binfmt.service systemd-coredump.socket systemd-journal-gatewayd.socket systemd-journal-remote.socket systemd-journal-upload.service systemd-kexec.service systemd-nspawn@.service telnet.socket tigervnc.service udisks2.service unattended-upgrades usb-gadget.target usbip.service usbipd.service usbmuxd.service usbmuxd.socket vboxadd-service.service vboxadd.service vboxautostart-service.service vboxballoonctrl-service.service vboxdrv.service vboxweb-service.service vino-server.service virtlockd.service virtlockd.socket virtlogd.service virtlogd.socket vmtoolsd.service vmware-tools.service vmware-vmblock-fuse.service vsftpd.service webmin.service winbind.service wpa_supplicant x11vnc.service xinetd.service xrdp-sesman.service xrdp.service xrdp.socket 2>/dev/null || true

systemctl mask accounts-daemon.service anacron.service anacron.timer apport.service apt-daily-upgrade.timer apt-daily.timer avahi-daemon.service avahi-daemon.socket bluetooth.service bluez bolt.service chef-client.service cloud-config.service cloud-final.service cloud-init-local.service cloud-init.service cloud-init.target cockpit.service cockpit.socket colord.service console-getty.service containerd.service cron.service ctrl-alt-del.target cups-browsed cups.path cups.service cups.socket debug-shell.service docker.service docker.socket e2scrub_all.timer fprintd.service fwupd.service geoclue.service getty@ttyS0.service hv-fcopy-daemon.service hv-kvp-daemon.service hv-vss-daemon.service hyperv-daemons.service iio-sensor-proxy.service inetd.service iscsi.service iscsid.service iscsid.socket kerneloops.service kexec.target krb5-admin-server.service krb5-kdc.service libvirt-guests.service libvirtd-admin.socket libvirtd-ro.socket libvirtd.service libvirtd.socket lxc-net.service lxc.service lxd.service lxd.socket machines.target man-db.timer ModemManager.service motd-news.timer multipassd.service nfs-blkmap.service nfs-client.target nfs-common.service nfs-idmapd.service nfs-mountd.service nfs-server.service nmbd.service nscd.service nslcd.service nvmefc-boot-connections.service nvmf-autoconnect.service open-iscsi.service open-vm-tools.service packagekit.service pcscd.socket podman.service podman.socket power-profiles-daemon.service printer.target proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.mount proftpd.service puppet.service pure-ftpd.service qemu-guest-agent.service remote-cryptsetup.target remote-fs-pre.target remote-fs.target rpcbind.service rpcbind.socket rpcbind.target rsync.service rtkit-daemon.service salt-minion.service samba-ad-dc.service samba.service serial-getty@.service serial-getty@*.service smbd.service snmpd.service snmptrapd.service speech-dispatcher spice-vdagentd.service spice-vdagentd.socket ssh.service ssh.socket sssd-autofs.socket sssd-kcm.socket sssd-nss.socket sssd-pac.socket sssd-pam.socket sssd-ssh.socket sssd-sudo.socket sssd.service sssd.socket switcheroo-control.service systemd-binfmt.service systemd-coredump.socket systemd-journal-gatewayd.socket systemd-journal-remote.socket systemd-journal-upload.service systemd-kexec.service systemd-nspawn@.service telnet.socket tigervnc.service udisks2.service unattended-upgrades usb-gadget.target usbip.service usbipd.service usbmuxd.service usbmuxd.socket vboxadd-service.service vboxadd.service vboxautostart-service.service vboxballoonctrl-service.service vboxdrv.service vboxweb-service.service vino-server.service virtlockd.service virtlockd.socket virtlogd.service virtlogd.socket vmtoolsd.service vmware-tools.service vmware-vmblock-fuse.service vsftpd.service webmin.service winbind.service wpa_supplicant x11vnc.service xinetd.service xrdp-sesman.service xrdp.service xrdp.socket 2>/dev/null || true

# PACKAGE REMOVAL
apt purge -y aircrack* anacron* ansible* apache* at autopsy* avahi* beef* bettercap* bind9* binwalk* blue* build* burp* cargo* chef* cmake* cockpit* container* courier* cowsay* crack* cron* cup* dirb* dns* docker* dropbear* dsniff* emacs* enum4linux* espeak* ettercap* exim* fastfetch* flatpak* foremost* fortune* fping* fprint* ftp* fuzz* gdb* ghc* ghost* gimp* gobuster* golang* hashcat* hping* hydra* imagemagick* impacket* inet* iw* john* libavahi* libcup* libfprint* libsql* libssh* libvirt* lighttpd* lldb* ltrace* lxc* lxd* maltego* masscan* medusa* meson* metasploit* mitm* mobile* modem* mosquit* nasm* nbtscan* ncat* neofetch* netcat* nfs* nginx* nikto* ninja* nmap* nodejs* npm* npm* open-vm* openssh* opensteg* outguess* perl pip podman* postfix* proftp* proxy* puppet* pure-ftp* python3 qemu* radar* recon* rlogin* rpc* rsh* rsync* rust* samba* scalpel* screen* screenfetch* sendmail* sleuth* samba* smb* snap* sniff* snmp* socat* spee* spice* spiderfoot* sql* ssh* sslstrip* steg* strace* tcp* telnet* theharvester* tiger* tinyssh* tmux* tor* traceroute* tshark* unattended* unicornscan* vagrant* valgrind* vbox* vim* virt* vmw* volatil* vsftp* webmin* wfuzz* wireless* wireshark* wpa* x11vnc* xen* xinetd* xrdp* yarn* yasm* zenmap* 2>/dev/null || true

# FIREWALL
apt purge -y nftables 2>/dev/null || true
apt install -y iptables iptables-persistent netfilter-persistent 2>/dev/null || true
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
iptables -N UDP 2>/dev/null || iptables -F UDP
iptables -N TCP 2>/dev/null || iptables -F TCP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP
iptables -A INPUT -p udp -j DROP
iptables -A INPUT -p tcp -j DROP
iptables -A INPUT -j DROP
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
netfilter-persistent save

# PACKAGE INSTALLATION
apt install -y rsyslog libpam-tmpdir sddm featherpad gnome-terminal lxqt-session lxqt-panel lxqt-runner lxqt-globalkeys lxqt-notificationd liblxqt2 lxqt-policykit lxqt-config labwc openbox wayland-protocols xwayland libseat1 seatd qt6wayland qtwayland5 pipewire wireplumber pipewire-pulse qterminal swaybg xfce4-pulseaudio-plugin xinit xserver-xorg xserver-xorg-legacy arc-theme gnome-brave-icon-theme breeze-gtk-theme bibata-cursor-theme librewolf gdebi-core qt5ct qt6ct opensnitch python3-opensnitch-ui extrepo --no-install-recommends 2>/dev/null || true

extrepo enable librewolf
apt update
apt install -y librewolf --no-install-recommends

sudo systemctl enable seatd --now 
sudo systemctl enable sddm


cat > /usr/share/wayland-sessions/lxqt-wayland.desktop << 'EOF'
[Desktop Entry]
Name=LXQt (Wayland)
Exec=labwc -- lxqt-session
Type=Application
DesktopNames=LXQt
EOF

# UNNECESSARY ACCOUNTS/GROUPS
groupdel _ssh --force 2>/dev/null || true
groupdel bluetooth --force 2>/dev/null || true
groupdel nogroup --force 2>/dev/null || true
groupdel fax --force 2>/dev/null || true
groupdel floppy --force 2>/dev/null || true
groupdel irc --force 2>/dev/null || true
groupdel kvm --force 2>/dev/null || true
groupdel voice --force 2>/dev/null || true
groupdel games --force 2>/dev/null || true
userdel nobody 2>/dev/null || true
userdel games 2>/dev/null || true
userdel irc 2>/dev/null || true
userdel proxy 2>/dev/null || true
userdel dhcpd 2>/dev/null || true
userdel list 2>/dev/null || true
userdel news 2>/dev/null || true
userdel sync 2>/dev/null || true
userdel man 2>/dev/null || true
userdel mail 2>/dev/null || true

# USER GROUPS
adduser dev render 2>/dev/null || true
adduser dev input 2>/dev/null || true
adduser dev video 2>/dev/null || true
adduser dev audio 2>/dev/null || true
adduser dev tty 2>/dev/null || true

# PAM/U2F
pamu2fcfg -u dev > /etc/security/u2f_keys
chmod 0400 /etc/security/u2f_keys
chown root:root /etc/security/u2f_keys
mkdir -p /var/log/faillock
chmod 0700 /var/log/faillock
rm -f /etc/pam.d/remote
rm -f /etc/pam.d/cron

cat > /etc/security/faillock.conf << 'EOF'
deny = 3-
unlock_time = 900
fail_interval = 900
silent
EOF

cat > /etc/pam.d/common-auth << 'EOF'
#%PAM-1.0
auth      required    pam_faildelay.so delay=2000000
auth      required    pam_faillock.so preauth silent deny=5 unlock_time=600 fail_interval=900
auth      [success=1 default=ignore] pam_u2f.so authfile=/etc/security/u2f_keys cue
auth      requisite   pam_deny.so
auth      optional    pam_faillock.so authsucc
EOF

cat > /etc/pam.d/common-account << 'EOF'
#%PAM-1.0
account   required    pam_faillock.so
account   required    pam_unix.so
EOF

cat > /etc/pam.d/common-password << 'EOF'
#%PAM-1.0
password  requisite   pam_deny.so
EOF

cat > /etc/pam.d/common-session << 'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
session   required    pam_unix.so
EOF

cat > /etc/pam.d/common-session-noninteractive << 'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
session   required    pam_unix.so
EOF

cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/sudo-i << 'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/su << 'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/su-l << 'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/login << 'EOF'
#%PAM-1.0
auth      requisite   pam_nologin.so
auth      include     common-auth
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

cat > /usr/lib/pam.d/polkit << 'EOF'
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF

chmod 0644 /etc/pam.d/*
chown root:root /etc/pam.d/*

# SUDO
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
chmod -R 0000 /etc/sudoers.d

# MISC HARDENING
cat >/etc/shells <<'EOF'
/bin/bash
EOF

cat >/etc/host.conf <<'EOF'
multi on
order hosts
EOF

cat >/etc/security/limits.d/limits.conf <<'EOF'
*           hard    nproc         512
*            -      maxlogins     1
*            -      maxsyslogins  1
dev         hard    nproc         2048
dev          -      maxlogins     1
dev          -      maxsyslogins  1
root        hard    nproc         65536
root         -      maxlogins     1
root         -      maxsyslogins  1
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
chmod 0644 /etc/hosts.allow
chmod 0644 /etc/hosts.deny

cat > /etc/security/access.conf << EOF
+:dev:LOCAL
-:dev:ALL EXCEPT LOCAL
-:ALL:REMOTE
-:ALL:ALL
EOF
chmod 0644 /etc/security/access.conf

# GRUB
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="quiet splash mitigations=auto spectre_v2=on spec_store_bypass_disable=on amd_iommu=on iommu=pt init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on slab_nomerge vsyscall=none debugfs=off oops=panic ipv6.disable=1 amdgpu.dcdebugmask=0x10 amdgpu.sg_display=0 amdgpu.gfx_off=0"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub

# SYSCTL
rm -rf /usr/lib/sysctl.d
mkdir -p /usr/lib/sysctl.d
cat > /usr/lib/sysctl.d/sysctl.conf << 'EOF'
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1
kernel.yama.ptrace_scope = 2
kernel.sysrq = 4
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
vm.oom_kill_allocating_task = 0
vm.panic_on_oom = 0
vm.overcommit_memory = 1
vm.overcommit_ratio = 50
vm.swappiness = 10
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
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
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
blacklist udf
install udf /bin/false
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
cp /etc/fstab /etc/fstab.bak

echo "proc     /proc      proc      noatime,nodev,nosuid,noexec,hidepid=2,gid=proc    0 0
tmpfs    /tmp       tmpfs     size=4G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /var/tmp   tmpfs     size=2G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /dev/shm   tmpfs     size=1G,noatime,nodev,nosuid,noexec,mode=1777   0 0
tmpfs    /run       tmpfs     size=1G,noatime,nodev,nosuid,mode=0755          0 0
tmpfs    /home/dev/.cache    tmpfs    size=1G,noatime,nodev,nosuid,noexec,mode=0700,uid=1000,gid=1000    0 0" >> /etc/fstab

groupadd -f proc
gpasswd -a root proc

# PERMISSIONS
chmod 0700 /root
chown root:root /root
chmod 0700 /home/dev
chown dev:dev /home/dev

find /home/dev -type f -exec chmod o-rwx {} \; 2>/dev/null || true
find /home/dev -type d -exec chmod o-rwx {} \; 2>/dev/null || true

chmod 0600 /etc/shadow
chmod 0600 /etc/gshadow
chown root:root /etc/shadow
chown root:root /etc/gshadow
chmod 0644 /etc/passwd
chmod 0644 /etc/group
chown root:root /etc/passwd
chown root:root /etc/group
chmod 0440 /etc/sudoers
chown root:root /etc/sudoers
chmod 0000 /etc/sudoers.d
chown root:root /etc/sudoers.d
find /etc/sudoers.d -type f -exec chmod 0440 {} \;
chmod 0644 /etc/pam.d/*
chown root:root /etc/pam.d/*
chmod 0600 /etc/security/access.conf
chmod 0600 /etc/security/limits.conf
chmod 0600 /etc/security/namespace.conf
chown root:root /etc/security/*
if [[ -d /etc/ssh ]]; then
    chmod 0000 /etc/ssh
    chmod 0000 /etc/ssh/*_key 2>/dev/null || true
    chmod 0000 /etc/ssh/*.pub 2>/dev/null || true
    chmod 0000 /etc/ssh/sshd_config 2>/dev/null || true
    chown -R root:root /etc/ssh
fi
chmod 0700 /etc/cron.d 2>/dev/null || true
chmod 0700 /etc/cron.daily 2>/dev/null || true
chmod 0700 /etc/cron.hourly 2>/dev/null || true
chmod 0700 /etc/cron.weekly 2>/dev/null || true
chmod 0700 /etc/cron.monthly 2>/dev/null || true
chmod 0600 /etc/crontab 2>/dev/null || true
if [[ -f /etc/at.deny ]]; then
    chmod 0600 /etc/at.deny
fi
chmod 0700 /boot
chown root:root /boot
find /boot -type f -name "vmlinuz*" -exec chmod 0600 {} \;
find /boot -type f -name "initrd*" -exec chmod 0600 {} \;
find /boot -type f -name "System.map*" -exec chmod 0600 {} \;
find /boot -type f -name "config-*" -exec chmod 0600 {} \;
if [[ -f /boot/grub/grub.cfg ]]; then
    chmod 0600 /boot/grub/grub.cfg
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

# OPENSNITCH 
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

mkdir -p /etc/opensnitchd/rules
chmod 0750 /etc/opensnitchd
chmod 0750 /etc/opensnitchd/rules
touch /var/log/opensnitchd.log
chmod 0640 /var/log/opensnitchd.log

systemctl daemon-reload
systemctl enable opensnitchd.service
systemctl start opensnitchd.service

apt install -y git 
git clone --depth 1 https://github.com/DXC-0/Respect-My-Internet.git
cd Respect-My-Internet
chmod +x install.sh
./install.sh
systemctl restart opensnitchd
cd

# PRIVILEGE ESCALATION HARDENING
echo "" > /etc/securetty
chmod 0600 /etc/securetty

echo "dev" > /etc/cron.allow
echo "dev" > /etc/at.allow
chmod 0600 /etc/cron.allow
chmod 0600 /etc/at.allow
echo "" > /etc/cron.deny 2>/dev/null || true
echo "" > /etc/at.deny 2>/dev/null || true


rm -r /usr/bin/run0 2>/dev/null || true
rm -r /usr/bin/su 2>/dev/null || true
rm -r /usr/bin/sudoreplay 2>/dev/null || true
rm -r /usr/bin/sudoedit 2>/dev/null || true
rm -r /usr/bin/aeehFCc 2>/dev/null || true
rm -r /dev/ng0n1 2>/dev/null || true
rm -r /dev/vhost* 2>/dev/null || true
rm -r /dev/vfio 2>/dev/null || true
rm -r /dev/vhci 2>/dev/null || true
rm -r /dev/ppp 2>/dev/null || true

# LOCKDOWN
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec chmod a-s {} \; 2>/dev/null || true
chmod u+s /usr/bin/sudo

apt clean
apt autopurge -y
RC_PKGS=$(dpkg -l | grep '^rc' | awk '{print $2}' || true)
if [ -n "$RC_PKGS" ]; then
apt purge -y $RC_PKGS 2>/dev/null || true
fi

# IMMUTABLE FLAGS
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
chattr +i /etc/host.conf 2>/dev/null || true
chattr +i /etc/hosts 2>/dev/null || true
chattr +i /etc/hosts.allow 2>/dev/null || true
chattr +i /etc/hosts.deny 2>/dev/null || true
chattr -R +i /etc/default 2>/dev/null || true
chattr -R +i /etc/sudoers 2>/dev/null || true
chattr -R +i /etc/sudoers.d 2>/dev/null || true
chattr -R +i /etc/pam.d 2>/dev/null || true
chattr -R +i /etc/security 2>/dev/null || true
chattr +i /usr/lib/sysctl.d/sysctl.conf 2>/dev/null || true
chattr -R +i /usr/lib/sysctl.d 2>/dev/null || true
chattr -R +i /etc/sysctl.conf 2>/dev/null || true
chattr -R +i /etc/sysctl.d 2>/dev/null || true
chattr -R +i /etc/modprobe.d 2>/dev/null || true
chattr -R +i /etc/iptables 2>/dev/null || true
chattr -R +i /etc/profile 2>/dev/null || true
chattr -R +i /etc/profile.d 2>/dev/null || true
chattr +i /etc/bash.bashrc 2>/dev/null || true
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
chattr -R +i /etc/X11 2>/dev/null || true
chattr -R +i /lib/modules 2>/dev/null || true
chattr -R +i /boot 2>/dev/null || true
chattr -R +i /usr 2>/dev/null || true

echo "HARDENING COMPLETE"
