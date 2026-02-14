#!/bin/bash

#######-DEBIAN-HARDENING-#########

set -euo pipefail
trap 'echo "FATAL: line $LINENO failed (exit $?)" >&2' ERR

# PRE-CONFIG
apt install -y extrepo iptables iptables-persistent netfilter-persistent --no-install-recommends
extrepo enable librewolf 
apt update
apt install -y librewolf --no-install-recommends


# PACKAGE DENY LIST
install -d /etc/apt/preferences.d

# Offensive / pentest tools
cat > /etc/apt/preferences.d/10-deny-offensive.pref << 'EOF'
Package: aircrack-ng* autopsy* beef-xss* bettercap* binwalk* burpsuite* crackmapexec* dirb* dsniff* enum4linux* ettercap* ettercap-common* ettercap-graphical* foremost* fping* gobuster* hashcat* hping3* hydra* hydra-gtk* impacket* impacket-scripts* john* macchanger* maltego* masscan* medusa* metagoofil* metasploit* metasploit-framework* mitmproxy* nbtscan* nikto* nmap* opensteg* openstego* outguess* radare2* recon-ng* responder* scalpel* scapy* sleuthkit* smbclient* smbmap* social-engineer* social-engineer-toolkit* spiderfoot* sqlmap* sslstrip* steghide* stegosuite* theharvester* tshark* unicornscan* volatility* wfuzz* wireshark* wireshark-gtk* wireshark-qt* yersinia* zenmap* zmap*
Pin: release *
Pin-Priority: -1
EOF

# Remote access / network services
cat > /etc/apt/preferences.d/20-deny-remote.pref << 'EOF'
Package: openssh* dropbear* tinyssh* telnet* telnetd* rsh* rsh-client* rsh-redone-client* rlogin* x11vnc* xrdp* tigervnc* openvpn* proxychains* proxychains4* apache2* nginx* lighttpd* proftpd* proftpd-basic* vsftpd* pure-ftpd* postfix* sendmail* exim4* courier* xinetd* webmin* cockpit* mosquitto*
Pin: release *
Pin-Priority: -1
EOF

# Dev toolchains / compilers / interpreters
cat > /etc/apt/preferences.d/30-deny-dev.pref << 'EOF'
Package: build-essential* gcc* g++* gfortran* gdb* binutils* autoconf* automake* bison* flex* cmake* make* m4* libtool* clang* llvm* lldb* nasm* cargo* rustc* golang* golang-go* default-jdk* default-jre* nodejs* npm* ruby* ruby-full* perl* php* php-cli* php-common* lua* luajit* python-is-python3* python3-pip* python-pip* pipx* cabal* cabal-install* ghc* fpc* erlang* elixir* julia* mono-complete* dotnet* dotnet-sdk-6.0* dotnet-sdk-7.0* dotnet-sdk-8.0* r-base* octave* meson* ninja-build* swig* cpan* composer*
Pin: release *
Pin-Priority: -1
EOF

# Containers / VMs / orchestration
cat > /etc/apt/preferences.d/40-deny-containers.pref << 'EOF'
Package: docker* docker-ce* docker-ce-cli* docker.io* podman* containerd.io* lxc* lxd* lxd-client* qemu* libvirt* vbox* vagrant* snap* snapd* flatpak* kubernetes* kubectl* ansible* chef* puppet* salt-minion* salt-common* terraform*
Pin: release *
Pin-Priority: -1
EOF

# Unwanted network/system tools
cat > /etc/apt/preferences.d/50-deny-network.pref << 'EOF'
Package: avahi* bind9* bluetooth* bluez* cups* dhcpcd* fprint* libfprint* nfs-common* nfs-kernel-server* nftables* rpcbind* rsync* samba* smbd* snmpd* snmptrapd* socat* strace* tcpdump* tftp* tftp-hpa* traceroute* tor* torsocks* wpa-supplicant* wpasupplicant* iw*
Pin: release *
Pin-Priority: -1
EOF

# Unwanted desktop / misc
cat > /etc/apt/preferences.d/60-deny-misc.pref << 'EOF'
Package: anacron* alpine* emacs* espeak* fastfetch* fortune* cowsay* gimp* imagemagick* neofetch* screen* tmux* vim* open-vm-tools* unattended-upgrades* valgrind* bochs* dosbox* spice-vdagent*
Pin: release *
Pin-Priority: -1
EOF

chmod 644 /etc/apt/preferences.d/*.pref

# SERVICES
DISABLE=(
    # Remote access / network services
    "ssh.service" "ssh.socket" "sshd.service"
    "telnet.socket"
    "inetd.service" "xinetd.service"
    "rpcbind.service" "rpcbind.socket" "rpcbind.target"
    "nfs-blkmap.service" "nfs-client.target" "nfs-common.service"
    "nfs-idmapd.service" "nfs-mountd.service" "nfs-server.service"
    "postfix.service" "sendmail.service" "exim4.service"
    "proftpd.service" "vsftpd.service" "pure-ftpd.service"
    "samba.service" "samba-ad-dc.service" "smbd.service" "nmbd.service" "winbind.service"
    "rsync.service"
    "webmin.service"
    "cockpit.service" "cockpit.socket"
    # VNC / RDP / remote desktop
    "x11vnc.service" "xrdp.service" "xrdp.socket" "xrdp-sesman.service"
    "tigervnc.service" "vino-server.service" "gnome-remote-desktop.service"
    # Display managers / GNOME
    "gdm3.service" "gnome-software-service.service"
    # Containers / VMs
    "containerd.service"
    "docker.service" "docker.socket"
    "podman.service" "podman.socket"
    "lxc.service" "lxc-net.service" "lxd.service" "lxd.socket"
    "libvirtd.service" "libvirtd.socket" "libvirtd-admin.socket" "libvirtd-ro.socket"
    "libvirt-guests.service"
    "virtlockd.service" "virtlockd.socket" "virtlogd.service" "virtlogd.socket"
    "qemu-guest-agent.service"
    "machines.target"
    "systemd-nspawn@.service"
    # VirtualBox / VMware / Hyper-V / SPICE
    "vboxadd.service" "vboxadd-service.service" "vboxautostart-service.service"
    "vboxballoonctrl-service.service" "vboxdrv.service" "vboxweb-service.service"
    "vmtoolsd.service" "vmware-tools.service" "vmware-vmblock-fuse.service"
    "open-vm-tools.service"
    "hv-fcopy-daemon.service" "hv-kvp-daemon.service" "hv-vss-daemon.service"
    "hyperv-daemons.service"
    "spice-vdagentd.service" "spice-vdagentd.socket"
    # Bluetooth / wireless / hardware
    "bluetooth.service" "bluetooth.target"
    "ModemManager.service"
    "wpa_supplicant.service"
    "bolt.service"
    "brltty.service"
    "fprintd.service"
    "fwupd.service" "fwupd-refresh.timer"
    "iio-sensor-proxy.service"
    "pcscd.socket"
    "usb-gadget.target" "usbip.service" "usbipd.service"
    "usbmuxd.service" "usbmuxd.socket"
    # Scheduling / maintenance timers
    "anacron.service" "anacron.timer"
    "cron.service"
    "apt-daily.timer" "apt-daily-upgrade.timer"
    "e2scrub_all.timer"
    "man-db.timer"
    "motd-news.timer"
    "unattended-upgrades.service"
    # Cloud / orchestration
    "cloud-init.service" "cloud-init-local.service"
    "cloud-config.service" "cloud-final.service" "cloud-init.target"
    "chef-client.service" "puppet.service" "salt-minion.service"
    "multipassd.service"
    # Storage
    "iscsi.service" "iscsid.service" "iscsid.socket" "open-iscsi.service"
    "lvm2-lvmpolld.service" "lvm2-lvmpolld.socket"
    "multipathd.service"
    "nvmefc-boot-connections.service" "nvmf-autoconnect.service"
    "rbdmap.service"
    "remote-cryptsetup.target" "remote-fs-pre.target" "remote-fs.target"
    # SSSD
    "sssd.service" "sssd.socket"
    "sssd-autofs.socket" "sssd-kcm.socket" "sssd-nss.socket"
    "sssd-pac.socket" "sssd-pam.socket" "sssd-ssh.socket" "sssd-sudo.socket"
    # Auth services
    "krb5-admin-server.service" "krb5-kdc.service"
    "nscd.service" "nslcd.service"
    # SNMP
    "snmpd.service" "snmptrapd.service"
    # Desktop / misc
    "accounts-daemon.service"
    "rtkit-daemon.service"
    "apport.service"
    "avahi-daemon.service" "avahi-daemon.socket"
    "colord.service"
    "cups-browsed.service" "cups.path" "cups.service" "cups.socket"
    "debug-shell.service"
    "geoclue.service"
    "console-getty.service" "getty@ttyS0.service"
    "serial-getty@.service"
    "kerneloops.service"
    "packagekit.service"
    "power-profiles-daemon.service"
    "printer.target"
    "snapd.seeded.service" "snapd.service" "snapd.socket"
    "speech-dispatcher.service"
    "switcheroo-control.service"
    "tracker-extract-3.service" "tracker-miner-fs-3.service"
    "tracker-miner-rss-3.service" "tracker-writeback-3.service"
    "udisks2.service"
    "upower.service"
    "whoopsie.service"
    # Systemd hardening
    "ctrl-alt-del.target"
    "kexec.target" "systemd-kexec.service"
    "proc-sys-fs-binfmt_misc.automount" "proc-sys-fs-binfmt_misc.mount"
    "systemd-binfmt.service"
    "systemd-coredump.socket"
    "systemd-journal-gatewayd.socket" "systemd-journal-remote.socket"
    "systemd-journal-upload.service"
)

for svc in "${DISABLE[@]}"; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true
done

# PACKAGE REMOVAL
REMOVE=(
    # GNOME desktop (replaced by LXQt)
    "gnome-session" "gnome-shell" "gnome-control-center" "gnome-tweaks"
    "gnome-system-monitor" "gnome-settings-daemon" "gnome-shell-extensions"
    "gnome-shell-extension-appindicator" "gnome-shell-extension-caffeine"
    "gnome-shell-extension-manager" "gnome-software" "gnome-remote-desktop"
    "mutter" "mutter-common" "network-manager-gnome"
    "xdg-desktop-portal-gnome" "dbus-x11" "gdm3"
    # Offensive / pentest tools
    "aircrack-ng" "autopsy" "beef-xss" "bettercap" "binwalk" "burpsuite"
    "crackmapexec" "dirb" "dsniff" "enum4linux" "ettercap*" "execstack"
    "exiftool" "foremost" "fping" "ghidra" "gobuster" "hashcat"
    "hping3" "hydra" "hydra-gtk" "impacket-scripts" "john"
    "macchanger" "maltego" "masscan" "medusa" "metagoofil"
    "metasploit-framework" "mitmproxy" "nbtscan" "nikto" "nmap"
    "openstego" "outguess" "radare2" "recon-ng" "responder"
    "scalpel" "scapy" "sleuthkit" "smbmap" "spiderfoot" "sqlmap"
    "steghide" "stegosuite" "theharvester" "tshark" "unicornscan"
    "wfuzz" "wireshark*" "yersinia" "zenmap" "zmap"
    # Remote access / network services
    "openssh-server" "openssh-client" "dropbear*" "tinyssh*" "telnet*"
    "rsh-client" "rsh-redone-client" "rlogin" "x11vnc" "xrdp*"
    "tigervnc*" "openvpn" "proftpd*" "vsftpd" "pure-ftpd"
    "apache2*" "nginx*" "lighttpd*" "postfix*" "sendmail*"
    "exim4*" "courier*" "xinetd" "webmin"
    # Dev toolchains
    "build-essential" "gcc*" "g++*" "gdb*" "binutils" "autoconf"
    "automake" "bison" "flex" "cmake*" "make" "m4" "libtool"
    "clang" "llvm" "lldb*" "nasm" "cargo*" "rustc" "golang*"
    "default-jdk" "default-jre" "nodejs*" "npm*" "ruby*" "perl"
    "php*" "lua*" "python-is-python3" "pip" "pip3" "cabal-install"
    "ghc*" "fpc" "erlang" "elixir" "julia" "mono-complete" "dotnet*"
    "octave" "r-base" "swig" "meson*" "ninja-build"
    # Containers / VMs
    "docker*" "podman*" "containerd*" "lxc*" "lxd*" "qemu*"
    "libvirt*" "vbox*" "snap*" "snapd" "flatpak*" "vagrant*"
    # Misc unwanted
    "anacron" "avahi*" "libavahi*" "bind9*" "cockpit*" "cron*"
    "cups*" "libcup*" "dhcpcd*" "emacs*" "espeak*" "fastfetch*"
    "fortune*" "cowsay*" "gimp*" "imagemagick*" "mosquitto*"
    "neofetch*" "nfs-common" "rpcbind" "rsync" "samba*" "smbd"
    "snmpd*" "socat" "strace" "tmux" "tor*" "traceroute"
    "unattended-upgrades" "valgrind*" "vim*" "wpa-supplicant"
    "bluetooth*" "bluez*" "modemmanager" "open-vm-tools"
    "patchelf" "prelink" "upx" "texlive-base" "texlive-latex-base"
    "fprint*" "libfprint*" "puppet*" "chef*" "ansible*" "salt-minion"
)

apt purge -y "${REMOVE[@]}" 2>/dev/null || true
apt-get autopurge -y
apt-get autoclean -y

# APT HARDENING
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
iptables -P OUTPUT ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -j DROP
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
netfilter-persistent savesave

# PACKAGE INSTALLATION
apt install -y rsyslog labwc swaybg foot apt install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra libpam-tmpdir needrestart acct rkhunter chkrootkit debsum pavucontrol lynis unhide libxfce4ui-utils xfce4-panel xfce4-session xfce4-settings xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulseaudio-plugin xfce4-whiskermenu-plugin gnome-terminal gnome-brave-icon-theme breeze-gtk-theme bibata-cursor-theme dbus-user-session xdg-desktop-portal xdg-desktop-portal-wlr xdg-utils wayland-protocols xwayland qt6-wayland qtwayland5 featherpad lightdm pipewire pipewire-pulse wireplumber mesa-vulkan-drivers mesa-va-drivers firmware-amd-graphics qt6ct opensnitch python3-opensnitch-ui --no-install-recommends

apt install extrepo
extrepo enable librewolf
apt update
apt install -y librewolf --no-install-recommends

# ACCOUNTS/GROUPS
for grp in _ssh bluetooth fax floppy irc kvm voice games; do
    groupdel "$grp" --force 2>/dev/null || true
done

for usr in nobody games irc uucp proxy dhcpcd list news sync man mail lp www-data; do
    userdel "$usr" 2>/dev/null || true
done

for grp in render input video audio tty; do
    adduser dev "$grp" 2>/dev/null || true
done

# USER AUDIT
echo "Accounts with UID 0:" && awk -F: '($3 == 0) {print $1}' /etc/passwd
echo "Duplicate UIDs:" && cut -d: -f3 /etc/passwd | sort | uniq -d
echo "Missing 'x' placeholders:" && awk -F: '$2 != "x" {print $1}' /etc/passwd
awk -F: '($2 == "" ) {print "CRITICAL: Empty password for " $1}' /etc/shadow
awk -F: '($2 ~ /^\$/ && length($2) < 20) {print "WARNING: Weak hash for " $1}' /etc/shadow
find /home -name "authorized_keys" -print -delete 2>/dev/null || true

while IFS= read -r user; do
    usermod -s /usr/sbin/nologin "$user"
done < <(awk -F: -v current_user="dev" '($3 >= 1000 && $1 != current_user && $7 != "/usr/sbin/nologin" && $7 != "/bin/false") {print $1}' /etc/passwd)

# PAM/U2F
pamu2fcfg -u dev > /etc/security/u2f_keys
chmod 0400 /etc/security/u2f_keys
chown root:root /etc/security/u2f_keys
mkdir -p /var/log/faillock
chmod 0700 /var/log/faillock
rm -f /etc/pam.d/remote
rm -f /etc/pam.d/cron

cat > /etc/security/faillock.conf << 'EOF'
deny = 3
unlock_time = 900
fail_interval = 900
silent
EOF

cat > /etc/pam.d/common-auth << 'EOF'
#%PAM-1.0
auth      required    pam_faildelay.so delay=2000000
auth      required    pam_faillock.so preauth
auth      [success=1 default=ignore] pam_u2f.so authfile=/etc/security/u2f_keys
auth      requisite   pam_deny.so
auth      optional    pam_faillock.so authsucc
EOF

cat > /etc/pam.d/common-account << 'EOF'
#%PAM-1.0
account   required    pam_access.so accessfile=/etc/security/access.conf
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
auth      required    pam_securetty.so
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
session   required    pam_limits.so
account   include     common-account
session   required    pam_env.so user_readenv=0
session   optional    pam_systemd.so
session   required    pam_unix.so
EOF

cat > /usr/lib/pam.d/polkit << 'EOF'
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF

chmod 0644 /etc/pam.d/*
chown root:root /etc/pam.d/
passwd -l dev
passwd -l root

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

mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
ProcessSizeMax=0
Storage=none
EOF

sed -i 's|^ENCRYPT_METHOD.*|ENCRYPT_METHOD YESCRYPT|' /etc/login.defs
sed -i 's|^UID_MIN.*|UID_MIN 1000|' /etc/login.defs
sed -i 's|^UID_MAX.*|UID_MAX 60000|' /etc/login.defs
sed -i 's|^PASS_MAX_DAYS.*|PASS_MAX_DAYS   15|' /etc/login.defs
sed -i 's|^PASS_MIN_DAYS.*|PASS_MIN_DAYS   7|' /etc/login.defs
sed -i 's|^CHFN_RESTRICT.*|CHFN_RESTRICT|' /etc/login.defs
sed -i 's|^#TTYGROUP.*|TTYGROUP       tty|' /etc/login.defs
sed -i 's|^LOGIN_RETRIES.*|LOGIN_RETRIES 2|' /etc/login.defs
sed -i 's|^LOG_OK_LOGINS.*|LOG_OK_LOGINS yes|' /etc/login.defs
sed -i 's|^DEFAULT_HOME.*|DEFAULT_HOME no|' /etc/login.defs
sed -i 's|^UMASK.*|UMASK 077|' /etc/login.defs
sed -i 's|^SHELL=.*|SHELL=/bin/false|' /etc/default/useradd
sed -i 's|^# HOME=.*|HOME=/home|' /etc/default/useradd
sed -i 's|^# SKEL=.*|SKEL=|' /etc/default/useradd
sed -i 's|^#DSHELL=.*|DSHELL=/usr/sbin/nologin|' /etc/adduser.conf
sed -i 's|^#DHOME=.*|DHOME=/home|' /etc/adduser.conf
sed -i 's|^#SKEL=/etc/skel.*|SKEL=|' /etc/adduser.conf
sed -i 's|^#DIR_MODE=.*|DIR_MODE=0700|' /etc/adduser.conf
sed -i 's|^#SYS_DIR_MODE=.*|SYS_DIR_MODE=0750|' /etc/adduser.conf
sed -i 's|^#ADD_EXTRA_GROUPS=.*|ADD_EXTRA_GROUPS=0|' /etc/adduser.conf

grep -q "ulimit -c 0" /etc/profile || echo "ulimit -c 0" >> /etc/profile
grep -q "umask 077" /etc/profile || echo "umask 077" >> /etc/profile
grep -q "umask 077" /etc/bash.bashrc || echo "umask 077" >> /etc/bash.bashrc

echo "ALL: LOCAL, 127.0.0.1" > /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny
chmod 0644 /etc/hosts.allow
chmod 0644 /etc/hosts.deny

cat > /etc/security/access.conf << EOF
+:dev:LOCAL
-:ALL EXCEPT dev:LOCAL
-:dev:ALL EXCEPT LOCAL
-:ALL:REMOTE
-:ALL:ALL
EOF
chmod 0644 /etc/security/access.conf

# GRUB
sed -i 's/^#GRUB_DISABLE_OS_PROBER=.*/GRUB_DISABLE_OS_PROBER=true/' /etc/default/grub
sed -i 's/^#GRUB_DISABLE_LINUX_UUID=.*/GRUB_DISABLE_LINUX_UUID=true/' /etc/default/grub
sed -i 's/^#GRUB_DISABLE_RECOVERY=.*/GRUB_DISABLE_RECOVERY=true/' /etc/default/grub
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="quiet splash mitigations=auto spectre_v2=on spec_store_bypass_disable=on amd_iommu=on iommu=pt init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on slab_nomerge vsyscall=none debugfs=off oops=panic ipv6.disable=1 amdgpu.dcdebugmask=0x10 amdgpu.sg_display=0 amdgpu.gfx_off=0"|' /etc/default/grub
update-grub 2>/dev/null || true
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
sysctl --system 2>/dev/null || true

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

if ! grep -q "hidepid=2" /etc/fstab; then
    cat >> /etc/fstab << 'EOF'
proc     /proc      proc      noatime,nodev,nosuid,noexec,hidepid=2,gid=proc    0 0
tmpfs    /tmp       tmpfs     size=8G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /var/tmp   tmpfs     size=4G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /dev/shm   tmpfs     size=2G,noatime,nodev,nosuid,noexec,mode=1777     0 0
tmpfs    /home/dev/.cache    tmpfs    size=2G,noatime,nodev,nosuid,noexec,mode=0700,uid=1000,gid=1000    0 0
EOF
fi

groupadd -f proc
gpasswd -a root proc
gpasswd -a dev proc

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
find /etc/sudoers.d -type f -exec chmod 0000 {} \; 2>/dev/null || true
chmod 0644 /etc/pam.d/*
chown root:root /etc/pam.d/*
chmod 0600 /etc/security/access.conf
chmod 0600 /etc/security/limits.conf
chmod 0600 /etc/security/namespace.conf
chown root:root /etc/security/*
if [[ -d /etc/ssh ]]; then
    chmod -R 0000 /etc/ssh
    chown -R root:root /etc/ssh
fi

chmod 0700 /boot
chown root:root /boot
find /boot -type f -name "vmlinuz*" -exec chmod 0600 {} \; 2>/dev/null || true
find /boot -type f -name "initrd*" -exec chmod 0600 {} \; 2>/dev/null || true
find /boot -type f -name "System.map*" -exec chmod 0600 {} \; 2>/dev/null || true
find /boot -type f -name "config-*" -exec chmod 0600 {} \; 2>/dev/null || true
if [[ -f /boot/grub/grub.cfg ]]; then
    chmod 0600 /boot/grub/grub.cfg
    chown root:root /boot/grub/grub.cfg
fi

find / -xdev \( -path "/tmp" -o -path "/var/tmp" -o -path "/proc" -o -path "/sys" \) -prune \
    -o -type f -perm -0002 -print0 2>/dev/null | xargs -0 -r chmod o-w 2>/dev/null || true

find / -xdev \( -path "/proc" -o -path "/sys" \) -prune \
    -o -type d -perm -0002 ! -perm -1000 -print0 2>/dev/null | xargs -0 -r chmod +t 2>/dev/null || true

find / -xdev \( -path "/proc" -o -path "/sys" -o -path "/dev" \) -prune \
    -o \( -nouser -o -nogroup \) -printf "Orphan found: %p (UID: %U, GID: %G)\n" 2>/dev/null || true
    
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
systemctl enable opensnitchd.service || true
systemctl start opensnitchd.service 2>/dev/null || true

apt install -y git 
git clone --depth 1 https://github.com/DXC-0/Respect-My-Internet.git
cd Respect-My-Internet
chmod +x install.sh
./install.sh
systemctl restart opensnitchd
cd

# POLKIT
mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/50-lxqt-allow.rules << 'EOF'
polkit.addRule(function(action, subject) {
    if (subject.user == "dev") {
        if (action.id == "org.freedesktop.login1.suspend" ||
            action.id == "org.freedesktop.login1.reboot" ||
            action.id == "org.freedesktop.login1.power-off") {
            return polkit.Result.YES;
        }
    }
    return polkit.Result.NO;
});
EOF

# PRIVILEGE ESCALATION HARDENING
echo "" > /etc/securetty
chmod 0400 /etc/securetty

rm -rf /etc/skel* 2>/dev/null || true
rm -rf /etc/dhcp* 2>/dev/null || true
rm -rf /etc/ssh* 2>/dev/null || true
rm -rf /etc/ppp* 2>/dev/null || true
rm -rf /etc/apparmor* 2>/dev/null || true
rm -rf /etc/cron* 2>/dev/null || true
rm -rf /etc/emacs* 2>/dev/null || true
rm -rf /etc/xemacs* 2>/dev/null || true
rm -rf /etc/gai* 2>/dev/null || true
rm -rf /etc/vim* 2>/dev/null || true
rm -rf /etc/wpa* 2>/dev/null || true
rm -rf /etc/manpath* 2>/dev/null || true
rm -rf /etc/libnl* 2>/dev/null || true

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
rm -r /usr/lib/emacs* 2>/dev/null || true
rm -r /usr/lib/gpg* 2>/dev/null || true
rm -r /usr/lib/gvfs* 2>/dev/null || true
rm -r /usr/lib/os-probe* 2>/dev/null || true
rm -r /usr/lib/man-db* 2>/dev/null || true
rm -r /usr/lib/ppp* 2>/dev/null || true
rm -r /usr/lib/gnupg* 2>/dev/null || true
rm -r /usr/lib/systemd/ssh* 2>/dev/null || true
rm -r /usr/lib/systemd/systemd-ssh* 2>/dev/null || true
rm -r /usr/lib/systemd/systemd-socket* 2>/dev/null || true
rm -r /usr/lib/systemd/network/73* 2>/dev/null || true
rm -r /usr/lib/systemd/network/80-container* 2>/dev/null || true
rm -r /usr/lib/systemd/network/80-wifi* 2>/dev/null || true
rm -r /usr/lib/systemd/system-generators/systemd-ssh* 2>/dev/null || true
# Block unwanted device nodes via udev (persistent across reboots)
cat > /etc/udev/rules.d/99-deny-devices.rules << 'EOF'
# Block virtualisation / tunnelling device nodes
KERNEL=="vhost-net",  OPTIONS+="static_node=vhost-net",  ACTION=="add", RUN+="/bin/rm -f /dev/vhost-net"
KERNEL=="vhost-vsock", OPTIONS+="static_node=vhost-vsock", ACTION=="add", RUN+="/bin/rm -f /dev/vhost-vsock"
KERNEL=="vfio*",      ACTION=="add", RUN+="/bin/rm -f /dev/%k"
KERNEL=="ppp",        ACTION=="add", RUN+="/bin/rm -f /dev/ppp"
KERNEL=="fuse",       ACTION=="add", RUN+="/bin/rm -f /dev/fuse"
KERNEL=="snapshot",   ACTION=="add", RUN+="/bin/rm -f /dev/snapshot"
KERNEL=="watchdog*",  ACTION=="add", RUN+="/bin/rm -f /dev/%k"
# Restrict spare TTYs (keep tty1-tty7 for labwc/login)
KERNEL=="tty[89]",          ACTION=="add", RUN+="/bin/rm -f /dev/%k"
KERNEL=="tty[1-6][0-9]",   ACTION=="add", RUN+="/bin/rm -f /dev/%k"
EOF
chmod 0644 /etc/udev/rules.d/99-deny-devices.rules
udevadm control --reload-rules 2>/dev/null || true

# SECURE PATH
SECURE_SUPATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
SECURE_PATH="/usr/local/bin:/usr/bin"
sed -i "s|^ENV_SUPATH.*|ENV_SUPATH      PATH=$SECURE_SUPATH|" /etc/login.defs
sed -i "s|^ENV_PATH.*|ENV_PATH        PATH=$SECURE_PATH|" /etc/login.defs
sed -i "s|PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"|PATH=\"$SECURE_SUPATH\"|g" /etc/profile
sed -i "s|PATH=\"/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games\"|PATH=\"$SECURE_PATH\"|g" /etc/profile
sed -i "s|^PATH=.*|PATH=\"$SECURE_SUPATH\"|" /etc/environment

# SUDO
cat >/etc/sudoers <<'EOF'
Defaults env_reset
Defaults !setenv
Defaults umask=0077
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

Cmnd_Alias FIREWALL = /usr/sbin/iptables -L, /usr/sbin/iptables -S, /usr/sbin/iptables-save
Cmnd_Alias PACKAGES = /usr/bin/apt update, /usr/bin/apt list --upgradable, /usr/bin/apt upgrade
Cmnd_Alias MAINT = /usr/bin/systemctl status *, /usr/bin/journalctl -xe

dev  ALL=(ALL) ALL
#dev ALL=(root) FIREWALL, PACKAGES, MAINT
EOF

chmod 0440 /etc/sudoers
chmod -R 0000 /etc/sudoers.d 2>/dev/null || true

# STRIP CAPABILITIES
STRIP_CAPS=(
"/bin/dash" "/bin/rbash" "/bin/sh" "/usr/bin/7z" "/usr/bin/7za" "/usr/bin/apropos" "/usr/bin/apt" "/usr/bin/apt-cache" "/usr/bin/apt-get" "/usr/bin/ar" "/usr/bin/aria2c" "/usr/bin/arj" "/usr/bin/ash" "/usr/bin/at" "/usr/bin/awk" "/usr/bin/base32" "/usr/bin/base64" "/usr/bin/basenc" "/usr/bin/bash" "/usr/bin/batch" "/usr/bin/bunzip2" "/usr/bin/busctl" "/usr/bin/busybox" "/usr/bin/bzip2" "/usr/bin/cat" "/usr/bin/cmp" "/usr/bin/column" "/usr/bin/comm" "/usr/bin/composer" "/usr/bin/cp" "/usr/bin/cpan" "/usr/bin/cpio" "/usr/bin/crontab" "/usr/bin/csh" "/usr/bin/csplit" "/usr/bin/curl" "/usr/bin/cut" "/usr/bin/cvs" "/usr/bin/dash" "/usr/bin/dd" "/usr/bin/diff" "/usr/bin/dmesg" "/usr/bin/dpkg" "/usr/bin/ed" "/usr/bin/egrep" "/usr/bin/emacs" "/usr/bin/emacsclient" "/usr/bin/env" "/usr/bin/expand" "/usr/bin/fgrep" "/usr/bin/file" "/usr/bin/find" "/usr/bin/fish" "/usr/bin/fmt" "/usr/bin/fold" "/usr/bin/gawk" "/usr/bin/gem" "/usr/bin/git" "/usr/bin/grep" "/usr/bin/gunzip" "/usr/bin/gzip" "/usr/bin/hd" "/usr/bin/head" "/usr/bin/hexdump" "/usr/bin/hg" "/usr/bin/hostnamectl" "/usr/bin/info" "/usr/bin/install" "/usr/bin/ionice" "/usr/bin/joe" "/usr/bin/join" "/usr/bin/journalctl" "/usr/bin/jq" "/usr/bin/ksh" "/usr/bin/less" "/usr/bin/ln" "/usr/bin/loginctl" "/usr/bin/lua" "/usr/bin/lua5.1" "/usr/bin/lua5.3" "/usr/bin/lua5.4" "/usr/bin/man" "/usr/bin/mawk" "/usr/bin/mcedit" "/usr/bin/more" "/usr/bin/most" "/usr/bin/mv" "/usr/bin/mysql" "/usr/bin/nano" "/usr/bin/nawk" "/usr/bin/ne" "/usr/bin/nice" "/usr/bin/nl" "/usr/bin/node" "/usr/bin/nodejs" "/usr/bin/nohup" "/usr/bin/npm" "/usr/bin/od" "/usr/bin/openssl" "/usr/bin/parallel" "/usr/bin/paste" "/usr/bin/pax" "/usr/bin/perl" "/usr/bin/pg" "/usr/bin/php" "/usr/bin/pico" "/usr/bin/pip" "/usr/bin/pip3" "/usr/bin/pr" "/usr/bin/psql" "/usr/bin/python" "/usr/bin/python3" "/usr/bin/red" "/usr/bin/redis-cli" "/usr/bin/resolvectl" "/usr/bin/rev" "/usr/bin/rsync" "/usr/bin/ruby" "/usr/bin/rview" "/usr/bin/rvim" "/usr/bin/scp" "/usr/bin/screen" "/usr/bin/script" "/usr/bin/sed" "/usr/bin/sftp" "/usr/bin/shuf" "/usr/bin/sort" "/usr/bin/split" "/usr/bin/sqlite3" "/usr/bin/ssh" "/usr/bin/ssh-keygen" "/usr/bin/ssh-keyscan" "/usr/bin/strings" "/usr/bin/svn" "/usr/bin/systemctl" "/usr/bin/tac" "/usr/bin/tail" "/usr/bin/tar" "/usr/bin/taskset" "/usr/bin/tclsh" "/usr/bin/tcsh" "/usr/bin/tee" "/usr/bin/time" "/usr/bin/timedatectl" "/usr/bin/timeout" "/usr/bin/tmux" "/usr/bin/tr" "/usr/bin/unexpand" "/usr/bin/uniq" "/usr/bin/unxz" "/usr/bin/unzip" "/usr/bin/vi" "/usr/bin/view" "/usr/bin/vim" "/usr/bin/vim.basic" "/usr/bin/vim.tiny" "/usr/bin/vimdiff" "/usr/bin/watch" "/usr/bin/wc" "/usr/bin/wget" "/usr/bin/whatis" "/usr/bin/wish" "/usr/bin/xargs" "/usr/bin/xmllint" "/usr/bin/xxd" "/usr/bin/xz" "/usr/bin/yarn" "/usr/bin/yelp" "/usr/bin/yq" "/usr/bin/zip" "/usr/bin/zsh" "/usr/sbin/arp" "/usr/sbin/bridge" "/usr/sbin/capsh" "/usr/sbin/chroot" "/usr/sbin/cryptsetup" "/usr/sbin/debugfs" "/usr/sbin/dmsetup" "/usr/sbin/fdisk" "/usr/sbin/gdisk" "/usr/sbin/getcap" "/usr/sbin/ifconfig" "/usr/sbin/ip" "/usr/sbin/ip6tables" "/usr/sbin/iptables" "/usr/sbin/losetup" "/usr/sbin/lvm" "/usr/sbin/lvs" "/usr/sbin/mkfs" "/usr/sbin/mount" "/usr/sbin/netstat" "/usr/sbin/nft" "/usr/sbin/parted" "/usr/sbin/pvs" "/usr/sbin/route" "/usr/sbin/setcap" "/usr/sbin/ss" "/usr/sbin/tc" "/usr/sbin/umount" "/usr/sbin/vgs"
)

ALL_GTFOBINS=(
"7z" "aa-exec" "ab" "agetty" "alpine" "ansible-playbook" "ansible-test" "aoss" "apache2ctl" "apt" "apt-get" "ar" "aria2c" "arj" "arp" "as" "ascii-xfr" "ascii85" "ash" "aspell" "at" "atobm" "awk" "aws" "base32" "base58" "base64" "basenc" "basez" "bash" "batcat" "bc" "bconsole" "bpftrace" "bridge" "bundle" "bundler" "busctl" "busybox" "byebug" "bzip2" "c89" "c99" "cabal" "cancel" "capsh" "cat" "cdist" "certbot" "check_by_ssh" "check_cups" "check_log" "check_memory" "check_raid" "check_ssl_cert" "check_statusfile" "chmod" "choom" "chown" "chroot" "clamscan" "cmp" "cobc" "column" "comm" "composer" "cowsay" "cowthink" "cp" "cpan" "cpio" "cpulimit" "crash" "crontab" "csh" "csplit" "csvtool" "cupsfilter" "curl" "cut" "dash" "date" "dc" "dd" "debugfs" "dialog" "diff" "dig" "distcc" "dmesg" "dmidecode" "dmsetup" "dnf" "docker" "dos2unix" "dosbox" "dotnet" "dpkg" "dstat" "dvips" "easy_install" "eb" "ed" "efax" "elvish" "emacs" "enscript" "env" "eqn" "espeak" "ex" "exiftool" "expand" "expect" "facter" "file" "find" "finger" "fish" "flock" "fmt" "fold" "fping" "ftp" "gawk" "gcc" "gcloud" "gcore" "gdb" "gem" "genie" "genisoimage" "ghc" "ghci" "gimp" "ginsh" "git" "grc" "grep" "gtester" "gzip" "hd" "head" "hexdump" "highlight" "hping3" "iconv" "iftop" "install" "ionice" "ip" "irb" "ispell" "jjs" "joe" "join" "journalctl" "jq" "jrunscript" "jtag" "julia" "knife" "ksh" "ksshell" "ksu" "kubectl" "latex" "latexmk" "ld.so" "ldconfig" "less" "lftp" "links" "ln" "loginctl" "logsave" "look" "lp" "ltrace" "lua" "lualatex" "luatex" "lwp-download" "lwp-request" "mail" "make" "man" "mawk" "minicom" "more" "mosquitto" "mount" "msfconsole" "msgattrib" "msgcat" "msgconv" "msgfilter" "msgmerge" "msguniq" "mtr" "multitime" "mv" "mysql" "nano" "nasm" "nawk" "nc" "ncdu" "ncftp" "neofetch" "nft" "nice" "nl" "nm" "nmap" "node" "nohup" "npm" "nroff" "nsenter" "ntpdate" "octave" "od" "openssl" "openvpn" "openvt" "opkg" "pandoc" "paste" "pax" "pdb" "pdflatex" "pdftex" "perf" "perl" "perlbug" "pexec" "pg" "php" "pic" "pico" "pidstat" "pip" "pkexec" "pkg" "posh" "pr" "pry" "psftp" "psql" "ptx" "puppet" "pwsh" "python" "rake" "rc" "readelf" "red" "redcarpet" "redis" "restic" "rev" "rlogin" "rlwrap" "rpm" "rpmdb" "rpmquery" "rpmverify" "rsync" "rtorrent" "ruby" "run-mailcap" "run-parts" "runscript" "rview" "rvim" "sash" "scanmem" "scp" "screen" "script" "scrot" "sed" "service" "setarch" "setfacl" "setlock" "sftp" "sg" "shuf" "slsh" "smbclient" "snap" "socat" "socket" "soelim" "softlimit" "sort" "split" "sqlite3" "sqlmap" "ss" "ssh" "ssh-agent" "ssh-keygen" "ssh-keyscan" "sshpass" "start-stop-daemon" "stdbuf" "strace" "strings" "su" "sudo" "sysctl" "systemctl" "systemd-resolve" "tac" "tail" "tar" "task" "taskset" "tasksh" "tbl" "tclsh" "tcpdump" "tdbtool" "tee" "telnet" "terraform" "tex" "tftp" "tic" "time" "timedatectl" "timeout" "tmate" "tmux" "top" "torify" "torsocks" "troff" "tshark" "ul" "unexpand" "uniq" "unshare" "unsquashfs" "unzip" "update-alternatives" "uudecode" "uuencode" "vagrant" "valgrind" "varnishncsa" "vi" "view" "vigr" "vim" "vimdiff" "vipw" "virsh" "volatility" "w3m" "wall" "watch" "wc" "wget" "whiptail" "whois" "wireshark" "wish" "xargs" "xdg-user-dir" "xdotool" "xelatex" "xetex" "xmodmap" "xmore" "xpad" "xxd" "xz" "yarn" "yash" "yelp" "yum" "zathura" "zip" "zsh" "zsoelim" "zypper"
)

for interp in "${STRIP_CAPS[@]}"; do
    [[ -f "$interp" ]] && getcap "$interp" &>/dev/null && setcap -r "$interp" 2>/dev/null || true
done

cap_output=$(getcap -r /usr 2>/dev/null | awk '{print $1}' || true)
for binary in $cap_output; do
    cap_basename=$(basename "$binary")
    for gtfo in "${ALL_GTFOBINS[@]}"; do
        if [[ "$cap_basename" == "$gtfo" ]] || [[ "$cap_basename" == "${gtfo}."* ]]; then
            setcap -r "$binary" 2>/dev/null || true
            break
        fi
    done
done

# CREATE PLACEHOLDER BLOCKERS
dangerous_paths=(
"/usr/bin/perl" "/usr/bin/perl5" "/usr/bin/python" "/usr/bin/python2" "/usr/bin/python3"
"/usr/bin/ruby" "/usr/bin/lua" "/usr/bin/lua5.1" "/usr/bin/lua5.3" "/usr/bin/lua5.4"
"/usr/bin/node" "/usr/bin/nodejs" "/usr/bin/php" "/usr/bin/php7" "/usr/bin/php8"
"/usr/bin/awk" "/usr/bin/gawk" "/usr/bin/mawk" "/usr/bin/nawk" "/usr/bin/sed"
"/usr/bin/ed" "/usr/bin/vi" "/usr/bin/vim" "/usr/bin/emacs" "/usr/bin/tar"
"/usr/bin/zip" "/usr/bin/unzip" "/usr/bin/gzip" "/usr/bin/bzip2" "/usr/bin/xz"
"/usr/bin/7z" "/usr/bin/7za" "/usr/bin/curl" "/usr/bin/wget" "/usr/bin/nc"
"/usr/bin/ncat" "/usr/bin/netcat" "/usr/bin/socat" "/usr/bin/telnet" "/usr/bin/ftp"
"/usr/bin/ssh" "/usr/bin/scp" "/usr/bin/sftp" "/usr/bin/rsync" "/usr/bin/dd"
"/usr/bin/xxd" "/usr/bin/od" "/usr/bin/hexdump" "/usr/bin/strings" "/usr/bin/objdump"
"/usr/bin/readelf" "/usr/bin/nm" "/usr/bin/as" "/usr/bin/ld" "/usr/bin/ar"
"/usr/sbin/tcpdump" "/usr/bin/nmap" "/usr/bin/tshark" "/usr/bin/wireshark"
"/usr/bin/msfconsole" "/usr/bin/msfvenom" "/usr/bin/hydra" "/usr/bin/medusa"
"/usr/bin/john" "/usr/bin/hashcat" "/usr/bin/sqlmap" "/usr/bin/nikto"
"/usr/bin/aircrack-ng" "/usr/bin/ettercap" "/usr/bin/bettercap" "/usr/bin/responder"
)

for binary_path in "${dangerous_paths[@]}"; do
    if [[ ! -e "$binary_path" ]]; then
        mkdir -p "$(dirname "$binary_path")"
        touch "$binary_path"
        chmod 000 "$binary_path"
        chattr +i "$binary_path" 2>/dev/null || true
    fi
done

# LOCKDOWN
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec chmod a-s {} \; 2>/dev/null || true
chmod u+s /usr/bin/sudo 2>/dev/null || true

apt clean || true
apt autopurge -y 2>/dev/null || true
RC_PKGS=$(dpkg -l | grep '^rc' | awk '{print $2}' || true)
if [ -n "$RC_PKGS" ]; then
    echo "$RC_PKGS" | xargs apt purge -y 2>/dev/null || true
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
chattr +i /etc/cron.allow 2>/dev/null || true
chattr +i /etc/at.allow 2>/dev/null || true
chattr -R +i /etc/polkit-1 2>/dev/null || true
chattr +i /etc/nsswitch.conf 2>/dev/null || true
chattr +i /etc/ld.so.conf 2>/dev/null || true
chattr -R +i /etc/ld.so.conf.d 2>/dev/null || true
chattr -R +i /etc/X11 2>/dev/null || true
chattr -R +i /lib/modules 2>/dev/null || true
chattr -R +i /boot 2>/dev/null || true
chattr -R +i /usr 2>/dev/null || true

echo "HARDENING COMPLETE"
