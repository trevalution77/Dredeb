!/bin/bash

#########-DEBIAN-HARDENING-#########
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
find / -xdev ( -perm -4000 -o -perm -2000 ) -type f --exec chmod a-s {} ; 2>/dev/null || true
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