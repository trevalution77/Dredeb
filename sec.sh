#!/bin/bash

set -euo pipefail

#-------Debian Hardening Script-------#

# ── Configuration ─────────────────────────────────────────────────

HARDEN_USER=“dev”
HARDEN_HOME=”/home/dev”
U2F_AUTHFILE=”/etc/security/conf”
PAM_ORIGIN=“pam://local”
PAM_APPID=“pam://local”
FAILLOCK_DENY=3
FAILLOCK_UNLOCK=900
FAILLOCK_INTERVAL=900
FAILDELAY=2000000
WARN_COUNT=0

# ──────────────────────────────────────────────────────────────────

# ── Color Output ──────────────────────────────────────────────────

RED=’\033[0;31m’
GREEN=’\033[0;32m’
YELLOW=’\033[1;33m’
CYAN=’\033[0;36m’
NC=’\033[0m’

log_info()  { echo -e “${GREEN}[+]${NC} $1”; }
log_warn()  { echo -e “${YELLOW}[!]${NC} $1”; }
log_error() { echo -e “${RED}[x]${NC} $1”; }
log_step()  { echo -e “\n${CYAN}══ $1 ══${NC}”; }

run_cmd() {
local description=”$1”
shift
local stderr_output
if stderr_output=$(”$@” 2>&1 >/dev/null); then
log_info “OK: ${description}”
else
local exit_code=$?
log_warn “Non-fatal failure: ${description} (exit ${exit_code})”
[[ -n “$stderr_output” ]] && echo “         └─ ${stderr_output}” >&2
(( WARN_COUNT++ )) || true
fi
return 0
}

# ──────────────────────────────────────────────────────────────────

# ── Pre-flight Checks ─────────────────────────────────────────────

log_step “PRE-FLIGHT”

[[ $EUID -ne 0 ]] && { log_error “Must be run as root”; exit 1; }

id “$HARDEN_USER” &>/dev/null || {
log_error “User ‘${HARDEN_USER}’ does not exist — create it before running”
exit 1
}

[[ -d “$HARDEN_HOME” ]] || {
log_error “Home directory ${HARDEN_HOME} does not exist”
exit 1
}

lsusb 2>/dev/null | grep -qi “yubico|u2f|fido” ||   
log_warn “No U2F device detected via lsusb — ensure key is inserted before enrollment step”

echo “”
log_warn “═══════════════════════════════════════════════════════════”
log_warn “  DESTRUCTIVE ONE-SHOT OPERATION”
log_warn “  This script locks the system immutably via chattr.”
log_warn “  Post-run changes require external boot media.”
log_warn “  Ensure your YubiKey is inserted and ready.”
log_warn “═══════════════════════════════════════════════════════════”
echo “”
read -rp “  Type YES to continue: “ confirm
[[ “$confirm” != “YES” ]] && { log_info “Aborted by user”; exit 0; }
echo “”

# ──────────────────────────────────────────────────────────────────

# ── Package Lists ─────────────────────────────────────────────────

REMOVE_PKGS=(
“acpi*” “aircrack-ng” “anacron*” “ansible*” “apache2*” “autoconf”
“automake” “autopsy” “avahi*” “bc” “beef-xss” “bettercap” “bind*”
“binutils” “binwalk” “bison” “blue*” “bochs*” “build-essential”
“burpsuite” “cabal-install” “cargo*” “chef*” “clang” “cmake*”
“cockpit*” “containerd*” “courier*” “cowsay*” “crackmapexec” “cron*”
“cup*” “dbus-x11” “default-jdk” “default-jre” “dhcp*” “dirb” “dns*”
“docker*” “dotnet*” “dropbear*” “dsniff” “elixir” “emacs*”
“enum4linux” “erlang” “espeak*” “ettercap*” “execstack” “exiftool”
“exim*” “fastfetch*” “flatpak*” “flex” “fonts-noto*” “foremost”
“fortune*” “fpc” “fping” “fprint*” “g++*” “gcc*” “gdb*” “gdm*”
“ghc*” “ghidra” “gimp*” “gnome-control-center” “gnome-remote-desktop”
“gnome-session” “gnome-settings-daemon” “gnome-shell*” “gnome-software”
“gnome-system-monitor” “gnome-tweaks” “gnustep*” “gobuster*” “golang*”
“hashcat*” “hping3*” “hydra*” “imagemagick*” “impacket-scripts”
“inet*” “john*” “julia*” “libavahi*” “libcup*” “libfprint*” “libssh*”
“libtool*” “libvirt*” “lighttpd*” “lldb*” “llvm*” “ltrace*” “lua*”
“lxc*” “lxd*” “m4*” “macchanger*” “make*” “maltego*” “masscan*”
“medusa*” “meson*” “metagoofil*” “metasploit*” “mitm*” “mobile*”
“modem*” “mono-complete” “mosquitto*” “mutter*” “nasm*” “nbtscan*”
“neofetch*” “netcat*” “network-manager*” “nfs*” “nftables*” “nginx*”
“nikto*” “ninja-build*” “nmap*” “nodejs*” “npm*” “octave*”
“open-vm*” “openssh*” “openssh-client” “openssh-server” “openstego*”
“openvpn*” “os-prober*” “outguess*” “patchelf*” “pci*” “perl”
“php*” “pip*” “pip3*” “pmount*” “podman*” “postfix*” “powertop”
“pp*” “prelink*” “print*” “proftpd*” “puppet*” “pure-ftpd*”
“python-is-python3” “python3” “qemu*” “r-base*” “radare2*” “rbdmap”
“recon*” “responder*” “rlogin*” “rpc*” “rsh-client”
“rsh-redone-client” “rsync*” “ruby*” “rustc” “salt-minion” “samba*”
“sane*” “scalpel” “scapy” “sendmail*” “sleuthkit” “smbd*” “snap*”
“snmpd*” “socat*” “spee*” “spiderfoot*” “sql*” “ssh*” “steg*”
“strace*” “swig” “tasksel*” “tcp*” “telnet*” “texlive*”
“theharvester*” “tigervnc*” “tinyssh*” “tmux*” “tor*” “trace*”
“tshark*” “uml*” “unattended-upgrades*” “unicorn*” “upx*” “usb*”
“util-linux-locales” “vagrant*” “valgrind*” “vbox*” “vim*” “virt*”
“vm*” “vsftp*” “webmin*” “wfuzz*” “winbind*” “wireless*”
“wireshark*” “wpa-supplicant” “x11vnc” “xdg-desktop-portal-gnome”
“xen*” “xinetd*” “xrdp*” “yersinia*” “zenmap” “zmap” “zram*”
# Final purge targets merged here for single pass
“pci*” “pmount*” “acpi*” “anacron*” “avahi*” “bc” “bind9*” “dns*”
“fastfetch” “fonts-noto*” “fprint*” “dhcp*” “lxc*” “docker*”
“podman*” “xen*” “bochs*” “uml*” “vagrant*” “libssh*” “ssh*”
“openssh*” “samba*” “winbind*” “qemu*” “libvirt*” “virt*” “cron*”
“cup*” “print*” “rsync*” “sane*” “rpc*” “nfs*” “blue*” “spee*”
“espeak*” “mobile*” “wireless*” “perl” “git*” “curl” “wget”
“traceroute” “os-prober*” “dictionaries-common” “doc-debian”
“iamerican” “ibritish” “ienglish-common” “inet*” “ispell”
“task-english” “util-linux-locales” “wamerican” “tasksel*” “vim*”
“netcat*” “zram*”
)

INSTALL_PKGS=(
“extrepo” “iptables” “iptables-persistent” “netfilter-persistent”
“rsyslog” “libpam-tmpdir” “libpam-u2f” “lynis” “unhide”
“libxfce4ui-utils” “xfce4-panel” “xfce4-session” “xfce4-settings”
“xfconf” “xfdesktop4” “xfwm4” “xserver-xorg” “xinit”
“xserver-xorg-legacy” “xfce4-pulseaudio-plugin”
“xfce4-whiskermenu-plugin” “qterminal” “breeze-gtk-theme”
“bibata-cursor-theme” “dbus-user-session” “featherpad”
“pipewire” “pipewire-pulse” “wireplumber”
“gstreamer1.0-libav” “gstreamer1.0-plugins-bad”
“qt5ct” “opensnitch” “opensnitch-ebpf-modules”
“python3-opensnitch-ui”
)

SERVICES_TO_DISABLE=(
“accounts-daemon.service” “anacron.service” “anacron.timer”
“apport.service” “apt-daily-upgrade.timer” “apt-daily.timer”
“avahi-daemon.service” “avahi-daemon.socket” “bluetooth.service”
“bluetooth.target” “bolt.service” “brltty.service”
“chef-client.service” “cloud-config.service” “cloud-final.service”
“cloud-init-local.service” “cloud-init.service” “cloud-init.target”
“cockpit.service” “cockpit.socket” “colord.service”
“console-getty.service” “containerd.service” “cron.service”
“ctrl-alt-del.target” “cups-browsed.service” “cups.path”
“cups.service” “cups.socket” “debug-shell.service” “docker.service”
“docker.socket” “e2scrub_all.service” “e2scrub_all.timer”
“e2scrub_reap.service” “e2scrub@.service” “exim4.service”
“factory-reset.target” “fprintd.service” “fwupd-refresh.timer”
“fwupd.service” “gdm3.service” “geoclue.service”
“getty@ttyS0.service” “gnome-remote-desktop.service”
“gnome-software-service.service” “hibernate.target”
“hv-fcopy-daemon.service” “hv-kvp-daemon.service”
“hv-vss-daemon.service” “hybrid-sleep.target”
“hyperv-daemons.service” “iio-sensor-proxy.service” “inetd.service”
“iscsi.service” “iscsid.service” “iscsid.socket”
“kerneloops.service” “kexec.target” “krb5-admin-server.service”
“krb5-kdc.service” “libvirt-guests.service”
“libvirtd-admin.socket” “libvirtd-ro.socket” “libvirtd.service”
“libvirtd.socket” “lvm2-lvmpolld.service” “lvm2-lvmpolld.socket”
“lxc-net.service” “lxc.service” “lxd.service” “lxd.socket”
“machines.target” “man-db.timer” “ModemManager.service”
“motd-news.timer” “multipassd.service” “multipathd.service”
“nfs-blkmap.service” “nfs-client.target” “nfs-common.service”
“nfs-idmapd.service” “nfs-mountd.service” “nfs-server.service”
“nmbd.service” “nscd.service” “nslcd.service”
“nvmefc-boot-connections.service” “nvmf-autoconnect.service”
“open-iscsi.service” “open-vm-tools.service” “packagekit.service”
“pcscd.socket” “podman.service” “podman.socket” “postfix.service”
“power-profiles-daemon.service” “powertop.service” “printer.target”
“proc-sys-fs-binfmt_misc.automount” “proc-sys-fs-binfmt_misc.mount”
“proftpd.service” “puppet.service” “pure-ftpd.service”
“qemu-guest-agent.service” “quotaon-root.service” “quotaon.service”
“rbdmap.service” “rc-local.service” “remote-cryptsetup.target”
“remote-fs-pre.target” “remote-fs.target”
“remote-integritysetup.target” “remote-veritysetup.target”
“rpcbind.service” “rpcbind.socket” “rpcbind.target” “rsync.service”
“rtkit-daemon.service” “salt-minion.service” “samba-ad-dc.service”
“samba.service” “sendmail.service” “serial-getty@.service”
“smbd.service” “snapd.seeded.service” “snapd.service” “snapd.socket”
“snmpd.service” “snmptrapd.service” “speech-dispatcher.service”
“spice-vdagentd.service” “spice-vdagentd.socket” “ssh.service”
“ssh.socket” “sshd.service” “sssd-autofs.socket” “sssd-kcm.socket”
“sssd-nss.socket” “sssd-pac.socket” “sssd-pam.socket”
“sssd-ssh.socket” “sssd-sudo.socket” “sssd.service” “sssd.socket”
“sudo.service” “suspend-then-hibernate.target”
“switcheroo-control.service” “systemd-backlight@.service”
“systemd-binfmt.service” “systemd-coredump.socket”
“systemd-factory-reset-complete.service”
“systemd-factory-reset-reboot.service”
“systemd-factory-reset-request.service” “systemd-firstboot.service”
“systemd-hibernate-clear.service” “systemd-hibernate-resume.service”
“systemd-homed-activate.service” “systemd-homed.service”
“systemd-hostnamed.service” “systemd-hybrid-sleep.service”
“systemd-journal-gatewayd.socket” “systemd-journal-remote.socket”
“systemd-journal-upload.service” “systemd-kexec.service”
“systemd-localed.service” “systemd-network-generator.service”
“systemd-networkd-wait-online.service” “systemd-networkd.service”
“systemd-networkd.socket” “systemd-nspawn@.service”
“systemd-pstore.service” “systemd-quotacheck-root.service”
“systemd-quotacheck@.service” “systemd-rfkill.service”
“systemd-rfkill.socket” “systemd-suspend-then-hibernate.service”
“systemd-timedated.service” “systemd-userdbd.service”
“systemd-userdbd.socket” “telnet.socket” “tigervnc.service”
“tracker-extract-3.service” “tracker-miner-fs-3.service”
“tracker-miner-rss-3.service” “tracker-writeback-3.service”
“udisks2.service” “unattended-upgrades.service” “upower.service”
“usb-gadget.target” “usbip.service” “usbipd.service”
“usbmuxd.service” “usbmuxd.socket” “vboxadd-service.service”
“vboxadd.service” “vboxautostart-service.service”
“vboxballoonctrl-service.service” “vboxdrv.service”
“vboxweb-service.service” “vino-server.service” “virtlockd.service”
“virtlockd.socket” “virtlogd.service” “virtlogd.socket”
“vmtoolsd.service” “vmware-tools.service”
“vmware-vmblock-fuse.service” “vsftpd.service” “webmin.service”
“whoopsie.service” “winbind.service” “wpa_supplicant.service”
“x11vnc.service” “xinetd.service” “xrdp-sesman.service”
“xrdp.service” “xrdp.socket”
)

STRIP_CAPS=(
“/bin/rbash” “/usr/bin/7z” “/usr/bin/7za” “/usr/bin/apropos”
“/usr/bin/apt” “/usr/bin/apt-cache” “/usr/bin/apt-get” “/usr/bin/ar”
“/usr/bin/aria2c” “/usr/bin/arj” “/usr/bin/ash” “/usr/bin/at”
“/usr/bin/awk” “/usr/bin/base32” “/usr/bin/base64” “/usr/bin/basenc”
“/usr/bin/bash” “/usr/bin/batch” “/usr/bin/bunzip2” “/usr/bin/busctl”
“/usr/bin/busybox” “/usr/bin/bzip2” “/usr/bin/cat” “/usr/bin/cmp”
“/usr/bin/column” “/usr/bin/comm” “/usr/bin/composer” “/usr/bin/cp”
“/usr/bin/cpan” “/usr/bin/cpio” “/usr/bin/crontab” “/usr/bin/csh”
“/usr/bin/csplit” “/usr/bin/curl” “/usr/bin/cut” “/usr/bin/cvs”
“/usr/bin/dash” “/usr/bin/dd” “/usr/bin/diff” “/usr/bin/dmesg”
“/usr/bin/ed” “/usr/bin/egrep” “/usr/bin/emacs” “/usr/bin/emacsclient”
“/usr/bin/env” “/usr/bin/expand” “/usr/bin/fgrep” “/usr/bin/file”
“/usr/bin/find” “/usr/bin/fish” “/usr/bin/fmt” “/usr/bin/fold”
“/usr/bin/gawk” “/usr/bin/gem” “/usr/bin/git” “/usr/bin/grep”
“/usr/bin/gunzip” “/usr/bin/gzip” “/usr/bin/hd” “/usr/bin/head”
“/usr/bin/hexdump” “/usr/bin/hg” “/usr/bin/hostnamectl”
“/usr/bin/info” “/usr/bin/install” “/usr/bin/ionice” “/usr/bin/joe”
“/usr/bin/join” “/usr/bin/journalctl” “/usr/bin/jq” “/usr/bin/ksh”
“/usr/bin/less” “/usr/bin/ln” “/usr/bin/loginctl” “/usr/bin/lua”
“/usr/bin/lua5.1” “/usr/bin/lua5.3” “/usr/bin/lua5.4” “/usr/bin/man”
“/usr/bin/mawk” “/usr/bin/mcedit” “/usr/bin/more” “/usr/bin/most”
“/usr/bin/mv” “/usr/bin/mysql” “/usr/bin/nano” “/usr/bin/nawk”
“/usr/bin/ne” “/usr/bin/nice” “/usr/bin/nl” “/usr/bin/node”
“/usr/bin/nodejs” “/usr/bin/nohup” “/usr/bin/npm” “/usr/bin/od”
“/usr/bin/openssl” “/usr/bin/parallel” “/usr/bin/paste” “/usr/bin/pax”
“/usr/bin/perl” “/usr/bin/pg” “/usr/bin/php” “/usr/bin/pico”
“/usr/bin/pip” “/usr/bin/pip3” “/usr/bin/pr” “/usr/bin/psql”
“/usr/bin/python” “/usr/bin/python3” “/usr/bin/red” “/usr/bin/redis-cli”
“/usr/bin/resolvectl” “/usr/bin/rev” “/usr/bin/rsync” “/usr/bin/ruby”
“/usr/bin/rview” “/usr/bin/rvim” “/usr/bin/scp” “/usr/bin/screen”
“/usr/bin/script” “/usr/bin/sed” “/usr/bin/sftp” “/usr/bin/shuf”
“/usr/bin/sort” “/usr/bin/split” “/usr/bin/sqlite3” “/usr/bin/ssh”
“/usr/bin/ssh-keygen” “/usr/bin/ssh-keyscan” “/usr/bin/strings”
“/usr/bin/svn” “/usr/bin/systemctl” “/usr/bin/tac” “/usr/bin/tail”
“/usr/bin/tar” “/usr/bin/taskset” “/usr/bin/tclsh” “/usr/bin/tcsh”
“/usr/bin/tee” “/usr/bin/time” “/usr/bin/timedatectl”
“/usr/bin/timeout” “/usr/bin/tmux” “/usr/bin/tr” “/usr/bin/unexpand”
“/usr/bin/uniq” “/usr/bin/unxz” “/usr/bin/unzip” “/usr/bin/vi”
“/usr/bin/view” “/usr/bin/vim” “/usr/bin/vim.basic” “/usr/bin/vim.tiny”
“/usr/bin/vimdiff” “/usr/bin/watch” “/usr/bin/wc” “/usr/bin/wget”
“/usr/bin/whatis” “/usr/bin/wish” “/usr/bin/xargs” “/usr/bin/xmllint”
“/usr/bin/xxd” “/usr/bin/xz” “/usr/bin/yarn” “/usr/bin/yelp”
“/usr/bin/yq” “/usr/bin/zip” “/usr/bin/zsh” “/usr/sbin/arp”
“/usr/sbin/bridge” “/usr/sbin/capsh” “/usr/sbin/chroot”
“/usr/sbin/cryptsetup” “/usr/sbin/debugfs” “/usr/sbin/dmsetup”
“/usr/sbin/fdisk” “/usr/sbin/gdisk” “/usr/sbin/getcap”
“/usr/sbin/ifconfig” “/usr/sbin/ip” “/usr/sbin/ip6tables”
“/usr/sbin/iptables” “/usr/sbin/losetup” “/usr/sbin/lvm”
“/usr/sbin/lvs” “/usr/sbin/mkfs” “/usr/sbin/mount” “/usr/sbin/netstat”
“/usr/sbin/nft” “/usr/sbin/parted” “/usr/sbin/pvs” “/usr/sbin/route”
“/usr/sbin/setcap” “/usr/sbin/ss” “/usr/sbin/tc” “/usr/sbin/umount”
“/usr/sbin/vgs”
)

ALL_GTFOBINS=(
“7z” “aa-exec” “ab” “agetty” “alpine” “ansible-playbook”
“ansible-test” “aoss” “apache2ctl” “apt” “apt-get” “ar” “aria2c”
“arj” “arp” “as” “ascii-xfr” “ascii85” “ash” “aspell” “at” “atobm”
“awk” “aws” “base32” “base58” “base64” “basenc” “basez” “bash”
“batcat” “bc” “bconsole” “bpftrace” “bridge” “bundle” “bundler”
“busctl” “busybox” “byebug” “bzip2” “c89” “c99” “cabal” “cancel”
“capsh” “cat” “cdist” “certbot” “check_by_ssh” “check_cups”
“check_log” “check_memory” “check_raid” “check_ssl_cert”
“check_statusfile” “chmod” “choom” “chown” “chroot” “clamscan” “cmp”
“cobc” “column” “comm” “composer” “cowsay” “cowthink” “cp” “cpan”
“cpio” “cpulimit” “crash” “crontab” “csh” “csplit” “csvtool”
“cupsfilter” “curl” “cut” “dash” “date” “dc” “dd” “debugfs” “dialog”
“diff” “dig” “distcc” “dmesg” “dmidecode” “dmsetup” “dnf” “docker”
“dos2unix” “dosbox” “dotnet” “dstat” “dvips” “easy_install” “eb” “ed”
“efax” “elvish” “emacs” “enscript” “env” “eqn” “espeak” “ex”
“exiftool” “expand” “expect” “facter” “file” “find” “finger” “fish”
“flock” “fmt” “fold” “fping” “ftp” “gawk” “gcc” “gcloud” “gcore”
“gdb” “gem” “genie” “genisoimage” “ghc” “ghci” “gimp” “ginsh” “git”
“grc” “grep” “gtester” “gzip” “hd” “head” “hexdump” “highlight”
“hping3” “iconv” “iftop” “install” “ionice” “ip” “irb” “ispell”
“jjs” “joe” “join” “journalctl” “jq” “jrunscript” “jtag” “julia”
“knife” “ksh” “ksshell” “ksu” “kubectl” “latex” “latexmk” “ld.so”
“ldconfig” “less” “lftp” “links” “ln” “loginctl” “logsave” “look”
“lp” “ltrace” “lua” “lualatex” “luatex” “lwp-download” “lwp-request”
“mail” “make” “man” “mawk” “minicom” “more” “mosquitto” “mount”
“msfconsole” “msgattrib” “msgcat” “msgconv” “msgfilter” “msgmerge”
“msguniq” “mtr” “multitime” “mv” “mysql” “nano” “nasm” “nawk” “nc”
“ncdu” “ncftp” “neofetch” “nft” “nice” “nl” “nm” “nmap” “node”
“nohup” “npm” “nroff” “nsenter” “ntpdate” “octave” “od” “openssl”
“openvpn” “openvt” “opkg” “pandoc” “paste” “pax” “pdb” “pdflatex”
“pdftex” “perf” “perl” “perlbug” “pexec” “pg” “php” “pic” “pico”
“pidstat” “pip” “pkexec” “pkg” “posh” “pr” “pry” “psftp” “psql”
“ptx” “puppet” “pwsh” “python” “rake” “rc” “readelf” “red”
“redcarpet” “redis” “restic” “rev” “rlogin” “rlwrap” “rpm” “rpmdb”
“rpmquery” “rpmverify” “rsync” “rtorrent” “ruby” “run-mailcap”
“run-parts” “runscript” “rview” “rvim” “sash” “scanmem” “scp”
“screen” “script” “scrot” “sed” “service” “setarch” “setfacl”
“setlock” “sftp” “sg” “shuf” “slsh” “smbclient” “snap” “socat”
“socket” “soelim” “softlimit” “sort” “split” “sqlite3” “sqlmap” “ss”
“ssh” “ssh-agent” “ssh-keygen” “ssh-keyscan” “sshpass”
“start-stop-daemon” “stdbuf” “strace” “strings” “su” “sudo” “sysctl”
“systemctl” “systemd-resolve” “tac” “tail” “tar” “task” “taskset”
“tasksh” “tbl” “tclsh” “tcpdump” “tdbtool” “tee” “telnet” “terraform”
“tex” “tftp” “tic” “time” “timedatectl” “timeout” “tmate” “tmux”
“top” “torify” “torsocks” “troff” “tshark” “ul” “unexpand” “uniq”
“unshare” “unsquashfs” “unzip” “update-alternatives” “uudecode”
“uuencode” “vagrant” “valgrind” “varnishncsa” “vi” “view” “vigr”
“vim” “vimdiff” “vipw” “virsh” “volatility” “w3m” “wall” “watch”
“wc” “wget” “whiptail” “whois” “wireshark” “wish” “xargs”
“xdg-user-dir” “xdotool” “xelatex” “xetex” “xmodmap” “xmore” “xpad”
“xxd” “xz” “yarn” “yash” “yelp” “yum” “zathura” “zip” “zsh”
“zsoelim” “zypper”
)

DANGEROUS_BINARY_PATTERNS=(
‘/usr/bin/gcc’ ‘/usr/bin/g++’ ‘/usr/bin/cc’ ‘/usr/bin/c++’
‘/usr/bin/as’ ‘/usr/bin/ld’ ‘/usr/bin/ar’ ‘/usr/bin/nm’
‘/usr/bin/make’ ‘/usr/bin/cmake’ ‘/usr/bin/python’ ‘/usr/bin/python2*’
‘/usr/bin/ruby*’ ‘/usr/bin/irb’ ‘/usr/bin/erb’ ‘/usr/bin/lua’
‘/usr/bin/luac’ ‘/usr/bin/node’ ‘/usr/bin/nodejs’ ‘/usr/bin/npm’
‘/usr/bin/php*’ ‘/usr/bin/gdb’ ‘/usr/bin/lldb’ ‘/usr/bin/strace’
‘/usr/bin/ltrace’ ‘/usr/bin/xxd’ ‘/usr/bin/hexdump’ ‘/usr/bin/objdump’
‘/usr/bin/readelf’ ‘/usr/bin/nc’ ‘/usr/bin/ncat’ ‘/usr/bin/netcat’
‘/usr/bin/nmap’ ‘/usr/bin/masscan’ ‘/usr/bin/socat’ ‘/usr/bin/arp*’
‘/usr/bin/trace*’ ‘/usr/bin/run0’ ‘/usr/bin/su’ ‘/usr/bin/sudoedit’
‘/usr/bin/sudoreplay’ ‘/usr/bin/pkexec’
‘/bin/zsh’ ‘/bin/fish’ ‘/bin/tcsh’ ‘/bin/csh’ ‘/bin/ksh’
‘/bin/ksh93’ ‘/bin/mksh’ ‘/bin/pdksh’ ‘/bin/ash’ ‘/bin/rc’
‘/bin/es’ ‘/bin/sash’ ‘/bin/yash’
‘/usr/bin/zsh’ ‘/usr/bin/fish’ ‘/usr/bin/tcsh’ ‘/usr/bin/csh’
‘/usr/bin/ksh*’
)

# ══════════════════════════════════════════════════════════════════

# BEGIN HARDENING

# ══════════════════════════════════════════════════════════════════

# ── Pre-config ───────────────────────────

log_step “PRE-CONFIG”
log_info “Installing prerequisites and enabling LibreWolf repo…”
apt install -y extrepo iptables iptables-persistent netfilter-persistent –no-install-recommends
extrepo enable librewolf
apt update -y

# ── Firewall ──────────────────────────────────────────────────────

log_step “FIREWALL”
log_info “Configuring iptables firewall…”
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
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack –ctstate INVALID -j DROP
iptables -A INPUT -m conntrack –ctstate RELATED,ESTABLISHED -j ACCEPT
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
log_info “Firewall configured and saved”

# ── Mullvad ──────────────────────────────────────────────────────

log_step "MULLVAD VPN"
MULLVAD_DEB="/tmp/mullvad-vpn.deb"
MULLVAD_URL="https://repository.mullvad.net/deb/stable/pool/main/m/mullvad-vpn/mullvad-vpn_2025.14_amd64.deb"

log_info "Downloading Mullvad VPN..."
if wget -q -O "$MULLVAD_DEB" "$MULLVAD_URL"; then
    log_info "Download complete — installing..."
    if dpkg -i "$MULLVAD_DEB"; then
        log_info "Mullvad installed successfully"
        rm -f "$MULLVAD_DEB"
        systemctl enable mullvad-daemon.service
        log_info "mullvad-daemon.service enabled for boot"
    else
        log_error "Mullvad dpkg install failed"
        (( WARN_COUNT++ )) || true
    fi
else
    log_error "Mullvad download failed — check connectivity and URL"
    (( WARN_COUNT++ )) || true
fi

# ── APT Hardening ─────────────────────────────────────────────────

log_step “APT HARDENING”
log_info “Configuring APT hardening…”
cat > /etc/apt/apt.conf.d/99-hardening << ‘EOF’
APT::Get::AllowUnauthenticated “false”;
Acquire::AllowInsecureRepositories “false”;
Acquire::AllowDowngradeToInsecureRepositories “false”;
APT::Install-Recommends “false”;
APT::Install-Suggests “false”;
APT::AutoRemove::RecommendsImportant “false”;
APT::AutoRemove::SuggestsImportant “false”;
APT::Periodic::Update-Package-Lists “1”;
APT::Periodic::Download-Upgradeable-Packages “0”;
APT::Periodic::AutocleanInterval “7”;
APT::Periodic::Unattended-Upgrade “0”;
APT::Sandbox::Seccomp “true”;
EOF

# ── Package Removal ────────────────────────────────────────

log_step “PACKAGE REMOVAL”
log_info “Removing unnecessary packages…”
apt purge -y “${REMOVE_PKGS[@]}” 2>/dev/null || true

# ── Package Deny Lists ────────────────────────────────────────────

log_info “Creating package deny lists…”
install -d /etc/apt/preferences.d

cat > /etc/apt/preferences.d/60-deny-misc.pref << ‘EOF’
Package: aircrack-ng* aircrack* alpine* anacron* ansible* aoss* apache* apache2* ar aria2c* arj* arp* as ascii* ash aspell* at atobm* autoconf* automake* autopsy* avahi* awk* aws* base32* base58* base64* basenc* basez* batcat* bc* bconsole* beef-xss* beef* bettercap* bind* bind9* binutils* binwalk* bison* blue* bluetooth* bluez* bochs* bpf* bridge* build-essential* build* bundle* burp* burpsuite* busctl* byebug* bz* c89* c99* cabal-install* cabal* cancel capsh* cargo* cdist* certbot* check_by_ssh* check_cups* check_log* check_memory* check_raid* check_ssl_cert* check_statusfile* chef* choom* chroot* clam* clang* cmake* cmp* cobc* cockpit* column comm composer* container* containerd.io* courier* cow* cowsay* cpan* cpio* cpulimit* crack* crackmapexec* cron* csh* csplit* csv* cup* cups* curl* cut dash* date dc* dd* debug* default-jdk* default-jre* dhcp* dhcpcd* dialog* diff dig* dirb* distcc* dm* dma* dnf* dns* docker-ce-cli* docker-ce* docker.io* docker* dos2unix* dosbox* dotnet*
Pin: release *
Pin-Priority: -1
EOF

cat > /etc/apt/preferences.d/50-deny-network.pref << ‘EOF’
Package: dropbear* dsniff* dstat* dvips* easy_install* eb ed efax* elf* elixir* elvish* emacs* enscript* enum* enum4linux* env eqn* erlang* espeak* ettercap-common* ettercap-graphical* ettercap* ex exif* exim* exim4* expect* facter* fastfetch* finger* fish* flatpak* flex* flock* fmt* fold fonts-noto* foremost* fortune* fpc* fping* fprint* ftp* fuzz* g++* gcc* gcloud* gcore* gdb* gdebi* gem* genie* geniso* gfortran* ghc* ghost* gimp* ginsh* gnustep* gobuster* golang-go* golang* grc grep gtester gzip* hash* hashcat* hd* head hex* highlight* hping* hping3* hydra-gtk* hydra* iconv* iftop* image* imagemagick* impacket-scripts* impacket* inet* ionice* irb* ispell* iw* jjs* joe* john* join* jrunscript* jtag* julia* knife* ksh* ksshell* ksu* kube* kubectl* kubernetes* latex*
Pin: release *
Pin-Priority: -1
EOF

cat > /etc/apt/preferences.d/40-deny-containers.pref << ‘EOF’
Package: ldconfig* lftp* libfprint* libsql* libtool* libvirt* lighttpd* links* lldb* llvm* ln* loginctl* logsave* look lp* ltrace* lua* luajit* lwp* lxc* lxd-client* lxd* m4* macchanger* mail* make* maltego* man* masscan* medusa* meson* metagoofil* metasploit-framework* metasploit* minicom* mitm* mitmproxy* mobile* modem* mono-complete* more mosquit* mosquitto* msg* msguniq* mtr* multitime* mysql* nasm* nawk* nbtscan* nc ncat* ncdu* nct* neofetch* netcat* nfs-common* nfs-kernel-server* nfs* nft* nftables* nginx* nice* nikto* ninja-build* ninja* nl nm nmap* node nodejs* nohup* npm* nroff* nsenter* ntpdate* octave* od open-vm-tools* open-vm* openssh* openssl* opensteg* openstego* openvpn* openvt* opkg* os-prober* outguess* pandoc* paste pax* pdb* pdf* perf perl* perlbug pexec* pg php-cli* php-common* php* pic pico* pip pip3 pipx pipx* pk* pkg* pmount* podman* posh* postfix* pp* pr print* proftp* proftpd-basic* proftpd* proxy* proxychains* proxychains4* pry* psftp* psql* ptx* puppet*
Pin: release *
Pin-Priority: -1
EOF

cat > /etc/apt/preferences.d/30-deny-dev.pref << ‘EOF’
Package: pure-ftpd* pure* pwsh* python python-is-python3* python-pip* python3-pip* qemu* r-base* radar* radare2* rake* rbdmap* rc* readelf* recon-ng* recon* red redcarpet* redis* responder* restic* rev rl* rlogin* rpc* rpcbind* rpm* rsh-client* rsh-redone-client* rsh* rsync* rtorrent* ruby-full* ruby* run-mailcap* run-parts* runscript* rust* rustc* rview* rvim* salt-common* salt-minion* samba* sane* sash* scalpel* scan* scapy* scp* screen* script* scrot* sed sendmail* service set setarch* setfacl* setlock* sftp* sg* shuf* sleuth* sleuthkit* slsh* smb* smbclient* smbd* smbmap* snap* snapd* sniff* snmp* snmpd* snmptrapd* so* socat socat* social-engineer-toolkit* social-engineer* socket* soelim* softlimit* sort spee* spice-vdagent* spice* spiderfoot* split sql* sqlmap* ss* ssh* ssl* sslstrip* stdb* steg* steghide* stegosuite* strace* strings* swig* systemd-resolve* tac tail* tar task tasksel* taskset* tasksh* tbl* tcl* tcp* tcpdump* tdbtool* tee telnet* telnetd* terraform* tex tftp-hpa* tftp* theharvester*
Pin: release *
Pin-Priority: -1
EOF

cat > /etc/apt/preferences.d/10-deny.pref << ‘EOF’
Package: tic tiger* tigervnc* timedatectl* timeout* tinyssh* tk* tmate* tmux* top tor* torsocks* traceroute* tripwire* troff* tshark* ul uml* unattended-upgrades* unattended* unexpand* unicornscan* uniq* unshare* unsquashfs* update-alternatives* util-linux-locales uuen* vagrant* valgrind* varnish* vbox* vigr* vim* vipw* virsh* virt* vmw* volatil* volatility* vsftp* vsftpd* w3m* wall watch* wc webmin* wfuzz* wget* whois* winbind* wireless* wireshark-gtk* wireshark-qt* wireshark* wish* wpa-supplicant* wpa* wpasupplicant* x11vnc* xargs* xdg-user-dir* xdotool* xelatex* xen* xetex* xinetd* xmod* xmore* xpad* xrdp* xxd* xz* yarn* yash* yasm* yersinia* yum* zathura* zenmap* zip* zmap* zram* zsh* zsoelim* zypper*
Pin: release *
Pin-Priority: -1
EOF

chmod 644 /etc/apt/preferences.d/*.pref

# ── Package Installation ──────────────────────────────────────

log_step “PACKAGE INSTALLATION”
log_info “Installing required packages…”
apt install -y “${INSTALL_PKGS[@]}” librewolf –no-install-recommends

# ── Systemd Services ──────────────────────────────────────────────

log_step “SYSTEMD HARDENING”
log_info “Masking unnecessary systemd services…”
for svc in “${SERVICES_TO_DISABLE[@]}”; do
run_cmd “Mask ${svc}” systemctl mask –now “$svc”
done

# ── Accounts & Groups ─────────────────────────────────────────────

log_step “ACCOUNTS & GROUPS”
for grp in _ssh bluetooth nogroup fax floppy irc kvm voice games; do
run_cmd “Delete group ${grp}” groupdel “$grp” –force
done

for usr in nobody games irc uucp proxy dhcpcd list news sync man mail lp www-data; do
run_cmd “Delete user ${usr}” userdel “$usr”
done

for grp in render input video audio tty; do
run_cmd “Add ${HARDEN_USER} to ${grp}” adduser “$HARDEN_USER” “$grp”
done

# ── PAM: U2F Enrollment ───────────────────────────────────────────

log_step “PAM CONFIGURATION”
log_info “Configuring U2F authentication…”
echo “”
log_warn “Physical key interaction required — insert your YubiKey now”
read -rp “  Press Enter when your key is inserted and ready: “

if ! pamu2fcfg -u “$HARDEN_USER” -o “$PAM_ORIGIN” -i “$PAM_APPID” > “$U2F_AUTHFILE”; then
log_error “U2F enrollment failed — key not detected or touch timed out”
log_error “Cannot continue without a valid U2F mapping — exiting”
exit 1
fi

if [[ ! -s “$U2F_AUTHFILE” ]]; then
log_error “U2F mapping file is empty — enrollment did not complete”
exit 1
fi

chmod 0400 “$U2F_AUTHFILE”
chown root:root “$U2F_AUTHFILE”
log_info “U2F enrollment successful — mapping written to ${U2F_AUTHFILE}”

# ── PAM: Faillock & Config Files ──────────────────────────────────

log_info “Configuring PAM stack…”
mkdir -p /var/log/faillock
chmod 0700 /var/log/faillock
rm -f /etc/pam.d/remote /etc/pam.d/cron 2>/dev/null || true

cat > /etc/security/faillock.conf << EOF
deny = ${FAILLOCK_DENY}
unlock_time = ${FAILLOCK_UNLOCK}
fail_interval = ${FAILLOCK_INTERVAL}
silent
EOF

cat > /etc/pam.d/common-auth << EOF
#%PAM-1.0
auth      required            pam_faildelay.so delay=${FAILDELAY}
auth      required            pam_faillock.so preauth deny=${FAILLOCK_DENY} unlock_time=${FAILLOCK_UNLOCK} fail_interval=${FAILLOCK_INTERVAL}
auth      [success=done default=die]  pam_u2f.so authfile=${U2F_AUTHFILE} cue origin=${PAM_ORIGIN} appid=${PAM_APPID} nouserok
auth      [default=die]       pam_faillock.so authfail deny=${FAILLOCK_DENY} unlock_time=${FAILLOCK_UNLOCK} fail_interval=${FAILLOCK_INTERVAL}
auth      requisite           pam_deny.so
EOF

cat > /etc/pam.d/common-account << ‘EOF’
#%PAM-1.0
account   required    pam_access.so accessfile=/etc/security/access.conf
account   required    pam_unix.so
EOF

cat > /etc/pam.d/common-password << ‘EOF’
#%PAM-1.0
password  requisite   pam_deny.so
EOF

cat > /etc/pam.d/common-session << ‘EOF’
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
session   required    pam_unix.so
EOF

cat > /etc/pam.d/common-session-noninteractive << ‘EOF’
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
session   required    pam_unix.so
EOF

cat > /etc/pam.d/sudo << ‘EOF’
#%PAM-1.0
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/sudo-i << ‘EOF’
#%PAM-1.0
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/su << ‘EOF’
#%PAM-1.0
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/su-l << ‘EOF’
#%PAM-1.0
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   include     common-session
EOF

cat > /etc/pam.d/login << ‘EOF’
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

cat > /etc/pam.d/chfn << ‘EOF’
#%PAM-1.0
auth      sufficient  pam_rootok.so
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat > /etc/pam.d/chsh << ‘EOF’
#%PAM-1.0
auth      required    pam_shells.so
auth      sufficient  pam_rootok.so
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat > /etc/pam.d/chpasswd << ‘EOF’
#%PAM-1.0
password  requisite   pam_deny.so
EOF

cat > /etc/pam.d/newusers << ‘EOF’
#%PAM-1.0
password  requisite   pam_deny.so
EOF

cat > /etc/pam.d/passwd << ‘EOF’
#%PAM-1.0
password  requisite   pam_deny.so
EOF

cat > /etc/pam.d/runuser << ‘EOF’
#%PAM-1.0
auth      sufficient  pam_rootok.so
session   required    pam_limits.so
session   required    pam_unix.so
EOF

cat > /etc/pam.d/runuser-l << ‘EOF’
#%PAM-1.0
auth      include     runuser
session   include     runuser
EOF

cat > /etc/pam.d/sshd << ‘EOF’
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF

cat > /etc/pam.d/other << ‘EOF’
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF

cat > /usr/lib/pam.d/systemd-user << ‘EOF’
#%PAM-1.0
session   required    pam_limits.so
account   include     common-account
session   required    pam_env.so user_readenv=0
session   optional    pam_systemd.so
session   required    pam_unix.so
EOF

cat > /usr/lib/pam.d/polkit << ‘EOF’
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF

chmod 0644 /etc/pam.d/*
chown root:root /etc/pam.d/*
passwd -l “$HARDEN_USER”
passwd -l root

# ── Miscellaneous Hardening ───────────────────────────────────────

log_step “MISC HARDENING”

cat > /etc/shells << ‘EOF’
/bin/bash
EOF

cat > /etc/host.conf << ‘EOF’
multi on
order hosts
EOF

cat > /etc/security/limits.d/limits.conf << EOF
*            -      nproc         512
*            -      maxlogins     1
*            -      maxsyslogins  1
dev          -      nproc         2048
dev          -      maxlogins     1
dev          -      maxsyslogins  1
root         -      nproc         65536
root         -      maxlogins     1
root         -      maxsyslogin   1
EOF

mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf << ‘EOF’
[Coredump]
ProcessSizeMax=0
Storage=none
EOF

sed -i ‘s|^ENCRYPT_METHOD.*|ENCRYPT_METHOD YESCRYPT|’ /etc/login.defs
sed -i ’s|^UID_MIN.*|UID_MIN 1000|’ /etc/login.defs
sed -i ‘s|^UID_MAX.*|UID_MAX 60000|’ /etc/login.defs
sed -i ’s|^PASS_MAX_DAYS.*|PASS_MAX_DAYS   15|’ /etc/login.defs
sed -i ‘s|^PASS_MIN_DAYS.*|PASS_MIN_DAYS   7|’ /etc/login.defs
sed -i ’s|^CHFN_RESTRICT.*|CHFN_RESTRICT     rwh|’ /etc/login.defs
sed -i ‘s|^#?TTYGROUP.*|TTYGROUP       tty|’ /etc/login.defs
sed -i ’s|^LOGIN_RETRIES.*|LOGIN_RETRIES 2|’ /etc/login.defs
sed -i ‘s|^LOG_OK_LOGINS.*|LOG_OK_LOGINS yes|’ /etc/login.defs
sed -i ’s|^DEFAULT_HOME.*|DEFAULT_HOME no|’ /etc/login.defs
sed -i ‘s|^SHELL=.*|SHELL=/bin/false|’ /etc/default/useradd
sed -i ’s|^# HOME=.*|HOME=/home|’ /etc/default/useradd
sed -i ‘s|^# SKEL=.*|SKEL=|’ /etc/default/useradd
sed -i ’s|^#?DSHELL=.*|DSHELL=/usr/sbin/nologin|’ /etc/adduser.conf
sed -i ‘s|^#?DHOME=.*|DHOME=/home|’ /etc/adduser.conf
sed -i ’s|^#?SKEL=/etc/skel.*|SKEL=|’ /etc/adduser.conf
sed -i ‘s|^#?DIR_MODE=.*|DIR_MODE=0700|’ /etc/adduser.conf
sed -i ’s|^#?SYS_DIR_MODE=.*|SYS_DIR_MODE=0750|’ /etc/adduser.conf
sed -i ‘s|^#?ADD_EXTRA_GROUPS=.*|ADD_EXTRA_GROUPS=0|’ /etc/adduser.conf

grep -q “ulimit -c 0” /etc/profile || echo “ulimit -c 0” >> /etc/profile
echo “UMASK 077” >> /etc/login.defs
echo “umask 077” >> /etc/profile
echo “umask 077” >> /etc/bash.bashrc

echo “ALL: LOCAL, 127.0.0.1” > /etc/hosts.allow
echo “ALL: ALL” > /etc/hosts.deny
chmod 0644 /etc/hosts.allow /etc/hosts.deny

cat > /etc/security/access.conf << EOF
+:${HARDEN_USER}:LOCAL
-:ALL EXCEPT ${HARDEN_USER}:LOCAL
-:${HARDEN_USER}:ALL EXCEPT LOCAL
-:root:ALL
-:ALL:REMOTE
-:ALL:ALL
EOF
chmod 644 /etc/security/access.conf

# ── GRUB ──────────────────────────────────────────────────────────

log_step “GRUB HARDENING”

sed -i ‘s|^#?GRUB_DISABLE_OS_PROBER=.*|GRUB_DISABLE_OS_PROBER=true|’ /etc/default/grub
sed -i ’s|^#?GRUB_DISABLE_LINUX_UUID=.*|GRUB_DISABLE_LINUX_UUID=true|’ /etc/default/grub
sed -i ‘s|^#?GRUB_DISABLE_RECOVERY=.*|GRUB_DISABLE_RECOVERY=true|’ /etc/default/grub
sed -i ’s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=“quiet splash mitigations=auto spectre_v2=on spec_store_bypass_disable=on amd_iommu=on iommu=pt init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on slab_nomerge vsyscall=none debugfs=off oops=panic ipv6.disable=1 amdgpu.dcdebugmask=0x10 amdgpu.sg_display=0 amdgpu.gfx_off=0 module.sig_enforce=1 nosmt nowatchdog nmi_watchdog=0”|’ /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub

# ── Sysctl ────────────────────────────────────────────────────────

log_step “SYSCTL HARDENING”
rm -rf /usr/lib/sysctl.d
mkdir -p /usr/lib/sysctl.d
cat > /usr/lib/sysctl.d/sysctl.conf << ‘EOF’
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
sysctl –system

# ── Kernel Modules ────────────────────────────────────────────────

log_step “MODULE BLACKLISTING”
cat > /etc/modprobe.d/harden.conf << ‘EOF’
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

# ── Filesystem Mounts ─────────────────────────────────────────────

log_step “FILESYSTEM HARDENING”
cp /etc/fstab /etc/fstab.bak

if ! grep -q “proc.*hidepid=2” /etc/fstab; then
cat >> /etc/fstab << EOF
proc     /proc             proc   noatime,nodev,nosuid,noexec,hidepid=2,gid=proc    0 0
tmpfs    /tmp              tmpfs  size=2G,noatime,nodev,nosuid,noexec,mode=1777      0 0
tmpfs    /var/tmp          tmpfs  size=1G,noatime,nodev,nosuid,noexec,mode=1777      0 0
tmpfs    /dev/shm          tmpfs  size=512M,noatime,nodev,nosuid,noexec,mode=1777    0 0
tmpfs    /run              tmpfs  size=512M,noatime,nodev,nosuid,mode=0755           0 0
tmpfs    ${HARDEN_HOME}/.cache  tmpfs  size=2G,noatime,nodev,nosuid,noexec,mode=700,uid=1000,gid=1000  0 0
EOF
fi

groupadd -f proc
adduser root proc
adduser “$HARDEN_USER” proc

# ── File Permissions ──────────────────────────────────────────────

log_step “PERMISSIONS”
chmod 0700 /root
chown root:root /root
chmod 0700 “$HARDEN_HOME”
chown “${HARDEN_USER}:${HARDEN_USER}” “$HARDEN_HOME”

find “$HARDEN_HOME” -type f -exec chmod o-rwx {} ; 2>/dev/null || true
find “$HARDEN_HOME” -type d -exec chmod o-rwx {} ; 2>/dev/null || true

chmod 0600 /etc/shadow /etc/gshadow
chown root:root /etc/shadow /etc/gshadow
chmod 0644 /etc/passwd /etc/group
chown root:root /etc/passwd /etc/group
chmod 0440 /etc/sudoers
chown root:root /etc/sudoers
chmod 0000 /etc/sudoers.d
chown root:root /etc/sudoers.d
find /etc/sudoers.d -type f -exec chmod 0000 {} ; 2>/dev/null || true
chmod 0644 /etc/pam.d/*
chown root:root /etc/pam.d/*
chmod 0600 /etc/security/access.conf /etc/security/limits.conf   
/etc/security/namespace.conf “$U2F_AUTHFILE” 2>/dev/null || true
chown root:root /etc/security/*

if [[ -d /etc/ssh ]]; then
chmod 700 /etc/ssh
chmod 600 /etc/ssh/*_key 2>/dev/null || true
chmod 644 /etc/ssh/*.pub 2>/dev/null || true
chmod 644 /etc/ssh/sshd_config 2>/dev/null || true
chown -R root:root /etc/ssh
fi

chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly   
/etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
chmod 600 /etc/crontab 2>/dev/null || true
[[ -f /etc/at.deny ]] && chmod 600 /etc/at.deny

chmod 0700 /boot
chown root:root /boot
find /boot -type f ( -name “vmlinuz*” -o -name “initrd*”   
-o -name “System.map*” -o -name “config-*” )   
-exec chmod 0600 {} ; 2>/dev/null || true
if [[ -f /boot/grub/grub.cfg ]]; then
chmod 0600 /boot/grub/grub.cfg
chown root:root /boot/grub/grub.cfg
fi

chown root:adm -R /var/log 2>/dev/null || true
chmod -R 0640 /var/log 2>/dev/null || true
chmod 0640 /var/log 2>/dev/null || true

# ── Single Filesystem Scan Pass ───────────────────────────────────

log_info “Scanning filesystem for permission issues…”
find / -xdev   
( -path “/tmp” -o -path “/var/tmp” -o -path “/proc”   
-o -path “/sys” -o -path “/dev” ) -prune -o   
(   
-type f -perm -0002 -exec chmod o-w {} ; -printf “Fixed world-writable: %p\n”   
-o   
-type d -perm -0002 ! -perm -1000 -exec chmod +t {} ; -printf “Fixed sticky bit: %p\n”   
-o   
( -nouser -o -nogroup ) -printf “Orphan: %p (UID: %U GID: %G)\n”   
) 2>/dev/null || true

# ── OpenSnitch ────────────────────────────────────────────────────

log_step “OPENSNITCH”
cat > /etc/systemd/system/opensnitchd.service << ‘EOF’
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
chmod 750 /etc/opensnitchd /etc/opensnitchd/rules
touch /var/log/opensnitchd.log
chmod 640 /var/log/opensnitchd.log
systemctl daemon-reload
run_cmd “Enable opensnitchd” systemctl enable opensnitchd.service
run_cmd “Start opensnitchd” systemctl start opensnitchd.service

log_info “Installing OpenSnitch blocklists…”
if git clone –depth 1 https://github.com/DXC-0/Respect-My-Internet.git; then
cd Respect-My-Internet
chmod +x install.sh
./install.sh
cd ~
rm -rf ~/Respect-My-Internet
else
log_warn “OpenSnitch blocklist clone failed — install manually post-boot”
(( WARN_COUNT++ )) || true
fi

# ── Privilege Escalation Hardening ────────────────────────────────

log_step “PRIVILEGE HARDENING”
echo “” > /etc/securetty
chmod 0400 /etc/securetty

chmod a-s /sbin/unix_chkpwd 2>/dev/null || true
chmod a-s /usr/sbin/unix_chkpwd 2>/dev/null || true

rm -rf /etc/skel* /etc/dhcp* /etc/ssh* /etc/ppp* /etc/apparmor*   
/etc/cron* /etc/emacs* /etc/xemacs* /etc/gai* /etc/vim*   
/etc/wpa* /etc/manpath* /etc/libnl* 2>/dev/null || true

rm -f /usr/bin/run0 /usr/sbin/arp* /usr/bin/passwd*   
/usr/bin/gpasswd* /usr/sbin/ebtables* /usr/sbin/xtables*   
/usr/bin/sudoreplay /usr/bin/sudoedit 2>/dev/null || true

rm -rf /usr/lib/emacs* /usr/lib/gpg* /usr/lib/gvfs*   
/usr/lib/os-probe* /usr/lib/man-db* /usr/lib/ppp*   
/usr/lib/gnupg* /usr/lib/systemd/ssh*   
/usr/lib/systemd/systemd-ssh*   
/usr/lib/systemd/systemd-socket*   
/usr/lib/systemd/systemd-sulogin*   
/usr/lib/systemd/network/73*   
/usr/lib/systemd/network/80-container*   
/usr/lib/systemd/network/80-wifi*   
/usr/lib/systemd/system-generators/systemd-ssh* 2>/dev/null || true

# ── Block Device Nodes ────────────────────────────────────────────

log_step “UDEV HARDENING”
cat > /etc/udev/rules.d/99-deny-devices.rules << ‘EOF’
KERNEL==“vhost-net”,   OPTIONS+=“static_node=vhost-net”,  ACTION==“add”, RUN+=”/bin/rm -f /dev/vhost-net”
KERNEL==“vhost-vsock”, OPTIONS+=“static_node=vhost-vsock”,ACTION==“add”, RUN+=”/bin/rm -f /dev/vhost-vsock”
KERNEL==“vfio*”,       ACTION==“add”, RUN+=”/bin/rm -f /dev/%k”
KERNEL==“ng0n1”,       ACTION==“add”, RUN+=”/bin/rm -f /dev/ng0n1”
KERNEL==“ppp”,         ACTION==“add”, RUN+=”/bin/rm -f /dev/ppp”
KERNEL==“fuse”,        ACTION==“add”, RUN+=”/bin/rm -f /dev/fuse”
KERNEL==“snapshot”,    ACTION==“add”, RUN+=”/bin/rm -f /dev/snapshot”
KERNEL==“watchdog*”,   ACTION==“add”, RUN+=”/bin/rm -f /dev/%k”
KERNEL==“tty[89]”,         ACTION==“add”, RUN+=”/bin/rm -f /dev/%k”
KERNEL==“tty[1-6][0-9]”,  ACTION==“add”, RUN+=”/bin/rm -f /dev/%k”
EOF
chmod 0644 /etc/udev/rules.d/99-deny-devices.rules
run_cmd “Reload udev rules” udevadm control –reload-rules

# ── Secure Path ───────────────────────────────────────────────────

log_step “PATH HARDENING”
SECURE_SUPATH=”/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin”
SECURE_PATH=”/usr/local/bin:/usr/bin”
sed -i “s|^ENV_SUPATH.*|ENV_SUPATH      PATH=${SECURE_SUPATH}|” /etc/login.defs
sed -i “s|^ENV_PATH.*|ENV_PATH        PATH=${SECURE_PATH}|” /etc/login.defs
sed -i “s|PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"|PATH="${SECURE_SUPATH}"|g” /etc/profile
sed -i “s|PATH="/usr/local/bin:/usr/bin:/bin"|PATH="${SECURE_PATH}"|g” /etc/profile
sed -i “s|^PATH=.*|PATH="${SECURE_SUPATH}"|” /etc/environment

# ── Polkit ────────────────────────────────────────────────────────

log_step “POLKIT LOCKDOWN”
mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/00-deny-all.rules << ‘EOF’
// Deny all polkit requests - hardened system
polkit.addRule(function(action, subject) {
return polkit.Result.NO;
});
EOF
chmod 0644 /etc/polkit-1/rules.d/00-deny-all.rules

# ── Sudo ──────────────────────────────────────────────────────────

log_step “SUDO HARDENING”
cat > /etc/sudoers << EOF
Defaults env_reset
Defaults !setenv
Defaults umask=0077
Defaults always_set_home
Defaults timestamp_timeout=0
Defaults passwd_timeout=0
Defaults passwd_tries=1
Defaults use_pty
Defaults secure_path=”${SECURE_SUPATH}”
Defaults logfile=”/var/log/sudo.log”
Defaults log_input,log_output
Defaults editor=/bin/false
Defaults !env_editor

Cmnd_Alias FIREWALL  = /usr/sbin/iptables -L, /usr/sbin/nft list *
Cmnd_Alias PACKAGES  = /usr/bin/apt update, /usr/bin/apt list –upgradable, /usr/bin/apt upgrade
Cmnd_Alias MAINT     = /usr/bin/systemctl status *, /usr/bin/journalctl -xe

${HARDEN_USER}  ALL=(ALL) ALL
#${HARDEN_USER} ALL=(root) FIREWALL, PACKAGES, MAINT
EOF
chmod 0440 /etc/sudoers
chmod -R 0440 /etc/sudoers.d

# ── GTFOBins / Capabilities ───────────────────────────────────────

log_step “CAPABILITY & BINARY STRIPPING”
for interp in “${STRIP_CAPS[@]}”; do
[[ -f “$interp” ]] && run_cmd “Strip caps from ${interp}” setcap -r “$interp”
done

cap_output=$(getcap -r /usr 2>/dev/null | awk ‘{print $1}’ || true)
for binary in $cap_output; do
cap_basename=$(basename “$binary”)
for gtfo in “${ALL_GTFOBINS[@]}”; do
if [[ “$cap_basename” == “$gtfo” ]] || [[ “$cap_basename” == “${gtfo}.”* ]]; then
run_cmd “Strip GTFOBin caps from ${binary}” setcap -r “$binary”
break
fi
done
done

for pattern in “${DANGEROUS_BINARY_PATTERNS[@]}”; do
rm -f $pattern 2>/dev/null || true
done

# ── SUID/SGID Strip ───────────────────────────────────────────────

log_step “SUID/SGID STRIPPING”
find / -xdev ( -perm -4000 -o -perm -2000 ) -exec chmod a-s {} ;

chmod u+s /usr/bin/sudo

# ── Final Cleanup ─────────────────────────────────────────────────

log_step “FINAL CLEANUP”
RC_PKGS=$(dpkg -l | grep ‘^rc’ | awk ‘{print $2}’ || true)
if [[ -n “$RC_PKGS” ]]; then
echo “$RC_PKGS” | xargs apt purge -y 2>/dev/null || true
fi
apt autopurge -y 2>/dev/null || true
apt clean

# ── Immutable Lock ────────────────────────────────────────────────

log_step “IMMUTABILITY LOCK”
log_warn “Applying chattr immutable locks — system will be locked after this point”

chattr +i /etc/passwd /etc/passwd- /etc/shadow /etc/shadow-   
/etc/group /etc/group- /etc/gshadow /etc/gshadow-   
/etc/login.defs /etc/shells /etc/securetty /etc/services   
/etc/fstab /etc/adduser.conf /etc/deluser.conf   
/etc/hosts /etc/hosts.allow /etc/hosts.deny   
/etc/nsswitch.conf /etc/ld.so.conf 2>/dev/null || true

chattr +i /root/.bashrc “${HARDEN_HOME}/.bashrc”  
/usr/lib/sysctl.d/sysctl.conf 2>/dev/null || true

chattr -R +i /etc/host.conf /etc/sudoers /etc/sudoers.d   
/etc/pam.d /usr/lib/pam.d /etc/security   
/etc/default /etc/sysctl.conf /etc/sysctl.d   
/etc/modprobe.d /usr/lib/modprobe.d   
/usr/lib/sysctl.d /etc/iptables   
/etc/profile /etc/profile.d /etc/bash.bashrc   
/etc/bashrc /etc/cron.allow /etc/at.allow   
/etc/cron.d /etc/cron.daily /etc/cron.hourly   
/etc/cron.monthly /etc/cron.weekly   
/etc/polkit-1 /etc/ld.so.conf.d   
/lib/modules /boot 2>/dev/null || true

# /usr locked last — intentional appliance model

# Changes require: external boot media + chattr -R -i /usr

chattr -R +i /usr /usr/local 2>/dev/null || true

log_info “Immutable lock applied”

# ══════════════════════════════════════════════════════════════════

# COMPLETION REPORT

# ══════════════════════════════════════════════════════════════════

echo “”
echo -e “${CYAN}══════════════════════════════════════════════════════${NC}”
echo -e “${GREEN}  DREDEB HARDENING COMPLETE${NC}”
echo -e “${CYAN}══════════════════════════════════════════════════════${NC}”
echo “”
log_info “U2F mapping:    ${U2F_AUTHFILE}”
log_info “PAM origin:     ${PAM_ORIGIN}”
log_info “Locked user:    ${HARDEN_USER}”
echo “”
if [[ $WARN_COUNT -eq 0 ]]; then
log_info “Non-fatal warnings: 0 — clean run”
else
log_warn “Non-fatal warnings: ${WARN_COUNT} — review output above”
fi
echo “”
log_warn “System is now IMMUTABLE”
log_warn “Post-run changes require external boot media”
log_warn “Unlock with: chattr -R -i /target/path after mounting externally”
echo -e “${CYAN}══════════════════════════════════════════════════════${NC}”
echo “”