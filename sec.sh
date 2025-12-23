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
iptables -A INPUT -i wg0 -j ACCEPT
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

# PACKAGE REMOVAL/RESTRICT
------------------------------------------------------------------------------
# BINARY CLASSIFICATIONS
# ------------------------------------------------------------------------------

# TIER 1: CRITICAL - Remove if possible, these are rarely needed on hardened systems
# Network tools, remote shells, exploitation frameworks
TIER1_REMOVE_PACKAGES=(
    "nmap"
    "netcat"
    "netcat-openbsd"
    "netcat-traditional"
    "ncat"
    "socat"
    "telnet"
    "telnetd"
    "rsh-client"
    "rsh-redone-client"
    "tftp"
    "tftp-hpa"
    "ftp"
    "lftp"
    "ncftp"
    "vsftpd"
    "proftpd-basic"
    "pure-ftpd"
    "smbclient"
    "nfs-common"
    "rpcbind"
    "tcpdump"
    "wireshark"
    "tshark"
    "ettercap-common"
    "dsniff"
    "hydra"
    "medusa"
    "john"
    "hashcat"
    "aircrack-ng"
    "metasploit-framework"
    "sqlmap"
    "nikto"
    "dirb"
    "gobuster"
    "wfuzz"
    "burpsuite"
    "proxychains"
    "proxychains4"
    "tor"
    "torsocks"
    "openvpn"
    "docker.io"
    "docker-ce"
    "podman"
    "lxc"
    "lxd"
    "snapd"
    "flatpak"
)

# TIER 2: HIGH RISK - Remove unless specifically needed
# Interpreters, compilers, debuggers
TIER2_REMOVE_PACKAGES=(
    "ruby"
    "ruby-full"
    "php"
    "php-cli"
    "php-common"
    "lua5.1"
    "lua5.3"
    "lua5.4"
    "nodejs"
    "npm"
    "gdb"
    "strace"
    "ltrace"
    "valgrind"
    "gcc"
    "g++"
    "clang"
    "make"
    "build-essential"
    "nasm"
    "yasm"
    "expect"
    "tcl"
    "tclsh"
    "wish"
    "gimp"
    "imagemagick"
    "ghostscript"
    "texlive-base"
    "texlive-latex-base"
    "octave"
    "r-base"
    "julia"
    "erlang"
    "elixir"
    "haskell-platform"
    "ghc"
    "cabal-install"
    "rustc"
    "cargo"
    "golang"
    "golang-go"
    "dotnet-sdk-8.0"
    "mono-complete"
)

# TIER 3: MEDIUM RISK - Keep but strip SUID/capabilities
# Common utilities that can be abused but are often needed
TIER3_STRIP_SUID=(
    "/usr/bin/find"
    "/usr/bin/vim"
    "/usr/bin/vim.basic"
    "/usr/bin/vim.tiny"
    "/usr/bin/vi"
    "/usr/bin/view"
    "/usr/bin/vimdiff"
    "/usr/bin/rvim"
    "/usr/bin/rview"
    "/usr/bin/nano"
    "/usr/bin/pico"
    "/usr/bin/ed"
    "/usr/bin/red"
    "/usr/bin/less"
    "/usr/bin/more"
    "/usr/bin/most"
    "/usr/bin/pg"
    "/usr/bin/head"
    "/usr/bin/tail"
    "/usr/bin/cat"
    "/usr/bin/tac"
    "/usr/bin/nl"
    "/usr/bin/cut"
    "/usr/bin/sort"
    "/usr/bin/uniq"
    "/usr/bin/wc"
    "/usr/bin/awk"
    "/usr/bin/gawk"
    "/usr/bin/mawk"
    "/usr/bin/nawk"
    "/usr/bin/sed"
    "/usr/bin/grep"
    "/usr/bin/egrep"
    "/usr/bin/fgrep"
    "/usr/bin/diff"
    "/usr/bin/cmp"
    "/usr/bin/comm"
    "/usr/bin/join"
    "/usr/bin/paste"
    "/usr/bin/expand"
    "/usr/bin/unexpand"
    "/usr/bin/fold"
    "/usr/bin/fmt"
    "/usr/bin/pr"
    "/usr/bin/column"
    "/usr/bin/rev"
    "/usr/bin/tr"
    "/usr/bin/od"
    "/usr/bin/xxd"
    "/usr/bin/hexdump"
    "/usr/bin/hd"
    "/usr/bin/base32"
    "/usr/bin/base64"
    "/usr/bin/basenc"
    "/usr/bin/strings"
    "/usr/bin/file"
    "/usr/bin/tar"
    "/usr/bin/gzip"
    "/usr/bin/gunzip"
    "/usr/bin/bzip2"
    "/usr/bin/bunzip2"
    "/usr/bin/xz"
    "/usr/bin/unxz"
    "/usr/bin/zip"
    "/usr/bin/unzip"
    "/usr/bin/7z"
    "/usr/bin/7za"
    "/usr/bin/ar"
    "/usr/bin/arj"
    "/usr/bin/cpio"
    "/usr/bin/pax"
    "/usr/bin/rsync"
    "/usr/bin/dd"
    "/usr/bin/cp"
    "/usr/bin/mv"
    "/usr/bin/ln"
    "/usr/bin/install"
    "/usr/bin/curl"
    "/usr/bin/wget"
    "/usr/bin/aria2c"
    "/usr/bin/ssh"
    "/usr/bin/scp"
    "/usr/bin/sftp"
    "/usr/bin/ssh-keygen"
    "/usr/bin/ssh-keyscan"
    "/usr/bin/openssl"
    "/usr/bin/git"
    "/usr/bin/hg"
    "/usr/bin/svn"
    "/usr/bin/cvs"
    "/usr/bin/screen"
    "/usr/bin/tmux"
    "/usr/bin/script"
    "/usr/bin/env"
    "/usr/bin/time"
    "/usr/bin/timeout"
    "/usr/bin/nice"
    "/usr/bin/ionice"
    "/usr/bin/taskset"
    "/usr/bin/nohup"
    "/usr/bin/at"
    "/usr/bin/batch"
    "/usr/bin/crontab"
    "/usr/bin/watch"
    "/usr/bin/xargs"
    "/usr/bin/parallel"
    "/usr/bin/tee"
    "/usr/bin/split"
    "/usr/bin/csplit"
    "/usr/bin/shuf"
    "/usr/bin/jq"
    "/usr/bin/yq"
    "/usr/bin/xmllint"
    "/usr/bin/sqlite3"
    "/usr/bin/mysql"
    "/usr/bin/psql"
    "/usr/bin/redis-cli"
    "/usr/bin/python3"
    "/usr/bin/python"
    "/usr/bin/perl"
    "/usr/bin/awk"
    "/usr/bin/busybox"
    "/usr/bin/ash"
    "/usr/bin/dash"
    "/usr/bin/bash"
    "/usr/bin/zsh"
    "/usr/bin/fish"
    "/usr/bin/ksh"
    "/usr/bin/csh"
    "/usr/bin/tcsh"
    "/bin/bash"
    "/bin/sh"
    "/bin/dash"
    "/usr/bin/dpkg"
    "/usr/bin/apt"
    "/usr/bin/apt-get"
    "/usr/bin/apt-cache"
    "/usr/bin/pip"
    "/usr/bin/pip3"
    "/usr/bin/gem"
    "/usr/bin/npm"
    "/usr/bin/yarn"
    "/usr/bin/cpan"
    "/usr/bin/composer"
    "/usr/bin/dmesg"
    "/usr/bin/journalctl"
    "/usr/bin/systemctl"
    "/usr/bin/loginctl"
    "/usr/bin/timedatectl"
    "/usr/bin/hostnamectl"
    "/usr/bin/resolvectl"
    "/usr/bin/busctl"
    "/usr/bin/man"
    "/usr/bin/info"
    "/usr/bin/whatis"
    "/usr/bin/apropos"
    "/usr/bin/yelp"
    "/usr/bin/emacs"
    "/usr/bin/emacsclient"
    "/usr/bin/joe"
    "/usr/bin/mcedit"
    "/usr/bin/ne"
    "/usr/sbin/arp"
    "/usr/sbin/ip"
    "/usr/sbin/ifconfig"
    "/usr/sbin/route"
    "/usr/sbin/ss"
    "/usr/sbin/netstat"
    "/usr/sbin/iptables"
    "/usr/sbin/ip6tables"
    "/usr/sbin/nft"
    "/usr/sbin/tc"
    "/usr/sbin/bridge"
    "/usr/sbin/debugfs"
    "/usr/sbin/fdisk"
    "/usr/sbin/gdisk"
    "/usr/sbin/parted"
    "/usr/sbin/mkfs"
    "/usr/sbin/mount"
    "/usr/sbin/umount"
    "/usr/sbin/losetup"
    "/usr/sbin/dmsetup"
    "/usr/sbin/lvm"
    "/usr/sbin/lvs"
    "/usr/sbin/vgs"
    "/usr/sbin/pvs"
    "/usr/sbin/cryptsetup"
    "/usr/sbin/chroot"
    "/usr/sbin/setcap"
    "/usr/sbin/getcap"
    "/usr/sbin/capsh"
)

# Interpreters - restrict capabilities but keep for system scripts
INTERPRETERS=(
    "/usr/bin/python3"
    "/usr/bin/python"
    "/usr/bin/perl"
    "/usr/bin/ruby"
    "/usr/bin/php"
    "/usr/bin/lua"
    "/usr/bin/lua5.1"
    "/usr/bin/lua5.3"
    "/usr/bin/lua5.4"
    "/usr/bin/node"
    "/usr/bin/nodejs"
    "/usr/bin/tclsh"
    "/usr/bin/wish"
    "/usr/bin/gawk"
    "/usr/bin/awk"
    "/usr/bin/mawk"
    "/usr/bin/nawk"
)

# All GTFOBins for comprehensive APT blocking
ALL_GTFOBINS=(
    "7z"
    "aa-exec"
    "ab"
    "agetty"
    "alpine"
    "ansible-playbook"
    "ansible-test"
    "aoss"
    "apache2ctl"
    "apt"
    "apt-get"
    "ar"
    "aria2c"
    "arj"
    "arp"
    "as"
    "ascii-xfr"
    "ascii85"
    "ash"
    "aspell"
    "at"
    "atobm"
    "awk"
    "aws"
    "base32"
    "base58"
    "base64"
    "basenc"
    "basez"
    "bash"
    "batcat"
    "bc"
    "bconsole"
    "bpftrace"
    "bridge"
    "bundle"
    "bundler"
    "busctl"
    "busybox"
    "byebug"
    "bzip2"
    "c89"
    "c99"
    "cabal"
    "cancel"
    "capsh"
    "cat"
    "cdist"
    "certbot"
    "check_by_ssh"
    "check_cups"
    "check_log"
    "check_memory"
    "check_raid"
    "check_ssl_cert"
    "check_statusfile"
    "chmod"
    "choom"
    "chown"
    "chroot"
    "clamscan"
    "cmp"
    "cobc"
    "column"
    "comm"
    "composer"
    "cowsay"
    "cowthink"
    "cp"
    "cpan"
    "cpio"
    "cpulimit"
    "crash"
    "crontab"
    "csh"
    "csplit"
    "csvtool"
    "cupsfilter"
    "curl"
    "cut"
    "dash"
    "date"
    "dc"
    "dd"
    "debugfs"
    "dialog"
    "diff"
    "dig"
    "distcc"
    "dmesg"
    "dmidecode"
    "dmsetup"
    "dnf"
    "docker"
    "dos2unix"
    "dosbox"
    "dotnet"
    "dpkg"
    "dstat"
    "dvips"
    "easy_install"
    "eb"
    "ed"
    "efax"
    "elvish"
    "emacs"
    "enscript"
    "env"
    "eqn"
    "espeak"
    "ex"
    "exiftool"
    "expand"
    "expect"
    "facter"
    "file"
    "find"
    "finger"
    "fish"
    "flock"
    "fmt"
    "fold"
    "fping"
    "ftp"
    "gawk"
    "gcc"
    "gcloud"
    "gcore"
    "gdb"
    "gem"
    "genie"
    "genisoimage"
    "ghc"
    "ghci"
    "gimp"
    "ginsh"
    "git"
    "grc"
    "grep"
    "gtester"
    "gzip"
    "hd"
    "head"
    "hexdump"
    "highlight"
    "hping3"
    "iconv"
    "iftop"
    "install"
    "ionice"
    "ip"
    "irb"
    "ispell"
    "jjs"
    "joe"
    "join"
    "journalctl"
    "jq"
    "jrunscript"
    "jtag"
    "julia"
    "knife"
    "ksh"
    "ksshell"
    "ksu"
    "kubectl"
    "latex"
    "latexmk"
    "ld.so"
    "ldconfig"
    "less"
    "lftp"
    "links"
    "ln"
    "loginctl"
    "logsave"
    "look"
    "lp"
    "ltrace"
    "lua"
    "lualatex"
    "luatex"
    "lwp-download"
    "lwp-request"
    "mail"
    "make"
    "man"
    "mawk"
    "minicom"
    "more"
    "mosquitto"
    "mount"
    "msfconsole"
    "msgattrib"
    "msgcat"
    "msgconv"
    "msgfilter"
    "msgmerge"
    "msguniq"
    "mtr"
    "multitime"
    "mv"
    "mysql"
    "nano"
    "nasm"
    "nawk"
    "nc"
    "ncdu"
    "ncftp"
    "neofetch"
    "nft"
    "nice"
    "nl"
    "nm"
    "nmap"
    "node"
    "nohup"
    "npm"
    "nroff"
    "nsenter"
    "ntpdate"
    "octave"
    "od"
    "openssl"
    "openvpn"
    "openvt"
    "opkg"
    "pandoc"
    "paste"
    "pax"
    "pdb"
    "pdflatex"
    "pdftex"
    "perf"
    "perl"
    "perlbug"
    "pexec"
    "pg"
    "php"
    "pic"
    "pico"
    "pidstat"
    "pip"
    "pkexec"
    "pkg"
    "posh"
    "pr"
    "pry"
    "psftp"
    "psql"
    "ptx"
    "puppet"
    "pwsh"
    "python"
    "rake"
    "rc"
    "readelf"
    "red"
    "redcarpet"
    "redis"
    "restic"
    "rev"
    "rlogin"
    "rlwrap"
    "rpm"
    "rpmdb"
    "rpmquery"
    "rpmverify"
    "rsync"
    "rtorrent"
    "ruby"
    "run-mailcap"
    "run-parts"
    "runscript"
    "rview"
    "rvim"
    "sash"
    "scanmem"
    "scp"
    "screen"
    "script"
    "scrot"
    "sed"
    "service"
    "setarch"
    "setfacl"
    "setlock"
    "sftp"
    "sg"
    "shuf"
    "slsh"
    "smbclient"
    "snap"
    "socat"
    "socket"
    "soelim"
    "softlimit"
    "sort"
    "split"
    "sqlite3"
    "sqlmap"
    "ss"
    "ssh"
    "ssh-agent"
    "ssh-keygen"
    "ssh-keyscan"
    "sshpass"
    "start-stop-daemon"
    "stdbuf"
    "strace"
    "strings"
    "su"
    "sudo"
    "sysctl"
    "systemctl"
    "systemd-resolve"
    "tac"
    "tail"
    "tar"
    "task"
    "taskset"
    "tasksh"
    "tbl"
    "tclsh"
    "tcpdump"
    "tdbtool"
    "tee"
    "telnet"
    "terraform"
    "tex"
    "tftp"
    "tic"
    "time"
    "timedatectl"
    "timeout"
    "tmate"
    "tmux"
    "top"
    "torify"
    "torsocks"
    "troff"
    "tshark"
    "ul"
    "unexpand"
    "uniq"
    "unshare"
    "unsquashfs"
    "unzip"
    "update-alternatives"
    "uudecode"
    "uuencode"
    "vagrant"
    "valgrind"
    "varnishncsa"
    "vi"
    "view"
    "vigr"
    "vim"
    "vimdiff"
    "vipw"
    "virsh"
    "volatility"
    "w3m"
    "wall"
    "watch"
    "wc"
    "wget"
    "whiptail"
    "whois"
    "wireshark"
    "wish"
    "xargs"
    "xdg-user-dir"
    "xdotool"
    "xelatex"
    "xetex"
    "xmodmap"
    "xmore"
    "xpad"
    "xxd"
    "xz"
    "yarn"
    "yash"
    "yelp"
    "yum"
    "zathura"
    "zip"
    "zsh"
    "zsoelim"
    "zypper"
)

# Packages to block from being installed (APT pinning)
# These provide dangerous GTFOBins capabilities
BLOCK_PACKAGES=(
    "nmap"
    "netcat"
    "netcat-openbsd"
    "netcat-traditional"
    "ncat"
    "socat"
    "telnet"
    "telnetd"
    "rsh-client"
    "rsh-redone-client"
    "tftp"
    "tftp-hpa"
    "ftp"
    "lftp"
    "ncftp"
    "vsftpd"
    "proftpd-basic"
    "pure-ftpd"
    "smbclient"
    "tcpdump"
    "wireshark"
    "wireshark-qt"
    "wireshark-gtk"
    "tshark"
    "ettercap-common"
    "ettercap-graphical"
    "dsniff"
    "hydra"
    "hydra-gtk"
    "medusa"
    "john"
    "hashcat"
    "aircrack-ng"
    "metasploit-framework"
    "sqlmap"
    "nikto"
    "dirb"
    "gobuster"
    "wfuzz"
    "proxychains"
    "proxychains4"
    "tor"
    "torsocks"
    "docker.io"
    "docker-ce"
    "docker-ce-cli"
    "containerd.io"
    "podman"
    "lxc"
    "lxd"
    "lxd-client"
    "snapd"
    "flatpak"
    "gdb"
    "strace"
    "ltrace"
    "valgrind"
    "radare2"
    "binwalk"
    "foremost"
    "volatility"
    "autopsy"
    "sleuthkit"
    "yersinia"
    "macchanger"
    "arpwatch"
    "arping"
    "hping3"
    "fping"
    "masscan"
    "zmap"
    "unicornscan"
    "nbtscan"
    "enum4linux"
    "smbmap"
    "crackmapexec"
    "impacket-scripts"
    "python3-impacket"
    "responder"
    "bettercap"
    "mitmproxy"
    "sslstrip"
    "beef-xss"
    "set"
    "social-engineer-toolkit"
    "maltego"
    "recon-ng"
    "theharvester"
    "spiderfoot"
    "metagoofil"
    "exiftool"
    "steghide"
    "outguess"
    "stegosuite"
    "openstego"
    "ruby"
    "ruby-full"
    "php"
    "php-cli"
    "php-common"
    "lua5.1"
    "lua5.3"
    "lua5.4"
    "luajit"
    "nodejs"
    "npm"
    "expect"
    "tcl"
    "tk"
    "gimp"
    "imagemagick"
    "ghostscript"
    "octave"
    "r-base"
    "julia"
    "erlang"
    "elixir"
    "ghc"
    "cabal-install"
    "rustc"
    "cargo"
    "golang"
    "golang-go"
    "mono-complete"
    "dotnet-sdk-6.0"
    "dotnet-sdk-7.0"
    "dotnet-sdk-8.0"
)
 ------------------------------------------------------------------------------
# PREFLIGHT CHECKS
# ------------------------------------------------------------------------------

preflight_checks() {
    log_info "Running preflight checks..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    if ! id dev &>/dev/null; then
        log_error "Primary user dev does not exist"
        exit 1
    fi
    
    # Create backup directory
    mkdir -p /var/backups/gtfobins-hardening
    chmod 700 /var/backups/gtfobins-hardening
    
    # Create log file
    touch /var/log/gtfobins-hardening.log
    chmod 600 /var/log/gtfobins-hardening.log
    
    log_success "Preflight checks passed"
}

# ------------------------------------------------------------------------------
# SECTION 1: REMOVE DANGEROUS PACKAGES
# ------------------------------------------------------------------------------

remove_dangerous_packages() {
    log ""
    log "============================================================================"
    log "SECTION 1: REMOVING DANGEROUS PACKAGES"
    log "============================================================================"
    
    local removed_count=0
    local failed_count=0
    
    # Tier 1: Critical removals
    log_info "Processing Tier 1 (Critical) packages..."
    for pkg in "${TIER1_REMOVE_PACKAGES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null 2>&1; then
            log_warn "Removing dangerous package: $pkg"
            if apt-get purge -y "$pkg" >> /var/log/gtfobins-hardening.log 2>&1; then
                ((removed_count++))
                log_success "Removed: $pkg"
            else
                ((failed_count++))
                log_error "Failed to remove: $pkg"
            fi
        fi
    done
    
    # Tier 2: High risk removals (optional - comment out if you need these)
    log_info "Processing Tier 2 (High Risk) packages..."
    for pkg in "${TIER2_REMOVE_PACKAGES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null 2>&1; then
            log_warn "Removing high-risk package: $pkg"
            if apt-get purge -y "$pkg" >> /var/log/gtfobins-hardening.log 2>&1; then
                ((removed_count++))
                log_success "Removed: $pkg"
            else
                ((failed_count++))
                log_error "Failed to remove: $pkg"
            fi
        fi
    done
    
    # Clean up orphaned packages
    log_info "Cleaning orphaned packages..."
    apt-get autoremove -y >> /var/log/gtfobins-hardening.log 2>&1
    apt-get autoclean >> /var/log/gtfobins-hardening.log 2>&1
    
    log_success "Package removal complete: $removed_count removed, $failed_count failed"
}

# ------------------------------------------------------------------------------
# SECTION 2: APT PACKAGE BLOCKING
# ------------------------------------------------------------------------------

block_package_installation() {
    log ""
    log "============================================================================"
    log "SECTION 2: BLOCKING DANGEROUS PACKAGE INSTALLATION"
    log "============================================================================"
    
    local apt_prefs="/etc/apt/preferences.d/gtfobins-block"
    
    # Backup existing if present
    if [[ -f "$apt_prefs" ]]; then
        cp "$apt_prefs" "${BACKUP_DIR}/gtfobins-block.bak"
    fi
    
    log_info "Creating APT preferences to block dangerous packages..."
    
    cat > "$apt_prefs" << 'APTEOF'
# =============================================================================
# GTFOBins Package Blocking
# =============================================================================
# This file prevents installation of packages commonly used for exploitation.
# Generated by GTFOBins Protection Module
# To allow a specific package: Create a higher-priority pin in another file
# =============================================================================

APTEOF
    
    for pkg in "${BLOCK_PACKAGES[@]}"; do
        cat >> "$apt_prefs" << EOF
# Block: $pkg
Package: $pkg
Pin: release *
Pin-Priority: -1

EOF
    done
    
    chmod 644 "$apt_prefs"
    
    log_success "APT package blocking configured: ${#BLOCK_PACKAGES[@]} packages blocked"
    log_info "Blocked packages list saved to: $apt_prefs"
}

# ------------------------------------------------------------------------------
# SECTION 3: STRIP SUID/SGID BITS
# ------------------------------------------------------------------------------

strip_suid_sgid() {
    log ""
    log "============================================================================"
    log "SECTION 3: STRIPPING SUID/SGID BITS FROM DANGEROUS BINARIES"
    log "============================================================================"
    
    local stripped_count=0
    
    for binary in "${TIER3_STRIP_SUID[@]}"; do
        if [[ -f "$binary" ]]; then
            local perms
            perms=$(stat -c '%a' "$binary" 2>/dev/null)
            
            # Check if SUID (4xxx) or SGID (2xxx) is set
            if [[ "$perms" =~ ^[4267] ]]; then
                log_warn "Stripping SUID/SGID from: $binary (was: $perms)"
                chmod u-s,g-s "$binary"
                ((stripped_count++))
                log_success "Stripped: $binary"
            fi
        fi
    done
    
    # Also scan system-wide for any SUID/SGID binaries we might have missed
    log_info "Scanning for additional SUID/SGID binaries..."
    
    while IFS= read -r -d '' binary; do
        local basename
        basename=$(basename "$binary")
        
        # Check if it's in our known list or if it matches GTFOBins
        for gtfo in "${ALL_GTFOBINS[@]}"; do
            if [[ "$basename" == "$gtfo" ]] || [[ "$basename" == "${gtfo}."* ]]; then
                log_warn "Found additional SUID/SGID GTFOBin: $binary"
                chmod u-s,g-s "$binary"
                ((stripped_count++))
                break
            fi
        done
    done < <(find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null)
    
    log_success "SUID/SGID stripping complete: $stripped_count binaries modified"
}

# ------------------------------------------------------------------------------
# SECTION 4: STRIP CAPABILITIES FROM INTERPRETERS
# ------------------------------------------------------------------------------

strip_capabilities() {
    log ""
    log "============================================================================"
    log "SECTION 4: STRIPPING CAPABILITIES FROM INTERPRETERS"
    log "============================================================================"
    
    local stripped_count=0
    
    for interp in "${INTERPRETERS[@]}"; do
        if [[ -f "$interp" ]]; then
            local caps
            caps=$(getcap "$interp" 2>/dev/null)
            
            if [[ -n "$caps" ]]; then
                log_warn "Stripping capabilities from: $interp"
                log_info "  Was: $caps"
                setcap -r "$interp" 2>/dev/null || true
                ((stripped_count++))
                log_success "Stripped capabilities: $interp"
            fi
        fi
    done
    
    # Scan for any binaries with dangerous capabilities
    log_info "Scanning for binaries with capabilities..."
    
    while IFS= read -r line; do
        local binary
        binary=$(echo "$line" | awk '{print $1}')
        local basename
        basename=$(basename "$binary")
        
        for gtfo in "${ALL_GTFOBINS[@]}"; do
            if [[ "$basename" == "$gtfo" ]] || [[ "$basename" == "${gtfo}."* ]]; then
                log_warn "Found GTFOBin with capabilities: $line"
                setcap -r "$binary" 2>/dev/null || true
                ((stripped_count++))
                break
            fi
        done
    done < <(getcap -r /usr /bin /sbin 2>/dev/null | grep -v "^$")
    
    log_success "Capability stripping complete: $stripped_count binaries modified"
}

# ------------------------------------------------------------------------------
# SECTION 5: SUDO RESTRICTIONS
# ------------------------------------------------------------------------------

configure_sudo_restrictions() {
    log ""
    log "============================================================================"
    log "SECTION 5: CONFIGURING SUDO RESTRICTIONS"
    log "============================================================================"
    
    local sudoers_file="/etc/sudoers.d/gtfobins-deny"
    
    # Backup existing if present
    if [[ -f "$sudoers_file" ]]; then
        cp "$sudoers_file" "${BACKUP_DIR}/gtfobins-deny.bak"
    fi
    
    log_info "Creating sudo restrictions for dangerous commands..."
    
    # Build the command alias - only include binaries that exist
    local cmd_list=""
    local count=0
    
    for gtfo in "${ALL_GTFOBINS[@]}"; do
        local path
        path=$(command -v "$gtfo" 2>/dev/null) || continue
        
        if [[ -n "$path" ]] && [[ -x "$path" ]]; then
            if [[ $count -gt 0 ]]; then
                cmd_list="${cmd_list}, "
            fi
            cmd_list="${cmd_list}${path}"
            ((count++))
        fi
    done
    
    if [[ $count -gt 0 ]]; then
        cat > "$sudoers_file" << EOF
# =============================================================================
# GTFOBins Sudo Restrictions
# =============================================================================
# Prevents regular users from running potentially dangerous commands via sudo.
# Root can still use these commands directly.
# Generated by GTFOBins Protection Module
# =============================================================================

# Command alias for dangerous binaries
Cmnd_Alias GTFOBINS_DANGEROUS = ${cmd_list}

# Deny these commands for all users except root
# Comment out the line below if you need specific users to access these
ALL, !root ALL = !GTFOBINS_DANGEROUS
EOF
        
        chmod 440 "$sudoers_file"
        
        # Validate sudoers syntax
        if visudo -c -f "$sudoers_file" >> /var/log/gtfobins-hardening.log 2>&1; then
            log_success "Sudo restrictions configured: $count commands restricted"
        else
            log_error "Sudoers syntax error! Removing invalid file."
            rm -f "$sudoers_file"
        fi
    else
        log_warn "No GTFOBins found on system to restrict"
    fi
}

# ------------------------------------------------------------------------------
# SECTION 6: AUDITD RULES
# ------------------------------------------------------------------------------

configure_audit_rules() {
    log ""
    log "============================================================================"
    log "SECTION 6: CONFIGURING AUDITD MONITORING RULES"
    log "============================================================================"
    
    # Check if auditd is available
    if ! command -v auditctl &>/dev/null; then
        log_warn "auditd not installed, skipping audit rules"
        log_info "Install with: apt-get install auditd"
        return
    fi
    
    local audit_rules="/etc/audit/rules.d/gtfobins.rules"
    
    # Backup existing if present
    if [[ -f "$audit_rules" ]]; then
        cp "$audit_rules" "${BACKUP_DIR}/gtfobins-audit.rules.bak"
    fi
    
    log_info "Creating auditd rules for GTFOBins monitoring..."
    
    cat > "$audit_rules" << 'AUDITEOF'
# =============================================================================
# GTFOBins Audit Rules
# =============================================================================
# Monitor execution of binaries commonly used in exploitation
# Key: gtfobins - use ausearch -k gtfobins to find events
# Generated by GTFOBins Protection Module
# =============================================================================

# Network reconnaissance tools
-w /usr/bin/nmap -p x -k gtfobins_recon
-w /usr/bin/nc -p x -k gtfobins_netcat
-w /usr/bin/ncat -p x -k gtfobins_netcat
-w /usr/bin/netcat -p x -k gtfobins_netcat
-w /usr/bin/socat -p x -k gtfobins_netcat
-w /usr/bin/telnet -p x -k gtfobins_remote
-w /usr/bin/ftp -p x -k gtfobins_remote
-w /usr/bin/tftp -p x -k gtfobins_remote
-w /usr/bin/curl -p x -k gtfobins_transfer
-w /usr/bin/wget -p x -k gtfobins_transfer
-w /usr/bin/scp -p x -k gtfobins_transfer
-w /usr/bin/sftp -p x -k gtfobins_transfer
-w /usr/bin/rsync -p x -k gtfobins_transfer

# Interpreters (potential shell escape)
-w /usr/bin/python -p x -k gtfobins_interpreter
-w /usr/bin/python3 -p x -k gtfobins_interpreter
-w /usr/bin/perl -p x -k gtfobins_interpreter
-w /usr/bin/ruby -p x -k gtfobins_interpreter
-w /usr/bin/php -p x -k gtfobins_interpreter
-w /usr/bin/lua -p x -k gtfobins_interpreter
-w /usr/bin/node -p x -k gtfobins_interpreter
-w /usr/bin/nodejs -p x -k gtfobins_interpreter
-w /usr/bin/tclsh -p x -k gtfobins_interpreter

# Editors with shell escape
-w /usr/bin/vim -p x -k gtfobins_editor
-w /usr/bin/vi -p x -k gtfobins_editor
-w /usr/bin/nano -p x -k gtfobins_editor
-w /usr/bin/emacs -p x -k gtfobins_editor
-w /usr/bin/ed -p x -k gtfobins_editor
-w /usr/bin/less -p x -k gtfobins_pager
-w /usr/bin/more -p x -k gtfobins_pager
-w /usr/bin/man -p x -k gtfobins_pager

# Compilers and debuggers
-w /usr/bin/gcc -p x -k gtfobins_compiler
-w /usr/bin/g++ -p x -k gtfobins_compiler
-w /usr/bin/make -p x -k gtfobins_compiler
-w /usr/bin/gdb -p x -k gtfobins_debugger
-w /usr/bin/strace -p x -k gtfobins_debugger
-w /usr/bin/ltrace -p x -k gtfobins_debugger

# Container/virtualization escape vectors
-w /usr/bin/docker -p x -k gtfobins_container
-w /usr/bin/podman -p x -k gtfobins_container
-w /usr/bin/lxc -p x -k gtfobins_container
-w /usr/bin/nsenter -p x -k gtfobins_container
-w /usr/bin/unshare -p x -k gtfobins_container
-w /usr/bin/chroot -p x -k gtfobins_container

# Privilege escalation vectors
-w /usr/bin/pkexec -p x -k gtfobins_privesc
-w /usr/bin/at -p x -k gtfobins_privesc
-w /usr/bin/crontab -p x -k gtfobins_privesc
-w /usr/bin/screen -p x -k gtfobins_privesc
-w /usr/bin/tmux -p x -k gtfobins_privesc

# System manipulation
-w /usr/bin/mount -p x -k gtfobins_system
-w /usr/bin/umount -p x -k gtfobins_system
-w /usr/sbin/debugfs -p x -k gtfobins_system
-w /usr/sbin/dmsetup -p x -k gtfobins_system

# Archive tools (file exfiltration)
-w /usr/bin/tar -p x -k gtfobins_archive
-w /usr/bin/zip -p x -k gtfobins_archive
-w /usr/bin/gzip -p x -k gtfobins_archive
-w /usr/bin/bzip2 -p x -k gtfobins_archive
-w /usr/bin/xz -p x -k gtfobins_archive

# Git (can be used for shell escape)
-w /usr/bin/git -p x -k gtfobins_git

# Watch for capability changes
-w /usr/sbin/setcap -p x -k gtfobins_caps
-w /usr/sbin/getcap -p x -k gtfobins_caps

AUDITEOF
    
    chmod 640 "$audit_rules"
    
    # Reload audit rules
    if systemctl is-active --quiet auditd; then
        log_info "Reloading auditd rules..."
        augenrules --load >> /var/log/gtfobins-hardening.log 2>&1 || auditctl -R "$audit_rules" >> /var/log/gtfobins-hardening.log 2>&1
        log_success "Audit rules loaded"
    else
        log_warn "auditd is not running. Start with: systemctl start auditd"
    fi
    
    log_success "Audit rules configured at: $audit_rules"
}

# ------------------------------------------------------------------------------
# SECTION 7: APPARMOR PROFILES (Optional - Restrictive)
# ------------------------------------------------------------------------------

configure_apparmor_profiles() {
    log ""
    log "============================================================================"
    log "SECTION 7: CONFIGURING APPARMOR DENY PROFILES"
    log "============================================================================"
    
    # Check if AppArmor is available
    if ! command -v aa-status &>/dev/null; then
        log_warn "AppArmor not installed, skipping profiles"
        return
    fi
    
    if ! aa-status --enabled 2>/dev/null; then
        log_warn "AppArmor not enabled, skipping profiles"
        return
    fi
    
    local apparmor_dir="/etc/apparmor.d"
    local profiles_created=0
    
    # Create deny profiles for the most dangerous network tools
    # These completely block the binaries from running
    
    local deny_binaries=(
        "/usr/bin/nmap"
        "/usr/bin/nc"
        "/usr/bin/ncat"
        "/usr/bin/netcat"
        "/usr/bin/socat"
        "/usr/bin/telnet"
        "/usr/bin/tftp"
        "/usr/sbin/tcpdump"
        "/usr/bin/wireshark"
        "/usr/bin/tshark"
    )
    
    for binary in "${deny_binaries[@]}"; do
        if [[ -f "$binary" ]]; then
            local profile_name
            profile_name=$(echo "$binary" | tr '/' '.')
            profile_name="${profile_name:1}"  # Remove leading dot
            
            local profile_path="${apparmor_dir}/${profile_name}"
            
            log_info "Creating AppArmor deny profile for: $binary"
            
            cat > "$profile_path" << EOF
# AppArmor deny profile for $binary
# Generated by GTFOBins Protection Module
# This profile completely blocks execution of the binary

$binary {
    # Deny all access
    deny /** rwklx,
    deny @{PROC}/** rwklx,
    deny @{sys}/** rwklx,
}
EOF
            
            chmod 644 "$profile_path"
            ((profiles_created++))
            
            # Load the profile
            if apparmor_parser -r "$profile_path" >> /var/log/gtfobins-hardening.log 2>&1; then
                log_success "Loaded AppArmor profile: $profile_name"
            else
                log_error "Failed to load profile: $profile_name"
            fi
        fi
    done
    
    log_success "AppArmor profiles created: $profiles_created"
}

# ------------------------------------------------------------------------------
# SECTION 8: CREATE PLACEHOLDER BLOCKERS
# ------------------------------------------------------------------------------

create_placeholder_blockers() {
    log ""
    log "============================================================================"
    log "SECTION 8: CREATING PLACEHOLDER BLOCKERS FOR UNINSTALLED BINARIES"
    log "============================================================================"
    
    # These are the most dangerous tools - if not installed, create immutable
    # empty files to prevent installation from placing executables there
    
    local dangerous_paths=(
        "/usr/bin/nmap"
        "/usr/bin/nc"
        "/usr/bin/ncat"
        "/usr/bin/netcat"
        "/usr/bin/socat"
        "/usr/bin/msfconsole"
        "/usr/bin/msfvenom"
        "/usr/bin/hydra"
        "/usr/bin/medusa"
        "/usr/bin/john"
        "/usr/bin/hashcat"
        "/usr/bin/sqlmap"
        "/usr/bin/nikto"
        "/usr/bin/aircrack-ng"
        "/usr/bin/ettercap"
        "/usr/bin/bettercap"
        "/usr/bin/responder"
    )
    
    local blocked_count=0
    
    for binary_path in "${dangerous_paths[@]}"; do
        if [[ ! -e "$binary_path" ]]; then
            log_info "Creating blocker for: $binary_path"
            
            # Create an empty file
            touch "$binary_path"
            
            # Remove all permissions
            chmod 000 "$binary_path"
            
            # Make it immutable
            chattr +i "$binary_path" 2>/dev/null || true
            
            ((blocked_count++))
            log_success "Blocked: $binary_path"
        fi
    done
    
    log_success "Placeholder blockers created: $blocked_count"
}

# ------------------------------------------------------------------------------
# SECTION 9: RESTRICT /tmp AND /dev/shm EXECUTION
# ------------------------------------------------------------------------------

restrict_temp_execution() {
    log ""
    log "============================================================================"
    log "SECTION 9: RESTRICTING EXECUTION IN TEMP DIRECTORIES"
    log "============================================================================"
    
    # This should already be in fstab from filesystem hardening module,
    # but we'll verify and add if missing
    
    local fstab="/etc/fstab"
    local modified=false
    
    # Backup fstab
    cp "$fstab" "${BACKUP_DIR}/fstab.bak"
    
    # Check /tmp mount options
    if grep -qE "^\s*/tmp\s+" "$fstab"; then
        if ! grep -qE "^\s*/tmp\s+.*noexec" "$fstab"; then
            log_warn "/tmp missing noexec option"
            sed -i '/^\s*\/tmp\s/s/defaults/defaults,noexec,nosuid,nodev/' "$fstab"
            modified=true
        fi
    else
        log_info "Adding /tmp entry with noexec"
        echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0" >> "$fstab"
        modified=true
    fi
    
    # Check /dev/shm mount options
    if grep -qE "^\s*/dev/shm\s+" "$fstab"; then
        if ! grep -qE "^\s*/dev/shm\s+.*noexec" "$fstab"; then
            log_warn "/dev/shm missing noexec option"
            sed -i '/^\s*\/dev\/shm\s/s/defaults/defaults,noexec,nosuid,nodev/' "$fstab"
            modified=true
        fi
    else
        log_info "Adding /dev/shm entry with noexec"
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> "$fstab"
        modified=true
    fi
    
    if $modified; then
        log_success "Temp directory restrictions configured"
        log_warn "Reboot or remount required for changes to take effect"
        log_info "  To remount now: mount -o remount /tmp && mount -o remount /dev/shm"
    else
        log_success "Temp directories already properly restricted"
    fi
}
# PACKAGE INSTALLATION
apt install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra rsyslog chrony libpam-tmpdir acct rkhunter chkrootkit debsums unzip patch pavucontrol pipewire pipewire-audio-client-libraries pipewire-pulse wireplumber lynis macchanger unhide tcpd fonts-liberation gnome-core gnome-terminal gnome-brave-icon-theme gdebi-core opensnitch python3-opensnitch*

SERVICES_TO_ENABLE=(
"systemd-journald.service"
"systemd-udevd.service"
"systemd-logind.service"
"dbus.service"
"polkit.service"
"gdm.service"
"NetworkManager.service"
"NetworkManager-wait-online.service"
"wg-quick@wg0.service"
"pipewire.socket"
"pipewire-pulse.socket"
"wireplumber.service"
"opensnitchd.service"
"iptables-restore.service"
"pcscd.service"
"pcscd.socket"
"systemd-timesyncd.service"
"upower.service"
"thermald.service"
"systemd-logind.service"
)

for svc in "${SERVICES_TO_ENABLE[@]}"; do
    echo "    [+] Enabling ${svc}"
    systemctl unmask "$svc" 2>/dev/null || true
    systemctl enable "$svc" 2>/dev/null || true
done

# PAM/U2F
pamu2fcfg -u dev > /etc/security/u2f_keys
chmod 0400 /etc/security/u2f_keys
chown root:root /etc/security/u2f_keys
chattr +i /etc/security/u2f_keys
mkdir -p /var/log/faillock
chmod 0700 /var/log/faillock
rm -f /etc/pam.d/remote
rm -f /etc/pam.d/cron

if ! getent group wheel &>/dev/null; then
    groupadd wheel
fi
usermod -aG wheel dev

cat > /etc/security/faillock.conf <<'EOF'
deny = 3
unlock_time = 900
silent
EOF
chattr +i /etc/security/faillock.conf

cat >/etc/pam.d/chfn <<'EOF'
#%PAM-1.0
auth      sufficient  pam_u2f.so authfile=/etc/security/u2f_keys
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat >/etc/pam.d/chpasswd <<'EOF'
#%PAM-1.0
password  include     common-password
EOF

cat >/etc/pam.d/chsh <<'EOF'
#%PAM-1.0
auth      required    pam_shells.so
auth      sufficient  pam_u2f.so authfile=/etc/security/u2f_keys
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat > /etc/pam.d/common-auth <<'EOF'
#%PAM-1.0
auth      required    pam_faildelay.so delay=3000000
auth      required    pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth     [success=1 default=ignore] pam_u2f.so authfile=/etc/security/u2f_keys
auth      requisite   pam_deny.so
auth      required    pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
EOF

cat >/etc/pam.d/common-account <<'EOF'
#%PAM-1.0
account   required    pam_access.so accessfile=/etc/security/access.conf
account   required    pam_faillock.so
account   required    pam_nologin.so
EOF

cat >/etc/pam.d/common-password <<'EOF'
#%PAM-1.0
password  requisite   pam_deny.so
EOF

cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session   required    pam_namespace.so
session   required    pam_limits.so
session   required    pam_umask.so umask=0077
session   required    pam_env.so readenv=1 user_readenv=0
session   required    pam_unix.so
session   optional    pam_systemd.so
EOF

cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session   required    pam_namespace.so
session   required    pam_limits.so
session   required    pam_umask.so umask=0077
session   required    pam_env.so readenv=1 user_readenv=0
session   required    pam_unix.so
session   optional    pam_systemd.so
EOF

cat >/etc/pam.d/sudo <<'EOF'
#%PAM-1.0
auth       required   pam_u2f.so authfile=/etc/security/u2f_keys
auth       required   pam_faillock.so preauth silent deny=3 unlock_time=900
account    include    common-account
session    required   pam_limits.so
session    include    common-session
EOF

cat >/etc/pam.d/sudo-i <<'EOF'
#%PAM-1.0
auth       required   pam_u2f.so authfile=/etc/security/u2f_keys
auth       required   pam_faillock.so preauth silent deny=3 unlock_time=900
account    include    common-account
session    required   pam_limits.so
session    include    common-session
EOF

cat >/etc/pam.d/su <<'EOF'
#%PAM-1.0
auth       required     pam_wheel.so use_uid group=wheel deny
auth       sufficient   pam_u2f.so authfile=/etc/security/u2f_keys
auth       include      common-auth
account    include      common-account
session    include      common-session
EOF

cat >/etc/pam.d/su-l <<'EOF'
#%PAM-1.0
auth       required     pam_wheel.so use_uid group=wheel deny
auth       sufficient   pam_u2f.so authfile=/etc/security/u2f_keys
auth       include      common-auth
account    include      common-account
session    include      common-session
EOF

cat >/etc/pam.d/sshd <<'EOF'
#%PAM-1.0
auth       required    pam_deny.so
account    required    pam_deny.so
password   required    pam_deny.so
session    required    pam_deny.so
EOF

cat >/etc/pam.d/other <<'EOF'
#%PAM-1.0
auth       required    pam_deny.so
account    required    pam_deny.so
password   required    pam_deny.so
session    required    pam_deny.so
EOF

cat >/etc/pam.d/login <<'EOF'
#%PAM-1.0
auth       required    pam_securetty.so
auth       required    pam_nologin.so
auth       include     common-auth
account    include     common-account
session    required    pam_limits.so
session    required    pam_loginuid.so
session    include     common-session
EOF

cat >/etc/pam.d/newusers <<'EOF'
#%PAM-1.0
password  include     common-password
EOF

cat >/etc/pam.d/passwd <<'EOF'
#%PAM-1.0
password  include     common-password
EOF

cat >/etc/pam.d/runuser <<'EOF'
#%PAM-1.0
auth      sufficient  pam_u2f.so authfile=/etc/security/u2f_keys
session   required    pam_limits.so
session   required    pam_unix.so
EOF

cat >/etc/pam.d/runuser-l <<'EOF'
#%PAM-1.0
auth      include     runuser
session   include     runuser
EOF

# SUDO
cat >/etc/sudoers <<'EOF'
Defaults    env_reset
Defaults    env_clear
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
Defaults    !visiblepw
Defaults    !rootpw
Defaults    !runaspw
Defaults    !targetpw
Defaults    mail_badpass
Defaults    mail_no_user
Defaults    mail_no_perms
Defaults    !env_editor
Defaults    editor=/bin/false

root  ALL=(ALL) ALL
%sudo ALL=(ALL) ALL
EOF
chmod 0440 /etc/sudoers
chmod -R 0440 /etc/sudoers.d

# MISC HARDENING
cat >/etc/shells <<'EOF'
/bin/bash
EOF

cat >/etc/host.conf <<'EOF'
multi on
order hosts,bind
EOF

cat >/etc/security/limits.d/limits.conf <<'EOF'
*           hard    nproc         2048
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
# Single user access
+ : dev : LOCAL
+ : root : LOCAL
# Deny everyone else
- : ALL : ALL
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
# Restrict kernel pointer exposure
dev.tty.ldisc_autoload = 0
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.panic = 60
kernel.panic_on_oops = 60
kernel.perf_event_paranoid = 3
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 2
net.core.bpf_jit_harden = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.shared_media = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.shared_media = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.tcp_challenge_ack_limit = 2147483647
net.ipv4.tcp_invalid_ratelimit = 500
net.ipv4.tcp_max_syn_backlog = 20480
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.eth0.accept_ra_rtr_pref = 0
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_loose = 0
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
tmpfs    /tmp       tmpfs     size=2G,noatime,nodev,nosuid,noexec,mode=1777     0 0
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
apt install git 
git clone --depth 1 https://github.com/DXC-0/Respect-My-Internet.git
cd Respect-My-Internet
chmod +x install.sh
./install.sh
systemctl restart opensnitchd
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

rm /usr/bin/run0
rm /usr/bin/pkexec
rm /usr/bin/su
mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/00-deny-all.rules << 'EOF'
// Deny all polkit requests - hardened system
polkit.addRule(function(action, subject) {
    return polkit.Result.NO;
});
EOF

chmod 0644 /etc/polkit-1/rules.d/00-deny-all.rules


# PRIVILEGE ESCALATION MONITORING 
cat > /usr/local/bin/escalation-monitor <<'EOF'
#!/bin/bash

LOG="/var/log/escalation-monitor.log"
BASELINE_FILE="/var/lib/escalation-monitor-baseline"
MODULES_BASELINE="/var/lib/modules-baseline"

HALT_ON_VIOLATION=1

EXCLUDE_DIRS=(
    "/timeshift"
)

log_alert() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERT: $1" >> "$LOG"
    logger -t ESCALATION_MONITOR -p security.crit "$1"
}

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$LOG"
}

# Build the find exclusion string
build_exclusions() {
    local excludes=""
    for dir in "${EXCLUDE_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            excludes="$excludes -path '$dir' -prune -o"
        fi
    done
    echo "$excludes"
}

# SUID/SGID CHECK
PRUNE_PATTERN=""
for dir in "${EXCLUDE_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        PRUNE_PATTERN="$PRUNE_PATTERN -path $dir -prune -o"
    fi
done

# Get current SUID files
CURRENT_SUID=$(eval "find / -xdev $PRUNE_PATTERN \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null" | sort)
CURRENT_SUID_COUNT=$(echo "$CURRENT_SUID" | grep -c . || echo "0"
if [ ! -f "$BASELINE_FILE" ]; then
    log_info "First run - establishing SUID baseline with $CURRENT_SUID_COUNT files"
    echo "$CURRENT_SUID" > "$BASELINE_FILE"
    chmod 600 "$BASELINE_FILE"
    chattr +i "$BASELINE_FILE" 2>/dev/null || true
    log_info "Baseline files:"
    echo "$CURRENT_SUID" >> "$LOG"
else
    # Compare against baseline
    chattr -i "$BASELINE_FILE" 2>/dev/null || true
    BASELINE_SUID=$(cat "$BASELINE_FILE")
    chattr +i "$BASELINE_FILE" 2>/dev/null || true
    
# Check for new SUID files
    NEW_SUID=$(comm -23 <(echo "$CURRENT_SUID") <(echo "$BASELINE_SUID") 2>/dev/null)
    
# Check for removed SUID files
    REMOVED_SUID=$(comm -13 <(echo "$CURRENT_SUID") <(echo "$BASELINE_SUID") 2>/dev/null)
    
    if [ -n "$NEW_SUID" ] && [ "$NEW_SUID" != "" ]; then
        log_alert "NEW SUID/SGID files detected:"
        echo "$NEW_SUID" >> "$LOG"
        
        if [ $HALT_ON_VIOLATION -eq 1 ]; then
            log_alert "Halting system due to unauthorized SUID files"
            sync
            systemctl halt
        fi
    fi
    
    if [ -n "$REMOVED_SUID" ] && [ "$REMOVED_SUID" != "" ]; then
        log_info "SUID/SGID files removed (may be normal):"
        echo "$REMOVED_SUID" >> "$LOG"
        # Don't halt on removal - that's usually fine
    fi
fi

# KERNEL MODULE CHECK 
if [ -f "$MODULES_BASELINE" ]; then
    # Create temp file for current state
    CURRENT_MODULES=$(mktemp)
    find /lib/modules -name "*.ko" -type f -exec md5sum {} \; 2>/dev/null | sort > "$CURRENT_MODULES"
    
    chattr -i "$MODULES_BASELINE" 2>/dev/null || true
    BASELINE_SORTED=$(mktemp)
    sort "$MODULES_BASELINE" > "$BASELINE_SORTED"
    chattr +i "$MODULES_BASELINE" 2>/dev/null || true
    
    if ! diff -q "$CURRENT_MODULES" "$BASELINE_SORTED" >/dev/null 2>&1; then
        # Get specific changes
        CHANGES=$(diff "$BASELINE_SORTED" "$CURRENT_MODULES" 2>/dev/null | head -20)
        log_alert "Kernel modules have been modified:"
        echo "$CHANGES" >> "$LOG"
        
        if [ $HALT_ON_VIOLATION -eq 1 ]; then
            log_alert "Halting system due to kernel module tampering"
            rm -f "$CURRENT_MODULES" "$BASELINE_SORTED"
            sync
            systemctl halt
        fi
    fi
    
    rm -f "$CURRENT_MODULES" "$BASELINE_SORTED"
else
    log_info "No module baseline found - creating one"
    find /lib/modules -name "*.ko" -type f -exec md5sum {} \; 2>/dev/null | sort > "$MODULES_BASELINE"
    chmod 600 "$MODULES_BASELINE"
    chattr +i "$MODULES_BASELINE" 2>/dev/null || true
fi

# U2F AUTHENTICATION FAILURES 
if [ -f /var/log/auth.log ]; then
    # Check for recent failures (last 10 minutes)
    RECENT_FAILS=$(grep "pam_u2f.*fail" /var/log/auth.log 2>/dev/null | tail -20 | wc -l || echo "0")
    
    if [ "$RECENT_FAILS" -ge 3 ]; then
        log_alert "Multiple U2F authentication failures detected: $RECENT_FAILS"
    fi
fi

# ROOTKIT CHECK
if command -v rkhunter >/dev/null 2>&1; then
    # Only run full check once per day to avoid performance hit
    LAST_CHECK="/var/lib/rkhunter-last-check"
    CURRENT_DAY=$(date +%Y%m%d)
    
    if [ ! -f "$LAST_CHECK" ] || [ "$(cat $LAST_CHECK 2>/dev/null)" != "$CURRENT_DAY" ]; then
        log_info "Running daily rkhunter check"
        RKHUNTER_OUTPUT=$(rkhunter --check --skip-keypress --report-warnings-only 2>&1 || true)
        
        if [ -n "$RKHUNTER_OUTPUT" ]; then
            log_alert "rkhunter warnings:"
            echo "$RKHUNTER_OUTPUT" >> "$LOG"
        fi
        
        echo "$CURRENT_DAY" > "$LAST_CHECK"
    fi
fi

# CRITICAL FILE INTEGRITY 
# Check if critical files have been modified (quick hash check)
CRITICAL_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/gshadow"
    "/etc/iptables/rules.v4"
    "/etc/default/grub"
    "/etc/sudoers"
    "/etc/security/access.conf"
    "/usr/lib/sysctl.d/sysctl.conf"  
    "/etc/pam.d/common-auth"
    "/etc/pam.d/sudo" 
    "/etc/security/limits.d/limits.conf"
    "/etc/shells"
    "/etc/securetty”
    "/etc/fstab”
    "/etc/modeprobe.d/harden.conf"
)

CRITICAL_BASELINE="/var/lib/critical-files-baseline"

if [ ! -f "$CRITICAL_BASELINE" ]; then
    log_info "Creating critical files baseline"
    for f in "${CRITICAL_FILES[@]}"; do
        if [ -f "$f" ]; then
            md5sum "$f" >> "$CRITICAL_BASELINE"
        fi
    done
    chmod 600 "$CRITICAL_BASELINE"
    chattr +i "$CRITICAL_BASELINE" 2>/dev/null || true
else
    chattr -i "$CRITICAL_BASELINE" 2>/dev/null || true
    CHANGED_FILES=""
    for f in "${CRITICAL_FILES[@]}"; do
        if [ -f "$f" ]; then
            CURRENT_HASH=$(md5sum "$f" | awk '{print $1}')
            BASELINE_HASH=$(grep "$f" "$CRITICAL_BASELINE" 2>/dev/null | awk '{print $1}')
            if [ -n "$BASELINE_HASH" ] && [ "$CURRENT_HASH" != "$BASELINE_HASH" ]; then
                CHANGED_FILES="$CHANGED_FILES $f"
            fi
        fi
    done
    chattr +i "$CRITICAL_BASELINE" 2>/dev/null || true
    
    if [ -n "$CHANGED_FILES" ]; then
        log_alert "Critical security files modified:$CHANGED_FILES"
        # Don't auto-halt on this - could be legitimate changes
        # But definitely want to know about it
    fi
fi

log_info "Escalation monitor check completed successfully"
EOF

chmod 700 /usr/local/bin/escalation-monitor
chattr +i /usr/local/bin/escalation-monitor

# Use systemd timer instead of cron (since cron is purged)
cat >/etc/systemd/system/escalation-monitor.service <<'EOF'
[Unit]
Description=Escalation Monitor Security Check

[Service]
Type=oneshot
ExecStart=/usr/local/bin/escalation-monitor
EOF

cat >/etc/systemd/system/escalation-monitor.timer <<'EOF'
[Unit]
Description=Run escalation monitor every 30 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable escalation-monitor.timer
systemctl start escalation-monitor.timer

# MAC RANDOMIZE
cat >/etc/systemd/system/macchanger@.service <<'EOF'
[Unit]
Description=MAC Address Randomization for %i
Wants=network-pre.target
Before=network-pre.target
BindsTo=sys-subsystem-net-devices-%i.device
After=sys-subsystem-net-devices-%i.device

[Service]
Type=oneshot
ExecStart=/usr/bin/macchanger -e %i
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable macchanger@enp0s31f6.service

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
chattr -R +i /etc 2>/dev/null || true
chattr -R +i /usr 2>/dev/null || true
chattr -R +i /boot 2>/dev/null || true 

echo “HARDENING COMPLETE”
