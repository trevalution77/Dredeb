#!/usr/bin/env bash

# Binary/File Protection Script

set -euo pipefail

#
# CONFIGURATION
#

LOG_FILE="/var/log/gtfobins-hardening.log"
BACKUP_DIR="/var/backups/gtfobins-hardening-$(date +%Y%m%d%H%M%S)"
PRIMARY_USER="dev"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#
# LOGGING FUNCTIONS
#

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "[INFO] $(date): $1" >> "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "[SUCCESS] $(date): $1" >> "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[WARNING] $(date): $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[ERROR] $(date): $1" >> "$LOG_FILE"
}

#
# PREFLIGHT CHECKS
#

preflight_checks() {
    log_info "Running preflight checks..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    # Check for backup directory
    mkdir -p "$BACKUP_DIR"
    log_success "Backup directory created: $BACKUP_DIR"
    
    # Check log file
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    
    log_success "Preflight checks completed"
}

#
# BINARY CLASSIFICATIONS
#

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

RISKY_PACKAGES=(
    "aircrack-ng"
    "arping"
    "arpspoof"
    "arpwatch"
    "as86"
    "autoconf"
    "automake"
    "autopsy"
    "beef-xss"
    "bettercap"
    "bin86"
    "binutils"
    "binwalk"
    "bison"
    "bvi"
    "byacc"
    "cabal-install"
    "cargo"
    "chrpath"
    "clang"
    "cmake"
    "containerd.io"
    "cpp"
    "crackmapexec"
    "default-jdk"
    "default-jre"
    "dirb"
    "docker-ce-cli"
    "docker-ce"
    "docker.io"
    "dotnet-sdk-6.0"
    "dotnet-sdk-7.0"
    "dotnet-sdk-8.0"
    "dsniff"
    "dwarfdump"
    "elfutils"
    "elixir"
    "enum4linux"
    "erlang"
    "ettercap-common"
    "ettercap-graphical"
    "execstack"
    "exiftool"
    "expect"
    "flatpak"
    "flex"
    "foremost"
    "fpc"
    "fping"
    "ftp"
    "g++"
    "gawk"
    "gcc"
    "gdb"
    "gfortran"
    "ghc"
    "ghidra"
    "ghostscript"
    "gimp"
    "gobuster"
    "golang-go"
    "golang"
    "hashcat"
    "hexedit"
    "hping3"
    "hydra-gtk"
    "hydra"
    "imagemagick"
    "impacket-scripts"
    "john"
    "julia"
    "lftp"
    "libtool"
    "lldb"
    "llvm"
    "ltrace"
    "lua5.1"
    "lua5.3"
    "lua5.4"
    "luajit"
    "lxc"
    "lxd-client"
    "lxd"
    "m4"
    "macchanger"
    "make"
    "maltego"
    "masscan"
    "mawk"
    "medusa"
    "meson"
    "metagoofil"
    "metasploit-framework"
    "mitmproxy"
    "mono-complete"
    "nasm"
    "nbtscan"
    "nc"
    "ncat"
    "ncftp"
    "ndisasm"
    "netcat-openbsd"
    "netcat-traditional"
    "netcat"
    "nikto"
    "ninja-build"
    "nmap"
    "nodejs"
    "npm"
    "objdump"
    "octave"
    "openstego"
    "outguess"
    "patchelf"
    "perl"
    "php-cli"
    "php-common"
    "php"
    "podman"
    "prelink"
    "proftpd-basic"
    "proxychains"
    "proxychains4"
    "pure-ftpd"
    "python-is-python3"
    "r-base"
    "radare2"
    "readelf"
    "recon-ng"
    "responder"
    "rsh-client"
    "rsh-redone-client"
    "ruby-full"
    "ruby"
    "rustc"
    "scapy"
    "sleuthkit"
    "smbclient"
    "smbmap"
    "snapd"
    "socat"
    "social-engineer-toolkit"
    "spiderfoot"
    "sqlmap"
    "sslstrip"
    "steghide"
    "stegosuite"
    "strace"
    "swig"
    "tcl"
    "tcpdump"
    "telnet"
    "telnetd"
    "tftp-hpa"
    "tftp"
    "theharvester"
    "tk"
    "tor"
    "torsocks"
    "tshark"
    "unicornscan"
    "upx"
    "valgrind"
    "volatility"
    "vsftpd"
    "wfuzz"
    "wireshark-gtk"
    "wireshark-qt"
    "wireshark"
    "xxd"
    "yasm"
    "yersinia"
    "zenmap"
    "zmap"
)

BLOCK_PACKAGES=(
    "aircrack-ng"
    "arping"
    "arpspoof"
    "arpwatch"
    "as86"
    "autoconf"
    "automake"
    "autopsy"
    "beef-xss"
    "bettercap"
    "bin86"
    "binutils"
    "binwalk"
    "bison"
    "bvi"
    "byacc"
    "cabal-install"
    "cargo"
    "chrpath"
    "clang"
    "cmake"
    "containerd.io"
    "cpp"
    "crackmapexec"
    "default-jdk"
    "default-jre"
    "dirb"
    "docker-ce-cli"
    "docker-ce"
    "docker.io"
    "dotnet-sdk-6.0"
    "dotnet-sdk-7.0"
    "dotnet-sdk-8.0"
    "dsniff"
    "dwarfdump"
    "elfutils"
    "elixir"
    "enum4linux"
    "erlang"
    "ettercap-common"
    "ettercap-graphical"
    "execstack"
    "exiftool"
    "expect"
    "flatpak"
    "flex"
    "foremost"
    "fpc"
    "fping"
    "ftp"
    "g++"
    "gawk"
    "gcc"
    "gdb"
    "gfortran"
    "ghc"
    "ghidra"
    "ghostscript"
    "gimp"
    "gobuster"
    "golang-go"
    "golang"
    "hashcat"
    "hexedit"
    "hping3"
    "hydra-gtk"
    "hydra"
    "imagemagick"
    "impacket-scripts"
    "john"
    "julia"
    "lftp"
    "libtool"
    "lldb"
    "llvm"
    "ltrace"
    "lua5.1"
    "lua5.3"
    "lua5.4"
    "luajit"
    "lxc"
    "lxd-client"
    "lxd"
    "m4"
    "macchanger"
    "make"
    "maltego"
    "masscan"
    "mawk"
    "medusa"
    "meson"
    "metagoofil"
    "metasploit-framework"
    "mitmproxy"
    "mono-complete"
    "nasm"
    "nbtscan"
    "nc"
    "ncat"
    "ncftp"
    "ndisasm"
    "netcat-openbsd"
    "netcat-traditional"
    "netcat"
    "nikto"
    "ninja-build"
    "nmap"
    "nodejs"
    "npm"
    "objdump"
    "octave"
    "openstego"
    "outguess"
    "patchelf"
    "perl"
    "php-cli"
    "php-common"
    "php"
    "podman"
    "prelink"
    "proftpd-basic"
    "proxychains"
    "proxychains4"
    "pure-ftpd"
    "python-is-python3"
    "r-base"
    "radare2"
    "readelf"
    "recon-ng"
    "responder"
    "rsh-client"
    "rsh-redone-client"
    "ruby-full"
    "ruby"
    "rustc"
    "scapy"
    "sleuthkit"
    "smbclient"
    "smbmap"
    "snapd"
    "socat"
    "social-engineer-toolkit"
    "spiderfoot"
    "sqlmap"
    "sslstrip"
    "steghide"
    "stegosuite"
    "strace"
    "swig"
    "tcl"
    "tcpdump"
    "telnet"
    "telnetd"
    "tftp-hpa"
    "tftp"
    "theharvester"
    "tk"
    "tor"
    "torsocks"
    "tshark"
    "unicornscan"
    "upx"
    "valgrind"
    "volatility"
    "vsftpd"
    "wfuzz"
    "wireshark-gtk"
    "wireshark-qt"
    "wireshark"
    "xxd"
    "yasm"
    "yersinia"
    "zenmap"
    "zmap"
)

#
# REMOVE DANGEROUS PACKAGES
#

remove_dangerous_packages() {
    log_info "Removing dangerous packages..."
    
    local removed_count=0
    local failed_count=0
    
    # Tier 1 packages
    log_info "Removing Tier 1 (highly dangerous) packages..."
    for pkg in "${TIER1_REMOVE_PACKAGES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null; then
            log_warn "Removing dangerous package: $pkg"
            if apt-get purge -y "$pkg"; then
                ((removed_count++))
                log_success "Removed: $pkg"
            else
                ((failed_count++))
                log_error "Failed to remove: $pkg"
            fi
        fi
    done
    
    # Tier 2 packages
    log_info "Removing Tier 2 (high-risk) packages..."
    for pkg in "${TIER2_REMOVE_PACKAGES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null; then
            log_warn "Removing high-risk package: $pkg"
            if apt-get purge -y "$pkg"; then
                ((removed_count++))
                log_success "Removed: $pkg"
            else
                ((failed_count++))
                log_error "Failed to remove: $pkg"
            fi
        fi
    done
    
    # Risky packages (cleanup)
    log_info "Cleaning up risky packages..."
    for pkg in "${RISKY_PACKAGES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null; then
            log_warn "Removing risky package: $pkg"
            apt purge -y "$pkg" 2>/dev/null || true
        fi
    done
    
    # Cleanup
    apt-get autoremove -y
    apt-get autoclean -y
    
    log_success "Package removal completed: $removed_count removed, $failed_count failed"
}

#
# BLOCK PACKAGE INSTALLATION
#

block_package_installation() {
    log_info "Blocking package installation..."
    
    local apt_prefs="/etc/apt/preferences.d/gtfobins-block"
    
    # Create backup
    if [[ -f "$apt_prefs" ]]; then
        cp "$apt_prefs" "${BACKUP_DIR}/gtfobins-block.bak"
    fi
    
    # Create new preferences file
    cat > "$apt_prefs" << EOF
# Block GTFOBins-related packages
# Generated by GTFOBins hardening script on $(date)
EOF
    
    for pkg in "${BLOCK_PACKAGES[@]}"; do
        # Check if package exists in repos
        if apt-cache show "$pkg" &>/dev/null; then
            cat >> "$apt_prefs" << EOF

Package: $pkg
Pin: release *
Pin-Priority: -1
EOF
        fi
    done
    
    chmod 644 "$apt_prefs"
    log_success "Package blocking configuration created"
}

#
# STRIP SUID/SGID BITS
#

strip_suid_sgid() {
    log_info "Stripping SUID/SGID bits..."
    
    local stripped_count=0
    
    # Strip from known binaries
    for binary in "${TIER3_STRIP_SUID[@]}"; do
        if [[ -f "$binary" ]]; then
            local perms
            perms=$(stat -c '%a' "$binary" 2>/dev/null || true)
            
            if [[ -n "$perms" ]] && [[ "$perms" =~ ^[4267] ]]; then
                log_warn "Stripping SUID/SGID from: $binary (was: $perms)"
                chmod u-s,g-s "$binary"
                ((stripped_count++))
                log_success "Stripped: $binary"
            fi
        fi
    done
    
    # Find and strip additional SUID/SGID binaries
    log_info "Searching for additional SUID/SGID binaries..."
    while IFS= read -r -d '' binary; do
        local basename
        basename=$(basename "$binary")
        
        # Check if it's in our known list
        for gtfo in "${ALL_GTFOBINS[@]}"; do
            if [[ "$basename" == "$gtfo" ]] || [[ "$basename" == "${gtfo}."* ]]; then
                log_warn "Found additional SUID/SGID GTFOBin: $binary"
                chmod u-s,g-s "$binary"
                ((stripped_count++))
                log_success "Stripped: $binary"
                break
            fi
        done
    done < <(find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null)
    
    log_success "SUID/SGID stripping completed: $stripped_count binaries processed"
}

#
# STRIP CAPABILITIES
#

strip_capabilities() {
    log_info "Stripping capabilities..."
    
    local stripped_count=0
    
    # Strip capabilities from interpreters
    for interp in "${INTERPRETERS[@]}"; do
        if [[ -f "$interp" ]]; then
            local caps
            caps=$(getcap "$interp" 2>/dev/null || true)
            
            if [[ -n "$caps" ]]; then
                log_warn "Stripping capabilities from: $interp"
                log_info "  Was: $caps"
                if setcap -r "$interp" 2>/dev/null; then
                    ((stripped_count++))
                    log_success "Stripped capabilities: $interp"
                else
                    log_error "Failed to strip capabilities from: $interp"
                fi
            fi
        fi
    done
    
    # Find and strip additional capabilities
    log_info "Searching for binaries with capabilities..."
    local cap_output
    cap_output=$(getcap -r /usr /bin /sbin 2>/dev/null | grep -v "^$" || true)
    
    if [[ -n "$cap_output" ]]; then
        while IFS= read -r line; do
            local binary
            binary=$(echo "$line" | awk '{print $1}')
            local basename
            basename=$(basename "$binary")
            
            for gtfo in "${ALL_GTFOBINS[@]}"; do
                if [[ "$basename" == "$gtfo" ]] || [[ "$basename" == "${gtfo}."* ]]; then
                    log_warn "Found GTFOBin with capabilities: $line"
                    if setcap -r "$binary" 2>/dev/null; then
                        ((stripped_count++))
                        log_success "Stripped capabilities: $binary"
                    else
                        log_error "Failed to strip capabilities from: $binary"
                    fi
                    break
                fi
            done
        done <<< "$cap_output"
    fi
    
    log_success "Capability stripping completed: $stripped_count binaries processed"
}

#
# CONFIGURE SUDO RESTRICTIONS
#

configure_sudo_restrictions() {
    log_info "Configuring sudo restrictions..."
    
    local sudoers_file="/etc/sudoers.d/gtfobins-deny"
    
    # Create backup
    if [[ -f "$sudoers_file" ]]; then
        cp "$sudoers_file" "${BACKUP_DIR}/gtfobins-deny.bak"
    fi
    
    # Build the command list - only include binaries that exist
    local cmd_list=""
    local count=0
    
    for gtfo in "${ALL_GTFOBINS[@]}"; do
        local path
        path=$(command -v "$gtfo" 2>/dev/null || true)
        
        if [[ -n "$path" ]] && [[ -x "$path" ]]; then
            if [[ $count -gt 0 ]]; then
                cmd_list="${cmd_list}, "
            fi
            cmd_list="${cmd_list}${path}"
            ((count++))
        fi
    done
    
    if [[ -n "$cmd_list" ]]; then
        cat > "$sudoers_file" << EOF
# Deny GTFOBins commands for all users (except root)
# Generated by GTFOBins hardening script on $(date)

Cmnd_Alias GTFOBINS = $cmd_list

ALL ALL = (ALL) ALL, !GTFOBINS
EOF
        
        chmod 440 "$sudoers_file"
        log_success "Sudo restrictions configured: $count commands restricted"
    else
        log_warn "No GTFOBins commands found to restrict"
    fi
}

#
# CREATE PLACEHOLDER BLOCKERS
#

create_placeholder_blockers() {
    log_info "Creating placeholder blockers..."
    
    local dangerous_paths=(
        "/usr/bin/perl"
        "/usr/bin/perl5"
        "/usr/bin/python"
        "/usr/bin/python2"
        "/usr/bin/python3"
        "/usr/bin/ruby"
        "/usr/bin/lua"
        "/usr/bin/lua5.1"
        "/usr/bin/lua5.3"
        "/usr/bin/lua5.4"
        "/usr/bin/node"
        "/usr/bin/nodejs"
        "/usr/bin/php"
        "/usr/bin/php7"
        "/usr/bin/php8"
        "/usr/bin/awk"
        "/usr/bin/gawk"
        "/usr/bin/mawk"
        "/usr/bin/nawk"
        "/usr/bin/sed"
        "/usr/bin/ed"
        "/usr/bin/vi"
        "/usr/bin/vim"
        "/usr/bin/emacs"
        "/usr/bin/tar"
        "/usr/bin/zip"
        "/usr/bin/unzip"
        "/usr/bin/gzip"
        "/usr/bin/bzip2"
        "/usr/bin/xz"
        "/usr/bin/7z"
        "/usr/bin/7za"
        "/usr/bin/curl"
        "/usr/bin/wget"
        "/usr/bin/nc"
        "/usr/bin/ncat"
        "/usr/bin/netcat"
        "/usr/bin/socat"
        "/usr/bin/telnet"
        "/usr/bin/ftp"
        "/usr/bin/ssh"
        "/usr/bin/scp"
        "/usr/bin/sftp"
        "/usr/bin/rsync"
        "/usr/bin/dd"
        "/usr/bin/xxd"
        "/usr/bin/od"
        "/usr/bin/hexdump"
        "/usr/bin/strings"
        "/usr/bin/objdump"
        "/usr/bin/readelf"
        "/usr/bin/nm"
        "/usr/bin/as"
        "/usr/bin/ld"
        "/usr/bin/ar"
        "/usr/sbin/tcpdump"
        "/usr/bin/nmap"
        "/usr/bin/tshark"
        "/usr/bin/wireshark"
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
            
            # Create parent directory if it doesn't exist
            mkdir -p "$(dirname "$binary_path")"
            
            # Create an empty file
            touch "$binary_path"
            
            # Remove all permissions
            chmod 000 "$binary_path"
            
            # Make it immutable if possible
            if chattr +i "$binary_path" 2>/dev/null; then
                ((blocked_count++))
                log_success "Blocked (immutable): $binary_path"
            else
                # Fallback to regular file
                chmod 000 "$binary_path"
                ((blocked_count++))
                log_success "Blocked: $binary_path"
            fi
        fi
    done
    
    log_success "Placeholder blockers created: $blocked_count"
}

#
# MAIN EXECUTION
#

main() {
    echo ""
    echo "============================================================================"
    echo "GTFOBins Protection Module"
    echo "============================================================================"
    echo ""
    echo "This module will harden your system against GTFOBins exploitation."
    echo "Reference: https://gtfobins.github.io/"
    echo ""
    echo "Starting in 3 seconds... (Ctrl+C to cancel)"
    sleep 3
    
    preflight_checks
    
    remove_dangerous_packages
    block_package_installation
    strip_suid_sgid
    strip_capabilities
    configure_sudo_restrictions
    create_placeholder_blockers
    
    echo "Hardening completed!"
  
}

# Run main
main "$@"
