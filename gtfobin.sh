#!/usr/bin/env bash
#
# =============================================================================
# GTFOBins Protection Module
# =============================================================================
# Target: Debian 12+ / ThinkPad P16s Gen 2
# Purpose: Proactive protection against GTFOBins exploitation techniques
# Policy: Remove dangerous packages, block installation, strip SUID/SGID,
#         create audit rules, and restrict capabilities
#
# This module protects against binaries that can be abused for:
# - Privilege escalation (SUID/sudo abuse)
# - Shell escape
# - File read/write as root
# - Reverse shells
# - Security bypass
#
# Reference: https://gtfobins.github.io/
# =============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------------

LOG_FILE="/var/log/gtfobins-hardening.log"
BACKUP_DIR="/var/backups/gtfobins-hardening-$(date +%Y%m%d%H%M%S)"
PRIMARY_USER="dev"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
# LOGGING FUNCTIONS
# ------------------------------------------------------------------------------

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"
}

# ------------------------------------------------------------------------------
# PREFLIGHT CHECKS
# ------------------------------------------------------------------------------

preflight_checks() {
    log_info "Running preflight checks..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    if ! id "$PRIMARY_USER" &>/dev/null; then
        log_error "Primary user '$PRIMARY_USER' does not exist"
        exit 1
    fi
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    
    # Create log file
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    
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
    
    # Tier 2: High risk removals (optional - comment out if you need these)
    log_info "Processing Tier 2 (High Risk) packages..."
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
    
    # Clean up orphaned packages
    log_info "Cleaning orphaned packages..."
    apt-get autoremove -y
    apt-get autoclean
    
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
            perms=$(stat -c '%a' "$binary")
            
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
    done < <(find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) -print0)
    
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
            caps=$(getcap "$interp")
            
            if [[ -n "$caps" ]]; then
                log_warn "Stripping capabilities from: $interp"
                log_info "  Was: $caps"
                if setcap -r "$interp"; then
                    ((stripped_count++))
                    log_success "Stripped capabilities: $interp"
                else
                    log_error "Failed to strip capabilities from: $interp"
                fi
            fi
        fi
    done
    
    # Scan for any binaries with dangerous capabilities
    log_info "Scanning for binaries with capabilities..."
    
    local cap_output
    cap_output=$(getcap -r /usr /bin /sbin 2>/dev/null | grep -v "^$") || true
    
    if [[ -n "$cap_output" ]]; then
        while IFS= read -r line; do
            local binary
            binary=$(echo "$line" | awk '{print $1}')
            local basename
            basename=$(basename "$binary")
        
        for gtfo in "${ALL_GTFOBINS[@]}"; do
            if [[ "$basename" == "$gtfo" ]] || [[ "$basename" == "${gtfo}."* ]]; then
                log_warn "Found GTFOBin with capabilities: $line"
                setcap -r "$binary" || log_error "Failed to strip: $binary"
                ((stripped_count++))
                break
            fi
        done
        done <<< "$cap_output"
    fi
    
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
        path=$(command -v "$gtfo") || continue
        
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
%users ALL = !GTFOBINS_DANGEROUS
EOF
        
        chmod 440 "$sudoers_file"
        
        # Validate sudoers syntax
        if visudo -c -f "$sudoers_file"; then
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
        if command -v augenrules &>/dev/null; then
            augenrules --load
        else
            auditctl -R "$audit_rules"
        fi
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
    
    if ! aa-status --enabled; then
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
            if apparmor_parser -r "$profile_path"; then
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
            if chattr +i "$binary_path"; then
                ((blocked_count++))
                log_success "Blocked: $binary_path"
            else
                log_warn "Could not set immutable flag on: $binary_path (filesystem may not support it)"
                ((blocked_count++))
            fi
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

# ------------------------------------------------------------------------------
# SECTION 10: GENERATE REPORT
# ------------------------------------------------------------------------------

generate_report() {
    log ""
    log "============================================================================"
    log "SECTION 10: GENERATING SECURITY REPORT"
    log "============================================================================"
    
    local report_file="${BACKUP_DIR}/gtfobins-report.txt"
    
    cat > "$report_file" << EOF
================================================================================
GTFOBins Protection Report
Generated: $(date)
Host: $(hostname)
================================================================================

SUMMARY
-------
This report summarizes the GTFOBins protection measures applied to your system.

REMAINING SUID/SGID BINARIES
----------------------------
$(find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) | sort)

BINARIES WITH CAPABILITIES
--------------------------
$(getcap -r /usr /bin /sbin || echo "None found or getcap not available")

INSTALLED GTFOBINS (Still Present)
----------------------------------
EOF
    
    for gtfo in "${ALL_GTFOBINS[@]}"; do
        local path
        path=$(command -v "$gtfo") || continue
        if [[ -n "$path" ]]; then
            echo "$gtfo -> $path" >> "$report_file"
        fi
    done
    
    cat >> "$report_file" << EOF

BLOCKED PACKAGES (APT)
----------------------
$(cat /etc/apt/preferences.d/gtfobins-block | grep "^Package:" | sed 's/Package: //' | sort -u || echo "None configured")

AUDIT RULES ACTIVE
------------------
$(auditctl -l | grep gtfobins || echo "No GTFOBins audit rules or auditd not running")

APPARMOR PROFILES
-----------------
$(aa-status | grep -E "gtfobins|nmap|netcat|socat" || echo "No GTFOBins AppArmor profiles or AppArmor not running")

RECOMMENDATIONS
---------------
1. Review the "REMAINING SUID/SGID BINARIES" list above
2. Consider removing any SUID bits from binaries you don't need
3. Monitor audit logs: ausearch -k gtfobins
4. Regularly update: apt update && apt upgrade
5. Review blocked packages list if you need to install something

FILES CREATED/MODIFIED
----------------------
- /etc/apt/preferences.d/gtfobins-block
- /etc/sudoers.d/gtfobins-deny
- /etc/audit/rules.d/gtfobins.rules
- /etc/apparmor.d/* (various deny profiles)
- Log file: $LOG_FILE
- Backup directory: $BACKUP_DIR

================================================================================
End of Report
================================================================================
EOF
    
    chmod 600 "$report_file"
    
    log_success "Report generated: $report_file"
    
    # Display summary
    echo ""
    echo "============================================================================"
    echo "GTFOBins PROTECTION MODULE COMPLETE"
    echo "============================================================================"
    echo ""
    echo "Actions taken:"
    echo "  - Removed dangerous packages (Tier 1 & 2)"
    echo "  - Blocked package installation via APT preferences"
    echo "  - Stripped SUID/SGID bits from dangerous binaries"
    echo "  - Stripped capabilities from interpreters"
    echo "  - Configured sudo restrictions"
    echo "  - Created auditd monitoring rules"
    echo "  - Created AppArmor deny profiles"
    echo "  - Created placeholder blockers"
    echo "  - Restricted temp directory execution"
    echo ""
    echo "Important files:"
    echo "  - Log: $LOG_FILE"
    echo "  - Report: $report_file"
    echo "  - Backups: $BACKUP_DIR"
    echo ""
    echo "Next steps:"
    echo "  1. Review the report: cat $report_file"
    echo "  2. Reboot to apply all changes"
    echo "  3. Monitor logs: ausearch -k gtfobins"
    echo ""
}

# ------------------------------------------------------------------------------
# MAIN EXECUTION
# ------------------------------------------------------------------------------

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
    configure_audit_rules
    configure_apparmor_profiles
    create_placeholder_blockers
    restrict_temp_execution
    generate_report
}

# Run main
main "$@"