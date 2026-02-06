#!/bin/bash
#
# SIGIL Production Installer
# ==========================
# Installs SIGIL Bitcoin Hardware Wallet on Raspberry Pi
#
# Usage:
#   sudo ./install.sh                    # Full install (Tor from apt)
#   sudo ./install.sh --tor-source       # Full install (compile Tor from source)
#   sudo ./install.sh --regen-onion      # Regenerate .onion address only
#

set -e

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
NC="\033[0m"

# Parse flags
TOR_FROM_SOURCE=false
REGEN_ONION=false
for arg in "$@"; do
    case "$arg" in
        --tor-source)  TOR_FROM_SOURCE=true ;;
        --regen-onion) REGEN_ONION=true ;;
        --help|-h)
            echo "Usage: sudo ./install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --tor-source     Compile and install current stable Tor from source"
            echo "  --regen-onion    Regenerate .onion address (run on existing install)"
            echo "  --help           Show this help"
            echo ""
            echo "Environment:"
            echo "  SIGIL_USER=user          Run as this user"
            echo "  SIGIL_INSTALL_DIR=/path  Install to this directory"
            exit 0
            ;;
    esac
done

# Configurable paths
INSTALL_DIR="${SIGIL_INSTALL_DIR:-/opt/sigil}"
SIGIL_USER="${SIGIL_USER:-$(logname 2>/dev/null || echo $SUDO_USER)}"

# Fallback if we still don't have a user
if [ -z "$SIGIL_USER" ] || [ "$SIGIL_USER" = "root" ]; then
    SIGIL_USER=$(ls /home | head -1)
fi

SIGIL_HOME="/home/${SIGIL_USER}"

print_banner() {
    echo -e "${CYAN}"
    echo "███████╗██╗ ██████╗ ██╗██╗     ██╗    ██╗███████╗██████╗ "
    echo "██╔════╝██║██╔════╝ ██║██║     ██║    ██║██╔════╝██╔══██╗"
    echo "███████╗██║██║  ███╗██║██║     ██║ █╗ ██║█████╗  ██████╔╝"
    echo "╚════██║██║██║   ██║██║██║     ██║███╗██║██╔══╝  ██╔══██╗"
    echo "███████║██║╚██████╔╝██║███████╗╚███╔███╔╝███████╗██████╔╝"
    echo "╚══════╝╚═╝ ╚═════╝ ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚═════╝"
    echo -e "${NC}"
    echo "SIGIL Production Installer"
    echo "=========================="
    echo ""
}

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root: sudo ./install.sh"
        exit 1
    fi
}

regen_onion() {
    log_info "Regenerating .onion address..."

    # Save old address for reference
    OLD_ONION=""
    if [ -f /var/lib/tor/sigil-web/hostname ]; then
        OLD_ONION=$(cat /var/lib/tor/sigil-web/hostname)
        echo -e "  Old address: ${RED}${OLD_ONION}${NC}"
    fi

    # Stop Tor, nuke the hidden service directory, restart
    systemctl stop tor
    rm -rf /var/lib/tor/sigil-web

    # Ensure torrc still has our config
    if ! grep -q "sigil-web" /etc/tor/torrc 2>/dev/null; then
        cat >> /etc/tor/torrc << TOREOF

# SIGIL Hardware Wallet
HiddenServiceDir /var/lib/tor/sigil-web/
HiddenServicePort 80 127.0.0.1:5000
TOREOF
    fi

    systemctl start tor

    # Wait for new hostname generation
    log_info "Waiting for Tor to generate new keypair..."
    for i in $(seq 1 20); do
        [ -f /var/lib/tor/sigil-web/hostname ] && break
        sleep 2
    done
    sleep 2

    if [ -f /var/lib/tor/sigil-web/hostname ]; then
        NEW_ONION=$(cat /var/lib/tor/sigil-web/hostname)
        echo ""
        echo -e "${GREEN}New .onion address:${NC}"
        echo -e "  ${YELLOW}${NEW_ONION}${NC}"
        echo ""
        if [ -n "$OLD_ONION" ]; then
            log_warn "Old address is now dead. Update any bookmarks."
        fi
    else
        log_error "Tor failed to generate new address. Check: journalctl -u tor"
    fi

    exit 0
}

confirm_settings() {
    echo ""
    echo -e "${CYAN}Installation Settings:${NC}"
    echo "  Install directory: ${INSTALL_DIR}"
    echo "  Run as user:       ${SIGIL_USER}"
    echo "  User home:         ${SIGIL_HOME}"
    echo ""
    
    if [ ! -d "$SIGIL_HOME" ]; then
        log_error "User home directory not found: ${SIGIL_HOME}"
        echo ""
        echo "Set a different user with: SIGIL_USER=username sudo ./install.sh"
        exit 1
    fi
    
    read -p "Continue with these settings? (Y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo ""
        echo "Customize with environment variables:"
        echo "  SIGIL_USER=myuser sudo ./install.sh"
        echo "  SIGIL_INSTALL_DIR=/my/path sudo ./install.sh"
        exit 0
    fi
}

install_tor_from_source() {
    log_info "Compiling Tor from source (current stable)..."

    # Build dependencies
    apt-get install -y -qq \
        automake autoconf libtool \
        libevent-dev libssl-dev zlib1g-dev \
        asciidoc > /dev/null

    TOR_BUILD_DIR=$(mktemp -d)
    cd "${TOR_BUILD_DIR}"

    # Fetch latest stable release version from Tor Project
    log_info "Fetching latest stable Tor release..."
    TOR_VERSION=$(curl -sL https://dist.torproject.org/ \
        | grep -oP 'tor-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz' \
        | sort -V | tail -1 | sed 's/\.tar\.gz//' | sed 's/tor-//')

    if [ -z "$TOR_VERSION" ]; then
        log_error "Could not determine latest Tor version"
        log_warn "Falling back to apt package..."
        apt-get install -y -qq tor > /dev/null
        return
    fi

    log_info "Building Tor ${TOR_VERSION}..."
    curl -sLO "https://dist.torproject.org/tor-${TOR_VERSION}.tar.gz"
    curl -sLO "https://dist.torproject.org/tor-${TOR_VERSION}.tar.gz.sha256sum"

    # Verify checksum
    if ! sha256sum -c "tor-${TOR_VERSION}.tar.gz.sha256sum" 2>/dev/null; then
        log_error "Tor source checksum verification FAILED"
        rm -rf "${TOR_BUILD_DIR}"
        exit 1
    fi
    log_info "Checksum verified"

    tar xzf "tor-${TOR_VERSION}.tar.gz"
    cd "tor-${TOR_VERSION}"

    ./configure --disable-asciidoc > /dev/null 2>&1
    make -j$(nproc) > /dev/null 2>&1
    make install > /dev/null 2>&1

    log_info "Tor ${TOR_VERSION} installed to /usr/local/bin/tor"

    # Clean up build dir
    rm -rf "${TOR_BUILD_DIR}"

    # Create tor user if it doesn't exist
    id -u debian-tor > /dev/null 2>&1 || useradd --system --no-create-home --group debian-tor debian-tor 2>/dev/null || true

    # Create data directory
    mkdir -p /var/lib/tor
    chown debian-tor:debian-tor /var/lib/tor
    chmod 700 /var/lib/tor

    # Create systemd service for source-built Tor
    if [ ! -f /etc/systemd/system/tor.service ] || grep -q "/usr/bin/tor" /etc/systemd/system/tor.service 2>/dev/null; then
        cat > /etc/systemd/system/tor.service << TORSVCEOF
[Unit]
Description=Tor Anonymizing Overlay Network
After=network.target

[Service]
Type=simple
User=debian-tor
ExecStart=/usr/local/bin/tor -f /etc/tor/torrc
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
TORSVCEOF
        systemctl daemon-reload
    fi

    # Ensure torrc exists
    mkdir -p /etc/tor
    [ -f /etc/tor/torrc ] || touch /etc/tor/torrc
    chown debian-tor:debian-tor /etc/tor/torrc
}

install_dependencies() {
    log_info "Updating package lists..."
    apt-get update -qq

    log_info "Installing system packages..."
    if [ "$TOR_FROM_SOURCE" = true ]; then
        # Install everything except Tor from apt
        apt-get install -y -qq \
            python3 \
            python3-pip \
            i2c-tools \
            build-essential \
            libffi-dev \
            libssl-dev \
            curl \
            > /dev/null
        install_tor_from_source
    else
        apt-get install -y -qq \
            python3 \
            python3-pip \
            tor \
            i2c-tools \
            build-essential \
            libffi-dev \
            libssl-dev \
            > /dev/null
    fi

    log_info "Installing Python packages..."
    pip3 install --break-system-packages -q \
        flask \
        gunicorn \
        requests \
        pysocks \
        qrcode \
        pillow \
        2>/dev/null || pip3 install -q flask gunicorn requests pysocks qrcode pillow
}

setup_i2c() {
    log_info "Configuring I2C..."
    
    CONFIG_FILE=""
    if [ -f /boot/firmware/config.txt ]; then
        CONFIG_FILE="/boot/firmware/config.txt"
    elif [ -f /boot/config.txt ]; then
        CONFIG_FILE="/boot/config.txt"
    fi
    
    if [ -n "$CONFIG_FILE" ]; then
        if ! grep -q "^dtparam=i2c_arm=on" "$CONFIG_FILE"; then
            echo "dtparam=i2c_arm=on" >> "$CONFIG_FILE"
            touch /tmp/sigil_needs_reboot
            log_warn "I2C enabled - REBOOT REQUIRED after install"
        fi
    fi
    
    modprobe i2c-dev 2>/dev/null || true
    usermod -aG i2c ${SIGIL_USER} 2>/dev/null || true
}

setup_directories() {
    log_info "Creating directories..."
    
    mkdir -p ${INSTALL_DIR}
    mkdir -p /var/log/sigil
    chown ${SIGIL_USER}:${SIGIL_USER} /var/log/sigil
    
    sudo -u ${SIGIL_USER} mkdir -p ${SIGIL_HOME}/.sigil
    sudo -u ${SIGIL_USER} mkdir -p ${SIGIL_HOME}/.se050-wallet
    chmod 700 ${SIGIL_HOME}/.sigil
    chmod 700 ${SIGIL_HOME}/.se050-wallet
}

install_files() {
    log_info "Installing SIGIL files..."
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Copy Python package
    cp -r ${SCRIPT_DIR}/sigil ${INSTALL_DIR}/
    cp ${SCRIPT_DIR}/wsgi.py ${INSTALL_DIR}/
    cp ${SCRIPT_DIR}/run.py ${INSTALL_DIR}/
    cp ${SCRIPT_DIR}/gunicorn.conf.py ${INSTALL_DIR}/ 2>/dev/null || true
    cp ${SCRIPT_DIR}/pyproject.toml ${INSTALL_DIR}/

    # Copy native library source
    cp -r ${SCRIPT_DIR}/native ${INSTALL_DIR}/
    cp ${INSTALL_DIR}/native/libse050.so* ${INSTALL_DIR}/ 2>/dev/null || true

    # Copy tools
    cp -r ${SCRIPT_DIR}/tools ${INSTALL_DIR}/ 2>/dev/null || true
    
    chown -R ${SIGIL_USER}:${SIGIL_USER} ${INSTALL_DIR}
}

build_library() {
    if [ -f "${INSTALL_DIR}/native/Makefile" ] && [ -f "${INSTALL_DIR}/native/se050_vcom.c" ]; then
        log_info "Building SE050 library..."
        cd ${INSTALL_DIR}/native
        sudo -u ${SIGIL_USER} make clean 2>/dev/null || true
        if sudo -u ${SIGIL_USER} make 2>/dev/null; then
            log_info "Library built successfully"
            # Copy lib to install root for runtime
            cp ${INSTALL_DIR}/native/libse050.so ${INSTALL_DIR}/ 2>/dev/null || true
        else
            if [ -f "${INSTALL_DIR}/libse050.so" ]; then
                log_warn "Build failed - using prebuilt library"
            else
                log_error "Library build failed and no prebuilt available"
            fi
        fi
    fi
}

setup_credentials() {
    echo ""
    echo -e "${CYAN}=== Credential Setup ===${NC}"
    echo ""
    
    # Web login password
    while true; do
        echo -e "${YELLOW}Set web login password${NC} (min 8 characters)"
        read -s -p "Password: " WEB_PASS
        echo
        
        if [ ${#WEB_PASS} -lt 8 ]; then
            log_error "Password must be at least 8 characters"
            continue
        fi
        
        read -s -p "Confirm:  " WEB_PASS2
        echo
        
        if [ "$WEB_PASS" != "$WEB_PASS2" ]; then
            log_error "Passwords don't match"
            continue
        fi
        
        break
    done
    
    # Set password using Python (pass via stdin to avoid exposure in ps)
    log_info "Setting web password..."
    cd ${INSTALL_DIR}
    echo "${WEB_PASS}" | sudo -u ${SIGIL_USER} python3 -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from sigil.web.helpers import set_password
password = sys.stdin.readline().rstrip('\n')
set_password(password)
print('Password set successfully')
"
    
    # Optional signing PIN
    echo ""
    read -p "Set up signing PIN for transactions? (recommended) (Y/n) " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        while true; do
            echo -e "${YELLOW}Set signing PIN${NC} (min 4 characters)"
            read -s -p "PIN: " SIGN_PIN
            echo
            
            if [ ${#SIGN_PIN} -lt 4 ]; then
                log_error "PIN must be at least 4 characters"
                continue
            fi
            
            read -s -p "Confirm: " SIGN_PIN2
            echo
            
            if [ "$SIGN_PIN" != "$SIGN_PIN2" ]; then
                log_error "PINs don't match"
                continue
            fi
            
            break
        done
        
        log_info "Setting signing PIN..."
        echo "${SIGN_PIN}" | sudo -u ${SIGIL_USER} python3 -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from sigil.web.helpers import set_signing_pin
pin = sys.stdin.readline().rstrip('\n')
set_signing_pin(pin)
print('Signing PIN set successfully')
"
    fi
}

setup_systemd() {
    log_info "Installing systemd service..."
    
    cat > /etc/systemd/system/sigil.service << SERVICEEOF
[Unit]
Description=SIGIL Bitcoin Hardware Wallet
After=network.target tor.service
Wants=tor.service

[Service]
Type=notify
User=${SIGIL_USER}
Group=${SIGIL_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/local/bin/gunicorn -c gunicorn.conf.py wsgi:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1
Environment=HOME=${SIGIL_HOME}

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${SIGIL_HOME}/.sigil ${SIGIL_HOME}/.se050-wallet /var/log/sigil ${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
SERVICEEOF

    systemctl daemon-reload
    systemctl enable sigil
}

setup_tor() {
    log_info "Configuring Tor hidden service..."
    
    if ! grep -q "sigil-web" /etc/tor/torrc 2>/dev/null; then
        cat >> /etc/tor/torrc << TOREOF

# SIGIL Hardware Wallet
HiddenServiceDir /var/lib/tor/sigil-web/
HiddenServicePort 80 127.0.0.1:5000
TOREOF
    fi
    
    systemctl enable tor
    systemctl restart tor
    # Wait for hostname generation (up to 30s on first run)
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [ -f /var/lib/tor/sigil-web/hostname ] && break
        sleep 3
    done
    sleep 3
}

setup_logrotate() {
    log_info "Configuring log rotation..."
    
    cat > /etc/logrotate.d/sigil << LOGEOF
/var/log/sigil/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 ${SIGIL_USER} ${SIGIL_USER}
    sharedscripts
    postrotate
        systemctl reload sigil > /dev/null 2>&1 || true
    endscript
}
LOGEOF
}

start_service() {
    log_info "Starting SIGIL..."
    systemctl start sigil
    sleep 2
    
    if systemctl is-active --quiet sigil; then
        log_info "Service started successfully"
    else
        log_warn "Service may not have started - check: journalctl -u sigil"
    fi
}

print_success() {
    ONION=""
    if [ -f /var/lib/tor/sigil-web/hostname ]; then
        ONION=$(cat /var/lib/tor/sigil-web/hostname)
    fi
    
    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  SIGIL Installation Complete!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    
    if [ -n "$ONION" ]; then
        echo -e "Your wallet address:"
        echo -e "  ${YELLOW}${ONION}${NC}"
        echo ""
    else
        echo -e "  ${YELLOW}Run: sudo cat /var/lib/tor/sigil-web/hostname${NC}"
        echo "  (Tor may still be generating keys)"
        echo ""
    fi
    
    echo -e "${CYAN}Access:${NC}"
    echo "  1. Open Tor Browser"
    echo "  2. Navigate to your .onion address"
    echo "  3. Login with the password you just set"
    echo ""
    echo -e "${CYAN}Commands:${NC}"
    echo "  sudo systemctl status sigil    # Check status"
    echo "  sudo systemctl restart sigil   # Restart"
    echo "  journalctl -u sigil -f         # View logs"
    echo "  sudo ./install.sh --regen-onion  # New .onion address"
    echo ""
    echo -e "${CYAN}Support SIGIL development:${NC}"
    echo -e "  ${YELLOW}bc1qtt02xk5qwgt9qsrz9gwuksqejrh7z5d2e6ny3k${NC}"
    echo ""

    if [ -f /tmp/sigil_needs_reboot ]; then
        echo -e "${YELLOW}>>> REBOOT REQUIRED for I2C <<<${NC}"
        echo ""
        read -p "Reboot now? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            reboot
        fi
    fi
}

# =============================================================================
#                                MAIN
# =============================================================================

print_banner
check_root

# Handle --regen-onion: standalone operation on existing install
if [ "$REGEN_ONION" = true ]; then
    regen_onion
fi

confirm_settings

log_info "Starting installation..."

install_dependencies
setup_i2c
setup_directories
install_files
build_library
setup_systemd
setup_tor
setup_logrotate
setup_credentials
start_service

print_success
