# SIGIL Setup Guide

## Quick Install

```bash
# Extract package
unzip sigil-production.zip
cd sigil-production

# Run installer (as root)
sudo ./install.sh

# Set web password
cd /opt/sigil
sudo -u $USER python3 sigil_web.py --set-password

# Start service
sudo systemctl start sigil

# Get your .onion address
sudo cat /var/lib/tor/sigil-web/hostname
```

## Custom Installation

Override defaults with environment variables:

```bash
# Custom user
SIGIL_USER=myuser sudo ./install.sh

# Custom install directory
SIGIL_INSTALL_DIR=/home/myuser/sigil sudo ./install.sh

# Both
SIGIL_USER=bitcoin SIGIL_INSTALL_DIR=/srv/sigil sudo ./install.sh
```

## Hardware Setup

### SE050 Wiring (I2C)

| SE050 Pin | Pi GPIO | Pi Physical Pin |
|-----------|---------|-----------------|
| VCC       | 3.3V    | Pin 1           |
| GND       | GND     | Pin 6           |
| SDA       | GPIO 2  | Pin 3           |
| SCL       | GPIO 3  | Pin 5           |

### Verify Connection

```bash
# Should show device at 0x48
sudo i2cdetect -y 1
```

## First Time Setup

### 1. Set Web Password
```bash
cd /opt/sigil  # or your install directory
sudo -u $USER python3 sigil_web.py --set-password
```

### 2. Start Service
```bash
sudo systemctl start sigil
sudo systemctl status sigil
```

### 3. Access Wallet
```bash
# Get your Tor address
sudo cat /var/lib/tor/sigil-web/hostname

# Open in Tor Browser
```

### 4. Enable Signing PIN (Recommended)
In web interface: Settings → Signing PIN

This adds 2FA for:
- Creating/importing wallets
- Deleting wallets
- Sending transactions
- Signing messages

## File Locations

| File | Path |
|------|------|
| Application | `/opt/sigil/` |
| User Config | `~/.sigil/` |
| Wallet Keys | `~/.se050-wallet/` |
| Logs | `/var/log/sigil/` |
| Tor Address | `/var/lib/tor/sigil-web/hostname` |

## Management Commands

```bash
# Service control
sudo systemctl start sigil
sudo systemctl stop sigil
sudo systemctl restart sigil
sudo systemctl status sigil

# View logs
journalctl -u sigil -f
tail -f /var/log/sigil/error.log

# Tor address
sudo cat /var/lib/tor/sigil-web/hostname
```

## Troubleshooting

### SE050 Not Detected
```bash
# Check I2C enabled
sudo raspi-config  # Interface Options → I2C

# Check wiring - should show 0x48
sudo i2cdetect -y 1

# May need reboot after enabling I2C
sudo reboot
```

### Service Won't Start
```bash
# Check for errors
journalctl -u sigil -n 50

# Test manually
cd /opt/sigil
python3 -c "import sigil_web; print('OK')"
```

### Forgot Password
```bash
cd /opt/sigil
sudo -u $USER python3 sigil_web.py --set-password
```

### Forgot Signing PIN
```bash
rm ~/.sigil/signing_pin.hash
# Then set new PIN via web interface
```
