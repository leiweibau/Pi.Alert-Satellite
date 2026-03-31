#!/usr/bin/env bash
# ------------------------------------------------------------------------------
#  pialert_satellite_update.sh - Update script
# ------------------------------------------------------------------------------
#  leiweibau 2024+                                         GNU GPLv3
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Variables
# ------------------------------------------------------------------------------
if [ "$1" = "--lxc" ]; then
  INSTALL_DIR="/opt"
else
  INSTALL_DIR="$HOME"
fi
PIALERT_SATELLITE_HOME="$INSTALL_DIR/pialert_satellite"
LOG="pialert_satellite_update_`date +"%Y-%m-%d_%H-%M"`.log"
PYTHON_BIN=python3


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
main() {
  print_superheader "Pi.Alert Satellite Update"
  log "`date`"
  log "Logfile: $LOG"
  log ""

  set -e

  check_pialert_home
  check_python_version
  create_backup
  check_packages
  download_satellite
  update_config
  configure_user

  test_pialert
  
  print_header "Update process finished"
  print_msg ""

  move_logfile
}

configure_user() {
  SAT_USER=$(whoami)
  print_msg "Pi.Alert-Satellite User: $SAT_USER"
  echo -e "    ...Create Satellite sudoer file to be able to run \"arp-scan\""
  echo "${SAT_USER} ALL=(ALL) NOPASSWD: /usr/sbin/arp-scan" | sudo tee /etc/sudoers.d/pialert-satellite
}

# ------------------------------------------------------------------------------
# Create backup
# ------------------------------------------------------------------------------
create_backup() {
  # Previous backups are deleted to preserve storage 
  print_msg "- Deleting previous Pi.Alert-Satellite backups..."
  rm -f "$INSTALL_DIR/"satellite_update_backup_*.tar
  print_msg "- Creating new Pi.Alert-Satellite backup..."
  cd "$INSTALL_DIR"
  tar cvf "$INSTALL_DIR"/satellite_update_backup_`date +"%Y-%m-%d_%H-%M"`.tar pialert_satellite --checkpoint=100 --checkpoint-action="ttyout=."     2>&1 >> "$LOG"
}

# ------------------------------------------------------------------------------
# Check packages
# ------------------------------------------------------------------------------
check_packages() {
  sudo apt-get update 2>&1 >>"$LOG"
  packages=("apt-utils" "git" "dnsutils" "net-tools" "nbtscan" "avahi-utils" "python3-requests" "python3-cpuinfo" "python3-psutil" "python3-distro" "python3-cryptography" "python3-tz" "python3-tzlocal" "libwww-perl" "mmdb-bin" "libtext-csv-perl" "aria2")
  print_msg "- Checking packages..."
  missing_packages=()
  for package in "${packages[@]}"; do
    if ! dpkg -l | grep -q "$package"; then
      missing_packages+=("$package")
    fi
  done
  if [ ${#missing_packages[@]} -gt 0 ]; then
    print_msg "- Installing missing packages: ${missing_packages[*]}"
    sudo apt-get install -y "${missing_packages[@]}" 2>&1 >>"$LOG"
  fi
}

# ------------------------------------------------------------------------------
# Download and uncompress Pi.Alert
# ------------------------------------------------------------------------------
download_satellite() {
  if [ -e "$HOME/Pi.Alert-Satellite" ] ; then
    rm -rf "$HOME/Pi.Alert-Satellite"
  fi

  Clone_Update=`(git clone --quiet https://github.com/leiweibau/Pi.Alert-Satellite) 2>&1 >> "$LOG"`
  #git clone --quiet https://github.com/leiweibau/Pi.Alert-Satellite                       2>&1 >> "$LOG"
  cp -rf "$HOME/Pi.Alert-Satellite/back" "$PIALERT_SATELLITE_HOME/"
  cp -rf "$HOME/Pi.Alert-Satellite/api/satellite.php" "$PIALERT_SATELLITE_HOME/api/satellite.php"
  cp -rf "$HOME/Pi.Alert-Satellite/config/version.conf" "$PIALERT_SATELLITE_HOME/config/version.conf"
  cp -rf "$HOME/Pi.Alert-Satellite/api/satellite.php" "$PIALERT_SATELLITE_HOME/api/satellite.php"
  cp -rf "$HOME/Pi.Alert-Satellite/docs" "$PIALERT_SATELLITE_HOME/"
  cp -rf "$HOME/Pi.Alert-Satellite/install" "$PIALERT_SATELLITE_HOME/"
  cp -rf "$HOME/Pi.Alert-Satellite/README.md" "$PIALERT_SATELLITE_HOME/"

  rm -rf "$HOME/Pi.Alert-Satellite"
}

# ------------------------------------------------------------------------------
#  Update conf file
# ------------------------------------------------------------------------------
update_config() {
  print_msg "- Config backup..."
  cp "$PIALERT_SATELLITE_HOME/config/satellite.conf" "$PIALERT_SATELLITE_HOME/config/satellite.conf.back"  2>&1 >> "$LOG"

  print_msg "- Updating config file..."

# 2024-11-01
if ! grep -Fq "# Mail-Account Settings" "$PIALERT_SATELLITE_HOME/config/satellite.conf" ; then
  cat << EOF >> "$PIALERT_SATELLITE_HOME/config/satellite.conf"

SATELLITE_ERROR_REPORT = False

# Mail-Account Settings
# ----------------------
SMTP_SERVER              = 'smtp.gmail.com'
SMTP_PORT                = 587
SMTP_USER                = 'user@gmail.com'
SMTP_PASS                = 'password'
SMTP_SKIP_TLS            = False
SMTP_SKIP_LOGIN          = False
FRIENDLY_NAME            = 'My Satellite'
MAIL_FROM                = FRIENDLY_NAME + ' - Pi.Alert Satellite <' + SMTP_USER +'>'
MAIL_TO                  = 'destination@example.com'
COLLECT_REPORTS_FOR_MAIL = 12
# Since a scan is performed every 5 minutes, 12 corresponds to a period of 1 hour during which no successful transmission takes place until a notification is sent.
EOF
fi

# 2025-01-17
if ! grep -Fq "# OpenWRT Configuration" "$PIALERT_SATELLITE_HOME/config/satellite.conf" ; then
  cat << EOF >> "$PIALERT_SATELLITE_HOME/config/satellite.conf"

# OpenWRT Configuration
# ----------------------
OPENWRT_ACTIVE   = False
OPENWRT_IP       = '192.168.1.1'
OPENWRT_USER     = 'root'
OPENWRT_PASS     = ''


NETWORK_DNS_SERVER    = 'localhost'
EOF
fi

# 2025-04-13
if ! grep -Fq "# Pi-hole Configuration" "$PIALERT_SATELLITE_HOME/config/satellite.conf" ; then
  cat << EOF >> "$PIALERT_SATELLITE_HOME/config/satellite.conf"

# Pi-hole Configuration
# ----------------------
PIHOLE_ACTIVE              = False
PIHOLE_DHCP_ACTIVE         = False
PIHOLE6_URL                = ''
PIHOLE6_PASSWORD           = ''
PIHOLE6_API_MAXCLIENTS     = 100
EOF
fi

# 2025-05-08
if ! grep -Fq "# AsusWRT Configuration" "$PIALERT_SATELLITE_HOME/config/satellite.conf" ; then
  cat << EOF >> "$PIALERT_SATELLITE_HOME/config/satellite.conf"

# AsusWRT Configuration
# ----------------------
ASUSWRT_ACTIVE            = False
ASUSWRT_IP                = '192.168.50.1'
ASUSWRT_USER              = 'root'
ASUSWRT_PASS              = ''
ASUSWRT_SSL               = False
EOF
fi

# 2025-11-18
if ! grep -Fq "# pfsense Configuration" "$PIALERT_SATELLITE_HOME/config/satellite.conf" ; then
  cat << EOF >> "$PIALERT_SATELLITE_HOME/config/satellite.conf"

# pfsense Configuration
# ----------------------
PFSENSE_ACTIVE            = False
PFSENSE_IP                = '192.168.1.1'
PFSENSE_PORT              = 80
PFSENSE_APIKEY            = ''
PFSENSE_SSL               = False
PFSENSE_EXCLUDE_INT       = ['WAN']
EOF
fi

# 2026-03-30
if ! grep -Fq "# OPNsense Configuration" "$PIALERT_SATELLITE_HOME/config/satellite.conf" ; then
  cat << EOF >> "$PIALERT_SATELLITE_HOME/config/satellite.conf"

# OPNsense Configuration
# ----------------------
OPNSENSE_ACTIVE           = False
OPNSENSE_IP               = '192.168.1.1'
OPNSENSE_PORT             = 443
OPNSENSE_APIKEY           = ''
OPNSENSE_APISECRET        = ''
OPNSENSE_SSL              = True
OPNSENSE_EXCLUDE_INT      = ['WAN']
EOF
fi

# 2026-03-30
if ! grep -Fq "# AdGuard Configuration" "$PIALERT_SATELLITE_HOME/config/satellite.conf" ; then
  cat << EOF >> "$PIALERT_SATELLITE_HOME/config/satellite.conf"

# AdGuard Configuration
# ----------------------
ADGUARD_ACTIVE            = False
ADGUARD_IP                = '192.168.1.1'
ADGUARD_PORT              = 3000
ADGUARD_USER              = ''
ADGUARD_PASSWORD          = ''
ADGUARD_SSL               = False
ADGUARD_QUERY_LIMIT       = 1000
EOF
fi

# 2026-03-31
if ! grep -Fq "QUERY_MYIP_SERVER_FALLBACK" "$PIALERT_SATELLITE_HOME/config/satellite.conf" ; then
  if grep -Fq "QUERY_MYIP_SERVER" "$PIALERT_SATELLITE_HOME/config/satellite.conf" ; then
    sed -i "/QUERY_MYIP_SERVER/a QUERY_MYIP_SERVER_FALLBACK = 'https://api.ipify.org?format=json'" "$PIALERT_SATELLITE_HOME/config/satellite.conf" 2>&1 >> "$LOG"
  else
    cat << EOF >> "$PIALERT_SATELLITE_HOME/config/satellite.conf"
QUERY_MYIP_SERVER_FALLBACK = 'https://api.ipify.org?format=json'
EOF
  fi
fi

}

# ------------------------------------------------------------------------------
# Test Pi.Alert-Satellite
# ------------------------------------------------------------------------------
test_pialert() {
  print_msg "- Testing Pi.Alert-Satellite Network scan..."
  stdbuf -i0 -o0 -e0 $PYTHON_BIN $PIALERT_SATELLITE_HOME/back/satellite.py scan                      2>&1 | tee -ai "$LOG"
}

# ------------------------------------------------------------------------------
# Check Pi.Alert Installation Path
# ------------------------------------------------------------------------------
check_pialert_home() {
  if [ ! -e "$PIALERT_SATELLITE_HOME" ] ; then
    process_error "Pi.Alert directory dosn't exists: $PIALERT_SATELLITE_HOME"
  fi
}

# ------------------------------------------------------------------------------
# Check Python versions available
# ------------------------------------------------------------------------------
check_and_install_package() {
  package_name="$1"
  if pip3 show "$package_name" > /dev/null 2>&1; then
    print_msg "  - $package_name is already installed"
  else
    print_msg "  - Installing $package_name..."
    if [ -e "$(find /usr/lib -path '*/python3.*/EXTERNALLY-MANAGED' -print -quit)" ]; then
      pip3 -q install "$package_name" --break-system-packages --no-warn-script-location         2>&1 >> "$LOG"
    else
      pip3 -q install "$package_name" --no-warn-script-location                                 2>&1 >> "$LOG"
    fi
    print_msg "    - $package_name is now installed"
  fi
}
check_python_version() {
  print_msg "- Checking Python..."
  PYTHON_BIN=""
  if [ -f /usr/bin/python3 ]; then
    PYTHON_BIN="python3"
    print_msg "Python 3 is installed on your system"
    check_and_install_package "mac-vendor-lookup"
    check_and_install_package "fritzconnection"
    check_and_install_package "routeros_api"
    check_and_install_package "pyunifi"
    check_and_install_package "openwrt-luci-rpc"
    check_and_install_package "asusrouter"

    REQUIRED_VERSION="2.31.0"
    INSTALLED_VERSION=$(pip3 show requests 2>/dev/null | awk '/^Version:/ {print $2}')

    version_lt () {
      [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" != "$2" ]
    }

    if [ -z "$INSTALLED_VERSION" ] || version_lt "$INSTALLED_VERSION" "$REQUIRED_VERSION"; then
      print_msg "  - Updating requests (installed: ${INSTALLED_VERSION:-none})"
      if [ -e "$(find /usr/lib -path '*/python3.*/EXTERNALLY-MANAGED' -print -quit)" ]; then
        pip3 -q install "requests>=${REQUIRED_VERSION}" --break-system-packages --no-warn-script-location   2>&1 >> "$LOG"
      else
        pip3 -q install "requests>=${REQUIRED_VERSION}" --no-warn-script-location                           2>&1 >> "$LOG"
      fi
    fi

  else
    print_msg "Python 3 NOT installed"
    process_error "Python 3 is required for this application"
  fi
}

# ------------------------------------------------------------------------------
# Move Logfile
# ------------------------------------------------------------------------------
move_logfile() {
  NEWLOG="$PIALERT_SATELLITE_HOME/log/$LOG"

  mkdir -p "$PIALERT_SATELLITE_HOME/log"
  mv $LOG $NEWLOG

  LOG="$NEWLOG"
  NEWLOG=""
}

# ------------------------------------------------------------------------------
# Log
# ------------------------------------------------------------------------------
log() {
  echo "$1" | tee -a "$LOG"
}

log_no_screen () {
  echo "$1" >> "$LOG"
}

log_only_screen () {
  echo "$1"
}

print_msg() {
  log_no_screen ""
  log "$1"
}

print_superheader() {
  log ""
  log "############################################################"
  log " $1"
  log "############################################################"  
}

print_header() {
  log ""
  log "------------------------------------------------------------"
  log " $1"
  log "------------------------------------------------------------"
}

process_error() {
  log ""
  log "************************************************************"
  log "************************************************************"
  log "**             ERROR UPDATING PI.ALERT                    **"
  log "************************************************************"
  log "************************************************************"
  log ""
  log "$1"
  log ""
  log "Use 'cat $LOG' to view update log"
  log ""

  exit 1
}

# ------------------------------------------------------------------------------
  main
  exit 0
