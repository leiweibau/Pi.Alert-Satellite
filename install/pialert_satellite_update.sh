#!/usr/bin/env bash
# ------------------------------------------------------------------------------
#  Pi.Alert
#  Open Source Network Guard / WIFI & LAN intrusion detector 
#
#  pialert_update.sh - Update script
# ------------------------------------------------------------------------------
#  Puche 2021        pi.alert.application@gmail.com        GNU GPLv3
#  leiweibau 2023                                          GNU GPLv3
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
  download_pialert_satellite
  update_config

  test_pialert
  
  print_header "Update process finished"
  print_msg ""

  move_logfile
}

# ------------------------------------------------------------------------------
# Create backup
# ------------------------------------------------------------------------------
create_backup() {
  # Previous backups are deleted to preserve storage 
  print_msg "- Deleting previous Pi.Alert backups..."
  rm -f "$INSTALL_DIR/"satellite_update_backup_*.tar
  print_msg "- Creating new Pi.Alert backup..."
  cd "$INSTALL_DIR"
  tar cvf "$INSTALL_DIR"/satellite_update_backup_`date +"%Y-%m-%d_%H-%M"`.tar pialert_satellite --checkpoint=100 --checkpoint-action="ttyout=."     2>&1 >> "$LOG"
}

# ------------------------------------------------------------------------------
# Check packages
# ------------------------------------------------------------------------------
check_packages() {
  sudo apt-get update 2>&1 >>"$LOG"
  packages=("apt-utils" "git" "dnsutils" "net-tools" "nbtscan" "avahi-utils" "python3-requests" "python3-cryptography" "libwww-perl" "mmdb-bin" "libtext-csv-perl" "aria2")
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
download_pialert_satellite() {
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

# 2023-10-19
# if ! grep -Fq "# Automatic Speedtest" "$PIALERT_SATELLITE_HOME/config/satellite.conf" ; then
#   cat << EOF >> "$PIALERT_SATELLITE_HOME/config/satellite.conf"

# # Automatic Speedtest
# # ----------------------
# SPEEDTEST_TASK_ACTIVE = False
# SPEEDTEST_TASK_HOUR   = []
# EOF
# fi

}

# ------------------------------------------------------------------------------
# Test Pi.Alert-Satellite
# ------------------------------------------------------------------------------
test_pialert() {
  echo ""
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
    print_msg "$package_name is already installed"
  else
    print_msg "Installing $package_name..."
    if [ -f /usr/lib/python3.*/EXTERNALLY-MANAGED ]; then
      pip3 -q install "$package_name" --break-system-packages --no-warn-script-location       2>&1 >> "$LOG"
    else
      pip3 -q install "$package_name" --no-warn-script-location                               2>&1 >> "$LOG"
    fi
    print_msg "$package_name is now installed"
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
