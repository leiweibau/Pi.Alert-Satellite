#!/bin/bash
# ------------------------------------------------------------------------------
#  pialert_satellite_install.sh - Installation script
# ------------------------------------------------------------------------------
#  Puche 2021        pi.alert.application@gmail.com        GNU GPLv3
#  leiweibau 2024                                          GNU GPLv3
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Variables
# ------------------------------------------------------------------------------
  SAT_TOKEN=$1
  SAT_PASSWORD=$2
  SAT_PROXY_MODE=$3
  SAT_URL=$4

  INSTALL_DIR=~
  PIALERT_SATELLITE_HOME="$INSTALL_DIR/pialert_satellite"
  LOG="satellite_install_`date +"%Y-%m-%d_%H-%M"`.log"
  
  USE_PYTHON_VERSION=0
  PYTHON_BIN=python

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
main() {
  print_superheader "Pi.Alert-Satellite Installation"
  log "`date`"
  log "Logfile: $LOG"
  install_dependencies

  check_pialert_satellite_home

  set -e

  install_additional_dependencies
  install_pialert_satellite

  print_header "Installation process finished"
  print_msg ""

  move_logfile
}


# ------------------------------------------------------------------------------
# Install arp-scan & dnsutils
# ------------------------------------------------------------------------------
install_additional_dependencies() {
  print_header "arp-scan, dnsutils and nmap"

  print_msg "- Installing arp-scan..."
  sudo apt-get install arp-scan -y                                                    2>&1 >> "$LOG"
  sudo mkdir -p /usr/share/ieee-data                                                  2>&1 >> "$LOG"
  if [ -f "/usr/share/arp-scan/ieee-iab.txt.bak" ]; then
      sudo mv /usr/share/arp-scan/ieee-iab.txt.bak /usr/share/arp-scan/ieee-iab.txt   2>&1 >> "$LOG"
  fi
  if [ -d "/usr/share/arp-scan/2_backup" ]; then
      sudo rm -rf /usr/share/arp-scan/2_backup                                        2>&1 >> "$LOG"
  fi
  print_msg "- Testing arp-scan..."
  sudo arp-scan -l | head -n -3 | tail +3 | tee -a "$LOG"

  print_msg "- Installing dnsutils & net-tools..."
  sudo apt-get install dnsutils net-tools curl libwww-perl libtext-csv-perl -y        2>&1 >> "$LOG"

  print_msg "- Installation of tools for hostname detection..."
  sudo apt-get install avahi-utils nbtscan -y                                         2>&1 >> "$LOG"

  print_msg "- Installing aria2"
  sudo apt-get install aria2 -y                                                       2>&1 >> "$LOG"

  print_header "Python"

  check_python_versions

  if $PYTHON3 ; then
    print_msg "  - Python 3 is available"
    USE_PYTHON_VERSION=3
  elif $PYTHON2 ; then
    print_msg "  - Python 2 is available but not compatible with Pi.Alert-Satellite"
    print_msg "    - Python 3 will be installed"
    USE_PYTHON_VERSION=3
  else
    print_msg "  - Python is not available in this system"
    print_msg "    - Python 3 will be installed"
    USE_PYTHON_VERSION=3
  fi

  if $PYTHON3 ; then
    print_msg "- Using Python 3"
    sudo apt-get install python3-pip python3-cryptography python3-requests python3-cpuinfo python3-distro python3-psutil python3-tz python3-tzlocal -y                 2>&1 >> "$LOG"
  else
    print_msg "- Installing Python 3..."
    sudo apt-get install python3 python3-pip python3-cryptography python3-requests python3-cpuinfo python3-distro python3-psutil python3-tz python3-tzlocal  -y         2>&1 >> "$LOG"
  fi
  print_msg "    - Install additional packages"
  if [ -f /usr/lib/python3.*/EXTERNALLY-MANAGED ]; then
    pip3 -q install mac-vendor-lookup --break-system-packages --no-warn-script-location       2>&1 >> "$LOG"
    pip3 -q install fritzconnection --break-system-packages --no-warn-script-location         2>&1 >> "$LOG"
    pip3 -q install routeros_api --break-system-packages --no-warn-script-location            2>&1 >> "$LOG"
    pip3 -q install pyunifi --break-system-packages --no-warn-script-location                 2>&1 >> "$LOG"
    pip3 -q install openwrt-luci-rpc --break-system-packages --no-warn-script-location        2>&1 >> "$LOG"
  else
    pip3 -q install mac-vendor-lookup  --no-warn-script-location                              2>&1 >> "$LOG"
    pip3 -q install fritzconnection --no-warn-script-location                                 2>&1 >> "$LOG"
    pip3 -q install routeros_api --no-warn-script-location                                    2>&1 >> "$LOG"
    pip3 -q install pyunifi --no-warn-script-location                                         2>&1 >> "$LOG"
    pip3 -q install openwrt-luci-rpc --no-warn-script-location                                2>&1 >> "$LOG"
  fi

  PYTHON_BIN="python3"

}

# ------------------------------------------------------------------------------
# Check Python versions available
# ------------------------------------------------------------------------------
check_python_versions() {
  if [ -f /usr/bin/python ] ; then
    PYTHON2=true
  else
    PYTHON2=false
  fi

  print_msg "- Checking Python 3..."
  if [ -f /usr/bin/python3 ] ; then
    print_msg "  - Python 3 is installed"
    print_msg "    - `python3 -V 2>&1`"
    PYTHON3=true
  else
    print_msg "  - Python 3 is NOT installed"
    PYTHON3=false
  fi
  echo ""
}

# ------------------------------------------------------------------------------
# Install Pi.Alert
# ------------------------------------------------------------------------------
install_pialert_satellite() {
  print_header "Pi.Alert-Satellite"

  download_satellite
  configure_satellite
  configure_user
  test_satellite
  add_jobs_to_crontab
}

# ------------------------------------------------------------------------------
# Download and uncompress Pi.Alert
# ------------------------------------------------------------------------------
download_satellite() {
  if [ -f "$INSTALL_DIR/pialert_satellite_latest.tar" ] ; then
    print_msg "- Deleting previous downloaded tar file"
    rm -r "$INSTALL_DIR/pialert_satellite_latest.tar"
  fi
  
  print_msg "- Downloading installation tar file..."
  URL="https://github.com/leiweibau/Pi.Alert-Satellite/raw/main/tar/pialert_satellite_latest.tar"

  wget -q --show-progress -O "$INSTALL_DIR/pialert_satellite_latest.tar" "$URL"
  echo ""

  print_msg "- Uncompressing tar file"
  tar xf "$INSTALL_DIR/pialert_satellite_latest.tar" -C "$INSTALL_DIR" --checkpoint=100 --checkpoint-action="ttyout=."        2>&1 >> "$LOG"
  echo ""

  print_msg "- Deleting downloaded tar file..."
  rm -r "$INSTALL_DIR/pialert_satellite_latest.tar"                                                                           2>&1 >> "$LOG"

}

# ------------------------------------------------------------------------------
# Configure Pi.Alert-Satellite parameters
# ------------------------------------------------------------------------------
configure_satellite() {
  print_msg "- Setting Pi.Alert-Satellite config file"

  if [ -n "$SAT_TOKEN" ]; then
      set_satellite_parameter SATELLITE_TOKEN "'$SAT_TOKEN'"
  fi

  if [ -n "$SAT_PASSWORD" ]; then
      set_satellite_parameter SATELLITE_PASSWORD "'$SAT_PASSWORD'"
  fi
  if [ -n "$SAT_PROXY_MODE" ]; then
      set_satellite_parameter PROXY_MODE "$SAT_PROXY_MODE"
  fi

  if [ -n "$SAT_URL" ]; then
      set_satellite_parameter SATELLITE_MASTER_URL "'$SAT_URL'"
  fi

  set_satellite_parameter SATELLITE_PATH "'$PIALERT_SATELLITE_HOME'"

}

# ------------------------------------------------------------------------------
# Configure User
# ------------------------------------------------------------------------------
configure_user() {
  SAT_USER=$(whoami)
  print_msg "Pi.Alert-Satellite User: $SAT_USER"
  echo -e "    ...Create Satellite sudoer file to be able to run \"arp-scan\""
  echo "${SAT_USER} ALL=(ALL) NOPASSWD: /usr/sbin/arp-scan" | sudo tee /etc/sudoers.d/pialert-satellite
}

# ------------------------------------------------------------------------------
# Set Pi.Alert-Satellite parameter
# ------------------------------------------------------------------------------
set_satellite_parameter() {
  if [ "$2" = "false" ] ; then
    VALUE="False"
  elif [ "$2" = "true" ] ; then
    VALUE="True"
  else
    VALUE="$2"
  fi
  
  sed -i "/^$1.*=/s|=.*|= $VALUE|" $PIALERT_SATELLITE_HOME/config/satellite.conf                          2>&1 >> "$LOG"
}

# ------------------------------------------------------------------------------
# Test Pi.Alert
# ------------------------------------------------------------------------------
test_satellite() {
  print_msg "- Testing Pi.Alert-Satellite HW vendors database update process..."
  print_msg "- Prepare directories..."
  if [ ! -e /var/lib/ieee-data ]; then
    sudo ln -s /usr/share/ieee-data/ /var/lib/ieee-data                                                   2>&1 >> "$LOG"
  fi

  stdbuf -i0 -o0 -e0  $PYTHON_BIN $PIALERT_SATELLITE_HOME/back/satellite.py update_vendors_silent         2>&1 | tee -ai "$LOG"
}

# ------------------------------------------------------------------------------
# Add Pi.Alert-Satellite jobs to crontab
# ------------------------------------------------------------------------------
add_jobs_to_crontab() {
  if crontab -l 2>/dev/null | grep -Fq satellite ; then
    print_msg "- Pi.Alert-Satellite crontab jobs already exists. This is your crontab:"
    crontab -l | grep -F satellite                                                                 2>&1 | tee -ai "$LOG"
    return    
  fi

  print_msg "- Adding jobs to the crontab..."

  (crontab -l 2>/dev/null || : ; cat $PIALERT_SATELLITE_HOME/install/satellite.cron) | crontab -
}

# ------------------------------------------------------------------------------
# Check Pi.Alert-Satellite Installation Path
# ------------------------------------------------------------------------------
check_pialert_satellite_home() {
  mkdir -p "$INSTALL_DIR"
  if [ ! -d "$INSTALL_DIR" ] ; then
    process_error "Installation path does not exists: $INSTALL_DIR"
  fi

  if [ -e "$PIALERT_SATELLITE_HOME" ] || [ -L "$PIALERT_SATELLITE_HOME" ] ; then
    process_error "Pi.Alert-Satellite path already exists: $PIALERT_SATELLITE_HOME"
  fi
  sudo apt-get install cron whiptail -y
}

# ------------------------------------------------------------------------------
# Check Pi.Alert-Satellite Installation Path
# ------------------------------------------------------------------------------
install_dependencies() {
  print_msg "- Installing dependencies..."
  if [ $(id -u) -eq 0 ]; then
      apt-get install sudo -y                                    2>&1 >> "$LOG"
  fi

  sudo apt-get install cron whiptail -y                          2>&1 >> "$LOG"
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
  log "**          ERROR INSTALLING PI.ALERT-SATELLITE           **"
  log "************************************************************"
  log "************************************************************"
  log ""
  log "$1"
  log ""
  log "Use 'cat $LOG' to view installation log"
  log ""

  # msgbox "****** ERROR INSTALLING Pi.Alert-Satellite ******" "$1"
  exit 1
}

# ------------------------------------------------------------------------------
  main
  exit 0
