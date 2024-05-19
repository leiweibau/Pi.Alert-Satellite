#!/bin/bash
# ------------------------------------------------------------------------------
#  Pi.Alert
#  Open Source Network Guard / WIFI & LAN intrusion detector 
#
#  pialert_install.sh - Installation script
# ------------------------------------------------------------------------------
#  Puche 2021        pi.alert.application@gmail.com        GNU GPLv3
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Variables
# ------------------------------------------------------------------------------
  COLS=70
  ROWS=12
  
  INSTALL_DIR=~
  PIALERT_HOME="$INSTALL_DIR/pialert_satellite"

  
  LOG="pialert_install_`date +"%Y-%m-%d_%H-%M"`.log"
  
  # MAIN_IP=`ip -o route get 1 | sed -n 's/.*src \([0-9.]\+\).*/\1/p'`
  MAIN_IP=`ip -o route get 1 | sed 's/^.*src \([^ ]*\).*$/\1/;q'`
  
  USE_PYTHON_VERSION=0
  PYTHON_BIN=python


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
main() {
  print_superheader "Pi.Alert Satellite Installation"
  log "`date`"
  log "Logfile: $LOG"
  install_dependencies

  check_pialert_home

  set -e

  install_arpscan
  install_python
  install_pialert

  print_header "Installation process finished"
  print_msg ""

  move_logfile
}


# ------------------------------------------------------------------------------
# Install arp-scan & dnsutils
# ------------------------------------------------------------------------------
install_arpscan() {
  print_header "arp-scan, dnsutils and nmap"

  print_msg "- Installing arp-scan..."
  sudo apt-get install arp-scan -y                                          2>&1 >> "$LOG"
  sudo mkdir -p /usr/share/ieee-data                                        2>&1 >> "$LOG"

  print_msg "- Testing arp-scan..."
  sudo arp-scan -l | head -n -3 | tail +3 | tee -a "$LOG"

  print_msg "- Installing dnsutils & net-tools..."
  sudo apt-get install dnsutils net-tools libwww-perl libtext-csv-perl -y   2>&1 >> "$LOG"

  print_msg "- Installing nmap, zip, aria2 and wakeonlan"
  sudo apt-get install aria2 -y                                             2>&1 >> "$LOG"
}
  
# ------------------------------------------------------------------------------
# Install Python
# ------------------------------------------------------------------------------
install_python() {
  print_header "Python"

  check_python_versions

  if [ $USE_PYTHON_VERSION -eq 0 ] ; then
    print_msg "- Using the available Python version installed"
    if $PYTHON3 ; then
      print_msg "  - Python 3 is available"
      USE_PYTHON_VERSION=3
    elif $PYTHON2 ; then
      print_msg "  - Python 2 is available but no longer compatible with Pi.Alert"
      print_msg "    - Python 3 will be installed"
      USE_PYTHON_VERSION=3
    else
      print_msg "  - Python is not available in this system"
      print_msg "    - Python 3 will be installed"
      USE_PYTHON_VERSION=3
    fi
    echo ""
  fi

  if [ $USE_PYTHON_VERSION -eq 3 ] ; then
    if $PYTHON3 ; then
      print_msg "- Using Python 3"
      sudo apt-get install python3-pip python3-cryptography python3-requests -y                 2>&1 >> "$LOG"
    else
      print_msg "- Installing Python 3..."
      sudo apt-get install python3 python3-pip python3-cryptography python3-requests -y         2>&1 >> "$LOG"
    fi
    print_msg "    - Install additional packages"
    if [ -f /usr/lib/python3.*/EXTERNALLY-MANAGED ]; then
      pip3 -q install mac-vendor-lookup --break-system-packages --no-warn-script-location       2>&1 >> "$LOG"
      pip3 -q install fritzconnection --break-system-packages --no-warn-script-location         2>&1 >> "$LOG"
      pip3 -q install routeros_api --break-system-packages --no-warn-script-location            2>&1 >> "$LOG"
      pip3 -q install pyunifi --break-system-packages --no-warn-script-location                 2>&1 >> "$LOG"
      pip3 -q install pycrypto --break-system-packages --no-warn-script-location                2>&1 >> "$LOG"
    else
      pip3 -q install mac-vendor-lookup  --no-warn-script-location                              2>&1 >> "$LOG"
      pip3 -q install fritzconnection --no-warn-script-location                                 2>&1 >> "$LOG"
      pip3 -q install routeros_api --no-warn-script-location                                    2>&1 >> "$LOG"
      pip3 -q install pyunifi --no-warn-script-location                                         2>&1 >> "$LOG"
      pip3 -q install pycrypto --no-warn-script-location                                        2>&1 >> "$LOG"
    fi

    PYTHON_BIN="python3"
  else
    process_error "Unknown Python version to use: $USE_PYTHON_VERSION"
  fi
}

# ------------------------------------------------------------------------------
# Check Python versions available
# ------------------------------------------------------------------------------
check_python_versions() {
  print_msg "- Checking Python 2..."
  if [ -f /usr/bin/python ] ; then
    print_msg "  - Python 2 is installed"
    print_msg "    - `python -V 2>&1`"
    PYTHON2=true
  else
    print_msg "  - Python 2 is NOT installed"
    PYTHON2=false
  fi
  echo ""

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
install_pialert() {
  # print_header "Pi.Alert"

  # download_pialert
  # configure_pialert
  # test_pialert
  # add_jobs_to_crontab
  # publish_pialert
  # set_pialert_default_page
}

# ------------------------------------------------------------------------------
# Download and uncompress Pi.Alert
# ------------------------------------------------------------------------------
download_pialert() {
  if [ -f "$INSTALL_DIR/pialert_latest.tar" ] ; then
    print_msg "- Deleting previous downloaded tar file"
    rm -r "$INSTALL_DIR/pialert_latest.tar"
  fi
  
  print_msg "- Downloading installation tar file..."
  URL="https://github.com/leiweibau/Pi.Alert/raw/main/tar/pialert_latest.tar"
  # Testing
  # ----------------------------------
  #URL=""
  wget -q --show-progress -O "$INSTALL_DIR/pialert_latest.tar" "$URL"
  echo ""

  print_msg "- Uncompressing tar file"
  tar xf "$INSTALL_DIR/pialert_latest.tar" -C "$INSTALL_DIR" --checkpoint=100 --checkpoint-action="ttyout=."        2>&1 >> "$LOG"
  echo ""

  print_msg "- Deleting downloaded tar file..."
  rm -r "$INSTALL_DIR/pialert_latest.tar"                                                                           2>&1 >> "$LOG"

  print_msg "- Generate autocomplete file..."
  PIALERT_CLI_PATH=$(dirname $PIALERT_HOME)
  sed -i "s|<YOUR_PIALERT_PATH>|$PIALERT_CLI_PATH/pialert|" $PIALERT_HOME/install/pialert-cli.autocomplete

  print_msg "- Copy autocomplete file..."
  if [ -d "/etc/bash_completion.d" ] ; then
      sudo cp $PIALERT_HOME/install/pialert-cli.autocomplete /etc/bash_completion.d/pialert-cli                     2>&1 >> "$LOG"
  elif [ -d "/usr/share/bash-completion/completions" ] ; then
      sudo cp $PIALERT_HOME/install/pialert-cli.autocomplete /usr/share/bash-completion/completions/pialert-cli     2>&1 >> "$LOG"
  fi

}

# ------------------------------------------------------------------------------
# Configure Pi.Alert parameters
# ------------------------------------------------------------------------------
configure_pialert() {
  print_msg "- Settting Pi.Alert config file"

  set_pialert_parameter PIALERT_PATH    "'$PIALERT_HOME'"

}

# ------------------------------------------------------------------------------
# Set Pi.Alert parameter
# ------------------------------------------------------------------------------
set_pialert_parameter() {
  if [ "$2" = "false" ] ; then
    VALUE="False"
  elif [ "$2" = "true" ] ; then
    VALUE="True"
  else
    VALUE="$2"
  fi
  
  sed -i "/^$1.*=/s|=.*|= $VALUE|" $PIALERT_HOME/config/pialert.conf                             2>&1 >> "$LOG"
}

# ------------------------------------------------------------------------------
# Test Pi.Alert
# ------------------------------------------------------------------------------
test_pialert() {
  print_msg "- Testing Pi.Alert HW vendors database update process..."
  print_msg "- Prepare directories..."
  if [ ! -e /var/lib/ieee-data ]; then
    sudo ln -s /usr/share/ieee-data/ /var/lib/ieee-data                                          2>&1 >> "$LOG"
  fi

  print_msg "*** PLEASE WAIT A COUPLE OF MINUTES..."
  stdbuf -i0 -o0 -e0  $PYTHON_BIN $PIALERT_HOME/back/satellite.py update_vendors_silent            2>&1 | tee -ai "$LOG"

  echo ""
  print_msg "- Testing Pi.Alert Internet IP Lookup..."
  stdbuf -i0 -o0 -e0  $PYTHON_BIN $PIALERT_HOME/back/satellite.py internet_IP                      2>&1 | tee -ai "$LOG"

  echo ""
  print_msg "- Testing Pi.Alert Network scan..."
  print_msg "*** PLEASE WAIT A COUPLE OF MINUTES..."
  stdbuf -i0 -o0 -e0  $PYTHON_BIN $PIALERT_HOME/back/satellite.py scan                             2>&1 | tee -ai "$LOG"

}

# ------------------------------------------------------------------------------
# Add Pi.Alert jobs to crontab
# ------------------------------------------------------------------------------
add_jobs_to_crontab() {
  if crontab -l 2>/dev/null | grep -Fq pialert ; then
    print_msg "- Pi.Alert crontab jobs already exists. This is your crontab:"
    crontab -l | grep -F pialert                                                                 2>&1 | tee -ai "$LOG"
    return    
  fi

  print_msg "- Adding jobs to the crontab..."
  # if [ $USE_PYTHON_VERSION -eq 3 ] ; then
  #   sed -i "s/\<python\>/$PYTHON_BIN/g" $PIALERT_HOME/install/pialert.cron
  # fi

  (crontab -l 2>/dev/null || : ; cat $PIALERT_HOME/install/pialert.cron) | crontab -
}

# ------------------------------------------------------------------------------
# Publish Pi.Alert web
# ------------------------------------------------------------------------------
publish_pialert() {
  if [ -e "$WEBROOT/pialert" ] || [ -L "$WEBROOT/pialert" ] ; then
    print_msg "- Deleting previous Pi.Alert site"
    sudo rm -r "$WEBROOT/pialert"                                                                               2>&1 >> "$LOG"
  fi

  print_msg "- Setting permissions..."
  chmod go+x $INSTALL_DIR
  sudo chgrp -R www-data "$PIALERT_HOME/db"                                                                     2>&1 >> "$LOG"
  sudo chmod -R 775 "$PIALERT_HOME/db"                                                                          2>&1 >> "$LOG"
  sudo chmod -R 775 "$PIALERT_HOME/db/temp"                                                                     2>&1 >> "$LOG"
  sudo chgrp -R www-data "$PIALERT_HOME/config"                                                                 2>&1 >> "$LOG"
  sudo chmod -R 775 "$PIALERT_HOME/config"                                                                      2>&1 >> "$LOG"
  sudo chgrp -R www-data "$PIALERT_HOME/front/reports"                                                          2>&1 >> "$LOG"
  sudo chmod -R 775 "$PIALERT_HOME/front/reports"                                                               2>&1 >> "$LOG"
  sudo chgrp -R www-data "$PIALERT_HOME/back/speedtest/"                                                        2>&1 >> "$LOG"
  sudo chmod -R 775 "$PIALERT_HOME/back/speedtest/"                                                             2>&1 >> "$LOG"
  chmod +x "$PIALERT_HOME/back/shoutrrr/arm64/shoutrrr"                                                         2>&1 >> "$LOG"
  chmod +x "$PIALERT_HOME/back/shoutrrr/armhf/shoutrrr"                                                         2>&1 >> "$LOG"
  chmod +x "$PIALERT_HOME/back/shoutrrr/x86/shoutrrr"                                                           2>&1 >> "$LOG"

  print_msg "- Set sudoers..."
  sudo $PIALERT_HOME/back/pialert-cli set_sudoers                                                               2>&1 >> "$LOG"

}

# ------------------------------------------------------------------------------
# Check Pi.Alert Installation Path
# ------------------------------------------------------------------------------
check_pialert_home() {
  mkdir -p "$INSTALL_DIR"
  if [ ! -d "$INSTALL_DIR" ] ; then
    process_error "Installation path does not exists: $INSTALL_DIR"
  fi

  if [ -e "$PIALERT_HOME" ] || [ -L "$PIALERT_HOME" ] ; then
    process_error "Pi.Alert path already exists: $PIALERT_HOME"
  fi
  sudo apt-get install cron whiptail -y
}

# ------------------------------------------------------------------------------
# Check Pi.Alert Installation Path
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
  NEWLOG="$PIALERT_HOME/log/$LOG"

  mkdir -p "$PIALERT_HOME/log"
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
  log "**            ERROR INSTALLING PI.ALERT                   **"
  log "************************************************************"
  log "************************************************************"
  log ""
  log "$1"
  log ""
  log "Use 'cat $LOG' to view installation log"
  log ""

  # msgbox "****** ERROR INSTALLING Pi.ALERT ******" "$1"
  exit 1
}

# ------------------------------------------------------------------------------
  main
  exit 0
