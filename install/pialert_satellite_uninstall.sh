#!/bin/bash
# ------------------------------------------------------------------------------
#  pialert_satellite_uninstall.sh - Uninstallation script
# ------------------------------------------------------------------------------
#  Puche 2021        pi.alert.application@gmail.com        GNU GPLv3
#  leiweibau 2024                                          GNU GPLv3
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Variables
# ------------------------------------------------------------------------------

  INSTALL_DIR=$HOME
  PIALERT_HOME="$INSTALL_DIR/pialert_satellite"
  LOG="pialert_uninstall_`date +"%Y-%m-%d_%H-%M"`.log"

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
main() {
  print_superheader "Pi.Alert Uninstallation"
  log "`date`"
  log "Logfile: $LOG"

  log "The uninstallation process will start now"

  # Uninstall prrocess
  print_header "Removing files"
  sudo rm -r "$PIALERT_HOME"                                      2>&1 >> "$LOG"
  #sudo rm /etc/sudoers.d/pialert-backend                          2>&1 >> "$LOG"
  #sudo rm /etc/sudoers.d/pialert-frontend                         2>&1 >> "$LOG"

  # Uninstall crontab jobs
  print_header "Removing crontab jobs"
  crontab -l 2>/dev/null | sed '/satellite.py/d' | crontab -

  # final message
  log "Uninstallation process finished"
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

# ------------------------------------------------------------------------------
  main
  exit 0
