#!/usr/bin/env python
#
#-------------------------------------------------------------------------------
#  Pi.Alert Satellite
#-------------------------------------------------------------------------------
#  Puche 2021                                              GNU GPLv3
#  leiweibau 2024                                          GNU GPLv3
#-------------------------------------------------------------------------------

#===============================================================================
# IMPORTS
#===============================================================================
from __future__ import print_function
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from mac_vendor_lookup import MacLookup
from time import sleep, time, strftime
from base64 import b64encode
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from datetime import datetime
import sys, subprocess, os, re, datetime, socket, io, requests, time, pwd, glob, ipaddress, ssl, json
from Crypto.Cipher import AES

#===============================================================================
# CONFIG CONSTANTS
#===============================================================================
PIALERT_BACK_PATH = os.path.dirname(os.path.abspath(__file__))
PIALERT_PATH = PIALERT_BACK_PATH + "/.."
STATUS_FILE_SCAN = PIALERT_BACK_PATH + "/.scanning"
STATUS_FILE_BACKUP = PIALERT_BACK_PATH + "/.backup"

if (sys.version_info > (3,0)):
    exec(open(PIALERT_PATH + "/config/version.conf").read())
    exec(open(PIALERT_PATH + "/config/satellite.conf").read())
else:
    execfile(PIALERT_PATH + "/config/version.conf")
    execfile(PIALERT_PATH + "/config/satellite.conf")

#===============================================================================
# MAIN
#===============================================================================
def main():
    global startTime
    global cycle
    global log_timestamp
    # global sql_connection
    # global sql

    # Header
    print('\nPi.Alert Satellite v'+ VERSION_DATE)
    print('---------------------------------------------------------')
    print(f"Executing user: {get_username()}\n")

    # Initialize global variables
    log_timestamp  = datetime.datetime.now()

    # Timestamp
    startTime = datetime.datetime.now()
    startTime = startTime.replace (second=0, microsecond=0)

    # Check parameters
    if len(sys.argv) != 2 :
        print('usage satelite scan | internet_IP | update_vendors' )
        return
    cycle = str(sys.argv[1])

    # internet_IP currently not used
    if cycle == 'update_vendors':
        res = update_devices_MAC_vendors()
    elif cycle == 'update_vendors_silent':
        res = update_devices_MAC_vendors('-s')
    elif cycle == 'scan':
        res = scan_network()
    else:
        print('usage satelite scan | internet_IP | update_vendors' )
        return

    # Remove scan status file created in scan_network()
    if cycle not in ['internet_IP' 'update_vendors', 'update_vendors_silent'] and os.path.exists(STATUS_FILE_SCAN):
        os.remove(STATUS_FILE_SCAN)

    # Final menssage
    print('\nDONE!!!\n\n')
    return 0    

#===============================================================================
# Set Env (Userpermissions DB-file)
#===============================================================================
def get_username():
    return pwd.getpwuid(os.getuid())[0]

#===============================================================================
# Satellite Scan
#===============================================================================
def check_internet_IP():
    # Header
    print('    Retrieving Internet IP...')
    internet_IP = get_internet_IP()

    # Check result = IP
    if internet_IP == "" :
        print('    Error retrieving Internet IP')
        print('    Exiting...\n')
        return 1
    
    print('   ', internet_IP)

    internet_detection = []
    internet_scan = {
        "mac": "Internet - " + SATELLITE_TOKEN,
        "ip": internet_IP
    }

    internet_detection.append(internet_scan)
    
    return internet_detection

# ------------------------------------------------------------------------------
def parse_cron_part(cron_part, current_value, cron_min_value, cron_max_value):
    if cron_part == '*':
        return set(range(cron_min_value, cron_max_value))
    elif '/' in cron_part:
        step = int(cron_part.split('/')[1])
        return set(range(cron_min_value, cron_max_value, step))
    elif '-' in cron_part:
        start, end = map(int, cron_part.split('-'))
        return set(range(start, end + 1))
    elif ',' in cron_part:
        values = cron_part.split(',')
        return set(int(value) for value in values)
    else:
        return {int(cron_part)}

#-------------------------------------------------------------------------------
def get_internet_IP():
    curl_args = ['curl', '-s', QUERY_MYIP_SERVER]
    cmd_output = subprocess.check_output (curl_args, universal_newlines=True)
    return check_IP_format (cmd_output)
    
#-------------------------------------------------------------------------------
def check_IP_format(pIP):
    # Check IP format
    IPv4SEG  = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
    IPv4ADDR = r'(?:(?:' + IPv4SEG + r'\.){3,3}' + IPv4SEG + r')'
    IP = re.search(IPv4ADDR, pIP)
    # Return error if not IP
    if IP is None :
        return ""
    return IP.group(0)

#-------------------------------------------------------------------------------
def update_devices_MAC_vendors (pArg = ''):
    print('Update HW Vendors')
    print('    Timestamp:', startTime )

    # Update vendors DB (oui)
    print('\nUpdating vendors DB...')
    update_args = ['sh', PIALERT_BACK_PATH + '/update_vendors.sh', pArg]
    update_output = subprocess.check_output (update_args)

    # mac-vendor-lookup update
    try:
        print('\nTry build in mac-vendor-lookup update')
        mac = MacLookup()
        mac.update_vendors()
        print('    Update successful')
    except:
        print('\nFallback')
        print('    Backup old mac-vendors.txt for mac-vendor-lookup')
        p = subprocess.call(["cp $HOME/.cache/mac-vendors.txt $HOME/.cache/mac-vendors.bak"], shell=True)
        print('    Create mac-vendors.txt for mac-vendor-lookup')
        p = subprocess.call(["/usr/bin/sed -e 's/\t/:/g' -e 's/Ã¼/ü/g' -e 's/Ã¶/ö/g' -e 's/Ã¤/ä/g' -e 's/Ã³/ó/g' -e 's/Ã©/é/g' -e 's/â/–/g' -e 's/Â//g' -e '/^#/d' /usr/share/arp-scan/ieee-oui.txt > $HOME/.cache/mac-vendors.txt"], shell=True)

#-------------------------------------------------------------------------------
def query_MAC_vendor(pMAC):
    try :
        pMACstr = str(pMAC)

        # Check MAC parameter
        mac = pMACstr.replace (':','')
        if len(pMACstr) != 17 or len(mac) != 12 :
            return -2

        # Search vendor in HW Vendors DB
        mac = mac[0:6]
        grep_args = ['grep', '-i', mac, VENDORS_DB]
        grep_output = subprocess.check_output (grep_args)

        # Return Vendor
        vendor = grep_output[7:]
        return vendor.rstrip()

    # not Found
    except subprocess.CalledProcessError :
        return -1
            
#-------------------------------------------------------------------------------
def scan_network():
    output_file_path = PIALERT_PATH + "/log/pialert.scan.log"
    original_stdout = sys.stdout
    with open(output_file_path, "w") as f:
        sys.stdout = f
        # Create scan status file
        with open(STATUS_FILE_SCAN, "w") as f:
            f.write("")

        # Header
        print('Scan Devices')
        print('    Timestamp:', startTime )
        print('\nCheck Internet Connectivity...')
        internet_detection = check_internet_IP()
        # arp-scan command
        print('\nScanning...')
        print('    arp-scan Method...')
        print_log ('arp-scan starts...')
        arpscan_devices = execute_arpscan()
        print_log ('arp-scan ends')
        # Fritzbox
        print('    Fritzbox Method...')
        # openDB()
        print_log ('Fritzbox copy starts...')
        fritzbox_network = read_fritzbox_active_hosts()
        # Mikrotik
        print('    Mikrotik Method...')
        # openDB()
        print_log ('Mikrotik copy starts...')
        mikrotik_network = read_mikrotik_leases()
        # UniFi
        print('    UniFi Method...')
        # openDB()
        print_log ('UniFi copy starts...')
        unifi_network = read_unifi_clients()
        # Load current scan data 1/2
        print('\nProcessing scan results...')
        # Load current scan data 2/2
        print('    Create json of scanned devices')
        jsondata = save_scanned_devices (internet_detection, arpscan_devices, fritzbox_network, mikrotik_network, unifi_network)
        print('    Encrypt data')
        encrypt_scandata(jsondata)
        print('    Transmit to Master')

    sys.stdout = original_stdout

    return 0


#-------------------------------------------------------------------------------
def execute_arpscan():

    # check if arp-scan is active
    try:
        module_arpscan_status = ARPSCAN_ACTIVE
    except NameError:
        module_arpscan_status = True
    if not module_arpscan_status :
        print('        ...Skipped')
        unique_devices = []
        return unique_devices

    # output of possible multiple interfaces
    arpscan_output = ""

    # multiple interfaces
    if type(SCAN_SUBNETS) is list:
        print("    arp-scan: Multiple interfaces")        
        for interface in SCAN_SUBNETS :            
            arpscan_output += execute_arpscan_on_interface (interface)
    # one interface only
    else:
        print("    arp-scan: One interface")
        arpscan_output += execute_arpscan_on_interface (SCAN_SUBNETS)

    # Search IP + MAC + Vendor as regular expresion
    re_ip = r'(?P<ip>((2[0-5]|1[0-9]|[0-9])?[0-9]\.){3}((2[0-5]|1[0-9]|[0-9])?[0-9]))'
    re_mac = r'(?P<mac>([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2}))'
    re_hw = r'(?P<hw>.*)'
    re_pattern = re.compile (re_ip + '\s+' + re_mac + '\s' + re_hw)

    # Create Userdict of devices
    devices_list = [device.groupdict()
        for device in re.finditer (re_pattern, arpscan_output)]

    # Delete duplicate MAC
    unique_mac = [] 
    unique_devices = [] 

    for device in devices_list :
        if device['mac'] not in unique_mac: 
            unique_mac.append(device['mac'])
            unique_devices.append(device)

    return unique_devices

#-------------------------------------------------------------------------------
def execute_arpscan_on_interface(SCAN_SUBNETS):
    # Prepare command arguments
    subnets = SCAN_SUBNETS.strip().split()
    # Retry is 3 to avoid false offline devices
    arpscan_args = ['sudo', 'arp-scan', '--ignoredups', '--bandwidth=256k', '--retry=6'] + subnets

    # Execute command
    try:
        # try runnning a subprocess
        result = subprocess.check_output (arpscan_args, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        # An error occured, handle it
        print(e.output)
        result = ""

    return result

#-------------------------------------------------------------------------------
def read_fritzbox_active_hosts():

    # check if Pi-hole is active
    if not FRITZBOX_ACTIVE :
        print('        ...Skipped')
        return

    from fritzconnection.lib.fritzhosts import FritzHosts

    fritzbox_network = []

    # copy Fritzbox Network list
    fh = FritzHosts(address=FRITZBOX_IP, user=FRITZBOX_USER, password=FRITZBOX_PASS)
    hosts = fh.get_hosts_info()
    for index, host in enumerate(hosts, start=1):
        if host['status'] :
            # status = 'active' if host['status'] else  '-'
            ip = host['ip'] if host['ip'] else 'no IP'
            mac = host['mac'].lower() if host['mac'] else '-'
            hostname = host['name']
            try:
                vendor = MacLookup().lookup(host['mac'])
            except:
                vendor = "Prefix is not registered"
            
            fritzbox_scan = {
                "mac": mac,
                "ip": ip,
                "name": hostname,
                "vendor": vendor
            }
            fritzbox_network.append(fritzbox_scan)
    return fritzbox_network

#-------------------------------------------------------------------------------
def read_mikrotik_leases():

    if not MIKROTIK_ACTIVE:
        print('        ...Skipped')
        return

    #installed using pip3 install routeros_api
    import routeros_api

    mikrotik_network = []

    data = []
    conn = routeros_api.RouterOsApiPool(MIKROTIK_IP, MIKROTIK_USER, MIKROTIK_PASS, plaintext_login=True)
    api = conn.get_api()
    ret = api.get_resource('/ip/dhcp-server/lease').get()
    conn.disconnect()
    for row in ret:
        if 'active-mac-address' in row:
            mac = row['active-mac-address'].lower()
            ip = row['active-address']
            hostname = row.get('host-name','')
            try:
                vendor = MacLookup().lookup(mac)
            except:
                vendor = "Prefix is not registered"

            mikrotik_scan = {
                "mac": mac,
                "ip": ip,
                "hostname": hostname,
                "vendor": vendor
            }

            mikrotik_network.append(mikrotik_scan)

    return mikrotik_network

#-------------------------------------------------------------------------------
def read_unifi_clients():

    if not UNIFI_ACTIVE:
        print('        ...Skipped')
        return

    from pyunifi.controller import Controller

    # Enable self signed SSL / no warnings
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    try:
        UNIFI_API_VERSION = UNIFI_API
    except NameError: # variable not defined, use a default
        UNIFI_API_VERSION = 'v5'

    unifi_network = []

    try:
        data = []
        c = Controller(UNIFI_IP,UNIFI_USER,UNIFI_PASS,8443,UNIFI_API_VERSION,'default',ssl_verify=False)
        clients = c.get_clients()
        for row in clients:
            mac = row['mac'].lower()
            ip = row.get('ip','no IP')
            hostname = row.get('hostname',row.get('name',''))
            vendor = row.get('oui',None)
            if not vendor:
                try:
                    vendor = MacLookup().lookup(mac)
                except:
                    vendor = "Prefix is not registered"

            unifi_scan = {
                "mac": mac,
                "ip": ip,
                "hostname": hostname,
                "vendor": vendor
            }

            unifi_network.append(unifi_scan)

    except Exception as e:
        print('        Could not connect to UniFi Controller')

    return unifi_network

#-------------------------------------------------------------------------------
def save_scanned_devices(p_internet_detection, p_arpscan_devices, p_fritzbox_network, p_mikrotik_network, p_unifi_network):

    all_devices = []

    if bool(p_internet_detection):
        for device in p_internet_detection:
            device_data = {
                'cur_MAC': device['mac'],
                'cur_IP': "",
                'cur_Vendor': "",
                'cur_ScanMethod': 'Internet Check',
                'cur_SatelliteID': SATELLITE_TOKEN
            }
            all_devices.append(device_data)

    if bool(p_arpscan_devices):
        for device in p_arpscan_devices:
            device_data = {
                'cur_MAC': device['mac'],
                'cur_IP': device['ip'],
                'cur_Vendor': device['hw'],
                'cur_ScanMethod': 'arp-scan',
                'cur_SatelliteID': SATELLITE_TOKEN
            }
            all_devices.append(device_data)

    if bool(p_fritzbox_network):
        for device in p_fritzbox_network:
            device_data = {
                'cur_MAC': device['mac'],
                'cur_IP': device['ip'],
                'cur_Vendor': device['vendor'],
                'cur_ScanMethod': 'Fritzbox',
                'cur_SatelliteID': SATELLITE_TOKEN
            }
            all_devices.append(device_data)

    if bool(p_mikrotik_network):
        for device in p_mikrotik_network:
            device_data = {
                'cur_MAC': device['mac'],
                'cur_IP': device['ip'],
                'cur_Vendor': device['vendor'],
                'cur_ScanMethod': 'Mikrotik',
                'cur_SatelliteID': SATELLITE_TOKEN
            }
            all_devices.append(device_data)

    if bool(p_unifi_network):
        for device in p_unifi_network:
            device_data = {
                'cur_MAC': device['mac'],
                'cur_IP': device['ip'],
                'cur_Vendor': device['vendor'],
                'cur_ScanMethod': 'UniFi',
                'cur_SatelliteID': SATELLITE_TOKEN
            }
            all_devices.append(device_data)

    return all_devices

    # Check Internet connectivity
    # internet_IP = get_internet_IP()
        # TESTING - Force IP
        # internet_IP = ""
    # if internet_IP != "" :
        # sql.execute ("""INSERT INTO CurrentScan (cur_ScanCycle, cur_MAC, cur_IP, cur_Vendor, cur_ScanMethod)
        #                 VALUES (?, 'Internet', ?, Null, 'queryDNS') """, (cycle, internet_IP) )

    local_mac_cmd = ["/sbin/ifconfig `ip -o route get 1 | sed 's/^.*dev \\([^ ]*\\).*$/\\1/;q'` | grep ether | awk '{print $2}'"]
    local_mac = subprocess.Popen (local_mac_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].decode().strip()
    
    # local_ip_cmd = ["ip route list default | awk {'print $7'}"]
    local_ip_cmd = ["ip -o route get 1 | sed 's/^.*src \\([^ ]*\\).*$/\\1/;q'"]
    local_ip = subprocess.Popen (local_ip_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].decode().strip()

    # Check if local mac has been detected with other methods
    # sql.execute ("SELECT COUNT(*) FROM CurrentScan WHERE cur_ScanCycle = ? AND cur_MAC = ? ", (cycle, local_mac) )
    # if sql.fetchone()[0] == 0 :
    #     sql.execute ("INSERT INTO CurrentScan (cur_ScanCycle, cur_MAC, cur_IP, cur_Vendor, cur_ScanMethod) "+
    #                  "VALUES ( ?, ?, ?, Null, 'local_MAC') ", (cycle, local_mac, local_ip) )

    # Write Data to JSON-file

#-------------------------------------------------------------------------------
def encrypt_scandata(json_data):

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # Konvertiere das Dictionary in JSON und dann in Binärdaten
    enc_json_data = json.dumps(json_data).encode('utf-8')

    # OpenSSL-Befehl zum Verschlüsseln der Daten
    openssl_command = [
        "openssl", "enc", "-aes-256-cbc", "-salt", "-out", "encrypted_scandata", "-pbkdf2",
        "-pass", "pass:{}".format(SATELLITE_PASSWORD)
    ]

    with subprocess.Popen(openssl_command, stdin=subprocess.PIPE) as proc:
        proc.stdin.write(enc_json_data)

    # # DEBUG
    # with open('output.json', 'w') as outfile:
    #     json.dump(json_data, outfile, indent=4)

    # Lese die verschlüsselten Daten aus der Datei
    with open("encrypted_scandata", "rb") as f:
        encrypted_data = f.read()

    # Die Daten für die API-Anfrage
    post_data = {
        "TOKEN": SATELLITE_TOKEN
    }

    # Dateien für die API-Anfrage
    files = {
        "encrypted_data": ("encrypted_scandata", encrypted_data)
    }

    # API-URL
    api_url = SATELLITE_MASTER_URL

    # Die Anfrage an die API senden, dabei SSL-Verifizierung deaktivieren
    response = requests.post(api_url, data=post_data, files=files, verify=False)

    # try:
    #     response_data = response.json()
    #     print("API-Antwort:")
    #     print(response_data)
    # except json.JSONDecodeError:
    #     print("ERROR / Raw output:")
    #     print(response.text)


#-------------------------------------------------------------------------------
def write_file(pPath, pText):
    # Write the text depending using the correct python version
    if sys.version_info < (3, 0):
        file = io.open (pPath , mode='w', encoding='utf-8')
        file.write ( pText.decode('unicode_escape') )
    else:
        file = open (pPath, 'w', encoding='utf-8')
        file.write (pText) 

    file.close() 

#-------------------------------------------------------------------------------
def append_line_to_file(pPath, pText):
    # append the line depending using the correct python version
    if sys.version_info < (3, 0):
        file = io.open (pPath , mode='a', encoding='utf-8')
        file.write ( pText.decode('unicode_escape') )
    else:
        file = open (pPath, 'a', encoding='utf-8')
        file.write (pText) 

    file.close() 

#-------------------------------------------------------------------------------
def SafeParseGlobalBool(boolVariable):
    if boolVariable in globals():
        return eval(boolVariable)
    return False

#===============================================================================
# UTIL
#===============================================================================
def print_log (pText):
    global log_timestamp

    # Check LOG actived
    if not PRINT_LOG :
        return

    # Current Time    
    log_timestamp2 = datetime.datetime.now()

    # Print line + time + elapsed time + text
    print('--------------------> ',
        log_timestamp2, ' ',
        log_timestamp2 - log_timestamp, ' ',
        pText)

    # Save current time to calculate elapsed time until next log
    log_timestamp = log_timestamp2

#===============================================================================
# BEGIN
#===============================================================================
if __name__ == '__main__':
    sys.exit(main())       
