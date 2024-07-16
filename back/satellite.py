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
from time import sleep, time, strftime, monotonic
from base64 import b64encode
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from datetime import datetime
import sys, subprocess, os, re, datetime, socket, io, requests, time, pwd, glob, ipaddress, ssl, json, cpuinfo, platform

#===============================================================================
# CONFIG CONSTANTS
#===============================================================================
SATELLITE_BACK_PATH = os.path.dirname(os.path.abspath(__file__))
SATELLITE_PATH = SATELLITE_BACK_PATH + "/.."
STATUS_FILE_SCAN = SATELLITE_BACK_PATH + "/.scanning"
STATUS_FILE_BACKUP = SATELLITE_BACK_PATH + "/.backup"

if (sys.version_info > (3,0)):
    exec(open(SATELLITE_PATH + "/config/version.conf").read())
    exec(open(SATELLITE_PATH + "/config/satellite.conf").read())
else:
    execfile(SATELLITE_PATH + "/config/version.conf")
    execfile(SATELLITE_PATH + "/config/satellite.conf")

#===============================================================================
# MAIN
#===============================================================================
def main():
    global startTime
    global cycle
    global log_timestamp

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
    update_args = ['sh', SATELLITE_BACK_PATH + '/update_vendors.sh', pArg]
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
    print('    Encrypt data and transmit to Master or Proxy')
    encrypt_submit_scandata(jsondata)

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

    # copy Fritzbox Network list
    fritzbox_network = []
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
                "hostname": hostname,
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
    # Internet Check
    if bool(p_internet_detection):
        for device in p_internet_detection:
            if len(device['mac']) > 12:
                device_data = {
                    'cur_MAC': device['mac'],
                    'cur_IP': device['ip'],
                    'cur_Vendor': "",
                    'cur_ScanMethod': 'Internet Check',
                    'cur_SatelliteID': SATELLITE_TOKEN
                }
                all_devices.append(device_data)
    # Fritz!Box
    if bool(p_fritzbox_network):
        for device in p_fritzbox_network:
            if len(device['mac']) > 12:
                device_data = {
                    'cur_MAC': device['mac'],
                    'cur_IP': device['ip'],
                    'cur_hostname': device['hostname'],
                    'cur_Vendor': device['vendor'],
                    'cur_ScanMethod': 'Fritzbox',
                    'cur_SatelliteID': SATELLITE_TOKEN
                }
                all_devices.append(device_data)
    # Mikrotik
    if bool(p_mikrotik_network):
        for device in p_mikrotik_network:
            if len(device['mac']) > 12:
                device_data = {
                    'cur_MAC': device['mac'],
                    'cur_IP': device['ip'],
                    'cur_hostname': device['hostname'],
                    'cur_Vendor': device['vendor'],
                    'cur_ScanMethod': 'Mikrotik',
                    'cur_SatelliteID': SATELLITE_TOKEN
                }
                all_devices.append(device_data)
    # UniFi
    if bool(p_unifi_network):
        for device in p_unifi_network:
            if len(device['mac']) > 12:
                device_data = {
                    'cur_MAC': device['mac'],
                    'cur_IP': device['ip'],
                    'cur_hostname': device['hostname'],
                    'cur_Vendor': device['vendor'],
                    'cur_ScanMethod': 'UniFi',
                    'cur_SatelliteID': SATELLITE_TOKEN
                }
                all_devices.append(device_data)
    # Arpscan
    if bool(p_arpscan_devices):
        for device in p_arpscan_devices:
            if len(device['mac']) > 12:
                device_data = {
                    'cur_MAC': device['mac'],
                    'cur_IP': device['ip'],
                    'cur_hostname': '(satellite network client)',
                    'cur_Vendor': device['hw'],
                    'cur_ScanMethod': 'arp-scan',
                    'cur_SatelliteID': SATELLITE_TOKEN
                }
                all_devices.append(device_data)

    # Get Satellite MAC
    local_mac_cmd = ["/sbin/ifconfig `ip -o route get 1 | sed 's/^.*dev \\([^ ]*\\).*$/\\1/;q'` | grep ether | awk '{print $2}'"]
    local_mac = subprocess.Popen (local_mac_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].decode().strip()
    
    # Get Satellite IP
    local_ip_cmd = ["ip -o route get 1 | sed 's/^.*src \\([^ ]*\\).*$/\\1/;q'"]
    local_ip = subprocess.Popen (local_ip_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].decode().strip()

    local_hostname = socket.gethostname()

    # Get Uptime
    monotonic_time = monotonic()
    weeks = int(monotonic_time // 604800)
    days = int((monotonic_time % 604800) // 86400)
    hours = int((monotonic_time % 86400) // 3600)
    minutes = int((monotonic_time % 3600) // 60)
    seconds = int(monotonic_time % 60)

    if weeks > 0:
        formatted_uptime = f"{weeks}w {days}d {hours:02}h {minutes:02}m {seconds:02}s "
    else:
        formatted_uptime = f"{days}d {hours:02}h {minutes:02}m {seconds:02}s "

    # Get Process count
    get_proc_count = subprocess.run(['sh', '-c', 'ps -e | wc -l'], capture_output=True, text=True)
    proc_count = get_proc_count.stdout.strip()


    # Get System
    try:
        import distro
        distro_available = True
    except ImportError:
        distro_available = False

    os_name = platform.system()

    if distro_available:
        dist_name = distro.name(pretty=True)
        sat_os_name = f"{dist_name}"
    else:
        sat_os_name = os_name

    # Prepare Satellite Meta Data
    satellite_meta_data = [{
        'hostname': local_hostname,
        'satellite_version': VERSION_DATE,
        'satellite_ip': local_ip,
        'satellite_mac': local_mac,
        'satellite_id': SATELLITE_TOKEN,
        'scan_time': str(startTime),
        'uptime': formatted_uptime,
        'cpu_name': cpuinfo.get_cpu_info()['brand'],
        'cpu_arch': cpuinfo.get_cpu_info()['raw_arch_string'],
        'cpu_cores': cpuinfo.get_cpu_info()['count'],
        'cpu_freq': cpuinfo.get_cpu_info()['hz_actual'],
        'proc_count': proc_count,
        'os_version': sat_os_name
    }]

    satellite_scan_config = [{
        'scan_arp': ARPSCAN_ACTIVE,
        'scan_fritzbox': FRITZBOX_ACTIVE,
        'scan_mikrotik': MIKROTIK_ACTIVE,
        'scan_unifi': UNIFI_ACTIVE
    }]

    # Write Data to JSON-file
    export_all_scans = {
        'satellite_meta_data': satellite_meta_data,
        'satellite_scan_config': satellite_scan_config,
        'scan_results': all_devices
    }

    return export_all_scans

#-------------------------------------------------------------------------------
def encrypt_submit_scandata(json_data):

    if PROXY_MODE:
        print('    Proxy-Mode enabled')

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # Convert the dictionary to JSON and then to binary data
    enc_json_data = json.dumps(json_data).encode('utf-8')

    # OpenSSL command for encrypting the data
    openssl_command = [
        "openssl", "enc", "-aes-256-cbc", "-salt", "-out", SATELLITE_BACK_PATH + "/encrypted_scandata", "-pbkdf2",
        "-pass", "pass:{}".format(SATELLITE_PASSWORD)
    ]

    with subprocess.Popen(openssl_command, stdin=subprocess.PIPE) as proc:
        proc.stdin.write(enc_json_data)

    # DEBUG
    # with open('output.json', 'w') as outfile:
    #     json.dump(json_data, outfile, indent=4)

    # Read the encrypted data from the file
    with open(SATELLITE_BACK_PATH + "/encrypted_scandata", "rb") as f:
        encrypted_data = f.read()

    transfer_mode = "proxy" if PROXY_MODE else "direct"

    # The data for the API requeste
    post_data = {
        "token": SATELLITE_TOKEN,
        "mode" : transfer_mode
    }
    # Files for the API request
    files = {
        "encrypted_data": ("encrypted_scandata", encrypted_data)
    }

    # API-URL
    api_url = SATELLITE_MASTER_URL

    # Send the request to the API, deactivating SSL verification in the process
    response = requests.post(api_url, data=post_data, files=files, verify=False)

    try:
        response_data = response.json()
        print(f"    API-Response: {response_data}")
        # print(response_data)
    except json.JSONDecodeError:
        print("     API-Response: ERROR:")
        print("------------------------------------------------------------------------")
        print("                                Raw output")
        print("------------------------------------------------------------------------")
        print(response.text)
        print("------------------------------------------------------------------------")

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
