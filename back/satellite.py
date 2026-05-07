#!/usr/bin/env python3
#
#-------------------------------------------------------------------------------
#  Pi.Alert Satellite
#-------------------------------------------------------------------------------
#  Puche 2021                                              GNU GPLv3
#  leiweibau 2024+                                         GNU GPLv3
#-------------------------------------------------------------------------------

#===============================================================================
# IMPORTS
#===============================================================================
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from mac_vendor_lookup import MacLookup
from time import sleep, time, strftime, monotonic
from base64 import b64encode
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from datetime import datetime
import sys, subprocess, os, re, datetime, socket, io, requests, time, pwd, glob, ipaddress, ssl, json, cpuinfo, platform, smtplib, psutil, tzlocal, asyncio, aiohttp

#===============================================================================
# CONFIG CONSTANTS
#===============================================================================
SATELLITE_BACK_PATH = os.path.dirname(os.path.abspath(__file__))
SATELLITE_PATH = SATELLITE_BACK_PATH + "/.."
SATELLITE_LOG_PATH = SATELLITE_PATH + "/log"
STATUS_FILE_SCAN = SATELLITE_BACK_PATH + "/.scanning"
STATUS_FILE_BACKUP = SATELLITE_BACK_PATH + "/.backup"
STATUS_FILE_REPORTED = SATELLITE_BACK_PATH + "/.reported"

PIHOLE6_SES_VALID = ""
PIHOLE6_SES_SID = ""
PIHOLE6_SES_CSRF = ""

# Only for debugging. Unencrypted scan results will be stored on the satellite
DEBUG_JSON_OUTPUT = False

exec(open(SATELLITE_PATH + "/config/version.conf").read())
exec(open(SATELLITE_PATH + "/config/satellite.conf").read())

RAW_CONFIG_SECRET_KEYS = [
    'SATELLITE_PASSWORD',
    'SMTP_PASS',
    'FRITZBOX_PASS',
    'MIKROTIK_PASS',
    'UNIFI_PASS',
    'OPENWRT_PASS',
    'ASUSWRT_PASS',
    'PFSENSE_APIKEY',
    'OPNSENSE_APIKEY',
    'OPNSENSE_APISECRET',
    'ADGUARD_PASSWORD',
    'PIHOLE6_PASSWORD',
]

#-------------------------------------------------------------------------------
def recover_sensitive_config_values(config_file, secret_keys):
    def contains_control_characters(value):
        return isinstance(value, str) and any(ord(char) < 32 for char in value)

    try:
        lines = open(config_file, encoding='utf-8').read().splitlines()
    except OSError:
        return

    for line in lines:
        match = re.match(r"^\s*([A-Z0-9_]+)\s*=\s*(['\"])(.*)\2\s*$", line)
        if not match:
            continue

        key = match.group(1)
        quote = match.group(2)
        raw_value = match.group(3)

        if key not in secret_keys:
            continue

        current_value = globals().get(key, '')
        if not contains_control_characters(current_value):
            continue

        recovered_value = raw_value.replace("\\\\", "\\")
        if quote == "'":
            recovered_value = recovered_value.replace("\\'", "'")
        else:
            recovered_value = recovered_value.replace('\\"', '"')

        globals()[key] = recovered_value

recover_sensitive_config_values(SATELLITE_PATH + "/config/satellite.conf", RAW_CONFIG_SECRET_KEYS)

#===============================================================================
# MAIN
#===============================================================================
def main():
    global startTime
    global cycle
    global log_timestamp
    global report_timestamp

    # Header
    print('\nPi.Alert Satellite v'+ VERSION_DATE)
    print('---------------------------------------------------------')
    print(f"Executing user: {get_username()}\n")

    # Initialize global variables
    log_timestamp  = datetime.datetime.now()
    report_timestamp = len(datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))

    # Timestamp
    startTime = datetime.datetime.now()
    startTime = startTime.replace (second=0, microsecond=0)

    # Check parameters
    if len(sys.argv) != 2 :
        print('usage satelite scan | update_vendors | email_test' )
        return
    cycle = str(sys.argv[1])

    # internet_IP currently not used
    if cycle == 'update_vendors':
        res = update_devices_MAC_vendors()
    elif cycle == 'update_vendors_silent':
        res = update_devices_MAC_vendors('-s')
    elif cycle == 'scan':
        res = scan_network()
    elif cycle == 'email_test':
        res = mail_notification('Test')
    else:
        print('usage satelite scan | update_vendors | email_test' )
        return

    # Remove scan status file created in scan_network()
    if cycle not in ['update_vendors', 'update_vendors_silent'] and os.path.exists(STATUS_FILE_SCAN):
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
    primary_args = ['curl', '-s', QUERY_MYIP_SERVER]
    fallback_args = ['curl', '-s', QUERY_MYIP_SERVER_FALLBACK]

    last_error = None

    for attempt in range(3):
        try:
            cmd_output = subprocess.check_output(primary_args, universal_newlines=True)
            return check_IP_format(cmd_output.strip())
        except (subprocess.CalledProcessError, OSError) as error:
            last_error = error
            print_log(f"Primary IP lookup failed (attempt {attempt + 1}/3): {error}")
            if attempt < 2:
                time.sleep(1)

    for attempt in range(3):
        try:
            cmd_output = subprocess.check_output(fallback_args, universal_newlines=True)
            data = json.loads(cmd_output)
            ip = data["ip"].strip()
            if not ip:
                raise ValueError("Fallback response does not contain a valid IP")
            return check_IP_format(ip)
        except (subprocess.CalledProcessError, OSError, json.JSONDecodeError, KeyError, ValueError) as error:
            last_error = error
            print_log(f"Fallback IP lookup failed (attempt {attempt + 1}/3): {error}")
            if attempt < 2:
                time.sleep(1)

    print_log(f"Internet IP lookup failed after all attempts: {last_error}")
    return "0.0.0.0"

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
    global PIHOLE6_SES_VALID
    # Header
    print('Scan Devices')
    print('    Timestamp:', startTime )
    print('\nCheck Internet Connectivity...')
    if INTERNET_DETECTION==True:
        wanip_detection = check_internet_IP()
    else:
        wanip_detection = []
        print('    Skipped...\n')
    # internet_detection = check_internet_IP()
    # arp-scan command
    print('\nScanning...')
    # arp-scan
    print_log ('arp-scan starts...')
    arpscan_devices = execute_arpscan()
    print_log ('Pi-hole copy starts...')
    pihole_network = copy_pihole_network()
    print_log ('Pi-hole DHCP copy starts...')
    pihole_dhcp = read_DHCP_leases()
    if PIHOLE6_SES_VALID==True:
        pihole_six_api_deauth()
    # Fritzbox
    print_log ('Fritzbox copy starts...')
    fritzbox_network = read_fritzbox_active_hosts()
    # Mikrotik
    print_log ('Mikrotik copy starts...')
    mikrotik_network = read_mikrotik_leases()
    # UniFi
    print_log ('UniFi copy starts...')
    unifi_network = read_unifi_clients()
    # OpenWRT
    print_log ('OpenWRT copy starts...')
    openwrt_network = read_openwrt_clients()
    # AsusWRT
    print_log ('AsusWRT copy starts...')
    asuswrt_network = read_asuswrt_clients()
    # pfSense
    print_log ('pfsense copy starts...')
    pfsense_network = read_pfsense_clients()
    # OPNsense
    print_log ('opnsense copy starts...')
    opnsense_network = read_opnsense_clients()
    # AdGuard
    print_log ('adguard copy starts...')
    adguard_network = read_adguard_data()
    print('\nProcessing scan results...')
    print('    Create json of scanned devices')
    jsondata = save_scanned_devices (wanip_detection, arpscan_devices, fritzbox_network, mikrotik_network, unifi_network, openwrt_network, asuswrt_network, pihole_network, pihole_dhcp, pfsense_network, opnsense_network, adguard_network)
    print('    Encrypt data and transmit to Master or Proxy')
    encrypt_submit_scandata(jsondata)
    mail_notification("scan")

    return 0

#-------------------------------------------------------------------------------
def pfsense_connect(endpoint,topic):
    global PFSENSE_PORT

    try:
        PFSENSE_PORT = int(PFSENSE_PORT)
    except (TypeError, ValueError):
        print(f"        ...{topic} Request canceled: Incorrect Port.")
        return None

    protocol = "https" if PFSENSE_SSL else "http"
    port = str(PFSENSE_PORT)

    url = f"{protocol}://{PFSENSE_IP}:{port}{endpoint}"
    headers = {
        "X-API-Key": PFSENSE_APIKEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"        ...❌ Error {response.status_code}: {response.text}")
            return None

    except requests.Timeout:
        print(f"        ...{topic} Request canceled: Timeout reached.")
        return None

    except requests.RequestException as e:
        print(f"        ...{topic} Skipped - Connection error")
        return None

#-------------------------------------------------------------------------------
def read_pfsense_clients():

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    pfsense_dhcpleases = ""
    pfsense_arptable = ""
    pfsense_local_interfaces = ""
    pfsense_processed = {}

    if PFSENSE_ACTIVE:
        # empty Table
        print(f"    pfSense Method...")
        endpoint = "/api/v2/status/dhcp_server/leases?limit=0&offset=0&sort_order=SORT_ASC&sort_flags=SORT_STRING"
        result = pfsense_connect(endpoint,"DHCP")
        print_log(result)
        if result:
            pfsense_dhcpleases = json.dumps(result, indent=4)

        endpoint = "/api/v2/diagnostics/arp_table?limit=0&offset=0"
        result = pfsense_connect(endpoint,"ARP")
        print_log(result)
        if result:
            pfsense_arptable = json.dumps(result, indent=4)

        endpoint = "/api/v2/interface/available_interfaces"
        result = pfsense_connect(endpoint,"Interfaces")
        print_log(result)
        if result:
            pfsense_local_interfaces = json.dumps(result, indent=4)

        pfsense_processed = pfsense_save_dhcp_data(pfsense_dhcpleases)
        pfsense_processed = pfsense_save_arp_data(pfsense_arptable, pfsense_local_interfaces, pfsense_processed)
        pfsense_processed = pfsense_mark_local_interfaces(pfsense_local_interfaces, pfsense_processed)

    return pfsense_processed

#-------------------------------------------------------------------------------
def pfsense_mark_local_interfaces(interfaces, p_pfsense_processed):

    if isinstance(interfaces, str):
        try:
            interfaces = json.loads(interfaces)
        except json.JSONDecodeError:
            print_log("        ...❌ Error: invalid JSON-format (interfaces)")
            return p_pfsense_processed

    local_interfaces = []
    if not interfaces or "data" not in interfaces:
        print_log("⚠️ no local interfaces were found")
        return p_pfsense_processed

    for entry in interfaces["data"]:
        mac = (entry.get("mac") or "").strip().lower()
        in_use_by = (entry.get("in_use_by") or "").strip()

        if not mac:
            continue

        local_interfaces.append({
            "MAC": mac,
            "in_use_by": in_use_by
        })

    for entry in local_interfaces:
        mac = entry["MAC"]
        in_use_by = entry["in_use_by"]
        new_name = f"pfSense {in_use_by}"

        # Datensatz nur ändern, wenn vorhanden
        if mac in p_pfsense_processed:

            present_mac = p_pfsense_processed[mac]

            # entspricht: WHERE PF_Name = '(unknown)'
            if present_mac.get("Name") == "(unknown)":
                present_mac["Name"] = new_name

    print_log(local_interfaces)
    return p_pfsense_processed

#-------------------------------------------------------------------------------
def pfsense_save_dhcp_data(pfsense_dhcpleases):

    if isinstance(pfsense_dhcpleases, str):
        try:
            pfsense_dhcpleases = json.loads(pfsense_dhcpleases)
        except json.JSONDecodeError:
            print_log("        ...❌ Error: invalid JSON-format (pfsense_dhcpleases)")
            return {}

    pfsense_network_dhcp = []

    # Check if "data" exists
    if not pfsense_dhcpleases or "data" not in pfsense_dhcpleases:
        print_log("⚠️ no DHCP-Leases were found")
        return {}

    for entry in pfsense_dhcpleases["data"]:
        mac = entry.get("mac", "").strip().lower()
        ip = entry.get("ip", "").strip()
        hostname = entry.get("hostname") or "(unknown)"
        ends_str = entry.get("ends")

        # convert "ends" in UNIX-Timestamp
        try:
            ends_ts = int(datetime.datetime.strptime(ends_str, "%Y/%m/%d %H:%M:%S").timestamp())
        except (ValueError, TypeError):
            ends_ts = 0

        pf_connected = False
        # Only active hosts for current scan
        if entry.get("online_status") == "active/online":
            pf_connected = True

        # All hosts für dhcp list
        pfsense_network_dhcp.append({
            "MAC": mac,
            "IP": ip,
            "Name": hostname,
            "Vendor": "",
            "Method": "pfSense",
            "Interface": "",
            "Custom_a": "",
            "Custom_b": "",
            "Connected": pf_connected,
            "Datetime": ends_ts
        })

    dict_pfsense_processed = {
        item["MAC"].lower(): item
        for item in pfsense_network_dhcp
        if item.get("MAC")
    }

    print_log(pfsense_network_dhcp)
    return dict_pfsense_processed

#-------------------------------------------------------------------------------
def pfsense_save_arp_data(pfsense_arptable, interfaces, p_pfsense_processed):

    if isinstance(pfsense_arptable, str):
        try:
            pfsense_arptable = json.loads(pfsense_arptable)
        except json.JSONDecodeError:
            print_log("        ...❌ Error: invalid JSON-format (pfsense_arptable)")
            return p_pfsense_processed

    if isinstance(interfaces, str):
        try:
            interfaces = json.loads(interfaces)
        except json.JSONDecodeError:
            print_log("        ...❌ Error: invalid JSON-format (interfaces)")
            return p_pfsense_processed

    pfsense_arp_list = []
    # Check if "data" exists
    if not pfsense_arptable or "data" not in pfsense_arptable:
        print_log("⚠️ no valid ARP-data found.")
        return p_pfsense_processed

    local_interfaces = []
    if not interfaces or "data" not in interfaces:
        return p_pfsense_processed

    for entry in interfaces["data"]:
        mac = (entry.get("mac") or "").strip().lower()
        in_use_by = (entry.get("in_use_by") or "").strip()

        if not mac:
            continue

        local_interfaces.append({
            "MAC": mac
        })

    for entry in pfsense_arptable["data"]:
        mac = entry.get("mac_address", "").strip().lower()
        ip = entry.get("ip_address", "").strip()
        hostname = entry.get("hostname", "").strip()
        dnsresolve = entry.get("dnsresolve", "").strip()
        interface = entry.get("interface", "").strip()
        arpexpires = entry.get("expires", "").strip()

        if interface.lower() in (i.lower() for i in PFSENSE_EXCLUDE_INT) and all(mac != entry["MAC"] for entry in local_interfaces):
            continue

        # Get Arp exp. seconds
        match = re.search(r"Expires\s+in\s+(\d+)\s+seconds", arpexpires, flags=re.I)

        if match:
            seconds = match.group(1)
        else:
            seconds = ""

        # set Connected-Status
        if arpexpires.lower() == "permanent" or (seconds != "" and int(seconds) > 0):
            connected = True
        else:
            connected = False

        # Hostname-Regeln
        if hostname == "" or hostname == "?":
            if dnsresolve != "" and dnsresolve != "?":
                hostname = dnsresolve
            else:
                hostname = "(unknown)"

        # All hosts für arp list
        pfsense_arp_list.append({
            "MAC": mac,
            "IP": ip,
            "Name": hostname,
            "Vendor": "",
            "Method": "pfSense",
            "Interface": interface,
            "Custom_a": seconds,
            "Custom_b": "",
            "Connected": connected,
            "Datetime": ""
        })

    for entry in pfsense_arp_list:
        mac = entry["MAC"].lower()  # wie COLLATE NOCASE bei SQLite

        if mac in p_pfsense_processed:
            # Record existiert → selective update
            present_mac = p_pfsense_processed[mac]

            # Interface aktualisieren (nur wenn DB leer und ARP-Entry vorhanden)
            if (not present_mac["Interface"] or present_mac["Interface"].strip() == "") \
                    and entry["Interface"]:
                present_mac["Interface"] = entry["Interface"]

            # Name aktualisieren
            if (not present_mac["Name"] or present_mac["Name"].strip() == "") \
                    and entry["Name"]:
                present_mac["Name"] = entry["Name"]

            # Connected aktualisieren
            if (not present_mac["Connected"]) and entry["Connected"]:
                present_mac["Connected"] = 1

        else:
            # Record existiert nicht → wie INSERT
            p_pfsense_processed[mac] = {
                "MAC": entry["MAC"],
                "IP": entry["IP"],
                "Name": entry["Name"],
                "Vendor": entry["Vendor"],
                "Method": entry["Method"],
                "Interface": entry["Interface"],
                "Custom_a": entry["Custom_a"],
                "Custom_b": entry["Custom_b"],
                "Connected": entry["Connected"],
                "Datetime": entry["Datetime"]
            }

    print_log(pfsense_arp_list)
    return p_pfsense_processed

#-------------------------------------------------------------------------------
def opnsense_connect(endpoint, topic):
    global OPNSENSE_PORT

    try:
        OPNSENSE_PORT = int(OPNSENSE_PORT)
    except (TypeError, ValueError):
        print(f"        ...{topic} Request canceled: Incorrect Port.")
        return None

    protocol = "https" if OPNSENSE_SSL else "http"
    port = str(OPNSENSE_PORT)
    url = f"{protocol}://{OPNSENSE_IP}:{port}{endpoint}"
    headers = {
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            auth=(OPNSENSE_APIKEY, OPNSENSE_APISECRET),
            verify=False,
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            print(f"        ...Error {response.status_code}: {response.text}")
            return None

    except requests.Timeout:
        print(f"        ...{topic} Request canceled: Timeout reached.")
        return None

    except requests.RequestException:
        print(f"        ...{topic} Skipped - Connection error")
        return None

#-------------------------------------------------------------------------------
def read_opnsense_clients():

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    opnsense_dhcpleases = ""
    opnsense_arptable = ""
    opnsense_interfaces = ""
    opnsense_interface_names = ""
    opnsense_processed = {}

    if OPNSENSE_ACTIVE:
        print("    OPNsense Method...")
        result = opnsense_fetch_dhcp_leases()
        print_log(result)
        if result:
            opnsense_dhcpleases = json.dumps(result, indent=4)

        endpoint = "/api/diagnostics/interface/search_arp"
        result = opnsense_connect(endpoint, "ARP")
        print_log(result)
        if result:
            opnsense_arptable = json.dumps(result, indent=4)

        endpoint = "/api/diagnostics/interface/get_interface_config"
        result = opnsense_connect(endpoint, "Interfaces")
        print_log(result)
        if result:
            opnsense_interfaces = json.dumps(result, indent=4)

        endpoint = "/api/diagnostics/interface/get_interface_names"
        result = opnsense_connect(endpoint, "Interface Names")
        print_log(result)
        if result:
            opnsense_interface_names = json.dumps(result, indent=4)

        opnsense_processed = opnsense_save_dhcp_data(opnsense_dhcpleases)
        opnsense_processed = opnsense_save_arp_data(opnsense_arptable, opnsense_interfaces, opnsense_interface_names, opnsense_processed)
        opnsense_processed = opnsense_mark_local_interfaces(opnsense_interfaces, opnsense_interface_names, opnsense_processed)

    return opnsense_processed

#-------------------------------------------------------------------------------
def opnsense_fetch_dhcp_leases():
    dhcp_endpoints = [
        ("/api/dhcpv4/leases/search_lease?inactive=1", "DHCP"),
        ("/api/dnsmasq/leases/search", "Dnsmasq DHCP"),
        ("/api/kea/leases4/search", "Kea DHCP")
    ]

    first_response = None

    for endpoint, topic in dhcp_endpoints:
        result = opnsense_connect(endpoint, topic)

        if first_response is None and result is not None:
            first_response = result

        if opnsense_get_rows(result):
            print_log(f"        ...OPNsense DHCP backend selected: {topic}")
            return result

    return first_response

#-------------------------------------------------------------------------------
def opnsense_get_rows(payload):
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return []

    if isinstance(payload, dict):
        if "rows" in payload and isinstance(payload["rows"], list):
            return payload["rows"]
        if "data" in payload and isinstance(payload["data"], list):
            return payload["data"]

    if isinstance(payload, list):
        return payload

    return []

#-------------------------------------------------------------------------------
def opnsense_get_interface_map(interface_names):
    if isinstance(interface_names, str):
        try:
            interface_names = json.loads(interface_names)
        except json.JSONDecodeError:
            return {}

    if isinstance(interface_names, dict):
        return interface_names

    return {}

#-------------------------------------------------------------------------------
def opnsense_mark_local_interfaces(interfaces, interface_names, p_opnsense_processed):

    if isinstance(interfaces, str):
        try:
            interfaces = json.loads(interfaces)
        except json.JSONDecodeError:
            print_log("        ...Error: invalid JSON-format (interfaces)")
            return p_opnsense_processed

    interface_map = opnsense_get_interface_map(interface_names)
    if not isinstance(interfaces, dict):
        print_log("        ...Info: no local interfaces were found")
        return p_opnsense_processed

    local_interfaces = []

    for if_name, if_data in interfaces.items():
        if not isinstance(if_data, dict):
            continue

        mac = (
            if_data.get("mac")
            or if_data.get("macaddr")
            or if_data.get("ether")
            or ""
        ).strip().lower()

        if not mac:
            continue

        local_interfaces.append({
            "MAC": mac,
            "Description": interface_map.get(if_name, if_name.upper())
        })

    for entry in local_interfaces:
        mac = entry["MAC"]
        if mac in p_opnsense_processed and p_opnsense_processed[mac].get("Name") == "(unknown)":
            p_opnsense_processed[mac]["Name"] = f"OPNsense {entry['Description']}"

    print_log(local_interfaces)
    return p_opnsense_processed

#-------------------------------------------------------------------------------
def opnsense_save_dhcp_data(opnsense_dhcpleases):

    if isinstance(opnsense_dhcpleases, str):
        try:
            opnsense_dhcpleases = json.loads(opnsense_dhcpleases)
        except json.JSONDecodeError:
            print_log("        ...Error: invalid JSON-format (opnsense_dhcpleases)")
            return {}

    opnsense_network_dhcp = []
    lease_rows = opnsense_get_rows(opnsense_dhcpleases)

    if not lease_rows:
        print_log("        ...Info: no DHCP-Leases were found")
        return {}

    for entry in lease_rows:
        mac = (entry.get("mac") or entry.get("hwaddr") or "").strip().lower()
        ip = (entry.get("address") or entry.get("ip") or "").strip()
        hostname = (entry.get("hostname") or entry.get("host") or entry.get("name") or entry.get("descr") or "(unknown)").strip() or "(unknown)"
        ends_str = entry.get("ends")
        expire_value = entry.get("expire")
        if_descr = entry.get("if_descr") or entry.get("if_name") or entry.get("if") or ""
        vendor = entry.get("man") or entry.get("mac_info") or entry.get("manufacturer") or ""

        if not mac or not ip:
            continue

        try:
            ends_ts = int(datetime.datetime.strptime(ends_str, "%Y/%m/%d %H:%M:%S").timestamp())
        except (ValueError, TypeError):
            try:
                ends_ts = int(ends_str)
            except (ValueError, TypeError):
                try:
                    ends_ts = int(expire_value)
                except (ValueError, TypeError):
                    ends_ts = 0

        status = str(entry.get("status") or "").lower()
        state = str(entry.get("state") or "").lower()
        active = entry.get("active")
        expired = entry.get("expired")

        if status != "":
            opn_connected = status == "online"
        elif active is not None:
            opn_connected = bool(active)
        elif expired is not None:
            opn_connected = not bool(expired)
        elif state != "":
            opn_connected = state not in ["expired", "offline", "released", "free"]
        else:
            opn_connected = True

        opnsense_network_dhcp.append({
            "MAC": mac,
            "IP": ip,
            "Name": hostname,
            "Vendor": vendor,
            "Method": "OPNsense",
            "Interface": if_descr,
            "Custom_a": entry.get("type", ""),
            "Custom_b": entry.get("state", ""),
            "Connected": opn_connected,
            "Datetime": ends_ts
        })

    dict_opnsense_processed = {
        item["MAC"].lower(): item
        for item in opnsense_network_dhcp
        if item.get("MAC")
    }

    print_log(opnsense_network_dhcp)
    return dict_opnsense_processed

#-------------------------------------------------------------------------------
def opnsense_save_arp_data(opnsense_arptable, interfaces, interface_names, p_opnsense_processed):

    if isinstance(opnsense_arptable, str):
        try:
            opnsense_arptable = json.loads(opnsense_arptable)
        except json.JSONDecodeError:
            print_log("        ...Error: invalid JSON-format (opnsense_arptable)")
            return p_opnsense_processed

    if isinstance(interfaces, str):
        try:
            interfaces = json.loads(interfaces)
        except json.JSONDecodeError:
            print_log("        ...Error: invalid JSON-format (interfaces)")
            return p_opnsense_processed

    interface_map = opnsense_get_interface_map(interface_names)
    arp_rows = opnsense_get_rows(opnsense_arptable)
    opnsense_arp_list = []

    if not arp_rows:
        print_log("        ...Info: no valid ARP-data found.")
        return p_opnsense_processed

    local_interfaces = []
    if isinstance(interfaces, dict):
        for if_name, if_data in interfaces.items():
            if not isinstance(if_data, dict):
                continue

            mac = (
                if_data.get("mac")
                or if_data.get("macaddr")
                or if_data.get("ether")
                or ""
            ).strip().lower()

            if mac:
                local_interfaces.append({
                    "MAC": mac,
                    "Description": interface_map.get(if_name, if_name.upper())
                })

    for entry in arp_rows:
        mac = (entry.get("mac") or entry.get("mac-address") or entry.get("mac_address") or "").strip().lower()
        ip = (entry.get("ip") or entry.get("ip-address") or entry.get("ip_address") or "").strip()
        hostname = (entry.get("hostname") or "").strip()
        dnsresolve = (entry.get("dnsresolve") or "").strip()
        interface = (entry.get("intf_description") or entry.get("interface") or entry.get("intf") or "").strip()
        interface_raw = (entry.get("intf") or entry.get("interface") or "").strip()
        manufacturer = (entry.get("manufacturer") or entry.get("vendor") or "").strip()
        expires_raw = entry.get("expires")
        permanent = bool(entry.get("permanent"))
        expired = bool(entry.get("expired"))

        if not mac or not ip:
            continue

        arpexpires = "" if expires_raw is None else str(expires_raw).strip()

        if interface.lower() in (i.lower() for i in OPNSENSE_EXCLUDE_INT) and all(mac != local_entry["MAC"] for local_entry in local_interfaces):
            continue
        if interface_raw.lower() in (i.lower() for i in OPNSENSE_EXCLUDE_INT) and all(mac != local_entry["MAC"] for local_entry in local_interfaces):
            continue

        match = re.search(r"Expires\s+in\s+(\d+)\s+seconds", arpexpires, flags=re.I)
        if match:
            seconds = match.group(1)
        elif arpexpires.isdigit():
            seconds = arpexpires
        else:
            seconds = ""

        if permanent or arpexpires.lower() == "permanent":
            connected = True
        elif expired:
            connected = False
        elif seconds != "":
            connected = int(seconds) > 0
        else:
            connected = True

        if hostname == "" or hostname == "?":
            if dnsresolve != "" and dnsresolve != "?":
                hostname = dnsresolve
            else:
                hostname = "(unknown)"

        opnsense_arp_list.append({
            "MAC": mac,
            "IP": ip,
            "Name": hostname,
            "Vendor": manufacturer,
            "Method": "OPNsense",
            "Interface": interface or interface_raw,
            "Custom_a": seconds,
            "Custom_b": "",
            "Connected": connected,
            "Datetime": ""
        })

    arp_macs = {entry["MAC"] for entry in opnsense_arp_list}

    for entry in opnsense_arp_list:
        mac = entry["MAC"].lower()

        if mac in p_opnsense_processed:
            present_mac = p_opnsense_processed[mac]

            if (not present_mac["Interface"] or present_mac["Interface"].strip() == "") and entry["Interface"]:
                present_mac["Interface"] = entry["Interface"]

            if (present_mac.get("Name") in ["", "(unknown)"]) and entry["Name"] and entry["Name"] != "(unknown)":
                present_mac["Name"] = entry["Name"]

            if entry["Vendor"] and not present_mac.get("Vendor"):
                present_mac["Vendor"] = entry["Vendor"]

            present_mac["Connected"] = entry["Connected"]

        else:
            p_opnsense_processed[mac] = {
                "MAC": entry["MAC"],
                "IP": entry["IP"],
                "Name": entry["Name"],
                "Vendor": entry["Vendor"],
                "Method": entry["Method"],
                "Interface": entry["Interface"],
                "Custom_a": entry["Custom_a"],
                "Custom_b": entry["Custom_b"],
                "Connected": entry["Connected"],
                "Datetime": entry["Datetime"]
            }

    if arp_macs:
        for mac, device in p_opnsense_processed.items():
            if mac not in arp_macs:
                device["Connected"] = False

    print_log(opnsense_arp_list)
    return p_opnsense_processed

#-------------------------------------------------------------------------------
def adguard_try_login(protocol, host, port, headers, payload):
    base_url = f"{protocol}://{host}:{port}"
    login_url = f"{base_url}/control/login"

    try:
        response = requests.post(login_url, data=json.dumps(payload), headers=headers, timeout=5)
        if response.status_code == 200:
            return response.cookies, base_url
    except requests.exceptions.RequestException:
        pass

    return None, None

#-------------------------------------------------------------------------------
def adguard_fetch_dns_queries(cookies, base_url, headers, limit=200):
    url = f"{base_url}/control/querylog"
    params = {
        "limit": limit,
        "response_status": "all",
    }

    try:
        response = requests.get(url, params=params, cookies=cookies, headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        return data.get("data", [])
    except Exception as error:
        print_log(f"[!] Failed to fetch query log: {error}")
        return []

#-------------------------------------------------------------------------------
def adguard_get_dhcp_leases(cookies, base_url, headers):
    url = f"{base_url}/control/dhcp/status"

    try:
        response = requests.get(url, cookies=cookies, headers=headers, timeout=5)
        response.raise_for_status()
        all_leases = response.json()
        return {
            "leases": all_leases.get("leases", []),
            "static_leases": all_leases.get("static_leases", []),
        }
    except Exception as error:
        print_log(f"[!] Failed to fetch DHCP leases: {error}")
        return {
            "leases": [],
            "static_leases": [],
        }

#-------------------------------------------------------------------------------
def adguard_get_current_queries_per_client(cookies, base_url, headers, limit=200):
    queries = adguard_fetch_dns_queries(cookies, base_url, headers, limit=limit)

    if not queries:
        return {}

    latest_per_client = {}

    for entry in queries:
        client_info = entry.get("client_info", {})
        client_ip = (entry.get("client") or "").strip()
        if not adguard_is_valid_ipv4(client_ip):
            continue

        client_name = (client_info.get("name") or client_ip).strip() or client_ip
        query_time_str = entry.get("time")

        try:
            query_time = datetime.datetime.fromisoformat(query_time_str.replace("Z", "+00:00")) if query_time_str else None
        except Exception:
            query_time = None

        if client_ip not in latest_per_client:
            latest_per_client[client_ip] = {
                "time": query_time,
                "client_ip": client_ip,
                "client_name": client_name,
            }
            continue

        current_time = latest_per_client[client_ip].get("time")
        if current_time is None and query_time is not None:
            latest_per_client[client_ip] = {
                "time": query_time,
                "client_ip": client_ip,
                "client_name": client_name,
            }
        elif query_time is not None and current_time is not None and query_time > current_time:
            latest_per_client[client_ip] = {
                "time": query_time,
                "client_ip": client_ip,
                "client_name": client_name,
            }

    return latest_per_client

#-------------------------------------------------------------------------------
def adguard_get_first_value(item, keys, default=""):
    for key in keys:
        value = item.get(key)
        if value is None:
            continue

        if isinstance(value, str):
            value = value.strip()

        if value != "":
            return value

    return default

#-------------------------------------------------------------------------------
def adguard_is_valid_ipv4(ip_value):
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return False

    return ip.version == 4 and not ip.is_loopback

#-------------------------------------------------------------------------------
def adguard_parse_lease_expires(expires_value):
    if expires_value in [None, ""]:
        return 0

    try:
        return int(expires_value)
    except (TypeError, ValueError):
        pass

    if isinstance(expires_value, str):
        try:
            return int(datetime.datetime.fromisoformat(expires_value.replace("Z", "+00:00")).timestamp())
        except ValueError:
            return 0

    return 0

#-------------------------------------------------------------------------------
def adguard_format_timestamp(date_value):
    if not isinstance(date_value, datetime.datetime):
        return ""

    return date_value.astimezone(datetime.timezone.utc).isoformat()

#-------------------------------------------------------------------------------
def adguard_normalize_dhcp_leases(lease_payload):
    normalized_leases = {}
    dynamic_leases = lease_payload.get("leases", [])
    static_leases = lease_payload.get("static_leases", [])

    for lease in dynamic_leases + static_leases:
        ip = str(adguard_get_first_value(lease, ["ip", "address"]))
        mac = str(adguard_get_first_value(lease, ["mac", "hwaddr"]))
        name = str(adguard_get_first_value(lease, ["hostname", "name", "host"], "(unknown)"))
        expires = adguard_parse_lease_expires(
            adguard_get_first_value(lease, ["expires", "expire", "expiration_time"], 0)
        )

        if not adguard_is_valid_ipv4(ip):
            continue
        if mac == "":
            continue

        normalized_leases[ip] = {
            "mac": mac.lower(),
            "ip": ip,
            "name": name,
            "connected": False,
            "lease_expires": expires,
            "last_query_time": None,
        }

    return normalized_leases

#-------------------------------------------------------------------------------
def adguard_mark_active_from_queries(devices_by_ip, latest_queries):
    unmatched_queries = {}

    for ip, query in latest_queries.items():
        if ip not in devices_by_ip:
            unmatched_queries[ip] = query
            continue

        devices_by_ip[ip]["connected"] = True
        devices_by_ip[ip]["last_query_time"] = query["time"]

        query_name = query.get("client_name", "").strip()
        if query_name and devices_by_ip[ip]["name"] in ["", "(unknown)"]:
            devices_by_ip[ip]["name"] = query_name

    return unmatched_queries

#-------------------------------------------------------------------------------
def adguard_build_network_state(devices_by_ip):
    devices_by_mac = {}

    for ip in sorted(devices_by_ip):
        device = devices_by_ip[ip]
        mac = device["mac"].lower()
        devices_by_mac[mac] = {
            "MAC": device["mac"],
            "IP": device["ip"],
            "Name": device["name"],
            "Vendor": "",
            "Method": "AdGuard",
            "Interface": "",
            "Custom_a": device["lease_expires"],
            "Custom_b": adguard_format_timestamp(device["last_query_time"]),
            "Connected": 1 if device["connected"] else 0,
            "Datetime": device["lease_expires"],
        }

    return devices_by_mac

#-------------------------------------------------------------------------------
def read_adguard_data():
    if not ADGUARD_ACTIVE:
        return {}

    print("    AdGuard Method...")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {
        "name": ADGUARD_USER,
        "password": ADGUARD_PASSWORD,
    }

    protocol_order = ["https", "http"] if ADGUARD_SSL else ["http", "https"]
    cookies = None
    base_url = None

    for protocol in protocol_order:
        cookies, base_url = adguard_try_login(protocol, ADGUARD_IP, ADGUARD_PORT, headers, payload)
        if cookies is not None:
            break

    if cookies is None:
        print("        ...Skipped - Connection failed")
        return {}

    lease_payload = adguard_get_dhcp_leases(cookies, base_url, headers)
    latest_queries = adguard_get_current_queries_per_client(
        cookies,
        base_url,
        headers,
        limit=ADGUARD_QUERY_LIMIT,
    )

    devices_by_ip = adguard_normalize_dhcp_leases(lease_payload)
    unmatched_queries = adguard_mark_active_from_queries(devices_by_ip, latest_queries)
    network_state = adguard_build_network_state(devices_by_ip)

    print_log(network_state)
    print_log(unmatched_queries)
    return network_state

#-------------------------------------------------------------------------------
def copy_pihole_network():
    # check if Pi-hole is active
    if not PIHOLE_ACTIVE :
        return

    print('    Pi-hole Method...')
    pihole_six_api_auth()
    pihole_network = copy_pihole_network_six()
    return pihole_network

#-------------------------------------------------------------------------------
def pihole_six_api_auth():
    global PIHOLE6_URL
    global PIHOLE6_PASSWORD
    global PIHOLE6_SES_VALID
    global PIHOLE6_SES_SID
    global PIHOLE6_SES_CSRF

    if not PIHOLE6_URL :
        print('        ...Skipped (Config Error)')
        return

    if not PIHOLE6_URL.endswith('/'):
        PIHOLE6_URL += '/'

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "User-Agent": "Pi.Alert/"+ VERSION_DATE
    }
    data = {
        "password": PIHOLE6_PASSWORD
    }
    try:
        response = requests.post(PIHOLE6_URL+'api/auth', headers=headers, json=data, verify=False, timeout=15)
    except requests.exceptions.Timeout:
        print(f"        Request timed out after 15 seconds")
        return
    except requests.exceptions.ConnectionError as e:
        print(f"        Connection error occurred")
        print_log (f"{e}")
        return
    except Exception as e:
        print(f"        An unexpected error occurred")
        print_log (f"{e}")
        return

    response_json = response.json()

    try:
        session_data = response_json.get('session', {})
        if session_data.get('valid', False):  # Standardwert False, falls 'valid' fehlt
            PIHOLE6_SES_VALID = session_data['valid']
            PIHOLE6_SES_SID = session_data['sid']
            # to prevent key error if pihole has no password
            if PIHOLE6_PASSWORD:
                PIHOLE6_SES_CSRF = session_data['csrf']
        else:
            print("        Auth required")
            return
    except KeyError as e:
        print(f"        Invalid response. Check Pi-hole URL")
        print_log(f"{e}")
        return

#-------------------------------------------------------------------------------
def pihole_six_api_deauth():
    global PIHOLE6_URL
    global PIHOLE6_SES_VALID
    global PIHOLE6_SES_SID
    global PIHOLE6_SES_CSRF

    if not PIHOLE6_URL.endswith('/'):
        PIHOLE6_URL += '/'

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    headers = {
        "X-FTL-SID": PIHOLE6_SES_SID
    }
    try:
        response = requests.delete(PIHOLE6_URL+'api/auth', headers=headers, verify=False, timeout=15)
    except requests.exceptions.Timeout:
        print(f"        Request timed out after 15 seconds")
        return
    except requests.exceptions.ConnectionError as e:
        print(f"        Connection error occurred")
        print_log(f"{e}")
        return
    except Exception as e:
        print(f"        An unexpected error occurred")
        print_log(f"{e}")
        return

#-------------------------------------------------------------------------------
def copy_pihole_network_six():
    global PIHOLE6_URL
    global PIHOLE6_SES_VALID
    global PIHOLE6_SES_SID
    global PIHOLE6_SES_CSRF
    global PIHOLE6_API_MAXCLIENTS

    if PIHOLE6_SES_VALID == True:
        headers = {
            "X-FTL-SID": PIHOLE6_SES_SID,
            "X-FTL-CSRF": PIHOLE6_SES_CSRF
        }
        #max_addresses=2 IPs per host
        raw_deviceslist = requests.get(PIHOLE6_URL+'api/network/devices?max_devices=' + str(PIHOLE6_API_MAXCLIENTS) + '&max_addresses=2', headers=headers, verify=False)
        deviceslist = raw_deviceslist.json()
        pihole_network = []

        # If pi-hole is outside the local Pi.Alert network and cannot be found with arp.
        interfaces = get_pihole_interface_data()

        actual_timestamp = int(time.time())

        for device in deviceslist['devices']:
            hwaddr = device['hwaddr']
            lastQuery = device['lastQuery']
            macVendor = device['macVendor']

            # skip lo interface
            if hwaddr == "00:00:00:00:00:00":
                continue

            for ip_info in device['ips']:
                ip = ip_info['ip']
                name = ip_info['name'] if ip_info['name'] not in [None, ""] else "(unknown)"

                # Check whether the IP could be a IPv4 address
                if '.' in ip:
                    # Change the “lastQuery” variable to mark the Pi-hole host as “active”
                    for mac, localips in interfaces.items():
                        if ip in localips:
                            lastQuery = str(int(datetime.datetime.now().timestamp()))

                    # Compare the last request with the current time to filter the active hosts
                    if int(lastQuery) > actual_timestamp-300: 
                        pihole_scan = {
                            "mac": hwaddr,
                            "ip": ip,
                            "hostname": name,
                            "vendor": macVendor
                        }
                        pihole_network.append(pihole_scan)

        return pihole_network
    else:
        print(f"        ...Skipped")
        return

#-------------------------------------------------------------------------------
def read_DHCP_leases():
    # check DHCP Leases is active
    if not PIHOLE_DHCP_ACTIVE :
        return

    print(f"    Pi-hole DHCP Leases Method...")

    if not PIHOLE6_SES_VALID == True:
        pihole_six_api_auth()
    pihole_dhcp = read_DHCP_leases_six()

    return pihole_dhcp

#-------------------------------------------------------------------------------
def read_DHCP_leases_six():
    global PIHOLE6_URL
    global PIHOLE6_PASSWORD
    global PIHOLE6_SES_VALID
    global PIHOLE6_SES_SID
    global PIHOLE6_SES_CSRF

    if PIHOLE6_SES_VALID == True:

        headers = {
            "X-FTL-SID": PIHOLE6_SES_SID,
            "X-FTL-CSRF": PIHOLE6_SES_CSRF
        }
        raw_deviceslist = requests.get(PIHOLE6_URL+'api/dhcp/leases', headers=headers, verify=False)
        deviceslist = raw_deviceslist.json()
        pihole_dhcp = []

        # Get Pi-hole local MAC-Adresses an IPs
        interfaces = get_pihole_interface_data()
        # Generate a theoretical lease period of +30min
        current_time = datetime.datetime.now()
        future_time = current_time + datetime.timedelta(minutes=30)
        dnsmasq_timestamp = int(future_time.timestamp()) 

        for device in deviceslist['leases']:
            # skip lo interface if present
            if device['hwaddr'] == "00:00:00:00:00:00":
                continue

            pihole_scan = {
                "expires": device['expires'],
                "mac": device['hwaddr'],
                "ip": device['ip'],
                "hostname": device['name']
            }
            pihole_dhcp.append(pihole_scan)

        return pihole_dhcp

    else:
        print(f"        ...Skipped")
        return

#-------------------------------------------------------------------------------
def get_pihole_interface_data():
    global PIHOLE6_URL
    global PIHOLE6_SES_VALID
    global PIHOLE6_SES_SID
    global PIHOLE6_SES_CSRF
    
    if PIHOLE6_SES_VALID == True:
        headers = {
            "X-FTL-SID": PIHOLE6_SES_SID,
            "X-FTL-CSRF": PIHOLE6_SES_CSRF
        }
        raw_interfacelist = requests.get(PIHOLE6_URL+'api/network/interfaces', headers=headers, verify=False)
        data = raw_interfacelist.json()
        result = {}

        for interface in data['interfaces']:
            mac_address = interface.get('address')
            
            if mac_address == "00:00:00:00:00:00":
                continue
            
            if 'addresses' in interface:
                ips = [addr['address'] for addr in interface['addresses'] if addr['family'] == 'inet']
                if mac_address and ips:
                    result[mac_address] = ips

    return result

#-------------------------------------------------------------------------------
def sorted_alphanumeric(data):
    convert = lambda text: int(text) if text.isdigit() else text.lower()
    alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ] 
    return sorted(data, key=alphanum_key)

#-------------------------------------------------------------------------------
def execute_arpscan():

    # check if arp-scan is active
    try:
        module_arpscan_status = ARPSCAN_ACTIVE
    except NameError:
        module_arpscan_status = True
    if not module_arpscan_status :
        unique_devices = []
        return unique_devices

    print('    arp-scan Method...')

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
    re_pattern = re.compile(r'' + re_ip + r'\s+' + re_mac + r'\s' + re_hw)

    # Create Userdict of devices
    devices_list = [device.groupdict()
        for device in re.finditer (re_pattern, arpscan_output)]

    # Delete duplicate MAC
    unique_mac = []
    unique_devices = []

    for device in devices_list:
        if device['mac'] not in unique_mac:
            unique_mac.append(device['mac'])
            unique_devices.append(device)

    return unique_devices

#-------------------------------------------------------------------------------
def execute_arpscan_on_interface(SCAN_SUBNETS):
    # Prepare command arguments
    subnets = SCAN_SUBNETS.strip().split()
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

    if not FRITZBOX_ACTIVE :
        return

    print('    Fritzbox Method...')
    fritzbox_network = []

    try:
        from fritzconnection.lib.fritzhosts import FritzHosts
    except:
        print('        Missing python package')
        return fritzbox_network

    try:
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
                    "hostname": hostname,
                    "vendor": vendor
                }
                fritzbox_network.append(fritzbox_scan)
    except Exception as e:
        print('        Could not connect to Fritzbox')
        print_log(f"{e}")

    return fritzbox_network

#-------------------------------------------------------------------------------
def read_mikrotik_leases():

    if not MIKROTIK_ACTIVE:
        return

    print('    Mikrotik Method...')
    mikrotik_network = []

    try:
        import routeros_api
    except:
        print('        Missing python package')
        return mikrotik_network

    try:
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
    except Exception as e:
        print('        Could not connect to Mikrotik Router')
        print(f"        ...Skipped")
        print_log(f"{e}")

    return mikrotik_network

#-------------------------------------------------------------------------------
def read_unifi_clients():

    if not UNIFI_ACTIVE:
        return

    print('    UniFi Method...')
    unifi_network = []

    try:
        from pyunifi.controller import Controller
    except:
        print('        Missing python package')
        return unifi_network

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    try:
        UNIFI_API_VERSION = UNIFI_API
    except NameError: # variable not defined, use a default
        UNIFI_API_VERSION = 'v5'

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
        print(f"        ...Skipped")
        print_log(f"{e}")

    return unifi_network

#-------------------------------------------------------------------------------
def read_openwrt_clients():

    if not OPENWRT_ACTIVE:
        return

    print('    OpenWRT Method...')
    openwrt_network = []

    try:
        from openwrt_luci_rpc import OpenWrtRpc
    except:
        print('        Missing python package')
        return openwrt_network

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    try:
        escaped_password = repr(OPENWRT_PASS)[1:-1]
        router = OpenWrtRpc(str(OPENWRT_IP), str(OPENWRT_USER), escaped_password)
        result = router.get_all_connected_devices(only_reachable=True)

        for device in result:
            if str(device.hostname) == 'None':
                hostname = resolve_device_name(device.mac,device.ip)
            else:
                hostname = device.hostname

            device_data = {
                "mac": device.mac.lower(),
                "hostname": hostname,
                "ip": device.ip,
                "vendor": "(unknown)"
            }
            openwrt_network.append(device_data)

    except Exception as e:
        print('        Could not connect to OpenWRT')
        print(f"        ...Skipped")
        print_log(f"{e}")

    return openwrt_network

#-------------------------------------------------------------------------------
def read_asuswrt_clients():

    if not ASUSWRT_ACTIVE:
        return

    print('    AsusWRT Method...')
    asuswrt_network = []

    try:
        from asusrouter import AsusRouter
        from asusrouter.modules.data import AsusData
    except:
        print('        Missing python package')
        return

    try:
        attempt = 0
        max_attempts = 5

        result = None
        while not result and attempt < max_attempts:
            result = asyncio.run(collect_asuswrt_data(AsusRouter, AsusData))
            attempt += 1
            if not result:
                asyncio.run(asyncio.sleep(5))  # 5 sec delay

        if not result:
            print(f"        No results received after {max_attempts} attempts")

        for client in result.values():
            hostname = client["name"] or "(unknown)"
            mac = client["mac"]
            vendor = client["vendor"]
            if vendor == "None" or vendor is None:
                vendor = "(unknown)"
            ip_method = client["ip_method"]

            device_data = {
                "mac": mac.lower(),
                "hostname": hostname,
                "ip": client["ip_address"],
                "vendor": vendor,
                "ip_method": ip_method
            }
            asuswrt_network.append(device_data)

    except Exception as e:
        print(f"        Could not connect to Asus Router")
        print(f"        ...Skipped")
        print_log(f"{e}")

    return asuswrt_network

#-------------------------------------------------------------------------------
async def collect_asuswrt_data(AsusRouter,AsusData):
    async with aiohttp.ClientSession() as session:
        router = AsusRouter(
            hostname=ASUSWRT_IP,
            username=ASUSWRT_USER,
            password=ASUSWRT_PASS,
            use_ssl=ASUSWRT_SSL,
            cache_time=2, 
            session=session,
        )

        connected = await router.async_connect()

        if not connected:
            return

        try:
            clients_data = await router.async_get_data(AsusData.CLIENTS)
            filtered_clients = {
                mac: {
                    'name': client.description.name,
                    'ip_address': client.connection.ip_address,
                    'mac': mac,
                    'vendor': client.description.vendor,
                    'ip_method': client.connection.ip_method.name
                }
                for mac, client in clients_data.items() if client.connection.online
            }

            if filtered_clients:
                return filtered_clients
            else:
                return {}
        
        except Exception as e:
            print(f"        Connection error occurred: {e}")
            print_log(f"{e}")

        await router.async_disconnect()

#-------------------------------------------------------------------------------
def resolve_device_name_netbios(pIP):
    try:
        nbtscan_args =['nbtscan', '-v', '-s', ':', pIP+'/32']
        newName = subprocess.run(nbtscan_args, capture_output=True, text=True, timeout=5)
        if newName.returncode == 0 and newName.stdout:
            lines = newName.stdout.strip().split('\n')
            for line in lines:
                if "00U" in line:
                    segments = line.split(':')
                    newName = segments[1].strip()
        else:
            newName = ""
        return newName

    except subprocess.TimeoutExpired:
        newName = ""
        return newName

#-------------------------------------------------------------------------------
def resolve_device_name_avahi(pIP):
    try:
        avahi_args = ['avahi-resolve', '-a', pIP]
        newName = subprocess.run(avahi_args, capture_output=True, text=True, timeout=5)
        if newName.returncode == 0 and newName.stdout:
                ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
                newName = re.sub(ip_regex, '', newName.stdout)
        else:
            newName = ""
        return newName.strip()

    except subprocess.TimeoutExpired:
        newName = ""
        return newName
    except subprocess.CalledProcessError:
        newName = ""
        return newName

#-------------------------------------------------------------------------------
def resolve_device_name_dig(pIP):
    # DNS Server Fallback
    try:
        dnsserver = NETWORK_DNS_SERVER
    except NameError:
        dnsserver = "localhost"

    try: 
        dig_args = ['dig', '+short', '-x', pIP, '@'+dnsserver]
        newName = subprocess.check_output (dig_args, universal_newlines=True, timeout=5)
        if ";; communications error to" in newName:
            newName = ""
        return newName.strip()

    except subprocess.TimeoutExpired:
        newName = ""
        return newName
    except subprocess.CalledProcessError:
        newName = ""
        return newName

#-------------------------------------------------------------------------------
def resolve_device_name(pMAC, pIP):
    pMACstr = str(pMAC)

    # Check MAC parameter
    mac = pMACstr.replace (':','')
    if len(pMACstr) != 17 or len(mac) != 12 :
        return -2

    newName = resolve_device_name_avahi(pIP)
    if newName == "":
        newName = resolve_device_name_dig(pIP)
    if newName == "":
        newName = resolve_device_name_netbios(pIP)

    # Check returns
    newName = newName.strip()
    if len(newName) == 0 :
        newName = "(satellite network client)"

    # Eliminate local domain
    suffixes = ['.', '.lan', '.local', '.home']

    for suffix in suffixes:
        if newName.endswith(suffix):
            newName = newName[:-len(suffix)]
            break

    return newName

#-------------------------------------------------------------------------------
def process_devices(network, scan_method, all_devices):
    if network:
        for device in network:
            if len(device['mac']) > 12:
                device_data = {
                    'cur_MAC': device['mac'],
                    'cur_IP': device['ip'],
                    'cur_hostname': device['hostname'],
                    'cur_Vendor': device['vendor'],
                    'cur_ScanMethod': scan_method,
                    'cur_SatelliteID': SATELLITE_TOKEN
                }
                all_devices.append(device_data)

#-------------------------------------------------------------------------------
def save_scanned_devices(p_internet_detection, p_arpscan_devices, p_fritzbox_network, p_mikrotik_network, p_unifi_network, p_openwrt_network, p_asuswrt_network, p_pihole_network, p_pihole_dhcp, p_pfsense_network, p_opnsense_network, p_adguard_network):

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
    process_devices(p_fritzbox_network, 'Fritzbox', all_devices)
    # Mikrotik
    process_devices(p_mikrotik_network, 'Mikrotik', all_devices)
    # UniFi
    process_devices(p_unifi_network, 'UniFi', all_devices)
    # OpenWRT
    process_devices(p_openwrt_network, 'OpenWRT', all_devices)
    # AsusWRT
    process_devices(p_asuswrt_network, 'AsusWRT', all_devices)
    # Pihole Network
    process_devices(p_pihole_network, 'Pi-hole', all_devices)
    # Pihole Network
    if bool(p_pihole_dhcp):
        for device in p_pihole_dhcp:
            if len(device['mac']) > 12:
                device_data = {
                    'cur_expires': device['expires'],
                    'cur_hwaddr': device['mac'],
                    'cur_ip': device['ip'],
                    'cur_name': device['hostname'],
                    'cur_clientid': '*',
                    'cur_ScanMethod': 'Pi-hole DHCP',
                    'cur_SatelliteID': SATELLITE_TOKEN
                }
                all_devices.append(device_data)
    # pfSense
    if p_pfsense_network:
        for mac, device in p_pfsense_network.items():
            if device.get("Connected") and len(mac) > 12:
                all_devices.append({
                    'cur_MAC': device.get('MAC', mac),
                    'cur_IP': device.get('IP', ''),
                    'cur_hostname': device.get('Name', '(unknown)'),
                    'cur_Vendor': "",
                    'cur_ScanMethod': 'pfSense',
                    'cur_SatelliteID': SATELLITE_TOKEN
                })
    # OPNsense
    if p_opnsense_network:
        for mac, device in p_opnsense_network.items():
            if device.get("Connected") and len(mac) > 12:
                all_devices.append({
                    'cur_MAC': device.get('MAC', mac),
                    'cur_IP': device.get('IP', ''),
                    'cur_hostname': device.get('Name', '(unknown)'),
                    'cur_Vendor': device.get('Vendor', ''),
                    'cur_ScanMethod': 'OPNsense',
                    'cur_SatelliteID': SATELLITE_TOKEN
                })
    # AdGuard
    if p_adguard_network:
        for mac, device in p_adguard_network.items():
            if device.get("Connected") and len(mac) > 12:
                all_devices.append({
                    'cur_MAC': device.get('MAC', mac),
                    'cur_IP': device.get('IP', ''),
                    'cur_hostname': device.get('Name', '(unknown)'),
                    'cur_Vendor': device.get('Vendor', ''),
                    'cur_ScanMethod': 'AdGuard',
                    'cur_SatelliteID': SATELLITE_TOKEN
                })
    # Arpscan
    if bool(p_arpscan_devices):
        for device in p_arpscan_devices:
            if len(device['mac']) > 12:
                device_data = {
                    'cur_MAC': device['mac'],
                    'cur_IP': device['ip'],
                    'cur_hostname': resolve_device_name(device['mac'],device['ip']),
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

    # Insert local data
    device_data = {
        'cur_MAC': local_mac.lower(),
        'cur_IP': local_ip,
        'cur_hostname': 'Satellite - ' + local_hostname,
        'cur_Vendor': 'unknown',
        'cur_ScanMethod': 'local',
        'cur_SatelliteID': SATELLITE_TOKEN
    }
    all_devices.append(device_data)

    # Get Uptime
    monotonic_time = monotonic()
    weeks = int(monotonic_time // 604800)
    days = int((monotonic_time % 604800) // 86400)
    hours = int((monotonic_time % 86400) // 3600)
    minutes = int((monotonic_time % 3600) // 60)
    seconds = int(monotonic_time % 60)

    if weeks > 0:
        formatted_uptime = f"{weeks}w {days}d {hours:02}h {minutes:02}m "
    else:
        formatted_uptime = f"{days}d {hours:02}h {minutes:02}m "

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

    # Get local timezone
    sat_os_timezone = tzlocal.get_localzone()

    cpu_info = cpuinfo.get_cpu_info()

    try:
        cpu_brand = cpu_info['brand']
    except KeyError:
        cpu_brand = cpu_info['brand_raw']

    try:
        cpu_arch = cpu_info['arch']
    except KeyError:
        cpu_arch = cpu_info['arch_string_raw']

    # Prepare Satellite Meta Data
    satellite_meta_data = [{
        'hostname': local_hostname,
        'satellite_version': VERSION_DATE,
        'satellite_ip': local_ip,
        'satellite_mac': local_mac,
        'satellite_id': SATELLITE_TOKEN,
        'satellite_proxymode': PROXY_MODE,
        'satellite_url': SATELLITE_MASTER_URL,
        'scan_time': str(startTime),
        'uptime': formatted_uptime,
        'cpu_name': cpu_brand,
        'cpu_arch': cpu_arch,
        'cpu_cores': cpu_info['count'],
        'cpu_freq': cpu_info['hz_actual'],
        'ram_total': psutil.virtual_memory()[0],
        'ram_used_percent': psutil.virtual_memory()[2],
        'proc_count': proc_count,
        'os_version': sat_os_name,
        'os_timezone': str(sat_os_timezone),
        'error_reporting': SATELLITE_ERROR_REPORT
    }]

    satellite_scan_config = [{
        'scan_arp': ARPSCAN_ACTIVE,
        'scan_fritzbox': FRITZBOX_ACTIVE,
        'scan_mikrotik': MIKROTIK_ACTIVE,
        'scan_unifi': UNIFI_ACTIVE,
        'scan_openwrt': OPENWRT_ACTIVE,
        'scan_asuswrt': ASUSWRT_ACTIVE,
        'scan_pihole_net': PIHOLE_ACTIVE,
        'scan_pihole_dhcp': PIHOLE_DHCP_ACTIVE,
        'scan_pfsense': PFSENSE_ACTIVE,
        'scan_opnsense': OPNSENSE_ACTIVE,
        'scan_adguard': ADGUARD_ACTIVE
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

    if DEBUG_JSON_OUTPUT:
        print("------------------------------------------------------------------------")
        print("                        Create Debug Output")
        print("------------------------------------------------------------------------")
        with open(SATELLITE_BACK_PATH + '/output.json', 'w') as outfile:
            json.dump(json_data, outfile, indent=4)

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
        # if statuscode != 0 save Logs
        if response_data.get('status') != '0':
            save_error(response_data)
        else:
            # if a successful transmission takes place again after less than x logs, delete the logs
            # if a successful transmission occurs again afterwards, delete the file and all logs
            delete_error_files()
            notification_stop('stop')

    except json.JSONDecodeError:
        print("    API-Response: ERROR:")
        print("------------------------------------------------------------------------")
        print("                                Raw output")
        print("------------------------------------------------------------------------")
        print(response.text)
        print("------------------------------------------------------------------------")
        save_error(response.text)

#-------------------------------------------------------------------------------
def save_error(response_data):
    if SATELLITE_ERROR_REPORT:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        existing_files = [
            f for f in sorted_alphanumeric(os.listdir(SATELLITE_LOG_PATH))
            if f.endswith(".txt") and "_error_" in f and len(f.split('_error_')[1].replace('.txt', '')) == report_timestamp
        ]
        file_count = len(existing_files) + 1
        
        file_name = f"{file_count}_error_{timestamp}.txt"
        file_path = os.path.join(SATELLITE_LOG_PATH, file_name)
        
        with open(file_path, 'w') as file:
            json.dump(response_data, file)
        
        print(f"    Error saved to file: {file_path}")
    else:
        print(f"    Error reporting disabled")
        delete_error_files()

#-------------------------------------------------------------------------------
def delete_error_files():
    for file_name in sorted_alphanumeric(os.listdir(SATELLITE_LOG_PATH)):
        # Check whether the file name corresponds to the naming scheme
        if "_error_" in file_name and file_name.endswith(".txt"):
            file_path = os.path.join(SATELLITE_LOG_PATH, file_name)
            try:
                os.remove(file_path)  # Lösche die Datei
                print(f"        File deleted: {file_name}")
            except Exception as e:
                print(f"        Error deleting file: {file_name}")
    notification_stop('stop')

#-------------------------------------------------------------------------------
def notification_stop(mode):
    if mode == "start":
        with open(STATUS_FILE_REPORTED, 'w') as file:
            pass

    if mode == "stop":
        if os.path.exists(STATUS_FILE_REPORTED):
            os.remove(STATUS_FILE_REPORTED)

#-------------------------------------------------------------------------------
def mail_notification(_Mode):
    global log_timestamp

    if SATELLITE_ERROR_REPORT:
        if _Mode == 'Test' :
            print(f"\nTest Message")
            notiMessage = "Test-Notification"
            send_email (notiMessage, notiMessage, False)
        # If further logs are sent after x logs, they are no longer sent because the file prevents it.
        else:
            print(f"\nSatellite error reporting")
            # No test message
            # If further logs are sent after x logs, they are no longer sent because the file prevents it.
            # The stop file is checked
            # Stop file does not exist
            if not os.path.exists(STATUS_FILE_REPORTED):
                # Count the reports to recognize whether a message should be sent
                existing_files = [
                    f for f in sorted_alphanumeric(os.listdir(SATELLITE_LOG_PATH))
                    if f.endswith(".txt") and "_error_" in f and len(f.split('_error_')[1].replace('.txt', '')) == report_timestamp
                ]

                # after x logs write an e-mail and attach the logs
                if len(existing_files) >= COLLECT_REPORTS_FOR_MAIL:
                    notiTEXT = 'The threshold for repeated transmission errors from the satellite to the API has been reached.'
                    notiHTML = """\
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>E-Mail Beispiel</title>
</head>
  <body>
    <p style="color:Tomato;">The threshold for repeated transmission errors from the satellite to the API has been reached.</p>
  </body>
</html>
"""
                    send_email (notiTEXT, notiHTML, True)
                    # create a file that recognizes that a mail has been sent
                    notification_stop('start')
                else:
                    print('    Nothing to report')
            else:
                print('    Reporting stopped because a mail has already been sent')

    else:
        print('    Satellite error reporting is disabled')
#-------------------------------------------------------------------------------
def send_email(pText, pHTML, logs):
    # Compose email
    msg = MIMEMultipart()
    msg['Subject'] = FRIENDLY_NAME + ' - Pi.Alert Satellite Message '
    msg['From'] = MAIL_FROM
    msg['To'] = MAIL_TO
    alternative = MIMEMultipart('alternative')
    alternative.attach(MIMEText(pText, 'plain'))
    alternative.attach(MIMEText(pHTML, 'html'))
    msg.attach(alternative)

    if logs:
        existing_files = [
            f for f in sorted_alphanumeric(os.listdir(SATELLITE_LOG_PATH))
            if f.endswith(".txt") and "_error_" in f and len(f.split('_error_')[1].replace('.txt', '')) == report_timestamp
        ]

        for file_name in existing_files:
            file_path = os.path.join(SATELLITE_LOG_PATH, file_name)
            with open(file_path, 'rb') as file:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(file.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename="{file_name}"')
                msg.attach(part)

    # Send mail
    try:
        smtp_connection = smtplib.SMTP (SMTP_SERVER, SMTP_PORT)
        smtp_connection.ehlo()
        if not SafeParseGlobalBool("SMTP_SKIP_TLS"):
            smtp_connection.starttls()
            smtp_connection.ehlo()
        if not SafeParseGlobalBool("SMTP_SKIP_LOGIN"):
            smtp_connection.login (SMTP_USER, SMTP_PASS)
        smtp_connection.sendmail (MAIL_FROM, MAIL_TO, msg.as_string())
    except Exception as e:
        print(f"    Error sending the e-mail")
    finally:
        smtp_connection.quit()
        print(f"    Message sent")

#-------------------------------------------------------------------------------
def SafeParseGlobalBool(boolVariable):
  return eval(boolVariable) if boolVariable in globals() else False

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
