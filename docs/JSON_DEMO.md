## DEMO json

Here you can see the basic structure of the unencrypted json, which is sent encrypted to the API.


```json
{
    "satellite_meta_data": [
        {
            "hostname": "Pialert-Satellite-Host",
            "satellite_version": "2024-07-03",
            "satellite_ip": "<SATELLITE IP>",
            "satellite_mac": "<SATELLITE MAC>",
            "satellite_id": "<SATELLITE_TOKEN>",
            "scan_time": "2024-07-16 15:28:00",
            "uptime": "0d 00h 17m ",
            "cpu_name": "Intel(R) Celeron(R) CPU  N2830  @ 2.16GHz",
            "cpu_arch": "x86_64",
            "cpu_cores": 2,
            "cpu_freq": "2.4167 GHz",
            "proc_count": "138"
        }
    ],
    "satellite_scan_config": [
        {
            "scan_arp": true,
            "scan_fritzbox": false,
            "scan_mikrotik": false,
            "scan_unifi": false
        }
    ],
    "scan_results": [
        {
            "cur_MAC": "Internet - <SATELLITE_TOKEN>",
            "cur_IP": "79.198.124.10",
            "cur_Vendor": "",
            "cur_ScanMethod": "Internet Check",
            "cur_SatelliteID": "<SATELLITE_TOKEN>"
        },
        {
            "cur_MAC": "00:11:22:aa:bb:cc",
            "cur_IP": "192.168.1.85",
            "cur_hostname": "(satellite network client)",
            "cur_Vendor": "(Unknown: locally administered)",
            "cur_ScanMethod": "arp-scan",
            "cur_SatelliteID": "<SATELLITE_TOKEN>"
        }
    ]
}
```

[Back](https://github.com/leiweibau/Pi.Alert-Satellite)
