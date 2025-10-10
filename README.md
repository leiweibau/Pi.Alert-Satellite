# Pi.Alert Satellite
A companion script for [Pi.Alert](https://github.com/leiweibau/Pi.Alert), which executes the Pi.Alert scan on an external host and sends the data as encrypted [JSON](docs/JSON_DEMO.md) to a special API.

### The satellite can operate in 1 of 2 different modes

![Satellite Modes][Satellite_Modes]

#### Direct API call:
Here the API of the Pi.Alert instance is called. This API compares the transmitted token with the Pi.Alert database to check whether the token is valid. If this is the case, the encrypted payload is decrypted and processed together with the scans of the Pi.Alert instance.

#### Indirect API call (proxy mode):
The API is installed on a separate web server. The satellite now transmits the data to the "proxy". This uses a configuration file to check whether it is a valid token and, if so, stores the data in encrypted form. Decryption on the proxy is not possible, as only the satellite and the Pi.Alert instance know the password. For Pi.Alert to retrieve the data, it must also be configured for proxy mode.

[Prepare PROXY_MODE](docs/PROXY_MODE.md)

### Scan Methods

<ins>**arp-scan**</ins> (system utility to search for devices using arp frames), 
<ins>**Pi-hole DNS**</ins> (v5 or v6), <ins>**Pi-hole DHCP**</ins>. (v5 or v6),
<ins>**Fritzbox**</ins> (active Hosts), <ins>**Mikrotik**</ins> (DHCP leases), <ins>**UniFi**</ins> (Client Devices), <ins>**OpenWRT**</ins> (active hosts), 
<ins>**AsusWRT**</ins> (active hosts)

### Installation
<!--- --------------------------------------------------------------------- --->
Initially designed to run on a Debian based Linux distribution. 

<table>
  <thead>
    <tr><th align="left">One-step Automated Install</th></tr>
  </thead>
  <tbody>
  <tr><td>

```
bash -c "$(wget -qLO - https://github.com/leiweibau/Pi.Alert-Satellite/raw/main/install/pialert_satellite_install.sh)"
```
  </td></tr>
  </tbody>
</table>

As an alternative to this installation, you can also click on the blue "i" icon on the right in the line of the corresponding satellite in the Pi.Alert instance after creating a satellite and create the 
installation command, which takes care of the important configuration during the installation.

[Main Config flie parameter](docs/CONFIG_FILE.md)

| ![Config MainScreen][Config] | ![PreConfig Modal][PreConfig] |
| ---------------------------- | ----------------------------- |

### Update
<!--- --------------------------------------------------------------------- --->
Initially designed to run on a Debian based Linux distribution. 

<table>
  <thead>
    <tr><th align="left">One-step Automated Update</th></tr>
  </thead>
  <tbody>
  <tr><td>

```
bash -c "$(wget -qLO - https://github.com/leiweibau/Pi.Alert-Satellite/raw/main/install/pialert_satellite_update.sh)"
```
  </td></tr>
  </tbody>
</table>

An archive of older versions can be found at [https://leiweibau.net/archive/pialert-satellite/](https://leiweibau.net/archive/pialert-satellite/). This archive contains all release notes.

### Uninstall
<!--- --------------------------------------------------------------------- --->

In the directory "pialert-satellite/install/" there is a script called "pialert_satellite_uninstall.sh". This can be used to delete the cronjob and the "pialert-satellite" directory.

### License
  GPL 3.0
  [Read more here](LICENSE.txt)

### Contact

  leiweibau@gmail.com


[Config]:          https://raw.githubusercontent.com/leiweibau/Pi.Alert/assets/satellite_config.png      "Config MainScreen"
[PreConfig]:       https://raw.githubusercontent.com/leiweibau/Pi.Alert/assets/satellite_preconfig.png   "PreConfig Modal"
[Satellite_Modes]: https://raw.githubusercontent.com/leiweibau/Pi.Alert/assets/Satellite_Modes.png       "Satellite Modes"
