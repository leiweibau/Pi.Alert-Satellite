# Pi.Alert Satellite
A companion script for [Pi.Alert](https://github.com/leiweibau/Pi.Alert), which executes the Pi.Alert scan on an external host and sends the data as encrypted JSON to a special API.

### The satellite can operate in 1 of 2 different modes

#### Direct API call:
Here the API of the Pi.Alert instance is called. This API compares the transmitted token with the Pi.Alert database to check whether the token is valid. If this is the case, the encrypted payload is decrypted and processed together with the scans of the Pi.Alert instance.

#### Indirect API call (proxy mode):
The API is installed on a separate web server. The satellite now transmits the data to the "proxy". This uses a configuration file to check whether it is a valid token and, if so, stores the data in encrypted form. Decryption on the proxy is not possible, as only the satellite and the Pi.Alert instance know the password. For Pi.Alert to retrieve the data, it must also be configured for proxy mode.

As I am still in the test/trial phase, there are still many things that are not possible. From time to time, the things that work are listed in the commits. 
The whole thing is still a prototype or feasibility study and there is no guarantee that the work on this will be completed. For this reason, I will not work on any issues that are reported during this prototype phase.

### Scan Methods

  - **arp-scan**. The arp-scan system utility is used to search for devices on the network using arp frames.
  - **Fritzbox**. If you use a Fritzbox (a router from the company "AVM"), it is possible to perform a query of the active hosts. This also includes hosts of the guest WLAN and Powerline devices from "AVM".
  - **Mikrotik**. If you use Mikrotik Router as DHCP server, it is possible to read DHCP leases.
  - **UniFi**. If you use UniFi controller, it is possible to read clients (Client Devices)

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

### Uninstall
<!--- --------------------------------------------------------------------- --->

In the directory "pialert-satellite/install/" there is a script called "pialert_satellite_uninstall.sh". This can be used to delete the cronjob and the "pialert-satellite" directory.

### License
  GPL 3.0
  [Read more here](LICENSE.txt)

### Contact

  leiweibau@gmail.com


[Config]:    https://raw.githubusercontent.com/leiweibau/Pi.Alert/assets/satellite_config.png          "Config MainScreen"
[PreConfig]: https://raw.githubusercontent.com/leiweibau/Pi.Alert/assets/satellite_preconfig.png       "PreConfig Modal"
