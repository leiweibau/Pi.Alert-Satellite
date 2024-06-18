## Use case:
If it is not desired for security reasons that the Satellite sends the data directly to the Pi.Alert API, a second web server can be used as a "proxy". 
In this case, the satellite sends the data to the proxy and Pi.Alert retrieves the data from it. The data is not decrypted on the proxy.

## Requirements:

- Web server with PHP support
- Web server must support file upload
- The web server must be accessible for both the satellite and the Pi.Alert instance itself
- An already installed version of Pi.Alert for creation of a configuration file

## Installation:

This step only needs to be performed once and can be used for multiple satellites.
Create a new folder for the Pi.Alert API Proxy on your web server within the web root (it can also be a subfolder). For the purposes of this guide, 
I will use the folder "pialert_proxy". Place the "api" folder and its contents into this directory. Additionally, create the "satellites" folder.
The resulting folder structure should be as follows:

```
pialert_proxy
├── api
└── satellites
```

The URL for the API is now, for example: https://example.com/pialert_proxy/api/satellite.php

## Configuration:
In the configuration file of the satellite ("config/satellite.conf"), the variable "PROXY_MODE" must be set to "True". The URL of the proxy is entered
as the value for the variable "SATELLITE_MASTER_URL" according to the example above. Finally, a file called "config.php", which can be downloaded from 
the Pi.Alert satellite settings, is also copied to the "api" directory. This file contains the tokens of all created satellites and ensures that only 
valid satellites are allowed to interact with the API.
