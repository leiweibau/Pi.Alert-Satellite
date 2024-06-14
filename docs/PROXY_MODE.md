Requirements:
- Web server with PHP support
- Web server must support file upload

Installation:
Create a new folder for the Pi.Alert API Proxy on your web server within the web root (it can also be a subfolder). For the purposes of this guide, I will use the folder "pialert_proxy". Place the "api" folder and its contents into this directory. Additionally, create the "satellites" folder.
The resulting folder structure should be as follows:

```
pialert_proxy
├── api
└── satellites
```

The URL for the API is now, for example: https://example.com/pialert_proxy/api/satellite.php