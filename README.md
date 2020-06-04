# CloudGenix Get Sites (Preview)
This utility is used to download sites specific information from the CloudGenix managed network to a CSV file.

#### Synopsis
Enables downloading of all the configured sites and it's relavant information such as location, policies to a CSV file.


#### Requirements
* Active CloudGenix Account
* Python >=3.6
* Python modules:
    * CloudGenix Python SDK >= 5.2.1b1 - <https://github.com/CloudGenix/sdk-python>
* ProgressBar2

#### License
MIT

#### Installation:
 - **Github:** Download files to a local directory, manually run `getsites.py`. 

### Usage:
```
./getsites.py
```

Help Text:
```angular2
Tanushrees-MacBook-Pro:getsites tanushreekamath$ ./getsites.py -h
usage: getsites.py [-h] [--controller CONTROLLER] [--insecure] [--email EMAIL]
                   [--pass PASS] [--debug DEBUG]

CloudGenix Get Site Info -> CSV Generator.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. https://cloudgenix.com:8443
  --insecure, -I        Disable SSL certificate and hostname verification

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of prompting
  --pass PASS, -PW PASS
                        Use this Password instead of prompting

Debug:
  These options enable debugging output

  --debug DEBUG, -D DEBUG
                        Verbose Debug info, levels 0-2
Tanushrees-MacBook-Pro:getsites tanushreekamath$ 

```

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b3** | Minor bug fixes |
| **1.0.0** | **b2** | Minor bug fixes |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional CloudGenix Documentation at <http://support.cloudgenix.com>
 
