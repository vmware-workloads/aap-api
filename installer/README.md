# AAP API Installer

Installs the AAP API ABX action, custom resource and secrets as defined in the config file.
 

## Prerequisites

-   Aria Automation 8.16 or higher
-   (Python installer) Python 3.10 or higher on the machine where the script will be executed


Download and copy the files into a local directory

## Files 
- `config.json`: installer configuration file.
- `install.ps1`: Windows installer.
- `install.py`: Python installer.
- `aao_api.py`: aria ABX action to be installed.


## Installation

### Windows

Run `install.ps1`


### Python Installer (multi platform)

1. Configure values in config.json

Sample values are shown below:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{
    "project_name":  "my project",
    "aria_base_url":  "https://example.com",
    "aria_username":  "Iorek.Byrnison",
    "aria_password":  "P@ssw0rd",
    "cr_name":  "AAP API Resource",
    "cr_type_name":  "Custom.AAP",
    "abx_action_name":  "AAP API ABX",
    "ansible_url":  "https://example.com",
    "ansible_user":  "admin",
    "ansible_password":  "P@ssword",
    "ansible_root_ca":  "XXXXXXX",
    "skip_certificate_check":  "True"
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



2. Run the installer:

`$ Python3 install.py`
