# AAP API Installer
==========================

Installs the AAP API ABX action, custom resource and secrets as defined in the config file.
 

## Installation

### Windows

Run `install.ps1`


### Linux, etc (Python)

1. Configure values in config.json

Sample values are shown below:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{
  "ansible_url": "https://",
  "ansible_user": "<ansible_user>",
  "ansible_password": "<ansible_pass>",
  "aria_base_url": "https://",
  "abx_action_name": "My_ABX",
  "cr_name": "my_aap",
  "cr_type_name": "Custom.myAAP",
  "aria_username": "<aria_user>",
  "aria_password": "<aria_pass>",
  "project_name": "MY_PROJECT",
  "skip_certificate_check": "True",
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



2. Run the installer:

`$ Python3 install.py`
