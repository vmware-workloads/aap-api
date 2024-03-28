import json
import requests
import time

import urllib3
import urllib.parse

from requests.auth import HTTPBasicAuth
from string import Template
from typing import List, Union


def invert_dict(d: dict, name: str) -> dict:
    inv_d = {}
    for k, vs in d.items():
        for v in vs:
            for host in v:
                host_name = host.get(name)
                inv_d.setdefault(host_name, []).append(k)
    return inv_d

def parse_groups(d: dict, name: str) -> dict:
    inv_d = {}
    #for k, v_list in d.items():
        
    


class AapHost(object):
    def __init__(self,
                 host: dict,
                 host_id: int = None,
                 host_variables: dict = None,
                 host_groups: List[str] = None):

        if host_variables is None:
            host_variables = {}

        if host_groups is None:
            host_groups = []

        # ansible_host is minimally required so Ansible Automation Platform can
        # reach the system to be configured. Typically, the system is not in DNS.
        variables = {"ansible_host": host.get("networks")[0].get("address")}
        for key, value in host_variables.items():
            variables[key] = value

        self.id = host_id
        self.name = host.get("resourceName")
        self.variables = json.dumps(variables)
        self.groups = host_groups

    @classmethod
    def create_app_hosts(cls, hosts: list, host_variables: dict, host_groups: dict) -> List['AapHost']:
        aap_hosts = []
        for host_list in hosts:
            for host in host_list:
                variables = host_variables.get(host.get("name"), {})
                groups = host_groups.get(host.get('resourceName'), [])
                aap_hosts.append(AapHost(host=host, host_variables=variables, host_groups=groups))
        return aap_hosts

    def get_host_data(self):
        return {
            "name": self.name,
            "variables": self.variables,
        }


class AapApi(object):
    PATH_TOKEN = "api/v2/tokens/"
    PATH_INVENTORY = "api/v2/inventories/"
    PATH_ORGANIZATION = "api/v2/organizations/"
    PATH_GROUPS = "api/v2/groups/"
    PATH_HOSTS = "api/v2/hosts/"
    PATH_BULK_HOST_CREATE = "api/v2/bulk/host_create/"
    PATH_GROUP_ADD = Template("api/v2/groups/$group_id/hosts/")
    PATH_JOB_TEMPLATES = "api/v2/job_templates/"
    PATH_JOB_TEMPLATES_LAUNCH = Template("api/v2/job_templates/$job_template_id/launch/")
    DEFAULT_ORGANIZATION_NAME = "Default"
    DEFAULT_ORGANIZATION_ID = 1

    def __init__(
        self, base_url: str, username: str, password: str, ssl_verify: bool = True
    ):
        """

        :type ssl_verify: bool
        """
        # Ansible Automation Platform details
        self.base_url = base_url
        self.username = username
        self.password = password
        self.ssl_verify = ssl_verify

        # Basic Auth credentials
        self._auth = HTTPBasicAuth(username=self.username, password=self.password)

        # POST for OATH2 token
        response = requests.post(
            url=urllib.parse.urljoin(self.base_url, url=self.PATH_TOKEN),
            auth=self._auth,
            verify=ssl_verify,
        )

        # Check for successful token creation
        response.raise_for_status()

        # Get the required data
        data = response.json()
        self._token = data.get("token")
        self._token_id = data.get("id")

    def __dict__(self) -> dict:
        return {
            "base_url": self.base_url,
            "username": self.username,
            "token": self._token,
            "token_id": self._token_id,
        }

    def __get(self, path: str):
        url = urllib.parse.urljoin(self.base_url, url=path)
        headers = {
            "Authorization": "Bearer " + self._token,
        }
        response = requests.get(url=url, headers=headers, verify=self.ssl_verify)
        response.raise_for_status()
        return response.json()

    def __post(self, path: str, data: dict):
        url = urllib.parse.urljoin(self.base_url, url=path)
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self._token,
        }
        response = requests.post(
            url=url, headers=headers, json=data, verify=self.ssl_verify
        )
        response.raise_for_status()
        if response.status_code not in [204]:
            return response.json()

    @classmethod
    def __find(cls, name: str, results: list) -> list:
        return list(filter(lambda x: x.get("name") == name, results))

    def find_organization_by_name(self, name: str) -> dict:
        """Search for an organization and return its ID"""
        path = self.PATH_ORGANIZATION + f"?search={name}"
        response = self.__get(path=path)
        results = response.get("results", [])

        # Search for exact name matches
        # Note: We have to search because a search for 'foo' would return entries
        #       that include 'foo', 'foobar', 'myfoo'.
        matches = self.__find(name=name, results=results)

        # We should only have one match
        if len(matches) > 1:
            raise RuntimeError(f"Found {len(matches)} organizations with name {name}.")

        # No matches, return the default organization
        if len(matches) < 1:
            return {
                "name": self.DEFAULT_ORGANIZATION_NAME,
                "id": self.DEFAULT_ORGANIZATION_ID,
            }

        # Return the organization id
        return {
            "name": name,
            "id": matches[0].get("id"),
        }

    def find_inventory_by_name(self, name: str) -> Union[None, dict]:
        """Search for an inventory and return its ID"""
        path = self.PATH_INVENTORY + f"?search={name}"
        response = self.__get(path=path)
        results = response.get("results", [])

        # Search for exact name matches
        # Note: We have to search because a search for 'foo' would return entries
        #       that include 'foo', 'foobar', 'myfoo'.
        matches = self.__find(name=name, results=results)

        # We should only have one match
        if len(matches) > 1:
            raise RuntimeError(f"Found {len(matches)} inventories with name {name}.")

        # Return 'None' if none found
        if len(matches) < 1:
            return None

        # Return the inventory id
        return {
            "name": name,
            "id": matches[0].get("id")
        }

    def find_group_by_name(self, name: str, inventory_id: int) -> Union[None, dict]:
        """Search for a group and return its ID"""
        path = self.PATH_GROUPS + f"?inventory={inventory_id}"
        response = self.__get(path=path)
        results = response.get("results", [])

        # Search for exact name matches
        # Note: The previous query returns all the groups part of an inventory,
        #       so we need to filter for the exact name
        matches = self.__find(name=name, results=results)

        # We should only have one match
        if len(matches) > 1:
            raise RuntimeError(
                f"Found {len(matches)} groups with name {name} in inventory {inventory_id}."
            )

        # Return 'None' if none found
        if len(matches) < 1:
            return None

        # Return the group id
        return {
            "name": name,
            "id": matches[0].get("id")
        }

    def find_job_template_by_name(self, name: str) -> Union[None, dict]:
        """Search for a job template by name."""
        path = self.PATH_JOB_TEMPLATES + f"?search={name}"
        response = self.__get(path=path)
        results = response.get("results", [])

        # Search for exact name matches
        # Note: The previous query returns all the groups part of an inventory,
        #       so we need to filter for the exact name
        matches = self.__find(name=name, results=results)

        # We should only have one match
        if len(matches) > 1:
            raise RuntimeError(f"Found {len(matches)} templates with name {name}.")

        # Return 'None' if none found
        if len(matches) < 1:
            return None

        # Return the inventory id
        return {
            "name": name,
            "id": matches[0].get("id")
        }

    def create_inventory(
        self, name: str, organization_id: int = DEFAULT_ORGANIZATION_ID
    ) -> dict:
        """Create a new inventory and add hosts to the inventory"""
        inventory = self.find_inventory_by_name(name=name)
        if inventory is None:
            data = {
                "name": name,
                "description": "Created via Aria Automation API",
                "organization": organization_id,
            }
            response = self.__post(path=self.PATH_INVENTORY, data=data)
            inventory = {
                "name": name,
                "id": response.get("id")
            }
        return inventory

    def create_group(self, name: str, inventory_id: int, description: str = None) -> dict:
        """Create a new group"""
        group = self.find_group_by_name(name=name, inventory_id=inventory_id)
        if group is None:
            data = {
                "name": name,
                "description": "" if description is None else description,
                "inventory": inventory_id,
            }
            response = self.__post(path=self.PATH_GROUPS, data=data)
            group = {
                "name": name,
                "id": response.get("id")
            }
        return group

    def add_hosts_to_inventory(self, inventory_id: int, hosts: List[AapHost]) -> List[AapHost]:
        """Add hosts to am inventory
        ref. https://www.redhat.com/en/blog/bulk-api-in-automation-controller
        """
        data = {
            "inventory": inventory_id,
            "hosts": [host.get_host_data() for host in hosts],
        }
        response = self.__post(path=self.PATH_BULK_HOST_CREATE, data=data)
        for host in hosts:
            host.id = next(item.get("id") for item in response.get("hosts") if item["name"] == host.name)
        return hosts

    def add_hosts_to_groups(self, aap_hosts: List[AapHost], aap_groups: List[dict]) -> None:
        """Add hosts to the specified groups."""
        groups_ids = {}
        for aap_group in aap_groups:
            groups_ids[aap_group.get('name')] = aap_group.get('id')

        for aap_host in aap_hosts:
            for group_name in aap_host.groups:
                group_id = groups_ids[group_name]
                group_path = self.PATH_GROUP_ADD.substitute({"group_id": group_id})
                data = {
                    "id": aap_host.id
                }
                self.__post(path=group_path, data=data)

    def launch_job_template(self, job_template_id: dict, inventory_id: int) -> dict:
        """Launch a job template with a specific inventory."""
        path = self.PATH_JOB_TEMPLATES_LAUNCH.substitute({"job_template_id": job_template_id})
        data = {
            "inventory": inventory_id,
        }
        response = self.__post(path=path, data=data)
        pass
        return response

    def get_job_status(self, job: dict):
        """Retrieve the status of a specific job."""
        path_job_url = job.get("url")
        response = self.__get(path=path_job_url)
        return response.get("status")

    def wait_for_job_completion(self, job: dict, interval: int = 5, max_timeout_seconds: int = 300):
        """Wait for a job to complete, checking the status at the specified interval."""
        for _ in range(0, max_timeout_seconds, max_timeout_seconds):
            status = self.get_job_status(job=job)
            if status in ('successful', 'failed', 'error', 'canceled'):
                return status
            else:
                print(f"Job {job.get('id')} is {status}. Waiting {interval} seconds out of {max_timeout_seconds}.")
                time.sleep(interval)


def handler(context, inputs):
    # Ansible Automation Platform Configuration
    base_url = inputs["base_url"]
    username = inputs["username"]
    password = context.getSecret(inputs["password"])
    ssl_verify = inputs.get("ssl_verify", True)
    verbose = inputs.get("verbose", False)

    # Ansible Automation Platform Inventory
    organization_name = inputs.get("organization_name", "Default")
    inventory_name = inputs.get("inventory_name", "aap-api")
    hosts = inputs.get("hosts", [])
    host_variables = inputs.get("host_variables", {})
    groups = [group_name for group_name in inputs.get("host_groups", {}).keys()]
    host_groups = invert_dict(d=inputs.get("host_groups", {}), name="resourceName")
    job_template_name = inputs.get("job_template_name")

    # Create AAP Hosts
    aap_hosts = AapHost.create_app_hosts(hosts=hosts, host_variables=host_variables, host_groups=host_groups)

    if verbose:
        print(f"base_url: '{base_url}'")
        print(f"username: '{username}'")
        print(f"ssl_verify: '{ssl_verify}'")
        print(f"inventory_name: '{inventory_name}'")
        print(f"host_variables: '{host_variables}'")
        print(f"groups: '{groups}'")
        print(f"host_groups: '{host_groups}'")
        print(f"hosts: '{[vars(aap_host) for aap_host in aap_hosts]}'")
        print(f"job_template_name: '{job_template_name}")

    # Disable SSL warning if we are not verifying the ansible host SSL certificate
    if not ssl_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Create Ansible Automation Platform API object
    aap = AapApi(base_url=base_url,
                 username=username,
                 password=password,
                 ssl_verify=ssl_verify)

    # Find the organization id
    aap_organization = aap.find_organization_by_name(name=organization_name)

    # Find the job template
    aap_job_template = aap.find_job_template_by_name(name=job_template_name)
    if aap_job_template is None:
        raise ValueError(f"Could not find a job template with name '{job_template_name}'")

    # Get the inventory id
    # If an inventory with that exact name exists, we return its id.
    # If an inventory with that exact name does not exist, we create one and return the id.
    aap_inventory = aap.create_inventory(name=inventory_name, organization_id=aap_organization.get("id"))

    # Get the group ids
    # If a group with the exact name exists, we return its id.
    # If a group with the exact name does not exist, we create one and return the id.
    aap_groups = [aap.create_group(name=group, inventory_id=aap_inventory.get("id")) for group in groups]

    # Add the hosts to the inventory
    # The host names *must* be unique within the inventory.
    aap_hosts = aap.add_hosts_to_inventory(inventory_id=aap_inventory.get("id"), hosts=aap_hosts)

    # Add the hosts to inventory groups
    aap.add_hosts_to_groups(aap_hosts=aap_hosts, aap_groups=aap_groups)

    # Start the job template with the created inventory
    aap_job = aap.launch_job_template(job_template_id=aap_job_template.get("id"), inventory_id=aap_inventory.get("id"))

    # Wait for the job to complete
    aap.wait_for_job_completion(job=aap_job)


if __name__ == "__main__":
    test = {
  "hosts": [
    [
      {
        "id": "/resources/compute/30a231b4-a1cf-4639-a6a1-c5fd71231763",
        "name": "crdb_vm",
        "tags": [
          {
            "key": "colour",
            "value": "blue"
          }
        ],
        "zone": "wdc-w01-cl01",
        "count": "2",
        "image": "test-image",
        "moref": "VirtualMachine:vm-511",
        "osType": "LINUX",
        "region": "wdc-w01-DC",
        "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
        "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
        "__moref": "VirtualMachine:vm-511",
        "account": "wdc-w01-vc01.vcf01.isvlab.vmware.com",
        "address": "172.16.63.132",
        "project": "087a503a-0da8-4254-9714-15094422021c",
        "storage": {
          "disks": [
            {
              "name": "CD/DVD drive 1",
              "type": "CDROM",
              "encrypted": False,
              "capacityGb": 0,
              "persistent": False,
              "resourceLink": "/resources/disks/220721b9-8401-42f8-9468-f3e9d2c2bf18",
              "controllerKey": "200",
              "existingResource": "False",
              "controllerUnitNumber": "0"
            },
            {
              "vm": "VirtualMachine:vm-511",
              "name": "crdb_vm-mcm3050-259990695356-boot-disk",
              "type": "HDD",
              "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
              "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-d4db-6e47-4405-0c42a12a8538/crdb_vm-mcm3050-259990695356_2.vmdk",
              "bootOrder": 1,
              "encrypted": False,
              "capacityGb": 60,
              "persistent": False,
              "independent": "False",
              "endpointType": "vsphere",
              "resourceLink": "/resources/disks/72bc7876-4d90-463c-a54a-6e1c11686f0e",
              "controllerKey": "1000",
              "diskPlacementRef": "Datastore:datastore-18",
              "existingResource": "False",
              "provisioningType": "thin",
              "controllerUnitNumber": "0"
            },
            {
              "name": "Floppy drive 1",
              "type": "FLOPPY",
              "encrypted": False,
              "capacityGb": 0,
              "persistent": False,
              "resourceLink": "/resources/disks/dc166778-1a6c-4f5d-90c2-dfddf03e1fb9",
              "controllerKey": "400",
              "existingResource": "False",
              "controllerUnitNumber": "0"
            },
            {
              "vm": "VirtualMachine:vm-511",
              "name": "Hard disk 2",
              "type": "HDD",
              "shares": "1000",
              "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-d4db-6e47-4405-0c42a12a8538/crdb_vm-mcm3050-259990695356_4.vmdk",
              "encrypted": False,
              "limitIops": "-1",
              "capacityGb": 800,
              "persistent": False,
              "independent": "False",
              "sharesLevel": "normal",
              "endpointType": "vsphere",
              "resourceLink": "/resources/disks/eb930716-ad54-45a7-97cb-2b1b40584cce",
              "controllerKey": "1001",
              "existingResource": "False",
              "provisioningType": "thin",
              "controllerUnitNumber": "0"
            }
          ]
        },
        "accounts": [
          "wdc-w01-vc01.vcf01.isvlab.vmware.com"
        ],
        "cpuCount": 4,
        "networks": [
          {
            "id": "/resources/network-interfaces/f64a7d33-8969-43f9-836e-cdcc5780ae39",
            "dns": [
              "172.16.16.16",
              "172.16.16.17"
            ],
            "name": "ls-wcp-management-172_16_63_128__27-dhcp",
            "domain": "vcf01.isvlab.vmware.com",
            "address": "172.16.63.132",
            "gateway": "172.16.63.129",
            "netmask": "255.255.255.224",
            "network": "/provisioning/resources/compute-networks/ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1",
            "gateways": "172.16.63.129",
            "assignment": "static",
            "deviceIndex": 0,
            "external_id": "7ee2bbee-e2fd-47cc-9d5f-9aba919eabf6",
            "mac_address": "00:50:56:84:06:bb",
            "resourceName": "ls-wcp-management-172_16_63_128__27-dhcp",
            "ipv6Addresses": [
              "fe80::250:56ff:fe84:6bb"
            ],
            "dnsSearchDomains": [
              "vcf01.isvlab.vmware.com"
            ],
            "assignPublicIpAddress": True
          }
        ],
        "username": "crdb",
        "coreCount": "1",
        "enableSSH": "True",
        "__imageRef": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
        "countIndex": "0",
        "endpointId": "b5c736bd-4aaa-4630-8778-21c0a56d89f0",
        "externalId": "500491a5-8cc0-8843-fae6-8957920f7a52",
        "isSimulate": "False",
        "powerState": "ON",
        "primaryMAC": "00:50:56:84:06:bb",
        "providerId": "500491a5-8cc0-8843-fae6-8957920f7a52",
        "resourceId": "30a231b4-a1cf-4639-a6a1-c5fd71231763",
        "cloudConfig": "#cloud-config\nssh_authorized_keys:\n- ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\npackage_update: True\npackage_upgrade: True\npackage_reboot_if_required: True\nusers:\n- name: crdb\n  shell: /bin/bash\n  sudo:\n  - ALL=(ALL) NOPASSWD:ALL\n- default\n- name: crdb\n  ssh_authorized_keys:\n  - ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\nssh_pwauth: True\nruncmd:\n- hostnamectl set-hostname --pretty crdb_vm-mcm3050-259990695356\n- sudo service sshd restart\npackages:\n- chrony\n",
        "__dcSelfLink": "/resources/groups/3f14e002-ef03-4662-9104-65b89ea1aee9",
        "endpointType": "vsphere",
        "instanceUUID": "500491a5-8cc0-8843-fae6-8957920f7a52",
        "remoteAccess": {
          "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
          "username": "crdb",
          "authentication": "publicPrivateKey"
        },
        "resourceLink": "/resources/compute/30a231b4-a1cf-4639-a6a1-c5fd71231763",
        "resourceName": "crdb_vm-mcm3050-259990695356",
        "resourcePool": "/resources/pools/4004ae581f4d5075-7f703c5265a63d87",
        "softwareName": "Ubuntu Linux (64-bit)",
        "vmFolderPath": "[wdc-w01-wdc-w01-vsan01] 40e60466-d4db-6e47-4405-0c42a12a8538",
        "__computeHost": "True",
        "__computeType": "VirtualMachine",
        "componentType": "Cloud.vSphere.Machine",
        "datastoreName": "wdc-w01-wdc-w01-vsan01",
        "totalMemoryMB": 16384,
        "__blueprint_id": "0a7686a1-6a94-462a-9839-2930a6518e15",
        "__endpointLink": "/resources/endpoints/b5c736bd-4aaa-4630-8778-21c0a56d89f0",
        "__endpointType": "vsphere",
        "cloneFromImage": "ubuntuTemplate-HWE",
        "computeHostRef": "ClusterComputeResource:domain-c8",
        "__deployment_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "__imageOsFamily": "LINUX",
        "__placementLink": "/resources/compute/b8d8c4dd-52d8-40a2-a008-1cb940b75fcb",
        "computeHostType": "ClusterComputeResource",
        "__bootDiskSizeMB": "61440",
        "__deploymentLink": "/resources/deployments/50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "customizeGuestOs": "True",
        "resourceDescLink": "/resources/compute-descriptions/0b4602e0-9cd0-4c32-aea6-44857a3d98c8",
        "__computeHostLink": "/resources/compute/b2bc2a04-56de-4492-8904-cd537a4e828c",
        "resourceGroupName": "",
        "__cpuHotAddEnabled": "False",
        "__imageMappingLink": "/provisioning/resources/image-profiles-v2/032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
        "__operationTimeout": "7200",
        "__storageReference": "Datastore:datastore-18",
        "neglectPowerOffVms": "False",
        "__component_type_id": "Compute.vSphere",
        "__isStorageReserved": "True",
        "__resolvedImageLink": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
        "__allocation_request": "True",
        "__memoryHotAddEnabled": "False",
        "__blueprint_request_id": "94686cd5-24b2-4111-a45f-562d44de00ca",
        "__vmw:provisioning:org": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d",
        "_clusterAllocationSize": "2",
        "__blueprint_resource_id": "30a231b4-a1cf-4639-a6a1-c5fd71231763",
        "__imageBootDiskSizeInMB": "61440",
        "__imageDisksTotalSizeMB": "880640",
        "__composition_context_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "__projectPlacementPolicy": "DEFAULT",
        "__blueprint_resource_name": "crdb_vm[0]",
        "__blueprint_resource_type": "Cloud.vSphere.Machine",
        "zone_overlapping_migrated": "True",
        "__vmw:provisioning:project": "087a503a-0da8-4254-9714-15094422021c",
        "__blueprint_request_event_id": "49d5b727-d0ef-41ef-b3fc-e9a1875dd9a3",
        "__groupResourcePlacementLink": "/provisioning/resources/group-placements/087a503a-0da8-4254-9714-15094422021c-d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
        "__vmw:provisioning:blueprint": "0a7686a1-6a94-462a-9839-2930a6518e15",
        "__vmw:provisioning:cloudZone": "d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
        "__vmw:provisioning:requester": "provisioning-hamskor2of8iplc9@provisioning-client.local",
        "__vmw:provisioning:deployment": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "__vmw:provisioning:imageMapping": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
        "__allowTerraformCloudzoneMapping": "True",
        "__blueprint_resource_dependencies": "[\"infra_net\"]",
        "__blueprint_resource_last_operation": "create",
        "__vmw:provisioning:blueprintResourceName": "crdb_vm",
        "__computeConfigContentPhoneHomeShouldWait": "False",
        "__blueprint_resource_dependent_resource_ids": "[\"febd9291-1373-4a35-9af4-19264611a64d\"]",
        "__blueprint_resource_dependency_resource_ids": "[\"ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1\"]",
        "__blueprint_resource_allocation_dependent_ids": "[]",
        "__ext:RequestBrokerState:STARTED:RESOURCE_COUNTED": "True",
        "__ext:ComputeReservationTaskState:STARTED:SELECTED": "True",
        "__computeConfigContentDeploymentFailOnCloudConfigRuntimeError": "True",
        "__ext:ComputeAllocationTaskState:STARTED:START_COMPUTE_ALLOCATION": "True"
      },
      {
        "id": "/resources/compute/71008850-0ffc-4940-8ad8-c0ea5c58e2de",
        "name": "crdb_vm",
        "tags": [
          {
            "key": "colour",
            "value": "blue"
          }
        ],
        "zone": "wdc-w01-cl01",
        "count": "2",
        "image": "test-image",
        "moref": "VirtualMachine:vm-512",
        "osType": "LINUX",
        "region": "wdc-w01-DC",
        "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
        "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
        "__moref": "VirtualMachine:vm-512",
        "account": "wdc-w01-vc01.vcf01.isvlab.vmware.com",
        "address": "172.16.63.141",
        "project": "087a503a-0da8-4254-9714-15094422021c",
        "storage": {
          "disks": [
            {
              "vm": "VirtualMachine:vm-512",
              "name": "Hard disk 2",
              "type": "HDD",
              "shares": "1000",
              "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-b6e8-bcda-b152-0c42a12a8530/crdb_vm-mcm3051-259990695356_4.vmdk",
              "encrypted": False,
              "limitIops": "-1",
              "capacityGb": 800,
              "persistent": False,
              "independent": "False",
              "sharesLevel": "normal",
              "endpointType": "vsphere",
              "resourceLink": "/resources/disks/242fe21a-a378-464b-a9ac-5b5582305049",
              "controllerKey": "1001",
              "existingResource": "False",
              "provisioningType": "thin",
              "controllerUnitNumber": "0"
            },
            {
              "vm": "VirtualMachine:vm-512",
              "name": "crdb_vm-mcm3051-259990695356-boot-disk",
              "type": "HDD",
              "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
              "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-b6e8-bcda-b152-0c42a12a8530/crdb_vm-mcm3051-259990695356_2.vmdk",
              "bootOrder": 1,
              "encrypted": False,
              "capacityGb": 60,
              "persistent": False,
              "independent": "False",
              "endpointType": "vsphere",
              "resourceLink": "/resources/disks/ed4d951c-9b30-4ebf-8f4f-0b22112508bf",
              "controllerKey": "1000",
              "diskPlacementRef": "Datastore:datastore-18",
              "existingResource": "False",
              "provisioningType": "thin",
              "controllerUnitNumber": "0"
            },
            {
              "name": "Floppy drive 1",
              "type": "FLOPPY",
              "encrypted": False,
              "capacityGb": 0,
              "persistent": False,
              "resourceLink": "/resources/disks/fd5e3b62-a2a2-4ba4-afdd-be76dd7921e4",
              "controllerKey": "400",
              "existingResource": "False",
              "controllerUnitNumber": "0"
            },
            {
              "name": "CD/DVD drive 1",
              "type": "CDROM",
              "encrypted": False,
              "capacityGb": 0,
              "persistent": False,
              "resourceLink": "/resources/disks/3c411098-2bbe-43b9-977d-b0551e4e0b6f",
              "controllerKey": "200",
              "existingResource": "False",
              "controllerUnitNumber": "0"
            }
          ]
        },
        "accounts": [
          "wdc-w01-vc01.vcf01.isvlab.vmware.com"
        ],
        "cpuCount": 4,
        "networks": [
          {
            "id": "/resources/network-interfaces/7382be23-86a9-4715-90b9-10e42f0a4b96",
            "dns": [
              "172.16.16.16",
              "172.16.16.17"
            ],
            "name": "ls-wcp-management-172_16_63_128__27-dhcp",
            "domain": "vcf01.isvlab.vmware.com",
            "address": "172.16.63.141",
            "gateway": "172.16.63.129",
            "netmask": "255.255.255.224",
            "network": "/provisioning/resources/compute-networks/ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1",
            "gateways": "172.16.63.129",
            "assignment": "static",
            "deviceIndex": 0,
            "external_id": "762b87b7-f00a-46cd-8d91-fcdb9d8b2fda",
            "mac_address": "00:50:56:84:fb:ac",
            "resourceName": "ls-wcp-management-172_16_63_128__27-dhcp",
            "ipv6Addresses": [
              "fe80::250:56ff:fe84:fbac"
            ],
            "dnsSearchDomains": [
              "vcf01.isvlab.vmware.com"
            ],
            "assignPublicIpAddress": True
          }
        ],
        "username": "crdb",
        "coreCount": "1",
        "enableSSH": "True",
        "__imageRef": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
        "countIndex": "1",
        "endpointId": "b5c736bd-4aaa-4630-8778-21c0a56d89f0",
        "externalId": "50043de2-66ee-a822-59e7-f430a57fa41f",
        "isSimulate": "False",
        "powerState": "ON",
        "primaryMAC": "00:50:56:84:fb:ac",
        "providerId": "50043de2-66ee-a822-59e7-f430a57fa41f",
        "resourceId": "71008850-0ffc-4940-8ad8-c0ea5c58e2de",
        "cloudConfig": "#cloud-config\nssh_authorized_keys:\n- ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\npackage_update: True\npackage_upgrade: True\npackage_reboot_if_required: True\nusers:\n- name: crdb\n  shell: /bin/bash\n  sudo:\n  - ALL=(ALL) NOPASSWD:ALL\n- default\n- name: crdb\n  ssh_authorized_keys:\n  - ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\nssh_pwauth: True\nruncmd:\n- hostnamectl set-hostname --pretty crdb_vm-mcm3051-259990695356\n- sudo service sshd restart\npackages:\n- chrony\n",
        "__dcSelfLink": "/resources/groups/3f14e002-ef03-4662-9104-65b89ea1aee9",
        "endpointType": "vsphere",
        "instanceUUID": "50043de2-66ee-a822-59e7-f430a57fa41f",
        "remoteAccess": {
          "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
          "username": "crdb",
          "authentication": "publicPrivateKey"
        },
        "resourceLink": "/resources/compute/71008850-0ffc-4940-8ad8-c0ea5c58e2de",
        "resourceName": "crdb_vm-mcm3051-259990695356",
        "resourcePool": "/resources/pools/4004ae581f4d5075-7f703c5265a63d87",
        "softwareName": "Ubuntu Linux (64-bit)",
        "vmFolderPath": "[wdc-w01-wdc-w01-vsan01] 40e60466-b6e8-bcda-b152-0c42a12a8530",
        "__computeHost": "True",
        "__computeType": "VirtualMachine",
        "componentType": "Cloud.vSphere.Machine",
        "datastoreName": "wdc-w01-wdc-w01-vsan01",
        "totalMemoryMB": 16384,
        "__blueprint_id": "0a7686a1-6a94-462a-9839-2930a6518e15",
        "__endpointLink": "/resources/endpoints/b5c736bd-4aaa-4630-8778-21c0a56d89f0",
        "__endpointType": "vsphere",
        "cloneFromImage": "ubuntuTemplate-HWE",
        "computeHostRef": "ClusterComputeResource:domain-c8",
        "__deployment_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "__imageOsFamily": "LINUX",
        "__placementLink": "/resources/compute/b8d8c4dd-52d8-40a2-a008-1cb940b75fcb",
        "computeHostType": "ClusterComputeResource",
        "__bootDiskSizeMB": "61440",
        "__deploymentLink": "/resources/deployments/50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "customizeGuestOs": "True",
        "resourceDescLink": "/resources/compute-descriptions/0b4602e0-9cd0-4c32-aea6-44857a3d98c8",
        "__computeHostLink": "/resources/compute/80fd003d-52e7-442c-a981-7dcef649fff0",
        "resourceGroupName": "",
        "__cpuHotAddEnabled": "False",
        "__imageMappingLink": "/provisioning/resources/image-profiles-v2/032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
        "__operationTimeout": "7200",
        "__storageReference": "Datastore:datastore-18",
        "neglectPowerOffVms": "False",
        "__component_type_id": "Compute.vSphere",
        "__isStorageReserved": "True",
        "__resolvedImageLink": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
        "__allocation_request": "True",
        "__memoryHotAddEnabled": "False",
        "__blueprint_request_id": "94686cd5-24b2-4111-a45f-562d44de00ca",
        "__vmw:provisioning:org": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d",
        "_clusterAllocationSize": "2",
        "__blueprint_resource_id": "71008850-0ffc-4940-8ad8-c0ea5c58e2de",
        "__imageBootDiskSizeInMB": "61440",
        "__imageDisksTotalSizeMB": "880640",
        "__composition_context_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "__projectPlacementPolicy": "DEFAULT",
        "__blueprint_resource_name": "crdb_vm[1]",
        "__blueprint_resource_type": "Cloud.vSphere.Machine",
        "zone_overlapping_migrated": "True",
        "__vmw:provisioning:project": "087a503a-0da8-4254-9714-15094422021c",
        "__blueprint_request_event_id": "49d5b727-d0ef-41ef-b3fc-e9a1875dd9a3",
        "__groupResourcePlacementLink": "/provisioning/resources/group-placements/087a503a-0da8-4254-9714-15094422021c-d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
        "__vmw:provisioning:blueprint": "0a7686a1-6a94-462a-9839-2930a6518e15",
        "__vmw:provisioning:cloudZone": "d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
        "__vmw:provisioning:requester": "provisioning-hamskor2of8iplc9@provisioning-client.local",
        "__vmw:provisioning:deployment": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "__vmw:provisioning:imageMapping": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
        "__allowTerraformCloudzoneMapping": "True",
        "__blueprint_resource_dependencies": "[\"infra_net\"]",
        "__blueprint_resource_last_operation": "create",
        "__vmw:provisioning:blueprintResourceName": "crdb_vm",
        "__computeConfigContentPhoneHomeShouldWait": "False",
        "__blueprint_resource_dependent_resource_ids": "[\"febd9291-1373-4a35-9af4-19264611a64d\"]",
        "__blueprint_resource_dependency_resource_ids": "[\"ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1\"]",
        "__blueprint_resource_allocation_dependent_ids": "[]",
        "__ext:RequestBrokerState:STARTED:RESOURCE_COUNTED": "True",
        "__ext:ComputeReservationTaskState:STARTED:SELECTED": "True",
        "__computeConfigContentDeploymentFailOnCloudConfigRuntimeError": "True",
        "__ext:ComputeAllocationTaskState:STARTED:START_COMPUTE_ALLOCATION": "True"
      }
    ],
    [
      {
        "id": "/resources/compute/b9b314ee-43c0-4c00-a946-1b340b6c27d3",
        "name": "redis_vm",
        "tags": [
          {
            "key": "colour",
            "value": "blue"
          }
        ],
        "zone": "wdc-w01-cl01",
        "count": "2",
        "image": "test-image",
        "moref": "VirtualMachine:vm-513",
        "osType": "LINUX",
        "region": "wdc-w01-DC",
        "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
        "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
        "__moref": "VirtualMachine:vm-513",
        "account": "wdc-w01-vc01.vcf01.isvlab.vmware.com",
        "address": "172.16.63.152",
        "project": "087a503a-0da8-4254-9714-15094422021c",
        "storage": {
          "disks": [
            {
              "name": "Floppy drive 1",
              "type": "FLOPPY",
              "encrypted": False,
              "capacityGb": 0,
              "persistent": False,
              "resourceLink": "/resources/disks/3164de67-cc45-4870-acb0-82e4a4601656",
              "controllerKey": "400",
              "existingResource": "False",
              "controllerUnitNumber": "0"
            },
            {
              "vm": "VirtualMachine:vm-513",
              "name": "redis_vm-mcm3338-259990701119-boot-disk",
              "type": "HDD",
              "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
              "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-e2ad-40b0-5419-0c42a12a8538/redis_vm-mcm3338-259990701119_2.vmdk",
              "bootOrder": 1,
              "encrypted": False,
              "capacityGb": 60,
              "persistent": False,
              "independent": "False",
              "endpointType": "vsphere",
              "resourceLink": "/resources/disks/d1253771-7c36-4b10-90a0-63b48b7ad9ea",
              "controllerKey": "1000",
              "diskPlacementRef": "Datastore:datastore-18",
              "existingResource": "False",
              "provisioningType": "thin",
              "controllerUnitNumber": "0"
            },
            {
              "vm": "VirtualMachine:vm-513",
              "name": "Hard disk 2",
              "type": "HDD",
              "shares": "1000",
              "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-e2ad-40b0-5419-0c42a12a8538/redis_vm-mcm3338-259990701119_4.vmdk",
              "encrypted": False,
              "limitIops": "-1",
              "capacityGb": 800,
              "persistent": False,
              "independent": "False",
              "sharesLevel": "normal",
              "endpointType": "vsphere",
              "resourceLink": "/resources/disks/1f1d2c07-5815-42c1-b8b2-cfe6626b0847",
              "controllerKey": "1001",
              "existingResource": "False",
              "provisioningType": "thin",
              "controllerUnitNumber": "0"
            },
            {
              "name": "CD/DVD drive 1",
              "type": "CDROM",
              "encrypted": False,
              "capacityGb": 0,
              "persistent": False,
              "resourceLink": "/resources/disks/69876876-90b3-4409-ac60-2ead4a733397",
              "controllerKey": "200",
              "existingResource": "False",
              "controllerUnitNumber": "0"
            }
          ]
        },
        "accounts": [
          "wdc-w01-vc01.vcf01.isvlab.vmware.com"
        ],
        "cpuCount": 4,
        "networks": [
          {
            "id": "/resources/network-interfaces/e08de91e-2ee7-4540-a641-bcfe8aaaf21a",
            "dns": [
              "172.16.16.16",
              "172.16.16.17"
            ],
            "name": "ls-wcp-management-172_16_63_128__27-dhcp",
            "domain": "vcf01.isvlab.vmware.com",
            "address": "172.16.63.152",
            "gateway": "172.16.63.129",
            "netmask": "255.255.255.224",
            "network": "/provisioning/resources/compute-networks/ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1",
            "gateways": "172.16.63.129",
            "assignment": "static",
            "deviceIndex": 0,
            "external_id": "39a59c37-afb3-473e-af44-fbd6420dccfa",
            "mac_address": "00:50:56:84:4e:f9",
            "resourceName": "ls-wcp-management-172_16_63_128__27-dhcp",
            "ipv6Addresses": [
              "fe80::250:56ff:fe84:4ef9"
            ],
            "dnsSearchDomains": [
              "vcf01.isvlab.vmware.com"
            ],
            "assignPublicIpAddress": True
          }
        ],
        "username": "crdb",
        "coreCount": "1",
        "enableSSH": "True",
        "__imageRef": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
        "countIndex": "0",
        "endpointId": "b5c736bd-4aaa-4630-8778-21c0a56d89f0",
        "externalId": "5004c77b-9143-a36f-db29-fc7b7cc7c420",
        "isSimulate": "False",
        "powerState": "ON",
        "primaryMAC": "00:50:56:84:4e:f9",
        "providerId": "5004c77b-9143-a36f-db29-fc7b7cc7c420",
        "resourceId": "b9b314ee-43c0-4c00-a946-1b340b6c27d3",
        "cloudConfig": "#cloud-config\nssh_authorized_keys:\n- ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\npackage_update: True\npackage_upgrade: True\npackage_reboot_if_required: True\nusers:\n- name: crdb\n  shell: /bin/bash\n  sudo:\n  - ALL=(ALL) NOPASSWD:ALL\n- default\n- name: crdb\n  ssh_authorized_keys:\n  - ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\nssh_pwauth: True\nruncmd:\n- hostnamectl set-hostname --pretty 'redis_vm-mcm3338-259990701119'\n- sudo service sshd restart\npackages:\n- chrony\n",
        "__dcSelfLink": "/resources/groups/3f14e002-ef03-4662-9104-65b89ea1aee9",
        "endpointType": "vsphere",
        "instanceUUID": "5004c77b-9143-a36f-db29-fc7b7cc7c420",
        "remoteAccess": {
          "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
          "username": "crdb",
          "authentication": "publicPrivateKey"
        },
        "resourceLink": "/resources/compute/b9b314ee-43c0-4c00-a946-1b340b6c27d3",
        "resourceName": "redis_vm-mcm3338-259990701119",
        "resourcePool": "/resources/pools/4004ae581f4d5075-7f703c5265a63d87",
        "softwareName": "Ubuntu Linux (64-bit)",
        "vmFolderPath": "[wdc-w01-wdc-w01-vsan01] 40e60466-e2ad-40b0-5419-0c42a12a8538",
        "__computeHost": "True",
        "__computeType": "VirtualMachine",
        "componentType": "Cloud.vSphere.Machine",
        "datastoreName": "wdc-w01-wdc-w01-vsan01",
        "totalMemoryMB": 16384,
        "__blueprint_id": "0a7686a1-6a94-462a-9839-2930a6518e15",
        "__endpointLink": "/resources/endpoints/b5c736bd-4aaa-4630-8778-21c0a56d89f0",
        "__endpointType": "vsphere",
        "cloneFromImage": "ubuntuTemplate-HWE",
        "computeHostRef": "ClusterComputeResource:domain-c8",
        "__deployment_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "__imageOsFamily": "LINUX",
        "__placementLink": "/resources/compute/b8d8c4dd-52d8-40a2-a008-1cb940b75fcb",
        "computeHostType": "ClusterComputeResource",
        "__bootDiskSizeMB": "61440",
        "__deploymentLink": "/resources/deployments/50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "customizeGuestOs": "True",
        "resourceDescLink": "/resources/compute-descriptions/154294ba-a164-46f2-b27e-21b360617523",
        "__computeHostLink": "/resources/compute/7a542d97-fa06-4494-999b-b879cfacdffa",
        "resourceGroupName": "",
        "__cpuHotAddEnabled": "False",
        "__imageMappingLink": "/provisioning/resources/image-profiles-v2/032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
        "__operationTimeout": "7200",
        "__storageReference": "Datastore:datastore-18",
        "neglectPowerOffVms": "False",
        "__component_type_id": "Compute.vSphere",
        "__isStorageReserved": "True",
        "__resolvedImageLink": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
        "__allocation_request": "True",
        "__memoryHotAddEnabled": "False",
        "__blueprint_request_id": "94686cd5-24b2-4111-a45f-562d44de00ca",
        "__vmw:provisioning:org": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d",
        "_clusterAllocationSize": "2",
        "__blueprint_resource_id": "b9b314ee-43c0-4c00-a946-1b340b6c27d3",
        "__imageBootDiskSizeInMB": "61440",
        "__imageDisksTotalSizeMB": "880640",
        "__composition_context_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "__projectPlacementPolicy": "DEFAULT",
        "__blueprint_resource_name": "redis_vm[0]",
        "__blueprint_resource_type": "Cloud.vSphere.Machine",
        "zone_overlapping_migrated": "True",
        "__vmw:provisioning:project": "087a503a-0da8-4254-9714-15094422021c",
        "__blueprint_request_event_id": "4649e92e-e748-4d0d-9f05-9fc61a1bac10",
        "__groupResourcePlacementLink": "/provisioning/resources/group-placements/087a503a-0da8-4254-9714-15094422021c-d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
        "__vmw:provisioning:blueprint": "0a7686a1-6a94-462a-9839-2930a6518e15",
        "__vmw:provisioning:cloudZone": "d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
        "__vmw:provisioning:requester": "provisioning-hamskor2of8iplc9@provisioning-client.local",
        "__vmw:provisioning:deployment": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "__vmw:provisioning:imageMapping": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
        "__allowTerraformCloudzoneMapping": "True",
        "__blueprint_resource_dependencies": "[\"infra_net\"]",
        "__blueprint_resource_last_operation": "create",
        "__vmw:provisioning:blueprintResourceName": "redis_vm",
        "__computeConfigContentPhoneHomeShouldWait": "False",
        "__blueprint_resource_dependent_resource_ids": "[\"febd9291-1373-4a35-9af4-19264611a64d\"]",
        "__blueprint_resource_dependency_resource_ids": "[\"ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1\"]",
        "__blueprint_resource_allocation_dependent_ids": "[]",
        "__ext:RequestBrokerState:STARTED:RESOURCE_COUNTED": "True",
        "__ext:ComputeReservationTaskState:STARTED:SELECTED": "True",
        "__computeConfigContentDeploymentFailOnCloudConfigRuntimeError": "True",
        "__ext:ComputeAllocationTaskState:STARTED:START_COMPUTE_ALLOCATION": "True"
      },
      {
        "id": "/resources/compute/97f9095d-2add-4fba-b3e0-dade5242c9e2",
        "name": "redis_vm",
        "tags": [
          {
            "key": "colour",
            "value": "blue"
          }
        ],
        "zone": "wdc-w01-cl01",
        "count": "2",
        "image": "test-image",
        "moref": "VirtualMachine:vm-510",
        "osType": "LINUX",
        "region": "wdc-w01-DC",
        "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
        "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
        "__moref": "VirtualMachine:vm-510",
        "account": "wdc-w01-vc01.vcf01.isvlab.vmware.com",
        "address": "172.16.63.140",
        "project": "087a503a-0da8-4254-9714-15094422021c",
        "storage": {
          "disks": [
            {
              "vm": "VirtualMachine:vm-510",
              "name": "redis_vm-mcm3339-259990701119-boot-disk",
              "type": "HDD",
              "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
              "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-eee9-6f47-c2f1-0c42a12a8538/redis_vm-mcm3339-259990701119_2.vmdk",
              "bootOrder": 1,
              "encrypted": False,
              "capacityGb": 60,
              "persistent": False,
              "independent": "False",
              "endpointType": "vsphere",
              "resourceLink": "/resources/disks/3783a236-c09e-47ad-b54f-b4b258fd5815",
              "controllerKey": "1000",
              "diskPlacementRef": "Datastore:datastore-18",
              "existingResource": "False",
              "provisioningType": "thin",
              "controllerUnitNumber": "0"
            },
            {
              "vm": "VirtualMachine:vm-510",
              "name": "Hard disk 2",
              "type": "HDD",
              "shares": "1000",
              "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-eee9-6f47-c2f1-0c42a12a8538/redis_vm-mcm3339-259990701119_4.vmdk",
              "encrypted": False,
              "limitIops": "-1",
              "capacityGb": 800,
              "persistent": False,
              "independent": "False",
              "sharesLevel": "normal",
              "endpointType": "vsphere",
              "resourceLink": "/resources/disks/8abdc155-bf77-4688-ba23-a7039908a744",
              "controllerKey": "1001",
              "existingResource": "False",
              "provisioningType": "thin",
              "controllerUnitNumber": "0"
            },
            {
              "name": "Floppy drive 1",
              "type": "FLOPPY",
              "encrypted": False,
              "capacityGb": 0,
              "persistent": False,
              "resourceLink": "/resources/disks/9e0c6859-d2ec-4602-b92f-6639bbffb341",
              "controllerKey": "400",
              "existingResource": "False",
              "controllerUnitNumber": "0"
            },
            {
              "name": "CD/DVD drive 1",
              "type": "CDROM",
              "encrypted": False,
              "capacityGb": 0,
              "persistent": False,
              "resourceLink": "/resources/disks/78479985-6774-47fb-a751-f6c81e77a8b3",
              "controllerKey": "200",
              "existingResource": "False",
              "controllerUnitNumber": "0"
            }
          ]
        },
        "accounts": [
          "wdc-w01-vc01.vcf01.isvlab.vmware.com"
        ],
        "cpuCount": 4,
        "networks": [
          {
            "id": "/resources/network-interfaces/b57b15c7-2e48-49fb-be93-c330fe8ab6f8",
            "dns": [
              "172.16.16.16",
              "172.16.16.17"
            ],
            "name": "ls-wcp-management-172_16_63_128__27-dhcp",
            "domain": "vcf01.isvlab.vmware.com",
            "address": "172.16.63.140",
            "gateway": "172.16.63.129",
            "netmask": "255.255.255.224",
            "network": "/provisioning/resources/compute-networks/ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1",
            "gateways": "172.16.63.129",
            "assignment": "static",
            "deviceIndex": 0,
            "external_id": "2858f58a-97ff-4129-ba31-b5fdaef3505f",
            "mac_address": "00:50:56:84:31:c6",
            "resourceName": "ls-wcp-management-172_16_63_128__27-dhcp",
            "ipv6Addresses": [
              "fe80::250:56ff:fe84:31c6"
            ],
            "dnsSearchDomains": [
              "vcf01.isvlab.vmware.com"
            ],
            "assignPublicIpAddress": True
          }
        ],
        "username": "crdb",
        "coreCount": "1",
        "enableSSH": "True",
        "__imageRef": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
        "countIndex": "1",
        "endpointId": "b5c736bd-4aaa-4630-8778-21c0a56d89f0",
        "externalId": "50049aa7-a573-3ee2-5fed-08f429d7feef",
        "isSimulate": "False",
        "powerState": "ON",
        "primaryMAC": "00:50:56:84:31:c6",
        "providerId": "50049aa7-a573-3ee2-5fed-08f429d7feef",
        "resourceId": "97f9095d-2add-4fba-b3e0-dade5242c9e2",
        "cloudConfig": "#cloud-config\nssh_authorized_keys:\n- ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\npackage_update: True\npackage_upgrade: True\npackage_reboot_if_required: True\nusers:\n- name: crdb\n  shell: /bin/bash\n  sudo:\n  - ALL=(ALL) NOPASSWD:ALL\n- default\n- name: crdb\n  ssh_authorized_keys:\n  - ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\nssh_pwauth: True\nruncmd:\n- hostnamectl set-hostname --pretty 'redis_vm-mcm3339-259990701119'\n- sudo service sshd restart\npackages:\n- chrony\n",
        "__dcSelfLink": "/resources/groups/3f14e002-ef03-4662-9104-65b89ea1aee9",
        "endpointType": "vsphere",
        "instanceUUID": "50049aa7-a573-3ee2-5fed-08f429d7feef",
        "remoteAccess": {
          "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
          "username": "crdb",
          "authentication": "publicPrivateKey"
        },
        "resourceLink": "/resources/compute/97f9095d-2add-4fba-b3e0-dade5242c9e2",
        "resourceName": "redis_vm-mcm3339-259990701119",
        "resourcePool": "/resources/pools/4004ae581f4d5075-7f703c5265a63d87",
        "softwareName": "Ubuntu Linux (64-bit)",
        "vmFolderPath": "[wdc-w01-wdc-w01-vsan01] 40e60466-eee9-6f47-c2f1-0c42a12a8538",
        "__computeHost": "True",
        "__computeType": "VirtualMachine",
        "componentType": "Cloud.vSphere.Machine",
        "datastoreName": "wdc-w01-wdc-w01-vsan01",
        "totalMemoryMB": 16384,
        "__blueprint_id": "0a7686a1-6a94-462a-9839-2930a6518e15",
        "__endpointLink": "/resources/endpoints/b5c736bd-4aaa-4630-8778-21c0a56d89f0",
        "__endpointType": "vsphere",
        "cloneFromImage": "ubuntuTemplate-HWE",
        "computeHostRef": "ClusterComputeResource:domain-c8",
        "__deployment_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "__imageOsFamily": "LINUX",
        "__placementLink": "/resources/compute/b8d8c4dd-52d8-40a2-a008-1cb940b75fcb",
        "computeHostType": "ClusterComputeResource",
        "__bootDiskSizeMB": "61440",
        "__deploymentLink": "/resources/deployments/50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "customizeGuestOs": "True",
        "resourceDescLink": "/resources/compute-descriptions/154294ba-a164-46f2-b27e-21b360617523",
        "__computeHostLink": "/resources/compute/7489b91d-c75c-4215-a0ef-ed403e9b4984",
        "resourceGroupName": "",
        "__cpuHotAddEnabled": "False",
        "__imageMappingLink": "/provisioning/resources/image-profiles-v2/032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
        "__operationTimeout": "7200",
        "__storageReference": "Datastore:datastore-18",
        "neglectPowerOffVms": "False",
        "__component_type_id": "Compute.vSphere",
        "__isStorageReserved": "True",
        "__resolvedImageLink": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
        "__allocation_request": "True",
        "__memoryHotAddEnabled": "False",
        "__blueprint_request_id": "94686cd5-24b2-4111-a45f-562d44de00ca",
        "__vmw:provisioning:org": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d",
        "_clusterAllocationSize": "2",
        "__blueprint_resource_id": "97f9095d-2add-4fba-b3e0-dade5242c9e2",
        "__imageBootDiskSizeInMB": "61440",
        "__imageDisksTotalSizeMB": "880640",
        "__composition_context_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "__projectPlacementPolicy": "DEFAULT",
        "__blueprint_resource_name": "redis_vm[1]",
        "__blueprint_resource_type": "Cloud.vSphere.Machine",
        "zone_overlapping_migrated": "True",
        "__vmw:provisioning:project": "087a503a-0da8-4254-9714-15094422021c",
        "__blueprint_request_event_id": "4649e92e-e748-4d0d-9f05-9fc61a1bac10",
        "__groupResourcePlacementLink": "/provisioning/resources/group-placements/087a503a-0da8-4254-9714-15094422021c-d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
        "__vmw:provisioning:blueprint": "0a7686a1-6a94-462a-9839-2930a6518e15",
        "__vmw:provisioning:cloudZone": "d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
        "__vmw:provisioning:requester": "provisioning-hamskor2of8iplc9@provisioning-client.local",
        "__vmw:provisioning:deployment": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
        "__vmw:provisioning:imageMapping": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
        "__allowTerraformCloudzoneMapping": "True",
        "__blueprint_resource_dependencies": "[\"infra_net\"]",
        "__blueprint_resource_last_operation": "create",
        "__vmw:provisioning:blueprintResourceName": "redis_vm",
        "__computeConfigContentPhoneHomeShouldWait": "False",
        "__blueprint_resource_dependent_resource_ids": "[\"febd9291-1373-4a35-9af4-19264611a64d\"]",
        "__blueprint_resource_dependency_resource_ids": "[\"ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1\"]",
        "__blueprint_resource_allocation_dependent_ids": "[]",
        "__ext:RequestBrokerState:STARTED:RESOURCE_COUNTED": "True",
        "__ext:ComputeReservationTaskState:STARTED:SELECTED": "True",
        "__computeConfigContentDeploymentFailOnCloudConfigRuntimeError": "True",
        "__ext:ComputeAllocationTaskState:STARTED:START_COMPUTE_ALLOCATION": "True"
      }
    ]
  ],
  "groups": [
    "crdb",
    "rack1"
  ],
  "verbose": True,
  "base_url": "https://wdc-ansible.vcf01.isvlab.vmware.com/",
  "password": "((secret:v1:AAHmKxVhv12umnGk/DoA0d5ox94ZFoh8BE/fSYPKK3yVtqYHva+vEmUfFo8=))",
  "username": "admin",
  "__metadata": {
    "headers": {
      "tokenId": "YqLj3IXm35P7VegxSxRhRr9gwZlJv8WNBhs4Dev5sUw=",
      "encryption-context": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8"
    },
    "project": "087a503a-0da8-4254-9714-15094422021c",
    "operation": "create",
    "resourceType": "Custom.my_custom_resource"
  },
  "ssl_verify": False,
  "host_groups": {
    "crdb": [
      [
        {
          "id": "/resources/compute/30a231b4-a1cf-4639-a6a1-c5fd71231763",
          "name": "crdb_vm",
          "tags": [
            {
              "key": "colour",
              "value": "blue"
            }
          ],
          "zone": "wdc-w01-cl01",
          "count": "2",
          "image": "test-image",
          "moref": "VirtualMachine:vm-511",
          "osType": "LINUX",
          "region": "wdc-w01-DC",
          "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
          "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
          "__moref": "VirtualMachine:vm-511",
          "account": "wdc-w01-vc01.vcf01.isvlab.vmware.com",
          "address": "172.16.63.132",
          "project": "087a503a-0da8-4254-9714-15094422021c",
          "storage": {
            "disks": [
              {
                "name": "CD/DVD drive 1",
                "type": "CDROM",
                "encrypted": False,
                "capacityGb": 0,
                "persistent": False,
                "resourceLink": "/resources/disks/220721b9-8401-42f8-9468-f3e9d2c2bf18",
                "controllerKey": "200",
                "existingResource": "False",
                "controllerUnitNumber": "0"
              },
              {
                "vm": "VirtualMachine:vm-511",
                "name": "crdb_vm-mcm3050-259990695356-boot-disk",
                "type": "HDD",
                "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-d4db-6e47-4405-0c42a12a8538/crdb_vm-mcm3050-259990695356_2.vmdk",
                "bootOrder": 1,
                "encrypted": False,
                "capacityGb": 60,
                "persistent": False,
                "independent": "False",
                "endpointType": "vsphere",
                "resourceLink": "/resources/disks/72bc7876-4d90-463c-a54a-6e1c11686f0e",
                "controllerKey": "1000",
                "diskPlacementRef": "Datastore:datastore-18",
                "existingResource": "False",
                "provisioningType": "thin",
                "controllerUnitNumber": "0"
              },
              {
                "name": "Floppy drive 1",
                "type": "FLOPPY",
                "encrypted": False,
                "capacityGb": 0,
                "persistent": False,
                "resourceLink": "/resources/disks/dc166778-1a6c-4f5d-90c2-dfddf03e1fb9",
                "controllerKey": "400",
                "existingResource": "False",
                "controllerUnitNumber": "0"
              },
              {
                "vm": "VirtualMachine:vm-511",
                "name": "Hard disk 2",
                "type": "HDD",
                "shares": "1000",
                "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-d4db-6e47-4405-0c42a12a8538/crdb_vm-mcm3050-259990695356_4.vmdk",
                "encrypted": False,
                "limitIops": "-1",
                "capacityGb": 800,
                "persistent": False,
                "independent": "False",
                "sharesLevel": "normal",
                "endpointType": "vsphere",
                "resourceLink": "/resources/disks/eb930716-ad54-45a7-97cb-2b1b40584cce",
                "controllerKey": "1001",
                "existingResource": "False",
                "provisioningType": "thin",
                "controllerUnitNumber": "0"
              }
            ]
          },
          "accounts": [
            "wdc-w01-vc01.vcf01.isvlab.vmware.com"
          ],
          "cpuCount": 4,
          "networks": [
            {
              "id": "/resources/network-interfaces/f64a7d33-8969-43f9-836e-cdcc5780ae39",
              "dns": [
                "172.16.16.16",
                "172.16.16.17"
              ],
              "name": "ls-wcp-management-172_16_63_128__27-dhcp",
              "domain": "vcf01.isvlab.vmware.com",
              "address": "172.16.63.132",
              "gateway": "172.16.63.129",
              "netmask": "255.255.255.224",
              "network": "/provisioning/resources/compute-networks/ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1",
              "gateways": "172.16.63.129",
              "assignment": "static",
              "deviceIndex": 0,
              "external_id": "7ee2bbee-e2fd-47cc-9d5f-9aba919eabf6",
              "mac_address": "00:50:56:84:06:bb",
              "resourceName": "ls-wcp-management-172_16_63_128__27-dhcp",
              "ipv6Addresses": [
                "fe80::250:56ff:fe84:6bb"
              ],
              "dnsSearchDomains": [
                "vcf01.isvlab.vmware.com"
              ],
              "assignPublicIpAddress": True
            }
          ],
          "username": "crdb",
          "coreCount": "1",
          "enableSSH": "True",
          "__imageRef": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
          "countIndex": "0",
          "endpointId": "b5c736bd-4aaa-4630-8778-21c0a56d89f0",
          "externalId": "500491a5-8cc0-8843-fae6-8957920f7a52",
          "isSimulate": "False",
          "powerState": "ON",
          "primaryMAC": "00:50:56:84:06:bb",
          "providerId": "500491a5-8cc0-8843-fae6-8957920f7a52",
          "resourceId": "30a231b4-a1cf-4639-a6a1-c5fd71231763",
          "cloudConfig": "#cloud-config\nssh_authorized_keys:\n- ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\npackage_update: True\npackage_upgrade: True\npackage_reboot_if_required: True\nusers:\n- name: crdb\n  shell: /bin/bash\n  sudo:\n  - ALL=(ALL) NOPASSWD:ALL\n- default\n- name: crdb\n  ssh_authorized_keys:\n  - ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\nssh_pwauth: True\nruncmd:\n- hostnamectl set-hostname --pretty crdb_vm-mcm3050-259990695356\n- sudo service sshd restart\npackages:\n- chrony\n",
          "__dcSelfLink": "/resources/groups/3f14e002-ef03-4662-9104-65b89ea1aee9",
          "endpointType": "vsphere",
          "instanceUUID": "500491a5-8cc0-8843-fae6-8957920f7a52",
          "remoteAccess": {
            "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
            "username": "crdb",
            "authentication": "publicPrivateKey"
          },
          "resourceLink": "/resources/compute/30a231b4-a1cf-4639-a6a1-c5fd71231763",
          "resourceName": "crdb_vm-mcm3050-259990695356",
          "resourcePool": "/resources/pools/4004ae581f4d5075-7f703c5265a63d87",
          "softwareName": "Ubuntu Linux (64-bit)",
          "vmFolderPath": "[wdc-w01-wdc-w01-vsan01] 40e60466-d4db-6e47-4405-0c42a12a8538",
          "__computeHost": "True",
          "__computeType": "VirtualMachine",
          "componentType": "Cloud.vSphere.Machine",
          "datastoreName": "wdc-w01-wdc-w01-vsan01",
          "totalMemoryMB": 16384,
          "__blueprint_id": "0a7686a1-6a94-462a-9839-2930a6518e15",
          "__endpointLink": "/resources/endpoints/b5c736bd-4aaa-4630-8778-21c0a56d89f0",
          "__endpointType": "vsphere",
          "cloneFromImage": "ubuntuTemplate-HWE",
          "computeHostRef": "ClusterComputeResource:domain-c8",
          "__deployment_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "__imageOsFamily": "LINUX",
          "__placementLink": "/resources/compute/b8d8c4dd-52d8-40a2-a008-1cb940b75fcb",
          "computeHostType": "ClusterComputeResource",
          "__bootDiskSizeMB": "61440",
          "__deploymentLink": "/resources/deployments/50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "customizeGuestOs": "True",
          "resourceDescLink": "/resources/compute-descriptions/0b4602e0-9cd0-4c32-aea6-44857a3d98c8",
          "__computeHostLink": "/resources/compute/b2bc2a04-56de-4492-8904-cd537a4e828c",
          "resourceGroupName": "",
          "__cpuHotAddEnabled": "False",
          "__imageMappingLink": "/provisioning/resources/image-profiles-v2/032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
          "__operationTimeout": "7200",
          "__storageReference": "Datastore:datastore-18",
          "neglectPowerOffVms": "False",
          "__component_type_id": "Compute.vSphere",
          "__isStorageReserved": "True",
          "__resolvedImageLink": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
          "__allocation_request": "True",
          "__memoryHotAddEnabled": "False",
          "__blueprint_request_id": "94686cd5-24b2-4111-a45f-562d44de00ca",
          "__vmw:provisioning:org": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d",
          "_clusterAllocationSize": "2",
          "__blueprint_resource_id": "30a231b4-a1cf-4639-a6a1-c5fd71231763",
          "__imageBootDiskSizeInMB": "61440",
          "__imageDisksTotalSizeMB": "880640",
          "__composition_context_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "__projectPlacementPolicy": "DEFAULT",
          "__blueprint_resource_name": "crdb_vm[0]",
          "__blueprint_resource_type": "Cloud.vSphere.Machine",
          "zone_overlapping_migrated": "True",
          "__vmw:provisioning:project": "087a503a-0da8-4254-9714-15094422021c",
          "__blueprint_request_event_id": "49d5b727-d0ef-41ef-b3fc-e9a1875dd9a3",
          "__groupResourcePlacementLink": "/provisioning/resources/group-placements/087a503a-0da8-4254-9714-15094422021c-d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
          "__vmw:provisioning:blueprint": "0a7686a1-6a94-462a-9839-2930a6518e15",
          "__vmw:provisioning:cloudZone": "d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
          "__vmw:provisioning:requester": "provisioning-hamskor2of8iplc9@provisioning-client.local",
          "__vmw:provisioning:deployment": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "__vmw:provisioning:imageMapping": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
          "__allowTerraformCloudzoneMapping": "True",
          "__blueprint_resource_dependencies": "[\"infra_net\"]",
          "__blueprint_resource_last_operation": "create",
          "__vmw:provisioning:blueprintResourceName": "crdb_vm",
          "__computeConfigContentPhoneHomeShouldWait": "False",
          "__blueprint_resource_dependent_resource_ids": "[\"febd9291-1373-4a35-9af4-19264611a64d\"]",
          "__blueprint_resource_dependency_resource_ids": "[\"ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1\"]",
          "__blueprint_resource_allocation_dependent_ids": "[]",
          "__ext:RequestBrokerState:STARTED:RESOURCE_COUNTED": "True",
          "__ext:ComputeReservationTaskState:STARTED:SELECTED": "True",
          "__computeConfigContentDeploymentFailOnCloudConfigRuntimeError": "True",
          "__ext:ComputeAllocationTaskState:STARTED:START_COMPUTE_ALLOCATION": "True"
        },
        {
          "id": "/resources/compute/71008850-0ffc-4940-8ad8-c0ea5c58e2de",
          "name": "crdb_vm",
          "tags": [
            {
              "key": "colour",
              "value": "blue"
            }
          ],
          "zone": "wdc-w01-cl01",
          "count": "2",
          "image": "test-image",
          "moref": "VirtualMachine:vm-512",
          "osType": "LINUX",
          "region": "wdc-w01-DC",
          "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
          "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
          "__moref": "VirtualMachine:vm-512",
          "account": "wdc-w01-vc01.vcf01.isvlab.vmware.com",
          "address": "172.16.63.141",
          "project": "087a503a-0da8-4254-9714-15094422021c",
          "storage": {
            "disks": [
              {
                "vm": "VirtualMachine:vm-512",
                "name": "Hard disk 2",
                "type": "HDD",
                "shares": "1000",
                "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-b6e8-bcda-b152-0c42a12a8530/crdb_vm-mcm3051-259990695356_4.vmdk",
                "encrypted": False,
                "limitIops": "-1",
                "capacityGb": 800,
                "persistent": False,
                "independent": "False",
                "sharesLevel": "normal",
                "endpointType": "vsphere",
                "resourceLink": "/resources/disks/242fe21a-a378-464b-a9ac-5b5582305049",
                "controllerKey": "1001",
                "existingResource": "False",
                "provisioningType": "thin",
                "controllerUnitNumber": "0"
              },
              {
                "vm": "VirtualMachine:vm-512",
                "name": "crdb_vm-mcm3051-259990695356-boot-disk",
                "type": "HDD",
                "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-b6e8-bcda-b152-0c42a12a8530/crdb_vm-mcm3051-259990695356_2.vmdk",
                "bootOrder": 1,
                "encrypted": False,
                "capacityGb": 60,
                "persistent": False,
                "independent": "False",
                "endpointType": "vsphere",
                "resourceLink": "/resources/disks/ed4d951c-9b30-4ebf-8f4f-0b22112508bf",
                "controllerKey": "1000",
                "diskPlacementRef": "Datastore:datastore-18",
                "existingResource": "False",
                "provisioningType": "thin",
                "controllerUnitNumber": "0"
              },
              {
                "name": "Floppy drive 1",
                "type": "FLOPPY",
                "encrypted": False,
                "capacityGb": 0,
                "persistent": False,
                "resourceLink": "/resources/disks/fd5e3b62-a2a2-4ba4-afdd-be76dd7921e4",
                "controllerKey": "400",
                "existingResource": "False",
                "controllerUnitNumber": "0"
              },
              {
                "name": "CD/DVD drive 1",
                "type": "CDROM",
                "encrypted": False,
                "capacityGb": 0,
                "persistent": False,
                "resourceLink": "/resources/disks/3c411098-2bbe-43b9-977d-b0551e4e0b6f",
                "controllerKey": "200",
                "existingResource": "False",
                "controllerUnitNumber": "0"
              }
            ]
          },
          "accounts": [
            "wdc-w01-vc01.vcf01.isvlab.vmware.com"
          ],
          "cpuCount": 4,
          "networks": [
            {
              "id": "/resources/network-interfaces/7382be23-86a9-4715-90b9-10e42f0a4b96",
              "dns": [
                "172.16.16.16",
                "172.16.16.17"
              ],
              "name": "ls-wcp-management-172_16_63_128__27-dhcp",
              "domain": "vcf01.isvlab.vmware.com",
              "address": "172.16.63.141",
              "gateway": "172.16.63.129",
              "netmask": "255.255.255.224",
              "network": "/provisioning/resources/compute-networks/ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1",
              "gateways": "172.16.63.129",
              "assignment": "static",
              "deviceIndex": 0,
              "external_id": "762b87b7-f00a-46cd-8d91-fcdb9d8b2fda",
              "mac_address": "00:50:56:84:fb:ac",
              "resourceName": "ls-wcp-management-172_16_63_128__27-dhcp",
              "ipv6Addresses": [
                "fe80::250:56ff:fe84:fbac"
              ],
              "dnsSearchDomains": [
                "vcf01.isvlab.vmware.com"
              ],
              "assignPublicIpAddress": True
            }
          ],
          "username": "crdb",
          "coreCount": "1",
          "enableSSH": "True",
          "__imageRef": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
          "countIndex": "1",
          "endpointId": "b5c736bd-4aaa-4630-8778-21c0a56d89f0",
          "externalId": "50043de2-66ee-a822-59e7-f430a57fa41f",
          "isSimulate": "False",
          "powerState": "ON",
          "primaryMAC": "00:50:56:84:fb:ac",
          "providerId": "50043de2-66ee-a822-59e7-f430a57fa41f",
          "resourceId": "71008850-0ffc-4940-8ad8-c0ea5c58e2de",
          "cloudConfig": "#cloud-config\nssh_authorized_keys:\n- ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\npackage_update: True\npackage_upgrade: True\npackage_reboot_if_required: True\nusers:\n- name: crdb\n  shell: /bin/bash\n  sudo:\n  - ALL=(ALL) NOPASSWD:ALL\n- default\n- name: crdb\n  ssh_authorized_keys:\n  - ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\nssh_pwauth: True\nruncmd:\n- hostnamectl set-hostname --pretty crdb_vm-mcm3051-259990695356\n- sudo service sshd restart\npackages:\n- chrony\n",
          "__dcSelfLink": "/resources/groups/3f14e002-ef03-4662-9104-65b89ea1aee9",
          "endpointType": "vsphere",
          "instanceUUID": "50043de2-66ee-a822-59e7-f430a57fa41f",
          "remoteAccess": {
            "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
            "username": "crdb",
            "authentication": "publicPrivateKey"
          },
          "resourceLink": "/resources/compute/71008850-0ffc-4940-8ad8-c0ea5c58e2de",
          "resourceName": "crdb_vm-mcm3051-259990695356",
          "resourcePool": "/resources/pools/4004ae581f4d5075-7f703c5265a63d87",
          "softwareName": "Ubuntu Linux (64-bit)",
          "vmFolderPath": "[wdc-w01-wdc-w01-vsan01] 40e60466-b6e8-bcda-b152-0c42a12a8530",
          "__computeHost": "True",
          "__computeType": "VirtualMachine",
          "componentType": "Cloud.vSphere.Machine",
          "datastoreName": "wdc-w01-wdc-w01-vsan01",
          "totalMemoryMB": 16384,
          "__blueprint_id": "0a7686a1-6a94-462a-9839-2930a6518e15",
          "__endpointLink": "/resources/endpoints/b5c736bd-4aaa-4630-8778-21c0a56d89f0",
          "__endpointType": "vsphere",
          "cloneFromImage": "ubuntuTemplate-HWE",
          "computeHostRef": "ClusterComputeResource:domain-c8",
          "__deployment_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "__imageOsFamily": "LINUX",
          "__placementLink": "/resources/compute/b8d8c4dd-52d8-40a2-a008-1cb940b75fcb",
          "computeHostType": "ClusterComputeResource",
          "__bootDiskSizeMB": "61440",
          "__deploymentLink": "/resources/deployments/50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "customizeGuestOs": "True",
          "resourceDescLink": "/resources/compute-descriptions/0b4602e0-9cd0-4c32-aea6-44857a3d98c8",
          "__computeHostLink": "/resources/compute/80fd003d-52e7-442c-a981-7dcef649fff0",
          "resourceGroupName": "",
          "__cpuHotAddEnabled": "False",
          "__imageMappingLink": "/provisioning/resources/image-profiles-v2/032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
          "__operationTimeout": "7200",
          "__storageReference": "Datastore:datastore-18",
          "neglectPowerOffVms": "False",
          "__component_type_id": "Compute.vSphere",
          "__isStorageReserved": "True",
          "__resolvedImageLink": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
          "__allocation_request": "True",
          "__memoryHotAddEnabled": "False",
          "__blueprint_request_id": "94686cd5-24b2-4111-a45f-562d44de00ca",
          "__vmw:provisioning:org": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d",
          "_clusterAllocationSize": "2",
          "__blueprint_resource_id": "71008850-0ffc-4940-8ad8-c0ea5c58e2de",
          "__imageBootDiskSizeInMB": "61440",
          "__imageDisksTotalSizeMB": "880640",
          "__composition_context_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "__projectPlacementPolicy": "DEFAULT",
          "__blueprint_resource_name": "crdb_vm[1]",
          "__blueprint_resource_type": "Cloud.vSphere.Machine",
          "zone_overlapping_migrated": "True",
          "__vmw:provisioning:project": "087a503a-0da8-4254-9714-15094422021c",
          "__blueprint_request_event_id": "49d5b727-d0ef-41ef-b3fc-e9a1875dd9a3",
          "__groupResourcePlacementLink": "/provisioning/resources/group-placements/087a503a-0da8-4254-9714-15094422021c-d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
          "__vmw:provisioning:blueprint": "0a7686a1-6a94-462a-9839-2930a6518e15",
          "__vmw:provisioning:cloudZone": "d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
          "__vmw:provisioning:requester": "provisioning-hamskor2of8iplc9@provisioning-client.local",
          "__vmw:provisioning:deployment": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "__vmw:provisioning:imageMapping": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
          "__allowTerraformCloudzoneMapping": "True",
          "__blueprint_resource_dependencies": "[\"infra_net\"]",
          "__blueprint_resource_last_operation": "create",
          "__vmw:provisioning:blueprintResourceName": "crdb_vm",
          "__computeConfigContentPhoneHomeShouldWait": "False",
          "__blueprint_resource_dependent_resource_ids": "[\"febd9291-1373-4a35-9af4-19264611a64d\"]",
          "__blueprint_resource_dependency_resource_ids": "[\"ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1\"]",
          "__blueprint_resource_allocation_dependent_ids": "[]",
          "__ext:RequestBrokerState:STARTED:RESOURCE_COUNTED": "True",
          "__ext:ComputeReservationTaskState:STARTED:SELECTED": "True",
          "__computeConfigContentDeploymentFailOnCloudConfigRuntimeError": "True",
          "__ext:ComputeAllocationTaskState:STARTED:START_COMPUTE_ALLOCATION": "True"
        }
      ]
    ],
    "redis": [
      [
        {
          "id": "/resources/compute/b9b314ee-43c0-4c00-a946-1b340b6c27d3",
          "name": "redis_vm",
          "tags": [
            {
              "key": "colour",
              "value": "blue"
            }
          ],
          "zone": "wdc-w01-cl01",
          "count": "2",
          "image": "test-image",
          "moref": "VirtualMachine:vm-513",
          "osType": "LINUX",
          "region": "wdc-w01-DC",
          "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
          "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
          "__moref": "VirtualMachine:vm-513",
          "account": "wdc-w01-vc01.vcf01.isvlab.vmware.com",
          "address": "172.16.63.152",
          "project": "087a503a-0da8-4254-9714-15094422021c",
          "storage": {
            "disks": [
              {
                "name": "Floppy drive 1",
                "type": "FLOPPY",
                "encrypted": False,
                "capacityGb": 0,
                "persistent": False,
                "resourceLink": "/resources/disks/3164de67-cc45-4870-acb0-82e4a4601656",
                "controllerKey": "400",
                "existingResource": "False",
                "controllerUnitNumber": "0"
              },
              {
                "vm": "VirtualMachine:vm-513",
                "name": "redis_vm-mcm3338-259990701119-boot-disk",
                "type": "HDD",
                "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-e2ad-40b0-5419-0c42a12a8538/redis_vm-mcm3338-259990701119_2.vmdk",
                "bootOrder": 1,
                "encrypted": False,
                "capacityGb": 60,
                "persistent": False,
                "independent": "False",
                "endpointType": "vsphere",
                "resourceLink": "/resources/disks/d1253771-7c36-4b10-90a0-63b48b7ad9ea",
                "controllerKey": "1000",
                "diskPlacementRef": "Datastore:datastore-18",
                "existingResource": "False",
                "provisioningType": "thin",
                "controllerUnitNumber": "0"
              },
              {
                "vm": "VirtualMachine:vm-513",
                "name": "Hard disk 2",
                "type": "HDD",
                "shares": "1000",
                "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-e2ad-40b0-5419-0c42a12a8538/redis_vm-mcm3338-259990701119_4.vmdk",
                "encrypted": False,
                "limitIops": "-1",
                "capacityGb": 800,
                "persistent": False,
                "independent": "False",
                "sharesLevel": "normal",
                "endpointType": "vsphere",
                "resourceLink": "/resources/disks/1f1d2c07-5815-42c1-b8b2-cfe6626b0847",
                "controllerKey": "1001",
                "existingResource": "False",
                "provisioningType": "thin",
                "controllerUnitNumber": "0"
              },
              {
                "name": "CD/DVD drive 1",
                "type": "CDROM",
                "encrypted": False,
                "capacityGb": 0,
                "persistent": False,
                "resourceLink": "/resources/disks/69876876-90b3-4409-ac60-2ead4a733397",
                "controllerKey": "200",
                "existingResource": "False",
                "controllerUnitNumber": "0"
              }
            ]
          },
          "accounts": [
            "wdc-w01-vc01.vcf01.isvlab.vmware.com"
          ],
          "cpuCount": 4,
          "networks": [
            {
              "id": "/resources/network-interfaces/e08de91e-2ee7-4540-a641-bcfe8aaaf21a",
              "dns": [
                "172.16.16.16",
                "172.16.16.17"
              ],
              "name": "ls-wcp-management-172_16_63_128__27-dhcp",
              "domain": "vcf01.isvlab.vmware.com",
              "address": "172.16.63.152",
              "gateway": "172.16.63.129",
              "netmask": "255.255.255.224",
              "network": "/provisioning/resources/compute-networks/ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1",
              "gateways": "172.16.63.129",
              "assignment": "static",
              "deviceIndex": 0,
              "external_id": "39a59c37-afb3-473e-af44-fbd6420dccfa",
              "mac_address": "00:50:56:84:4e:f9",
              "resourceName": "ls-wcp-management-172_16_63_128__27-dhcp",
              "ipv6Addresses": [
                "fe80::250:56ff:fe84:4ef9"
              ],
              "dnsSearchDomains": [
                "vcf01.isvlab.vmware.com"
              ],
              "assignPublicIpAddress": True
            }
          ],
          "username": "crdb",
          "coreCount": "1",
          "enableSSH": "True",
          "__imageRef": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
          "countIndex": "0",
          "endpointId": "b5c736bd-4aaa-4630-8778-21c0a56d89f0",
          "externalId": "5004c77b-9143-a36f-db29-fc7b7cc7c420",
          "isSimulate": "False",
          "powerState": "ON",
          "primaryMAC": "00:50:56:84:4e:f9",
          "providerId": "5004c77b-9143-a36f-db29-fc7b7cc7c420",
          "resourceId": "b9b314ee-43c0-4c00-a946-1b340b6c27d3",
          "cloudConfig": "#cloud-config\nssh_authorized_keys:\n- ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\npackage_update: True\npackage_upgrade: True\npackage_reboot_if_required: True\nusers:\n- name: crdb\n  shell: /bin/bash\n  sudo:\n  - ALL=(ALL) NOPASSWD:ALL\n- default\n- name: crdb\n  ssh_authorized_keys:\n  - ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\nssh_pwauth: True\nruncmd:\n- hostnamectl set-hostname --pretty 'redis_vm-mcm3338-259990701119'\n- sudo service sshd restart\npackages:\n- chrony\n",
          "__dcSelfLink": "/resources/groups/3f14e002-ef03-4662-9104-65b89ea1aee9",
          "endpointType": "vsphere",
          "instanceUUID": "5004c77b-9143-a36f-db29-fc7b7cc7c420",
          "remoteAccess": {
            "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
            "username": "crdb",
            "authentication": "publicPrivateKey"
          },
          "resourceLink": "/resources/compute/b9b314ee-43c0-4c00-a946-1b340b6c27d3",
          "resourceName": "redis_vm-mcm3338-259990701119",
          "resourcePool": "/resources/pools/4004ae581f4d5075-7f703c5265a63d87",
          "softwareName": "Ubuntu Linux (64-bit)",
          "vmFolderPath": "[wdc-w01-wdc-w01-vsan01] 40e60466-e2ad-40b0-5419-0c42a12a8538",
          "__computeHost": "True",
          "__computeType": "VirtualMachine",
          "componentType": "Cloud.vSphere.Machine",
          "datastoreName": "wdc-w01-wdc-w01-vsan01",
          "totalMemoryMB": 16384,
          "__blueprint_id": "0a7686a1-6a94-462a-9839-2930a6518e15",
          "__endpointLink": "/resources/endpoints/b5c736bd-4aaa-4630-8778-21c0a56d89f0",
          "__endpointType": "vsphere",
          "cloneFromImage": "ubuntuTemplate-HWE",
          "computeHostRef": "ClusterComputeResource:domain-c8",
          "__deployment_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "__imageOsFamily": "LINUX",
          "__placementLink": "/resources/compute/b8d8c4dd-52d8-40a2-a008-1cb940b75fcb",
          "computeHostType": "ClusterComputeResource",
          "__bootDiskSizeMB": "61440",
          "__deploymentLink": "/resources/deployments/50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "customizeGuestOs": "True",
          "resourceDescLink": "/resources/compute-descriptions/154294ba-a164-46f2-b27e-21b360617523",
          "__computeHostLink": "/resources/compute/7a542d97-fa06-4494-999b-b879cfacdffa",
          "resourceGroupName": "",
          "__cpuHotAddEnabled": "False",
          "__imageMappingLink": "/provisioning/resources/image-profiles-v2/032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
          "__operationTimeout": "7200",
          "__storageReference": "Datastore:datastore-18",
          "neglectPowerOffVms": "False",
          "__component_type_id": "Compute.vSphere",
          "__isStorageReserved": "True",
          "__resolvedImageLink": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
          "__allocation_request": "True",
          "__memoryHotAddEnabled": "False",
          "__blueprint_request_id": "94686cd5-24b2-4111-a45f-562d44de00ca",
          "__vmw:provisioning:org": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d",
          "_clusterAllocationSize": "2",
          "__blueprint_resource_id": "b9b314ee-43c0-4c00-a946-1b340b6c27d3",
          "__imageBootDiskSizeInMB": "61440",
          "__imageDisksTotalSizeMB": "880640",
          "__composition_context_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "__projectPlacementPolicy": "DEFAULT",
          "__blueprint_resource_name": "redis_vm[0]",
          "__blueprint_resource_type": "Cloud.vSphere.Machine",
          "zone_overlapping_migrated": "True",
          "__vmw:provisioning:project": "087a503a-0da8-4254-9714-15094422021c",
          "__blueprint_request_event_id": "4649e92e-e748-4d0d-9f05-9fc61a1bac10",
          "__groupResourcePlacementLink": "/provisioning/resources/group-placements/087a503a-0da8-4254-9714-15094422021c-d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
          "__vmw:provisioning:blueprint": "0a7686a1-6a94-462a-9839-2930a6518e15",
          "__vmw:provisioning:cloudZone": "d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
          "__vmw:provisioning:requester": "provisioning-hamskor2of8iplc9@provisioning-client.local",
          "__vmw:provisioning:deployment": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "__vmw:provisioning:imageMapping": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
          "__allowTerraformCloudzoneMapping": "True",
          "__blueprint_resource_dependencies": "[\"infra_net\"]",
          "__blueprint_resource_last_operation": "create",
          "__vmw:provisioning:blueprintResourceName": "redis_vm",
          "__computeConfigContentPhoneHomeShouldWait": "False",
          "__blueprint_resource_dependent_resource_ids": "[\"febd9291-1373-4a35-9af4-19264611a64d\"]",
          "__blueprint_resource_dependency_resource_ids": "[\"ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1\"]",
          "__blueprint_resource_allocation_dependent_ids": "[]",
          "__ext:RequestBrokerState:STARTED:RESOURCE_COUNTED": "True",
          "__ext:ComputeReservationTaskState:STARTED:SELECTED": "True",
          "__computeConfigContentDeploymentFailOnCloudConfigRuntimeError": "True",
          "__ext:ComputeAllocationTaskState:STARTED:START_COMPUTE_ALLOCATION": "True"
        },
        {
          "id": "/resources/compute/97f9095d-2add-4fba-b3e0-dade5242c9e2",
          "name": "redis_vm",
          "tags": [
            {
              "key": "colour",
              "value": "blue"
            }
          ],
          "zone": "wdc-w01-cl01",
          "count": "2",
          "image": "test-image",
          "moref": "VirtualMachine:vm-510",
          "osType": "LINUX",
          "region": "wdc-w01-DC",
          "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
          "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
          "__moref": "VirtualMachine:vm-510",
          "account": "wdc-w01-vc01.vcf01.isvlab.vmware.com",
          "address": "172.16.63.140",
          "project": "087a503a-0da8-4254-9714-15094422021c",
          "storage": {
            "disks": [
              {
                "vm": "VirtualMachine:vm-510",
                "name": "redis_vm-mcm3339-259990701119-boot-disk",
                "type": "HDD",
                "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-eee9-6f47-c2f1-0c42a12a8538/redis_vm-mcm3339-259990701119_2.vmdk",
                "bootOrder": 1,
                "encrypted": False,
                "capacityGb": 60,
                "persistent": False,
                "independent": "False",
                "endpointType": "vsphere",
                "resourceLink": "/resources/disks/3783a236-c09e-47ad-b54f-b4b258fd5815",
                "controllerKey": "1000",
                "diskPlacementRef": "Datastore:datastore-18",
                "existingResource": "False",
                "provisioningType": "thin",
                "controllerUnitNumber": "0"
              },
              {
                "vm": "VirtualMachine:vm-510",
                "name": "Hard disk 2",
                "type": "HDD",
                "shares": "1000",
                "diskFile": "[wdc-w01-wdc-w01-vsan01] 40e60466-eee9-6f47-c2f1-0c42a12a8538/redis_vm-mcm3339-259990701119_4.vmdk",
                "encrypted": False,
                "limitIops": "-1",
                "capacityGb": 800,
                "persistent": False,
                "independent": "False",
                "sharesLevel": "normal",
                "endpointType": "vsphere",
                "resourceLink": "/resources/disks/8abdc155-bf77-4688-ba23-a7039908a744",
                "controllerKey": "1001",
                "existingResource": "False",
                "provisioningType": "thin",
                "controllerUnitNumber": "0"
              },
              {
                "name": "Floppy drive 1",
                "type": "FLOPPY",
                "encrypted": False,
                "capacityGb": 0,
                "persistent": False,
                "resourceLink": "/resources/disks/9e0c6859-d2ec-4602-b92f-6639bbffb341",
                "controllerKey": "400",
                "existingResource": "False",
                "controllerUnitNumber": "0"
              },
              {
                "name": "CD/DVD drive 1",
                "type": "CDROM",
                "encrypted": False,
                "capacityGb": 0,
                "persistent": False,
                "resourceLink": "/resources/disks/78479985-6774-47fb-a751-f6c81e77a8b3",
                "controllerKey": "200",
                "existingResource": "False",
                "controllerUnitNumber": "0"
              }
            ]
          },
          "accounts": [
            "wdc-w01-vc01.vcf01.isvlab.vmware.com"
          ],
          "cpuCount": 4,
          "networks": [
            {
              "id": "/resources/network-interfaces/b57b15c7-2e48-49fb-be93-c330fe8ab6f8",
              "dns": [
                "172.16.16.16",
                "172.16.16.17"
              ],
              "name": "ls-wcp-management-172_16_63_128__27-dhcp",
              "domain": "vcf01.isvlab.vmware.com",
              "address": "172.16.63.140",
              "gateway": "172.16.63.129",
              "netmask": "255.255.255.224",
              "network": "/provisioning/resources/compute-networks/ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1",
              "gateways": "172.16.63.129",
              "assignment": "static",
              "deviceIndex": 0,
              "external_id": "2858f58a-97ff-4129-ba31-b5fdaef3505f",
              "mac_address": "00:50:56:84:31:c6",
              "resourceName": "ls-wcp-management-172_16_63_128__27-dhcp",
              "ipv6Addresses": [
                "fe80::250:56ff:fe84:31c6"
              ],
              "dnsSearchDomains": [
                "vcf01.isvlab.vmware.com"
              ],
              "assignPublicIpAddress": True
            }
          ],
          "username": "crdb",
          "coreCount": "1",
          "enableSSH": "True",
          "__imageRef": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
          "countIndex": "1",
          "endpointId": "b5c736bd-4aaa-4630-8778-21c0a56d89f0",
          "externalId": "50049aa7-a573-3ee2-5fed-08f429d7feef",
          "isSimulate": "False",
          "powerState": "ON",
          "primaryMAC": "00:50:56:84:31:c6",
          "providerId": "50049aa7-a573-3ee2-5fed-08f429d7feef",
          "resourceId": "97f9095d-2add-4fba-b3e0-dade5242c9e2",
          "cloudConfig": "#cloud-config\nssh_authorized_keys:\n- ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\npackage_update: True\npackage_upgrade: True\npackage_reboot_if_required: True\nusers:\n- name: crdb\n  shell: /bin/bash\n  sudo:\n  - ALL=(ALL) NOPASSWD:ALL\n- default\n- name: crdb\n  ssh_authorized_keys:\n  - ((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))\nssh_pwauth: True\nruncmd:\n- hostnamectl set-hostname --pretty 'redis_vm-mcm3339-259990701119'\n- sudo service sshd restart\npackages:\n- chrony\n",
          "__dcSelfLink": "/resources/groups/3f14e002-ef03-4662-9104-65b89ea1aee9",
          "endpointType": "vsphere",
          "instanceUUID": "50049aa7-a573-3ee2-5fed-08f429d7feef",
          "remoteAccess": {
            "sshKey": "((secret:v1:AAH1aDQ2+xi+Lyceszza9E5TGDguqAIAIydmiDLw8xaeHc2DJvY3nHd98hHfoNouuTAJ+meE5pqzcvps9uG/E0OaS41YoD3qZ0gzepVUojvCuUjcLDPhA65ua4cjlPlyb3+OI7gD+ZaxD3x+bVX5+j7BZLUUDhFF7iU1torIXMQcYek4sDiyO/oWcpc8Zelh+VnZx8MC7oLnj0UAwI+xjUmw0wcmIqrIGbol3Y6V2FhcnfuXD6e2EIaiE6pE1KmKRZjPyFAxOLsXM9k2EOsp1I4CtBLpzhSuJDTo9j3CXbC6meLViDjQe7e8LOd+CymfkKtNqUMKE9VFMQGqhTHE6BcXabqSHm+KezZSxwRDRP3gfIxs1ytQyhvLgRW21BU3ENnK4SDFx9P96WmG9m7Aboe/eZX5JTz9ljkWXfXLxHgefNq/3GSXZJRRERThr1FRTBeTRyBe49cWwVDCI3ksuiBTbDPBVN0cBNhH09qOPIkf1lxxvaqIEGgacVD2FfDnn8emk/+9iBZxG2SuYmNrzbtm0zvM937QC1sVVUtfV1cr64MHvp97oSulxPQYgXpL5fvNQT9yhfFKheTtI13MlHmK+diH7LBTeibnp8Hn26zaNrL8ppTmSwFMpAV2aIVnghyptfJrUgkQVjgolP9YLY0DohZya+qEXd/6L2VloTcx341KHYlSdfu2ufzYsn4OssR5b2mFXRgrHqtyqVlKl29Z3lX7GZOKs+YsFt9LxUkUW8fKBAUVbnfChuFOJ0XMlolsLbVchVjbBh7ssRscUDqzc5cKCJ7nz6K3))",
            "username": "crdb",
            "authentication": "publicPrivateKey"
          },
          "resourceLink": "/resources/compute/97f9095d-2add-4fba-b3e0-dade5242c9e2",
          "resourceName": "redis_vm-mcm3339-259990701119",
          "resourcePool": "/resources/pools/4004ae581f4d5075-7f703c5265a63d87",
          "softwareName": "Ubuntu Linux (64-bit)",
          "vmFolderPath": "[wdc-w01-wdc-w01-vsan01] 40e60466-eee9-6f47-c2f1-0c42a12a8538",
          "__computeHost": "True",
          "__computeType": "VirtualMachine",
          "componentType": "Cloud.vSphere.Machine",
          "datastoreName": "wdc-w01-wdc-w01-vsan01",
          "totalMemoryMB": 16384,
          "__blueprint_id": "0a7686a1-6a94-462a-9839-2930a6518e15",
          "__endpointLink": "/resources/endpoints/b5c736bd-4aaa-4630-8778-21c0a56d89f0",
          "__endpointType": "vsphere",
          "cloneFromImage": "ubuntuTemplate-HWE",
          "computeHostRef": "ClusterComputeResource:domain-c8",
          "__deployment_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "__imageOsFamily": "LINUX",
          "__placementLink": "/resources/compute/b8d8c4dd-52d8-40a2-a008-1cb940b75fcb",
          "computeHostType": "ClusterComputeResource",
          "__bootDiskSizeMB": "61440",
          "__deploymentLink": "/resources/deployments/50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "customizeGuestOs": "True",
          "resourceDescLink": "/resources/compute-descriptions/154294ba-a164-46f2-b27e-21b360617523",
          "__computeHostLink": "/resources/compute/7489b91d-c75c-4215-a0ef-ed403e9b4984",
          "resourceGroupName": "",
          "__cpuHotAddEnabled": "False",
          "__imageMappingLink": "/provisioning/resources/image-profiles-v2/032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
          "__operationTimeout": "7200",
          "__storageReference": "Datastore:datastore-18",
          "neglectPowerOffVms": "False",
          "__component_type_id": "Compute.vSphere",
          "__isStorageReserved": "True",
          "__resolvedImageLink": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
          "__allocation_request": "True",
          "__memoryHotAddEnabled": "False",
          "__blueprint_request_id": "94686cd5-24b2-4111-a45f-562d44de00ca",
          "__vmw:provisioning:org": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d",
          "_clusterAllocationSize": "2",
          "__blueprint_resource_id": "97f9095d-2add-4fba-b3e0-dade5242c9e2",
          "__imageBootDiskSizeInMB": "61440",
          "__imageDisksTotalSizeMB": "880640",
          "__composition_context_id": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "__projectPlacementPolicy": "DEFAULT",
          "__blueprint_resource_name": "redis_vm[1]",
          "__blueprint_resource_type": "Cloud.vSphere.Machine",
          "zone_overlapping_migrated": "True",
          "__vmw:provisioning:project": "087a503a-0da8-4254-9714-15094422021c",
          "__blueprint_request_event_id": "4649e92e-e748-4d0d-9f05-9fc61a1bac10",
          "__groupResourcePlacementLink": "/provisioning/resources/group-placements/087a503a-0da8-4254-9714-15094422021c-d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
          "__vmw:provisioning:blueprint": "0a7686a1-6a94-462a-9839-2930a6518e15",
          "__vmw:provisioning:cloudZone": "d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
          "__vmw:provisioning:requester": "provisioning-hamskor2of8iplc9@provisioning-client.local",
          "__vmw:provisioning:deployment": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
          "__vmw:provisioning:imageMapping": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
          "__allowTerraformCloudzoneMapping": "True",
          "__blueprint_resource_dependencies": "[\"infra_net\"]",
          "__blueprint_resource_last_operation": "create",
          "__vmw:provisioning:blueprintResourceName": "redis_vm",
          "__computeConfigContentPhoneHomeShouldWait": "False",
          "__blueprint_resource_dependent_resource_ids": "[\"febd9291-1373-4a35-9af4-19264611a64d\"]",
          "__blueprint_resource_dependency_resource_ids": "[\"ac31fbe7-7cb1-4d4d-9d99-2bd90be331b1\"]",
          "__blueprint_resource_allocation_dependent_ids": "[]",
          "__ext:RequestBrokerState:STARTED:RESOURCE_COUNTED": "True",
          "__ext:ComputeReservationTaskState:STARTED:SELECTED": "True",
          "__computeConfigContentDeploymentFailOnCloudConfigRuntimeError": "True",
          "__ext:ComputeAllocationTaskState:STARTED:START_COMPUTE_ALLOCATION": "True"
        }
      ]
    ]
  },
  "host_variables": {
    "crdb_vm": {
      "port": 80,
      "rack": 1,
      "verbose": True
    },
    "redis_vm": {
      "port": 8080,
      "verbose": False
    }
  },
  "inventory_name": "50b8d3b3-1fa8-4bc6-937e-1674bca499d8",
  "job_template_name": "CRDB Template",
  "organization_name": "Default"
}

    class Passthrough(object):
        def __init__(self):
            pass

        @classmethod
        def getSecret(cls, x):
            return x

    handler(Passthrough(), test)
