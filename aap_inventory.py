import json
import requests
import urllib3
import urllib.parse

from requests.auth import HTTPBasicAuth
from string import Template
from typing import List, Union


class AapHost(object):
    def __init__(self, **kwargs):
        # Mandatory parameters
        self.name = kwargs.get("hostName")

        variables = {"ansible_host": kwargs.get("networks")[0].get("address")}

        if "tags" in kwargs.keys():
            for tag in kwargs.get("tags"):
                variables[tag["key"]] = tag["value"]

        self.variables = json.dumps(variables)


class AapInventory(object):
    PATH_TOKEN = "api/v2/tokens/"
    PATH_INVENTORY = "api/v2/inventories/"
    PATH_ORGANIZATION = "api/v2/organizations/"
    PATH_GROUPS = "api/v2/groups/"
    PATH_HOSTS = "api/v2/hosts/"
    PATH_BULK_HOST_CREATE = "api/v2/bulk/host_create/"
    PATH_GROUP_ADD = Template("api/v2/groups/$group_id/hosts/")
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

    def find_organization_by_name(self, name: str) -> int:
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
            return self.DEFAULT_ORGANIZATION_ID

        # Return the organization id
        return matches[0].get("id")

    def find_inventory_by_name(self, name: str) -> Union[None, int]:
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
        return matches[0].get("id")

    def find_group_by_name(self, name: str, inventory_id: int) -> Union[None, int]:
        """Search for a group and return its ID"""
        path = self.PATH_GROUPS + f"?inventory={inventory_id}"
        response = self.__get(path=path)
        results = response.get("results", [])

        # Search for exact name matches
        # Note: The previous query returns all the groups part of an inventory
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
        return matches[0].get("id")

    def create_inventory(
        self, name: str, organization_id: int = DEFAULT_ORGANIZATION_ID
    ) -> int:
        """Create a new inventory and add hosts to the inventory"""
        inventory_id = self.find_inventory_by_name(name=name)
        if inventory_id is not None:
            return inventory_id

        data = {
            "name": name,
            "description": "Created via Aria Automation API",
            "organization": organization_id,
        }
        response = self.__post(path=self.PATH_INVENTORY, data=data)
        return response.get("id")

    def create_group(self, name: str, inventory_id: int, description: str = None):
        """Create a new group"""
        group_id = self.find_group_by_name(name=name, inventory_id=inventory_id)
        if group_id is not None:
            return group_id

        data = {
            "name": name,
            "description": "" if description is None else description,
            "inventory": inventory_id,
        }
        response = self.__post(path=self.PATH_GROUPS, data=data)
        return response.get("id")

    def add_hosts_to_inventory(
        self, inventory_id: int, hosts: List[AapHost]
    ) -> List[int]:
        """Add hosts to am inventory
        ref. https://www.redhat.com/en/blog/bulk-api-in-automation-controller
        """
        data = {
            "inventory": inventory_id,
            "hosts": [vars(host) for host in hosts],
        }
        response = self.__post(path=self.PATH_BULK_HOST_CREATE, data=data)
        return [host.get("id") for host in response.get("hosts", [])]

    def add_hosts_to_groups(self, group_ids: List[int], host_ids: List[int]) -> None:
        """Add hosts to the specified groups."""
        for group_id in group_ids:
            for host_id in host_ids:
                group_path = self.PATH_GROUP_ADD.substitute({"group_id": group_id})
                data = {"id": host_id}
                self.__post(path=group_path, data=data)


def handler(context, inputs):
    # Ansible Automation Platform configuration
    base_url = inputs["base_url"]
    username = inputs["username"]
    password = context.getSecret(inputs["password"])
    ssl_verify = inputs.get("ssl_verify", True)

    # Ansible Automation Platform Inventory
    inventory_name = inputs.get("inventory_name", "aap-api-inventory")
    hosts = [AapHost(**host) for host in inputs.get("hosts", [])]
    host_variables = inputs.get("host_variables", {})
    groups = inputs.get("groups", [])

    if not ssl_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    aap = AapInventory(base_url=base_url, username=username, password=password, ssl_verify=ssl_verify)
    organization_id = aap.find_organization_by_name(name="Default")
    inventory_id = aap.create_inventory(name=inventory_name, organization_id=organization_id)
    host_ids = aap.add_hosts_to_inventory(inventory_id=inventory_id, hosts=hosts)
    group_ids = [aap.create_group(name=group, inventory_id=inventory_id) for group in groups]
    aap.add_hosts_to_groups(host_ids=host_ids, group_ids=group_ids)


if __name__ == "__main__":
    test = {
        "base_url": "https://wdc-ansible.vcf01.isvlab.vmware.com",
        "username": "admin",
        "password": "P@ssword123!",
        "ssl_verify": False,
        "inventory_name": "foobar",
        "hosts": [
            {
                "id": "/resources/compute/491a2ff8-2bc7-4a86-aaea-588ba82619c0",
                "name": "crdb_vm",
                "tags": [],
                "zone": "wdc-w01-cl01",
                "image": "test-image",
                "moref": "VirtualMachine:vm-427",
                "osType": "LINUX",
                "region": "wdc-w01-DC",
                "sshKey": "((secret:v1:AAHF2N0KL6SMw92CceafwVOL0ZO10KmieWwF2t77uRcHm4xZMW5vyGN87jc0+UjDyzWCrq0hdq+o/+ejPzkZMf/YbzQpaj/D2+hYVQVatuSxEJOQr19YLZ0J2SlGdJL7XBc1Z1yvj6gUZ7u22WdKynO2Zbriu7wYsIxiV1hFRJBnasX/D2l7u0xI0co0kYZnTEC5FCCKwgXb7xq+C+So1TxOxyxiOq0Rca94Q0uguBkKUdEAXRrOyDroQXP2h+2+JDyaCym2ipUeKVGqbshxuxVUhY3DD9SCIRFVT1zxPAaVVN2N/oNXrXQ9aKsIYSvfVK/ygpdNqF0QtF+0pVgP7qOqA4otviPfxz9gx8o7rLsB2P1m2a2fbzk03fPzEMUqXN+GkDPIZUvWhHxbBx0PQ37Ee8Gv71wMH/BwzyOFrwKeHjvx3xSunPOafYJ9cpdedqe92LEneFIeqSkPuSRk4s4SHrYksHVrm//8vsGXa5/JUsjcO7X8yw2e4Cm3b3wlIDVS7THfwYqRwtneQEXNWihtEbgVV5NyBZ5rVpMqvQFoGcdtbbiAJF8cQXW5RphylgdoGNQIfZd20DKRJmn0wUcvJHDFhe9l/6jrjt58u87dwX6fnEJmGSl8+3DkTy+idTgiyuhbbiuKg5LcZIvTgGSMMfoiG07WpRt61bsjiTda/rtRR2badk9H1W3HHUsHFlZBGtI0V+BRmnxNpj++mUr3LCnA8XktkCTp+yRwXuLKGdU+w2dhNQzJV0kvbXLpvaA/L1tF/MKMLOoiJNyLZpy+qAg/J4W3sBSU))",
                "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                "__moref": "VirtualMachine:vm-427",
                "account": "wdc-w01-vc01.vcf01.isvlab.vmware.com",
                "address": "172.16.63.147",
                "project": "087a503a-0da8-4254-9714-15094422021c",
                "storage": {
                    "disks": [
                        {
                            "vm": "VirtualMachine:vm-427",
                            "name": "CD/DVD drive 1",
                            "type": "CDROM",
                            "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                            "encrypted": False,
                            "capacityGb": 0,
                            "persistent": False,
                            "endpointType": "vsphere",
                            "resourceLink": "/resources/disks/440e72ce-2720-4a75-9122-dbd7cea45481",
                            "controllerKey": "200",
                            "existingResource": "False",
                            "controllerUnitNumber": "0",
                        },
                        {
                            "vm": "VirtualMachine:vm-427",
                            "name": "Floppy drive 1",
                            "type": "FLOPPY",
                            "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                            "encrypted": False,
                            "capacityGb": 0,
                            "persistent": False,
                            "endpointType": "vsphere",
                            "resourceLink": "/resources/disks/5e3d2011-79e9-4231-95c2-5947a7fb9ac6",
                            "controllerKey": "400",
                            "existingResource": "False",
                            "controllerUnitNumber": "0",
                        },
                        {
                            "vm": "VirtualMachine:vm-427",
                            "name": "crdb_vm-mcm1952-259497566102-boot-disk",
                            "type": "HDD",
                            "shares": "1000",
                            "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                            "diskFile": "[wdc-w01-wdc-w01-vsan01] 3a60fd65-0ac5-c6ab-796b-0c42a12a8540/crdb_vm-mcm1952-259497566102_2.vmdk",
                            "bootOrder": 1,
                            "encrypted": False,
                            "limitIops": "-1",
                            "capacityGb": 60,
                            "persistent": False,
                            "independent": "False",
                            "sharesLevel": "normal",
                            "endpointType": "vsphere",
                            "resourceLink": "/resources/disks/d30cb053-3aa3-4c3e-a482-5d6d97f228fc",
                            "controllerKey": "1000",
                            "diskPlacementRef": "Datastore:datastore-18",
                            "existingResource": "False",
                            "provisioningType": "thin",
                            "controllerUnitNumber": "0",
                        },
                        {
                            "vm": "VirtualMachine:vm-427",
                            "name": "Hard disk 2",
                            "type": "HDD",
                            "shares": "1000",
                            "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                            "diskFile": "[wdc-w01-wdc-w01-vsan01] 3a60fd65-0ac5-c6ab-796b-0c42a12a8540/crdb_vm-mcm1952-259497566102_4.vmdk",
                            "encrypted": False,
                            "limitIops": "-1",
                            "capacityGb": 800,
                            "persistent": False,
                            "independent": "False",
                            "sharesLevel": "normal",
                            "endpointType": "vsphere",
                            "resourceLink": "/resources/disks/3a414f9b-2990-4aab-b83d-104983d1063b",
                            "controllerKey": "1001",
                            "diskPlacementRef": "Datastore:datastore-18",
                            "existingResource": "False",
                            "provisioningType": "thin",
                            "controllerUnitNumber": "0",
                        },
                    ]
                },
                "accounts": ["wdc-w01-vc01.vcf01.isvlab.vmware.com"],
                "cpuCount": 4,
                "hostName": "crdb-vm-mcm1952-259497566102",
                "memoryGB": "16",
                "networks": [
                    {
                        "id": "/resources/network-interfaces/4632f82a-e76b-43ef-8af5-d73a367eaa58",
                        "dns": ["172.16.16.16", "172.16.16.17"],
                        "name": "ls-wcp-management-172_16_63_128__27-dhcp",
                        "domain": "vcf01.isvlab.vmware.com",
                        "address": "172.16.63.147",
                        "gateway": "172.16.63.129",
                        "netmask": "255.255.255.224",
                        "network": "/provisioning/resources/compute-networks/05f3e14a-0278-4fcd-b691-d6f1998b308c",
                        "gateways": "172.16.63.129",
                        "assignment": "static",
                        "deviceIndex": 0,
                        "external_id": "fdcc78dd-8756-442e-97bf-2f0d221f39b3",
                        "mac_address": "00:50:56:84:a7:fa",
                        "resourceName": "ls-wcp-management-172_16_63_128__27-dhcp",
                        "ipv6Addresses": ["fe80::250:56ff:fe84:a7fa"],
                        "securityGroups": [],
                        "dnsSearchDomains": ["vcf01.isvlab.vmware.com"],
                        "assignPublicIpAddress": True,
                    }
                ],
                "username": "crdb",
                "coreCount": 4,
                "enableSSH": "True",
                "__imageRef": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
                "countIndex": "0",
                "datacenter": "Datacenter:datacenter-3",
                "endpointId": "b5c736bd-4aaa-4630-8778-21c0a56d89f0",
                "externalId": "500442ee-2cc7-31d7-1ca4-1a4bb02e775c",
                "isSimulate": "False",
                "powerState": "ON",
                "primaryMAC": "00:50:56:84:a7:fa",
                "providerId": "500442ee-2cc7-31d7-1ca4-1a4bb02e775c",
                "resourceId": "491a2ff8-2bc7-4a86-aaea-588ba82619c0",
                "cloudConfig": "#cloud-config\nssh_authorized_keys:\n- ((secret:v1:AAHF2N0KL6SMw92CceafwVOL0ZO10KmieWwF2t77uRcHm4xZMW5vyGN87jc0+UjDyzWCrq0hdq+o/+ejPzkZMf/YbzQpaj/D2+hYVQVatuSxEJOQr19YLZ0J2SlGdJL7XBc1Z1yvj6gUZ7u22WdKynO2Zbriu7wYsIxiV1hFRJBnasX/D2l7u0xI0co0kYZnTEC5FCCKwgXb7xq+C+So1TxOxyxiOq0Rca94Q0uguBkKUdEAXRrOyDroQXP2h+2+JDyaCym2ipUeKVGqbshxuxVUhY3DD9SCIRFVT1zxPAaVVN2N/oNXrXQ9aKsIYSvfVK/ygpdNqF0QtF+0pVgP7qOqA4otviPfxz9gx8o7rLsB2P1m2a2fbzk03fPzEMUqXN+GkDPIZUvWhHxbBx0PQ37Ee8Gv71wMH/BwzyOFrwKeHjvx3xSunPOafYJ9cpdedqe92LEneFIeqSkPuSRk4s4SHrYksHVrm//8vsGXa5/JUsjcO7X8yw2e4Cm3b3wlIDVS7THfwYqRwtneQEXNWihtEbgVV5NyBZ5rVpMqvQFoGcdtbbiAJF8cQXW5RphylgdoGNQIfZd20DKRJmn0wUcvJHDFhe9l/6jrjt58u87dwX6fnEJmGSl8+3DkTy+idTgiyuhbbiuKg5LcZIvTgGSMMfoiG07WpRt61bsjiTda/rtRR2badk9H1W3HHUsHFlZBGtI0V+BRmnxNpj++mUr3LCnA8XktkCTp+yRwXuLKGdU+w2dhNQzJV0kvbXLpvaA/L1tF/MKMLOoiJNyLZpy+qAg/J4W3sBSU))\npackage_update: True\npackage_upgrade: True\npackage_reboot_if_required: True\nusers:\n- name: crdb\n  shell: /bin/bash\n  sudo:\n  - ALL=(ALL) NOPASSWD:ALL\n- default\n- name: crdb\n  ssh_authorized_keys:\n  - ((secret:v1:AAHF2N0KL6SMw92CceafwVOL0ZO10KmieWwF2t77uRcHm4xZMW5vyGN87jc0+UjDyzWCrq0hdq+o/+ejPzkZMf/YbzQpaj/D2+hYVQVatuSxEJOQr19YLZ0J2SlGdJL7XBc1Z1yvj6gUZ7u22WdKynO2Zbriu7wYsIxiV1hFRJBnasX/D2l7u0xI0co0kYZnTEC5FCCKwgXb7xq+C+So1TxOxyxiOq0Rca94Q0uguBkKUdEAXRrOyDroQXP2h+2+JDyaCym2ipUeKVGqbshxuxVUhY3DD9SCIRFVT1zxPAaVVN2N/oNXrXQ9aKsIYSvfVK/ygpdNqF0QtF+0pVgP7qOqA4otviPfxz9gx8o7rLsB2P1m2a2fbzk03fPzEMUqXN+GkDPIZUvWhHxbBx0PQ37Ee8Gv71wMH/BwzyOFrwKeHjvx3xSunPOafYJ9cpdedqe92LEneFIeqSkPuSRk4s4SHrYksHVrm//8vsGXa5/JUsjcO7X8yw2e4Cm3b3wlIDVS7THfwYqRwtneQEXNWihtEbgVV5NyBZ5rVpMqvQFoGcdtbbiAJF8cQXW5RphylgdoGNQIfZd20DKRJmn0wUcvJHDFhe9l/6jrjt58u87dwX6fnEJmGSl8+3DkTy+idTgiyuhbbiuKg5LcZIvTgGSMMfoiG07WpRt61bsjiTda/rtRR2badk9H1W3HHUsHFlZBGtI0V+BRmnxNpj++mUr3LCnA8XktkCTp+yRwXuLKGdU+w2dhNQzJV0kvbXLpvaA/L1tF/MKMLOoiJNyLZpy+qAg/J4W3sBSU))\nssh_pwauth: True\nruncmd:\n- hostnamectl set-hostname --pretty crdb_vm-mcm1952-259497566102\n- sudo service sshd restart\npackages:\n- chrony\n",
                "__dcSelfLink": "/resources/groups/3f14e002-ef03-4662-9104-65b89ea1aee9",
                "endpointType": "vsphere",
                "hasSnapshots": "False",
                "instanceUUID": "500442ee-2cc7-31d7-1ca4-1a4bb02e775c",
                "remoteAccess": {
                    "sshKey": "((secret:v1:AAHF2N0KL6SMw92CceafwVOL0ZO10KmieWwF2t77uRcHm4xZMW5vyGN87jc0+UjDyzWCrq0hdq+o/+ejPzkZMf/YbzQpaj/D2+hYVQVatuSxEJOQr19YLZ0J2SlGdJL7XBc1Z1yvj6gUZ7u22WdKynO2Zbriu7wYsIxiV1hFRJBnasX/D2l7u0xI0co0kYZnTEC5FCCKwgXb7xq+C+So1TxOxyxiOq0Rca94Q0uguBkKUdEAXRrOyDroQXP2h+2+JDyaCym2ipUeKVGqbshxuxVUhY3DD9SCIRFVT1zxPAaVVN2N/oNXrXQ9aKsIYSvfVK/ygpdNqF0QtF+0pVgP7qOqA4otviPfxz9gx8o7rLsB2P1m2a2fbzk03fPzEMUqXN+GkDPIZUvWhHxbBx0PQ37Ee8Gv71wMH/BwzyOFrwKeHjvx3xSunPOafYJ9cpdedqe92LEneFIeqSkPuSRk4s4SHrYksHVrm//8vsGXa5/JUsjcO7X8yw2e4Cm3b3wlIDVS7THfwYqRwtneQEXNWihtEbgVV5NyBZ5rVpMqvQFoGcdtbbiAJF8cQXW5RphylgdoGNQIfZd20DKRJmn0wUcvJHDFhe9l/6jrjt58u87dwX6fnEJmGSl8+3DkTy+idTgiyuhbbiuKg5LcZIvTgGSMMfoiG07WpRt61bsjiTda/rtRR2badk9H1W3HHUsHFlZBGtI0V+BRmnxNpj++mUr3LCnA8XktkCTp+yRwXuLKGdU+w2dhNQzJV0kvbXLpvaA/L1tF/MKMLOoiJNyLZpy+qAg/J4W3sBSU))",
                    "username": "crdb",
                    "authentication": "publicPrivateKey",
                },
                "resourceLink": "/resources/compute/491a2ff8-2bc7-4a86-aaea-588ba82619c0",
                "resourceName": "crdb_vm-mcm1952-259497566102",
                "resourcePool": "/resources/pools/4004ae581f4d5075-7f703c5265a63d87",
                "softwareName": "Ubuntu Linux (64-bit)",
                "vmFolderPath": "[wdc-w01-wdc-w01-vsan01] 3a60fd65-0ac5-c6ab-796b-0c42a12a8540",
                "__computeHost": "True",
                "__computeType": "VirtualMachine",
                "componentType": "Cloud.vSphere.Machine",
                "datastoreName": "wdc-w01-wdc-w01-vsan01",
                "snapshotCount": "0",
                "totalMemoryMB": 16384,
                "__blueprint_id": "812304a6-5de3-4c8f-9370-ab337fcacb9d",
                "__endpointLink": "/resources/endpoints/b5c736bd-4aaa-4630-8778-21c0a56d89f0",
                "__endpointType": "vsphere",
                "cloneFromImage": "ubuntuTemplate-HWE",
                "computeHostRef": "ClusterComputeResource:domain-c8",
                "__deployment_id": "ce81b7d1-3eba-44df-8c10-2b5443ea17a1",
                "__imageOsFamily": "LINUX",
                "__placementLink": "/resources/compute/b8d8c4dd-52d8-40a2-a008-1cb940b75fcb",
                "computeHostType": "ClusterComputeResource",
                "environmentName": "On premise",
                "__bootDiskSizeMB": "61440",
                "__deploymentLink": "/resources/deployments/ce81b7d1-3eba-44df-8c10-2b5443ea17a1",
                "customizeGuestOs": "True",
                "resourceDescLink": "/resources/compute-descriptions/4c1fa278-9eba-457b-889d-c1a329c9a67f",
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
                "cloudConfigSettings": {
                    "deploymentFailOnCloudConfigRuntimeError": True
                },
                "__allocation_request": "True",
                "areVMActionsDisabled": "False",
                "__memoryHotAddEnabled": "False",
                "__blueprint_request_id": "136db825-0b23-4642-8a7b-4c791d4ec86b",
                "__vmw:provisioning:org": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d",
                "_clusterAllocationSize": "2",
                "__blueprint_resource_id": "491a2ff8-2bc7-4a86-aaea-588ba82619c0",
                "__imageBootDiskSizeInMB": "61440",
                "__imageDisksTotalSizeMB": "880640",
                "__composition_context_id": "ce81b7d1-3eba-44df-8c10-2b5443ea17a1",
                "__ownerComputeResourceId": "ClusterComputeResource:domain-c8",
                "__projectPlacementPolicy": "DEFAULT",
                "__blueprint_resource_name": "crdb_vm[0]",
                "__blueprint_resource_type": "Cloud.vSphere.Machine",
                "zone_overlapping_migrated": "True",
                "__ownerComputeResourceLink": "/resources/compute/b8d8c4dd-52d8-40a2-a008-1cb940b75fcb",
                "__vmw:provisioning:project": "087a503a-0da8-4254-9714-15094422021c",
                "__blueprint_request_event_id": "2000995e-1660-47d8-a762-f9111b273e00",
                "__groupResourcePlacementLink": "/provisioning/resources/group-placements/087a503a-0da8-4254-9714-15094422021c-d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
                "__vmw:provisioning:blueprint": "812304a6-5de3-4c8f-9370-ab337fcacb9d",
                "__vmw:provisioning:cloudZone": "d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
                "__vmw:provisioning:requester": "provisioning-hamskor2of8iplc9@provisioning-client.local",
                "__vmw:provisioning:deployment": "ce81b7d1-3eba-44df-8c10-2b5443ea17a1",
                "__vmw:provisioning:imageMapping": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
                "__allowTerraformCloudzoneMapping": "True",
                "__blueprint_resource_dependencies": '["infra_net"]',
                "__blueprint_deployment_resource_id": "491a2ff8-2bc7-4a86-aaea-588ba82619c0",
                "__blueprint_resource_last_operation": "create",
                "__vmw:provisioning:blueprintResourceName": "crdb_vm",
                "__computeConfigContentPhoneHomeShouldWait": "False",
                "__blueprint_resource_dependent_resource_ids": '["43123ed6-4576-4914-8bef-afeb026fed2a","5afe93a8-7c5d-4b1c-aeb1-4fec4b61d498"]',
                "__blueprint_resource_dependency_resource_ids": '["05f3e14a-0278-4fcd-b691-d6f1998b308c"]',
                "__blueprint_resource_allocation_dependent_ids": "[]",
                "__ext:RequestBrokerState:STARTED:RESOURCE_COUNTED": "True",
                "__ext:ComputeReservationTaskState:STARTED:SELECTED": "True",
                "__computeConfigContentDeploymentFailOnCloudConfigRuntimeError": "True",
                "__ext:ComputeAllocationTaskState:STARTED:START_COMPUTE_ALLOCATION": "True",
            },
            {
                "id": "/resources/compute/0e8215ad-66fd-427c-9f64-c60d87b3de2b",
                "name": "crdb_vm",
                "tags": [],
                "zone": "wdc-w01-cl01",
                "image": "test-image",
                "moref": "VirtualMachine:vm-431",
                "osType": "LINUX",
                "region": "wdc-w01-DC",
                "sshKey": "((secret:v1:AAF42R6Wdfn6Eue7IyZa9mX/XWv4OBOeH+kPE3bGmRgfjb4axlWwMZ/6U6pOjLpzzYLKLb+QuSDE2mKOBM8rN/6uazbqSATWh0PUlX0cOdeKsgGUYtjDMmbviTlDlIBKvmfj6toWp7VMSPDy8TRgKNu9eMvK2bmjxOC3+lVDuqc19zlAeuD01vRD1CY6xLsHcl8fHeVDm9nD17bSTtEtSffQ+iyD0DvKc/pnRqcqlQ2Av5XS58JO1n8DHwZwb6Aiu2xJTJY1yCwE5Cy8eFd2gchBq1qtLeBgjycbeHOh6Ve+LAppZFefkaNtIe3/bRfhDwVxhhsPDktCwzfe7Zy4UWrLx4uQpW5XMvY3c79IThjvNDHBzMZ+nVNFqbcsZd8NO6EaJ7l1BhEH3hvNvuBsZ6fBQtQf3U0gWXo+uXhAiODnTC5f5zR5ZaTRtfRetcFeu3KD4G//hB6fPnQKuzFxZrLK8HFyMBcHmfx5DQHBXbcYpmVNINQB7Zj3wcl6G1v1Svwk0RgPJSqvyF4jA9EkyInj6Tg5lVzc9Ole5ZPj//5DW4xdV1r0Ogr0dVVuaznuSX99mF3FvhL6Nd2qCavRF9/dgUqvvOwdzo+osXCXuVHVaKyO2qB45LRud1dR+lJENczoHRypprh4UvOkmGwFk2w1PCbhtmtfC3zrT3UzQHPWbIevm71ZGaS7RP/wnivgs5N0d5fllE4rXOQk2rh5yqvmcpAtcYmhRbabe5jVuty8rZIhn/kkIk7dqgW1SHyA4DPpIESIhMMJcvk0mn8+2+/+68U/VECGrFsT))",
                "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                "__moref": "VirtualMachine:vm-431",
                "account": "wdc-w01-vc01.vcf01.isvlab.vmware.com",
                "address": "172.16.63.135",
                "project": "087a503a-0da8-4254-9714-15094422021c",
                "storage": {
                    "disks": [
                        {
                            "vm": "VirtualMachine:vm-431",
                            "name": "Hard disk 2",
                            "type": "HDD",
                            "shares": "1000",
                            "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                            "diskFile": "[wdc-w01-wdc-w01-vsan01] 6e8f0166-62ba-ee5b-073b-0c42a12a8150/crdb_vm-mcm2571-259771773836_4.vmdk",
                            "encrypted": False,
                            "limitIops": "-1",
                            "capacityGb": 800,
                            "persistent": False,
                            "independent": "False",
                            "sharesLevel": "normal",
                            "endpointType": "vsphere",
                            "resourceLink": "/resources/disks/26befda5-cc97-4c15-ba7a-0ed0002d104c",
                            "controllerKey": "1001",
                            "diskPlacementRef": "Datastore:datastore-18",
                            "existingResource": "False",
                            "provisioningType": "thin",
                            "controllerUnitNumber": "0",
                        },
                        {
                            "vm": "VirtualMachine:vm-431",
                            "name": "crdb_vm-mcm2571-259771773836-boot-disk",
                            "type": "HDD",
                            "shares": "1000",
                            "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                            "diskFile": "[wdc-w01-wdc-w01-vsan01] 6e8f0166-62ba-ee5b-073b-0c42a12a8150/crdb_vm-mcm2571-259771773836_2.vmdk",
                            "bootOrder": 1,
                            "encrypted": False,
                            "limitIops": "-1",
                            "capacityGb": 60,
                            "persistent": False,
                            "independent": "False",
                            "sharesLevel": "normal",
                            "endpointType": "vsphere",
                            "resourceLink": "/resources/disks/322a5104-ce7b-4b3e-bd85-8b5c8d8338a3",
                            "controllerKey": "1000",
                            "diskPlacementRef": "Datastore:datastore-18",
                            "existingResource": "False",
                            "provisioningType": "thin",
                            "controllerUnitNumber": "0",
                        },
                        {
                            "vm": "VirtualMachine:vm-431",
                            "name": "CD/DVD drive 1",
                            "type": "CDROM",
                            "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                            "encrypted": False,
                            "capacityGb": 0,
                            "persistent": False,
                            "endpointType": "vsphere",
                            "resourceLink": "/resources/disks/c64f79c6-64ea-403b-a6f4-6534e56af7d8",
                            "controllerKey": "200",
                            "existingResource": "False",
                            "controllerUnitNumber": "0",
                        },
                        {
                            "vm": "VirtualMachine:vm-431",
                            "name": "Floppy drive 1",
                            "type": "FLOPPY",
                            "vcUuid": "6127dc5d-fb67-438f-af24-042590c8c8de",
                            "encrypted": False,
                            "capacityGb": 0,
                            "persistent": False,
                            "endpointType": "vsphere",
                            "resourceLink": "/resources/disks/ae3ad450-4736-4705-89e4-1bea299ed96d",
                            "controllerKey": "400",
                            "existingResource": "False",
                            "controllerUnitNumber": "0",
                        },
                    ]
                },
                "accounts": ["wdc-w01-vc01.vcf01.isvlab.vmware.com"],
                "cpuCount": 4,
                "hostName": "crdb-vm-mcm2571-259771773836",
                "memoryGB": "16",
                "networks": [
                    {
                        "id": "/resources/network-interfaces/b6a5e5b5-c534-4474-ac26-78e36c0b767e",
                        "dns": ["172.16.16.16", "172.16.16.17"],
                        "name": "ls-wcp-management-172_16_63_128__27-dhcp",
                        "domain": "vcf01.isvlab.vmware.com",
                        "address": "172.16.63.135",
                        "gateway": "172.16.63.129",
                        "netmask": "255.255.255.224",
                        "network": "/provisioning/resources/compute-networks/05f3e14a-0278-4fcd-b691-d6f1998b308c",
                        "gateways": "172.16.63.129",
                        "assignment": "static",
                        "deviceIndex": 0,
                        "external_id": "064e4de8-a5dd-472f-be22-e884bd46924f",
                        "mac_address": "00:50:56:84:6e:75",
                        "resourceName": "ls-wcp-management-172_16_63_128__27-dhcp",
                        "ipv6Addresses": ["fe80::250:56ff:fe84:6e75"],
                        "securityGroups": [],
                        "dnsSearchDomains": ["vcf01.isvlab.vmware.com"],
                        "assignPublicIpAddress": True,
                    }
                ],
                "username": "crdb",
                "coreCount": 4,
                "enableSSH": "True",
                "__imageRef": "/resources/images/8beff4a20ad5ddb7b4334cb4ab9d62c19f48113e",
                "countIndex": "1",
                "datacenter": "Datacenter:datacenter-3",
                "endpointId": "b5c736bd-4aaa-4630-8778-21c0a56d89f0",
                "externalId": "5004d3d5-8f3f-ed43-8b3c-62c564a4b1d6",
                "isSimulate": "False",
                "powerState": "ON",
                "primaryMAC": "00:50:56:84:6e:75",
                "providerId": "5004d3d5-8f3f-ed43-8b3c-62c564a4b1d6",
                "resourceId": "0e8215ad-66fd-427c-9f64-c60d87b3de2b",
                "cloudConfig": "#cloud-config\nssh_authorized_keys:\n- ((secret:v1:AAF42R6Wdfn6Eue7IyZa9mX/XWv4OBOeH+kPE3bGmRgfjb4axlWwMZ/6U6pOjLpzzYLKLb+QuSDE2mKOBM8rN/6uazbqSATWh0PUlX0cOdeKsgGUYtjDMmbviTlDlIBKvmfj6toWp7VMSPDy8TRgKNu9eMvK2bmjxOC3+lVDuqc19zlAeuD01vRD1CY6xLsHcl8fHeVDm9nD17bSTtEtSffQ+iyD0DvKc/pnRqcqlQ2Av5XS58JO1n8DHwZwb6Aiu2xJTJY1yCwE5Cy8eFd2gchBq1qtLeBgjycbeHOh6Ve+LAppZFefkaNtIe3/bRfhDwVxhhsPDktCwzfe7Zy4UWrLx4uQpW5XMvY3c79IThjvNDHBzMZ+nVNFqbcsZd8NO6EaJ7l1BhEH3hvNvuBsZ6fBQtQf3U0gWXo+uXhAiODnTC5f5zR5ZaTRtfRetcFeu3KD4G//hB6fPnQKuzFxZrLK8HFyMBcHmfx5DQHBXbcYpmVNINQB7Zj3wcl6G1v1Svwk0RgPJSqvyF4jA9EkyInj6Tg5lVzc9Ole5ZPj//5DW4xdV1r0Ogr0dVVuaznuSX99mF3FvhL6Nd2qCavRF9/dgUqvvOwdzo+osXCXuVHVaKyO2qB45LRud1dR+lJENczoHRypprh4UvOkmGwFk2w1PCbhtmtfC3zrT3UzQHPWbIevm71ZGaS7RP/wnivgs5N0d5fllE4rXOQk2rh5yqvmcpAtcYmhRbabe5jVuty8rZIhn/kkIk7dqgW1SHyA4DPpIESIhMMJcvk0mn8+2+/+68U/VECGrFsT))\npackage_update: True\npackage_upgrade: True\npackage_reboot_if_required: True\nusers:\n- name: crdb\n  shell: /bin/bash\n  sudo:\n  - ALL=(ALL) NOPASSWD:ALL\n- default\n- name: crdb\n  ssh_authorized_keys:\n  - ((secret:v1:AAF42R6Wdfn6Eue7IyZa9mX/XWv4OBOeH+kPE3bGmRgfjb4axlWwMZ/6U6pOjLpzzYLKLb+QuSDE2mKOBM8rN/6uazbqSATWh0PUlX0cOdeKsgGUYtjDMmbviTlDlIBKvmfj6toWp7VMSPDy8TRgKNu9eMvK2bmjxOC3+lVDuqc19zlAeuD01vRD1CY6xLsHcl8fHeVDm9nD17bSTtEtSffQ+iyD0DvKc/pnRqcqlQ2Av5XS58JO1n8DHwZwb6Aiu2xJTJY1yCwE5Cy8eFd2gchBq1qtLeBgjycbeHOh6Ve+LAppZFefkaNtIe3/bRfhDwVxhhsPDktCwzfe7Zy4UWrLx4uQpW5XMvY3c79IThjvNDHBzMZ+nVNFqbcsZd8NO6EaJ7l1BhEH3hvNvuBsZ6fBQtQf3U0gWXo+uXhAiODnTC5f5zR5ZaTRtfRetcFeu3KD4G//hB6fPnQKuzFxZrLK8HFyMBcHmfx5DQHBXbcYpmVNINQB7Zj3wcl6G1v1Svwk0RgPJSqvyF4jA9EkyInj6Tg5lVzc9Ole5ZPj//5DW4xdV1r0Ogr0dVVuaznuSX99mF3FvhL6Nd2qCavRF9/dgUqvvOwdzo+osXCXuVHVaKyO2qB45LRud1dR+lJENczoHRypprh4UvOkmGwFk2w1PCbhtmtfC3zrT3UzQHPWbIevm71ZGaS7RP/wnivgs5N0d5fllE4rXOQk2rh5yqvmcpAtcYmhRbabe5jVuty8rZIhn/kkIk7dqgW1SHyA4DPpIESIhMMJcvk0mn8+2+/+68U/VECGrFsT))\nssh_pwauth: True\nruncmd:\n- hostnamectl set-hostname --pretty crdb_vm-mcm2571-259771773836\n- sudo service sshd restart\npackages:\n- chrony\n",
                "__dcSelfLink": "/resources/groups/3f14e002-ef03-4662-9104-65b89ea1aee9",
                "endpointType": "vsphere",
                "hasSnapshots": "False",
                "instanceUUID": "5004d3d5-8f3f-ed43-8b3c-62c564a4b1d6",
                "remoteAccess": {
                    "sshKey": "((secret:v1:AAF42R6Wdfn6Eue7IyZa9mX/XWv4OBOeH+kPE3bGmRgfjb4axlWwMZ/6U6pOjLpzzYLKLb+QuSDE2mKOBM8rN/6uazbqSATWh0PUlX0cOdeKsgGUYtjDMmbviTlDlIBKvmfj6toWp7VMSPDy8TRgKNu9eMvK2bmjxOC3+lVDuqc19zlAeuD01vRD1CY6xLsHcl8fHeVDm9nD17bSTtEtSffQ+iyD0DvKc/pnRqcqlQ2Av5XS58JO1n8DHwZwb6Aiu2xJTJY1yCwE5Cy8eFd2gchBq1qtLeBgjycbeHOh6Ve+LAppZFefkaNtIe3/bRfhDwVxhhsPDktCwzfe7Zy4UWrLx4uQpW5XMvY3c79IThjvNDHBzMZ+nVNFqbcsZd8NO6EaJ7l1BhEH3hvNvuBsZ6fBQtQf3U0gWXo+uXhAiODnTC5f5zR5ZaTRtfRetcFeu3KD4G//hB6fPnQKuzFxZrLK8HFyMBcHmfx5DQHBXbcYpmVNINQB7Zj3wcl6G1v1Svwk0RgPJSqvyF4jA9EkyInj6Tg5lVzc9Ole5ZPj//5DW4xdV1r0Ogr0dVVuaznuSX99mF3FvhL6Nd2qCavRF9/dgUqvvOwdzo+osXCXuVHVaKyO2qB45LRud1dR+lJENczoHRypprh4UvOkmGwFk2w1PCbhtmtfC3zrT3UzQHPWbIevm71ZGaS7RP/wnivgs5N0d5fllE4rXOQk2rh5yqvmcpAtcYmhRbabe5jVuty8rZIhn/kkIk7dqgW1SHyA4DPpIESIhMMJcvk0mn8+2+/+68U/VECGrFsT))",
                    "username": "crdb",
                    "authentication": "publicPrivateKey",
                },
                "resourceLink": "/resources/compute/0e8215ad-66fd-427c-9f64-c60d87b3de2b",
                "resourceName": "crdb_vm-mcm2571-259771773836",
                "resourcePool": "/resources/pools/4004ae581f4d5075-7f703c5265a63d87",
                "softwareName": "Ubuntu Linux (64-bit)",
                "vmFolderPath": "[wdc-w01-wdc-w01-vsan01] 6e8f0166-62ba-ee5b-073b-0c42a12a8150",
                "__computeHost": "True",
                "__computeType": "VirtualMachine",
                "componentType": "Cloud.vSphere.Machine",
                "datastoreName": "wdc-w01-wdc-w01-vsan01",
                "snapshotCount": "0",
                "totalMemoryMB": 16384,
                "__blueprint_id": "812304a6-5de3-4c8f-9370-ab337fcacb9d",
                "__endpointLink": "/resources/endpoints/b5c736bd-4aaa-4630-8778-21c0a56d89f0",
                "__endpointType": "vsphere",
                "cloneFromImage": "ubuntuTemplate-HWE",
                "computeHostRef": "ClusterComputeResource:domain-c8",
                "__deployment_id": "ce81b7d1-3eba-44df-8c10-2b5443ea17a1",
                "__imageOsFamily": "LINUX",
                "__placementLink": "/resources/compute/b8d8c4dd-52d8-40a2-a008-1cb940b75fcb",
                "computeHostType": "ClusterComputeResource",
                "environmentName": "On premise",
                "__bootDiskSizeMB": "61440",
                "__deploymentLink": "/resources/deployments/ce81b7d1-3eba-44df-8c10-2b5443ea17a1",
                "customizeGuestOs": "True",
                "resourceDescLink": "/resources/compute-descriptions/4c1fa278-9eba-457b-889d-c1a329c9a67f",
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
                "cloudConfigSettings": {
                    "deploymentFailOnCloudConfigRuntimeError": True
                },
                "__allocation_request": "True",
                "areVMActionsDisabled": "False",
                "__memoryHotAddEnabled": "False",
                "__blueprint_request_id": "136db825-0b23-4642-8a7b-4c791d4ec86b",
                "__vmw:provisioning:org": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d",
                "_clusterAllocationSize": "1",
                "__blueprint_resource_id": "0e8215ad-66fd-427c-9f64-c60d87b3de2b",
                "__imageBootDiskSizeInMB": "61440",
                "__imageDisksTotalSizeMB": "880640",
                "__composition_context_id": "ce81b7d1-3eba-44df-8c10-2b5443ea17a1",
                "__ownerComputeResourceId": "ClusterComputeResource:domain-c8",
                "__projectPlacementPolicy": "DEFAULT",
                "__blueprint_resource_name": "crdb_vm[1]",
                "__blueprint_resource_type": "Cloud.vSphere.Machine",
                "zone_overlapping_migrated": "True",
                "__attachedDisksTotalSizeMB": "0",
                "__ownerComputeResourceLink": "/resources/compute/b8d8c4dd-52d8-40a2-a008-1cb940b75fcb",
                "__vmw:provisioning:project": "087a503a-0da8-4254-9714-15094422021c",
                "__blueprint_request_event_id": "2000995e-1660-47d8-a762-f9111b273e00",
                "__groupResourcePlacementLink": "/provisioning/resources/group-placements/087a503a-0da8-4254-9714-15094422021c-d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
                "__vmw:provisioning:blueprint": "812304a6-5de3-4c8f-9370-ab337fcacb9d",
                "__vmw:provisioning:cloudZone": "d1eef1e5-6f9c-4b1b-b8ef-ab0d62e53b9b",
                "__vmw:provisioning:requester": "provisioning-hamskor2of8iplc9@provisioning-client.local",
                "__vmw:provisioning:deployment": "ce81b7d1-3eba-44df-8c10-2b5443ea17a1",
                "__vmw:provisioning:imageMapping": "032ded8d-86a7-4229-b7ad-dc8a1ce3ce6d-7ba9292a-4053-4d3a-b3e9-f26437a03e88",
                "__allowTerraformCloudzoneMapping": "True",
                "__blueprint_resource_dependencies": '["infra_net"]',
                "__blueprint_deployment_resource_id": "0e8215ad-66fd-427c-9f64-c60d87b3de2b",
                "__blueprint_resource_last_operation": "create",
                "__vmw:provisioning:blueprintResourceName": "crdb_vm",
                "__computeConfigContentPhoneHomeShouldWait": "False",
                "__blueprint_resource_dependent_resource_ids": '["1e857adc-73ec-43e5-a2c4-c3cf3573889b","321029c6-2e42-4abe-83e5-899edc91adf5","0142121f-10ad-4b8f-b631-dc76f82a9a17"]',
                "__blueprint_resource_dependency_resource_ids": '["05f3e14a-0278-4fcd-b691-d6f1998b308c"]',
                "__blueprint_resource_allocation_dependent_ids": "[]",
                "__ext:RequestBrokerState:STARTED:RESOURCE_COUNTED": "True",
                "__ext:ComputeReservationTaskState:STARTED:SELECTED": "True",
                "__computeConfigContentDeploymentFailOnCloudConfigRuntimeError": "True",
                "__ext:ComputeAllocationTaskState:STARTED:START_COMPUTE_ALLOCATION": "True",
            },
        ],
        "groups": ["crdb", "bar"],
    }

    class Passthrough(object):
        def __init__(self):
            pass

        @classmethod
        def getSecret(cls, x):
            return x

    handler(Passthrough(), test)
