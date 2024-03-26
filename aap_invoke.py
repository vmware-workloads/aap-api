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


class AapApi(object):
    PATH_TOKEN = "api/v2/tokens/"
    PATH_INVENTORY = "api/v2/inventories/"
    PATH_ORGANIZATION = "api/v2/organizations/"
    PATH_GROUPS = "api/v2/groups/"
    PATH_HOSTS = "api/v2/hosts/"
    PATH_BULK_HOST_CREATE = "api/v2/bulk/host_create/"
    PATH_GROUP_ADD = Template('api/v2/groups/$group_id/hosts/')
    DEFAULT_ORGANIZATION_ID = 1

    def __init__(
        self, base_url: str, username: str, password: str, ssl_verify: bool = True
    ):

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
        response = requests.post(url=url, headers=headers, json=data, verify=self.ssl_verify)
        response.raise_for_status()
        if response.status_code not in [204]:
            return response.json()

    @classmethod
    def __find(cls, name: str, results: list) -> list:
        return list(
            filter(lambda x: x.get("name") == name, results)
        )

    def get_organization_id(self, name: str) -> int:
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

    def get_inventory_id(self, name: str) -> Union[None, int]:
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

    def get_group_id(self, name: str, inventory_id: int) -> Union[None, int]:
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
            raise RuntimeError(f"Found {len(matches)} groups with name {name} in inventory {inventory_id}.")

        # Return 'None' if none found
        if len(matches) < 1:
            return None

        # Return the group id
        return matches[0].get("id")

    def create_inventory(
        self, name: str, organization_id: int = DEFAULT_ORGANIZATION_ID
    ) -> int:
        """Create a new inventory and add hosts to the inventory"""
        inventory_id = self.get_inventory_id(name=name)
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
        group_id = self.get_group_id(name=name, inventory_id=inventory_id)
        if group_id is not None:
            return group_id

        data = {
            "name": name,
            "description": "" if description is None else description,
            "inventory": inventory_id,
        }
        response = self.__post(path=self.PATH_GROUPS, data=data)
        return response.get("id")

    def add_hosts_to_inventory(self, inventory_id: int, hosts: List[AapHost]) -> List[int]:
        """Add hosts to am inventory
        ref. https://www.redhat.com/en/blog/bulk-api-in-automation-controller
        """
        data = {
            "inventory": inventory_id,
            "hosts": [vars(host) for host in hosts],
        }
        response = self.__post(path=self.PATH_BULK_HOST_CREATE, data=data)
        return [host.get('id') for host in response.get('hosts', [])]

    def add_host_to_group(self, group_id: int, host_id: int) -> None:
        """Add a host to the specified group."""
        group_path = self.PATH_GROUP_ADD.substitute({'group_id': group_id})
        data = {
            "id": host_id
        }
        self.__post(path=group_path, data=data)

    def add_hosts_to_groups(self, group_ids: List[int], host_ids: List[int]) -> None:
        """Add hosts to the specified groups."""
        for group_id in group_ids:
            for host_id in host_ids:
                self.add_host_to_group(group_id=group_id, host_id=host_id)


def handler(context, inputs):
    # Ansible Automation Platform configuration
    base_url = inputs["base_url"]
    username = inputs["username"]
    password = context.getSecret(inputs["password"])
    ssl_verify = inputs.get("ssl_verify", True)

    # Ansible Automation Platform Inventory
    inventory_name = inputs.get("inventory_name", "aap-api-inventory")
    hosts = [AapHost(**host) for host in inputs.get("hosts", [])]
    groups = inputs.get("groups", [])

    if not ssl_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    aap = AapApi(
        base_url=base_url, username=username, password=password, ssl_verify=ssl_verify
    )
    organization_id = aap.get_organization_id(name="Default")
    inventory_id = aap.create_inventory(
        name=inventory_name, organization_id=organization_id
    )
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
                "hostName": "foo1",
                "networks": [{"address": "192.168.1.1"}],
                "tags": [
                    {"key": "tag1", "value": "value"},
                    {"key": "tag2", "value": 2},
                    {"key": "tag3", "value": True},
                ],
            },
            {
                "hostName": "foo2",
                "networks": [{"address": "192.168.1.2"}],
                "tags": [
                    {"key": "tag1", "value": "value"},
                    {"key": "tag2", "value": 2},
                    {"key": "tag3", "value": True},
                ],
            },
            {
                "hostName": "foo3",
                "networks": [{"address": "192.168.1.3"}],
                "tags": [
                    {"key": "tag1", "value": "value"},
                    {"key": "tag2", "value": 2},
                    {"key": "tag3", "value": True},
                ],
            },
        ],
        "groups": ["crdb", "bar"]
    }

    class Passthrough(object):
        def __init__(self):
            pass

        @classmethod
        def getSecret(cls, x):
            return x

    handler(Passthrough(), test)
