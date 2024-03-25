import requests
import uuid
import urllib3
import urllib.parse

from requests.auth import HTTPBasicAuth
from typing import List, Union


class AapHost(object):
    def __init__(
        self,
        name: str,
        variables: str = None,
        instance_id: str = None,
        description: str = None,
        enabled: bool = None,
    ):
        self.name = name

        if variables is not None:
            self.variables = variables

        if instance_id is not None:
            self.instance_id = instance_id

        if description is not None:
            self.description = description

        if enabled is not None:
            self.enabled = enabled



class AapApi(object):
    URL_TOKEN = "api/v2/tokens/"
    URL_INVENTORY = "api/v2/inventories/"
    URL_ORGANIZATION = "api/v2/organizations/"
    URL_HOSTS = "api/v2/hosts/"
    URL_BULK_HOST_CREATE = "api/v2/bulk/host_create/"
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
            url=urllib.parse.urljoin(self.base_url, url=self.URL_TOKEN),
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

    def get_organization_id(self, name: str) -> int:
        """Search for an organization and return its ID"""
        url = urllib.parse.urljoin(
            self.base_url, url=self.URL_ORGANIZATION + f"?search={name}"
        )
        headers = {
            "Authorization": "Bearer " + self._token,
        }
        response = requests.get(url=url, headers=headers, verify=self.ssl_verify)
        response.raise_for_status()

        # Find the organization
        # Note: We have to search because a search for 'foo' would return entries
        #       that include 'foo', 'foobar', 'thatfoo'.
        results = response.json().get("results", [])
        matches = list(
            filter(
                lambda organization: organization.get("name") == name, results
            )
        )

        # Return organization ID if found, otherwise default
        if len(matches) < 1:
            return self.DEFAULT_ORGANIZATION_ID
        return matches[0].get("id")

    def get_inventory_id(self, name: str) -> Union[None, int]:
        """Search for an inventory and return its ID"""
        url = urllib.parse.urljoin(
            self.base_url, url=self.URL_INVENTORY + f"?search={name}"
        )
        headers = {
            "Authorization": "Bearer " + self._token,
        }
        response = requests.get(url=url, headers=headers, verify=self.ssl_verify)
        response.raise_for_status()

        # Find the inventory
        # Note: We have to search because a search for 'foo' would return entries
        #       that include 'foo', 'foobar', 'thatfoo'.
        # Get the required data
        results = response.json().get("results", [])
        matches = list(filter(lambda inventory: inventory.get("name") == name, results))

        # Return inventory ID if found
        if len(matches) < 1:
            return None
        return matches[0].get("id")

    def create_inventory(
        self, name: str, organization_id: int = DEFAULT_ORGANIZATION_ID
    ):
        """Create a new inventory and add hosts to the inventory"""

        if self.get_inventory_id(name=name) is not None:
            print(f"Inventory name { name } already exists.")
            name = f"{ name }-{str(uuid.uuid1())}"
            print(f"Generated unique inventory name {name}.")

        url = urllib.parse.urljoin(self.base_url, url=self.URL_INVENTORY)
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self._token,
        }
        data = {
            "name": name,
            "description": "Created via Aria Automation API",
            "organization": organization_id,
        }
        response = requests.post(
            url=url, headers=headers, json=data, verify=self.ssl_verify
        )
        response.raise_for_status()
        inventory_id = response.json().get("id")
        return inventory_id

    def add_hosts_to_inventory(self, inventory_id: int, hosts: List[AapHost]):
        """Add hosts to am inventory
        ref. https://www.redhat.com/en/blog/bulk-api-in-automation-controller
        """
        url = urllib.parse.urljoin(self.base_url, url=self.URL_BULK_HOST_CREATE)
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self._token,
        }
        data = {
            "inventory": inventory_id,
            "hosts": [vars(host) for host in hosts],
        }
        response = requests.post(
            url=url, headers=headers, json=data, verify=self.ssl_verify
        )
        response.raise_for_status()


def handler(context, inputs):
    base_url = inputs["base_url"]
    username = inputs["username"]
    password = context.getSecret(inputs["password"])
    ssl_verify = inputs.get('ssl_verify', True)
    inventory_name = inputs.get('inventory_name', 'aap-api-inventory')
    hosts = [AapHost(**host) for host in inputs.get('hosts', [])]

    if not ssl_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    aap = AapApi(
        base_url=base_url, username=username, password=password, ssl_verify=False
    )
    organization_id = aap.get_organization_id(name="Default")
    inventory_id = aap.create_inventory(name=inventory_name, organization_id=organization_id)
    aap.add_hosts_to_inventory(inventory_id=inventory_id, hosts=hosts)


if __name__ == "__main__":
    test = {
        "base_url": "https://wdc-ansible.vcf01.isvlab.vmware.com",
        "username": "admin",
        "password": "P@ssword123!",
        "ssl_verify": False,
        "inventory_name": "foobar",
        "hosts": [
            {"name": "foo1"},
            {"name": "foo2"},
            {"name": "foo3"}
        ],
    }

    class Passthrough(object):
        def __init__(self):
            pass

        @classmethod
        def getSecret(cls, x):
            return x

    handler(Passthrough(), test)





