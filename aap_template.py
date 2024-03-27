import requests
import urllib3
import urllib.parse


from requests.auth import HTTPBasicAuth
from typing import List, Union


class AapTemplate(object):
    PATH_INVENTORY = "api/v2/inventories/"
    PATH_TOKEN = "api/v2/tokens/"
    PATH_TEMPLATES = "api/v2/job_templates/"

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
    def __find(cls, name: str, results: list) -> List[dict]:
        # Search for exact name matches
        # Note: We have to search because a search for 'foo' would return entries
        #       that include 'foo', 'foobar', 'myfoo'.
        return list(filter(lambda x: x.get("name") == name, results))

    def find_job_template_by_name(self, name: str) -> Union[None, int]:
        """Search for a job template by name."""
        path = self.PATH_TEMPLATES + f"?search={name}"
        response = self.__get(path=path)
        results = response.get("results", [])
        matches = self.__find(name=name, results=results)

        # We should only have one match
        if len(matches) > 1:
            raise RuntimeError(f"Found {len(matches)} templates with name {name}.")

        # Return 'None' if none found
        if len(matches) < 1:
            return None

        # Return the inventory id
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

    def launch_job_template(self, job_template_id: int, inventory_id: int) -> dict:
        """Launch a job template with a specific inventory."""
        path = f"api/v2/job_templates/{job_template_id}/launch/"
        data = {
            "inventory": inventory_id,
        }
        response = self.__post(path=path, data=data)

        return response


def handler(context, inputs):
    # Ansible Automation Platform configuration
    base_url = inputs["base_url"]
    username = inputs["username"]
    password = context.getSecret(inputs["password"])
    ssl_verify = inputs.get("ssl_verify", True)

    # Ansible Automation Platform Inventory
    job_template_name = inputs.get("template_name")
    inventory_name = inputs.get("inventory_name")

    if not ssl_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    aap = AapTemplate(
        base_url=base_url, username=username, password=password, ssl_verify=ssl_verify
    )
    job_template_id = aap.find_job_template_by_name(name=job_template_name)
    inventory_id = aap.find_inventory_by_name(name=inventory_name)
    result = aap.launch_job_template(job_template_id=job_template_id, inventory_id=inventory_id)
    return "foo"


if __name__ == "__main__":
    test = {
        "base_url": "https://wdc-ansible.vcf01.isvlab.vmware.com",
        "username": "admin",
        "password": "P@ssword123!",
        "ssl_verify": False,
        "template_name": "CRDB Template",
        "inventory_name": "CRDB_CLUSTER_01",
    }

    class Passthrough(object):
        def __init__(self):
            pass

        @classmethod
        def getSecret(cls, x):
            return x

    handler(Passthrough(), test)
