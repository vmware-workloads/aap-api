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
        variables = {"ansible_host": host.get("address")}
        for key, value in host_variables.items():
            variables[key] = value

        self.id = host_id
        self.name = host.get("resourceName")
        self.variables = json.dumps(variables)
        self.groups = host_groups



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

    def __delete(self, path: str, id: int):
        url = urllib.parse.urljoin(self.base_url, url=path)
        delete_url = urllib.parse.urljoin(url, url=str(id))
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self._token,
        }
        response = requests.delete(url=delete_url, headers=headers, verify=self.ssl_verify)
        response.raise_for_status()
        if response.status_code not in [202]:
            return "RuntimeError in delete:" + str(response.status_code)

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

    def get_job_status(self, job: dict):
        """Retrieve the status of a specific job."""
        path_job_url = job.get("url")
        response = self.__get(path=path_job_url)
        return response.get("status")


    def lookup_inventory(
        self, name: str, organization_id: int = DEFAULT_ORGANIZATION_ID
    ) -> dict:
        """Create a new inventory and add hosts to the inventory"""
        inventory = self.find_inventory_by_name(name=name)
        return inventory

    def delete_inventory(self, inventory_id: int):  
        """Delete an inventory"""
        response = self.__delete(path=self.PATH_INVENTORY, id=inventory_id)


    def launched_job_template(self, job_template_id: dict, inventory_id: int) -> dict:
        """Launch a job template with a specific inventory."""
        path = self.PATH_JOB_TEMPLATES + str(job_template_id)
        data = {
            "inventory": inventory_id,
        }
        response = self.__post(path=path, data=data)
        pass
        return response

    def lookup_inventory(
        self, name: str, organization_id: int = DEFAULT_ORGANIZATION_ID
    ) -> dict:
        """lookup inventory"""
        inventory = self.find_inventory_by_name(name=name)
        return inventory

    def delete_inventory(self, inventory_id: int):  
        """Delete an inventory"""
        response = self.__delete(path=self.PATH_INVENTORY, id=inventory_id)       


    def get_job_status(self, job: dict):
        """Retrieve the status of a specific job."""
        path_job_url = job.get("url")
        response = self.__get(path=path_job_url)
        return response.get("status")

    def wait_for_job_completion(self, job: dict, interval: int = 5, max_timeout_seconds: int = 300):
        """Wait for a job to complete, checking the status at the specified interval."""
        for _ in range(0, max_timeout_seconds, interval):
            status = self.get_job_status(job=job)
            if status in ('successful', 'failed', 'error', 'canceled'):
                return status
            else:
                print(f"Job {job.get('id')} is {status}. Waiting {interval} seconds out of {max_timeout_seconds}.")
                time.sleep(interval)
                
    def clean(self):
        response = self.__delete(path=self.PATH_TOKEN, id=self._token_id)


def handler(context, inputs) -> dict:
    # Ansible Automation Platform Configuration
    base_url = inputs["base_url"]
    username = inputs["username"]
    password = context.getSecret(inputs["password"])
    ssl_verify = inputs.get("ssl_verify", True)
    verbose = inputs.get("verbose", False)

    # Ansible Automation Platform Inventory
    organization_name = inputs.get("organization_name", "Default")
    inventory_name = inputs.get("inventory_name", "aap-api")
    job_template_name = inputs.get("job_template_name")
    

    if verbose:
        print(f"base_url: '{base_url}'")
        print(f"username: '{username}'")
        print(f"ssl_verify: '{ssl_verify}'")
        print(f"inventory_name: '{inventory_name}'")
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

    # Get the inventory id
    # If an inventory with that exact name exists, we return its id.
    aap_inventory = aap.lookup_inventory(name=inventory_name, organization_id=aap_organization.get("id"))

    # Find the job template
    aap_job_template = aap.find_job_template_by_name(name=job_template_name)
    if aap_job_template is None:
        raise ValueError(f"Could not find a job template with name '{job_template_name}'")

    aap_job = aap.launched_job_template(job_template_id=aap_job_template.get("id"), inventory_id=aap_inventory.get("id"))

    # Check the status of any running jobs
    aap_job_status = aap.get_job_status(job=aap_job)
    
    # Cleanup: delete the access token_id
    aap_cleanup = aap.clean()

    print(f"job status: '{aap_job_status}")
    
    return {
        "base_url": base_url,
        "username": username,
        "password": password,
        "ssl_verify": ssl_verify,
        "inventory_id": aap_inventory.get("id"),
        "job_template_id": aap_job_template.get("id"),
        "inventory_name": inventory_name,
        "job_template_name": job_template_name,
        "organization_name": organization_name,
        "status" : aap_job_status
    }
