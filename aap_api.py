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
    test = json.load(open("test-02.json"))

    class Passthrough(object):
        def __init__(self):
            pass

        @classmethod
        def getSecret(cls, x):
            return x

    handler(Passthrough(), test)
