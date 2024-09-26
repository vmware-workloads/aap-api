import json
import re
import requests
import time

import urllib3
import urllib.parse
import string

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

        if host_variables is not None:
            variables = host_variables
        else:
            variables = {}

        if host_groups is None:
            host_groups = []

        # ansible_host is minimally required so Ansible Automation Platform can
        # reach the system to be configured. Typically, the system is not in DNS.
        variables["ansible_host"] = host.get("address")
        variables["inventory_hostname"] = host.get("hostName", "")

        self.id = host_id

        # aria automation appends [x] when creating VM using count. this is a problem
        # because these names do not adhere to host naming convention. We swap the '[' and ']'
        # characters to '-' since this is what set-hostname is also doing.
        self.name = re.sub(r'(\[|\])', '', host.get("resourceName"))
        self.variables = json.dumps(variables)
        self.groups = host_groups

    @classmethod
    def create_app_hosts(cls, hosts: list, host_variables: dict, host_groups: dict) -> List['AapHost']:
        aap_hosts = []
        for host_list in hosts:
            # When count == 1, aria returns a dict
            # When count > 1, aria returns a list of dict
            if not isinstance(host_list, list):
                host_list = [host_list]
            for host in host_list:
                # In some cases the VM name is appended with [0], [1], [n] so we need
                # to strip that off.
                name = re.sub(r'(\[\d+\])*', '', host.get("name"))
                variables = host_variables.get(name, {})
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

    def lookup_inventory(
        self, name: str, organization_id: int = DEFAULT_ORGANIZATION_ID
    ) -> dict:
        """Lookup inventory"""
        inventory = self.find_inventory_by_name(name=name)
        return inventory

    def delete_inventory(self, inventory_id: int):  
        """Delete an inventory"""
        response = self.__delete(path=self.PATH_INVENTORY, id=inventory_id)     

    def create_inventory(
        self, name: str, variables: dict = None, organization_id: int = DEFAULT_ORGANIZATION_ID
    ) -> dict:
        """Create a new inventory and add hosts to the inventory"""
        inventory = self.find_inventory_by_name(name=name)
        if inventory is None:
            data = {
                "name": name,
                "description": "Created via Aria Automation API",
                "organization": organization_id,
            }
            if variables is not None:
                data['variables'] = json.dumps(variables)
            response = self.__post(path=self.PATH_INVENTORY, data=data)
            inventory = {
                "name": name,
                "id": response.get("id")
            }
        return inventory

    def create_group(self, name: str, inventory_id: int, variables: dict = None, description: str = None) -> dict:
        """Create a new group"""
        group = self.find_group_by_name(name=name, inventory_id=inventory_id)
        if group is None:
            data = {
                "name": name,
                "description": "" if description is None else description,
                "inventory": inventory_id,
            }
            if variables.get(name) is not None:
                data['variables'] = json.dumps(variables.get(name))
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
        for _ in range(0, max_timeout_seconds, interval):
            status = self.get_job_status(job=job)
            if status in ('successful', 'failed', 'error', 'canceled'):
                return status
            else:
                print(f"Job {job.get('id')} is {status}. Waiting {interval} seconds out of {max_timeout_seconds}.")
                time.sleep(interval)

    def clean(self):
        response = self.__delete(path=self.PATH_TOKEN, id=self._token_id)


def nested_keys_exist(element: dict, *keys: string):
    """
        Check if *keys (nested) exists in `element` (dict).

        Args:
            element (dict): Dictionary to search
            *keys (string): Ordered key[s] to look for in `element`
        Returns:
            bool: True if key[s] exists, False if any are missing
    """
    if not isinstance(element, dict):
        raise AttributeError('nested_keys_exist() expects dict as first argument.')
    if len(keys) == 0:
        raise AttributeError('nested_keys_exist() expects at least two arguments, one given.')

    _element = element
    for key in keys:
        try:
            _element = _element[key]
        except KeyError:
            return False
    return True


def handler(context, inputs):
    """
        Entrypoint for ABX <-- VCF automation should be setup to have this as the 'main function'

        Args:
            context: The context object containing information about the ABX event.
            inputs: The inputs provided for the ABX event.

        Returns:
            outputs: The outputs generated by the ABX handler.
    """    

    # Setup Ansible Automation Platform credentials

    base_url = context.getSecret(inputs["aapURL"])
    username = context.getSecret(inputs["aapUser"])
    password = context.getSecret(inputs["aapPass"])
    ssl_verify = inputs.get("ssl_verify", True)
    verbose = inputs.get("verbose", False)

    # Populate the output json with the input values
    # this will be our return value
    outputs = inputs

    # Set the Ansible Automation Platform org name to 'Default'
    # And obtain the template name to run
    organization_name = inputs.get("organization_name", "Default")
    job_template_name = inputs.get("job_template_name")

    # Get the inventory name and other variables for the Ansible Automation Platform
    inventory_name = inputs.get("inventory_name", "aap-api")
    hosts = inputs.get("hosts", [])
    groups = [group_name for group_name in inputs.get("host_groups", {}).keys()]
    host_groups = invert_dict(d=inputs.get("host_groups", {}), name="resourceName")
    host_variables = inputs.get("host_variables", {})
    group_variables = inputs.get("group_variables", {})
    inventory_variables = inputs.get("inventory_variables", {})

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

###

   #
   # Get the operation type from the automation engine.
   # This can be either 'create', 'read', 'update' or 'delete'
   #

    abx_operation = None
    if nested_keys_exist(inputs, "__metadata", "operation"):
        abx_operation = inputs["__metadata"]["operation"]


   # logic for the 'create' operation
    if abx_operation == "create":
        outputs['create'] = True                 
        
        # Find the job template
        aap_job_template = aap.find_job_template_by_name(name=job_template_name)
        if aap_job_template is None:
            raise ValueError(f"Could not find a job template with name '{job_template_name}'")

        # Get the inventory id
        # If an inventory with that exact name exists, we return its id.
        # If an inventory with that exact name does not exist, we create one and return the id.
        aap_inventory = aap.create_inventory(name=inventory_name,
                                             variables=inventory_variables,
                                             organization_id=aap_organization.get("id"))    

        # Get the group ids
        # If a group with the exact name exists, we return its id.
        # If a group with the exact name does not exist, we create one and return the id.
        aap_groups = [aap.create_group(name=group,
                                       variables=group_variables,
                                       inventory_id=aap_inventory.get("id")) for group in groups]

        # Add the hosts to the inventory
        # The host names *must* be unique within the inventory.
        aap_hosts = aap.add_hosts_to_inventory(inventory_id=aap_inventory.get("id"),
                                               hosts=aap_hosts)

        # Add the hosts to inventory groups
        aap.add_hosts_to_groups(aap_hosts=aap_hosts,
                                aap_groups=aap_groups)

        # Start the job template with the created inventory
        aap_job = aap.launch_job_template(job_template_id=aap_job_template.get("id"),
                                          inventory_id=aap_inventory.get("id"))

        # Wait for the job to complete
        # WE NEED A TIMEOUT HERE     
        aap.wait_for_job_completion(job=aap_job)

        # populate the return structure
        outputs["inventory_id"] = aap_inventory.get("id"),
        outputs["job_template_id"] = aap_job_template.get("id")
        outputs["aap_job"] =  aap_job
        outputs["aap_organization"] = aap_organization
    

   # logic for the 'update' operation            
    elif abx_operation == "update":
        # update logic goes here
        print("update logic goes here")

        # populate the return structure
        #outputs["inventory_id"] = aap_inventory.get("id"),
        #outputs["job_template_id"] = aap_job_template.get("id")



   # logic for the 'read' operation
    elif abx_operation == "read":

        # Get the inventory id
        # If an inventory with that exact name exists, we return its id.
        aap_inventory = aap.lookup_inventory(name=inventory_name, organization_id=aap_organization.get("id"))

        # Find the job template
        aap_job_template = aap.find_job_template_by_name(name=job_template_name)
        if aap_job_template is None:
            raise ValueError(f"Could not find a job template with name '{job_template_name}'")

        # populate the return structure
        outputs["inventory_id"] = aap_inventory.get("id"),
        outputs["job_template_id"] = aap_job_template.get("id")
        outputs["aap_organization"] = aap_organization        


   # logic for the 'delete' operation
    elif abx_operation == "delete":

        # Get the inventory id
        # If an inventory with that exact name exists, we return its id.
        aap_inventory = aap.lookup_inventory(name=inventory_name, organization_id=aap_organization.get("id"))

        # Delete the inventory
        aap_inventory_deleted = aap.delete_inventory(inventory_id=aap_inventory.get("id"))

        # populate the return structure
        outputs["inventory_id"] = aap_inventory.get("id"),


####


    
    # Cleanup: delete the ansible automation platform access token
    aap_cleanup = aap.clean()
    
    return outputs


if __name__ == "__main__":
    test = json.load(open("test-05.json"))

    class Passthrough(object):
        def __init__(self):
            pass

        @classmethod
        def getSecret(cls, x):
            return x

    handler(Passthrough(), test)

