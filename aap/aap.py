import logging

import requests
import time
import urllib3
import urllib.parse

from requests.auth import HTTPBasicAuth
from typing import List, Type, TypeVar, ParamSpec

from . import AriaInventory, AriaHosts, AriaHost
from .aap_groups import AapGroups
from .aap_hosts import AapHosts
from .aap_job import AapJob
from .aap_job_template import AapJobTemplate
from .aap_inventory import AapInventory
from .aap_host import AapHost
from .aap_group import AapGroup
from .aap_token import AapToken
from .aap_organization import AapOrganization
from .aria_group import AriaGroup
from .aria_group_mapping import AriaGroupMapping
from .aria_groups import AriaGroups

DEFAULT_ORGANIZATION = "Default"

# Aria has a max timeout of 900 seconds (15 minutes).
# If an action doesn't complete its execution within 15 minutes, then it is marked as failed.
# Specifying the timeout value to be 14 minutes, so we try to complete the deployment request
# operation within the max timeout of aria which is 15 minutes.
# If the create db operation takes longer, then we don't want to let vRA think it failed.
MAX_TIMEOUT = 840  # 14 minutes


log = logging.getLogger(__name__)

T = TypeVar("T")
P = ParamSpec("P")


class Aap:

    def __init__(self, base_url: str, username: str, password: str, ssl_verify: bool = True):
        log.debug(f"__init__: (base_url: '{base_url}', username: '{username}', ssl_verify: '{ssl_verify}')")
        self.base_url = base_url
        self.username = username
        self.password = password
        self.ssl_verify = ssl_verify

        # Basic Auth credentials
        self._auth = HTTPBasicAuth(username=self.username, password=self.password)

        # Initialize
        self.api_url = None
        self._aap_token = None

    def __repr__(self):
        return (f"{self.__class__}: ["
                f"base_url: '{self.base_url}', "
                f"username: '{self.username}', "
                f"ssl_verify: '{self.ssl_verify}']")

    def __enter__(self):
        log.debug(f"__enter__")
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        log.debug(f"__exit__")
        self.disconnect()

    @classmethod
    def from_aria(cls, context: object, inputs: dict) -> "Aap":
        """
            Creates an Aap object from Aria context and inputs

            Args:
                context (dict): Dictionary to search
                inputs (list[str]): Ordered key[s] to look for in `element`

            Returns:
                dict: Contains the base_url, username, password, and ssl_verify
        """
        log.debug(f"from_aria'")
        try:

            # Aria action constants can only be passed as string...
            ssl_verify = inputs.get("aapSSL", False)
            if isinstance(ssl_verify, str):
                ssl_verify = ssl_verify.lower() == "true"

            # noinspection PyUnresolvedReferences
            return cls(
                base_url=inputs["aapURL"],
                username=inputs["aapUser"],
                password=context.getSecret(inputs["aapPass"]),
                ssl_verify=ssl_verify,
            )
        except KeyError as e:
            msg = "Failed to get a required credential parameter in inputs"
            log.critical(msg)
            raise ValueError(msg) from e

    def connect(self):
        """
            Connects and authenticates to an Ansible Automation Platform. This method
            obtains and sets an authentication token.
        """
        log.info(f"connect: Connecting to {self.base_url}'")

        # Disable SSL warning if we are not verifying the ansible host SSL certificate
        if not self.ssl_verify:
            log.debug(f"connect: Disabling insecure request warnings'")
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Set API endpoint
        self.__set_api_endpoint()

        # Create URL
        url = urllib.parse.urljoin(self.api_url, url=AapToken.path())
        log.debug(f"connect: Connection url: '{url}'")

        # POST for OATH2 token
        response = requests.post(
            url=url,
            auth=self._auth,
            verify=self.ssl_verify,
        )

        # Check for successful token creation
        response.raise_for_status()

        # Get the required data
        try:
            self._aap_token = AapToken(**(response.json()))
            log.info(f"connect: Connection successful")
        except KeyError as e:
            msg = f"connect: No token in response."
            log.critical(msg)
            raise RuntimeError(msg) from e

    def disconnect(self):
        """
            Disconnects from an Ansible Automation Platform. This method deletes the
            authentication token.
        """
        log.info(f"disconnect: Disconnecting from '{self.base_url}'")
        if self._aap_token is not None:
            log.debug(f"disconnect: Deleting token ao '{self._aap_token.url}'")
            self.__delete(path=self._aap_token.url)

    def __set_api_endpoint(self):
        """
            Discovers and sets the API. Depending on the implementation and version,
            the API URL may change.
        """
        log.debug(f"__set_api_endpoint: Checking API URL for '{self.base_url}'")

        # Get API
        response = requests.get(
            url=urllib.parse.urljoin(self.base_url, url="api/"),
            verify=self.ssl_verify,
        )

        # Check for successful connection
        response.raise_for_status()

        # Get data
        data = response.json()

        # Multiple APIs
        if 'apis' in data:
            if 'controller' in data['apis']:

                # Controller API
                controller_api_url = data['apis']['controller']

                # Get controller API
                response = requests.get(
                    url=urllib.parse.urljoin(self.base_url, url=controller_api_url),
                    verify=self.ssl_verify,
                )

                # Check for successful connection
                response.raise_for_status()

                # Update data
                data = response.json()


        if 'current_version' not in data:
            raise RuntimeError(f"Could not find the current controller API URL")

        # Get current controller API
        self.api_url = urllib.parse.urljoin(self.base_url, data['current_version'])

    def __get(self, path: str) -> dict:
        log.debug(f"__get: (path: '{path}')")

        if self._aap_token is None:
            msg = "__get: Token is not initialized"
            log.critical(msg)
            raise RuntimeError(msg)

        # Create headers
        headers = {
            "Authorization": f"Bearer {self._aap_token.token}",
        }

        # Create URL
        url = urllib.parse.urljoin(self.api_url, url=path)
        log.debug(f"__get: url: '{url}'")

        # HTTP(s) GET
        response = requests.get(url=url, headers=headers, verify=self.ssl_verify)
        response.raise_for_status()
        if response.status_code not in [200, 202, 204]:
            msg = f"Unexpected status in requests.get: : {str(response.status_code)} - {response.text}"
            log.error(msg)
            raise RuntimeError(msg)

        return response.json()

    def __post(self, path: str, data: dict) -> dict:
        log.debug(f"__post: (path: '{path}', data: '{data}')")

        if self._aap_token is None:
            msg = "__post: Token is not initialized"
            log.critical(msg)
            raise RuntimeError(msg)

        # Create headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._aap_token.token}",
        }

        # Create URL
        url = urllib.parse.urljoin(self.api_url, url=path)
        log.debug(f"__post: url: '{url}'")

        response = requests.post(
            url=url,
            headers=headers,
            json=data,
            verify=self.ssl_verify
        )
        response.raise_for_status()

        if response.status_code not in [204]:
            return response.json()

    def __patch(self, path: str, data: dict) -> dict:
        log.debug(f"__patch: (path: '{path}', data: '{data}')")

        if self._aap_token is None:
            msg = "__patch: Token is not initialized"
            log.critical(msg)
            raise RuntimeError(msg)

        # Create headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._aap_token.token}",
        }

        # Create URL
        url = urllib.parse.urljoin(self.api_url, url=path)
        log.debug(f"__patch: url: '{url}'")

        response = requests.patch(
            url=url,
            headers=headers,
            json=data,
            verify=self.ssl_verify
        )
        response.raise_for_status()
        if response.status_code not in [204]:
            return response.json()

    def __delete(self, path: str):
        log.debug(f"__delete: (path: '{path}')")

        if self._aap_token is None:
            msg = "__delete: Token is not initialized"
            log.critical(msg)
            raise RuntimeError(msg)

        # Create headers
        headers = {
            "Authorization": f"Bearer {self._aap_token.token}",
        }

        # Create URL
        url = urllib.parse.urljoin(self.api_url, url=path)
        log.debug(f"__delete: url: '{url}'")

        # HTTP(s) DELETE
        response = requests.delete(url=url, headers=headers, verify=self.ssl_verify)
        response.raise_for_status()
        if response.status_code not in [202, 204]:
            msg = f"Unexpected status in requests.delete: : {str(response.status_code)} - {response.text}"
            log.error(msg)
            raise RuntimeError(msg)

    def __list(self, obj: P) -> List[P]:
        log.debug(f"__list: (type '{type(obj).__name__}')")
        return self.__search(obj=obj)

    def __search(self, obj: P, **kwargs) -> List[P]:
        log.debug(f"__search: (type: '{type(obj).__name__}', kwargs: {kwargs})")
        path = obj.path()
        if kwargs:
            path = f"{path}?{'&'.join([f'{k}={v}' for k, v in kwargs.items()])}"
        log.debug(f"__search: (path: '{path}'")
        response = self.__get(path=path)
        log.debug(f"__search: (found: '{response.get('count')}' matches")
        return [obj.from_aap(data=item) for item in response.get('results')]

    def __obj_create(self, data: dict, obj: P) -> P:
        log.debug(f"__obj_patch: (type: '{type(obj).__name__}', data: {data})")
        try:
            return obj.from_aap(self.__post(path=obj.path(), data=data))
        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 400:
                raise ValueError(f"{err}:{err.response.text}")

    def __obj_patch(self, data: dict, obj: P) -> P:
        log.debug(f"__obj_patch: (type: '{type(obj).__name__}', data: {data})")
        try:
            if hasattr(obj, 'url'):
                path = obj.url
                log.debug(f"__obj_patch setting path using url '{path}'")

            elif hasattr(obj, 'id'):
                path = urllib.parse.urljoin(obj.path(), f"{obj.id}/")
                log.debug(f"__obj_patch setting path using id '{path}'")
            else:
                log.critical(f"__obj_patch: obj does not have 'url' or 'id'")
                raise RuntimeError(f"Cannot patch object: no 'url' or 'id'")

            return obj.from_aap(self.__patch(path=path, data=data))

        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 400:
                raise ValueError(f"{err}:{err.response.text}")
            if err.response.status_code != 404:
                raise err

    def __obj_delete(self, obj: T) -> None:
        log.debug(f"__obj_delete: (type: '{type(obj).__name__}')")
        try:
            if hasattr(obj, 'url'):
                path = obj.url
                log.debug(f"__obj_delete setting path using url '{path}'")

            elif hasattr(obj, 'id'):
                path = urllib.parse.urljoin(obj.path(), f"{obj.id}/")
                log.debug(f"__obj_delete setting path using id '{path}'")
            else:
                log.critical(f"__obj_delete: obj does not have 'url' or 'id'")
                raise RuntimeError(f"Cannot delete object: no 'url' or 'id'")

            self.__delete(path=path)

            # If we try to create an object of the same name immediately
            # after deleting, the old object name still exists, and we get
            # an error. We add this pause to ensure the deletion has time
            # to propagate in the system.
            time.sleep(1)

        except requests.exceptions.HTTPError as err:
            if err.response.status_code != 404:
                raise err

    #
    # Organizations
    #
    def list_organizations(self) -> List[AapOrganization]:
        return self.__list(obj=AapOrganization)

    def search_organizations(self, **kwargs) -> List[AapOrganization]:
        return self.__search(obj=AapOrganization, **kwargs)

    #
    # Job Template
    #
    def list_job_templates(self) -> List[AapJobTemplate]:
        return self.__list(obj=AapJobTemplate)

    def search_job_templates(self, **kwargs) -> List[AapJobTemplate]:
        return self.__search(obj=AapJobTemplate, **kwargs)

    def launch_job_template(self, job_template: AapJobTemplate, inventory: AapInventory) -> AapJob:
        """Launch a job template with a specific inventory."""
        log.info(f"launch_job_template: (job_template: '{job_template.name}, inventory: '{inventory.name}')")

        # Create path
        path = urllib.parse.urljoin(job_template.url, url="launch/")
        log.debug(f"launch_job_template: url: '{path}'")

        # Create data
        data = {
            "inventory": inventory.id,
        }
        log.debug(f"launch_job_template: data: '{data}'")

        # Start the job
        return AapJob.from_aap(data=self.__post(path=path, data=data))

    #
    # Jobs
    #
    def list_jobs(self) -> List[AapJob]:
        return self.__list(Type[AapJob])

    def search_jobs(self, **kwargs) -> List[AapJob]:
        return self.__search(obj=Type[AapJob], **kwargs)

    def get_job(self, job: AapJob) -> AapJob:
        """Retrieve a specific job."""
        return AapJob.from_aap(data=self.__get(path=job.url))

    def wait_on_job(self, job: AapJob, interval: int = 5, max_timeout_seconds: int = MAX_TIMEOUT) -> AapJob:
        """
            Wait for a job to complete, checking the status at the specified interval.

            Ref. https://docs.ansible.com/automation-controller/latest/html/controllerapi/api_ref.html#/api/api_jobs_read
        """
        log.info(f"wait_on_job (job: '{job.name}', interval: {interval}, max_timeout_seconds: {max_timeout_seconds})")

        if max_timeout_seconds > MAX_TIMEOUT:
            log.warning(f"Aria has a max timeout of 900 seconds and will automatically terminate the ABX run.")

        for count in range(0, max_timeout_seconds, interval):

            # Update the job status
            job = self.get_job(job=job)
            '''
            status: (choice)
                new: New
                pending: Pending
                waiting: Waiting
                running: Running
                successful: Successful
                failed: Failed
                error: Error
                canceled: Canceled
            '''
            match job.status.lower():
                case 'successful':
                    log.info(f"Job {job.id}: status '{job.status}',  finished: '{job.finished}'")
                    return job
                case 'canceled':
                    log.warning(f"Job {job.id}: status '{job.status}',  finished: '{job.finished}'")
                    return job
                case 'failed' | 'error':
                    log.error(f"Job {job.id}: status '{job.status}',  finished: '{job.finished}'")
                    return job
                case _:
                    log.debug(f"Job {job.id}: status {job.status}. Elapsed {count} of {max_timeout_seconds} seconds.")

            # Sleep
            time.sleep(interval)

        log.warning(f'Waiting for job timed out after {max_timeout_seconds} seconds')
        return self.get_job(job=job)

    #
    #  Inventories
    #
    def list_inventories(self) -> list[AapInventory]:
        return self.__list(AapInventory)

    def search_inventories(self, **kwargs) -> List[AapInventory]:
        return self.__search(obj=AapInventory, **kwargs)

    def add_inventory(self, inventory: AriaInventory, organization: AapOrganization) -> AapInventory:
        data = inventory.data()
        data['organization'] = organization.id
        return self.__obj_create(data=data, obj=AapInventory)

    def update_inventory(self, inventory: AapInventory, updated: AriaInventory) -> AapInventory:
        log.info(f"update_inventory (id: {inventory.id}, name: '{inventory.name}')")

        # Get current data
        result = self.search_inventories(id=inventory.id)
        if len(result) > 1:
            raise RuntimeError("Update inventory found multiple inventories with the same id")

        updated_inventory = updated.data()
        current_inventory = result[0].data()

        changes = {k: v for k, v in updated_inventory.items() if updated_inventory[k] != current_inventory[k]}
        if not changes:
            log.warning(f"update_inventory no changes found")
            return inventory

        log.debug(f"update_inventory (changes: {changes})")
        return self.__obj_patch(data=changes, obj=inventory)

    def delete_inventory(self, inventory: AapInventory) -> None:
        self.__obj_delete(obj=inventory)

    #
    # Hosts
    #
    def list_hosts(self) -> list[AapHost]:
        return self.__list(AapHost)

    def search_hosts(self, **kwargs) -> List[AapHost]:
        return self.__search(obj=AapHost, **kwargs)

    def add_host(self, host: AriaHost, inventory: AapInventory) -> AapHost:
        log.info(f"add_host (inventory: '{inventory.name}', name: {host.name})")
        path = urllib.parse.urljoin(inventory.url, "hosts/")
        return AapHost.from_aap(data=self.__post(path=path, data=host.data()))

    def add_hosts(self, hosts: AriaHosts, inventory: AapInventory) -> AapHosts:
        log.info(f"add_hosts (count: {len(hosts)})")
        log.info(f"add_hosts (inventory: '{inventory.name}, hosts: '{', '.join([host.name for host in hosts])}'')")

        data = {
            "inventory": inventory.id,
            "hosts": hosts.data(),
        }

        # This function uses a special bulk add API for better performance
        response = self.__post(path=AapHosts.PATH_BULK_HOST_CREATE, data=data)



        return AapHosts(hosts=[AapHost.from_aap(data=host) for host in response.get('hosts', [])])

    def update_host(self, host: AapHost) -> AapHost:
        log.info(f"update_host (id: {host.id}, name: '{host.name}')")

        # Get current data
        result = self.search_hosts(id=host.id)
        if len(result) > 1:
            raise RuntimeError("Update host found multiple hosts with the same id")

        updated_host = host.data()
        current_host = result[0].data()

        changes = {k: v for k, v in updated_host.items() if updated_host[k] != current_host[k]}
        if not changes:
            log.warning(f"update_host no changes found")
            return host

        log.debug(f"update_host (changes: {changes})")
        return self.__obj_patch(data=changes, obj=host)

    def update_hosts(self, hosts: AapHosts) -> List[AapHost]:
        log.info(f"update_hosts (count: {len(hosts)})")
        return [self.update_host(host=host) for host in hosts]

    def delete_host(self, host: AapHost):
        log.debug(f"delete_host (id: {host.id}, name: '{host.name}')")
        self.__obj_delete(obj=host)

    def delete_hosts(self, hosts: AapHosts):
        log.debug(f"delete_hosts (count: {len(hosts)})")
        for host in hosts:
            self.delete_host(host=host)

    #
    # Groups
    #
    def list_groups(self) -> list[AapGroup]:
        return self.__list(AapGroup)

    def search_groups(self, **kwargs) -> List[AapGroup]:
        return self.__search(obj=AapGroup, **kwargs)

    def add_group(self, group: AriaGroup, inventory: AapInventory) -> AapGroup:
        log.info(f"add_group (name: '{group.name}', inventory: '{inventory.name})")
        data = group.data()
        data['inventory'] = inventory.id
        aap_group = AapGroup.from_aap(data=self.__post(path=AapGroup.path(), data=data))
        log.debug(f"add_group created group (id: '{aap_group.id}', name: '{aap_group.name}')")
        return aap_group

    def add_groups(self, groups: AriaGroups, inventory: AapInventory) -> AapGroups:
        log.info(f"add_groups (count: {len(groups)})")
        return AapGroups(groups=[self.add_group(group=group, inventory=inventory) for group in groups])

    def update_group(self, group: AapGroup) -> AapGroup:
        log.debug(f"update_group (id: {group.id}, name: '{group.name}')")

        # Get current data
        result = self.search_groups(id=group.id)
        if len(result) > 1:
            raise RuntimeError("Update group found multiple groups with the same id")

        updated_group = group.data()
        current_group = result[0].data()

        changes = {k: v for k, v in updated_group.items() if updated_group[k] != current_group[k]}
        if not changes:
            log.warning(f"update_group no changes found")
            return group

        log.debug(f"update_group (changes: {changes})")
        return self.__obj_patch(data=changes, obj=group)

    def update_groups(self, groups: AapGroups) -> AapGroups:
        log.debug(f"update_groups (count: {len(groups)})")
        return AapGroups(groups=[self.update_group(group=group) for group in groups])

    def delete_group(self, group: AapGroup):
        self.__obj_delete(obj=group)

    def delete_groups(self, groups: AapGroups):
        log.debug(f"delete_groups (count: {len(groups)})")
        for group in groups:
            self.delete_group(group=group)

    #
    # Host / Groups
    #
    def add_host_to_group(self, host: AapHost, group: AapGroup) -> None:
        log.info(f"add_host_to_group (host '{host.name}' to group '{group.name}')")

        # Create request parameters
        path = urllib.parse.urljoin(group.url, url="hosts/")
        data = {
            "id": host.id
        }
        log.debug(f"path: '{path}', data: '{data}'")

        # Post request
        self.__post(path=path, data=data)
        log.debug(f"add_host_to_group host '{host.name}' added to group '{group.name}'")

    def add_hosts_to_groups(self, mapping: AriaGroupMapping, hosts: AapHosts, groups: AapGroups):
        log.info(f"add_hosts_to_groups ({mapping}")

        for host_name, group_names in mapping.host_groups_inverted.items():

            # Search for host
            host = hosts.find(name=host_name)
            if not host:
                msg = f"Could not find host with name '{host_name}'"
                log.critical(msg)
                raise ValueError(msg)
            log.debug(f"Found host '{host.name}' with id '{host.id}'")

            for group_name in group_names:

                # Search for group
                group = groups.find(name=group_name)
                if not group:
                    msg = f"Could not find group with name '{group_name}'"
                    log.critical(msg)
                    raise ValueError(msg)
                log.debug(f"Found group '{group.name}' with id '{group.id}'")

                # Add host to group
                self.add_host_to_group(host=host, group=group)

    def delete_host_from_group(self, host: AapHost, group: AapGroup) -> None:
        log.info(f"delete_host_from_group (host '{host.name}' to group '{group.name}')")
        path = urllib.parse.urljoin(group.url, url=f"hosts/{host.id}/")
        self.__delete(path=path)

    def delete_hosts_from_group(self, hosts: AapHosts, group: AapGroup) -> None:
        log.info(f"delete_hosts_from_group (hosts: '{hosts}', group: '{group.name}')")
        for host in hosts:
            self.delete_host_from_group(host=host, group=group)

    def update_hosts_to_groups(self,
                               mapping: AriaGroupMapping,
                               groups: AapGroups,
                               inventory: AapInventory):
        log.info(f"update_hosts_to_groups ({mapping}")

        # Get all inventory hosts
        all_hosts = AapHosts(hosts=self.search_hosts(inventory=inventory.id))

        # Remove hosts
        for group in groups:
            log.debug(f"Processing hosts for group '{group.name}'")

            # Get expected group hosts
            expected_group_hosts_names = [host.get('resourceName') for host in mapping.host_groups_flat.get(group.name, [])]

            # Get current group hosts
            path = urllib.parse.urljoin(group.url, "hosts/")
            result = self.__get(path=path)
            current_group_hosts = AapHosts(hosts=[AapHost.from_aap(data=host) for host in result.get('results', [])])

            # There are 3 possible options
            #   removed: host(s) are being removed
            #   added : host(s) are being added
            #   existing: host(s) are already in the inventory (nothing to do)
            removed_hosts = [host for host in current_group_hosts if host.name not in expected_group_hosts_names]
            added_hosts = [all_hosts.find(name=host_name) for host_name in expected_group_hosts_names if not current_group_hosts.find(host_name)]
            #existing_hosts = [host for host in current_group_hosts if host.name in expected_group_hosts_names]

            if removed_hosts:
                for host in removed_hosts:
                    self.delete_host_from_group(host=host, group=group)

            if added_hosts:
                for host in added_hosts:
                    self.add_host_to_group(host=host, group=group)


    #
    # Inventory Hosts
    #
    def update_inventory_hosts(self, hosts: AriaHosts, inventory: AapInventory) -> AapHosts:
        log.info(f"update_inventory_hosts")

        inventory_hosts = self.search_hosts(inventory=inventory.id)
        inventory_hosts_names = [host.name for host in inventory_hosts]
        hosts_names = [host.name for host in hosts]

        # There are 3 possible options
        #   removed: host(s) are being removed
        #   added : host(s) are being added
        #   existing: host(s) are already in the inventory
        removed_hosts = [host for host in inventory_hosts if host.name not in hosts_names]
        added_hosts = [host for host in hosts if host.name not in inventory_hosts_names]
        existing_hosts = [host for host in inventory_hosts if host.name in hosts_names]

        new_hosts = AapHosts()

        # Case removed
        for host in removed_hosts:
            log.info(f"Removing host '{host.name}'")
            self.delete_host(host=host)

        # Case added
        for host in added_hosts:
            log.info(f"Adding host '{host.name}'")
            new_hosts.hosts.append(self.add_host(host=host, inventory=inventory))

        # Case existing
        for host in existing_hosts:
            log.info(f"Updating host '{host.name}'")
            aria_host = hosts.find(host.name)
            host.update(host=aria_host)
            new_hosts.hosts.append(self.update_host(host=host))

        return new_hosts

    #
    # Inventory Groups
    #
    def update_inventory_groups(self, groups: AriaGroups, inventory: AapInventory) -> AapGroups:
        log.info(f"update_inventory_groups")

        inventory_groups = self.search_groups(inventory=inventory.id)
        inventory_groups_names = [group.name for group in inventory_groups]
        group_names = [group.name for group in groups]

        # There are 3 possible options
        #   removed: host(s) are being removed
        #   added : host(s) are being added
        #   existing: host(s) are already in the inventory
        removed_groups = [group for group in inventory_groups if group.name not in group_names]
        added_groups = [group for group in groups if group.name not in inventory_groups_names]
        existing_groups = [group for group in inventory_groups if group.name in group_names]

        new_groups = AapGroups()

        # Case removed
        for group in removed_groups:
            log.info(f"Removing group '{group.name}'")
            self.delete_group(group=group)

        # Case added
        for group in added_groups:
            log.info(f"Adding group '{group.name}'")
            new_groups.groups.append(self.add_group(group=group, inventory=inventory))

        # Case existing
        for group in existing_groups:
            log.info(f"Updating group '{group.name}'")
            aria_group = groups.find(name=group.name)
            group.update(group=aria_group)
            new_groups.groups.append(self.update_group(group=group))

        return new_groups
