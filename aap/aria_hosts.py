import logging
import re

from collections.abc import Sized
from typing import List

from .aria_host import AriaHost

log = logging.getLogger(__name__)

NAME_REGEX = r"(\[\d+\])*"


class AriaHosts(Sized):
    def __init__(self, hosts: List[AriaHost]) -> None:
        hosts = hosts if hosts is not None else []
        log.debug(
            f"Initializing {self.__class__}: [{', '.join([host.name for host in hosts])}"
        )
        self.hosts = hosts

    def __eq__(self, other) -> bool:
        if isinstance(other, AriaHosts):
            return self.hosts == other.hosts
        return False

    def __len__(self) -> int:
        return len(self.hosts)

    def __iter__(self):
        self.index = 0
        return self

    def __next__(self):
        if self.index < len(self.hosts):
            result = self.hosts[self.index]
            self.index += 1
            return result
        else:
            raise StopIteration

    def __str__(self):
        return ", ".join([host.name for host in self.hosts])

    def __repr__(self) -> str:
        return f"{self.__class__} [{', '.join([host.name for host in self.hosts])}]"

    def data(self) -> List[dict]:
        return [host.data() for host in self.hosts]

    def find(self, name: str) -> AriaHost:
        return next(filter(lambda x: x.name == name, self.hosts), None)

    @classmethod
    def from_aria(cls, inputs: dict) -> "AriaHosts":
        log.debug(f"Initializing {cls.__class__} from Aria inputs")
        try:
            hosts = inputs["hosts"]
        except KeyError as e:
            raise ValueError("Missing key in inputs") from e

        host_variables = inputs.get("host_variables", {})

        obj = cls(hosts=[])

        for host_list in hosts:
            # When count == 1, aria returns a dict
            # When count > 1, aria returns a list of dict
            if not isinstance(host_list, list):
                host_list = [host_list]
            for host in host_list:
                log.debug(f"Processing host '{host.get('resourceName')}'")

                try:
                    # In some cases the VM name is appended with [0], [1], [n] so we need
                    # to strip that off.
                    name = re.sub(NAME_REGEX, "", host.get("name"))

                    resource_name = host["resourceName"]

                    # Need to make a copy otherwise it pass by reference and all the hosts
                    # get the same variables which get overwritten in the address
                    # assignment step.
                    variables = host_variables.get(name, {}).copy()

                    # ansible_host is minimally required so Ansible Automation Platform can
                    # reach the system to be configured. Typically, the system is not in DNS.
                    variables["ansible_host"] = host["address"]

                    # if the hostname is set, configure the  inventory_hostname
                    if "hostName" in host:
                        variables["inventory_hostname"] = host["hostName"]

                except KeyError as e:
                    raise ValueError(f'Missing key" {e}')

                obj.hosts.append(AriaHost(name=resource_name, variables=variables))

        return obj

    @property
    def hosts(self) -> List[AriaHost]:
        return self._hosts

    @hosts.setter
    def hosts(self, value: List[AriaHost]) -> None:
        if not all(isinstance(host, AriaHost) for host in value):
            raise TypeError(
                "Property 'hosts' must all be of type be of type 'AriaHost'"
            )
        self._hosts = value
