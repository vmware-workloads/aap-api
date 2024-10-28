import logging

from collections.abc import Sized
from typing import List

from . import AapHost


log = logging.getLogger(__name__)


class AapHosts(Sized):
    PATH_BULK_HOST_CREATE = "bulk/host_create/"

    def __init__(self, hosts: List[AapHost] = None):
        hosts = hosts if hosts is not None else []
        log.debug(f"Initializing {self.__class__}: [{', '.join([host.name for host in hosts])}")
        self.hosts = hosts

    def __eq__(self, other):
        if isinstance(other, AapHosts):
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

    def __repr__(self):
        return f"{self.__class__}: [{', '.join([host.name for host in self.hosts])}]"

    def find(self, name: str) -> AapHost:
        return next(filter(lambda x: x.name == name, self.hosts), None)

    @property
    def hosts(self) -> List[AapHost]:
        return self._hosts

    @hosts.setter
    def hosts(self, value: List[AapHost]) -> None:
        if not all(isinstance(host, AapHost) for host in value):
            raise TypeError(
                "Property 'hosts' must all be of type be of type 'AapHost'"
            )
        self._hosts = value
