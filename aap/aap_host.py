import json
import logging
import re

from typing import Union

from . import AapBase, AriaHost


log = logging.getLogger(__name__)


VM_NAME_KEY = "resourceName"


class AapHost(AapBase, AriaHost):
    PATH = "hosts/"

    def __init__(self,
                 id_: int,
                 name: str,
                 inventory: int,
                 description: str,
                 variables: dict,
                 url: str):
        log.debug(f"Initializing {self.__class__}: ["
                  f"{id_}, "
                  f"{name}, "
                  f"{inventory}, "
                  f"{description}, "
                  f"{variables}, "
                  f"{url}]")
        AapBase.__init__(self, id_=id_, url=url)
        AriaHost.__init__(self, name=name, description=description, variables=variables)
        self.inventory = inventory

    def __eq__(self, other):
        if isinstance(other, AapHost):
            return (AapBase.__eq__(self, other)
                    and AriaHost.__eq__(self, other)
                    and self.inventory == other.inventory
                    and self.url == other.url)
        return False

    def __repr__(self) -> str:
        return (f"{self.__class__} ["
                f"{AapBase.__repr__(self)}, "
                f"{AriaHost.__repr__(self)}, "
                f"inventory: '{self.inventory}']")

    @classmethod
    def from_aap(cls, data: dict) -> 'AapHost':
        log.debug(f"Initializing {cls.__class__} from AAP inputs")
        try:
            return cls(
                id_=data['id'],
                name=data['name'],
                inventory=data['inventory'],
                description=data['description'],
                variables=json.loads(data['variables']),
                url=data['url'],
                )
        except KeyError as e:
            raise ValueError("Failed to get a required host parameter") from e

    @property
    def inventory(self) -> int:
        return self._inventory

    @inventory.setter
    def inventory(self, value: Union[int, str]) -> None:
        # On some versions, the inventory is returned as an integer, on
        # others it's the URL to the inventory. We normalize it to an
        # integer.
        if not isinstance(value, Union[int, str]):
            raise ValueError("Variable 'inventory' must be a int or str")
        if isinstance(value, int):
            self._inventory = value
        if isinstance(value, str):
            found = re.search(r"^/.+/(\d+)/$", value)
            if found:
                self._inventory = int(found.group(1))
            else:
                raise ValueError(f"Variable 'inventory' is of type str but could not find an integer '{value}'")
