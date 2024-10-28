import json
import logging

from aap import AapBase
from aap.aria_group import AriaGroup

log = logging.getLogger(__name__)


class AapGroup(AapBase, AriaGroup):
    PATH = "groups/"

    def __init__(self,
                 id_: int,
                 name: str,
                 inventory: int,
                 description: str,
                 variables: dict,
                 url: str):
        AapBase.__init__(self, id_=id_, url=url)
        AriaGroup.__init__(self, name=name, description=description, variables=variables)
        self.inventory = inventory

    def __eq__(self, other):
        if isinstance(other, AapGroup):
            return (AapBase.__eq__(self, other)
                    and AriaGroup.__eq__(self, other)
                    and self.inventory == other.inventory)
        return False

    def __repr__(self):
        return (f"{self.__class__} ["
                f"{AapBase.__repr__(self)}, "
                f"{AriaGroup.__repr__(self)}, "
                f"inventory: '{self.inventory}'")

    @classmethod
    def from_aap(cls, data: dict) -> 'AapGroup':
        log.debug(f"Initializing AapGroup from AAP inputs")
        try:
            return cls(id_=data['id'],
                       name=data['name'],
                       inventory=data['inventory'],
                       description=data['description'],
                       variables=json.loads(data['variables']),
                       url=data['url'])
        except KeyError as e:
            raise ValueError("Failed to get a required group parameter") from e

    @property
    def inventory(self) -> int:
        return self._inventory

    @inventory.setter
    def inventory(self, value: int) -> None:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("Property 'inventory' must be a int")
        if value < 1:
            raise ValueError("Property 'inventory' must be a positive int")
        self._inventory = value

