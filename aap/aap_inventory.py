import json
import logging

from . import AapBase, AriaInventory


log = logging.getLogger(__name__)


class AapInventory(AapBase, AriaInventory):
    PATH = "inventories/"
    DEFAULT_ORGANIZATION_ID = 1

    def __init__(self,
                 id_: int,
                 name: str,
                 organization: int,
                 description: str,
                 variables: dict,
                 url: str
                 ):
        log.debug(f"Initializing {self.__class__}: ["
                  f"{id_}, "
                  f"{name}, "
                  f"{organization}, "
                  f"{description}, "
                  f"{variables}, "
                  f"{url}]")
        AapBase.__init__(self, id_=id_, url=url)
        AriaInventory.__init__(self, name=name, description=description, variables=variables)
        self.organization = organization

    def __eq__(self, other):
        if isinstance(other, AapInventory):
            return (AapBase.__eq__(self, other)
                    and AriaInventory.__eq__(self, other)
                    and self.organization == other.organization
                    and self.url == other.url)
        return False

    def __repr__(self) -> str:
        return (f"{self.__class__} ["
                f"{AapBase.__repr__(self)}, "
                f"{AriaInventory.__repr__(self)}, "
                f"organization: '{self.organization}']")

    @classmethod
    def from_aap(cls, data: dict) -> 'AapInventory':
        log.debug(f"Initializing {cls.__class__}: from AAP inputs")
        try:
            return cls(
                id_=data['id'],
                name=data['name'],
                organization=data['organization'],
                description=data['description'],
                variables=json.loads(data['variables']),
                url=data['url'],
                )
        except KeyError as e:
            raise ValueError("Failed to get a required inventory parameter") from e

    @property
    def organization(self) -> int:
        return self._organization

    @organization.setter
    def organization(self, value: int) -> None:
        if not isinstance(value, int):
            raise TypeError("Property 'organization' must be of type 'int'")
        if value < 1:
            raise ValueError("Property 'organization' must be greater than 0")
        self._organization = value
