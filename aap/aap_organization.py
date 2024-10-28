import logging

from . import AapBase

log = logging.getLogger(__name__)


class AapOrganization(AapBase):
    PATH = "organizations/"

    def __init__(self,
                 id_: int,
                 name: str,
                 url: str,
                 description: str = None):
        log.debug(f"Initializing {self.__class__}: [{name}, {id_}, {description}]")
        AapBase.__init__(self, id_=id_, url=url)
        self.name = name
        self.description = description

    def __eq__(self, other):
        if isinstance(other, AapOrganization):
            return (AapBase.__eq__(self, other)
                    and self.name == other.name
                    and self.description == other.description)
        return False

    def __repr__(self) -> str:
        return (f"{self.__class__} ["
                f"{AapBase.__repr__(self)}, "
                f"name: '{self.name}', "
                f"description: '{self.description}']")

    @classmethod
    def from_aap(cls, data: dict) -> 'AapOrganization':
        log.debug(f"Initializing {cls.__class__} from AAP inputs")
        try:
            return cls(
                id_=data['id'],
                name=data['name'],
                url=data['url'],
                description=data['description'])
        except KeyError as e:
            raise ValueError("Failed to get a required organization parameter") from e

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Property 'name' must be of type 'str'")
        self._name = value

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Property 'description' must be of type 'str'")
        self._description = value
