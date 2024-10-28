import logging

from datetime import datetime

from . import AapBase
from .utils import str2datetime

log = logging.getLogger(__name__)


class AapJob(AapBase):
    PATH = "jobs/"

    def __init__(self,
                 id_: int,
                 name: str,
                 description: str,
                 inventory: int,
                 url: str,
                 status: str,
                 **kwargs):
        log.debug(f"Initializing {self.__class__}: ["
                  f"{id_}, "
                  f"{name}, "
                  f"{description}, "
                  f"{inventory}, "
                  f"{url}, "
                  f"{status}, "
                  f"{kwargs}]")
        super().__init__(id_=id_, url=url)
        self.name = name
        self.description = description
        self.inventory = inventory
        self.status = status

        if 'created' in kwargs.keys() and kwargs['created']:
            self.created = str2datetime(kwargs['created'])
        else:
            self.created = None

        if 'modified' in kwargs.keys() and kwargs['modified']:
            self.modified = str2datetime(kwargs['modified'])
        else:
            self.modified = None

        if 'started' in kwargs.keys() and kwargs['started']:
            self.started = str2datetime(kwargs['started'])
        else:
            self.started = None

        if 'finished' in kwargs.keys() and kwargs['finished']:
            self.finished = str2datetime(kwargs['finished'])
        else:
            self.finished = None

    def __eq__(self, other):
        if isinstance(other, AapJob):
            return (AapJob.__eq__(self, other)
                    and self.name == other.name,
                    self.description == other.description)
        return False

    def __repr__(self):
        return (f"{self.__class__}: ["
                f"{AapBase.__repr__(self)}, "
                f"name: '{self.name}', "
                f"description: '{self.description}']")

    def __str__(self):
        if (self.finished is not None
                and isinstance(self.finished, datetime)
                and self.started is not None
                and isinstance(self.started, datetime)):
            elapsed = (self.finished - self.started).total_seconds()
        else:
            elapsed = (datetime.now() - self.started).total_seconds()

        return (f"Job ["
                f"id: {self.id}, "
                f"name: '{self.name}', "
                f"status: {self.status}, "
                f"started: '{self.started}', "
                f"finished: '{self.finished}', "
                f"elapsed: {elapsed}]")

    @classmethod
    def from_aap(cls, data: dict) -> 'AapJob':
        log.debug(f"Initializing {cls.__class__} from AAP inputs")
        try:
            return cls(
                id_=data['id'],
                name=data['name'],
                inventory=data['inventory'],
                description=data['description'],
                url=data['url'],
                status=data['status'],
                created=data.get('created'),
                modified=data.get('modified'),
                started=data.get('started'),
                finished=data.get('finished'),
            )
        except KeyError as e:
            msg = f"Failed to get required parameter from AapJob: {e}"
            log.critical(msg)
            raise ValueError(msg)

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Property 'name' must be of type 'str'")
        self._name = value

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Property 'description' must be of type 'str'")
        self._description = value

    @property
    def inventory(self) -> int:
        return self._inventory

    @inventory.setter
    def inventory(self, value: int):
        if not isinstance(value, int):
            raise TypeError("Property 'inventory' must be of type 'int'")
        self._inventory = value

    @property
    def status(self) -> str:
        return self._status

    @status.setter
    def status(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Property 'status' must be of type 'str'")
        self._status = value
