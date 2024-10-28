import logging
import urllib.parse

from abc import ABC, abstractmethod

log = logging.getLogger(__name__)


class AapBase(ABC):
    PATH = 'api/v2/'

    def __init__(self, id_: int, url: str):
        self.id = id_
        self.url = url

    def __eq__(self, other):
        if isinstance(other, AapBase):
            return self.id == other.id and self.url == other.url
        return False

    def __repr__(self):
        return f"{self.__class__} [id: '{self.id}', url: '{self.url}]"

    @property
    def id(self) -> int:
        return self._id

    @id.setter
    def id(self, value:int):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("Parameter 'id' must be an integer")
        if value < 1:
            raise ValueError("Parameter 'id' must be a positive integer")

        self._id = value

    @property
    def url(self) -> str:
        return self._url

    @url.setter
    def url(self, value: int) -> None:
        if not isinstance(value, str):
            raise TypeError("Parameter 'url' must be a string")
        self._url = value

    @classmethod
    @abstractmethod
    def from_aap(cls, data: dict):
        raise NotImplementedError

    @classmethod
    def path(cls, **kwargs) -> str:

        if not kwargs:
            return cls.PATH

        if 'name' in kwargs.keys():
            name = kwargs['name']
            if not isinstance(name, str):
                raise ValueError("Parameter 'name' must be a string")
            return urllib.parse.urljoin(cls.PATH, url=f"?search={urllib.parse.quote(kwargs.get('name'))}")

        if 'id' in kwargs.keys():
            id_ = kwargs['id']
            if not isinstance(id_, int):
                raise ValueError("Parameter 'id' must be an integer")
            if id_ < 1:
                raise ValueError("Parameter 'id' must be greater than 0")
            return urllib.parse.urljoin(cls.PATH, url=f"{id_}/")

        raise ValueError(f"Unexpected keyword arguments: '{kwargs}'")

