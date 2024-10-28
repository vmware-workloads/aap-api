import logging

from abc import ABC, abstractmethod
from typing import Union

log = logging.getLogger(__name__)


class AriaBase(ABC):

    def __init__(self, name: str, description: Union[str, None] = None):
        log.debug(f"Initializing {self.__class__}: [{name}, {description}]")
        self.name = name
        self.description = description if description is not None else ""

    def __eq__(self, other) -> bool:
        if isinstance(other, AriaBase):
            return (self.name == other.name
                    and self.description == other.description)
        return False

    def __repr__(self):
        return f"{self.__class__} [name: '{self.name}', description: '{self.description}']"

    def data(self) -> dict:
        return {
            "name": self.name,
            "description": self.description
        }

    @classmethod
    @abstractmethod
    def from_aria(cls, inputs: dict):
        raise NotImplementedError

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Property 'name' must be of type 'str'")
        if len(value) < 1:
            raise ValueError("Property 'name' must not be empty")
        self._name = value

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Property 'description' must be of type 'str'")
        self._description = value
