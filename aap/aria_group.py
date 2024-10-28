import json
import logging

from typing import Union

from aap import AriaBase

log = logging.getLogger(__name__)


class AriaGroup(AriaBase):

    def __init__(
        self,
        name: str,
        description: Union[str, None] = None,
        variables: Union[dict, None] = None,
    ):
        log.debug(
            f"Initializing {self.__class__}: [{name}, {description}, {variables}]"
        )
        super().__init__(name=name, description=description)
        self.variables = variables if variables else {}

    def __eq__(self, other):
        if isinstance(other, AriaGroup):
            return (
                AriaBase.__eq__(self, other)
                and self.variables == other.variables
            )
        return False

    def __repr__(self) -> str:
        return f"{self.__class__} [{AriaBase.__repr__(self)}, variables: '{self.variables}']"

    def data(self) -> dict:
        base = super().data()
        base["variables"] = self.variables_json
        return base

    def update(self, group: 'AriaGroup'):
        self.name = group.name
        self.description = group.description
        self.variables = group.variables

    @classmethod
    def from_aria(cls, inputs: dict):
        raise NotImplementedError

    @property
    def variables(self) -> dict:
        return self._variables

    @variables.setter
    def variables(self, value: dict) -> None:
        if not isinstance(value, dict):
            raise TypeError("Property 'variables' must be of type 'dict'")
        self._variables = value

    @property
    def variables_json(self) -> str:
        return json.dumps(self.variables)
