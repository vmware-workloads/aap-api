import json
import logging

from typing import Union

from aap import AriaBase

log = logging.getLogger(__name__)


class AriaInventory(AriaBase):

    def __init__(
        self,
        name: str,
        description: Union[str, None] = None,
        variables: Union[dict, None] = None,
    ):
        log.debug(f"Initializing {self.__class__}: [{name}, {description}]")
        super().__init__(name=name, description=description)
        self.variables = variables

    def __eq__(self, other):
        if isinstance(other, AriaInventory):
            return AriaBase.__eq__(self, other) and self.variables == other.variables
        return False

    def __repr__(self) -> str:
        return (
            f"{self.__class__} [{AriaBase.__repr__(self)}, variables: '{self.variables}']"
        )

    def data(self) -> dict:
        base = super().data()
        base["variables"] = self.variables_json
        return base

    @classmethod
    def from_aria(cls, inputs: dict) -> "AriaInventory":
        log.debug(f"Initializing {cls.__class__} from Aria inputs")
        try:
            return cls(
                name=inputs["inventory_name"],
                description=None,
                variables=inputs.get("inventory_variables", {}),
            )
        except KeyError as e:
            raise ValueError("Missing key 'inventory_name' in inputs") from e

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
