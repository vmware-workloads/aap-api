import logging

from collections.abc import Sized
from typing import List

from aap.aria_group import AriaGroup

log = logging.getLogger(__name__)


class AriaGroups(Sized):
    def __init__(self, groups: List[AriaGroup] = None) -> None:
        groups = groups if groups is not None else []
        log.debug(
            f"Initializing {self.__class__}: [{', '.join([group.name for group in groups])}]"
        )
        self.groups = groups

    def __eq__(self, other) -> bool:
        if isinstance(other, AriaGroups):
            return self.groups == other.groups
        return False

    def __len__(self) -> int:
        return len(self.groups)

    def __iter__(self):
        self.index = 0
        return self

    def __next__(self):
        if self.index < len(self.groups):
            result = self.groups[self.index]
            self.index += 1
            return result
        else:
            raise StopIteration

    def __str__(self):
        return ", ".join([group.name for group in self.groups])

    def __repr__(self) -> str:
        return f"{self.__class__} [{', '.join([group.name for group in self.groups])}]"

    def data(self) -> List[dict]:
        return [group.data() for group in self.groups]

    def find(self, name: str) -> AriaGroup:
        return next(filter(lambda x: x.name == name, self.groups), None)

    @classmethod
    def from_aria(cls, inputs: dict) -> 'AriaGroups':
        log.debug(f"Initializing {cls.__class__} from Aria inputs")
        obj = cls(groups=[])
        host_groups = inputs.get("host_groups", {})
        # host_variables = inputs.get("host_variables", {})
        group_variables = inputs.get("group_variables", {})

        for group, hosts in host_groups.items():
            variables = group_variables.get(group, {})
            #aria_inputs = {
            #    "hosts": hosts,
            #    "host_variables": host_variables,
            #}
            obj.groups.append(
                AriaGroup(
                    name=group,
                    variables=variables,
                )
            )
        return obj

    @property
    def groups(self) -> List[AriaGroup]:
        return self._groups

    @groups.setter
    def groups(self, value: List[AriaGroup]) -> None:
        if not all(isinstance(host, AriaGroup) for host in value):
            raise TypeError(
                "Property 'groups' must all be of type be of type 'AriaGroup'"
            )
        self._groups = value
