import logging

from collections.abc import Sized
from typing import List

from .aap_group import AapGroup

log = logging.getLogger(__name__)


class AapGroups(Sized):

    def __init__(self, groups: List[AapGroup] = None):
        groups = groups if groups is not None else []
        log.debug(f"Initializing {self.__class__}: [{', '.join([group.name for group in groups])}")
        self.groups = groups if groups else []

    def __eq__(self, other) -> bool:
        if isinstance(other, AapGroups):
            return self.groups == other.groups
        return False

    def __len__(self):
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

    def __repr__(self):
        return f"{self.__class__}: [{', '.join([group.name for group in self.groups])}]"

    def find(self, name: str) -> AapGroup:
        return next(filter(lambda x: x.name == name, self.groups), None)

    @property
    def groups(self) -> List[AapGroup]:
        return self._groups

    @groups.setter
    def groups(self, value: List[AapGroup]) -> None:
        if not all(isinstance(group, AapGroup) for group in value):
            raise TypeError(
                "Variable 'groups' must all be of type be of type 'AapGroup'"
            )
        self._groups = value

