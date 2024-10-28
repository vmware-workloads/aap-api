import logging

from .utils import invert_dict

log = logging.getLogger(__name__)


class AriaGroupMapping:
    def __init__(self):
        log.debug(
            f"Initializing {self.__class__}: []"
        )
        self.host_groups = {}
        self.host_groups_flat = {}
        self.host_groups_inverted = {}

    def __str__(self):
        return str({
            group: [host.get("resourceName") for hosts1 in hosts2 for host in hosts1]
            for group, hosts2 in self.host_groups.items()
        })

    @classmethod
    def from_aria(cls, inputs: dict) -> 'AriaGroupMapping':
        log.debug(f"Initializing {cls.__class__} from Aria inputs")
        obj = cls()
        obj.host_groups = inputs.get("host_groups", {})
        obj.host_groups_flat = {group: [host for host_l in host_ll for host in host_l] for group, host_ll in obj.host_groups.items()}
        obj.host_groups_inverted = invert_dict(
            d=inputs.get("host_groups", {}), name="resourceName"
        )
        return obj
