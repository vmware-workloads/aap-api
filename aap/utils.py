from datetime import datetime


def str2datetime(time: str) -> datetime:
    return datetime.strptime(time, "%Y-%m-%dT%H:%M:%S.%fZ")


def invert_dict(d: dict, name: str) -> dict:
    inv_d = {}
    for k, vs in d.items():
        for v in vs:
            # When count == 1, aria returns a dict
            # When count > 1, aria returns a list of dict
            if not isinstance(v, list):
                v = [v]
            for host in v:
                host_name = host.get(name)
                inv_d.setdefault(host_name, []).append(k)
    return inv_d
