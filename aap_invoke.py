import requests
import urllib.parse


def handler(context, inputs):
    class AapInvoke(object):
        def __init__(self, base_url: str, username: str, password: str):

            # Ansible Automation Platform details
            self.base_url = base_url
            self.username = username
            self.password = password

            # Headers for JSON content type
            self._headers = {"Content-Type": "application/json"}

            # Authentication token
            self._auth_token = None

            # Inventory
            self._inventory_id = None

        def __dict__(self) -> dict:
            return {
                "base_url": self.base_url,
                "username": self.username,
                "inventory_id": self._inventory_id,
            }

        def __repr__(self):
            return f"{self.__class__.__name__}(base_url={self.base_url}, username={self.username}, inventory_id={self._inventory_id})"

        def is_authenticated(self) -> bool:
            return self._auth_token is not None and len(self._auth_token) > 0

        def is_inventory_created(self) -> bool:
            return self._inventory_id is not None

        def authenticate(self):
            """Authenticate with the AAP and return the auth token."""
            auth_url = urllib.parse.urljoin(self.base_url, "api/v2/authtoken/")
            response = requests.post(
                auth_url,
                headers=self._headers,
                json={"username": self.username, "password": self.password},
            )
            response.raise_for_status()  # Raises an error if the authentication fails
            self._auth_token = response.json()["token"]

        def create_inventory(self, inventory_name: str, organization_id: int = 1):

            if not self.is_authenticated():
                raise RuntimeError(
                    f"Not authenticated. Please authenticate before calling this method."
                )

            """Create a new inventory and return its ID."""
            inventory_url = urllib.parse.urljoin(self.base_url, "api/v2/inventories/")
            self._headers["Authorization"] = f"Token {self._auth_token}"
            data = {
                "name": inventory_name,
                "description": "Created via Aria Automation API",
                "organization": organization_id,
            }
            response = requests.post(inventory_url, headers=self._headers, json=data)
            response.raise_for_status()
            self._inventory_id = response.json()["id"]

        def add_host_to_inventory(
                self, inventory_id, host_name: str, host_description: str
        ):

            if not self.is_authenticated():
                raise RuntimeError(
                    f"Not authenticated. Please authenticate before calling this method."
                )

            if not self.is_inventory_created():
                raise RuntimeError(
                    f"Inventory not defined. Please create an inventory before calling this method."
                )

            """Add a host to the specified inventory."""
            hosts_url = urllib.parse.urljoin(self.base_url, "api/v2/hosts/")

            self._headers["Authorization"] = f"Token {self._auth_token}"
            data = {
                "name": host_name,
                "description": host_description,
                "inventory": inventory_id,
            }
            response = requests.post(hosts_url, headers=self._headers, json=data)
            response.raise_for_status()
            return response.json()

    base_url = inputs["base_url"]
    username = inputs["username"]
    password = context.getSecret(inputs["password"])
    inventory_name = inputs["inventory_name"]
    hosts = inputs["hosts"]

    aap = AapInvoke(base_url=base_url, username=username, password=password)
    aap.authenticate()
    aap.create_inventory(inventory_name=inventory_name)

    return f"Inventory created: {str(aap)}"
