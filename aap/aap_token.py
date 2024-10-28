import datetime
import logging

from typing import Union

from aap.utils import str2datetime

log = logging.getLogger(__name__)


class AapToken(object):
    """
    A data class for the Ansible Automation Platform authentication tokens

    Args:
        token (str): The authentication token.
        username (int): The username account associated with the token.
        url (str): The REST API url for the token.
        scope (str): The user’s permissions. Must be in ['read', 'write'].
    """

    PATH = "tokens/"

    def __init__(self, token: str, user: int, url: str, scope: str, **kwargs):
        log.debug(f"__init__: (token: '{'*' * 12}', user: '{user}', url: '{url}', scope: '{scope}')")
        self.token = token
        self.user = user
        self.url = url
        self.scope = scope

        if "id" in kwargs:
            self.id = kwargs["id"]

        if "type" in kwargs:
            self.type = kwargs.get("type")

        if "description" in kwargs:
            self.description = kwargs.get("description")

        if "refresh_token" in kwargs:
            self.refresh_token = kwargs.get("refresh_token")

        if "application" in kwargs:
            self.application = kwargs.get("application")

        # Dates
        self.expires = str2datetime(kwargs.get("expires")) if kwargs.get("expires") is not None else None
        self.created = str2datetime(kwargs.get("created")) if kwargs.get("created") is not None else None
        self.modified = str2datetime(kwargs.get("modified")) if kwargs.get("modified") is not None else None

    @classmethod
    def path(cls) -> str:
        return cls.PATH

    @property
    def token(self) -> str:
        return self._token

    @token.setter
    def token(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Property token must be a string")
        self._token = value

    @property
    def user(self) -> int:
        return self._user

    @user.setter
    def user(self, value: int):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("Property user must be a integer")
        if value < 1:
            raise ValueError("Property user must be a positive integer")
        self._user = value

    @property
    def url(self) -> str:
        return self._url

    @url.setter
    def url(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Property url must be a string")
        self._url = value

    @property
    def scope(self) -> str:
        return self._scope

    @scope.setter
    def scope(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Property scope must be a string")
        if value not in ["read", "write"]:
            # As of 2.4 and 2.5 the scope is always lowercase. It's unclear
            # if we should be case-insensitive, but for now we are strict
            # about the lower case spelling
            raise ValueError("Property scope must be either 'read' or 'write'")
        self._scope = value

    @property
    def expires(self) -> Union[datetime.datetime, None]:
        return self._expires

    @expires.setter
    def expires(self, value: Union[datetime.datetime, None]):
        if not isinstance(value, datetime.datetime) and value is not None:
            raise TypeError("Property 'expires' must be a datetime.datetime")
        self._expires = value

    @property
    def created(self) -> Union[datetime.datetime, None]:
        return self._created

    @created.setter
    def created(self, value: Union[datetime.datetime, None]):
        if not isinstance(value, datetime.datetime) and value is not None:
            raise TypeError("Property 'created' must be a datetime.datetime")
        self._created = value

    @property
    def modified(self) -> Union[datetime.datetime, None]:
        return self._modified

    @modified.setter
    def modified(self, value: Union[datetime.datetime, None]):
        if not isinstance(value, datetime.datetime) and value is not None:
            raise TypeError("Property 'modified' must be a datetime.datetime")
        self._modified = value
