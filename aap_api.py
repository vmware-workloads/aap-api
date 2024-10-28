import logging
from typing import Any, List

import requests

from abx_handler_create import abx_create
from abx_handler_delete import abx_delete
from abx_handler_read import abx_read
from abx_handler_update import abx_update


def create_console_log(log_level: int, logger_name: str = None) -> logging.Logger:

    logger_name = logger_name if logger_name else ""

    log = logging.getLogger(logger_name)

    # Set logging level
    log.setLevel(log_level)

    # Set log format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)

    return log


def nested_keys_exist(inputs: dict, keys: List[str]) -> bool:
    """
        Check if keys (nested) exists in `element` (dict).

        Args:
            inputs (dict): Dictionary to search
            keys (list[str]): Ordered key[s] to look for in `element`
        Returns:
            bool: True if key[s] exists, False if any are missing
    """
    if not isinstance(inputs, dict):
        raise AttributeError('nested_keys_exist() expects dict as first argument.')
    if len(keys) == 0:
        raise AttributeError('nested_keys_exist() expects at least two arguments, one given.')
    if not all(isinstance(key, str) for key in keys):
        raise AttributeError('nested_keys_exist() expects keys to all be strings')

    _element = inputs
    for key in keys:
        try:
            _element = _element[key]
        except KeyError:
            return False
    return True


def get_nested_values(inputs: dict, keys: List[str]) -> Any:
    """
        Check if keys (nested) exists in `element` (dict).

        Args:
            inputs (dict): Dictionary to search
            keys (list[str]): Ordered key[s] to look for in `element`
        Returns:
            Any: value stored at the key path
    """
    if not isinstance(inputs, dict):
        raise AttributeError('nested_keys_exist() expects dict as first argument.')
    if len(keys) == 0:
        raise AttributeError('nested_keys_exist() expects at least two arguments, one given.')
    if not all(isinstance(key, str) for key in keys):
        raise AttributeError('nested_keys_exist() expects keys to all be strings')

    _element = inputs
    for key in keys:
        try:
            _element = _element[key]
        except KeyError:
            return None
    return _element


def get_operation(inputs: dict) -> str:
    """
        Checks and returns the requested operation from Aria

        Args:
            inputs (dict): Dictionary to search
        Returns:
           str: operation at key, or empty string if key does not exist
    """
    operation_keys: list[str] = ['__metadata', 'operation']
    if nested_keys_exist(inputs=inputs, keys=operation_keys):
        return get_nested_values(inputs=inputs, keys=operation_keys)
    return ""


def handler(context: object, inputs: dict):

    # Set verbosity
    if inputs.get("verbose", False):
        print('')
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    # Create root logger
    log = create_console_log(log_level=log_level)

    # Validate required inputs
    for item in ['aapURL', 'aapUser', 'aapPass', 'inventory_name', 'job_template_name', '__metadata']:
        if item not in inputs:
            msg = f"Missing required input '{item}' in inputs"
            log.critical(msg)
            raise ValueError(msg)

    # Print metadata
    for key, value in inputs['__metadata'].items():
        log.debug(f"Metadata - '{key}': '{value}'")

    # Call handlers
    try:
        operation = get_operation(inputs=inputs)
        log.info(f"Requested operation: '{operation}'")
        match operation:
            case "create":
                log.info("Calling handler for 'create' operation")
                return abx_create(context=context, inputs=inputs)

            case "read":
                log.info("Calling handler for 'read' operation")
                return abx_read(context=context, inputs=inputs)

            case "update":
                log.info("Calling handler for 'update' operation")
                return abx_update(context=context, inputs=inputs)

            case "delete":
                log.info("Calling handler for 'delete' operation")
                return abx_delete(context=context, inputs=inputs)

            case _:
                log.critical("Input did not contain a valid operation. Exiting.")

    except ValueError as e:
        log.debug(e)
        log.critical(f"Aborting. Value error: {e}")

    except KeyError as e:
        log.critical(f"Aborting: Failed to get key: {e}")

    except requests.exceptions.ConnectTimeout as e:
        log.debug(e)
        log.critical(f"Aborting: Connection to Ansible server timed out")

    except requests.exceptions.ConnectionError as e:
        log.debug(e)
        log.critical(f"Aborting: Unable to connect to Ansible server")




if __name__ == "__main__":
    import json

    with open('test/data/sample_2.5_update.json') as json_data:
        data = json.load(json_data)

    class Passthrough(object):
        def __init__(self):
            pass

        @classmethod
        def getSecret(cls, x):
            return x

    handler(Passthrough, data)
