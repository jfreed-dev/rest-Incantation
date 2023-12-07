from typing import Union
import json
import yaml
import logging

def load_openapi_documentation(file_path: str) -> Union[dict, list, None]:
    """
    Load OpenAPI documentation from a JSON or YAML file.

    :param file_path: The path to the file.
    :return: The loaded data as a dictionary or list, or None in case of an error.
    """
    try:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            with open(file_path, 'r') as file:
                return yaml.safe_load(file)
        elif file_path.endswith('.json'):
            with open(file_path, 'r') as file:
                return json.load(file)
        else:
            raise ValueError("Unsupported file format")
    except (OSError, IOError, yaml.YAMLError, json.JSONDecodeError) as e:
        logging.error(f"Error loading OpenAPI documentation: {e}")
        return None