import json
from typing import Any
import yaml
import argparse


def load_openapi_documentation(file_path: object) -> object:
    """

    :type file_path: object
    :param file_path:
    :return:
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
    except Exception as e:
        print(f"Error loading OpenAPI documentation: {e}")
        return None


def get_file_path_interactive():
    return input("Enter the path to the OpenAPI documentation file: ")


def parse_arguments():
    parser = argparse.ArgumentParser(description='Load OpenAPI documentation.')
    parser.add_argument('file_path', nargs='?', help='Path to the OpenAPI documentation file (JSON or YAML)')
    return parser.parse_args()


# Main Execution
if __name__ == "__main__":
    args = parse_arguments()
    # If the script is run without any arguments, it will prompt for file path
    file_path = args.file_path if args.file_path else get_file_path_interactive()
    api_documentation: Any | None = load_openapi_documentation(file_path)
    if api_documentation:
        print("OpenAPI Documentation loaded successfully!")
        # Further processing of the api_documentation dictionary can be done here
