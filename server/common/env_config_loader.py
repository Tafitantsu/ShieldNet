import os
from dotenv import load_dotenv
from typing import Optional, Union, List

class EnvConfigError(ValueError):
    """Custom exception for configuration errors from environment variables."""
    pass

def load_env_config(env_path: Optional[str] = None) -> bool:
    """
    Loads environment variables from a .env file.

    Args:
        env_path: Optional path to the .env file. If None, python-dotenv
                  will try to find .env in the current directory or parent directories.

    Returns:
        True if a .env file was loaded, False otherwise.
    """
    if env_path:
        if not os.path.exists(env_path):
            # This is not necessarily an error if defaults are used, could be a warning.
            # print(f"Warning: Specified .env file not found: {env_path}")
            return False
        return load_dotenv(dotenv_path=env_path, override=True)
    else:
        # Try loading .env from standard locations (e.g., current dir, then parent dirs)
        return load_dotenv(override=True)

def get_env_str(key: str, default: Optional[str] = None, required: bool = False) -> Optional[str]:
    """Retrieves a string environment variable."""
    value = os.getenv(key)
    if value is None:
        if required:
            raise EnvConfigError(f"Required environment variable '{key}' is not set.")
        return default
    return value

def get_env_int(key: str, default: Optional[int] = None, required: bool = False) -> Optional[int]:
    """Retrieves an integer environment variable."""
    value_str = get_env_str(key, default=None, required=required) # Handle required at str level
    if value_str is None: # Not required and not set
        return default
    try:
        return int(value_str)
    except ValueError:
        raise EnvConfigError(f"Environment variable '{key}' with value '{value_str}' cannot be converted to an integer.")

def get_env_bool(key: str, default: bool = False) -> bool:
    """
    Retrieves a boolean environment variable.
    Considers 'true', '1', 'yes', 'on' (case-insensitive) as True.
    Everything else is False. If not set, returns default.
    """
    value_str = os.getenv(key)
    if value_str is None:
        return default
    return value_str.lower() in ['true', '1', 'yes', 'on']

def get_env_list_str(key: str, default: Optional[List[str]] = None, required: bool = False, delimiter: str = ',') -> Optional[List[str]]:
    """
    Retrieves a list of strings environment variable, split by a delimiter.
    Filters out empty strings after splitting.
    """
    value_str = get_env_str(key, default=None, required=required)
    if value_str is None: # Not required and not set
        return default if default is not None else []

    if not value_str.strip(): # If the string is empty or just whitespace
        return []

    return [item.strip() for item in value_str.split(delimiter) if item.strip()]

def resolve_env_path(base_dir: str, path_from_env: Optional[str]) -> Optional[str]:
    """
    Resolves a path obtained from an environment variable.
    If the path is absolute, it's returned as is.
    If relative, it's resolved against the base_dir.
    If path_from_env is None, returns None.

    Args:
        base_dir: The base directory to resolve relative paths against.
                  Typically the project root or a config directory.
        path_from_env: The path string from the environment variable.

    Returns:
        The absolute path, or None.
    """
    if path_from_env is None or not path_from_env.strip():
        return None
    if os.path.isabs(path_from_env):
        return path_from_env
    return os.path.abspath(os.path.join(base_dir, path_from_env))

# Example usage (for testing this module directly)
if __name__ == '__main__':
    # Create a dummy .env file for testing
    DUMMY_ENV_CONTENT = """
SHIELDNET_TEST_STRING="Hello World"
SHIELDNET_TEST_INT="123"
SHIELDNET_TEST_BOOL_TRUE="true"
SHIELDNET_TEST_BOOL_FALSE="false"
SHIELDNET_TEST_LIST="apple, banana, cherry"
SHIELDNET_TEST_EMPTY_LIST=""
SHIELDNET_TEST_REQUIRED_STR="I am required"
SHIELDNET_TEST_RELATIVE_PATH="certs/mycert.pem"
# SHIELDNET_TEST_UNSET_DEFAULT (not set)
    """
    dummy_env_file = ".test_env_loader.env"
    with open(dummy_env_file, "w") as f:
        f.write(DUMMY_ENV_CONTENT)

    print(f"Loading .env file: {dummy_env_file}")
    loaded = load_env_config(dummy_env_file)
    print(f"Loaded: {loaded}\n")

    print("--- Testing String Retrieval ---")
    print(f"SHIELDNET_TEST_STRING: {get_env_str('SHIELDNET_TEST_STRING')}")
    print(f"SHIELDNET_TEST_UNSET_STR (default 'Unset'): {get_env_str('SHIELDNET_TEST_UNSET_STR', 'Unset')}")
    try:
        get_env_str('SHIELDNET_TEST_REQUIRED_UNSET', required=True)
    except EnvConfigError as e:
        print(f"Caught expected error for required string: {e}")
    print(f"SHIELDNET_TEST_REQUIRED_STR: {get_env_str('SHIELDNET_TEST_REQUIRED_STR', required=True)}")


    print("\n--- Testing Integer Retrieval ---")
    print(f"SHIELDNET_TEST_INT: {get_env_int('SHIELDNET_TEST_INT')}")
    print(f"SHIELDNET_TEST_UNSET_INT (default 0): {get_env_int('SHIELDNET_TEST_UNSET_INT', 0)}")
    os.environ['SHIELDNET_TEST_BAD_INT'] = "not-an-int"
    try:
        get_env_int('SHIELDNET_TEST_BAD_INT')
    except EnvConfigError as e:
        print(f"Caught expected error for bad int: {e}")
    del os.environ['SHIELDNET_TEST_BAD_INT']


    print("\n--- Testing Boolean Retrieval ---")
    print(f"SHIELDNET_TEST_BOOL_TRUE: {get_env_bool('SHIELDNET_TEST_BOOL_TRUE', False)}")
    print(f"SHIELDNET_TEST_BOOL_FALSE: {get_env_bool('SHIELDNET_TEST_BOOL_FALSE', True)}")
    print(f"SHIELDNET_TEST_UNSET_BOOL (default True): {get_env_bool('SHIELDNET_TEST_UNSET_BOOL', True)}")
    os.environ['SHIELDNET_TEST_BOOL_ONE'] = "1"
    print(f"SHIELDNET_TEST_BOOL_ONE (from '1'): {get_env_bool('SHIELDNET_TEST_BOOL_ONE', False)}")
    del os.environ['SHIELDNET_TEST_BOOL_ONE']

    print("\n--- Testing List Retrieval ---")
    print(f"SHIELDNET_TEST_LIST: {get_env_list_str('SHIELDNET_TEST_LIST')}")
    print(f"SHIELDNET_TEST_EMPTY_LIST: {get_env_list_str('SHIELDNET_TEST_EMPTY_LIST')}")
    print(f"SHIELDNET_TEST_UNSET_LIST (default ['a','b']): {get_env_list_str('SHIELDNET_TEST_UNSET_LIST', ['a','b'])}")
    os.environ['SHIELDNET_TEST_LIST_SPACES'] = "  one,two  , three "
    print(f"SHIELDNET_TEST_LIST_SPACES: {get_env_list_str('SHIELDNET_TEST_LIST_SPACES')}")
    del os.environ['SHIELDNET_TEST_LIST_SPACES']

    print("\n--- Testing Path Resolution ---")
    # Assuming PROJECT_ROOT is where this test runs from or similar
    # For testing, let's define a base_dir explicitly
    test_base_dir = os.getcwd()
    print(f"Using test_base_dir: {test_base_dir}")
    print(f"SHIELDNET_TEST_RELATIVE_PATH resolved: {resolve_env_path(test_base_dir, get_env_str('SHIELDNET_TEST_RELATIVE_PATH'))}")
    abs_path_example = os.path.abspath("certs/abs_cert.pem")
    os.environ['SHIELDNET_TEST_ABS_PATH'] = abs_path_example
    print(f"SHIELDNET_TEST_ABS_PATH resolved: {resolve_env_path(test_base_dir, get_env_str('SHIELDNET_TEST_ABS_PATH'))}")
    del os.environ['SHIELDNET_TEST_ABS_PATH']
    print(f"Unset path resolved: {resolve_env_path(test_base_dir, get_env_str('SHIELDNET_NONEXISTENT_PATH'))}")


    # Clean up dummy .env file
    if os.path.exists(dummy_env_file):
        os.remove(dummy_env_file)
    print(f"\nCleaned up {dummy_env_file}")
