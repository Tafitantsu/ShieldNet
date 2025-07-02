import yaml
import os
from typing import Dict, Any, Optional

class ConfigError(Exception):
    """Custom exception for configuration errors."""
    pass

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Loads a YAML configuration file.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        A dictionary representing the configuration.

    Raises:
        ConfigError: If the file is not found, cannot be parsed, or is empty.
        FileNotFoundError: If the config_path does not exist.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    try:
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        if not config_data:
            raise ConfigError(f"Configuration file is empty or invalid: {config_path}")
        return config_data
    except yaml.YAMLError as e:
        raise ConfigError(f"Error parsing YAML configuration file {config_path}: {e}")
    except Exception as e:
        raise ConfigError(f"An unexpected error occurred while loading configuration {config_path}: {e}")

def get_config_value(config: Dict[str, Any], key_path: str, default: Optional[Any] = None, required: bool = False) -> Any:
    """
    Retrieves a value from the configuration dictionary using a dot-separated key path.

    Args:
        config: The configuration dictionary.
        key_path: A dot-separated string representing the path to the key (e.g., "logging.log_level").
        default: The default value to return if the key is not found and not required.
        required: If True and the key is not found, raises ConfigError.

    Returns:
        The value found at the key_path or the default value.

    Raises:
        ConfigError: If the key is required and not found, or if an intermediate key is not a dictionary.
    """
    keys = key_path.split('.')
    current_level = config
    for key in keys:
        if isinstance(current_level, dict) and key in current_level:
            current_level = current_level[key]
        else:
            if required:
                raise ConfigError(f"Required configuration key not found: {key_path}")
            return default
    return current_level

def resolve_path(base_dir: str, path: Optional[str]) -> Optional[str]:
    """
    Resolves a path relative to a base directory if it's not absolute.
    If the path is None, returns None.

    Args:
        base_dir: The base directory (usually the directory of the config file).
        path: The path string to resolve.

    Returns:
        The absolute path, or None if the input path was None.
    """
    if path is None:
        return None
    if os.path.isabs(path):
        return path
    return os.path.abspath(os.path.join(base_dir, path))

def validate_config(config_data: Dict[str, Any], config_type: str, config_base_dir: str) -> Dict[str, Any]:
    """
    Validates the loaded configuration and resolves paths.
    This is a basic validator and can be expanded significantly.

    Args:
        config_data: The raw configuration dictionary.
        config_type: "client" or "server" to guide validation.
        config_base_dir: The directory where the config file was loaded from, for resolving relative paths.

    Returns:
        The validated (and path-resolved) configuration dictionary.

    Raises:
        ConfigError: For any validation failures.
    """
    # Example: Ensure essential sections exist
    required_sections = {
        "client": ["logging", "local_listener", "remote_server", "tls", "timeouts"],
        "server": ["logging", "server_listener", "target_service", "tls", "timeouts"]
    }

    for section in required_sections.get(config_type, []):
        if section not in config_data:
            raise ConfigError(f"Missing required section '{section}' in {config_type} configuration.")

    # Resolve paths for certificate files and log files
    paths_to_resolve = []
    if config_type == "client":
        paths_to_resolve = [
            ("logging", "log_file"),
            ("remote_server", "server_ca_cert"),
            ("tls", "client_cert"),
            ("tls", "client_key"),
        ]
    elif config_type == "server":
        paths_to_resolve = [
            ("logging", "log_file"),
            ("tls", "server_cert"),
            ("tls", "server_key"),
            ("tls", "client_ca_cert"),
        ]

    for section, key in paths_to_resolve:
        if section in config_data and key in config_data[section]:
            original_path = config_data[section][key]
            if original_path: # Only resolve if a path is actually provided
                 config_data[section][key] = resolve_path(config_base_dir, original_path)
            # else: it might be an optional path, handled by logic using it

    # Validate log level (basic example)
    log_level = get_config_value(config_data, "logging.log_level", "INFO")
    valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if log_level.upper() not in valid_log_levels:
        raise ConfigError(f"Invalid log_level '{log_level}'. Must be one of {valid_log_levels}.")
    config_data["logging"]["log_level"] = log_level.upper()


    # Validate TLS min_version (basic example)
    tls_min_version = get_config_value(config_data, "tls.min_version", "TLSv1.2")
    valid_tls_versions = ["TLSV1_2", "TLSV1_3"] # Check ssl module for actual attribute names if needed
    # Normalizing for comparison, actual SSLContext setup will need specific ssl.TLSVersion attributes
    normalized_tls_version = tls_min_version.upper().replace(".", "").replace("V", "v")


    if normalized_tls_version not in [v.lower() for v in valid_tls_versions]:
         # This check is a bit loose, actual mapping to ssl.TLSVersion objects will be more robust
        pass # For now, we'll let the SSLContext setup handle invalid values more gracefully or refine this.
             # A better check would be to map to actual ssl.TLSVersion enum members.
    config_data["tls"]["min_version_str"] = tls_min_version # Store original string for reference if needed

    # Add more specific validations as needed (e.g., port numbers, host formats, timeouts are positive integers)
    # Example: Timeout validation
    timeout_keys = {
        "client": [("timeouts", "connect"), ("timeouts", "tls_handshake"), ("timeouts", "socket_data"), ("timeouts", "reconnect_delay_base"), ("timeouts", "reconnect_max_retries")],
        "server": [("timeouts", "tls_handshake"), ("timeouts", "socket_data")]
    }
    for section, key in timeout_keys.get(config_type, []):
        # Use a different way to access to avoid recursion with get_config_value if we were using it for this.
        # Here, we assume section and key are directly under config_data or one level deep.
        current_val_dict = config_data
        if section in current_val_dict and isinstance(current_val_dict[section], dict) and \
           key in current_val_dict[section]:
            val = current_val_dict[section][key]
        else:
            val = None # Or some other indicator that it's not found at this specific check path

        if val is not None:
            if not isinstance(val, (int, float)) or val < 0:
                raise ConfigError(f"Timeout value for '{section}.{key}' must be a non-negative number. Got: {val}")
            if key == "reconnect_max_retries" and val < 0 : # Should be int
                 raise ConfigError(f"Timeout value for '{section}.{key}' must be a non-negative integer. Got: {val}")

    # Validate allowed_client_cns for server config
    if config_type == "server":
        allowed_cns = get_config_value(config_data, "tls.allowed_client_cns", default=[])
        if not isinstance(allowed_cns, list) or not all(isinstance(cn, str) for cn in allowed_cns):
            raise ConfigError("'tls.allowed_client_cns' must be a list of strings.")
        # No further validation on CN content itself here, that's for runtime.
        # Ensure the key exists in the structure even if empty, for consistent access.
        if "tls" not in config_data: config_data["tls"] = {}
        config_data["tls"]["allowed_client_cns"] = allowed_cns


    return config_data


def load_and_validate_config(config_path: str, config_type: str) -> Dict[str, Any]:
    """
    Loads and validates a YAML configuration file.

    Args:
        config_path: Path to the YAML configuration file.
        config_type: "client" or "server", used for validation rules.

    Returns:
        A dictionary representing the validated configuration with resolved paths.
    """
    raw_config = load_config(config_path)
    config_base_dir = os.path.dirname(config_path)
    if not config_base_dir: # If config_path is just a filename, dirname is empty
        config_base_dir = "."

    validated_config = validate_config(raw_config, config_type, config_base_dir)
    return validated_config

if __name__ == '__main__':
    # Example Usage (for testing this module directly)
    # Create dummy config files for testing
    example_client_config_content = """
logging:
  log_file: "../logs/client.log" # Relative to config file location
  log_level: "DEBUG"
  log_rotation_bytes: 5242880 # 5MB
  log_backup_count: 3

local_listener:
  host: "127.0.0.1"
  port: 1081

remote_server:
  host: "localhost"
  port: 8444
  server_ca_cert: "certs/ca.pem"

tls:
  client_cert: "certs/client.pem"
  client_key: "certs/client.key.unencrypted"
  min_version: "TLSv1.2"

timeouts:
  connect: 5
  tls_handshake: 10
  socket_data: 30
  reconnect_delay_base: 2
  reconnect_max_retries: 10
"""
    example_server_config_content = """
logging:
  log_file: "server.log" # Relative to where this script is run if config is in same dir
  log_level: "INFO"

server_listener:
  host: "0.0.0.0"
  port: 8444

target_service:
  host: "127.0.0.1"
  port: 8080

tls:
  server_cert: "certs/server.pem"
  server_key: "certs/server.key.unencrypted"
  client_ca_cert: "certs/ca.pem" # For mTLS
  min_version: "TLSv1.3"
  # allowed_client_cns:
  #  - "testclient"

timeouts:
  tls_handshake: 10
  socket_data: 30
"""
    test_config_dir = "temp_config_test"
    os.makedirs(test_config_dir, exist_ok=True)
    client_config_file = os.path.join(test_config_dir, "client_test.yaml")
    server_config_file = os.path.join(test_config_dir, "server_test.yaml")

    with open(client_config_file, "w") as f:
        f.write(example_client_config_content)
    with open(server_config_file, "w") as f:
        f.write(example_server_config_content)

    print("Testing config loader...")
    try:
        print("\n--- Loading Client Config ---")
        client_cfg = load_and_validate_config(client_config_file, "client")
        print(f"Client Config Loaded: {client_cfg}")
        print(f"Resolved client log file path: {client_cfg['logging']['log_file']}")
        print(f"Resolved server_ca_cert path: {client_cfg['remote_server']['server_ca_cert']}")


        print("\n--- Loading Server Config ---")
        server_cfg = load_and_validate_config(server_config_file, "server")
        print(f"Server Config Loaded: {server_cfg}")
        print(f"Resolved server log file path: {server_cfg['logging']['log_file']}")
        print(f"Resolved server_cert path: {server_cfg['tls']['server_cert']}")

        print("\n--- Testing get_config_value ---")
        print(f"Client Log Level: {get_config_value(client_cfg, 'logging.log_level')}")
        print(f"Client Reconnect Retries: {get_config_value(client_cfg, 'timeouts.reconnect_max_retries')}")
        print(f"Server Target Host: {get_config_value(server_cfg, 'target_service.host')}")
        print(f"Optional value (not present): {get_config_value(client_cfg, 'non_existent.key', default='Not Found')}")
        try:
            get_config_value(client_cfg, 'non_existent.key', required=True)
        except ConfigError as e:
            print(f"Caught expected error for required key: {e}")

        # Test path resolution with absolute path in config
        abs_path_config_content = """
logging:
  log_file: "/tmp/abs_client.log"
local_listener: {host: 1, port: 1}
remote_server: {host: 1, port: 1}
tls: {min_version: "TLSv1.2"}
timeouts: {}
        """
        abs_path_config_file = os.path.join(test_config_dir, "abs_path_test.yaml")
        with open(abs_path_config_file, "w") as f:
            f.write(abs_path_config_content)
        abs_cfg = load_and_validate_config(abs_path_config_file, "client")
        print(f"\nAbsolute path test, log_file: {abs_cfg['logging']['log_file']}")


    except FileNotFoundError as e:
        print(f"Error: Test config file not found. {e}")
    except ConfigError as e:
        print(f"Config Error: {e}")
    finally:
        # Clean up dummy files
        import shutil
        shutil.rmtree(test_config_dir, ignore_errors=True)
        print(f"\nCleaned up {test_config_dir}")

    print("Config loader test finished.")
