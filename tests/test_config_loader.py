import unittest
import os
import yaml
import tempfile
import shutil

# Adjust import path if your tests directory is not at the same level as src
# For example, if tests is a subdir of project root, and src is also a subdir of project root:
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.common.config_loader import (
    load_config,
    get_config_value,
    resolve_path,
    validate_config,
    load_and_validate_config,
    ConfigError
)

class TestConfigLoader(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for config files
        self.test_dir = tempfile.mkdtemp()
        self.certs_dir = os.path.join(self.test_dir, "certs")
        os.makedirs(self.certs_dir, exist_ok=True)
        # Create dummy cert files for path resolution tests
        with open(os.path.join(self.certs_dir, "ca.crt"), "w") as f: f.write("dummy ca")
        with open(os.path.join(self.certs_dir, "client.crt"), "w") as f: f.write("dummy client cert")
        with open(os.path.join(self.certs_dir, "client.key"), "w") as f: f.write("dummy client key")


    def tearDown(self):
        # Remove the temporary directory after tests
        shutil.rmtree(self.test_dir)

    def _create_temp_config(self, content, filename="test_config.yaml"):
        path = os.path.join(self.test_dir, filename)
        with open(path, 'w') as f:
            if isinstance(content, dict):
                yaml.dump(content, f)
            else:
                f.write(content)
        return path

    def test_load_config_success(self):
        content = {"key": "value", "nested": {"subkey": "subvalue"}}
        path = self._create_temp_config(content)
        config = load_config(path)
        self.assertEqual(config, content)

    def test_load_config_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_config("non_existent_file.yaml")

    def test_load_config_yaml_error(self):
        path = self._create_temp_config("key: value\n  bad_indent")
        with self.assertRaises(ConfigError) as cm:
            load_config(path)
        self.assertIn("Error parsing YAML", str(cm.exception))


    def test_load_config_empty_file(self):
        path = self._create_temp_config("") # Empty content
        with self.assertRaises(ConfigError) as cm:
            load_config(path)
        self.assertIn("empty or invalid", str(cm.exception))


    def test_get_config_value_success(self):
        config = {"key": "value", "nested": {"subkey": "subvalue"}, "num": 123}
        self.assertEqual(get_config_value(config, "key"), "value")
        self.assertEqual(get_config_value(config, "nested.subkey"), "subvalue")
        self.assertEqual(get_config_value(config, "num"), 123)

    def test_get_config_value_not_found_default(self):
        config = {"key": "value"}
        self.assertEqual(get_config_value(config, "non_existent", default="default_val"), "default_val")
        self.assertIsNone(get_config_value(config, "non_existent.deep", default=None))

    def test_get_config_value_not_found_required(self):
        config = {"key": "value"}
        with self.assertRaises(ConfigError) as cm:
            get_config_value(config, "non_existent", required=True)
        self.assertIn("Required configuration key not found: non_existent", str(cm.exception))

    def test_get_config_value_intermediate_not_dict(self):
        config = {"key": "value"} # "key" is not a dict
        with self.assertRaises(ConfigError) as cm: # Should raise error if trying to access key.subkey
            get_config_value(config, "key.subkey", required=True)
        self.assertIn("Required configuration key not found: key.subkey", str(cm.exception))


    def test_resolve_path(self):
        base_dir = self.test_dir
        self.assertEqual(resolve_path(base_dir, "file.txt"), os.path.abspath(os.path.join(base_dir, "file.txt")))
        self.assertEqual(resolve_path(base_dir, "/abs/path.txt"), "/abs/path.txt")
        self.assertIsNone(resolve_path(base_dir, None))

    def test_validate_config_client_basic_success(self):
        # Paths are relative to self.test_dir where certs/ exist
        raw_config = {
            "logging": {"log_file": "client.log", "log_level": "INFO"},
            "local_listener": {"host": "127.0.0.1", "port": 1080},
            "remote_server": {"host": "server.com", "port": 8443, "server_ca_cert": "certs/ca.crt"},
            "tls": {"client_cert": "certs/client.crt", "client_key": "certs/client.key", "min_version": "TLSv1.2"},
            "timeouts": {"connect": 10, "tls_handshake": 15, "socket_data": 60, "reconnect_delay_base": 5, "reconnect_max_retries": 3}
        }
        # config_base_dir is the directory containing the config file.
        # Here, we simulate the config file being in self.test_dir
        validated_config = validate_config(raw_config, "client", self.test_dir)
        self.assertEqual(validated_config["logging"]["log_file"], os.path.join(self.test_dir, "client.log"))
        self.assertEqual(validated_config["remote_server"]["server_ca_cert"], os.path.join(self.test_dir, "certs/ca.crt"))
        self.assertTrue(os.path.exists(validated_config["remote_server"]["server_ca_cert"])) # Check if dummy exists

    def test_validate_config_server_basic_success(self):
        raw_config = {
            "logging": {"log_file": "server.log", "log_level": "DEBUG"},
            "server_listener": {"host": "0.0.0.0", "port": 8443},
            "target_service": {"host": "localhost", "port": 80},
            "tls": {"server_cert": "certs/client.crt", "server_key": "certs/client.key", "client_ca_cert": "certs/ca.crt", "min_version": "TLSv1.3", "allowed_client_cns": ["client1.example.com"]},
            "timeouts": {"tls_handshake": 10, "socket_data": 30}
        }
        validated_config = validate_config(raw_config, "server", self.test_dir)
        self.assertEqual(validated_config["tls"]["server_cert"], os.path.join(self.test_dir, "certs/client.crt"))
        self.assertEqual(validated_config["tls"]["allowed_client_cns"], ["client1.example.com"])

    def test_validate_config_missing_section(self):
        raw_config = {"logging": {"log_level": "INFO"}} # Missing other required sections
        with self.assertRaises(ConfigError) as cm:
            validate_config(raw_config, "client", self.test_dir)
        self.assertIn("Missing required section", str(cm.exception))

    def test_validate_config_invalid_log_level(self):
        raw_config = {
            "logging": {"log_level": "INVALID"},
            "local_listener": {}, "remote_server": {}, "tls": {}, "timeouts": {} # Satisfy section checks
        }
        with self.assertRaises(ConfigError) as cm:
            validate_config(raw_config, "client", self.test_dir)
        self.assertIn("Invalid log_level", str(cm.exception))

    def test_validate_config_invalid_timeout_value(self):
        raw_config = {
            "logging": {"log_level": "INFO"},
            "local_listener": {}, "remote_server": {}, "tls": {},
            "timeouts": {"connect": -5} # Invalid timeout
        }
        with self.assertRaises(ConfigError) as cm:
            validate_config(raw_config, "client", self.test_dir)
        self.assertIn("must be a non-negative number", str(cm.exception))
        self.assertIn("timeouts.connect", str(cm.exception))

    def test_validate_config_allowed_cns_not_list(self):
        raw_config = {
            "logging": {}, "server_listener": {}, "target_service": {}, "timeouts": {},
            "tls": {"allowed_client_cns": "not-a-list"}
        }
        with self.assertRaisesRegex(ConfigError, "'tls.allowed_client_cns' must be a list of strings"):
            validate_config(raw_config, "server", self.test_dir)

    def test_validate_config_allowed_cns_list_not_strings(self):
        raw_config = {
            "logging": {}, "server_listener": {}, "target_service": {}, "timeouts": {},
            "tls": {"allowed_client_cns": ["cn1", 123]} # Contains non-string
        }
        with self.assertRaisesRegex(ConfigError, "'tls.allowed_client_cns' must be a list of strings"):
            validate_config(raw_config, "server", self.test_dir)


    def test_load_and_validate_config(self):
        content = {
            "logging": {"log_file": "client.log", "log_level": "INFO"},
            "local_listener": {"host": "127.0.0.1", "port": 1080},
            "remote_server": {"host": "server.com", "port": 8443, "server_ca_cert": "certs/ca.crt"},
            "tls": {"client_cert": "certs/client.crt", "client_key": "certs/client.key", "min_version": "TLSv1.2"},
            "timeouts": {"connect": 10, "tls_handshake": 15, "socket_data": 60, "reconnect_delay_base":5, "reconnect_max_retries":0}
        }
        path = self._create_temp_config(content)
        config = load_and_validate_config(path, "client")
        self.assertIsNotNone(config)
        self.assertEqual(config["logging"]["log_file"], os.path.join(self.test_dir, "client.log"))
        self.assertEqual(config["tls"]["min_version_str"], "TLSv1.2")


if __name__ == '__main__':
    unittest.main(verbosity=2)
