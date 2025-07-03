import unittest
from unittest.mock import Mock, patch, ANY, call, MagicMock
import socket
import ssl
import threading
import time
import sys
import os

# Corrected import assuming tests are run from project root
from client.client import handle_local_connection, main as client_main
from client.common.env_config_loader import EnvConfigError

MOCK_TARGET_HOST_CLI = "dynamic.target.com"
MOCK_TARGET_PORT_CLI = 8080

# This dictionary represents the values we expect to be loaded from .env
# It will be used to set the return_values of mocked get_env_* functions.
MOCK_ENV_VALUES_CLIENT = {
    "SHIELDNET_REMOTE_SERVER_HOST": "remotehost.example.com",
    "SHIELDNET_REMOTE_SERVER_PORT": 8443,
    "SHIELDNET_REMOTE_SERVER_CA_CERT": "certs/ca.crt",
    "SHIELDNET_TLS_CLIENT_CERT": "certs/client.crt",
    "SHIELDNET_TLS_CLIENT_KEY": "certs/client.key",
    "SHIELDNET_TLS_MIN_VERSION": "TLSv1.2",
    "SHIELDNET_TLS_EXPECTED_SERVER_CN": None, # Example: "expected.server.name" or None
    "SHIELDNET_TIMEOUT_CONNECT": 1,
    "SHIELDNET_TIMEOUT_TLS_HANDSHAKE": 1,
    "SHIELDNET_TIMEOUT_SOCKET_DATA": 1,
    "SHIELDNET_TIMEOUT_RECONNECT_DELAY_BASE": 0.01,
    "SHIELDNET_TIMEOUT_RECONNECT_MAX_RETRIES": 2,
    # For main() tests
    "SHIELDNET_LOG_LEVEL": "DEBUG",
    "SHIELDNET_LOG_FILE": "logs/client/client_test.log",
    "SHIELDNET_LOG_ROTATION_BYTES": 10000,
    "SHIELDNET_LOG_BACKUP_COUNT": 1,
    "SHIELDNET_LOCAL_LISTENER_HOST": "127.0.0.1",
    "SHIELDNET_LOCAL_LISTENER_PORT": 10999
}

# Base dir for resolving paths in tests, simulating client.py's ENV_BASE_DIR
TEST_CLIENT_ENV_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(client_main.__code__.co_filename), ".."))

def mock_client_get_env_str(key, default=None, required=False):
    val = MOCK_ENV_VALUES_CLIENT.get(key)
    if val is None:
        if required: raise EnvConfigError(f"Required env var '{key}' not set in mock.")
        return default
    return str(val) if val is not None else default

def mock_client_get_env_int(key, default=None, required=False):
    val_str = MOCK_ENV_VALUES_CLIENT.get(key)
    if val_str is None:
        if required: raise EnvConfigError(f"Required env var '{key}' not set in mock.")
        return default
    try:
        return int(val_str)
    except ValueError:
        raise EnvConfigError(f"Mocked env var '{key}' ('{val_str}') cannot be int.")

def mock_client_resolve_env_path(base_dir, path_from_env):
    if not path_from_env: return None
    # Ensure the base_dir used in the test matches what client.py would use
    # For client.py, ENV_BASE_DIR is calculated relative to client.py's location.
    return os.path.abspath(os.path.join(base_dir, path_from_env))


@patch('client.client.forward_data')
@patch('socket.socket')
@patch('ssl.SSLContext')
@patch('client.client.get_env_str', side_effect=mock_client_get_env_str)
@patch('client.client.get_env_int', side_effect=mock_client_get_env_int)
@patch('client.client.resolve_env_path', side_effect=mock_client_resolve_env_path)
class TestClientHandleLocalConnection(unittest.TestCase):

    def test_successful_connection(self, mock_resolve_path, mock_get_int, mock_get_str, MockSSLContext, MockSocket, mock_forward_data):
        mock_local_conn = MagicMock(spec=socket.socket)
        mock_local_conn.getpeername.return_value = ("127.0.0.1", 54321)

        mock_plain_socket_instance = MagicMock(spec=socket.socket)
        MockSocket.return_value = mock_plain_socket_instance

        mock_ssl_context_instance = MagicMock(spec=ssl.SSLContext)
        MockSSLContext.return_value = mock_ssl_context_instance

        mock_tls_socket_instance = MagicMock(spec=ssl.SSLSocket)
        mock_ssl_context_instance.wrap_socket.return_value = mock_tls_socket_instance
        mock_tls_socket_instance.cipher.return_value = ("TLS_TEST_CIPHER", "TLSv1.3", 256)
        mock_tls_socket_instance.getpeercert.return_value = {"subject": ((("commonName", MOCK_ENV_VALUES_CLIENT["SHIELDNET_REMOTE_SERVER_HOST"]),),)}

        handler_thread = threading.Thread(target=handle_local_connection,
                                          args=(mock_local_conn, ("127.0.0.1", 54321), MOCK_TARGET_HOST_CLI, MOCK_TARGET_PORT_CLI))
        handler_thread.start()
        time.sleep(0.2) # Allow for operations

        MockSocket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_plain_socket_instance.settimeout.assert_any_call(MOCK_ENV_VALUES_CLIENT["SHIELDNET_TIMEOUT_CONNECT"])
        mock_plain_socket_instance.connect.assert_called_once_with(
            (MOCK_ENV_VALUES_CLIENT["SHIELDNET_REMOTE_SERVER_HOST"], MOCK_ENV_VALUES_CLIENT["SHIELDNET_REMOTE_SERVER_PORT"])
        )
        MockSSLContext.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)

        expected_ca_cert_path = os.path.abspath(os.path.join(TEST_CLIENT_ENV_BASE_DIR, MOCK_ENV_VALUES_CLIENT["SHIELDNET_REMOTE_SERVER_CA_CERT"]))
        mock_ssl_context_instance.load_verify_locations.assert_called_once_with(cafile=expected_ca_cert_path)

        expected_client_cert_path = os.path.abspath(os.path.join(TEST_CLIENT_ENV_BASE_DIR, MOCK_ENV_VALUES_CLIENT["SHIELDNET_TLS_CLIENT_CERT"]))
        expected_client_key_path = os.path.abspath(os.path.join(TEST_CLIENT_ENV_BASE_DIR, MOCK_ENV_VALUES_CLIENT["SHIELDNET_TLS_CLIENT_KEY"]))
        mock_ssl_context_instance.load_cert_chain.assert_called_once_with(certfile=expected_client_cert_path, keyfile=expected_client_key_path)

        mock_plain_socket_instance.settimeout.assert_any_call(MOCK_ENV_VALUES_CLIENT["SHIELDNET_TIMEOUT_TLS_HANDSHAKE"])
        mock_ssl_context_instance.wrap_socket.assert_called_once_with(
            mock_plain_socket_instance, server_hostname=MOCK_ENV_VALUES_CLIENT["SHIELDNET_REMOTE_SERVER_HOST"]
        )

        target_dest_str_expected = f"{MOCK_TARGET_HOST_CLI}:{MOCK_TARGET_PORT_CLI}\n"
        mock_tls_socket_instance.sendall.assert_any_call(target_dest_str_expected.encode('utf-8'))

        mock_local_conn.settimeout.assert_called_with(MOCK_ENV_VALUES_CLIENT["SHIELDNET_TIMEOUT_SOCKET_DATA"])
        mock_tls_socket_instance.settimeout.assert_any_call(MOCK_ENV_VALUES_CLIENT["SHIELDNET_TIMEOUT_SOCKET_DATA"])

        self.assertEqual(mock_forward_data.call_count, 2)
        if mock_forward_data.call_count == 2: # pragma: no branch
            shutdown_event = mock_forward_data.call_args_list[0][0][3]
            self.assertIsInstance(shutdown_event, threading.Event)
            shutdown_event.set() # Ensure thread can terminate

        handler_thread.join(timeout=1)
        self.assertFalse(handler_thread.is_alive(), "Handler thread did not terminate")

        mock_local_conn.close.assert_called_once()
        mock_tls_socket_instance.close.assert_called_once()

    @patch('time.sleep', return_value=None)
    def test_connection_refused_with_retries(self, mock_time_sleep, mock_resolve_path, mock_get_int, mock_get_str, MockSSLContext, MockSocket, mock_forward_data):
        mock_local_conn = MagicMock(spec=socket.socket)
        mock_plain_socket_instance = MagicMock(spec=socket.socket)
        MockSocket.return_value = mock_plain_socket_instance

        num_retries = MOCK_ENV_VALUES_CLIENT["SHIELDNET_TIMEOUT_RECONNECT_MAX_RETRIES"]
        connect_effects = [ConnectionRefusedError("Connection refused")] * (num_retries + 1)
        mock_plain_socket_instance.connect.side_effect = connect_effects

        handle_local_connection(mock_local_conn, ("127.0.0.1", 12346), MOCK_TARGET_HOST_CLI, MOCK_TARGET_PORT_CLI)

        self.assertEqual(mock_plain_socket_instance.connect.call_count, num_retries + 1)
        self.assertEqual(mock_time_sleep.call_count, num_retries)
        mock_forward_data.assert_not_called()
        mock_local_conn.close.assert_called_once()

# Patching imports for the client.main function's scope
@patch('client.client.load_env_config', Mock(return_value=True))
@patch('client.client.setup_logging', Mock())
@patch('socket.socket') # Mock the listening socket in client.main
@patch('client.client.get_env_str', side_effect=mock_client_get_env_str)
@patch('client.client.get_env_int', side_effect=mock_client_get_env_int)
@patch('client.client.resolve_env_path', side_effect=mock_client_resolve_env_path)
class TestClientMain(unittest.TestCase):

    def test_main_successful_startup_and_shutdown(self, mock_main_resolve_path, mock_main_get_int, mock_main_get_str, mock_main_socket_constructor, mock_main_setup_logging, mock_main_load_env):
        mock_listening_socket = MagicMock(spec=socket.socket)
        mock_listening_socket.accept.side_effect = KeyboardInterrupt # Simulate immediate shutdown
        mock_main_socket_constructor.return_value = mock_listening_socket

        test_args = ['client.py', '--config', 'dummy.env', '--target-host', 'foo', '--target-port', '123']
        with patch.object(sys, 'argv', test_args):
            with self.assertRaises(SystemExit) as cm:
                 with patch('logging.info'), patch('logging.error'), patch('logging.critical'), patch('logging.warning'): # Suppress logs
                    client_main()
            self.assertEqual(cm.exception.code, 0) # Expect clean exit

        mock_main_load_env.assert_called_with('dummy.env')
        mock_main_setup_logging.assert_called() # Check it's called, args depend on MOCK_ENV_VALUES

        expected_bind_host = MOCK_ENV_VALUES_CLIENT["SHIELDNET_LOCAL_LISTENER_HOST"]
        expected_bind_port = MOCK_ENV_VALUES_CLIENT["SHIELDNET_LOCAL_LISTENER_PORT"]
        mock_listening_socket.bind.assert_called_with((expected_bind_host, expected_bind_port))
        mock_listening_socket.listen.assert_called()
        mock_listening_socket.close.assert_called()

    def test_main_env_config_error_missing_required(self, mock_main_resolve_path, mock_main_get_int, mock_main_get_str, mock_main_socket_constructor, mock_main_setup_logging, mock_main_load_env):
        # Simulate SHIELDNET_LOCAL_LISTENER_PORT (required) missing
        def temp_get_int_effect(key, default=None, required=False):
            if key == "SHIELDNET_LOCAL_LISTENER_PORT":
                if required: raise EnvConfigError(f"Required env var '{key}' not set.")
                return default
            return mock_client_get_env_int(key, default, required)

        mock_main_get_int.side_effect = temp_get_int_effect

        test_args = ['client.py', '--config', 'dummy.env', '--target-host', 'foo', '--target-port', '123']
        with patch.object(sys, 'argv', test_args):
            with self.assertRaises(SystemExit) as cm:
                with patch('logging.error') as mock_log_error:
                    client_main()
            self.assertEqual(cm.exception.code, 1)
            mock_log_error.assert_any_call("FATAL: SHIELDNET_LOCAL_LISTENER_PORT is not defined in the configuration.")

        # Restore default mock side effect for other tests if any
        mock_main_get_int.side_effect = mock_client_get_env_int


    def test_main_missing_cli_target_args(self, mock_main_resolve_path, mock_main_get_int, mock_main_get_str, mock_main_socket_constructor, mock_main_setup_logging, mock_main_load_env):
        # Restore default mock side effect for this test
        mock_main_get_int.side_effect = mock_client_get_env_int

        test_args_missing_host = ['client.py', '--config', 'dummy.env', '--target-port', '123']
        with patch.object(sys, 'argv', test_args_missing_host):
            with self.assertRaises(SystemExit) as cm:
                client_main()
            self.assertEqual(cm.exception.code, 2) # Argparse error

        test_args_missing_port = ['client.py', '--config', 'dummy.env', '--target-host', 'foo']
        with patch.object(sys, 'argv', test_args_missing_port):
            with self.assertRaises(SystemExit) as cm:
                client_main()
            self.assertEqual(cm.exception.code, 2) # Argparse error


if __name__ == '__main__':
    unittest.main(verbosity=2)
```
