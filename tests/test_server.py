import unittest
from unittest.mock import Mock, patch, ANY, call, MagicMock
import socket
import ssl
import threading
import time
import sys
import os

from server.server import handle_client_connection, main as server_main
from client.common.env_config_loader import EnvConfigError # Assuming server uses this too

MOCK_SERVER_DYNAMIC_TARGET_HOST = "dynamic-target.test"
MOCK_SERVER_DYNAMIC_TARGET_PORT = 8000

MOCK_ENV_VALUES_SERVER = {
    "SHIELDNET_TLS_CLIENT_CA_CERT": "certs/client_ca.crt",
    "SHIELDNET_TLS_ALLOWED_CLIENT_CNS": "testclient.example.com,another.valid.client",
    "SHIELDNET_TIMEOUT_SOCKET_DATA": 1,
    "SHIELDNET_TIMEOUT_TARGET_CONNECT": 2,
    # For main()
    "SHIELDNET_LOG_LEVEL": "DEBUG",
    "SHIELDNET_LOG_FILE": "logs/server/server_test.log",
    "SHIELDNET_TLS_SERVER_CERT": "certs/server.crt",
    "SHIELDNET_TLS_SERVER_KEY": "certs/server.key",
    "SHIELDNET_TLS_MIN_VERSION": "TLSv1.2",
    "SHIELDNET_SERVER_LISTENER_HOST": "0.0.0.0",
    "SHIELDNET_SERVER_LISTENER_PORT": 9443,
    "SHIELDNET_TIMEOUT_TLS_HANDSHAKE": 1,
}

TEST_SERVER_ENV_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(server_main.__code__.co_filename), ".."))


def mock_server_get_env_str(key, default=None, required=False):
    val = MOCK_ENV_VALUES_SERVER.get(key)
    if val is None:
        if required: raise EnvConfigError(f"Required env var '{key}' not set in mock.")
        return default
    return str(val) if val is not None else default

def mock_server_get_env_int(key, default=None, required=False):
    val_str = MOCK_ENV_VALUES_SERVER.get(key)
    if val_str is None:
        if required: raise EnvConfigError(f"Required env var '{key}' not set in mock.")
        return default
    try:
        return int(val_str)
    except ValueError:
        raise EnvConfigError(f"Mocked env var '{key}' ('{val_str}') cannot be int.")

def mock_server_get_env_list_str(key, default=None, required=False, delimiter=','):
    val_str = MOCK_ENV_VALUES_SERVER.get(key)
    if val_str is None:
        return default if default is not None else []
    if not val_str.strip(): return []
    return [item.strip() for item in val_str.split(delimiter) if item.strip()]

def mock_server_resolve_env_path(base_dir, path_from_env):
    if not path_from_env: return None
    return os.path.abspath(os.path.join(base_dir, path_from_env))

# Mock the global lock from server.py
mock_server_lock_instance = MagicMock(spec=threading.Lock)

@patch('server.server.active_connections_lock', new=mock_server_lock_instance)
@patch('server.server.forward_data')
@patch('socket.create_connection') # Used by server to connect to dynamic target
@patch('server.server.get_env_str', side_effect=mock_server_get_env_str)
@patch('server.server.get_env_int', side_effect=mock_server_get_env_int)
@patch('server.server.get_env_list_str', side_effect=mock_server_get_env_list_str)
@patch('server.server.resolve_env_path', side_effect=mock_server_resolve_env_path)
class TestServerHandleClientConnection(unittest.TestCase):

    @patch('server.server.active_connections_count', 0) # Patch as a global if it is
    def test_successful_connection_mtls_cn_auth(self, mock_active_count_zero, mock_resolve_path, mock_get_list, mock_get_int, mock_get_str, mock_create_conn, mock_forward_data):
        mock_tls_client_socket = MagicMock(spec=ssl.SSLSocket)
        mock_tls_client_socket.getpeername.return_value = ("client.ip", 12345)
        mock_tls_client_socket.cipher.return_value = ("TEST_CIPHER", "TLSv1.2", 128)
        mock_tls_client_socket.gettimeout.return_value = 30 # Original timeout

        target_dest_str = f"{MOCK_SERVER_DYNAMIC_TARGET_HOST}:{MOCK_SERVER_DYNAMIC_TARGET_PORT}\n"
        # Simulate recv: first the destination, then data for forwarding
        mock_tls_client_socket.recv.side_effect = [target_dest_str.encode('utf-8'), b"client_data_chunk", b""]

        client_cert = {"subject": ((("commonName", "testclient.example.com"),),)}
        mock_tls_client_socket.getpeercert.return_value = client_cert

        mock_forward_socket = MagicMock(spec=socket.socket)
        mock_create_conn.return_value = mock_forward_socket

        handler_thread = threading.Thread(target=handle_client_connection, args=(mock_tls_client_socket,))
        handler_thread.start()
        time.sleep(0.2)

        mock_tls_client_socket.getpeercert.assert_called_once()
        mock_tls_client_socket.recv.assert_any_call(1024) # For reading destination

        mock_create_conn.assert_called_once_with(
            (MOCK_SERVER_DYNAMIC_TARGET_HOST, MOCK_SERVER_DYNAMIC_TARGET_PORT),
            timeout=MOCK_ENV_VALUES_SERVER["SHIELDNET_TIMEOUT_TARGET_CONNECT"]
        )
        mock_tls_client_socket.settimeout.assert_any_call(MOCK_ENV_VALUES_SERVER["SHIELDNET_TIMEOUT_SOCKET_DATA"])
        mock_forward_socket.settimeout.assert_called_with(MOCK_ENV_VALUES_SERVER["SHIELDNET_TIMEOUT_SOCKET_DATA"])

        self.assertEqual(mock_forward_data.call_count, 2)
        if mock_forward_data.call_count == 2: # pragma: no branch
            shutdown_event = mock_forward_data.call_args_list[0][0][3]
            self.assertIsInstance(shutdown_event, threading.Event)
            shutdown_event.set()

        handler_thread.join(timeout=1)
        self.assertFalse(handler_thread.is_alive())
        mock_tls_client_socket.close.assert_called_once()
        mock_forward_socket.close.assert_called_once()
        self.assertGreaterEqual(mock_server_lock_instance.__enter__.call_count, 1)
        self.assertGreaterEqual(mock_server_lock_instance.__exit__.call_count, 1)

    @patch('server.server.active_connections_count', 0)
    def test_mtls_cn_auth_fail(self, mock_active_count_zero, mock_resolve_path, mock_get_list, mock_get_int, mock_get_str, mock_create_conn, mock_forward_data):
        mock_tls_client_socket = MagicMock(spec=ssl.SSLSocket)
        mock_tls_client_socket.getpeername.return_value = ("client.ip", 12345)
        # Destination needs to be "received" before CN check
        target_dest_str = f"{MOCK_SERVER_DYNAMIC_TARGET_HOST}:{MOCK_SERVER_DYNAMIC_TARGET_PORT}\n"
        mock_tls_client_socket.recv.return_value = target_dest_str.encode('utf-8')

        client_cert = {"subject": ((("commonName", "unauthorized.client.com"),),)}
        mock_tls_client_socket.getpeercert.return_value = client_cert

        handle_client_connection(mock_tls_client_socket)

        mock_tls_client_socket.getpeercert.assert_called_once()
        mock_create_conn.assert_not_called()
        mock_forward_data.assert_not_called()
        mock_tls_client_socket.close.assert_called_once()
        self.assertGreaterEqual(mock_server_lock_instance.__enter__.call_count, 1) # For increment
        self.assertGreaterEqual(mock_server_lock_instance.__exit__.call_count, 1) # For decrement (in finally)

    @patch('server.server.active_connections_count', 0)
    def test_target_connect_refused(self, mock_active_count_zero, mock_resolve_path, mock_get_list, mock_get_int, mock_get_str, mock_create_conn, mock_forward_data):
        mock_tls_client_socket = MagicMock(spec=ssl.SSLSocket)
        mock_tls_client_socket.getpeername.return_value = ("client.ip", 12345)
        target_dest_str = f"{MOCK_SERVER_DYNAMIC_TARGET_HOST}:{MOCK_SERVER_DYNAMIC_TARGET_PORT}\n"
        mock_tls_client_socket.recv.return_value = target_dest_str.encode('utf-8')

        # Simulate mTLS success (no specific CN check by overriding allowed_client_cns to be empty for this call)
        def temp_get_list_str(key, default=None, required=False, delimiter=','):
            if key == "SHIELDNET_TLS_ALLOWED_CLIENT_CNS": return []
            return mock_server_get_env_list_str(key,default,required,delimiter)
        mock_get_list.side_effect = temp_get_list_str

        client_cert = {"subject": ((("commonName", "any.client.com"),),)}
        mock_tls_client_socket.getpeercert.return_value = client_cert

        mock_create_conn.side_effect = ConnectionRefusedError("Target refused")

        handle_client_connection(mock_tls_client_socket)

        mock_create_conn.assert_called_once()
        mock_forward_data.assert_not_called()
        mock_tls_client_socket.close.assert_called_once()

        # Restore mock_get_list side_effect if other tests in this class depend on original
        mock_get_list.side_effect = mock_server_get_env_list_str


# Patching for server.main
@patch('server.server.load_env_config', Mock(return_value=True))
@patch('server.server.setup_logging', Mock())
@patch('socket.socket') # Mock listening socket in main
@patch('ssl.SSLContext') # Mock SSLContext in main
@patch('server.server.get_env_str', side_effect=mock_server_get_env_str)
@patch('server.server.get_env_int', side_effect=mock_server_get_env_int)
@patch('server.server.resolve_env_path', side_effect=mock_server_resolve_env_path)
class TestServerMain(unittest.TestCase):
    def test_main_successful_startup_and_shutdown(self, mock_main_resolve_path, mock_main_get_int, mock_main_get_str, MockSSLContextMain, mock_main_socket_constructor, mock_main_setup_logging, mock_main_load_env):
        mock_listening_socket = MagicMock(spec=socket.socket)
        mock_listening_socket.accept.side_effect = KeyboardInterrupt
        mock_main_socket_constructor.return_value = mock_listening_socket

        mock_ssl_context_main_inst = MagicMock(spec=ssl.SSLContext)
        MockSSLContextMain.return_value = mock_ssl_context_main_inst

        test_args = ['server.py', '--config', 'dummy_server.env']
        with patch.object(sys, 'argv', test_args):
            with self.assertRaises(SystemExit) as cm:
                with patch('logging.info'), patch('logging.error'), patch('logging.critical'), patch('logging.warning'):
                    server_main()
            self.assertEqual(cm.exception.code, 0)

        mock_main_load_env.assert_called_with('dummy_server.env')
        mock_main_setup_logging.assert_called()
        MockSSLContextMain.assert_called_with(ssl.PROTOCOL_TLS_SERVER)

        expected_server_cert = os.path.abspath(os.path.join(TEST_SERVER_ENV_BASE_DIR, MOCK_ENV_VALUES_SERVER["SHIELDNET_TLS_SERVER_CERT"]))
        expected_server_key = os.path.abspath(os.path.join(TEST_SERVER_ENV_BASE_DIR, MOCK_ENV_VALUES_SERVER["SHIELDNET_TLS_SERVER_KEY"]))
        mock_ssl_context_main_inst.load_cert_chain.assert_called_with(certfile=expected_server_cert, keyfile=expected_server_key)

        # Check if mTLS was configured (it is in MOCK_ENV_VALUES_SERVER)
        expected_client_ca = os.path.abspath(os.path.join(TEST_SERVER_ENV_BASE_DIR, MOCK_ENV_VALUES_SERVER["SHIELDNET_TLS_CLIENT_CA_CERT"]))
        mock_ssl_context_main_inst.load_verify_locations.assert_called_with(cafile=expected_client_ca)
        self.assertEqual(mock_ssl_context_main_inst.verify_mode, ssl.CERT_REQUIRED)

        mock_listening_socket.bind.assert_called_with((MOCK_ENV_VALUES_SERVER["SHIELDNET_SERVER_LISTENER_HOST"], MOCK_ENV_VALUES_SERVER["SHIELDNET_SERVER_LISTENER_PORT"]))
        mock_listening_socket.close.assert_called()

    def test_main_config_error_missing_cert(self, mock_main_resolve_path, mock_main_get_int, mock_main_get_str, MockSSLContextMain, mock_main_socket_constructor, mock_main_setup_logging, mock_main_load_env):
        def temp_get_str_effect(key, default=None, required=False):
            if key == "SHIELDNET_TLS_SERVER_CERT":
                if required: raise EnvConfigError("Server cert is required.")
                return None # Simulate missing
            return mock_server_get_env_str(key, default, required)
        mock_main_get_str.side_effect = temp_get_str_effect

        test_args = ['server.py', '--config', 'dummy_server.env']
        with patch.object(sys, 'argv', test_args):
            with self.assertRaises(SystemExit) as cm:
                with patch('logging.error') as mock_log_error:
                    server_main()
            self.assertEqual(cm.exception.code, 1)
            # This specific error is now caught earlier by the "if not server_cert_path" check
            mock_log_error.assert_any_call("FATAL: Server certificate or key path not configured.")
            # mock_log_error.assert_any_call("FATAL: Configuration error from environment: Server cert is required.")

        mock_main_get_str.side_effect = mock_server_get_env_str # Restore


if __name__ == '__main__':
    unittest.main(verbosity=2)
```
