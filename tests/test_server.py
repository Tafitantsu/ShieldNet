import unittest
from unittest.mock import Mock, patch, ANY, call
import socket
import ssl
import threading
import time

# Adjust import path
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.server import handle_client_connection
# Mocking global statistics variables and lock from server.py
# This is a bit tricky; ideally, these would be part of a class or passed around.
# For now, we can patch them where they are used if they are module-level globals.

# Dummy config for testing
DEFAULT_TEST_SERVER_CONFIG = {
    "target_service": {
        "host": "targethost.example.com",
        "port": 8080
    },
    "tls": {
        "client_ca_cert": "/path/to/client_ca.crt", # For mTLS
        "allowed_client_cns": ["testclient.example.com", "another.valid.client"],
        "min_version_str": "TLSv1.2" # Not directly used by handler, but by context setup in main
    },
    "timeouts": {
        "socket_data": 1, # Short for tests
        # "forward_connect_timeout": 1 # Not directly used by handler, but by create_connection call
    },
    "logging": {"log_level": "DEBUG"} # For enabling debug logs during test if needed
}

# Mocking the global active_connections_lock from server.py
# This needs to be done carefully if tests run in parallel or affect global state.
# For simplicity in this example, we assume it's okay to patch globally for the test.
mock_server_active_connections_lock = Mock(spec=threading.Lock)
mock_server_active_connections_lock.__enter__ = Mock()
mock_server_active_connections_lock.__exit__ = Mock(return_value=False)


@patch('src.server.active_connections_lock', new=mock_server_active_connections_lock)
class TestServerHandleClientConnection(unittest.TestCase):

    def setUp(self):
        self.mock_app_config = DEFAULT_TEST_SERVER_CONFIG.copy()

        self.forward_data_patcher = patch('src.server.forward_data')
        self.mock_forward_data = self.forward_data_patcher.start()
        self.addCleanup(self.forward_data_patcher.stop)

        # Patch 'socket.create_connection' used by the handler to connect to target service
        self.create_connection_patcher = patch('socket.create_connection')
        self.mock_create_connection = self.create_connection_patcher.start()
        self.mock_forward_socket = Mock(spec=socket.socket) # Mock for the connection to target
        self.mock_create_connection.return_value = self.mock_forward_socket
        self.addCleanup(self.create_connection_patcher.stop)

        # Reset active_connections_count for each test if it's a global in server.py
        # This is more involved if it's truly global. A better design would avoid this.
        # For now, we assume its changes are observable via logging or side effects
        # or we can patch 'src.server.active_connections_count' if it's directly accessible.
        # Let's try patching it if it's a direct global.
        self.active_count_patcher = patch('src.server.active_connections_count', 0) # Start at 0
        self.mock_active_count = self.active_count_patcher.start()
        self.addCleanup(self.active_count_patcher.stop)


    def test_handle_client_connection_successful_mtls_cn_auth(self):
        mock_tls_client_socket = Mock(spec=ssl.SSLSocket)
        mock_tls_client_socket.getpeername.return_value = ("client.ip", 12345)
        mock_tls_client_socket.cipher.return_value = ("TEST_CIPHER", "TLSv1.2", 128)

        # Simulate client cert with a valid CN
        client_cert = {
            "subject": ((("commonName", "testclient.example.com"),),),
            "subjectAltName": (("DNS", "testclient.example.com"),) # Example SAN
        }
        mock_tls_client_socket.getpeercert.return_value = client_cert

        # --- Test Execution ---
        handler_thread = threading.Thread(target=handle_client_connection,
                                          args=(mock_tls_client_socket, self.mock_app_config))
        handler_thread.start()
        time.sleep(0.1) # Allow threads to spawn

        # --- Assertions ---
        # mTLS checks
        mock_tls_client_socket.getpeercert.assert_called_once()

        # Connection to target service
        self.mock_create_connection.assert_called_once_with(
            (self.mock_app_config["target_service"]["host"], self.mock_app_config["target_service"]["port"]),
            timeout=ANY # forward_connect_timeout (currently 10, but use ANY for flexibility)
        )

        # Socket timeouts set
        mock_tls_client_socket.settimeout.assert_any_call(self.mock_app_config["timeouts"]["socket_data"])
        self.mock_forward_socket.settimeout.assert_called_with(self.mock_app_config["timeouts"]["socket_data"])

        # forward_data calls
        self.assertEqual(self.mock_forward_data.call_count, 2)
        # Args for call 1: tls_client_socket -> forward_socket
        args_call1 = self.mock_forward_data.call_args_list[0][0]
        self.assertEqual(args_call1[0], mock_tls_client_socket)
        self.assertEqual(args_call1[1], self.mock_forward_socket)
        self.assertIsInstance(args_call1[3], threading.Event) # shutdown_event
        self.assertTrue(callable(args_call1[4])) # stats_callback for to_target

        # Args for call 2: forward_socket -> tls_client_socket
        args_call2 = self.mock_forward_data.call_args_list[1][0]
        self.assertEqual(args_call2[0], self.mock_forward_socket)
        self.assertEqual(args_call2[1], mock_tls_client_socket)
        self.assertIsInstance(args_call2[3], threading.Event) # shutdown_event
        self.assertTrue(callable(args_call2[4])) # stats_callback for to_client

        # Simulate forward_data completion
        if self.mock_forward_data.call_count == 2:
            shutdown_event_from_mock = self.mock_forward_data.call_args_list[0][0][3]
            shutdown_event_from_mock.set()

        handler_thread.join(timeout=0.5)
        self.assertFalse(handler_thread.is_alive(), "Handler thread did not terminate")

        # Socket cleanup
        mock_tls_client_socket.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        mock_tls_client_socket.close.assert_called_once()
        self.mock_forward_socket.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        self.mock_forward_socket.close.assert_called_once()

        # Check active_connections_lock usage (simplified check)
        self.assertGreaterEqual(mock_server_active_connections_lock.__enter__.call_count, 1) # increment
        self.assertGreaterEqual(mock_server_active_connections_lock.__exit__.call_count, 1) # decrement


    def test_handle_client_connection_mtls_cn_auth_fail(self):
        mock_tls_client_socket = Mock(spec=ssl.SSLSocket)
        mock_tls_client_socket.getpeername.return_value = ("client.ip", 12345)
        mock_tls_client_socket.cipher.return_value = ("TEST_CIPHER", "TLSv1.2", 128)

        # Simulate client cert with an invalid CN
        client_cert = {"subject": ((("commonName", "unauthorized.client.com"),),)}
        mock_tls_client_socket.getpeercert.return_value = client_cert

        handle_client_connection(mock_tls_client_socket, self.mock_app_config)

        mock_tls_client_socket.getpeercert.assert_called_once()
        self.mock_create_connection.assert_not_called() # Should fail before this
        self.mock_forward_data.assert_not_called()

        # Socket should be closed due to auth failure
        mock_tls_client_socket.close.assert_called_once()
        # Decrement of active connections should still happen in finally
        self.assertGreaterEqual(mock_server_active_connections_lock.__enter__.call_count, 1) # For increment
        self.assertGreaterEqual(mock_server_active_connections_lock.__exit__.call_count, 1) # For decrement


    def test_handle_client_connection_no_mtls_cn_check(self):
        # Modify config for this test: no allowed_client_cns, but client_ca_cert is still there (mTLS enabled)
        config_no_cn_check = self.mock_app_config.copy()
        config_no_cn_check["tls"] = config_no_cn_check["tls"].copy()
        config_no_cn_check["tls"]["allowed_client_cns"] = [] # Empty list means any cert from CA is fine

        mock_tls_client_socket = Mock(spec=ssl.SSLSocket)
        mock_tls_client_socket.getpeername.return_value = ("client.ip", 12345)
        mock_tls_client_socket.cipher.return_value = ("TEST_CIPHER", "TLSv1.2", 128)
        client_cert = {"subject": ((("commonName", "any.client.com"),),)} # CN doesn't matter now
        mock_tls_client_socket.getpeercert.return_value = client_cert

        handler_thread = threading.Thread(target=handle_client_connection,
                                          args=(mock_tls_client_socket, config_no_cn_check))
        handler_thread.start()
        time.sleep(0.1)

        mock_tls_client_socket.getpeercert.assert_called_once() # Still gets cert to log
        self.mock_create_connection.assert_called_once()
        self.assertEqual(self.mock_forward_data.call_count, 2)

        if self.mock_forward_data.call_count == 2:
            shutdown_event_from_mock = self.mock_forward_data.call_args_list[0][0][3]
            shutdown_event_from_mock.set()
        handler_thread.join(timeout=0.5)
        self.assertFalse(handler_thread.is_alive())


    def test_handle_client_connection_target_connect_refused(self):
        mock_tls_client_socket = Mock(spec=ssl.SSLSocket)
        mock_tls_client_socket.getpeername.return_value = ("client.ip", 12345)
        mock_tls_client_socket.cipher.return_value = ("TEST_CIPHER", "TLSv1.2", 128)
        # No CN check for this test, simplify config for tls section
        config_simple_mtls = self.mock_app_config.copy()
        config_simple_mtls["tls"] = {
            "client_ca_cert": "/path/to/client_ca.crt",
            "allowed_client_cns": [] # No specific CN check
        }
        client_cert = {"subject": ((("commonName", "client.com"),),)}
        mock_tls_client_socket.getpeercert.return_value = client_cert

        self.mock_create_connection.side_effect = ConnectionRefusedError("Target service refused connection")

        handle_client_connection(mock_tls_client_socket, config_simple_mtls)

        self.mock_create_connection.assert_called_once()
        self.mock_forward_data.assert_not_called() # Forwarding threads should not start

        mock_tls_client_socket.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        mock_tls_client_socket.close.assert_called_once()
        self.mock_forward_socket.close.assert_not_called() # forward_socket was never successfully opened and assigned


if __name__ == '__main__':
    unittest.main(verbosity=2)
