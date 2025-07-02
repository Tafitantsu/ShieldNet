import unittest
from unittest.mock import Mock, patch, ANY, call
import socket
import ssl
import threading
import time # For testing retries

# Adjust import path
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.client import handle_local_connection
# Assuming config_loader and network_utils are tested separately
# We will mock their outputs/effects where client.py uses them.

# Dummy config for testing
DEFAULT_TEST_CLIENT_CONFIG = {
    "remote_server": {
        "host": "remotehost.example.com",
        "port": 8443,
        "server_ca_cert": "/path/to/ca.crt" # Assume validated and path resolved
    },
    "tls": {
        "client_cert": "/path/to/client.crt", # Assume validated
        "client_key": "/path/to/client.key",   # Assume validated
        "min_version_str": "TLSv1.2"
    },
    "timeouts": {
        "connect": 1, # Short for tests
        "tls_handshake": 1, # Short for tests
        "socket_data": 1, # Short for tests
        "reconnect_delay_base": 0.01, # Very short for tests
        "reconnect_max_retries": 2
    },
    # logging config not directly used by handle_local_connection logic being tested here
}


class TestClientHandleLocalConnection(unittest.TestCase):

    def setUp(self):
        # Mock the global config that would be loaded in client.main()
        # For tests focusing on handle_local_connection, we pass app_config directly.
        self.mock_app_config = DEFAULT_TEST_CLIENT_CONFIG.copy()

        # Patch common.network_utils.forward_data to prevent actual forwarding
        self.forward_data_patcher = patch('src.client.forward_data')
        self.mock_forward_data = self.forward_data_patcher.start()
        self.addCleanup(self.forward_data_patcher.stop)

    @patch('socket.socket')
    @patch('ssl.SSLContext')
    def test_handle_local_connection_successful_connect(self, mock_ssl_context_constructor, mock_socket_constructor):
        # --- Mocks Setup ---
        # Mock local connection socket
        mock_local_conn = Mock(spec=socket.socket)
        mock_local_conn.getpeername.return_value = ("127.0.0.1", 54321)

        # Mock the plain socket returned by socket.socket()
        mock_plain_socket_instance = Mock(spec=socket.socket)
        mock_socket_constructor.return_value = mock_plain_socket_instance

        # Mock SSLContext instance and its methods
        mock_ssl_context_instance = Mock(spec=ssl.SSLContext)
        mock_ssl_context_constructor.return_value = mock_ssl_context_instance

        # Mock the TLS wrapped socket
        mock_tls_socket_instance = Mock(spec=ssl.SSLSocket)
        mock_ssl_context_instance.wrap_socket.return_value = mock_tls_socket_instance
        mock_tls_socket_instance.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_tls_socket_instance.getpeercert.return_value = {"subject": ((("commonName", "remotehost.example.com"),),)}


        # --- Test Execution ---
        # Run handle_local_connection in a thread as it contains blocking join calls
        handler_thread = threading.Thread(target=handle_local_connection,
                                          args=(mock_local_conn, ("127.0.0.1", 54321), self.mock_app_config))
        handler_thread.start()

        # Allow some time for the threads inside handle_local_connection to start and for forward_data to be called
        # This is a bit fragile; a more robust way would be to use Events or check mock_forward_data.call_count
        time.sleep(0.2) # Increased sleep to allow threads to run

        # --- Assertions ---
        # Socket creation and configuration
        mock_socket_constructor.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_plain_socket_instance.settimeout.assert_any_call(self.mock_app_config["timeouts"]["connect"])
        mock_plain_socket_instance.connect.assert_called_once_with(
            (self.mock_app_config["remote_server"]["host"], self.mock_app_config["remote_server"]["port"])
        )

        # SSLContext setup
        mock_ssl_context_constructor.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        mock_ssl_context_instance.load_verify_locations.assert_called_once_with(
            cafile=self.mock_app_config["remote_server"]["server_ca_cert"]
        )
        mock_ssl_context_instance.load_cert_chain.assert_called_once_with(
            certfile=self.mock_app_config["tls"]["client_cert"],
            keyfile=self.mock_app_config["tls"]["client_key"]
        )

        # Handshake timeout before wrap_socket
        mock_plain_socket_instance.settimeout.assert_any_call(self.mock_app_config["timeouts"]["tls_handshake"])

        # Wrapping socket
        mock_ssl_context_instance.wrap_socket.assert_called_once_with(
            mock_plain_socket_instance,
            server_hostname=self.mock_app_config["remote_server"]["host"]
        )

        # Data timeouts on sockets after successful connection
        mock_local_conn.settimeout.assert_called_with(self.mock_app_config["timeouts"]["socket_data"])
        mock_tls_socket_instance.settimeout.assert_any_call(self.mock_app_config["timeouts"]["socket_data"]) # First set to None, then to data_timeout

        # Check that forward_data was called twice (for two directions)
        self.assertEqual(self.mock_forward_data.call_count, 2)
        # Check arguments of forward_data calls
        # Call 1: local_conn_socket -> tls_server_socket
        args_call1 = self.mock_forward_data.call_args_list[0][0]
        self.assertEqual(args_call1[0], mock_local_conn)
        self.assertEqual(args_call1[1], mock_tls_socket_instance)
        self.assertIn("local", args_call1[2]) # direction_tag
        self.assertIsInstance(args_call1[3], threading.Event) # shutdown_event

        # Call 2: tls_server_socket -> local_conn_socket
        args_call2 = self.mock_forward_data.call_args_list[1][0]
        self.assertEqual(args_call2[0], mock_tls_socket_instance)
        self.assertEqual(args_call2[1], mock_local_conn)
        self.assertIn("remote", args_call2[2]) # direction_tag
        self.assertIsInstance(args_call2[3], threading.Event) # shutdown_event

        # Ensure the handler thread finishes (it might be waiting on mock_forward_data if not careful)
        # If forward_data is mocked correctly (doesn't block), the thread should exit.
        # We need to make sure the mock_forward_data doesn't make the thread hang.
        # One way is to have mock_forward_data set the shutdown event.

        # Simulate forward_data threads completing by setting the event they share
        # This helps the join loop in handle_local_connection to terminate.
        # We assume the shared event is the 4th argument to forward_data (index 3)
        if self.mock_forward_data.call_count == 2:
            shutdown_event_from_mock = self.mock_forward_data.call_args_list[0][0][3]
            shutdown_event_from_mock.set()

        handler_thread.join(timeout=1) # Increased join timeout
        self.assertFalse(handler_thread.is_alive(), "Handler thread did not terminate")

        # Socket cleanup
        mock_local_conn.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        mock_local_conn.close.assert_called_once()
        mock_tls_socket_instance.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        mock_tls_socket_instance.close.assert_called_once()
        # plain_socket_instance is closed by tls_socket_instance closing


    @patch('socket.socket')
    @patch('ssl.SSLContext')
    @patch('time.sleep', return_value=None) # Mock time.sleep to speed up retry tests
    def test_handle_local_connection_connection_refused_with_retries(self, mock_time_sleep, mock_ssl_context_constructor, mock_socket_constructor):
        mock_local_conn = Mock(spec=socket.socket)
        mock_local_conn.getpeername.return_value = ("127.0.0.1", 12346)

        mock_plain_socket_instance = Mock(spec=socket.socket)
        mock_socket_constructor.return_value = mock_plain_socket_instance

        # Simulate ConnectionRefusedError for all attempts
        mock_plain_socket_instance.connect.side_effect = ConnectionRefusedError("Connection refused by server")

        # --- Test Execution ---
        handle_local_connection(mock_local_conn, ("127.0.0.1", 12346), self.mock_app_config)

        # --- Assertions ---
        # connect should be called for each attempt (initial + max_retries)
        num_attempts = self.mock_app_config["timeouts"]["reconnect_max_retries"] + 1
        self.assertEqual(mock_plain_socket_instance.connect.call_count, num_attempts)

        # time.sleep should be called max_retries times
        self.assertEqual(mock_time_sleep.call_count, self.mock_app_config["timeouts"]["reconnect_max_retries"])

        # SSLContext should not be fully set up if connect always fails
        mock_ssl_context_constructor.assert_called() # Context is created each attempt
        mock_ssl_context_instance = mock_ssl_context_constructor.return_value
        mock_ssl_context_instance.wrap_socket.assert_not_called() # wrap_socket is after connect

        # forward_data should not be called
        self.mock_forward_data.assert_not_called()

        # Local socket should be closed because all retries failed
        mock_local_conn.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        mock_local_conn.close.assert_called_once()

        # Plain socket should have been closed after each failed attempt
        self.assertEqual(mock_plain_socket_instance.close.call_count, num_attempts)


    @patch('socket.socket')
    @patch('ssl.SSLContext')
    @patch('time.sleep', return_value=None)
    def test_handle_local_connection_ssl_error_with_retries(self, mock_time_sleep, mock_ssl_context_constructor, mock_socket_constructor):
        mock_local_conn = Mock(spec=socket.socket)
        mock_local_conn.getpeername.return_value = ("127.0.0.1", 12347)

        mock_plain_socket_instance = Mock(spec=socket.socket)
        mock_socket_constructor.return_value = mock_plain_socket_instance
        mock_plain_socket_instance.connect.return_value = None # Successful connect

        mock_ssl_context_instance = Mock(spec=ssl.SSLContext)
        mock_ssl_context_constructor.return_value = mock_ssl_context_instance
        # Simulate SSL handshake error
        mock_ssl_context_instance.wrap_socket.side_effect = ssl.SSLError("Mocked SSL Handshake Error")

        handle_local_connection(mock_local_conn, ("127.0.0.1", 12347), self.mock_app_config)

        num_attempts = self.mock_app_config["timeouts"]["reconnect_max_retries"] + 1
        self.assertEqual(mock_plain_socket_instance.connect.call_count, num_attempts)
        self.assertEqual(mock_ssl_context_instance.wrap_socket.call_count, num_attempts)
        self.assertEqual(mock_time_sleep.call_count, self.mock_app_config["timeouts"]["reconnect_max_retries"])

        self.mock_forward_data.assert_not_called()
        mock_local_conn.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        mock_local_conn.close.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
