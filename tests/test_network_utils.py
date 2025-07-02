import unittest
from unittest.mock import Mock, call, patch
import socket
import threading # For testing shutdown_event

# Adjust import path
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.common.network_utils import forward_data

class TestNetworkUtils(unittest.TestCase):

    def test_forward_data_simple_transfer(self):
        source_socket = Mock(spec=socket.socket)
        dest_socket = Mock(spec=socket.socket)

        # Simulate recv calls: first returns data, second returns empty (EOF)
        source_socket.recv.side_effect = [b"data1", b"data2", b""]
        source_socket.getpeername.return_value = ("127.0.0.1", 12345)

        stats_callback = Mock()

        forward_data(source_socket, dest_socket, "TestDir", stats_callback=stats_callback)

        # Check that sendall was called correctly
        calls = [call(b"data1"), call(b"data2")]
        dest_socket.sendall.assert_has_calls(calls)
        self.assertEqual(dest_socket.sendall.call_count, 2)

        # Check stats_callback
        stats_calls = [call(len(b"data1")), call(len(b"data2"))]
        stats_callback.assert_has_calls(stats_calls)
        self.assertEqual(stats_callback.call_count, 2)


    def test_forward_data_recv_os_error(self):
        source_socket = Mock(spec=socket.socket)
        dest_socket = Mock(spec=socket.socket)

        source_socket.recv.side_effect = OSError("Mocked Recv Error")
        source_socket.getpeername.return_value = ("127.0.0.1", 12345)

        forward_data(source_socket, dest_socket, "TestDirError")

        # sendall should not have been called
        dest_socket.sendall.assert_not_called()

    def test_forward_data_sendall_os_error(self):
        source_socket = Mock(spec=socket.socket)
        dest_socket = Mock(spec=socket.socket)

        source_socket.recv.side_effect = [b"data1", b""] # Send one chunk then EOF
        source_socket.getpeername.return_value = ("127.0.0.1", 12345)
        dest_socket.sendall.side_effect = OSError("Mocked Sendall Error")

        forward_data(source_socket, dest_socket, "TestDirSendError")

        # sendall should have been called once (and then failed)
        dest_socket.sendall.assert_called_once_with(b"data1")

    def test_forward_data_recv_socket_timeout(self):
        source_socket = Mock(spec=socket.socket)
        dest_socket = Mock(spec=socket.socket)

        # Simulate recv: timeout, then data, then EOF
        source_socket.recv.side_effect = [socket.timeout, b"data_after_timeout", b""]
        source_socket.getpeername.return_value = ("127.0.0.1", 12345)

        forward_data(source_socket, dest_socket, "TestDirRecvTimeout")

        dest_socket.sendall.assert_called_once_with(b"data_after_timeout")

    def test_forward_data_sendall_socket_timeout(self):
        source_socket = Mock(spec=socket.socket)
        dest_socket = Mock(spec=socket.socket)

        source_socket.recv.side_effect = [b"data_to_send", b""]
        source_socket.getpeername.return_value = ("127.0.0.1", 12345)
        dest_socket.sendall.side_effect = socket.timeout # Timeout on the first sendall

        forward_data(source_socket, dest_socket, "TestDirSendTimeout")

        # sendall should have been attempted once
        dest_socket.sendall.assert_called_once_with(b"data_to_send")


    def test_forward_data_with_shutdown_event(self):
        source_socket = Mock(spec=socket.socket)
        dest_socket = Mock(spec=socket.socket)
        shutdown_event = threading.Event()

        # Simulate continuous data flow until shutdown
        def recv_side_effect(bufsize):
            if shutdown_event.is_set():
                return b"" # Stop sending data if shutdown is set
            return b"data_packet"

        source_socket.recv.side_effect = recv_side_effect
        source_socket.getpeername.return_value = ("127.0.0.1", 12345)

        # Set the shutdown event after a short delay in a separate thread
        def trigger_shutdown():
            # Let some data flow
            for _ in range(5): # Allow a few packets
                 if source_socket.recv.call_count > 2 : break # ensure some calls happened
                 threading.Event().wait(0.001) # short sleep
            shutdown_event.set()

        shutdown_thread = threading.Thread(target=trigger_shutdown)
        shutdown_thread.start()

        forward_data(source_socket, dest_socket, "TestDirShutdown", shutdown_event=shutdown_event)
        shutdown_thread.join()

        # Check that sendall was called at least once but not indefinitely
        self.assertGreater(dest_socket.sendall.call_count, 0)
        # The exact number of calls before shutdown can vary due to timing,
        # so we don't assert a specific count other than it happened.
        # Verify that the loop terminated due to shutdown_event.
        # This is implicitly tested by the test not hanging and by log messages if observed.


    def test_forward_data_stats_callback_exception_handling(self):
        source_socket = Mock(spec=socket.socket)
        dest_socket = Mock(spec=socket.socket)

        source_socket.recv.side_effect = [b"data1", b""]
        source_socket.getpeername.return_value = ("127.0.0.1", 12345)

        stats_callback = Mock(side_effect=Exception("Callback error"))

        # Patch logging to check for error messages
        with patch('src.common.network_utils.logging') as mock_logging:
            forward_data(source_socket, dest_socket, "TestDirCallbackErr", stats_callback=stats_callback)

        dest_socket.sendall.assert_called_once_with(b"data1")
        stats_callback.assert_called_once_with(len(b"data1"))

        # Check that an error was logged due to callback exception
        error_logged = False
        for call_args in mock_logging.error.call_args_list:
            if "Error in stats_callback" in call_args[0][0]:
                error_logged = True
                break
        self.assertTrue(error_logged, "Error from stats_callback was not logged")


if __name__ == '__main__':
    unittest.main(verbosity=2)
