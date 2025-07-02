import socket
import logging
from typing import Callable # For type hinting the stats callback

# Define a callback type for reporting stats, e.g., bytes transferred
StatsCallback = Callable[[int], None]

def forward_data(source_socket: socket.socket,
                 dest_socket: socket.socket,
                 direction_tag: str,
                 shutdown_event: any = None, # e.g., threading.Event, for cooperative shutdown
                 stats_callback: StatsCallback = None,
                 buffer_size: int = 4096):
    """
    Forwards data from source_socket to dest_socket.
    Includes basic error handling, stats reporting, and respects socket timeouts.

    Args:
        source_socket: The socket to read data from.
        dest_socket: The socket to write data to.
        direction_tag: A string tag for logging purposes (e.g., "Client->Server").
        shutdown_event: An optional event (e.g., threading.Event) to signal shutdown.
                        The forwarding loop will check this event.
        stats_callback: An optional callback function `(bytes_transferred: int) -> None`
                        called after each successful sendall.
        buffer_size: Size of the buffer for recv.
    """
    bytes_forwarded_session = 0
    try:
        while True:
            if shutdown_event and shutdown_event.is_set():
                logging.info(f"Shutdown event triggered for {direction_tag}. Stopping data forwarding.")
                break

            try:
                # recv() will respect the socket's timeout if set.
                data = source_socket.recv(buffer_size)
            except socket.timeout:
                # This is not necessarily an error, could be normal if no data is flowing.
                # If shutdown_event is used, this allows the loop to check it periodically.
                # logging.debug(f"Socket timeout during recv in {direction_tag}, checking shutdown.")
                continue # Go back to check shutdown_event or try recv again
            except OSError as e:
                # More serious socket errors (e.g., connection reset)
                logging.warning(f"Socket error during recv in {direction_tag}: {e}. Total bytes this session: {bytes_forwarded_session}")
                break # Break the loop on significant OSError

            if not data:
                peername = "unknown"
                try:
                    peername = source_socket.getpeername()
                except (OSError, socket.error): # socket might be closed already
                    pass
                logging.info(f"Connection closed by {peername} (or source closed) in {direction_tag}. Total bytes this session: {bytes_forwarded_session}")
                break # End of data stream

            try:
                # sendall() will also respect socket's timeout.
                dest_socket.sendall(data)
                bytes_forwarded_session += len(data)
                if stats_callback:
                    try:
                        stats_callback(len(data))
                    except Exception as cb_exc:
                        logging.error(f"Error in stats_callback for {direction_tag}: {cb_exc}", exc_info=True)

            except socket.timeout:
                logging.warning(f"Socket timeout during sendall in {direction_tag} after forwarding {bytes_forwarded_session} bytes. Potential network issue or unresponsive peer.")
                # Depending on policy, we might break here or try again. For now, break.
                break
            except OSError as e:
                logging.warning(f"Socket error during sendall in {direction_tag}: {e}. Total bytes this session: {bytes_forwarded_session}")
                break # Break the loop

            # logging.debug(f"Forwarded {len(data)} bytes via {direction_tag}. Session total: {bytes_forwarded_session}")

    except Exception as e:
        # Catch-all for unexpected errors in the forwarding loop itself
        logging.error(f"Unexpected error during data forwarding in {direction_tag}: {e}. Total bytes this session: {bytes_forwarded_session}", exc_info=True)
    finally:
        logging.info(f"Finished forwarding for {direction_tag}. Total bytes transferred in this session: {bytes_forwarded_session}.")
        # Sockets are not closed here; they should be managed by the calling handler
        # (e.g., handle_local_connection or handle_client_connection)
        # This ensures that if one direction of forwarding stops (e.g., due to FIN),
        # the other direction can still transmit remaining data until it also closes.
        # The calling handler is responsible for ensuring both sockets are eventually closed.
        # If a shutdown_event is used, the caller might also want to signal the other thread.

# Example usage (not run directly, but for illustration)
if __name__ == '__main__':
    # This is just for illustrative purposes on how it might be called.
    # Actual usage will be in client.py and server.py

    # Setup basic logging for the example
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

    # Mock sockets for testing
    class MockSocket:
        def __init__(self, name="mock", data_to_recv=None):
            self.name = name
            self.sent_data = b""
            self.recv_buffer = data_to_recv if data_to_recv else [] # list of byte strings
            self.timeout_val = None
            self._closed = False

        def getpeername(self):
            return (self.name, 12345)

        def recv(self, bufsize):
            if self._closed: raise OSError("Socket closed")
            if not self.recv_buffer:
                if self.timeout_val is not None: # Simulate timeout if no data and timeout is set
                    # For testing, we might need a way to break out of infinite timeout polling
                    # This mock doesn't fully simulate blocking with timeout, just one shot.
                    # raise socket.timeout("mocked timeout") # Uncomment to test timeout
                    return b"" # Simulate non-blocking behavior after timeout for testing loop
                return b"" # Simulate connection closed by peer
            return self.recv_buffer.pop(0)

        def sendall(self, data):
            if self._closed: raise OSError("Socket closed")
            if self.name == "dest_socket_error_on_send": # Simulate error
                raise OSError("mocked send error")
            self.sent_data += data
            logging.debug(f"{self.name} sent: {data}")

        def settimeout(self, value):
            self.timeout_val = value
            logging.debug(f"{self.name} timeout set to {value}")

        def close(self):
            self._closed = True
            logging.debug(f"{self.name} closed")

    # --- Test Scenario 1: Simple forward ---
    print("\n--- Test Scenario 1: Simple forward ---")
    source1 = MockSocket("source1", [b"hello", b"world", b""])
    dest1 = MockSocket("dest1")
    def my_stats_callback(bytes_count):
        print(f"STATS: Transferred {bytes_count} bytes.")

    forward_data(source1, dest1, "Test1 S->D", stats_callback=my_stats_callback)
    print(f"Destination 1 received: {dest1.sent_data}")
    assert dest1.sent_data == b"helloworld"

    # --- Test Scenario 2: Source closes early ---
    print("\n--- Test Scenario 2: Source closes early (empty data means FIN) ---")
    source2 = MockSocket("source2", [b"part1", b""]) # "" means peer closed
    dest2 = MockSocket("dest2")
    forward_data(source2, dest2, "Test2 S->D")
    print(f"Destination 2 received: {dest2.sent_data}")
    assert dest2.sent_data == b"part1"

    # --- Test Scenario 3: Error on send ---
    print("\n--- Test Scenario 3: Error on send ---")
    source3 = MockSocket("source3", [b"data1", b"data2"])
    dest3 = MockSocket("dest_socket_error_on_send") # This mock will raise OSError on sendall
    forward_data(source3, dest3, "Test3 S->D")
    print(f"Destination 3 received (should be empty or partial): {dest3.sent_data}")
    # If sendall fails, no data or only first chunk might be "sent" (depending on mock)
    # Here, our mock fails on first sendall.

    # --- Test Scenario 4: Shutdown event ---
    print("\n--- Test Scenario 4: Shutdown event ---")
    source4 = MockSocket("source4", [b"chunk1", b"chunk2", b"chunk3"]*10) # Lots of data
    dest4 = MockSocket("dest4")
    event = threading.Event()

    def trigger_shutdown():
        import time
        time.sleep(0.01) # Let some data flow
        print("TRIGGERING SHUTDOWN EVENT")
        event.set()

    shutdown_trigger_thread = threading.Thread(target=trigger_shutdown)
    shutdown_trigger_thread.start()

    forward_data(source4, dest4, "Test4 S->D", shutdown_event=event)
    shutdown_trigger_thread.join()
    print(f"Destination 4 received (should be partial due to shutdown): {dest4.sent_data}")
    assert len(dest4.sent_data) < len(b"chunk1chunk2chunk3"*10) and len(dest4.sent_data) > 0

    print("\nnetwork_utils.py example tests finished.")
