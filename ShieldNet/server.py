import socket
import ssl
import argparse
import threading
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def forward_data(source_socket, dest_socket, direction):
    """Forwards data from source_socket to dest_socket."""
    try:
        while True:
            data = source_socket.recv(4096)
            if not data:
                logging.info(f"Connection closed by {source_socket.getpeername()} (or source closed). Shutting down {direction} forwarder.")
                break
            dest_socket.sendall(data)
            # logging.debug(f"Forwarded {len(data)} bytes {direction}")
    except OSError as e:
        logging.warning(f"Socket error during data forwarding {direction}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during data forwarding {direction}: {e}", exc_info=True)
    finally:
        logging.info(f"Closing forwarding sockets for {direction}.")
        # Don't close sockets here, let the main handler do it to avoid race conditions
        # or closing prematurely if one direction fails but the other is still active.
        # The main handler should ensure both source and dest are closed.
        pass


def handle_client_connection(tls_client_socket, forward_host, forward_port):
    """
    Handles a single client connection:
    1. Establishes a plain TCP connection to the forward_host:forward_port.
    2. Sets up two threads to forward data bidirectionally.
    """
    client_addr = tls_client_socket.getpeername()
    logging.info(f"Accepted TLS connection from {client_addr}")

    forward_socket = None
    try:
        forward_socket = socket.create_connection((forward_host, forward_port))
        logging.info(f"Successfully connected to forward destination {forward_host}:{forward_port} for client {client_addr}")

        # Start forwarding threads
        thread_to_forward = threading.Thread(
            target=forward_data,
            args=(tls_client_socket, forward_socket, f"{client_addr} -> {forward_host}:{forward_port}"),
            daemon=True
        )
        thread_to_client = threading.Thread(
            target=forward_data,
            args=(forward_socket, tls_client_socket, f"{forward_host}:{forward_port} -> {client_addr}"),
            daemon=True
        )

        thread_to_forward.start()
        thread_to_client.start()

        # Keep the handler alive while threads are running.
        # Threads will exit when sockets are closed or data stream ends.
        # We can join them, but if one fails, the other should also stop.
        # A simpler approach is to rely on socket closure to terminate threads.
        # However, for cleaner shutdown, we can monitor them.

        while thread_to_forward.is_alive() and thread_to_client.is_alive():
            thread_to_forward.join(timeout=0.1) # Non-blocking join
            thread_to_client.join(timeout=0.1)


    except socket.gaierror as e:
        logging.error(f"DNS resolution error for forward host {forward_host}: {e}")
    except ConnectionRefusedError:
        logging.error(f"Forward connection to {forward_host}:{forward_port} refused.")
    except socket.timeout:
        logging.error(f"Timeout connecting to forward destination {forward_host}:{forward_port}.")
    except Exception as e:
        logging.error(f"Error handling client {client_addr} or connecting to forward destination: {e}", exc_info=True)
    finally:
        logging.info(f"Closing connection for client {client_addr} and its forward socket.")
        if tls_client_socket:
            try:
                tls_client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass # Ignore if already closed
            tls_client_socket.close()
        if forward_socket:
            try:
                forward_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass # Ignore if already closed
            forward_socket.close()
        logging.info(f"Connection with {client_addr} and forward socket fully closed.")


def main():
    parser = argparse.ArgumentParser(description="ShieldNet TLS Server: Listens for TLS connections and forwards them.")
    parser.add_argument('--listen-port', type=int, required=True, help="Port to listen for incoming TLS connections.")
    parser.add_argument('--forward-host', type=str, required=True, help="Host to forward decrypted traffic to.")
    parser.add_argument('--forward-port', type=int, required=True, help="Port to forward decrypted traffic to.")
    parser.add_argument('--cert', type=str, required=True, help="Path to the server's TLS certificate file (PEM).")
    parser.add_argument('--key', type=str, required=True, help="Path to the server's TLS private key file (PEM).")
    # Optional: --tls flag (default enabled), but here we assume TLS is always on for the server.
    # If we wanted to disable it, the logic would be more complex.

    args = parser.parse_args()

    # Setup SSL context
    # Using PROTOCOL_TLS_SERVER for modern TLS, requires Python 3.6+
    # For wider compatibility with older Python, ssl.PROTOCOL_TLS could be used,
    # but PROTOCOL_TLS_SERVER is generally preferred.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=args.cert, keyfile=args.key)
        logging.info(f"Successfully loaded certificate {args.cert} and key {args.key}")
    except FileNotFoundError:
        logging.error(f"Error: Certificate or key file not found. Cert: '{args.cert}', Key: '{args.key}'")
        return
    except ssl.SSLError as e:
        logging.error(f"SSL Error loading certificate/key: {e}. Ensure cert and key are valid and match.")
        return
    except Exception as e:
        logging.error(f"An unexpected error occurred loading cert/key: {e}")
        return


    server_socket = None
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', args.listen_port))
        server_socket.listen(5) # Queue up to 5 incoming connections
        logging.info(f"Server listening on 0.0.0.0:{args.listen_port} for TLS connections...")
        logging.info(f"Forwarding decrypted traffic to {args.forward_host}:{args.forward_port}")

        while True:
            try:
                plain_client_socket, client_address = server_socket.accept()
                logging.info(f"Accepted plain TCP connection from {client_address}, attempting TLS handshake...")

                tls_client_socket = None
                try:
                    # server_side=True is implicit with PROTOCOL_TLS_SERVER context
                    tls_client_socket = context.wrap_socket(plain_client_socket, server_side=True)
                    # logging.info(f"TLS handshake successful with {client_address}. Cipher: {tls_client_socket.cipher()}")

                    # Create a new thread to handle this client connection
                    thread = threading.Thread(
                        target=handle_client_connection,
                        args=(tls_client_socket, args.forward_host, args.forward_port),
                        daemon=True # Daemon threads will exit when the main program exits
                    )
                    thread.start()

                except ssl.SSLError as e:
                    logging.error(f"TLS handshake failed with {client_address}: {e}")
                    if tls_client_socket: # Should not happen if wrap_socket failed, but defensive
                        tls_client_socket.close()
                    elif plain_client_socket: # if wrap_socket failed, plain_client_socket is still open
                        plain_client_socket.close()
                except Exception as e:
                    logging.error(f"Error during or after TLS handshake with {client_address}: {e}", exc_info=True)
                    if tls_client_socket:
                        tls_client_socket.close()
                    elif plain_client_socket:
                         plain_client_socket.close()

            except Exception as e:
                # This catches errors from server_socket.accept() itself or pre-TLS wrap issues
                logging.error(f"Error accepting connection: {e}", exc_info=True)
                # Potentially rate-limit or break if accept fails continuously

    except OSError as e:
        logging.error(f"Server socket OS error: {e}. Port {args.listen_port} might be in use or require privileges.")
    except KeyboardInterrupt:
        logging.info("Server shutting down due to KeyboardInterrupt...")
    except Exception as e:
        logging.error(f"Critical server error: {e}", exc_info=True)
    finally:
        logging.info("Closing server socket.")
        if server_socket:
            server_socket.close()
        logging.info("Server has shut down.")

if __name__ == '__main__':
    main()
