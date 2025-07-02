import socket
import ssl
import argparse
import threading
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def forward_data(source_socket, dest_socket, direction_tag):
    """Forwards data from source_socket to dest_socket."""
    try:
        while True:
            data = source_socket.recv(4096)
            if not data:
                logging.info(f"Connection closed by {source_socket.getpeername()} (or source closed). Shutting down {direction_tag} forwarder.")
                break
            dest_socket.sendall(data)
            # logging.debug(f"Forwarded {len(data)} bytes via {direction_tag}")
    except OSError as e:
        # This can happen if the other side closes abruptly
        logging.warning(f"Socket error during data forwarding {direction_tag}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during data forwarding {direction_tag}: {e}", exc_info=True)
    finally:
        logging.info(f"Closing forwarding {direction_tag}.")
        # Sockets will be closed by the main handler (handle_local_connection)
        pass

def handle_local_connection(local_conn_socket, local_addr, remote_host, remote_port, ca_file):
    """
    Handles a single local connection:
    1. Establishes a TLS connection to the remote ShieldNet server.
    2. Sets up two threads to forward data bidirectionally between local_conn and the TLS server.
    """
    logging.info(f"Accepted local connection from {local_addr}. Attempting to connect to remote server {remote_host}:{remote_port} via TLS.")

    tls_server_socket = None
    try:
        # Create a standard TCP socket
        plain_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Setup SSL context for client-side TLS
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True # Verifies server hostname against its certificate
        context.verify_mode = ssl.CERT_REQUIRED # Requires server to provide a certificate

        if ca_file:
            try:
                context.load_verify_locations(cafile=ca_file)
                logging.info(f"Loaded CA certificate {ca_file} for server verification.")
            except FileNotFoundError:
                logging.error(f"CA certificate file {ca_file} not found. Cannot verify server.")
                return # local_conn_socket will be closed in finally
            except ssl.SSLError as e:
                logging.error(f"Error loading CA certificate {ca_file}: {e}. Cannot verify server.")
                return
        else:
            # If no CA file is provided, it will use system's default CAs.
            # For self-signed certs, this will likely fail unless the self-signed CA is in the system store.
            # The task implies --ca is the primary way for self-signed certs.
            logging.warning("No CA file provided (--ca). TLS connection will use system default CAs for server verification.")
            # For self-signed certs, it's better to explicitly disable verification if no CA is given,
            # but the requirement is to support --ca. If --ca is omitted, it's up to the user.
            # For this exercise, we'll assume if --ca is not given, they might be using a publicly trusted cert
            # or have the self-signed CA in their system store. Or it will fail, which is fine.

        # Wrap the socket for TLS:
        # server_hostname should match the CN or SAN in the server's certificate.
        # If the server's cert is for 'localhost' and remote_host is '127.0.0.1', this might mismatch.
        # For self-signed certs, this is often the same as remote_host if cert was generated for that IP/hostname.
        # If the server certificate's Common Name (CN) or Subject Alternative Name (SAN)
        # does not match `remote_host`, TLS handshake will fail `check_hostname`.
        # For testing with self-signed certs where CN might be "localhost", one might need to use "localhost"
        # as remote_host or ensure the cert CN matches the IP/hostname used.
        tls_server_socket = context.wrap_socket(plain_server_socket, server_hostname=remote_host)

        tls_server_socket.connect((remote_host, remote_port))
        logging.info(f"Successfully connected to remote server {remote_host}:{remote_port} via TLS. Cipher: {tls_server_socket.cipher()}")
        logging.info(f"Server certificate: {tls_server_socket.getpeercert()}")


        # Start forwarding threads
        # Direction: Local App -> ShieldNet Client -> ShieldNet Server -> Target Service
        thread_to_remote = threading.Thread(
            target=forward_data,
            args=(local_conn_socket, tls_server_socket, f"local {local_addr} to remote {remote_host}:{remote_port}"),
            daemon=True
        )
        # Direction: Target Service -> ShieldNet Server -> ShieldNet Client -> Local App
        thread_to_local = threading.Thread(
            target=forward_data,
            args=(tls_server_socket, local_conn_socket, f"remote {remote_host}:{remote_port} to local {local_addr}"),
            daemon=True
        )

        thread_to_remote.start()
        thread_to_local.start()

        # Keep handler alive while threads are running
        while thread_to_remote.is_alive() and thread_to_local.is_alive():
            thread_to_remote.join(timeout=0.1)
            thread_to_local.join(timeout=0.1)

    except ssl.SSLCertVerificationError as e:
        logging.error(f"TLS Certificate Verification Error for {remote_host}:{remote_port}: {e}. Ensure --ca points to the correct CA cert, and server cert is valid.")
    except ssl.SSLError as e:
        # This can include handshake errors, protocol mismatches, etc.
        logging.error(f"TLS/SSL Error connecting to {remote_host}:{remote_port}: {e}")
    except socket.gaierror as e:
        logging.error(f"DNS resolution error for remote host {remote_host}: {e}")
    except ConnectionRefusedError:
        logging.error(f"Connection to remote server {remote_host}:{remote_port} refused.")
    except socket.timeout:
        logging.error(f"Timeout connecting to remote server {remote_host}:{remote_port}.")
    except Exception as e:
        logging.error(f"Error in handling local connection {local_addr} to remote {remote_host}:{remote_port}: {e}", exc_info=True)
    finally:
        logging.info(f"Closing connection for local client {local_addr} and its TLS connection to server.")
        if local_conn_socket:
            try:
                local_conn_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            local_conn_socket.close()
        if tls_server_socket:
            try:
                tls_server_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass # Might already be closed if server connection failed
            tls_server_socket.close()
        logging.info(f"Connection for {local_addr} fully closed.")

def main():
    parser = argparse.ArgumentParser(description="ShieldNet TLS Client: Listens for local TCP connections and forwards them over TLS.")
    parser.add_argument('--listen-port', type=int, required=True, help="Local port to listen for incoming application connections.")
    parser.add_argument('--remote-host', type=str, required=True, help="Remote ShieldNet server host.")
    parser.add_argument('--remote-port', type=int, required=True, help="Remote ShieldNet server port.")
    parser.add_argument('--ca', type=str, help="Path to the CA certificate file to verify the server (PEM). Required for self-signed certs.")
    # Optional: --tls flag (default: enabled). Here, client always uses TLS.

    args = parser.parse_args()

    if not args.ca:
        logging.warning("IMPORTANT: No --ca file specified. Server certificate verification might fail if the server uses a self-signed certificate not in the system's trust store. For self-signed certificates, --ca is required.")


    local_server_socket = None
    try:
        local_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        local_server_socket.bind(('127.0.0.1', args.listen_port)) # Listen on loopback only for local apps
        local_server_socket.listen(5)
        logging.info(f"Client listening on 127.0.0.1:{args.listen_port} for local application connections...")
        logging.info(f"Will forward traffic to ShieldNet server at {args.remote_host}:{args.remote_port} over TLS.")

        while True:
            try:
                local_conn_socket, local_addr = local_server_socket.accept()
                # No TLS wrap here, this is the plain TCP connection from the local application
                # logging.info(f"Accepted local connection from {local_addr}")

                # Create a new thread to handle this local connection and its tunnel
                thread = threading.Thread(
                    target=handle_local_connection,
                    args=(local_conn_socket, local_addr, args.remote_host, args.remote_port, args.ca),
                    daemon=True
                )
                thread.start()
            except Exception as e:
                logging.error(f"Error accepting local connection: {e}", exc_info=True)


    except OSError as e:
        logging.error(f"Client local server socket OS error: {e}. Port {args.listen_port} might be in use.")
    except KeyboardInterrupt:
        logging.info("Client shutting down due to KeyboardInterrupt...")
    except Exception as e:
        logging.error(f"Critical client error: {e}", exc_info=True)
    finally:
        logging.info("Closing client listening socket.")
        if local_server_socket:
            local_server_socket.close()
        logging.info("Client has shut down.")

if __name__ == '__main__':
    main()
