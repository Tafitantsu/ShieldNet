import socket
import ssl
import argparse
import threading
import logging
import sys # For sys.exit
import time # For session uptime

from common.config_loader import load_and_validate_config, get_config_value, ConfigError
from common.logging_setup import setup_logging
from common.network_utils import forward_data # Import the new forward_data

# Initial basic logging to catch early errors (e.g., config loading)
# This will be replaced by setup_logging() once config is loaded.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global config variable
config = None

# --- Statistics Globals ---
active_connections_count = 0
active_connections_lock = threading.Lock()

# Potentially:
# global_bytes_sent = 0
# global_bytes_received = 0
# global_stats_lock = threading.Lock()
# For now, focusing on active connections and per-session stats logged on completion.

# The old forward_data function is removed from here.

def handle_client_connection(tls_client_socket, app_config):
    """
    Handles a single client connection from a ShieldNet client:
    1. Establishes a plain TCP connection to the configured forward_host:forward_port.
    2. Sets up two threads to forward data bidirectionally.
    """
    client_addr = "unknown"
    try:
        client_addr = tls_client_socket.getpeername()
    except OSError as e:
        logging.warning(f"Could not get peername from TLS client socket ({e}), it might be already closed or in an error state.")
        try:
            if tls_client_socket: tls_client_socket.close()
        except Exception as close_exc:
            logging.debug(f"Exception while trying to close problematic socket: {close_exc}")
        return

    logging.info(f"Handling client connection from {client_addr}. Cipher: {tls_client_socket.cipher()}")

    # mTLS Client Certificate CN/SAN Validation
    client_ca_cert_path = get_config_value(app_config, "tls.client_ca_cert")
    allowed_client_cns = get_config_value(app_config, "tls.allowed_client_cns", default=[])

    if client_ca_cert_path and allowed_client_cns: # mTLS is on AND specific CNs are required
        peer_cert = tls_client_socket.getpeercert()
        if not peer_cert:
            logging.error(f"Client {client_addr} did not provide a certificate, but mTLS with CN check is configured. Closing connection.")
            tls_client_socket.close()
            return

        # Extract CNs and SANs from the client certificate
        # SANs are under 'subjectAltName', CN is in 'subject'
        # Subject is a tuple of tuples: ((('countryName', 'US'),), (('stateOrProvinceName', 'CA'),), ...)
        # CN is usually the last part of a distinguished name component.
        client_cert_subjects = []
        if 'subject' in peer_cert:
            for rdn_set in peer_cert['subject']:
                for rdn in rdn_set:
                    if rdn[0] == 'commonName':
                        client_cert_subjects.append(rdn[1])

        if 'subjectAltName' in peer_cert:
            for san_type, san_value in peer_cert['subjectAltName']:
                # We are interested in DNS names or other relevant SAN types
                # For simplicity, adding all SAN values. Refine if specific types (DNS, IP) are needed.
                client_cert_subjects.append(san_value)

        logging.debug(f"Client {client_addr} presented certificate with subjects/SANs: {client_cert_subjects}")

        is_authorized = False
        for presented_cn in client_cert_subjects:
            if presented_cn in allowed_client_cns:
                is_authorized = True
                logging.info(f"Client {client_addr} authorized via CN/SAN: '{presented_cn}'.")
                break

        if not is_authorized:
            logging.warning(f"Client {client_addr} presented certificate subjects {client_cert_subjects}, but none are in the allowed list: {allowed_client_cns}. Closing connection.")
            tls_client_socket.close()
            return
    elif client_ca_cert_path: # mTLS is on, but no specific CNs to check (any cert signed by CA is okay)
        peer_cert = tls_client_socket.getpeercert()
        if not peer_cert:
            logging.error(f"Client {client_addr} did not provide a certificate, but mTLS is configured (no specific CNs). Closing connection.")
            tls_client_socket.close()
            return
        logging.info(f"Client {client_addr} provided a certificate, validated by CA. Proceeding (no specific CN check). Cert: {peer_cert.get('subject', 'N/A')}")


    forward_host = get_config_value(app_config, "target_service.host")
    forward_port = get_config_value(app_config, "target_service.port")
    socket_data_timeout = get_config_value(app_config, "timeouts.socket_data", 60)
    # TODO: Add a specific connect_timeout for the forward_socket from server config,
    # similar to how client has `timeouts.connect`. For now, using a default for create_connection.
    forward_connect_timeout = 10 # Default, make this configurable

    forward_socket = None
    session_start_time = time.time()
    session_bytes_to_target = 0
    session_bytes_to_client = 0

    # Increment active connections count
    global active_connections_count
    with active_connections_lock:
        active_connections_count += 1
    logging.info(f"Active connections: {active_connections_count} (client {client_addr} connected)")

    try:
        forward_socket = socket.create_connection((forward_host, forward_port), timeout=forward_connect_timeout)
        logging.info(f"Successfully connected to forward destination {forward_host}:{forward_port} for client {client_addr}")

        # Apply data timeouts to both sockets involved in forwarding
        if socket_data_timeout and socket_data_timeout > 0:
            tls_client_socket.settimeout(socket_data_timeout)
            forward_socket.settimeout(socket_data_timeout)
            logging.debug(f"Set socket data timeout to {socket_data_timeout}s for {client_addr} and its target connection.")
        else: # Disable timeout
            tls_client_socket.settimeout(None)
            forward_socket.settimeout(None)
            logging.debug(f"Socket data timeout disabled for {client_addr} and its target connection.")

        # Prepare a shared shutdown event for the two forwarding threads
        shutdown_event = threading.Event()

        # Define stats callbacks
        def update_bytes_to_target(byte_count):
            nonlocal session_bytes_to_target
            session_bytes_to_target += byte_count
            # Potentially update global_bytes_sent here with lock

        def update_bytes_to_client(byte_count):
            nonlocal session_bytes_to_client
            session_bytes_to_client += byte_count
            # Potentially update global_bytes_received here with lock

        thread_to_forward = threading.Thread(
            target=forward_data,
            args=(tls_client_socket, forward_socket, f"TLS client {client_addr} -> target {forward_host}:{forward_port}", shutdown_event, update_bytes_to_target),
            daemon=True, name=f"Fwd-ToTarget-{client_addr}"
        )
        thread_to_client = threading.Thread(
            target=forward_data,
            args=(forward_socket, tls_client_socket, f"Target {forward_host}:{forward_port} -> TLS client {client_addr}", shutdown_event, update_bytes_to_client),
            daemon=True, name=f"Fwd-ToClient-{client_addr}"
        )

        thread_to_forward.start()
        thread_to_client.start()

        while thread_to_forward.is_alive() and thread_to_client.is_alive():
            thread_to_forward.join(timeout=0.1)
            thread_to_client.join(timeout=0.1)

    except socket.gaierror as e:
        logging.error(f"DNS resolution error for forward host {forward_host} (client {client_addr}): {e}")
    except ConnectionRefusedError:
        logging.error(f"Forward connection to {forward_host}:{forward_port} refused (client {client_addr}).")
    except socket.timeout:
        logging.error(f"Timeout connecting to forward destination {forward_host}:{forward_port} (client {client_addr}).")
    except Exception as e:
        logging.error(f"Error handling client {client_addr} or connecting to forward destination: {e}", exc_info=True)
    finally:
        # Ensure shutdown event is set for the other thread if one fails.
        if 'shutdown_event' in locals(): # Check if shutdown_event was initialized
            shutdown_event.set()

        session_uptime = time.time() - session_start_time
        logging.info(
            f"Session ended for client {client_addr}. "
            f"Uptime: {session_uptime:.2f}s. "
            f"Bytes to target: {session_bytes_to_target}. "
            f"Bytes to client: {session_bytes_to_client}."
        )

        # Decrement active connections count
        with active_connections_lock:
            active_connections_count -= 1
        logging.info(f"Active connections: {active_connections_count} (client {client_addr} disconnected)")

        # Update global counters (if implemented)
        # with global_stats_lock:
        #     global_bytes_sent += session_bytes_to_target
        #     global_bytes_received += session_bytes_to_client

        logging.info(f"Closing connection for client {client_addr} and its forward socket.")
        if tls_client_socket:
            try:
                tls_client_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            tls_client_socket.close()
        if forward_socket:
            try:
                forward_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            forward_socket.close()
        logging.info(f"Connection with {client_addr} and forward socket fully closed.")


def main():
    global config

    parser = argparse.ArgumentParser(description="ShieldNet TLS Server")
    parser.add_argument('--config', type=str, default='config/server_config.yaml', help="Path to the server configuration file (default: config/server_config.yaml).")
    parser.add_argument('--verbose', '-v', action='store_const', const='DEBUG', help="Enable DEBUG level logging. Overrides config file log level.")
    parser.add_argument('--debug', action='store_const', const='DEBUG', help="Alias for --verbose.")

    args = parser.parse_args()
    cli_log_level_override = args.verbose or args.debug

    try:
        config = load_and_validate_config(args.config, "server")
        # Setup logging using the loaded configuration
        setup_logging(get_config_value(config, "logging", default={}), cli_log_level_override=cli_log_level_override)
        logging.info(f"Configuration loaded successfully from {args.config}")
    except FileNotFoundError:
        logging.error(f"FATAL: Configuration file not found: {args.config}. Please ensure the path is correct.")
        sys.exit(1)
    except ConfigError as e:
        logging.error(f"FATAL: Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"FATAL: Failed to load or validate configuration: {e}", exc_info=True)
        sys.exit(1)

    # Extract essential config values for SSLContext setup
    server_cert_path = get_config_value(config, "tls.server_cert", required=True)
    server_key_path = get_config_value(config, "tls.server_key", required=True)
    client_ca_cert_path = get_config_value(config, "tls.client_ca_cert")
    min_tls_version_str = get_config_value(config, "tls.min_version_str", "TLSv1.2")
    # allowed_client_cns = get_config_value(config, "tls.allowed_client_cns", []) # For CN validation later

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    if min_tls_version_str.upper() == "TLSV1.3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        logging.debug("TLS minimum version set to TLSv1.3")
    elif min_tls_version_str.upper() == "TLSV1.2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        logging.debug("TLS minimum version set to TLSv1.2")
    else:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        logging.warning(f"Unsupported TLS version '{min_tls_version_str}' in config, defaulting to TLSv1.2 for server.")

    # Consider context.set_ciphers('ECDHE+AESGCM:CHACHA20') if specific ciphers are desired.

    try:
        context.load_cert_chain(certfile=server_cert_path, keyfile=server_key_path)
        logging.info(f"Successfully loaded server certificate {server_cert_path} and key {server_key_path}")

        if client_ca_cert_path: # This enables mTLS
            context.load_verify_locations(cafile=client_ca_cert_path)
            context.verify_mode = ssl.CERT_REQUIRED # Require client certificate and verify it
            logging.info(f"mTLS enabled: Loaded client CA {client_ca_cert_path}. Client certificates will be required and verified.")
        else:
            # Standard TLS: Server authenticates to client, client does not authenticate to server with a cert.
            context.verify_mode = ssl.CERT_NONE # Explicitly state no client cert required by server context
            logging.info("mTLS disabled: No client_ca_cert provided. Client certificates will not be requested by server.")

    except FileNotFoundError as e:
        logging.error(f"FATAL: Certificate or key file not found: {e}. Please check paths in configuration.")
        sys.exit(1)
    except ssl.SSLError as e:
        logging.error(f"SSL Error loading certificates/keys: {e}. Ensure certs/keys are valid and match.")
        sys.exit(1)
    except Exception as e: # Catch any other unexpected error during context setup
        logging.error(f"An unexpected error occurred setting up SSL context: {e}", exc_info=True)
        sys.exit(1)

    listen_host = get_config_value(config, "server_listener.host", "0.0.0.0")
    listen_port = get_config_value(config, "server_listener.port", required=True)
    if listen_port is None: # Should be caught by required=True
        logging.error("FATAL: server_listener.port is not defined in the configuration.")
        sys.exit(1)

    tls_handshake_timeout = get_config_value(config, "timeouts.tls_handshake", 15) # Get from config

    server_socket = None
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((listen_host, listen_port))
        server_socket.listen(5) # Configurable backlog?
        logging.info(f"Server listening on {listen_host}:{listen_port} for TLS connections...")
        logging.info(f"Forwarding decrypted traffic to {get_config_value(config, 'target_service.host')}:{get_config_value(config, 'target_service.port')}")

        active_threads = []
        while True:
            try:
                plain_client_socket, client_address = server_socket.accept()
                logging.debug(f"Accepted plain TCP connection from {client_address}, attempting TLS handshake...")

                tls_client_socket = None # Define here for broader scope in finally if wrap fails
                try:
                    # Apply handshake timeout to the plain socket before wrap
                    if tls_handshake_timeout and tls_handshake_timeout > 0:
                        plain_client_socket.settimeout(tls_handshake_timeout)
                        logging.debug(f"Set TLS handshake timeout to {tls_handshake_timeout}s for client {client_address}")
                    else:
                        plain_client_socket.settimeout(None) # Disable timeout
                        logging.debug(f"TLS handshake timeout disabled for client {client_address}")

                    tls_client_socket = context.wrap_socket(plain_client_socket, server_side=True)

                    # After successful handshake, clear handshake timeout.
                    # Data timeouts will be handled by forward_data or connection handler later.
                    tls_client_socket.settimeout(None)

                    # logging.info(f"TLS handshake successful with {client_address}.") # Moved to handle_client_connection
                    # Client cert CN/SAN validation is now inside handle_client_connection

                    thread = threading.Thread(
                        target=handle_client_connection, # CN/SAN check is now inside this function
                        args=(tls_client_socket, config), # Pass the whole config
                        daemon=True,
                        name=f"Handler-{client_address}"
                    )
                    thread.start()
                    active_threads.append(thread)

                except ssl.SSLError as e:
                    logging.error(f"TLS handshake failed with {client_address}: {e}")
                    if tls_client_socket: tls_client_socket.close()
                    elif plain_client_socket: plain_client_socket.close() # Close the original socket if wrap failed
                except socket.timeout as e: # Catch handshake timeout specifically
                    logging.error(f"TLS handshake timed out with {client_address}: {e}")
                    if tls_client_socket: tls_client_socket.close()
                    elif plain_client_socket: plain_client_socket.close()
                except Exception as e: # Catch other errors during/after handshake
                    logging.error(f"Error during or after TLS handshake with {client_address}: {e}", exc_info=True)
                    if tls_client_socket: tls_client_socket.close()
                    elif plain_client_socket: plain_client_socket.close()
                finally:
                    # Clean up active_threads list
                    active_threads = [t for t in active_threads if t.is_alive()]
                    # logging.debug(f"Active handler threads: {len(active_threads)}")


            except Exception as e:
                logging.error(f"Error accepting connection: {e}", exc_info=True)

    except OSError as e:
        logging.error(f"Server socket OS error: {e}. Port {listen_port} might be in use or host '{listen_host}' invalid.")
    except KeyboardInterrupt:
        logging.info("Server shutting down due to KeyboardInterrupt...")
    except Exception as e:
        logging.critical(f"Critical server error in main loop: {e}", exc_info=True)
    finally:
        logging.info("Closing server socket.")
        if server_socket:
            server_socket.close()
        logging.info("Server has shut down.")

if __name__ == '__main__':
    main()
