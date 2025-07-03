import socket
import ssl
import argparse
import threading
import logging
import sys # For sys.exit
import time # For session uptime
import os # For path operations

# Use the new .env config loader
# Assuming common utilities are accessible similarly to how client accesses them.
# If server has its own common dir, this path might need adjustment or mirroring the loader.
from client.common.env_config_loader import (
    load_env_config, get_env_str, get_env_int, get_env_bool,
    get_env_list_str, resolve_env_path, EnvConfigError
)
from client.common.logging_setup import setup_logging # Assuming shared logging setup
from client.common.network_utils import forward_data   # Assuming shared network utils


# Initial basic logging to catch early errors (e.g., config loading)
# This will be replaced by setup_logging() once config is loaded.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Base directory for resolving relative paths from .env (e.g., certs, logs)
# Similar to client, this assumes project root or where server.py is run from.
ENV_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# --- Statistics Globals ---
active_connections_count = 0
active_connections_lock = threading.Lock()

# Potentially:
# global_bytes_sent = 0
# global_bytes_received = 0
# global_stats_lock = threading.Lock()
# For now, focusing on active connections and per-session stats logged on completion.

# The old forward_data function is removed from here.

def handle_client_connection(tls_client_socket):
    """
    Handles a single client connection from a ShieldNet client:
    1. Reads the target destination (host:port) sent by the client.
    2. Establishes a plain TCP connection to this dynamic target.
    3. Sets up two threads to forward data bidirectionally.
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
    # Resolve paths from .env
    client_ca_cert_path_env = resolve_env_path(ENV_BASE_DIR, get_env_str("SHIELDNET_TLS_CLIENT_CA_CERT"))
    allowed_client_cns_str = get_env_str("SHIELDNET_TLS_ALLOWED_CLIENT_CNS", "")
    allowed_client_cns_list = get_env_list_str("SHIELDNET_TLS_ALLOWED_CLIENT_CNS", default=[])


    if client_ca_cert_path_env and allowed_client_cns_list: # mTLS is on AND specific CNs are required
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
            if presented_cn in allowed_client_cns_list:
                is_authorized = True
                logging.info(f"Client {client_addr} authorized via CN/SAN: '{presented_cn}'.")
                break

        if not is_authorized:
            logging.warning(f"Client {client_addr} presented certificate subjects {client_cert_subjects}, but none are in the allowed list: {allowed_client_cns_list}. Closing connection.")
            tls_client_socket.close()
            return
    elif client_ca_cert_path_env: # mTLS is on (CA provided), but no specific CNs to check (allowed_client_cns_list is empty)
        peer_cert = tls_client_socket.getpeercert()
        if not peer_cert:
            logging.error(f"Client {client_addr} did not provide a certificate, but mTLS (client CA specified) is configured. Closing connection.")
            tls_client_socket.close()
            return
        logging.info(f"Client {client_addr} provided a certificate, validated by CA. Proceeding (no specific CN check). Cert: {peer_cert.get('subject', 'N/A')}")

    # Read the target destination from the client
    # Expecting "host:port\n"
    target_host = None
    target_port = None
    try:
        # Set a short timeout for reading the destination
        # Original socket timeout is restored or set later.
        original_timeout = tls_client_socket.gettimeout()
        tls_client_socket.settimeout(10) # 10 seconds to receive destination

        destination_buffer = b""
        while not destination_buffer.endswith(b"\n"):
            chunk = tls_client_socket.recv(1024) # Read in chunks
            if not chunk:
                logging.error(f"Client {client_addr} disconnected before sending target destination.")
                tls_client_socket.close()
                return
            destination_buffer += chunk
            if len(destination_buffer) > 4096: # Prevent buffer overflow for destination string
                logging.error(f"Client {client_addr} sent oversized target destination string. Closing.")
                tls_client_socket.close()
                return

        tls_client_socket.settimeout(original_timeout) # Restore original timeout behavior

        destination_str = destination_buffer.decode('utf-8').strip()
        if ':' not in destination_str:
            raise ValueError("Invalid destination format. Expected host:port.")

        target_host, port_str = destination_str.rsplit(':', 1)
        target_port = int(port_str)
        if not (0 < target_port < 65536):
            raise ValueError(f"Invalid port number: {target_port}")

        logging.info(f"Client {client_addr} requested forwarding to {target_host}:{target_port}")

    except (ValueError, UnicodeDecodeError) as e:
        logging.error(f"Client {client_addr} sent invalid target destination: {e}. Raw: '{destination_buffer if 'destination_buffer' in locals() else 'N/A'}' Closing connection.")
        tls_client_socket.close()
        return
    except socket.timeout:
        logging.error(f"Timeout waiting for target destination from client {client_addr}. Closing connection.")
        tls_client_socket.close()
        return
    except socket.error as e:
        logging.error(f"Socket error reading target destination from client {client_addr}: {e}. Closing connection.")
        tls_client_socket.close()
        return
    except Exception as e: # Catch-all for unexpected errors
        logging.error(f"Unexpected error reading target destination from client {client_addr}: {e}", exc_info=True)
        tls_client_socket.close()
        return

    # Configurable values from .env
    socket_data_timeout = get_env_int("SHIELDNET_TIMEOUT_SOCKET_DATA", 60)
    forward_connect_timeout = get_env_int("SHIELDNET_TIMEOUT_TARGET_CONNECT", 10)

    forward_socket = None
    session_start_time = time.time()
    session_bytes_to_target = 0
    session_bytes_to_client = 0

    # Increment active connections count
    global active_connections_count
    with active_connections_lock:
        active_connections_count += 1
    logging.info(f"Active connections: {active_connections_count} (client {client_addr} connected, target: {target_host}:{target_port})")

    try:
        # Use the dynamically received target_host and target_port
        forward_socket = socket.create_connection((target_host, target_port), timeout=forward_connect_timeout)
        logging.info(f"Successfully connected to dynamic target {target_host}:{target_port} for client {client_addr}")

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
            args=(tls_client_socket, forward_socket, f"TLS client {client_addr} -> target {target_host}:{target_port}", shutdown_event, update_bytes_to_target),
            daemon=True, name=f"Fwd-ToTarget-{client_addr}"
        )
        thread_to_client = threading.Thread(
            target=forward_data,
            args=(forward_socket, tls_client_socket, f"Target {target_host}:{target_port} -> TLS client {client_addr}", shutdown_event, update_bytes_to_client),
            daemon=True, name=f"Fwd-ToClient-{client_addr}"
        )

        thread_to_forward.start()
        thread_to_client.start()

        while thread_to_forward.is_alive() and thread_to_client.is_alive():
            thread_to_forward.join(timeout=0.1)
            thread_to_client.join(timeout=0.1)

    except socket.gaierror as e:
        logging.error(f"DNS resolution error for dynamic target host {target_host} (client {client_addr}): {e}")
    except ConnectionRefusedError:
        logging.error(f"Dynamic target connection to {target_host}:{target_port} refused (client {client_addr}).")
    except socket.timeout: # This could be from create_connection to target or data timeout later
        logging.error(f"Timeout related to dynamic target {target_host}:{target_port} (client {client_addr}). Check if it was during connection or data transfer.")
    except Exception as e:
        logging.error(f"Error handling client {client_addr} or connecting to dynamic target {target_host}:{target_port}: {e}", exc_info=True)
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
    parser = argparse.ArgumentParser(description="ShieldNet TLS Server")
    parser.add_argument('--config', type=str, default='server/config/.env', help="Path to the server .env configuration file (default: server/config/.env).")
    parser.add_argument('--verbose', '-v', action='store_const', const='DEBUG', help="Enable DEBUG level logging. Overrides .env log level.")
    parser.add_argument('--debug', action='store_const', const='DEBUG', help="Alias for --verbose.")

    args = parser.parse_args()
    cli_log_level_override = args.verbose or args.debug

    # Load .env configuration
    env_file_path = args.config
    if not load_env_config(env_file_path):
        logging.warning(f"Could not load .env file from {env_file_path}. Relying on environment variables or defaults.")
    else:
        logging.info(f"Configuration loaded from {env_file_path}")

    try:
        # Setup logging using environment variables
        log_level_env = get_env_str("SHIELDNET_LOG_LEVEL", "INFO")
        log_file_env = resolve_env_path(ENV_BASE_DIR, get_env_str("SHIELDNET_LOG_FILE", "logs/server/server.log"))
        log_rotation_bytes_env = get_env_int("SHIELDNET_LOG_ROTATION_BYTES", 10485760)
        log_backup_count_env = get_env_int("SHIELDNET_LOG_BACKUP_COUNT", 5)

        if log_file_env:
            log_dir = os.path.dirname(log_file_env)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

        logging_config_dict = {
            "log_level": cli_log_level_override if cli_log_level_override else log_level_env,
            "log_file": log_file_env,
            "log_rotation_bytes": log_rotation_bytes_env,
            "log_backup_count": log_backup_count_env
        }
        setup_logging(logging_config_dict)

        # Extract essential config values for SSLContext setup from environment
        server_cert_path = resolve_env_path(ENV_BASE_DIR, get_env_str("SHIELDNET_TLS_SERVER_CERT", required=True))
        server_key_path = resolve_env_path(ENV_BASE_DIR, get_env_str("SHIELDNET_TLS_SERVER_KEY", required=True))
        client_ca_cert_path_env = resolve_env_path(ENV_BASE_DIR, get_env_str("SHIELDNET_TLS_CLIENT_CA_CERT")) # Optional for mTLS
        min_tls_version_str = get_env_str("SHIELDNET_TLS_MIN_VERSION", "TLSv1.2")
        # allowed_client_cns are handled inside handle_client_connection

        if not server_cert_path or not server_key_path:
            logging.error("FATAL: Server certificate or key path not configured.")
            sys.exit(1)

    except EnvConfigError as e:
        logging.error(f"FATAL: Configuration error from environment: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"FATAL: Failed to initialize configuration or logging: {e}", exc_info=True)
        sys.exit(1)

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

        if client_ca_cert_path_env: # This enables mTLS
            context.load_verify_locations(cafile=client_ca_cert_path_env)
            context.verify_mode = ssl.CERT_REQUIRED # Require client certificate and verify it
            logging.info(f"mTLS enabled: Loaded client CA {client_ca_cert_path_env}. Client certificates will be required and verified.")
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

    listen_host = get_env_str("SHIELDNET_SERVER_LISTENER_HOST", "0.0.0.0")
    listen_port = get_env_int("SHIELDNET_SERVER_LISTENER_PORT", required=True)

    # The old target_service host/port from YAML are no longer relevant for primary logic.
    # They are commented out in the .env.example. If someone sets them, they are ignored here.

    if listen_port is None: # Should be caught by required=True from get_env_int
        logging.error("FATAL: SHIELDNET_SERVER_LISTENER_PORT is not defined in the configuration.")
        sys.exit(1)

    tls_handshake_timeout = get_env_int("SHIELDNET_TIMEOUT_TLS_HANDSHAKE", 15)

    server_socket = None
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((listen_host, listen_port))
        server_socket.listen(5) # Configurable backlog?
        logging.info(f"Server listening on {listen_host}:{listen_port} for TLS connections...")
        logging.info("Server will dynamically forward traffic based on client requests.")

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
                    tls_client_socket.settimeout(None) # Reset timeout before passing to handler

                    thread = threading.Thread(
                        target=handle_client_connection,
                        args=(tls_client_socket,), # No app_config dict needed anymore
                        daemon=True,
                        name=f"Handler-{client_address}"
                    )
                    thread.start()
                    active_threads.append(thread)

                except ssl.SSLError as e:
                    logging.error(f"TLS handshake failed with {client_address}: {e}")
                    if tls_client_socket: tls_client_socket.close()
                    elif plain_client_socket: plain_client_socket.close()
                except socket.timeout as e:
                    logging.error(f"TLS handshake timed out with {client_address}: {e}")
                    if tls_client_socket: tls_client_socket.close()
                    elif plain_client_socket: plain_client_socket.close()
                except Exception as e:
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
