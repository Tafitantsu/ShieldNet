import socket
import ssl
import argparse
import threading
import logging
import sys # For sys.exit
import time # For reconnection delay

from common.config_loader import load_and_validate_config, get_config_value, ConfigError
from common.logging_setup import setup_logging
from common.network_utils import forward_data # Import the new forward_data

# Initial basic logging to catch early errors (e.g., config loading)
# This will be replaced by setup_logging() once config is loaded.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global config variable
config = None

# The old forward_data function is removed from here. It's now in common.network_utils

def handle_local_connection(local_conn_socket, local_addr, app_config):
    """
    Handles a single local connection:
    1. Establishes a TLS connection to the remote ShieldNet server using settings from app_config.
    2. Sets up two threads to forward data bidirectionally.
    """
    remote_host = get_config_value(app_config, "remote_server.host")
    remote_port = get_config_value(app_config, "remote_server.port")
    server_ca_cert = get_config_value(app_config, "remote_server.server_ca_cert")
    client_cert_path = get_config_value(app_config, "tls.client_cert")
    client_key_path = get_config_value(app_config, "tls.client_key")
    min_tls_version_str = get_config_value(app_config, "tls.min_version_str", "TLSv1.2") # from validation step
    # expected_server_cn = get_config_value(app_config, "tls.expected_server_cn") # For future use

    connect_timeout = get_config_value(app_config, "timeouts.connect", 10)
    tls_handshake_timeout = get_config_value(app_config, "timeouts.tls_handshake", 15)
    socket_data_timeout = get_config_value(app_config, "timeouts.socket_data", 60)
    reconnect_delay_base = get_config_value(app_config, "timeouts.reconnect_delay_base", 5)
    reconnect_max_retries = get_config_value(app_config, "timeouts.reconnect_max_retries", 5)

    logging.info(f"[{local_addr}] Accepted local connection. Attempting to connect to remote server {remote_host}:{remote_port} (min TLS: {min_tls_version_str}).")

    tls_server_socket = None
    plain_server_socket = None # Keep plain_server_socket outside retry loop to avoid re-creation if not needed
                               # However, socket must be fresh for each connect attempt.

    for attempt in range(reconnect_max_retries + 1): # +1 to include initial attempt
        try:
            logging.info(f"[{local_addr}] Connection attempt {attempt + 1}/{reconnect_max_retries + 1} to {remote_host}:{remote_port}.")
            # Sockets must be new for each attempt
            plain_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Setup SSL context for client-side TLS
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 # Disable older protocols

            # Set minimum TLS version
            if min_tls_version_str.upper() == "TLSV1.3":
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                logging.debug("TLS minimum version set to TLSv1.3")
            elif min_tls_version_str.upper() == "TLSV1.2":
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                logging.debug("TLS minimum version set to TLSv1.2")
            else: # Default or if misconfigured, should have been caught by validator but good to be defensive
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                logging.warning(f"Unsupported TLS version '{min_tls_version_str}' in config, defaulting to TLSv1.2.")

            # Consider adding context.set_ciphers('ECDHE+AESGCM:CHACHA20') for specific strong ciphers if needed

            context.check_hostname = True # Verifies server hostname against its certificate
            context.verify_mode = ssl.CERT_REQUIRED # Requires server to provide a certificate

            if server_ca_cert:
                try:
                    context.load_verify_locations(cafile=server_ca_cert)
                    logging.info(f"Loaded CA certificate {server_ca_cert} for server verification.")
                except FileNotFoundError:
                    logging.error(f"CA certificate file {server_ca_cert} not found. Cannot verify server.")
                    return
                except ssl.SSLError as e:
                    logging.error(f"Error loading CA certificate {server_ca_cert}: {e}. Cannot verify server.")
                    return
            else:
                logging.warning("No server_ca_cert provided in config. TLS connection will use system default CAs for server verification. This may fail for self-signed server certificates.")

            if client_cert_path and client_key_path:
                try:
                    context.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)
                    logging.info(f"Loaded client certificate {client_cert_path} and key for mTLS.")
                except FileNotFoundError:
                    logging.error(f"Client certificate or key file not found (Cert: {client_cert_path}, Key: {client_key_path}). Cannot proceed with mTLS.")
                    return
                except ssl.SSLError as e:
                    logging.error(f"Error loading client certificate/key: {e}.")
                    return
            elif client_cert_path or client_key_path: # Only one is provided
                logging.warning("Client certificate or key path is missing. Both are required for mTLS. Proceeding without client certificate.")


            # server_hostname for SNI and cert validation should be remote_host
            # unless expected_server_cn is specified and different.
            hostname_to_verify = remote_host # Default to remote_host
            # if expected_server_cn:
            #     hostname_to_verify = expected_server_cn
            #     logging.info(f"Overriding server_hostname for TLS to: {hostname_to_verify}")

            # Apply connect timeout
            plain_server_socket.settimeout(connect_timeout)
            plain_server_socket.connect((remote_host, remote_port))
            logging.info(f"TCP connection established to {remote_host}:{remote_port}.")

            # Apply TLS handshake timeout before wrap_socket
            if tls_handshake_timeout and tls_handshake_timeout > 0:
                plain_server_socket.settimeout(tls_handshake_timeout)
                logging.debug(f"Set TLS handshake timeout to {tls_handshake_timeout}s for connection to {remote_host}:{remote_port}")
            else: # Disable timeout if 0 or None, or invalid
                plain_server_socket.settimeout(None)
                logging.debug(f"TLS handshake timeout disabled for connection to {remote_host}:{remote_port}")

            tls_server_socket = context.wrap_socket(plain_server_socket, server_hostname=hostname_to_verify)

            # After successful handshake, set the data timeout for both sockets
            if socket_data_timeout and socket_data_timeout > 0:
                local_conn_socket.settimeout(socket_data_timeout)
                tls_server_socket.settimeout(socket_data_timeout)
                logging.debug(f"Set socket data timeout to {socket_data_timeout}s for {local_addr} and its remote connection.")
            else: # Disable timeout if 0, None, or invalid
                local_conn_socket.settimeout(None)
                tls_server_socket.settimeout(None)
                logging.debug(f"Socket data timeout disabled for {local_addr} and its remote connection.")

            logging.info(f"Successfully connected to remote server {remote_host}:{remote_port} via TLS. Cipher: {tls_server_socket.cipher()}")
            logging.debug(f"Server certificate: {tls_server_socket.getpeercert()}")

            # Prepare a shared shutdown event for the two forwarding threads
            # This allows one thread to signal the other if it encounters a critical error or normal EOF
            shutdown_event = threading.Event()

            thread_to_remote = threading.Thread(
                target=forward_data,
                args=(local_conn_socket, tls_server_socket, f"local {local_addr} -> remote {remote_host}:{remote_port}", shutdown_event),
                daemon=True, name=f"Fwd-ToRemote-{local_addr}"
            )
            thread_to_local = threading.Thread(
                target=forward_data,
                args=(tls_server_socket, local_conn_socket, f"remote {remote_host}:{remote_port} -> local {local_addr}", shutdown_event),
                daemon=True, name=f"Fwd-ToLocal-{local_addr}"
            )

            thread_to_remote.start()
            thread_to_local.start()

            # If connection successful, break from retry loop and proceed
            logging.info(f"[{local_addr}] Successfully established connection to {remote_host}:{remote_port} on attempt {attempt + 1}.")
            break
        except (socket.timeout, ConnectionRefusedError, ssl.SSLError, socket.gaierror) as e:
            logging.warning(f"[{local_addr}] Connection attempt {attempt + 1} failed: {e}")
            if plain_server_socket: # Close the failed socket before retrying
                try: plain_server_socket.close()
                except OSError: pass
                plain_server_socket = None # Ensure it's reset
            if tls_server_socket: # Should not be set if wrap failed, but defensive
                try: tls_server_socket.close()
                except OSError: pass
                tls_server_socket = None


            if attempt < reconnect_max_retries:
                delay = reconnect_delay_base * (2 ** attempt)
                logging.info(f"[{local_addr}] Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logging.error(f"[{local_addr}] All {reconnect_max_retries + 1} connection attempts failed. Giving up.")
                # Ensure local connection is closed if all retries fail
                if local_conn_socket:
                    try: local_conn_socket.shutdown(socket.SHUT_RDWR)
                    except OSError: pass
                    local_conn_socket.close()
                return # Exit handler for this local connection
        except Exception as e: # Catch any other unexpected error during connection setup
            logging.error(f"[{local_addr}] Unexpected error during connection attempt {attempt + 1}: {e}", exc_info=True)
            if plain_server_socket: plain_server_socket.close()
            if tls_server_socket: tls_server_socket.close()
            # Similar to above, close local connection and exit if this happens
            if local_conn_socket:
                try: local_conn_socket.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                local_conn_socket.close()
            return


    # If loop completed without break, it means all retries failed (already handled, but as a safeguard)
    if not tls_server_socket: # Or check if attempt == reconnect_max_retries and failed
        logging.info(f"[{local_addr}] Failed to establish connection after all retries. Terminating handler.")
        # Ensure local_conn_socket is closed (might be redundant if handled in loop, but safe)
        if local_conn_socket:
            try: local_conn_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            local_conn_socket.close()
        return

    # === Data Forwarding === (Only if connection was successful)
    try:
        while thread_to_remote.is_alive() and thread_to_local.is_alive():
            thread_to_remote.join(timeout=0.1)
            thread_to_local.join(timeout=0.1)
    except Exception as e: # Catch errors during the join loop itself, though less common
        logging.error(f"[{local_addr}] Error while waiting for forwarding threads: {e}", exc_info=True)
    finally:
        logging.info(f"[{local_addr}] Closing connection for local client and its TLS connection to server.")
        # Ensure shutdown_event is set to signal threads, though they might have exited from socket errors/EOF
        if 'shutdown_event' in locals() and shutdown_event: # Check if shutdown_event was defined
            shutdown_event.set()

        if local_conn_socket:
            try:
                local_conn_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass # Socket might already be closed
            local_conn_socket.close()

        if tls_server_socket: # This is the wrapped (TLS) socket
            try:
                tls_server_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass # Socket might already be closed
            tls_server_socket.close()
        # plain_server_socket is part of tls_server_socket's lifecycle if wrap was successful
        # and should be closed when tls_server_socket is closed.
        # If wrap failed, it's closed in the retry loop.

        logging.info(f"[{local_addr}] Connection fully closed.")


def main():
    global config # Allow main to modify the global config

    parser = argparse.ArgumentParser(description="ShieldNet TLS Client")
    parser.add_argument('--config', type=str, default='config/client_config.yaml', help="Path to the client configuration file (default: config/client_config.yaml).")
    parser.add_argument('--verbose', '-v', action='store_const', const='DEBUG', help="Enable DEBUG level logging. Overrides config file log level.")
    parser.add_argument('--debug', action='store_const', const='DEBUG', help="Alias for --verbose.") # Common alternative

    args = parser.parse_args()
    cli_log_level_override = args.verbose or args.debug # Will be 'DEBUG' or None

    try:
        config = load_and_validate_config(args.config, "client")
        # Setup logging as early as possible after config is loaded
        # The 'logging' section from config is passed directly.
        setup_logging(get_config_value(config, "logging", default={}), cli_log_level_override=cli_log_level_override)
        logging.info(f"Configuration loaded successfully from {args.config}")
    except FileNotFoundError:
        # setup_logging might not have run if config file itself is not found.
        # The initial basicConfig should catch this.
        logging.error(f"FATAL: Configuration file not found: {args.config}. Please ensure the path is correct.")
        sys.exit(1)
    except ConfigError as e:
        logging.error(f"FATAL: Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"FATAL: Failed to load or validate configuration: {e}", exc_info=True)
        sys.exit(1)

    # Extract config values needed for main operation
    listen_host = get_config_value(config, "local_listener.host", "127.0.0.1")
    listen_port = get_config_value(config, "local_listener.port", required=True)
    if listen_port is None: # Should be caught by required=True, but as a safeguard
        logging.error("FATAL: local_listener.port is not defined in the configuration.")
        sys.exit(1)

    local_server_socket = None
    try:
        local_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        local_server_socket.bind((listen_host, listen_port))
        local_server_socket.listen(5) # Configurable backlog?
        logging.info(f"Client listening on {listen_host}:{listen_port} for local application connections...")
        logging.info(f"Will forward traffic to ShieldNet server at {get_config_value(config, 'remote_server.host')}:{get_config_value(config, 'remote_server.port')} over TLS.")

        active_threads = []
        while True:
            try:
                local_conn_socket, local_addr = local_server_socket.accept()
                logging.debug(f"Accepted local connection from {local_addr}")

                thread = threading.Thread(
                    target=handle_local_connection,
                    args=(local_conn_socket, local_addr, config), # Pass the whole config dict
                    daemon=True,
                    name=f"Handler-{local_addr}"
                )
                thread.start()
                active_threads.append(thread)

                # Basic thread cleanup (optional, daemon threads handle this mostly)
                active_threads = [t for t in active_threads if t.is_alive()]
                # logging.debug(f"Active handler threads: {len(active_threads)}")

            except Exception as e:
                logging.error(f"Error accepting local connection: {e}", exc_info=True)
                # Consider if this type of error should cause the client to exit or just log and continue.

    except OSError as e:
        logging.error(f"Client local server socket OS error: {e}. Port {listen_port} might be in use or host {listen_host} invalid.")
    except KeyboardInterrupt:
        logging.info("Client shutting down due to KeyboardInterrupt...")
    except Exception as e:
        logging.critical(f"Critical client error in main loop: {e}", exc_info=True)
    finally:
        logging.info("Closing client listening socket.")
        if local_server_socket:
            local_server_socket.close()

        # Wait for active handler threads to complete? (Graceful shutdown)
        # This is tricky with daemon threads. For a truly graceful shutdown,
        # one might signal threads to stop and then join them.
        # For now, daemon threads will be terminated when main exits.
        logging.info("Client has shut down.")

if __name__ == '__main__':
    main()
