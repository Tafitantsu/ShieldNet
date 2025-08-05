import socket
import ssl
import argparse
import threading
import logging
import sys
import time
import os

import yaml

from common.env_config_loader import (
    load_env_config, get_env_str, get_env_int, get_env_bool,
    resolve_env_path, EnvConfigError
)
from common.logging_setup import setup_logging, DEFAULT_LOG_FORMAT
from common.network_utils import forward_data
from typing import Optional, Dict, Any


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', force=True)

ENV_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Resolves a configuration path, handling both absolute and relative paths.
def resolve_path_from_config(path_from_config: str) -> Optional[str]:
    if not path_from_config:
        return None
    if os.path.isabs(path_from_config):
        return path_from_config
    abs_env_base_dir = os.path.abspath(ENV_BASE_DIR)
    return os.path.join(abs_env_base_dir, path_from_config)

# Loads and parses the YAML configuration file.
def load_yaml_config(config_path: str) -> Dict:
    try:
        if not os.path.isabs(config_path) and not os.path.exists(config_path):
            potential_path = resolve_path_from_config(config_path)
            if potential_path and os.path.exists(potential_path):
                config_path = potential_path

        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        if not isinstance(config_data, dict):
            logging.error(f"Error: Configuration file {config_path} is not a valid YAML dictionary.")
            sys.exit(1)

        common_settings = config_data.get('common_settings', {})
        for cert_key in ['server_ca_cert', 'client_cert', 'client_key']:
            cert_path = common_settings.get(cert_key)
            if cert_path:
                common_settings[cert_key] = resolve_path_from_config(cert_path)

        return config_data
    except FileNotFoundError:
        logging.error(f"Error: Configuration file not found at {config_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML configuration file {config_path}: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading configuration from {config_path}: {e}")
        sys.exit(1)

# Handles a single local connection, connecting it to the remote server.
def handle_local_connection(local_conn_socket, local_addr, target_host_arg, target_port_arg, common_config: Dict):
    remote_host = common_config.get("remote_server_host")
    remote_port = common_config.get("remote_server_port")

    server_ca_cert = common_config.get("server_ca_cert")
    client_cert_path = common_config.get("client_cert")
    client_key_path = common_config.get("client_key")

    min_tls_version_str = common_config.get("tls_min_version", "TLSv1.2")

    connect_timeout = common_config.get("connect_timeout", 10)
    tls_handshake_timeout = common_config.get("tls_handshake_timeout", 15)
    socket_data_timeout = common_config.get("socket_data_timeout", 60)
    reconnect_delay_base = common_config.get("reconnect_delay_base", 5)
    reconnect_max_retries = common_config.get("reconnect_max_retries", 3)


    if not remote_host or not remote_port:
        logging.error("Remote server host or port not configured in common_settings. Exiting handler.")
        if local_conn_socket:
            try: local_conn_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            local_conn_socket.close()
        return

    logging.info(f"[{local_addr}] Accepted local connection. Attempting to connect to remote server {remote_host}:{remote_port} (min TLS: {min_tls_version_str}) for target {target_host_arg}:{target_port_arg}.")

    tls_server_socket = None
    plain_server_socket = None

    for attempt in range(reconnect_max_retries + 1):
        try:
            logging.info(f"[{local_addr}] Connection attempt {attempt + 1}/{reconnect_max_retries + 1} to {remote_host}:{remote_port}.")
            plain_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

            if min_tls_version_str.upper() == "TLSV1.3":
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                logging.debug("TLS minimum version set to TLSv1.3")
            elif min_tls_version_str.upper() == "TLSV1.2":
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                logging.debug("TLS minimum version set to TLSv1.2")
            else:
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                logging.warning(f"Unsupported TLS version '{min_tls_version_str}' in config, defaulting to TLSv1.2.")

            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

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
            elif client_cert_path or client_key_path:
                logging.warning("Client certificate or key path is missing. Both are required for mTLS. Proceeding without client certificate.")


            hostname_to_verify = remote_host

            plain_server_socket.settimeout(connect_timeout)
            plain_server_socket.connect((remote_host, remote_port))
            logging.info(f"TCP connection established to {remote_host}:{remote_port}.")

            if tls_handshake_timeout and tls_handshake_timeout > 0:
                plain_server_socket.settimeout(tls_handshake_timeout)
                logging.debug(f"Set TLS handshake timeout to {tls_handshake_timeout}s for connection to {remote_host}:{remote_port}")
            else:
                plain_server_socket.settimeout(None)
                logging.debug(f"TLS handshake timeout disabled for connection to {remote_host}:{remote_port}")

            tls_server_socket = context.wrap_socket(plain_server_socket, server_hostname=hostname_to_verify)
            logging.info(f"TLS handshake successful with {remote_host}:{remote_port}. Cipher: {tls_server_socket.cipher()}")
            logging.debug(f"Server certificate: {tls_server_socket.getpeercert()}")

            target_destination_str = f"{target_host_arg}:{target_port_arg}\n"
            try:
                tls_server_socket.sendall(target_destination_str.encode('utf-8'))
                logging.info(f"[{local_addr}] Sent target destination '{target_destination_str.strip()}' to server.")
            except socket.error as e:
                logging.error(f"[{local_addr}] Failed to send target destination to server: {e}")
                tls_server_socket.close()
                if plain_server_socket and plain_server_socket is not tls_server_socket:
                    plain_server_socket.close()
                if local_conn_socket:
                    try: local_conn_socket.shutdown(socket.SHUT_RDWR)
                    except OSError: pass
                    local_conn_socket.close()
                return

            if socket_data_timeout and socket_data_timeout > 0:
                local_conn_socket.settimeout(socket_data_timeout)
                tls_server_socket.settimeout(socket_data_timeout)
                logging.debug(f"Set socket data timeout to {socket_data_timeout}s for {local_addr} and its remote connection.")
            else:
                local_conn_socket.settimeout(None)
                tls_server_socket.settimeout(None)
                logging.debug(f"Socket data timeout disabled for {local_addr} and its remote connection.")

            logging.info(f"Successfully connected to remote server {remote_host}:{remote_port} and sent target info.")

            shutdown_event = threading.Event()

            thread_to_remote = threading.Thread(
                target=forward_data,
                args=(local_conn_socket, tls_server_socket, f"local {local_addr} -> remote {remote_host}:{remote_port} (target: {target_host_arg}:{target_port_arg})", shutdown_event),
                daemon=True, name=f"Fwd-ToRemote-{local_addr}"
            )
            thread_to_local = threading.Thread(
                target=forward_data,
                args=(tls_server_socket, local_conn_socket, f"remote {remote_host}:{remote_port} (target: {target_host_arg}:{target_port_arg}) -> local {local_addr}", shutdown_event),
                daemon=True, name=f"Fwd-ToLocal-{local_addr}"
            )

            thread_to_remote.start()
            thread_to_local.start()

            logging.info(f"[{local_addr}] Successfully established tunnel to {remote_host}:{remote_port} for target {target_host_arg}:{target_port_arg} on attempt {attempt + 1}.")
            break
        except (socket.timeout, ConnectionRefusedError, ssl.SSLError, socket.gaierror) as e:
            logging.warning(f"[{local_addr}] Connection attempt {attempt + 1} failed: {e}")
            if plain_server_socket:
                try: plain_server_socket.close()
                except OSError: pass
                plain_server_socket = None
            if tls_server_socket:
                try: tls_server_socket.close()
                except OSError: pass
                tls_server_socket = None


            if attempt < reconnect_max_retries:
                delay = reconnect_delay_base * (2 ** attempt)
                logging.info(f"[{local_addr}] Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logging.error(f"[{local_addr}] All {reconnect_max_retries + 1} connection attempts failed. Giving up.")
                if local_conn_socket:
                    try: local_conn_socket.shutdown(socket.SHUT_RDWR)
                    except OSError: pass
                    local_conn_socket.close()
                return
        except Exception as e:
            logging.error(f"[{local_addr}] Unexpected error during connection attempt {attempt + 1}: {e}", exc_info=True)
            if plain_server_socket: plain_server_socket.close()
            if tls_server_socket: tls_server_socket.close()
            if local_conn_socket:
                try: local_conn_socket.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                local_conn_socket.close()
            return


    if not tls_server_socket:
        logging.info(f"[{local_addr}] Failed to establish connection after all retries. Terminating handler.")
        if local_conn_socket:
            try: local_conn_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            local_conn_socket.close()
        return

    try:
        while thread_to_remote.is_alive() and thread_to_local.is_alive():
            thread_to_remote.join(timeout=0.1)
            thread_to_local.join(timeout=0.1)
    except Exception as e:
        logging.error(f"[{local_addr}] Error while waiting for forwarding threads: {e}", exc_info=True)
    finally:
        logging.info(f"[{local_addr}] Closing connection for local client and its TLS connection to server.")
        if 'shutdown_event' in locals() and shutdown_event:
            shutdown_event.set()

        if local_conn_socket:
            try:
                local_conn_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            local_conn_socket.close()

        if tls_server_socket:
            try:
                tls_server_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            tls_server_socket.close()

        logging.info(f"[{local_addr}] Connection fully closed.")

# Main function to start the client.
def main():
    parser = argparse.ArgumentParser(description="ShieldNet TLS Client Utility")
    parser.add_argument(
        '--config',
        type=str,
        default='client/config/client_config.yaml',
        help="Path to the client YAML configuration file (default: client/config/client_config.yaml)."
    )
    parser.add_argument(
        '--log-level',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default=None,
        help="Override the log level from the configuration file."
    )

    subparsers = parser.add_subparsers(dest='mode', required=True, help="Operating mode")

    tcp_parser = subparsers.add_parser('tcp-tunnel', help="Run in TCP tunnel mode (local port forwarding).")
    socks_parser = subparsers.add_parser('socks5-proxy', help="Run as a SOCKS5 proxy.")

    args = parser.parse_args()

    config = load_yaml_config(args.config)
    if not config:
        sys.exit(1)

    common_config = config.get('common_settings', {})
    logging_config_from_yaml = common_config.get('logging', {})

    raw_log_file_path = logging_config_from_yaml.get("log_file")
    if raw_log_file_path and not os.path.isabs(raw_log_file_path):
        abs_env_base_dir = os.path.abspath(ENV_BASE_DIR)
        logging_config_from_yaml["log_file"] = os.path.join(abs_env_base_dir, raw_log_file_path)

    setup_logging(logging_config_from_yaml, cli_log_level_override=args.log_level)

    logging.info(f"ShieldNet Client starting in '{args.mode}' mode.")
    logging.info(f"Successfully loaded configuration from: {args.config}")
    if args.log_level:
        logging.info(f"Log level overridden by CLI: {args.log_level}")
    logging.debug(f"Full configuration loaded: {config}")


    if args.mode == 'tcp-tunnel':
        run_tcp_tunnel_mode(args, config)
    elif args.mode == 'socks5-proxy':
        run_socks5_proxy_mode(args, config)
    else:
        logging.error(f"Unknown mode: {args.mode}")
        sys.exit(1)

# Runs the client in TCP tunnel mode.
def run_tcp_tunnel_mode(args: argparse.Namespace, config: Dict[str, Any]):
    logging.info("TCP Tunnel mode selected.")

    common_settings = config.get('common_settings', {})
    tcp_tunnel_config = config.get('tcp_tunnel_mode', {})
    tunnels = tcp_tunnel_config.get('tunnels', [])

    if not common_settings:
        logging.error("TCP Tunnel Mode: 'common_settings' are missing in the configuration.")
        sys.exit(1)
    if not tunnels:
        logging.warning("TCP Tunnel Mode: No tunnels defined in 'tcp_tunnel_mode.tunnels'. Nothing to do.")
        print("No tunnels configured. Client will exit.")
        return

    listener_threads = []
    all_tunnel_sockets = []

    def tunnel_listener_thread(local_host, local_port, target_host, target_port, common_cfg):
        local_server_socket = None
        try:
            local_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            local_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            local_server_socket.bind((local_host, local_port))
            local_server_socket.listen(5)
            all_tunnel_sockets.append(local_server_socket)
            logging.info(f"[Tunnel {local_host}:{local_port} -> {target_host}:{target_port}] Listening for local connections...")

            active_handler_threads = []
            while True:
                try:
                    local_conn_socket, local_addr = local_server_socket.accept()
                    logging.debug(f"[Tunnel {local_host}:{local_port}] Accepted local connection from {local_addr}")

                    handler_thread = threading.Thread(
                        target=handle_local_connection,
                        args=(local_conn_socket, local_addr, target_host, target_port, common_cfg),
                        daemon=True,
                        name=f"Handler-{local_addr}-To-{target_host}:{target_port}"
                    )
                    handler_thread.start()
                    active_handler_threads.append(handler_thread)
                    active_handler_threads = [t for t in active_handler_threads if t.is_alive()]

                except socket.error as e:
                    logging.info(f"[Tunnel {local_host}:{local_port}] Socket error accepting connection (likely shutdown): {e}")
                    break
                except Exception as e:
                    logging.error(f"[Tunnel {local_host}:{local_port}] Error accepting local connection: {e}", exc_info=True)

        except OSError as e:
            logging.error(f"[Tunnel {local_host}:{local_port}] OS error setting up listener: {e}. This tunnel will not start.")
        except Exception as e:
            logging.critical(f"[Tunnel {local_host}:{local_port}] Critical error in listener thread: {e}", exc_info=True)
        finally:
            if local_server_socket:
                logging.info(f"[Tunnel {local_host}:{local_port}] Closing listener socket.")
                if local_server_socket in all_tunnel_sockets:
                    all_tunnel_sockets.remove(local_server_socket)
                local_server_socket.close()
            logging.info(f"[Tunnel {local_host}:{local_port}] Listener thread finished.")


    for i, tunnel_def in enumerate(tunnels):
        try:
            local_listen_host = tunnel_def.get('local_listen_host', '127.0.0.1')
            local_listen_port = int(tunnel_def['local_listen_port'])
            target_service_host = tunnel_def['target_service_host']
            target_service_port = int(tunnel_def['target_service_port'])

            if not (local_listen_port and target_service_host and target_service_port):
                raise ValueError("Missing required tunnel parameters (local_listen_port, target_service_host, target_service_port)")

            thread = threading.Thread(
                target=tunnel_listener_thread,
                args=(local_listen_host, local_listen_port, target_service_host, target_service_port, common_settings.copy()),
                name=f"TunnelListener-{local_listen_host}:{local_listen_port}",
                daemon=False
            )
            listener_threads.append(thread)
            thread.start()
        except (KeyError, ValueError) as e:
            logging.error(f"Invalid tunnel definition at index {i}: {tunnel_def}. Error: {e}. Skipping this tunnel.")
        except Exception as e:
            logging.error(f"Failed to start tunnel for definition {tunnel_def} due to: {e}", exc_info=True)

    if not listener_threads:
        logging.info("TCP Tunnel Mode: No valid tunnels were started.")
        return

    logging.info(f"TCP Tunnel Mode: {len(listener_threads)} tunnel listener(s) started. Client running. Press Ctrl+C to exit.")

    try:
        while any(t.is_alive() for t in listener_threads):
            for t in listener_threads:
                t.join(timeout=0.1)
    except KeyboardInterrupt:
        logging.info("TCP Tunnel Mode: Shutdown signal (KeyboardInterrupt) received.")
    except Exception as e:
        logging.critical(f"TCP Tunnel Mode: Unexpected error in main monitoring loop: {e}", exc_info=True)
    finally:
        logging.info("TCP Tunnel Mode: Shutting down all tunnel listeners...")
        for sock in all_tunnel_sockets[:]:
            try:
                logging.debug(f"Closing socket {sock.getsockname()} from main shutdown sequence.")
                sock.close()
            except Exception as e:
                logging.warning(f"Error closing a tunnel server socket {sock}: {e}")

        for t in listener_threads:
            if t.is_alive():
                logging.debug(f"Waiting for listener thread {t.name} to complete...")
                t.join(timeout=2)
                if t.is_alive():
                    logging.warning(f"Listener thread {t.name} did not exit cleanly.")
        logging.info("TCP Tunnel Mode: All tunnel listeners have been processed for shutdown.")

    logging.info("ShieldNet Client TCP Tunnel Mode has finished.")

# Runs the client in SOCKS5 proxy mode.
def run_socks5_proxy_mode(args: argparse.Namespace, config: Dict[str, Any]):
    logging.info("SOCKS5 Proxy mode selected.")

    common_settings = config.get('common_settings', {})
    socks_config = config.get('socks5_proxy_mode', {})

    if not common_settings:
        logging.error("SOCKS5 Proxy Mode: 'common_settings' are missing in the configuration.")
        sys.exit(1)
    if not socks_config:
        logging.error("SOCKS5 Proxy Mode: 'socks5_proxy_mode' settings are missing in the configuration.")
        sys.exit(1)

    listen_host = socks_config.get('local_listen_host', '127.0.0.1')
    listen_port = socks_config.get('local_listen_port')

    if not listen_port:
        logging.error("SOCKS5 Proxy Mode: 'local_listen_port' is missing in socks5_proxy_mode configuration.")
        sys.exit(1)

    logging.info(f"Starting SOCKS5 Proxy mode: Listening on {listen_host}:{listen_port}")

    socks_server_socket = None
    try:
        socks_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socks_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socks_server_socket.bind((listen_host, int(listen_port)))
        socks_server_socket.listen(10)
        logging.info(f"SOCKS5 proxy listening on {listen_host}:{listen_port}...")

        active_socks_threads = []
        while True:
            try:
                client_socket, client_addr = socks_server_socket.accept()
                logging.debug(f"SOCKS5: Accepted connection from {client_addr}")

                thread = threading.Thread(
                    target=handle_socks5_connection,
                    args=(client_socket, client_addr, common_settings.copy()),
                    daemon=True,
                    name=f"SOCKS5Handler-{client_addr}"
                )
                thread.start()
                active_socks_threads.append(thread)
                active_socks_threads = [t for t in active_socks_threads if t.is_alive()]

            except socket.error as e:
                logging.info(f"SOCKS5: Socket error accepting connection (likely server socket closed): {e}")
                break
            except Exception as e:
                logging.error(f"SOCKS5: Error accepting client connection: {e}", exc_info=True)

    except OSError as e:
        logging.error(f"SOCKS5: OS error setting up listener on {listen_host}:{listen_port}: {e}. SOCKS5 proxy will not start.")
    except KeyboardInterrupt:
        logging.info("SOCKS5 Proxy Mode: Shutdown signal (KeyboardInterrupt) received.")
    except Exception as e:
        logging.critical(f"SOCKS5 Proxy Mode: Critical error in main SOCKS5 listener loop: {e}", exc_info=True)
    finally:
        logging.info("SOCKS5 Proxy Mode: Shutting down SOCKS5 listener...")
        if socks_server_socket:
            socks_server_socket.close()
        logging.info("SOCKS5 Proxy Mode: Listener shut down.")

    logging.info("ShieldNet Client SOCKS5 Proxy Mode has finished.")

# Handles a single SOCKS5 client connection.
def handle_socks5_connection(client_socket: socket.socket, client_addr, common_config: Dict):
    try:
        logging.debug(f"SOCKS5 [{client_addr}]: New connection, starting negotiation.")

        greeting = client_socket.recv(2)
        if not greeting:
            logging.warning(f"SOCKS5 [{client_addr}]: Client closed connection during greeting.")
            return

        ver, nmethods = greeting[0], greeting[1]
        if ver != 5:
            logging.warning(f"SOCKS5 [{client_addr}]: Unsupported SOCKS version {ver}. Closing.")
            return

        methods = client_socket.recv(nmethods)
        if len(methods) != nmethods:
            logging.warning(f"SOCKS5 [{client_addr}]: Did not receive all declared methods. Closing.")
            return

        if b'\x00' not in methods:
            logging.warning(f"SOCKS5 [{client_addr}]: Client does not support 'No Authentication'. Sending error reply.")
            client_socket.sendall(b'\x05\xff')
            return

        client_socket.sendall(b'\x05\x00')
        logging.debug(f"SOCKS5 [{client_addr}]: Authentication negotiation successful (No Authentication).")

        request_header = client_socket.recv(4)
        if len(request_header) < 4:
            logging.warning(f"SOCKS5 [{client_addr}]: Client closed connection or sent incomplete request header.")
            return

        req_ver, cmd, rsv, atyp = request_header[0], request_header[1], request_header[2], request_header[3]

        if req_ver != 5:
            logging.warning(f"SOCKS5 [{client_addr}]: Invalid SOCKS version in request {req_ver}. Closing.")
            return

        if cmd != 1:
            logging.warning(f"SOCKS5 [{client_addr}]: Unsupported command {cmd}. Sending 'Command not supported' reply.")
            client_socket.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            return

        target_host = ""
        if atyp == 1:
            ipv4_bytes = client_socket.recv(4)
            if len(ipv4_bytes) < 4:
                logging.warning(f"SOCKS5 [{client_addr}]: Incomplete IPv4 address received.")
                client_socket.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            target_host = socket.inet_ntoa(ipv4_bytes)
        elif atyp == 3:
            domain_len_byte = client_socket.recv(1)
            if not domain_len_byte:
                logging.warning(f"SOCKS5 [{client_addr}]: Did not receive domain length.")
                client_socket.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            domain_len = domain_len_byte[0]
            domain_bytes = client_socket.recv(domain_len)
            if len(domain_bytes) < domain_len:
                logging.warning(f"SOCKS5 [{client_addr}]: Incomplete domain name received.")
                client_socket.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            target_host = domain_bytes.decode('utf-8', errors='ignore')
        elif atyp == 4:
            logging.warning(f"SOCKS5 [{client_addr}]: IPv6 address type (ATYP=4) is not supported by this proxy. Sending 'Address type not supported'.")
            client_socket.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            return
        else:
            logging.warning(f"SOCKS5 [{client_addr}]: Unknown address type {atyp}. Sending 'Address type not supported'.")
            client_socket.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            return

        port_bytes = client_socket.recv(2)
        if len(port_bytes) < 2:
            logging.warning(f"SOCKS5 [{client_addr}]: Did not receive port bytes.")
            client_socket.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            return
        target_port = int.from_bytes(port_bytes, 'big')

        logging.info(f"SOCKS5 [{client_addr}]: Received CONNECT request for {target_host}:{target_port}")

        try:
            client_socket.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            logging.debug(f"SOCKS5 [{client_addr}]: Sent CONNECT success reply for {target_host}:{target_port}.")
        except socket.error as e:
            logging.warning(f"SOCKS5 [{client_addr}]: Failed to send success reply to client: {e}. Aborting.")
            return

        logging.info(f"SOCKS5 [{client_addr}]: Handing off to tunnel creation for {target_host}:{target_port}.")
        handle_local_connection(client_socket, client_addr, target_host, target_port, common_config)

        logging.info(f"SOCKS5 [{client_addr}]: Tunnel for {target_host}:{target_port} finished or failed. Closing SOCKS handler.")

    except socket.timeout:
        logging.warning(f"SOCKS5 [{client_addr}]: Socket timeout during SOCKS negotiation or operation.")
    except ConnectionResetError:
        logging.warning(f"SOCKS5 [{client_addr}]: Client reset the connection.")
    except Exception as e:
        logging.error(f"SOCKS5 [{client_addr}]: Unexpected error in SOCKS5 handler: {e}", exc_info=True)
        if client_socket and client_socket.fileno() != -1:
            try:
                client_socket.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            except socket.error:
                pass
    finally:
        if client_socket:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client_socket.close()
            logging.debug(f"SOCKS5 [{client_addr}]: Client socket closed.")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    main()
