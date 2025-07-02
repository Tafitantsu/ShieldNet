# Secure TCP Tunnel (Refactored)

This project provides a robust, production-grade TLS-encrypted TCP tunnel. It's a refactored and enhanced version of an initial simpler tunnel, designed for security, resilience, and manageability. The client listens locally for TCP connections and forwards traffic over a TLS-encrypted link to the server. The server then decrypts this traffic and forwards it to a predefined target TCP service.

## Architecture Overview

The system consists of two main components: `client.py` and `server.py`.

```
+-----------------+      TCP      +-------------+      TLS      +-------------+      TCP      +----------------+
| Local           |<------------->| Tunnel      |<------------->| Tunnel      |<------------->| Target         |
| Application     | Plaintext     | Client      |  Encrypted    | Server      | Plaintext     | Service        |
| (e.g., browser, | (on          | (client.py) |  (m)TLS       | (server.py) | (on           | (e.g., web     |
|  database tool) | localhost)    |             |  Tunnel       |             | server's host) |  server, DB)   |
+-----------------+               +-------------+               +-------------+               +----------------+
                                   ^                                           ^
                                   | listens on configured                     | listens on configured
                                   | local port (e.g., 1080)                   | public port (e.g., 8443)
```

## Core Features Implemented

*   **Security (TLS and Auth):**
    *   Mutual TLS authentication (mTLS): Server verifies client cert against a CA; client verifies server cert.
    *   TLS 1.2 or TLS 1.3 enforcement (configurable, defaults to TLS 1.2).
    *   Strict CN/SAN hostname checking (client checks server CN/SAN; server can check client CN/SAN if configured).
    *   TLS handshake timeout to prevent DoS.
*   **Networking & Resilience:**
    *   Bidirectional TCP data forwarding.
    *   Timeouts on socket operations (connect, TLS handshake, data recv/send).
    *   Automatic client reconnection: If the tunnel client fails to connect to the server for a specific local connection, it retries with exponential backoff.
*   **Developer/DevOps Experience:**
    *   Configuration via YAML files (`client_config.yaml`, `server_config.yaml`).
    *   Structured logging to files with rotation and configurable log levels.
    *   `--verbose`/`--debug` CLI flags to override configured log level.
    *   Dockerfiles for client and server.
    *   `docker-compose.yml` for easy multi-container local testing.
    *   Unit tests for core logic (config loading, network utilities, client/server handlers).
    *   A local shell script (`scripts/test_tunnel.sh`) for end-to-end testing using Docker Compose.
*   **Monitoring:**
    *   Server logs active connection counts.
    *   Server logs per-session statistics (uptime, bytes sent/received) upon session completion.

## Project Structure

```
.
├── certs/                   # (User-created) For TLS certificates
│   ├── ca.crt
│   ├── server.crt
│   ├── server.key
│   ├── client.crt
│   └── client.key
├── config/                  # Configuration files
│   ├── client_config.yaml   # (User-created from example)
│   ├── client_config.yaml.example
│   ├── server_config.yaml   # (User-created from example)
│   └── server_config.yaml.example
├── docker/                  # Docker related files
│   ├── client.Dockerfile
│   ├── server.Dockerfile
│   └── docker-compose.yml
├── logs/                    # (Auto-created) Log files will appear here
│   ├── client/
│   └── server/
├── scripts/                 # Helper and test scripts
│   └── test_tunnel.sh
├── src/                     # Source code
│   ├── common/              # Shared utility modules
│   │   ├── config_loader.py
│   │   ├── logging_setup.py
│   │   └── network_utils.py
│   ├── client.py            # Client application
│   └── server.py            # Server application
├── tests/                   # Unit tests
│   ├── __init__.py
│   ├── test_client.py
│   ├── test_server.py
│   ├── test_config_loader.py
│   └── test_network_utils.py
├── AGENTS.md                # Instructions for AI agents
├── README.md                # This file
└── requirements.txt         # Python dependencies
```

## Getting Started

### 1. Prerequisites
*   Python 3.7+
*   OpenSSL (for generating certificates)
*   Docker and Docker Compose (for containerized execution and testing script)
*   `PyYAML` (install via `pip install -r requirements.txt`)

### 2. Generating TLS Certificates (Self-Signed for Testing)

You'll need a Certificate Authority (CA), a server certificate signed by the CA, and a client certificate signed by the CA for mTLS.

Create a `certs` directory in the project root: `mkdir certs && cd certs`

**a. Create CA:**
```bash
# Generate CA private key
openssl genpkey -algorithm RSA -out ca.key -pkeyopt rsa_keygen_bits:2048
# Generate CA certificate (self-signed)
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=MyTestCA"
```

**b. Create Server Certificate:**
(Replace `your.server.com` with the actual hostname or IP the client will use to connect to the server, or `tunnel-server` for Docker Compose).
```bash
SERVER_HOSTNAME="your.server.com" # Or "tunnel-server" for docker-compose
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key server.key -out server.csr -subj "/CN=${SERVER_HOSTNAME}"
# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 360 -extfile <(printf "subjectAltName=DNS:${SERVER_HOSTNAME},DNS:localhost,IP:127.0.0.1")
```
*Note: `localhost` and `127.0.0.1` are added to SANs for easier local testing if the server runs directly on the host.*

**c. Create Client Certificate:**
(Replace `your.client.id` with a suitable identifier if you plan to use `allowed_client_cns` on the server).
```bash
CLIENT_ID="your.client.id" # e.g., "client1" or "testclient.example.com"
openssl genpkey -algorithm RSA -out client.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key client.key -out client.csr -subj "/CN=${CLIENT_ID}"
# Sign client certificate with CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAserial ca.srl -out client.crt -days 360
```
After these steps, your `certs/` directory should contain: `ca.crt`, `ca.key`, `ca.srl` (serial number file), `server.crt`, `server.key`, `server.csr`, `client.crt`, `client.key`, `client.csr`. The `.csr` and `ca.key` (after signing) are not strictly needed for running the application but are part of the generation process.

### 3. Configuration

Copy the example configuration files and customize them:
```bash
mkdir -p config logs/client logs/server
cp config/client_config.yaml.example config/client_config.yaml
cp config/server_config.yaml.example config/server_config.yaml
```

Edit `config/client_config.yaml` and `config/server_config.yaml`.

**Key settings to adjust:**

*   **`client_config.yaml`**:
    *   `remote_server.host`: Server's hostname/IP. For Docker Compose, use `tunnel-server`.
    *   `remote_server.port`: Server's listening port (e.g., `8443`).
    *   `remote_server.server_ca_cert`: Path to CA cert (e.g., `certs/ca.crt`).
    *   `tls.client_cert`: Path to client's certificate (e.g., `certs/client.crt`).
    *   `tls.client_key`: Path to client's private key (e.g., `certs/client.key`).
    *   `logging.log_file`: e.g., `logs/client.log`.
    *   Paths for Docker: When running via Docker Compose, cert paths should be relative to `/app` (e.g., `/app/certs/ca.crt`) and log paths e.g. `/app/logs/client.log` if you want them inside the mounted log volume. The examples provided in `docker-compose.yml` comments show this.

*   **`server_config.yaml`**:
    *   `server_listener.host`: Typically `0.0.0.0` to listen on all interfaces.
    *   `server_listener.port`: Port for server to listen on (e.g., `8443`).
    *   `target_service.host`: Hostname/IP of the final service. For Docker Compose, use `echo-server`.
    *   `target_service.port`: Port of the final service (e.g., `8080` for the test echo-server).
    *   `tls.server_cert`: Path to server's certificate (e.g., `certs/server.crt`).
    *   `tls.server_key`: Path to server's private key (e.g., `certs/server.key`).
    *   `tls.client_ca_cert`: Path to CA cert for mTLS client verification (e.g., `certs/ca.crt`). If blank, mTLS is disabled (server won't request client certs).
    *   `tls.allowed_client_cns`: (Optional) List of Common Names (CNs) or Subject Alternative Names (SANs) from client certificates that are allowed if mTLS is active and this list is populated.
    *   `logging.log_file`: e.g., `logs/server.log`.
    *   Paths for Docker: Similar to client, adjust for `/app/certs/...` and `/app/logs/server.log`.

**Example Configuration for Docker Compose:**

Refer to the comments in `docker-compose.yml` for how to set `host` and certificate paths in your YAML configuration files when using Docker. Specifically:
*   Client's `remote_server.host` should be `tunnel-server`.
*   Server's `target_service.host` should be `echo-server`.
*   All certificate paths in YAML files should be like `certs/ca.crt` (as they will be mounted to `/app/certs/ca.crt` inside container).
*   Log file paths like `logs/client.log` (mounted to `/app/logs/client.log`).

### 4. Running the Application

**a. Using Docker Compose (Recommended for Testing):**

This is the easiest way to test the full setup, including mTLS.
1.  Ensure certificates are generated in `./certs/`.
2.  Ensure `config/client_config.yaml` and `config/server_config.yaml` are created and correctly point to service names (e.g., `tunnel-server`, `echo-server`) and in-container cert/log paths (e.g., `certs/ca.crt`, `logs/client.log`).
3.  Create log directories: `mkdir -p logs/client logs/server` (Docker might create these too, but good practice).

```bash
# Start services in detached mode
docker-compose up --build -d

# View logs
docker-compose logs -f tunnel-client
docker-compose logs -f tunnel-server
docker-compose logs -f echo-server

# Test with the script
bash scripts/test_tunnel.sh

# Stop services
docker-compose down -v
```

**b. Manual Execution (Python directly):**

1.  Install dependencies: `pip install -r requirements.txt`
2.  Ensure certificates are generated and configuration files are correctly set up for your environment (e.g., `remote_server.host` pointing to the actual server IP if not on localhost).

    **Start the Server:**
    ```bash
    python src/server.py --config config/server_config.yaml
    # For verbose logging:
    # python src/server.py --config config/server_config.yaml --verbose
    ```

    **Start the Client:**
    (In a new terminal)
    ```bash
    python src/client.py --config config/client_config.yaml
    # For verbose logging:
    # python src/client.py --config config/client_config.yaml --verbose
    ```
3.  Test by sending traffic to the client's listen port (e.g., `localhost:1080` if configured). For example, if the server forwards to a web server on `target-host:80`:
    ```bash
    curl http://localhost:1080
    ```

### 5. Running Unit Tests

Ensure you are in the project root directory.
```bash
python -m unittest discover -s tests -v
```
This will discover and run all tests within the `tests` directory.

### 6. End-to-End Testing Script

The `scripts/test_tunnel.sh` script automates testing using Docker Compose:
1.  It starts the `docker-compose` services (client, server, echo-server).
2.  Waits for them to initialize.
3.  Sends a test message via `netcat` through `localhost:1080` (client's port).
4.  Checks if the echoed response matches the sent message.
5.  Reports success or failure.

Make sure your `config/*.yaml` files are set up for the Docker Compose environment as described above (service names as hosts, `/app/certs` paths).
```bash
bash scripts/test_tunnel.sh
```
To automatically clean up Docker containers after the script runs, you can uncomment `trap cleanup EXIT` at the top of `test_tunnel.sh`.

## Development

*   **Code Style**: Follow PEP 8. Use a linter like Flake8.
*   **Type Hinting**: Used throughout the codebase.
*   **Logging**: Use the `logging` module. See `src/common/logging_setup.py`.
*   **Testing**: Add unit tests for new functionality in the `tests/` directory. Maintain the end-to-end test script.

## License

MIT License (assuming from original project, can be confirmed/changed).
This project was refactored and enhanced based on an initial version.
