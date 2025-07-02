# Agent Instructions for Secure TCP Tunnel Project

Welcome, agent! This file contains guidelines and conventions to follow while working on this project.

## 1. Coding Style & Conventions

*   **Python:** Follow PEP 8 guidelines. Use a linter like Flake8 or Black if possible.
*   **Type Hinting:** Use type hints for all function signatures and critical variables.
*   **Logging:**
    *   Use the standard `logging` module.
    *   Log messages should be clear and informative.
    *   Use appropriate log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    *   Avoid print statements for logging; use the logging framework.
*   **Error Handling:**
    *   Handle exceptions gracefully.
    *   Provide context in error messages.
    *   Avoid catching generic `Exception` where possible; catch specific exceptions.
*   **Modularity:**
    *   Strive for small, focused functions and classes.
    *   Shared utilities should go into the `src/common/` directory.
*   **Configuration:**
    *   All configurable parameters should be managed through the YAML configuration files. Avoid hardcoding values that might need to change.

## 2. TLS/SSL Implementation

*   **Security First:** Prioritize secure defaults.
*   **Explicit TLS Versions:** When configuring `SSLContext`, explicitly disable insecure protocols (SSLv3, TLSv1.0, TLSv1.1) and set the minimum version to TLS 1.2.
*   **Certificate Validation:**
    *   Always validate peer certificates in mTLS.
    *   Perform hostname/CN/SAN validation rigorously.
*   **Error Messages:** TLS-related errors should be logged with sufficient detail to help diagnose issues (e.g., certificate verification errors, handshake failures).

## 3. Testing

*   **Unit Tests:** Write unit tests for new functionality, especially for logic in `src/common/` and core connection handling.
    *   Use the `unittest` or `pytest` framework.
    *   Employ mocks (`unittest.mock`) extensively to isolate units of code, especially for network operations and SSL/TLS interactions.
*   **Integration Testing:** The `scripts/test_tunnel.sh` (or similar) should be maintained to ensure end-to-end functionality.

## 4. Docker

*   Dockerfiles should be kept minimal and efficient.
*   Use multi-stage builds if it significantly reduces image size.
*   Ensure `docker-compose.yml` is up-to-date for easy local testing.

## 5. Commits and Pull Requests (If Applicable)

*   Follow conventional commit message formats if the project adopts them.
*   Ensure code is formatted and linted before committing.
*   Ensure all tests pass.

## 6. Plan Adherence

*   Stick to the established plan. If deviations are necessary, update the plan using `set_plan` and inform the user.
*   Mark plan steps as complete using `plan_step_complete()`.

## 7. Dependencies

*   Add new dependencies to `requirements.txt`.
*   Prefer well-maintained and reputable libraries.

By following these guidelines, we can ensure the project remains maintainable, secure, and robust. Thank you!
