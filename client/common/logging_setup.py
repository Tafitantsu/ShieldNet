import logging
import logging.handlers
import os
from typing import Dict, Any, Optional

DEFAULT_LOG_FORMAT = '%(asctime)s - %(levelname)s - %(threadName)s - %(filename)s:%(lineno)d - %(message)s'

def setup_logging(config: Dict[str, Any], cli_log_level_override: Optional[str] = None) -> None:
    """
    Configures the logging system based on the provided configuration dictionary
    and an optional command-line log level override.

    Args:
        config: A dictionary containing logging configuration, typically from logging.*
                Expected keys:
                - log_file (str, optional): Path to the log file. If None or empty, logs to console.
                - log_level (str): Logging level (e.g., "INFO", "DEBUG").
                - log_rotation_bytes (int, optional): Max bytes before log rotation.
                - log_backup_count (int, optional): Number of backup files for rotation.
                - log_format (str, optional): Custom log format string.
        cli_log_level_override (str, optional): A log level string from CLI to override config.
    """
    log_level_str = config.get("log_level", "INFO").upper()
    if cli_log_level_override:
        log_level_str = cli_log_level_override.upper()

    numeric_log_level = getattr(logging, log_level_str, None)
    if not isinstance(numeric_log_level, int):
        print(f"Warning: Invalid log level '{log_level_str}'. Defaulting to INFO.")
        numeric_log_level = logging.INFO

    log_format = config.get("log_format", DEFAULT_LOG_FORMAT)
    log_formatter = logging.Formatter(log_format)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_log_level)

    # Remove any existing handlers (e.g., from basicConfig in main scripts)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        handler.close() # Ensure handlers release resources

    # Configure console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    root_logger.addHandler(console_handler)

    # Configure file handler if log_file is specified
    log_file_path = config.get("log_file")
    if log_file_path:
        try:
            # Ensure log directory exists
            log_dir = os.path.dirname(log_file_path)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            max_bytes = int(config.get("log_rotation_bytes", 10 * 1024 * 1024)) # Default 10MB
            backup_count = int(config.get("log_backup_count", 5)) # Default 5 backups

            if max_bytes > 0 and backup_count > 0:
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file_path,
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                    encoding='utf-8'
                )
            else: # Basic file handler if rotation is not configured properly
                file_handler = logging.FileHandler(log_file_path, encoding='utf-8')

            file_handler.setFormatter(log_formatter)
            root_logger.addHandler(file_handler)
            logging.info(f"Logging initialized. Level: {log_level_str}. Outputting to console and file: {log_file_path}")
        except Exception as e:
            # If file logging setup fails, we still have console logging.
            logging.error(f"Failed to configure file logging to {log_file_path}: {e}", exc_info=True)
            logging.info(f"Logging initialized. Level: {log_level_str}. Outputting to console only.")
    else:
        logging.info(f"Logging initialized. Level: {log_level_str}. Outputting to console only (no log_file specified).")


if __name__ == '__main__':
    # Example usage:
    print("--- Test 1: Basic Console Logging (INFO) ---")
    test_config_1 = {
        "log_level": "INFO"
    }
    setup_logging(test_config_1)
    logging.debug("This is a DEBUG message (Test 1 - should not see).")
    logging.info("This is an INFO message (Test 1 - should see).")
    logging.warning("This is a WARNING message (Test 1 - should see).")

    print("\n--- Test 2: File Logging with Rotation (DEBUG) ---")
    # Create a temporary directory for log files
    temp_log_dir = "temp_logs"
    if not os.path.exists(temp_log_dir):
        os.makedirs(temp_log_dir)

    test_log_file = os.path.join(temp_log_dir, "test_app.log")

    test_config_2 = {
        "log_file": test_log_file,
        "log_level": "DEBUG",
        "log_rotation_bytes": 1024, # 1KB for quick rotation test
        "log_backup_count": 2
    }
    setup_logging(test_config_2)
    logging.debug(f"This is a DEBUG message (Test 2 - should see in console and file: {test_log_file}).")
    logging.info("This is an INFO message (Test 2 - should see).")
    for i in range(20): # Generate some log volume
        logging.debug(f"Logging message number {i} to test rotation. " + "abcdefg " * 20) # make it ~160 chars
    logging.info("Finished Test 2 logging.")
    print(f"Check {test_log_file} and its rotated versions (e.g., test_app.log.1) in '{temp_log_dir}'.")


    print("\n--- Test 3: CLI Override (WARNING) ---")
    test_config_3 = {
        "log_file": os.path.join(temp_log_dir, "cli_override.log"),
        "log_level": "INFO", # Config says INFO
    }
    setup_logging(test_config_3, cli_log_level_override="WARNING") # CLI overrides to WARNING
    logging.debug("This is a DEBUG message (Test 3 - should not see).")
    logging.info("This is an INFO message (Test 3 - should not see).")
    logging.warning("This is a WARNING message (Test 3 - should see).")
    print(f"Check {os.path.join(temp_log_dir, 'cli_override.log')}.")


    print("\n--- Test 4: Invalid Log Level in Config ---")
    test_config_4 = {
        "log_level": "INVALID_LEVEL",
        "log_file": os.path.join(temp_log_dir, "invalid_level.log")
    }
    setup_logging(test_config_4) # Should default to INFO and print a warning
    logging.info("This is an INFO message (Test 4 - should see, after warning about invalid level).")
    print(f"Check {os.path.join(temp_log_dir, 'invalid_level.log')}.")

    # Clean up (optional)
    # import shutil
    # shutil.rmtree(temp_log_dir)
    # print(f"\nCleaned up temporary log directory: {temp_log_dir}")
    print("\nLogging setup tests finished. Manual cleanup of 'temp_logs' directory might be needed.")
