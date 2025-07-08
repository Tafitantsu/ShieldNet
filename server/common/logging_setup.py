import logging
import logging.handlers
import os
from typing import Dict, Any, Optional
import sys # For sys.stderr

try:
    import coloredlogs
    COLOREDLOGS_AVAILABLE = True
except ImportError:
    COLOREDLOGS_AVAILABLE = False

DEFAULT_LOG_FORMAT = '%(asctime)s - %(levelname)s - %(threadName)s - %(filename)s:%(lineno)d - %(message)s'
# Coloredlogs typically uses its own default format which is quite nice.
# We can define a custom one if needed, e.g.,
# DEFAULT_COLORED_LOG_FORMAT = '%(asctime)s %(hostname)s %(name)s[%(process)d] %(levelname)s %(message)s'
# For simplicity, we'll let coloredlogs use its default or a field_styles/level_styles customized one.

DEFAULT_FIELD_STYLES = {
    'asctime': {'color': 'green'},
    'hostname': {'color': 'magenta'},
    'levelname': {'color': 'black', 'bold': True}, # Default coloredlogs has its own level colors
    'name': {'color': 'blue'},
    'programname': {'color': 'cyan'},
    'threadName': {'color': 'yellow'},
    'filename': {'color': 'blue'},
    'lineno': {'color': 'blue'},
}

DEFAULT_LEVEL_STYLES = {
    'spam': {'color': 'green', 'faint': True},
    'debug': {'color': 'white', 'faint': True}, # Faint white for debug
    'verbose': {'color': 'blue'},
    'info': {'color': 'green'}, # Green for info
    'notice': {'color': 'magenta'},
    'warning': {'color': 'yellow'}, # Yellow for warning
    'success': {'color': 'green', 'bold': True},
    'error': {'color': 'red'}, # Red for error
    'critical': {'color': 'red', 'bold': True, 'background': 'white'}, # Bold red on white for critical
}


def setup_logging(config: Dict[str, Any], cli_log_level_override: Optional[str] = None, use_color: bool = True) -> None:
    """
    Configures the logging system based on the provided configuration dictionary
    and an optional command-line log level override.

    Args:
        config: A dictionary containing logging configuration.
                Expected keys:
                - log_file (str, optional): Path to the log file. If None or empty, logs to console only.
                - log_level (str): Logging level (e.g., "INFO", "DEBUG").
                - log_rotation_bytes (int, optional): Max bytes before log rotation.
                - log_backup_count (int, optional): Number of backup files for rotation.
                - log_format (str, optional): Custom log format string for file logger.
                                            Console logger will use coloredlogs default or custom colored format.
                - log_color (bool, optional): Explicitly enable/disable color for console. Defaults to True.
        cli_log_level_override (str, optional): A log level string from CLI to override config.
        use_color (bool): General flag to enable/disable color, can be overridden by config['log_color']
    """
    log_level_str = config.get("log_level", "INFO").upper()
    if cli_log_level_override:
        log_level_str = cli_log_level_override.upper()

    numeric_log_level = getattr(logging, log_level_str, None)
    if not isinstance(numeric_log_level, int):
        # Use basic print for this warning as logging might not be fully set up.
        print(f"Warning: Invalid log level '{log_level_str}'. Defaulting to INFO.", file=sys.stderr)
        numeric_log_level = logging.INFO
        log_level_str = "INFO" # Ensure log_level_str is also updated for messages

    # Determine if color should be used for console
    should_use_color_from_config = config.get("log_color", None)
    if should_use_color_from_config is not None:
        effective_use_color = should_use_color_from_config
    else:
        effective_use_color = use_color


    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_log_level)

    # Remove any existing handlers (e.g., from basicConfig in main scripts or previous setup_logging calls)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        handler.close() # Ensure handlers release resources

    # Configure console handler (potentially with color)
    if COLOREDLOGS_AVAILABLE and effective_use_color and sys.stderr.isatty(): # Check if output is a TTY
        # `isatty()` helps avoid outputting ANSI codes if stdout/stderr is redirected to a file
        coloredlogs.install(
            level=numeric_log_level,
            logger=root_logger, # Install on the root logger
            fmt=config.get("log_format_console", '%(asctime)s %(levelname)-8s %(name)s: %(message)s'), # Example format
            level_styles=config.get("log_level_styles", DEFAULT_LEVEL_STYLES),
            field_styles=config.get("log_field_styles", DEFAULT_FIELD_STYLES),
            stream=sys.stderr # It's common practice to log to stderr
        )
        # coloredlogs.install replaces existing handlers on the logger it's installed on.
        # So, we don't add a separate StreamHandler if coloredlogs is used.
        console_configured_message = "Console logging configured with coloredlogs."
    else:
        console_handler = logging.StreamHandler(sys.stderr)
        console_formatter = logging.Formatter(config.get("log_format_console", DEFAULT_LOG_FORMAT))
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
        if not COLOREDLOGS_AVAILABLE and effective_use_color:
            # Use basic print as logging might not be fully set up for this specific warning
             print("Warning: 'coloredlogs' library not found or color explicitly disabled. Using standard console logging.", file=sys.stderr)
        console_configured_message = "Console logging configured with standard StreamHandler."


    # Configure file handler if log_file is specified
    log_file_path = config.get("log_file")
    file_handler_configured = False
    if log_file_path:
        try:
            # Ensure log directory exists
            log_dir = os.path.dirname(log_file_path)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            # Use a specific formatter for files (no ANSI codes)
            file_log_format = config.get("log_format_file", DEFAULT_LOG_FORMAT)
            file_formatter = logging.Formatter(file_log_format)

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

            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
            file_handler_configured = True
        except Exception as e:
            # If file logging setup fails, we still have console logging.
            # Log this error to the console (which should be configured by now)
            root_logger.error(f"Failed to configure file logging to {log_file_path}: {e}", exc_info=True)

    # Initial status message
    status_message = f"Logging initialized. Level: {log_level_str}. {console_configured_message}"
    if file_handler_configured:
        status_message += f" Outputting to file: {log_file_path}."
    elif log_file_path: # Attempted file logging but failed
        status_message += " File logging failed to initialize."
    else: # No file logging requested
        status_message += " No file logging configured."

    # Use a logger that's part of the hierarchy, or the root logger itself for this initial message.
    # This ensures it respects the configured level and handlers.
    logging.getLogger(__name__).info(status_message)


if __name__ == '__main__':
    # Example usage (this is the correct __main__ block from the latest version I have):
    print("--- Test 1: Basic Console Logging (INFO) - Colored if available ---")
    test_config_1 = {
        "log_level": "INFO",
        "log_format_console": "%(asctime)s [%(levelname)s] %(message)s (%(name)s)"
    }
    setup_logging(test_config_1)
    logging.debug("This is a DEBUG message (Test 1 - should not see).")
    logging.info("This is an INFO message (Test 1 - should see).")
    logging.warning("This is a WARNING message (Test 1 - should see).")
    logging.error("This is an ERROR message (Test 1 - should see).")
    logging.critical("This is a CRITICAL message (Test 1 - should see).")


    print("\n--- Test 2: File Logging with Rotation (DEBUG) - Console Colored ---")
    # Create a temporary directory for log files
    temp_log_dir_main = "temp_logs_colored_main" # Changed name to avoid conflict if module is run multiple times
    if not os.path.exists(temp_log_dir_main):
        os.makedirs(temp_log_dir_main)

    test_log_file_main = os.path.join(temp_log_dir_main, "test_app_colored.log")

    test_config_2 = {
        "log_file": test_log_file_main,
        "log_level": "DEBUG",
        "log_rotation_bytes": 1024,
        "log_backup_count": 2,
        "log_format_file": "%(asctime)s - FILE - %(levelname)s - %(message)s",
        "log_format_console": "%(asctime)s CONSOLE [%(levelname)s] %(message)s"
    }
    setup_logging(test_config_2)
    logging.debug(f"This is a DEBUG message (Test 2 - should see in console and file: {test_log_file_main}).")
    logging.info("This is an INFO message (Test 2 - should see).")
    for i in range(20):
        logging.debug(f"Logging message number {i} to test rotation. " + "abcdefg " * 20)
    logging.info("Finished Test 2 logging.")
    print(f"Check {test_log_file_main} and its rotated versions in '{temp_log_dir_main}'.")
    print(f"Console output for Test 2 should be colored and use its specific format.")


    print("\n--- Test 3: CLI Override (WARNING) - Console Colored ---")
    test_config_3 = {
        "log_file": os.path.join(temp_log_dir_main, "cli_override_colored.log"),
        "log_level": "INFO",
        "log_color": True
    }
    setup_logging(test_config_3, cli_log_level_override="WARNING")
    logging.debug("This is a DEBUG message (Test 3 - should not see).")
    logging.info("This is an INFO message (Test 3 - should not see).")
    logging.warning("This is a WARNING message (Test 3 - should see).")
    print(f"Check {os.path.join(temp_log_dir_main, 'cli_override_colored.log')}.")


    print("\n--- Test 4: Invalid Log Level in Config - Console Colored ---")
    test_config_4 = {
        "log_level": "INVALID_LEVEL",
        "log_file": os.path.join(temp_log_dir_main, "invalid_level_colored.log")
    }
    setup_logging(test_config_4)
    logging.info("This is an INFO message (Test 4 - should see, after warning about invalid level).")
    print(f"Check {os.path.join(temp_log_dir_main, 'invalid_level_colored.log')}.")

    print("\n--- Test 5: Color explicitly disabled in config ---")
    test_config_5 = {
        "log_level": "INFO",
        "log_color": False,
        "log_file": os.path.join(temp_log_dir_main, "no_color_config.log"),
    }
    setup_logging(test_config_5)
    logging.info("This is an INFO message (Test 5 - should see, NO COLOR from config).")
    print(f"Check {os.path.join(temp_log_dir_main, 'no_color_config.log')}.")

    print("\n--- Test 6: Color disabled by global flag (e.g. if not a TTY conceptually) ---")
    test_config_6 = {
        "log_level": "INFO",
        "log_file": os.path.join(temp_log_dir_main, "no_color_global_flag.log"),
    }
    setup_logging(test_config_6, use_color=False)
    logging.info("This is an INFO message (Test 6 - should see, NO COLOR from global flag).")
    print(f"Check {os.path.join(temp_log_dir_main, 'no_color_global_flag.log')}.")

    print("\nLogging setup tests finished. Manual cleanup of 'temp_logs_colored_main' directory might be needed.")
