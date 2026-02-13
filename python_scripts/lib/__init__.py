"""RPM build utilities for Konflux pipeline."""

import logging
import re

__version__ = "0.1.0"

# Logging configuration
DEFAULT_LOG_WIDTH = 120
MAX_LOG_LINE_LENGTH = 114

# ============================================================================
# Logging Utilities
# ============================================================================

def sanitize_error_message(error_msg: str) -> str:
    """
    Sanitize error messages to remove sensitive information like passwords or secrets.

    This function should be used whenever logging error messages that might contain
    sensitive data such as passwords, API keys, tokens, or other credentials.

    Args:
        error_msg: Original error message that may contain sensitive data

    Returns:
        Sanitized error message with sensitive information redacted
    """
    # List of sensitive field names that should be redacted
    sensitive_fields = [
        'password', 'secret', 'token', 'key', 'credential', 'auth',
        'client_secret', 'client_id', 'api_key', 'access_token',
        'private_key', 'privatekey', 'cert', 'certificate'
    ]

    sanitized = error_msg
    # Try to redact common patterns like key=value or "key": "value"
    for field in sensitive_fields:
        # Pattern: field = "value" or field="value" (with optional quotes)
        # Match values that might be on the same line or next line
        pattern = rf'\b{field}\s*=\s*["\']?[^"\'\n\r]+["\']?'
        sanitized = re.sub(pattern, f'{field} = <REDACTED>', sanitized, flags=re.IGNORECASE)
        # Pattern: "field": "value" or 'field': 'value'
        pattern = rf'["\']?{field}["\']?\s*:\s*["\']?[^"\'\n\r]+["\']?'
        sanitized = re.sub(pattern, f'"{field}": "<REDACTED>"', sanitized, flags=re.IGNORECASE)
        # Pattern: [field] section with values below (for TOML)
        pattern = rf'\[{field}\][^\]]*'
        sanitized = re.sub(pattern, f'[{field}] <REDACTED>', sanitized, flags=re.IGNORECASE | re.DOTALL)

    return sanitized


class WrappingFormatter(logging.Formatter):
    """
    Custom formatter that wraps long log messages for better readability.

    This formatter extends the standard logging formatter to handle
    long messages by wrapping them at a specified width.
    """

    def __init__(self, fmt=None, datefmt=None, width=DEFAULT_LOG_WIDTH):
        """
        Initialize the wrapping formatter.

        Args:
            fmt: Format string for log messages
            datefmt: Date format string
            width: Maximum width for log message wrapping
        """
        super().__init__(fmt, datefmt)
        self.width = width

    def format(self, record):
        """
        Format the log record with line wrapping.

        Args:
            record: Log record to format

        Returns:
            Formatted log message with wrapping
        """
        formatted = super().format(record)

        # Only wrap if the message is longer than the specified width
        if len(formatted) > self.width:
            lines = []
            current_line = ""

            for word in formatted.split():
                if len(current_line + " " + word) <= self.width:
                    current_line += (" " + word) if current_line else word
                else:
                    if current_line:
                        lines.append(current_line)
                    current_line = word

            if current_line:
                lines.append(current_line)

            formatted = "\n".join(lines)

        return formatted


def _setup_wrapping_logging(level: int) -> None:
    """Setup logging with wrapping formatter."""
    formatter = WrappingFormatter(
        fmt='%(asctime)s - %(levelname)s - %(message)s',
        width=120
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    # Clear any existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level)

def _setup_basic_logging(level: int) -> None:
    """Setup basic logging configuration."""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def setup_logging(debug: bool, use_wrapping: bool = False) -> None:
    """
    Setup logging configuration.

    This function configures the logging system with appropriate level and
    formatter. Optionally uses a custom wrapping formatter for better readability.

    Args:
        debug: If True, enable debug level logging; otherwise use info level
        use_wrapping: If True, use wrapping formatter for long messages
    """
    level = logging.DEBUG if debug else logging.INFO

    if use_wrapping:
        _setup_wrapping_logging(level)
    else:
        _setup_basic_logging(level)
