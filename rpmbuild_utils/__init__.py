"""RPM build utilities for Konflux pipeline."""

import logging

__version__ = "0.1.0"


def setup_logging(debug=False):
    """Configure logging based on debug flag."""
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
