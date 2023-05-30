import argparse
import logging

from gmsad.config import load_config
from gmsad.utils import configure_logging
from gmsad import run

DEFAULT_CONFIG = "/etc/gmsad.conf"
DEFAULT_LOGLEVEL = "INFO"

def main() -> int:
    # Initialy configure logging to default level
    logging.basicConfig(level=DEFAULT_LOGLEVEL)

    parser = argparse.ArgumentParser(description="Linux service to manage gMSA accounts")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    parser.add_argument("-l", "--loglevel",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])

    args = parser.parse_args()

    config = load_config(args.config)

    if args.loglevel:
        configure_logging(args.loglevel)
    else:
        configure_logging(config.get('gmsad', 'loglevel', fallback=DEFAULT_LOGLEVEL))

    return run(config)
