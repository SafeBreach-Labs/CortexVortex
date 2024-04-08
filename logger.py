"""
This module provides utilities for logging messages with custom formatting.

It includes a custom logging formatter `CortexVortexLogger` 
that adds a bullet point prefix to log messages based on their severity level.
It also provides a function `init_logger()` to initialize the logger
with a stream handler and set the logging level to INFO.

Example usage:
    import logging_util
    
    logging_util.init_logger()
    logging.info("This is an information message.")
    logging.debug("This is a debug message.")
    logging.error("This is an error message.")
"""

import sys
import logging

class CortexVortexLogger(logging.Formatter):
    """
    Custom logging formatter that adds a bullet point prefix based on log level.

    The bullet points indicate the severity of the log message:
    - [+] for INFO level messages
    - [DEBUG]: for DEBUG level messages
    - [!] for ERROR level messages
    - [~] for WARNNING level messages
    - [X] for other log messages

    :param logging.Formatter: Parent class for formatting log messages.
    """
    def __init__(self) -> None:
        super().__init__("%(bullet)s %(asctime)s.%(msecs)03d %(message)s", "%Y-%m-%d %H:%M:%S")

    def format(self, record):
        """
        Formats the log record with a bullet point prefix based on the log level.

        :param record: The log record to be formatted.
        :return: The formatted log message.
        """

        if record.levelno == logging.INFO:
            record.bullet = '[+]'
        elif record.levelno == logging.DEBUG:
            record.bullet = '[DEBUG]:'
        elif record.levelno == logging.ERROR:
            record.bullet = '[!]'
        elif record.levelno == logging.WARNING:
            record.bullet = '[~]'
        else:
            record.bullet = '[X]'

        return logging.Formatter.format(self, record)


def init_logger():
    """
    Initializes the logger with a stream handler and sets the logging level to INFO.
    :return: None
    """

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(CortexVortexLogger())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)
