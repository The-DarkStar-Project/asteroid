import logging
import coloredlogs
import os
import sys

# Add current directory to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from constants import OUTPUT_DIR

# set success level
logging.SUCCESS = 25  # between WARNING and INFO
logging.addLevelName(logging.SUCCESS, "SUCCESS")


class LogFormatter(logging.Formatter):
    """Custom log formatter with color-coded log levels."""

    grey = "\x1b[38;20m"
    green = "\x1b[32;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    msg = "%(message)s"

    FORMATS = {
        logging.DEBUG: grey + msg + reset,
        logging.INFO: grey + msg + reset,
        logging.SUCCESS: green + msg + reset,
        logging.WARNING: yellow + msg + reset,
        logging.ERROR: red + msg + reset,
        logging.CRITICAL: bold_red + msg + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %H:%M:%S")
        return formatter.format(record)


class OutputToFileFilter(logging.Filter):
    def __init__(self, output_to_file=True):
        super().__init__()
        self.output_to_file = output_to_file

    def filter(self, record):
        # Only allow records with the specified output_to_file attribute
        return getattr(record, "output_to_file", True) == self.output_to_file


def get_logger(name, outputdir=OUTPUT_DIR, level="INFO"):
    """
    Configures and returns a logger instance.

    Args:
        name (str): Name of the logger.
        level (str): Logging level (e.g., "DEBUG", "INFO").

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)

    setattr(
        logger,
        "success",
        lambda message, *args: logger._log(logging.SUCCESS, message, args),
    )

    coloredlogs.install(level=level, fmt="%(message)s")

    return logger


# def set_outputdir(logger, outputdir):
#     """
#     Sets the output directory for the logger.

#     Args:
#         logger (logging.Logger): Logger instance.
#         outputdir (str): Output directory to set.
#     """
#     if not os.path.exists(outputdir):
#         os.makedirs(outputdir)

#     for handler in logger.handlers:
#         if isinstance(handler, logging.FileHandler):
#             handler.baseFilename = os.path.join(outputdir, "results.txt")
#             handler.stream = open(handler.baseFilename, 'a')


def set_logger(logger, outputdir=OUTPUT_DIR, level="INFO"):
    """
    Sets up the logger with a file handler and colored output.

    Args:
        logger (logging.Logger): The logger instance to configure.
        outputdir (str): The directory to save log files.
        level (str): The logging level to set.
    """
    # Set level
    logger.setLevel(level)

    # Set output directory
    if outputdir and not os.path.exists(outputdir):
        os.makedirs(outputdir)

    while logger.handlers:
        logger.removeHandler(logger.handlers[0])
    
    if outputdir:
        # File handler
        file_handler = logging.FileHandler(os.path.join(outputdir, "results.txt"))
        file_handler.setLevel(level)
        file_handler.addFilter(
            OutputToFileFilter(output_to_file=True)
        )  # Only log messages with output_to_file=True
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        file_handler.stream = open(file_handler.baseFilename, "a")

        # Add handlers to the logger
        logger.addHandler(file_handler)
    