import logging
import coloredlogs
import os
import sys

# Add parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import OUTPUT_DIR

# set success level
logging.SUCCESS = 25  # between WARNING and INFO
logging.addLevelName(logging.SUCCESS, "SUCCESS")


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


def set_logger(logger, outputdir=None, level="INFO"):
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
