from abc import ABC, abstractmethod
import os
from urllib.parse import urlparse
import sys

# Add current directory to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from constants import URLS_FILE, DIRECTORIES_FILE, OUTPUT_DIR


class BaseModule(ABC):
    """Abstract base class for all modules."""

    name = "BaseModule"
    index = 99
    is_default_module = True
    description = "Example description"

    def __init__(self, args):
        """
        Initializes the base module with common parameters.

        :param args: The command line arguments passed to the script.
        """
        self.target = args["target"]

        if not str(self.target).startswith("http") and not str(self.target).startswith(
            "https://"
        ):
            self.target = "http://" + str(self.target)  # TODO: check if http or https

        self.output_dir = args["output_dir"]
        if not self.output_dir:
            self.output_dir = os.path.join(OUTPUT_DIR, urlparse(self.target).netloc)

        self.verbose = args["verbose"]

        self.target_name = urlparse(self.target).netloc
        self.script_dir = os.path.dirname(
            sys.modules[self.__class__.__module__].__file__
        )
        self.urls_file = os.path.join(self.output_dir, URLS_FILE)
        self.directories_file = os.path.join(self.output_dir, DIRECTORIES_FILE)

        # Ensure the output directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def has_run_before(self) -> bool:
        """Checks if the module has run before by checking the existence of the output file."""
        return os.path.exists(self.output_file)
    
    @abstractmethod
    def pre(self) -> bool:
        """Checks preconditions before running the module."""
        return True

    @abstractmethod
    def run(self):
        """Runs the module's main functionality."""
        pass

    @abstractmethod
    def post(self):
        """Performs post-processing after the module has run."""
        pass
