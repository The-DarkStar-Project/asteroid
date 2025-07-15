import os
import sys

# Add the grandparent directory to sys.path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from modules.utils import logger
from modules.base_module import BaseModule, main


class DirectoryListingModule(BaseModule):
    """A class to detect Directory Listing from Feroxbuster output."""

    name = "DirectoryListing"
    index = 30
    is_default_module = True
    description = "Detects directory listings from Feroxbuster output"

    def __init__(self, args):
        """
        Initializes the Directory Listing class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)
        self.feroxbuster_output_file: str = os.path.join(os.path.join(self.base_output_dir, "15-feroxbuster"),"feroxbuster.txt")
        self.output_file: str = os.path.join(self.output_dir, "directory-listings.txt")

    def pre(self) -> bool:
        """Checks preconditions before running Feroxbuster."""
        if not os.path.exists(self.feroxbuster_output_file):
            logger.critical(
                f"Feroxbuster output file {self.feroxbuster_output_file} does not exist"
            )
            return False

        return True

    def run(self):
        """Processes the Feroxbuster output to find directory listings."""
        with open(self.feroxbuster_output_file, "r") as f:
            lines = f.readlines()

        directory_listings = set()
        for line in lines:
            if "heuristics detected directory listing" in line:
                directory_listings.add(
                    line.split(" ")[-2]
                    + ("/" if line.split(" ")[-2][-1] != "/" else "")
                )
        directory_listings = sorted(directory_listings)

        if directory_listings:
            logger.success(f"Found {len(directory_listings)} directory listings:")
            for listing in directory_listings:
                logger.info(listing)
        else:
            logger.info("No directory listings found.")

        with open(self.output_file, "w") as f:
            for listing in directory_listings:
                f.write(listing + "\n")

    def post(self):
        pass


def add_arguments(parser):
    pass


if __name__ == "__main__":
    main("DirectoryListing", DirectoryListingModule, add_arguments)
