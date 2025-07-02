import argparse
import os
import sys

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import logger
from base_module import BaseModule


class DirectoryListingModule(BaseModule):
    """A class to detect Directory Listing from Feroxbuster output."""

    name = "Directory Listing"
    index = 30
    is_default_module = True
    description = "Detects directory listings from Feroxbuster output"

    def __init__(self, args):
        """
        Initializes the Directory Listing class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)
        self.feroxbuster_output_file: str = f"{self.output_dir}/feroxbuster.txt"
        self.output_file: str = f"{self.output_dir}/directory-listings.txt"

    def has_run_before(self) -> bool:
        """Checks if the Directory Listing scan has been run before by checking the output file."""
        return os.path.exists(self.output_file)

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
    parser = argparse.ArgumentParser(description="Directory Listing Module")
    parser.add_argument("target", help="The target domain")
    parser.add_argument("-o", "--output", help="Output directory to save results")
    add_arguments(parser)
    args = parser.parse_args()

    if not args.target:
        logger.critical("No target specified. Please provide a target domain.")
        sys.exit(1)

    directory_listing_module = DirectoryListingModule(args)
    if not directory_listing_module.pre():
        logger.critical("Preconditions not met. Exiting.")
        sys.exit(1)

    try:
        directory_listing_module.run()
        directory_listing_module.post()
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)
