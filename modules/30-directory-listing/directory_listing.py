import os
import sys

# Add the grandparent directory to sys.path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from modules.utils import logger
from modules.base_module import BaseModule, main, Vuln


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
        self.feroxbuster_output_file: str = os.path.join(
            os.path.join(self.base_output_dir, "15-feroxbuster"), "feroxbuster.txt"
        )
        self.output_file: str = os.path.join(self.output_dir, "directory-listings.txt")

        self.directory_listings = set()

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

        for line in lines:
            if "heuristics detected directory listing" in line:
                self.directory_listings.add(
                    line.split(" ")[-2]
                    + ("/" if line.split(" ")[-2][-1] != "/" else "")
                )
        self.directory_listings = sorted(self.directory_listings)

    def post(self):
        if self.directory_listings:
            logger.success(f"Found {len(self.directory_listings)} directory listings:")
            for listing in self.directory_listings:
                logger.info(listing)
        else:
            logger.info("No directory listings found.")

        with open(self.output_file, "w") as f:
            for listing in self.directory_listings:
                f.write(listing + "\n")

        for directory in self.directory_listings:
            vuln = Vuln(
                title="Directory Listing",
                affected_item=directory,
                confidence=100,
                severity="low",
                host=self.target,
                summary=f"There is an open directory listing at {directory}. This can lead to information disclosure.",
            )
            self.add_vulnerability(vuln)
        logger.debug(f"Vulnerabilities added to {self.json_file}")


def add_arguments(parser):
    pass


if __name__ == "__main__":
    main("DirectoryListing", DirectoryListingModule, add_arguments)
