import argparse
import subprocess
import os
import sys
import shutil
from typing import Optional

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from constants import DEFAULT_RATE_LIMIT
from utils import logger, add_argument_if_not_exists, merge_files, run_command, filter_false_positives
from base_module import BaseModule


class GauModule(BaseModule):
    """A class to encapsulate Gau functionality for gathering URLs from various sources."""

    name = "Gau"
    index = 20
    is_default_module = True
    description = (
        "Runs Gau for passively gathering URLs from sources like Wayback Machine"
    )

    def __init__(self, args):
        """
        Initializes the Katana class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)
        self.proxy: Optional[str] = args.proxy
        self.rate_limit: Optional[str] = args.rate_limit  # Used for httpx

        self.output_file: str = f"{self.output}/gau.txt"
        self.output_filtered_file: str = f"{self.output}/gau-filtered.txt"

    def has_run_before(self) -> bool:
        """Checks if the Gau scan has been run before by checking the output file."""
        return os.path.exists(self.output_file)

    def pre(self) -> bool:
        """Checks preconditions before running Gau."""
        if not shutil.which("gau"):
            logger.critical(
                "Gau is not installed or not in PATH. Please install it before running."
            )
            return False
        if not shutil.which("httpx"):
            logger.critical(
                "httpx is not installed or not in PATH. Please install it before running."
            )
            return False
        if not shutil.which("uro"):
            logger.critical(
                "uro is not installed or not in PATH. Please install it before running."
            )
            return False
        return True

    def run(self):
        """Runs gau with the provided arguments"""
        # Construct the command as a list
        cmd_gau = [
            "gau",
            self.target,
            "--o",
            self.output_file,
        ]

        # Add optional proxy argument if provided
        if self.proxy:
            cmd_gau.extend(["--proxy", self.proxy])

        # Run the command using subprocess
        run_command(cmd_gau, verbose=self.verbose)

    def post(self):
        """Post-processing after running Gau."""
        filter_false_positives(self.output_file, self.output_filtered_file, rate_limit=self.rate_limit)

        # Print filtered results
        with open(self.output_filtered_file, "r") as f:
            filtered_urls = [url.strip() for url in f.readlines()]
            if filtered_urls:
                logger.success(f"Found {len(filtered_urls)} (filtered) URLs with Gau:")
                for url in filtered_urls:
                    logger.info(url)
            else:
                logger.info("No URLs found with Gau.")

        # Merge the filtered results with the URLs file
        merge_files(self.output_filtered_file, self.urls_file, self.urls_file)


def add_arguments(parser):
    """Adds Gau-specific arguments to the main argument parser."""
    group = parser.add_argument_group("gau")
    add_argument_if_not_exists(
        group, "--proxy", help="HTTP/SOCKS5 proxy to use for the requests"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gau Module")
    parser.add_argument("target", help="The target domain")
    parser.add_argument("-o", "--output", help="Output directory to save results")
    parser.add_argument(
        "-rl",
        "--rate-limit",
        help="Maximum requests to send per second",
        default=DEFAULT_RATE_LIMIT,
    )
    add_arguments(parser)

    args = parser.parse_args()

    if not args.target:
        logger.critical("No target specified. Please provide a target domain.")
        sys.exit(1)

    gau_module = GauModule(args)
    if not gau_module.pre():
        logger.critical("Preconditions not met. Exiting.")
        sys.exit(1)

    try:
        gau_module.run()
        gau_module.post()
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)
