import argparse
import os
import json
import sys
import shutil
from typing import Optional

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from constants import DEFAULT_RATE_LIMIT, DEFAULT_TIME_LIMIT
from utils import (
    logger,
    add_argument_if_not_exists,
    merge_files,
    run_command,
    filter_false_positives,
)
from base_module import BaseModule


class KatanaModule(BaseModule):
    """A class to encapsulate Katana functionality for crawling domains."""

    name = "Katana"
    index = 10
    is_default_module = True
    description = "Runs Katana for crawling domains"

    def __init__(self, args):
        """
        Initializes the Katana class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)
        self.rate_limit: Optional[str] = args["rate_limit"]
        self.headless: Optional[bool] = args["headless"]
        self.time_limit: Optional[str] = args["time_limit"]
        self.headers: Optional[str] = args["headers"]
        self.proxy: Optional[str] = args["proxy"]
        self.dont_scan: Optional[str] = args["dont_scan"]

        self.output_file: str = f"{self.output_dir}/katana.jsonl"
        self.output_urls_file: str = f"{self.output_dir}/katana-urls.txt"
        self.output_filtered_file: str = f"{self.output_dir}/katana-filtered.txt"

    def pre(self) -> bool:
        """Checks if katana is installed and if target is given"""
        if not shutil.which("katana"):
            logger.critical(
                "Katana is not installed or not in PATH. Please install it before running."
            )
            return False

        if not shutil.which("uro"):
            logger.critical(
                "uro is not installed or not in PATH. Please install it before running."
            )
            return False

        if not shutil.which("httpx"):
            logger.critical(
                "https is not installed or not in PATH. Please install it before running."
            )
            return False

        if not self.target:
            logger.critical("No target specified. Please provide a valid target.")
            return False

        return True

    def run(self):
        """Runs Katana with the provided arguments."""
        cmd_katana = [
            "katana",
            "-fx",
            "-jc",
            "-kf",
            "all",
            "-jsl",
            "-u",
            self.target,
            "-rl",
            self.rate_limit,
            "-ct",
            self.time_limit,
            "-j",
            "-o",
            self.output_file,
            "-cos",
            self.dont_scan,
        ]

        # Add optional arguments if provided
        if self.headless:
            cmd_katana.append("-headless")
        if self.headers:
            cmd_katana.extend(["-H", self.headers])
        if self.proxy:
            cmd_katana.extend(["-proxy", self.proxy])

        run_command(cmd_katana, verbose=self.verbose)

        logger.success(f"Katana scan completed. Results saved to {self.output_file}")

    def post(self):
        """Processes the output of Katana."""
        found_urls = []
        try:
            with open(self.output_file, "r") as f:
                found_urls = [json.loads(line)["request"]["endpoint"] for line in f]

            # Save the found URLs to a file
            with open(self.output_urls_file, "w") as f:
                f.writelines(f"{url}\n" for url in found_urls)
            logger.info(f"Found URLs saved to {self.output_urls_file}")

        except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
            logger.error(f"Error processing Katana output: {e}")
            raise

        filter_false_positives(
            self.output_urls_file, self.output_filtered_file, rate_limit=self.rate_limit
        )

        # Print filtered results
        with open(self.output_filtered_file, "r") as f:
            filtered_urls = [url.strip() for url in f.readlines()]
            if filtered_urls:
                logger.success(
                    f"Found {len(filtered_urls)} (filtered) URLs with Katana:"
                )
                for url in filtered_urls:
                    logger.info(url)
            else:
                logger.info("No URLs found with Katana.")

        merge_files(self.output_filtered_file, self.urls_file, self.urls_file)


def add_arguments(parser):
    """Adds Katana-specific arguments to the main argument parser."""
    group = parser.add_argument_group("katana")
    add_argument_if_not_exists(
        group, "-headless", help="Run in headless mode in Katana", action="store_true"
    )
    add_argument_if_not_exists(
        group,
        "-tl",
        "--time-limit",
        help="Time limit for the Katana scan",
        default=DEFAULT_TIME_LIMIT,
    )
    add_argument_if_not_exists(group, "-H", "--headers", help="Headers to use")
    add_argument_if_not_exists(
        group, "--proxy", help="HTTP/SOCKS5 proxy to use for the requests"
    )
    add_argument_if_not_exists(
        group,
        "--dont-scan",
        help="Do not scan URLs matching this regex",
        default=".*(logout|uitloggen).*",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Katana Module")
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

    katana_module = KatanaModule(args)
    if not katana_module.pre():
        logger.critical("Preconditions not met. Exiting.")
        sys.exit(1)

    try:
        katana_module.run()
        katana_module.post()
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)
