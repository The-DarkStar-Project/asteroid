import argparse
import subprocess
import os
import sys
import shutil
from typing import Optional

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from constants import (
    DEFAULT_RATE_LIMIT,
    DEFAULT_TIME_LIMIT,
    DEFAULT_FEROXBUSTER_FILTER_STATUS_CODES,
    DEFAULT_SENSITIVE_FILES_WORDLIST,
)
from utils import logger, add_argument_if_not_exists, merge_list_with_file
from base_module import BaseModule


class SensitiveFilesModule(BaseModule):
    """A class to encapsulate SensitiveFiles functionality for finding sensitive files."""

    name = "Sensitive Files"
    index = 35
    is_default_module = True

    def __init__(self, args):
        """
        Initializes the Sensitive Files class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)
        self.C: Optional[str] = args.C
        self.rate_limit: Optional[str] = args.rate_limit
        self.time_limit: Optional[str] = args.time_limit
        self.headers: Optional[str] = args.headers
        self.proxy: Optional[str] = args.proxy
        self.wordlist: str = args.wordlist

        self.output_file: str = f"{args.output}/sensitive-files.txt"

    def has_run_before(self) -> bool:
        """Checks if the Sensitive Files scan has been run before by checking the output file."""
        return os.path.exists(self.output_file)

    def pre(self) -> bool:
        """Checks preconditions before running Sensitive Files fuzzer."""
        if not shutil.which("feroxbuster"):
            logger.critical(
                "Feroxbuster is not installed or not in PATH. Please install it before running."
            )
            return False
        if not os.path.exists(self.directories_file):
            logger.critical(f"Directories file {self.directories_file} does not exist")
            return False

        return True

    def run(self):
        """Runs Feroxbuster with the provided arguments"""
        cmd_cat = ["cat", self.directories_file]
        cmd_feroxbuster = [
            "feroxbuster",
            "--stdin",
            "--silent",
            "-w",
            self.wordlist,
            "--collect-backups",
            "--collect-extensions",
            "--dont-extract-links",
            "-o",
            self.output_file,
            "-C",
            self.C,  # Example status codes, replace with args.C if needed
            "-d",
            "1",
            "--no-state",
            "--time-limit",
            self.time_limit,  # Replace with args.time_limit if needed
            "--rate-limit",
            self.rate_limit,  # Replace with args.rate_limit if needed
            "--dont-scan",
            ".*(logout|uitloggen).*",
        ]

        # Add optional headers and proxy
        if self.headers:
            cmd_feroxbuster.extend(["-H", self.headers])
        if self.proxy:
            cmd_feroxbuster.extend(["--proxy", self.proxy])

        logger.debug(
            f"Running command: {' '.join(cmd_cat)} | {' '.join(cmd_feroxbuster)}"
        )

        try:
            cat_proc = subprocess.Popen(cmd_cat, stdout=subprocess.PIPE, text=True)
            subprocess.run(
                cmd_feroxbuster,
                stdin=cat_proc.stdout,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            cat_proc.stdout.close()  # Allow `cat_proc` to receive a SIGPIPE if `ferox_proc` exits
        except Exception as e:
            logger.critical(f"Feroxbuster execution failed: {e}")
            raise

    def post(self):
        """Processes the Feroxbuster output and merges results."""
        try:
            with open(self.output_file, "r") as f:
                sensitive_paths = [
                    path.strip()
                    for path in f.readlines()
                    if self.target in path and "MSG" not in path
                ]

            if sensitive_paths:
                logger.success(f"Found {len(sensitive_paths)} sensitive files:")
                for path in sensitive_paths:
                    logger.info(path)

                # Write the filtered results back to the output file
                with open(self.output_file, "w") as f:
                    f.write("\n".join(sensitive_paths))

                # Merge the results into the URLs file
                merge_list_with_file(sensitive_paths, self.urls_file, self.urls_file)
                logger.info(
                    f"Sensitive files successfully merged into {self.urls_file}"
                )
            else:
                logger.info("No sensitive files detected.")
        except FileNotFoundError:
            logger.error(f"Output file {self.output_file} not found.")
        except Exception as e:
            logger.error(f"An error occurred during post-processing: {e}")


def add_arguments(parser):
    group = parser.add_argument_group("sensitive files")
    add_argument_if_not_exists(
        group,
        "-rl",
        "--rate-limit",
        help="Maximum requests to send per second",
        default=DEFAULT_RATE_LIMIT,
    )
    add_argument_if_not_exists(
        group,
        "-tl",
        "--time-limit",
        help="Time limit for the feroxbuster",
        default=DEFAULT_TIME_LIMIT,
    )
    add_argument_if_not_exists(
        group,
        "-C",
        help="Filter status codes for feroxbuster",
        default=DEFAULT_FEROXBUSTER_FILTER_STATUS_CODES,
    )
    add_argument_if_not_exists(group, "-H", "--headers", help="Headers to use")
    add_argument_if_not_exists(
        group, "--proxy", help="HTTP/SOCKS5 proxy to use for the requests"
    )
    add_argument_if_not_exists(
        group,
        "-w",
        "--wordlist",
        help="Wordlist to use for feroxbuster",
        default=DEFAULT_SENSITIVE_FILES_WORDLIST,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sensitive Files Module")
    parser.add_argument("target", help="The target domain")
    parser.add_argument("-o", "--output", help="Output directory to save results")
    add_arguments(parser)
    args = parser.parse_args()

    if not args.target:
        logger.critical("No target specified. Please provide a target domain.")
        sys.exit(1)

    sensitive_files_module = SensitiveFilesModule(args)
    if not sensitive_files_module.pre():
        logger.critical("Preconditions not met. Exiting.")
        sys.exit(1)

    try:
        sensitive_files_module.run()
        sensitive_files_module.post()
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)
