import subprocess
import os
import sys
import shutil
from typing import Optional

# Add the grandparent directory to sys.path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from config import (
    DEFAULT_DONT_SCAN_REGEX,
    DEFAULT_TIME_LIMIT,
    DEFAULT_FEROXBUSTER_FILTER_STATUS_CODES,
    DEFAULT_SENSITIVE_FILES_WORDLIST,
)
from modules.utils import logger, add_argument_if_not_exists, merge_list_with_file
from modules.base_module import BaseModule, main


class SensitiveFilesModule(BaseModule):
    """A class to encapsulate SensitiveFiles functionality for finding sensitive files."""

    name = "SensitiveFiles"
    index = 35
    is_default_module = True

    def __init__(self, args):
        """
        Initializes the Sensitive Files class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)
        self.C: Optional[str] = args.get("C", DEFAULT_FEROXBUSTER_FILTER_STATUS_CODES)
        self.time_limit: Optional[str] = args.get("time_limit", DEFAULT_TIME_LIMIT)
        self.headers: Optional[str] = args.get("headers")
        self.sensitive_files_wordlist: str = args.get("sensitive_files_wordlist", DEFAULT_SENSITIVE_FILES_WORDLIST)
        self.dont_scan: Optional[str] = args.get("dont_scan", DEFAULT_DONT_SCAN_REGEX)

        self.output_file: str = f"{self.output_dir}/sensitive-files.txt"

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

        if os.path.exists(self.output_file):
            logger.warning(
                f"Output file {self.output_file} already exists. We will overwrite it."
            )
            os.remove(self.output_file)

        return True

    def run(self):
        """Runs Feroxbuster with the provided arguments"""
        cmd_cat = ["cat", self.directories_file]
        cmd_feroxbuster = [
            "feroxbuster",
            "--stdin",
            "--silent",
            "-w",
            self.sensitive_files_wordlist,
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
            self.dont_scan,
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
            else:
                logger.info("No sensitive files detected.")

            # Merge the results into the URLs file
            merge_list_with_file(sensitive_paths, self.urls_file, self.urls_file)
            logger.info(f"Sensitive files successfully merged into {self.urls_file}")
        except FileNotFoundError:
            logger.error(f"Output file {self.output_file} not found.")
        except Exception as e:
            logger.error(f"Error processing Feroxbuster output: {e}")


def add_arguments(parser):
    group = parser.add_argument_group("sensitive files")
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
        group,
        "-sfw",
        "--sensitive-files-wordlist",
        help="Wordlist to use for Feroxbuster sensitive files scan",
        default=DEFAULT_SENSITIVE_FILES_WORDLIST,
    )
    add_argument_if_not_exists(
        group,
        "--dont-scan",
        help="Do not scan URLs matching this regex",
        default=DEFAULT_DONT_SCAN_REGEX,
    )


if __name__ == "__main__":
    main("SensitiveFiles", SensitiveFilesModule, add_arguments)
