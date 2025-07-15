import os
import sys
import shutil
from typing import Optional

# Add the grandparent directory to sys.path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from config import DEFAULT_ARJUN_WORDLIST
from modules.utils import (
    logger,
    add_argument_if_not_exists,
    merge_files,
    run_command,
    match_urls_non_static,
)
from modules.base_module import BaseModule, main


class ArjunModule(BaseModule):
    """A class to encapsulate Arjun functionality for parameter mining."""

    name = "Arjun"
    index = 25
    is_default_module = False
    description = "Runs Arjun for parameter mining"

    def __init__(self, args):
        """
        Initializes the Arjun class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)
        self.headers: Optional[str] = args.get("headers")
        self.arjun_wordlist: str = args.get("arjun_wordlist", DEFAULT_ARJUN_WORDLIST)

        self.urls_non_static_file: str = os.path.join(
            self.output_dir, "urls-non-static.txt"
        )
        self.output_file: str = os.path.join(self.output_dir, "arjun.txt")

    def pre(self) -> bool:
        """Checks preconditions before running Arjun."""
        if not shutil.which("arjun"):
            logger.critical(
                "Arjun is not installed or not in PATH. Please install it before running."
            )
            return False

        if not os.path.exists(self.urls_file):
            logger.critical(
                f"URLs file {self.urls_file} does not exist. Please ensure it is available."
            )
            return False

        if not os.path.exists(self.urls_non_static_file):
            match_urls_non_static(self.urls_file, self.urls_non_static_file)
        logger.info("pre done")
        return True

    def run(self):
        """Runs Arjun with the provided arguments"""
        # Construct the command as a list
        cmd_arjun = [
            "arjun",
            "-i",
            self.urls_non_static_file,
            "-w",
            self.arjun_wordlist,
            "-oT",
            self.output_file,
            "--rate-limit",
            self.rate_limit,
        ]

        # Add optional headers and proxy arguments if provided
        if self.headers:
            cmd_arjun.extend(["--headers", self.headers])
        if self.proxy:
            cmd_arjun.extend(["-oB", self.proxy])

        run_command(cmd_arjun, verbose=self.verbose)
        logger.info("run done")

    def post(self):
        """Prints results and merges Arjun results with the URLs file."""
        with open(self.output_file, "r") as f:
            found_urls = [url.strip() for url in f.readlines()]
            if found_urls:
                logger.success(f"Found {len(found_urls)} URLs with Arjun:")
                for url in found_urls:
                    logger.info(url)
            else:
                logger.info("No URLs found with Arjun.")

        merge_files(self.output_file, self.urls_file, self.urls_file)
        logger.info(f"Arjun results merged with {self.urls_file}")


def add_arguments(parser):
    """Adds Arjun-specific arguments to the main argument parser."""
    group = parser.add_argument_group("arjun")
    add_argument_if_not_exists(group, "-H", "--headers", help="Headers to use")
    add_argument_if_not_exists(
        group,
        "-aw",
        "--arjun-wordlist",
        help="Wordlist to use for parameter mining",
        default=DEFAULT_ARJUN_WORDLIST,
    )


if __name__ == "__main__":
    main("Arjun", ArjunModule, add_arguments)
