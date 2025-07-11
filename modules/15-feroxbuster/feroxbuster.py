import subprocess
import os
import sys
import shutil
from typing import List, Optional

# Add the grandparent directory to sys.path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from config import (
    DEFAULT_DONT_SCAN_REGEX,
    DEFAULT_TIME_LIMIT,
    DEFAULT_FEROXBUSTER_WORDLIST,
    DEFAULT_FEROXBUSTER_DEPTH,
    DEFAULT_FEROXBUSTER_FILTER_STATUS_CODES,
    DEFAULT_FEROXBUSTER_EXTENSIONS,
)
from modules.utils import (
    logger,
    add_argument_if_not_exists,
    merge_list_with_file,
    run_command,
)
from modules.base_module import BaseModule, main


class FeroxbusterModule(BaseModule):
    """A class to encapsulate Feroxbuster functionality to bruteforce paths."""

    name = "Feroxbuster"
    index = 15
    is_default_module = True
    description = "Runs Feroxbuster for directory bruteforcing"

    def __init__(self, args):
        """
        Initializes the Feroxbuster class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)
        self.wordlist: Optional[str] = args.get(
            "wordlist", DEFAULT_FEROXBUSTER_WORDLIST
        )
        self.depth: Optional[str] = args.get("depth", DEFAULT_FEROXBUSTER_DEPTH)
        self.C: Optional[str] = args.get("C", DEFAULT_FEROXBUSTER_FILTER_STATUS_CODES)
        self.extensions: Optional[str] = args.get(
            "extensions", DEFAULT_FEROXBUSTER_EXTENSIONS
        )
        self.time_limit: Optional[str] = args.get("time_limit", DEFAULT_TIME_LIMIT)
        self.headers: Optional[str] = args.get("headers")
        self.dont_scan: Optional[str] = args.get("dont_scan", DEFAULT_DONT_SCAN_REGEX)

        self.output_file: str = f"{self.output_dir}/feroxbuster.txt"

    def pre(self) -> bool:
        """Checks if Feroxbuster is installed and prepares the environment for Feroxbuster."""
        if not shutil.which("feroxbuster"):
            logger.critical(
                "Feroxbuster is not installed or not in PATH. Please install it before running."
            )
            return False

        if os.path.exists(self.output_file):
            logger.warning(
                f"Output file {self.output_file} already exists. We will overwrite it."
            )
            os.remove(self.output_file)

        if not os.path.exists(self.urls_file):
            logger.warning(
                f"URLs file {self.urls_file} does not exist, falling back to target_name"
            )
            self._create_urls_file()

        directories = self._generate_directories()
        self._write_directories_to_file(directories)

        return True

    def _create_urls_file(self):
        """Creates the URLs file with the target as the default entry."""
        os.makedirs(os.path.dirname(self.urls_file), exist_ok=True)
        with open(self.urls_file, "w") as f:
            f.write(self.target)
        logger.info(f"Created URLs file {self.urls_file} with target {self.target}")

    def _generate_directories(self) -> List[str]:
        """Generates a list of directories from the URLs file."""
        with open(self.urls_file, "r") as f:
            found_urls = [url.strip() for url in f.readlines()]

        stripped_urls = [url.split("?")[0] for url in found_urls]
        target_with_slash = (
            self.target if self.target.endswith("/") else self.target + "/"
        )
        directories = set([target_with_slash]) | set(
            ["/".join(url.split("/")[:-1]) + "/" for url in stripped_urls]
        )

        # Add root directories
        directories_with_root_dirs = set()
        for directory in directories:
            subdirs = directory.split("/")
            root_dirs = [
                "/".join(subdirs[: i + 1]) + "/"
                for i in range(len(subdirs))
                if subdirs[i]
            ]
            directories_with_root_dirs.update(root_dirs)

        return sorted([dir for dir in directories_with_root_dirs if self.target in dir])

    def _write_directories_to_file(self, directories):
        """Writes the generated directories to the directories file."""
        with open(self.directories_file, "w") as f:
            f.write("\n".join(directories))

    def run(self):
        """Runs Feroxbuster with the provided arguments."""
        # Command to read directories
        cmd_cat = ["cat", self.directories_file]

        # Command to run Feroxbuster
        cmd_feroxbuster = [
            "feroxbuster",
            "--stdin",
            "--silent",
            "-w",
            self.wordlist,
            "--collect-words",
            "--collect-backups",
            "--collect-extensions",
            "-o",
            self.output_file,
            "-C",
            self.C,
            "-d",
            self.depth,
            "--no-state",
            "--time-limit",
            self.time_limit,
            "--rate-limit",
            self.rate_limit,
            "-x",
            self.extensions,
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
            run_command(
                cmd_feroxbuster,
                stdin=cat_proc.stdout,
                verbose=self.verbose,
            )
            cat_proc.stdout.close()
            cat_proc.wait()
        except Exception as e:
            logger.critical(f"Feroxbuster execution failed: {e}")
            raise

    def post(self):
        """Processes the Feroxbuster output and merges results."""
        try:
            with open(self.output_file, "r") as f:
                feroxbuster_paths = [
                    path.strip()
                    for path in f
                    if self.target in path and "MSG" not in path
                ]

            if feroxbuster_paths:
                logger.success(f"Found {len(feroxbuster_paths)} URLs with Feroxbuster:")
                for path in feroxbuster_paths:
                    logger.info(path)
            else:
                logger.info("No URLs found with Feroxbuster.")

            merge_list_with_file(feroxbuster_paths, self.urls_file, self.urls_file)
            logger.info(f"Feroxbuster results merged into {self.urls_file}")
        except FileNotFoundError:
            logger.error(f"Output file {self.output_file} not found.")
            raise
        except Exception as e:
            logger.error(f"Error processing Feroxbuster output: {e}")
            raise


def add_arguments(parser):
    """Adds Feroxbuster-specific arguments to the main argument parser."""
    group = parser.add_argument_group("feroxbuster")
    add_argument_if_not_exists(
        group,
        "-w",
        "--wordlist",
        help="Wordlist to use for feroxbuster",
        default=DEFAULT_FEROXBUSTER_WORDLIST,
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
        "-d",
        "--depth",
        help="Recursive depth for feroxbuster",
        default=DEFAULT_FEROXBUSTER_DEPTH,
    )
    add_argument_if_not_exists(
        group,
        "-C",
        help="Filter status codes for feroxbuster",
        default=DEFAULT_FEROXBUSTER_FILTER_STATUS_CODES,
    )
    add_argument_if_not_exists(
        group,
        "-x",
        "--extensions",
        help="Extensions to use for feroxbuster, reads values (newline-separated) from file if input starts with an @ (ex: @ext.txt)",
        default=DEFAULT_FEROXBUSTER_EXTENSIONS,
    )
    add_argument_if_not_exists(group, "-H", "--headers", help="Headers to use")
    add_argument_if_not_exists(
        group,
        "--dont-scan",
        help="Do not scan URLs matching this regex",
        default=DEFAULT_DONT_SCAN_REGEX,
    )


if __name__ == "__main__":
    main("Feroxbuster", FeroxbusterModule, add_arguments)
