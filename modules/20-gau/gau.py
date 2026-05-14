import os
import sys
import shutil
from urllib.parse import urlparse

# Add the grandparent directory to sys.path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from modules.utils import (
    logger,
    merge_files,
    run_command,
    filter_false_positives,
)
from modules.base_module import BaseModule, main


def _same_target_host(url: str, target: str) -> bool:
    """Keep passive URL output scoped to the requested target host."""
    url_host = urlparse(url).hostname or ""
    target_host = urlparse(target).hostname or target
    return url_host == target_host or url_host.endswith(f".{target_host}")


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

        self.output_file: str = os.path.join(self.output_dir, "gau.txt")
        self.output_filtered_file: str = os.path.join(
            self.output_dir, "gau-filtered.txt"
        )

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
        filter_false_positives(
            self.output_file, self.output_filtered_file, rate_limit=self.rate_limit
        )

        # Print filtered results
        with open(self.output_filtered_file, "r") as f:
            filtered_urls = [
                url.strip()
                for url in f.readlines()
                if url.strip() and _same_target_host(url.strip(), self.target)
            ]
        with open(self.output_filtered_file, "w") as f:
            f.write("\n".join(filtered_urls))
        if filtered_urls:
            logger.success(f"Found {len(filtered_urls)} in-scope URLs with Gau:")
            for url in filtered_urls[:20]:
                logger.info(url)
            if len(filtered_urls) > 20:
                logger.info(f"... {len(filtered_urls) - 20} more URLs omitted from live log")
        else:
            logger.info("No in-scope URLs found with Gau.")

        # Merge the filtered results with the URLs file
        merge_files(self.output_filtered_file, self.urls_file, self.urls_file)


def add_arguments(parser):
    """Adds Gau-specific arguments to the main argument parser."""
    pass


if __name__ == "__main__":
    main("Gau", GauModule, add_arguments)
