import argparse
import os
import sys
import shutil
import time
from typing import Optional

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from constants import DEFAULT_RATE_LIMIT, DEFAULT_MAX_FILESIZE
from utils import logger, add_argument_if_not_exists, run_command
from base_module import BaseModule


class TrufflehogModule(BaseModule):
    """A class to encapsulate Trufflehog functionality for finding secrets in files."""

    name = "Trufflehog"
    index = 40
    is_default_module = False
    description = "Runs Trufflehog for finding secrets in files."

    def __init__(self, args):
        """
        Initializes the TrufflehogModule class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)
        self.headers: Optional[str] = args["headers"]
        self.keep_downloads: Optional[bool] = args["keep_downloads"]
        self.max_download_size: Optional[str] = args["max_download_size"]

        self.output_file: str = f"{self.output_dir}/trufflehog.txt"

    def pre(self) -> bool:
        """Checks if the necessary conditions are met before running the module."""
        if not os.path.exists(self.urls_file):
            logger.critical(f"URLs file {self.urls_file} does not exist")
            return False

        if not shutil.which("trufflehog"):
            logger.critical(
                "Trufflehog is not installed or not in PATH. Please install it before running."
            )
            return False

        if not shutil.which("curl"):
            logger.critical(
                "Curl is not installed or not in PATH. Please install it before running."
            )
            return False

        return True

    def run(self):
        """Runs Trufflehog with the provided arguments."""
        # Ensure the output directory for Trufflehog exists
        trufflehog_output_dir = os.path.join(self.output_dir, "trufflehog_output")
        if not os.path.exists(trufflehog_output_dir):
            os.makedirs(trufflehog_output_dir)

        # Download files using curl
        with open(self.urls_file, "r") as f:
            for url in f.readlines():
                url = url.strip()
                if url:
                    filename = url.replace("/", "_").replace(":", "_")
                    output_path = os.path.join(trufflehog_output_dir, filename)
                    cmd_curl = [
                        "curl",
                        "-o",
                        output_path,
                        "-s",
                        "--max-filesize",
                        self.max_download_size,
                        url,
                    ]
                    if self.headers:
                        cmd_curl.extend(["-H", self.headers])
                    if self.proxy:
                        cmd_curl.extend(["-x", self.proxy])

                    curl_proc = run_command(cmd_curl, verbose=self.verbose)

                    if curl_proc:
                        return_code = curl_proc.returncode
                    else:
                        return_code = 1

                    if return_code == 63:
                        logger.warning(
                            f"File at {url} is too large to download (exceeds {self.max_download_size} bytes), only partial download may be available."
                        )
                    elif return_code != 0:
                        logger.error(
                            f"Failed to download {url}. Return code: {return_code}"
                        )
                time.sleep(1 / int(self.rate_limit))  # Rate limit the requests

        # Run Trufflehog on the downloaded files
        cmd_trufflehog = [
            "trufflehog",
            "filesystem",
            trufflehog_output_dir,
        ]
        with open(self.output_file, "w") as output_file:
            run_command(cmd_trufflehog, verbose=self.verbose, stdout=output_file)

        # Cleanup downloaded files if the keep_output flag is not set
        if not self.keep_downloads:
            logger.info("Cleaning up downloaded files...")
            for file in os.listdir(trufflehog_output_dir):
                os.remove(os.path.join(trufflehog_output_dir, file))
        else:
            logger.warning(
                "Keeping downloaded files. You can find them in the trufflehog_output directory."
            )

        with open(self.output_file, "r") as f:
            lines = f.readlines()
            if lines:
                logger.success("Trufflehog results:")
                for line in lines:
                    logger.info(line.strip())
            else:
                logger.info("No sensitive data found by Trufflehog.")

    def post(self):
        pass


def add_arguments(parser):
    group = parser.add_argument_group("trufflehog")
    add_argument_if_not_exists(
        group,
        "--keep-downloads",
        help="Do not cleanup the output directory",
        action="store_true",
    )
    add_argument_if_not_exists(group, "-H", "--headers", help="Headers to use")
    add_argument_if_not_exists(
        group,
        "--max-download-size",
        help="Maximum file size to download, e.g. 5M",
        default=DEFAULT_MAX_FILESIZE,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trufflehog Module")
    parser.add_argument("target", help="The target domain")
    parser.add_argument("-o", "--output", help="Output directory to save results")
    parser.add_argument(
        "-rl",
        "--rate-limit",
        help="Maximum requests to send per second",
        default=DEFAULT_RATE_LIMIT,
    )
    parser.add_argument("-p", "--proxy", help="HTTP proxy to use for the requests")
    add_arguments(parser)

    args = parser.parse_args()

    if not args.target:
        logger.critical("No target specified. Please provide a target domain.")
        sys.exit(1)

    trufflehog_module = TrufflehogModule(args)
    if not trufflehog_module.pre():
        logger.critical("Preconditions not met. Exiting.")
        sys.exit(1)

    try:
        trufflehog_module.run()
        trufflehog_module.post()
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)
