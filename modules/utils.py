import subprocess
import os
import sys
import random
import string
from urllib.parse import parse_qs, urlparse

# Add parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.logger_config import get_logger

logger = get_logger("main")

static_extensions = [
    ".css",
    ".js",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".txt",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".mp4",
    ".mp3",
    ".wav",
    ".ogg",
    ".xml",
    ".conf",
    ".bak",
    ".log",
    ".sql",
    ".db",
    ".sqlite",
    ".md",
    ".json",
    ".csv",
    ".xls",
    ".xlsx",
    ".doc",
    ".docx",
    ".ppt",
    ".pptx",
    ".exe",
    ".apk",
    ".bin",
    ".dll",
    ".so",
    ".dmg",
    ".iso",
]


def add_argument_if_not_exists(parser, *args, **kwargs):
    """Adds an argument to the parser only if it doesn't already exist."""
    for arg in args:
        if arg in parser._option_string_actions:
            return  # Argument already exists, skip adding
    parser.add_argument(*args, **kwargs)


def merge_files(file1, file2, output_file):
    """Merges two files into one, removing duplicates."""
    logger.debug(
        f"Merging files {file1} and {file2} into {output_file}, removing duplicates."
    )
    lines = set()

    # Read lines from file1 if it exists
    if os.path.exists(file1):
        with open(file1, "r") as f1:
            lines.update([line.strip() for line in f1])

    # Read lines from file2 if it exists
    if os.path.exists(file2):
        with open(file2, "r") as f2:
            lines.update([line.strip() for line in f2])

    # Write the merged lines to the output file
    if os.path.exists(output_file):
        os.remove(output_file)

    with open(output_file, "w") as f_out:
        f_out.write("\n".join(deduplicate_urls(list(filter(lambda x: bool(x.strip()), lines)))))


def merge_list_with_file(list_to_merge, file_to_merge, output_file):
    """Merges a list with a file, removing duplicates."""
    logger.debug(
        f"Merging list with file {file_to_merge} into {output_file}, removing duplicates."
    )
    lines = set(list_to_merge)

    # Read lines from the file if it exists
    if os.path.exists(file_to_merge):
        with open(file_to_merge, "r") as f:
            lines.update([line.strip() for line in f])
    else:
        logger.debug(
            f"File {file_to_merge} does not exist. Proceeding with the list only."
        )

    # Write the merged lines to the output file
    if os.path.exists(output_file):
        os.remove(output_file)

    with open(output_file, "w") as f_out:
        f_out.write("\n".join(deduplicate_urls(list(filter(lambda x: bool(x.strip()), lines)))))


def filter_false_positives(input_file, output_file, rate_limit=150):
    """Filters out duplicates and false positives from the input file using httpx."""
    if not os.path.exists(input_file):
        logger.critical(f"Input file {input_file} does not exist.")
        return

    if input_file == output_file:
        logger.critical("Input and output files cannot be the same.")
        return

    logger.info(
        "Filtering out duplicates and false positives with httpx...",
        extra={"output_to_file": False},
    )

    # Construct the command for filtering with httpx
    httpx_cmd = [
        "httpx",
        "-silent",
        "-fc",
        "404,403",
        # "-fd", # Filtering duplicates did not work in testing
        "-fhr",
        "-rl",
        str(rate_limit),
        # "-o",
        # output_file,
    ]

    try:        
        with open(input_file, "r") as f:
            urls = list(filter(lambda x: bool(x.strip()), [url.strip() for url in f.readlines()]))
        unique_urls = deduplicate_urls(urls)

        httpx_proc = subprocess.run(
            httpx_cmd, input="\n".join(unique_urls), capture_output=True, text=True
        )
        filtered_urls = httpx_proc.stdout.strip().splitlines()
        formatted_urls = []
        for url in filtered_urls:
            if " " in url:
                # Only take the second URL (the redirected URL)
                second_url = url.split(" ")[1]
                stripped_second_url = second_url[6:-5]
                formatted_urls.append(stripped_second_url)
            else:
                formatted_urls.append(url)
        
        formatted_urls = sorted(formatted_urls)

        with open(output_file, "w") as f:
            f.write("\n".join(formatted_urls))

    except Exception as e:
        logger.critical(f"Error running httpx: {e}")
        raise


def run_command(
    command,
    verbose=False,
    capture_output=False,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    **kwargs,
):
    """Runs a shell command and returns the output."""
    logger.debug(f"Running command: {' '.join(command)}")
    process = None
    try:
        if capture_output:
            process = subprocess.run(
                command, **kwargs, check=True, capture_output=capture_output, text=True
            )
        elif verbose:
            # output to stdout and stderr
            if stdout == subprocess.DEVNULL:
                stdout = sys.stdout
            if stderr == subprocess.DEVNULL:
                stderr = sys.stderr

        process = subprocess.run(
            command,
            **kwargs,
            check=True,
            text=True,
            stdout=stdout,
            stderr=stderr,
        )
    except subprocess.CalledProcessError as e:
        # Add an exception for Feroxbuster as it returns an exit code of 1 when combining with --time-limit
        if "feroxbuster" in command[0]:
            return
        logger.error(f"Command failed with error: {e}")
        return e
    except Exception as e:
        logger.error(f"Command failed with error: {e}")
    if capture_output:
        return process.stdout, process.stderr
    else:
        return process


def match_urls_non_static(input_file, output_file):
    """Matches non-static URLs from the input file and saves them to the output file."""
    if not os.path.exists(input_file):
        logger.error(f"Input file {input_file} does not exist.")
        return

    with open(input_file, "r") as f:
        urls = f.readlines()

    non_static_urls = {
        url.strip().split("?")[0]  # Remove query parameters
        for url in urls
        if not any(url.strip().split("?")[0].endswith(ext) for ext in static_extensions)
    }
    non_static_urls = sorted(list(non_static_urls))

    with open(output_file, "w") as f:
        f.writelines("\n".join(non_static_urls))

    logger.info(f"Found non-static URLs saved to {output_file}")


def match_urls_with_params(input_file, output_file):
    """Matches URLs with parameters from the input file and saves them to the output file."""
    if not os.path.exists(input_file):
        logger.error(f"Input file {input_file} does not exist.")
        return

    with open(input_file, "r") as f:
        urls = f.readlines()

    # Filter out static URLs and keep only those with parameters
    non_static_urls = [
        url.strip()
        for url in urls
        if not any(url.strip().split("?")[0].endswith(ext) for ext in static_extensions)
    ]
    urls_with_params = [
        url.strip() for url in non_static_urls if "?" in url or "=" in url
    ]

    with open(output_file, "w") as f:
        f.writelines("\n".join(urls_with_params))

    logger.info(f"Found URLs with parameters saved to {output_file}")


def random_string(length=10):
    """Generates a random string of fixed length consisting of letters"""
    return "".join(random.choice(string.ascii_letters) for _ in range(length))

def deduplicate_urls(urls: list[str]) -> list[str]:
    """
    Author: @markfijneman, see https://github.com/markfijneman/scanner/blob/6bdd72f5a243c9f78868d97784b43730f16f5270/utils/utils.py#L112-L144

    Create a list of unique URLs, keeping only one of each URL with the same
    query parameter combinations.

    :param urls: List of URLs

    :return: List of deduplicated URLs
    """
    # Keep track of which query param combinations have been encountered already for specific base urls
    encountered_query_sets = {}
    unique_urls = []

    # Extract parameters from URLs.
    for url in urls:
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        # Create set of query param keys
        query_params = frozenset(parse_qs(parsed_url.query).keys())

        # Check if query param set has been encountered before for this URL
        if (
            base_url in encountered_query_sets
            and query_params in encountered_query_sets[base_url]
        ):
            continue

        encountered_query_sets.setdefault(base_url, []).append(query_params)

        unique_urls.append(url)

    return sorted(unique_urls)