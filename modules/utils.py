import subprocess
import os
import sys
import random
import string

# Add current directory to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from logger_config import get_logger

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
    """Merges two files into one, removing duplicates with uro."""
    lines = set()

    # Read lines from file1 if it exists
    if os.path.exists(file1):
        with open(file1, "r") as f1:
            lines.update(f1.readlines())

    # Read lines from file2 if it exists
    if os.path.exists(file2):
        with open(file2, "r") as f2:
            lines.update(f2.readlines())

    # Write the merged lines to the output file using uro for deduplication
    if os.path.exists(output_file):
        os.remove(output_file)

    process = subprocess.Popen(
        ["uro", "-o", output_file], stdin=subprocess.PIPE, text=True
    )
    process.communicate(input="\n".join(sorted(lines)))


def merge_list_with_file(list_to_merge, file_to_merge, output_file):
    """Merges a list with a file, removing duplicates with uro."""
    lines = set(list_to_merge)

    # Read lines from the file if it exists
    if os.path.exists(file_to_merge):
        with open(file_to_merge, "r") as f:
            lines.update(f.readlines())
    else:
        logger.debug(
            f"File {file_to_merge} does not exist. Proceeding with the list only."
        )

    # Use uro to remove duplicates and write to the output file
    if os.path.exists(output_file):
        os.remove(output_file)

    process = subprocess.Popen(
        ["uro", "-o", output_file], stdin=subprocess.PIPE, text=True
    )
    process.communicate(input="\n".join(sorted(lines)))


def filter_false_positives(input_file, output_file, rate_limit=150):
    """Filters out duplicates and false positives from the input file using uro and httpx."""
    if not os.path.exists(input_file):
        logger.critical(f"Input file {input_file} does not exist.")
        return

    if input_file == output_file:
        logger.critical("Input and output files cannot be the same.")
        return

    logger.info(
        "Filtering out duplicates and false positives with uro and httpx...",
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
        # Run `uro` and pipe its output to `httpx`
        uro_cmd = ["uro", "-i", input_file]
        uro_proc = subprocess.Popen(
            uro_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        httpx_output = subprocess.run(
            httpx_cmd, stdin=uro_proc.stdout, capture_output=True, text=True
        )
        # Pipe output into jq
        # jq_output = subprocess.run(
        #     ["jq", ".final_url"],
        #     input=httpx_proc.stdout,
        #     capture_output=True,
        # )
        uro_proc.stdout.close()  # Allow `uro_proc` to receive a SIGPIPE if `httpx_proc` exits
        uro_proc.wait()
        # filtered_urls = "\n".join([url[1:-1] for url in jq_output.stdout.decode().strip().splitlines()])
        # with open(output_file, "w") as f:
        #     f.write(filtered_urls)
        filtered_urls = httpx_output.stdout.strip().splitlines()
        formatted_urls = []
        for url in filtered_urls:
            if " " in url:
                # Only take the second URL (the redirected URL)
                second_url = url.split(" ")[1]
                stripped_second_url = second_url[6:-5]
                formatted_urls.append(stripped_second_url)
            else:
                formatted_urls.append(url)

        with open(output_file, "w") as f:
            f.write("\n".join(formatted_urls))

    except Exception as e:
        logger.critical(f"Error running uro and httpx: {e}")
        raise


def run_command(command, verbose=False, capture_output=False, **kwargs):
    """Runs a shell command and returns the output."""
    logger.debug(f"Running command: {' '.join(command)}")
    process = None
    try:
        if verbose:
            process = subprocess.run(
                command, **kwargs, check=True, capture_output=capture_output, text=True
            )
        elif capture_output:
            process = subprocess.run(
                command, **kwargs, check=True, capture_output=capture_output, text=True
            )
        else:
            process = subprocess.run(
                command,
                **kwargs,
                check=True,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except subprocess.CalledProcessError as e:
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
