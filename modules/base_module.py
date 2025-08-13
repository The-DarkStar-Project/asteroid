from abc import ABC, abstractmethod
import argparse
import json
import os
from urllib.parse import urlparse
import sys
from typing import Optional

# Add parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    DEFAULT_RATE_LIMIT,
    DIRECTORIES_FILE,
    OUTPUT_DIR,
    URLS_FILE,
    JSON_FILE,
)


class Vuln:
    """Class representing a vulnerability."""

    def __init__(
        self,
        title,
        affected_item,
        confidence,
        host,
        tool="Asteroid",
        cve_number="",
        summary="",
        impact="",
        solution="",
        poc="",
        references="",
        epss=None,
        cvss=None,
        severity="unknown",
        cwe="",
        capec="",
    ):
        self.title = title
        self.affected_item = affected_item
        self.tool = tool
        self.confidence = confidence
        self.severity = severity
        self.host = host

        self.cve = cve_number
        self.summary = summary
        self.impact = impact
        self.solution = solution
        self.poc = poc
        self.references = references
        self.epss = epss
        self.cvss = cvss
        self.cwe = cwe
        self.capec = capec

        if self.cvss and self.severity == "unknown":
            self.severity = self.get_severity_from_cvss()

    def to_dict(self):
        """Convert the vulnerability to a dictionary."""
        return {
            "title": self.title,
            "affected_item": self.affected_item,
            "tool": self.tool,
            "confidence": self.confidence,
            "severity": self.severity,
            "host": self.host,
            "cve_number": getattr(self, "cve", None),
            "summary": self.summary,
            "impact": self.impact,
            "solution": self.solution,
            "poc": self.poc,
            "references": self.references,
            "epss": self.epss,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "capec": self.capec,
        }

    def get_severity_from_cvss(self):
        """Get severity based on CVSS score."""
        if self.cvss is None:
            return "unknown"
        if self.cvss >= 9.0:
            return "critical"
        elif self.cvss >= 7.0:
            return "high"
        elif self.cvss >= 4.0:
            return "medium"
        elif self.cvss >= 0.1:
            return "low"
        else:
            return "info"


class BaseModule(ABC):
    """Abstract base class for all modules."""

    name = "BaseModule"
    index = 99
    is_default_module = True
    description = "Example description"

    def __init__(self, args):
        """
        Initializes the base module with common parameters.

        :param args: The command line arguments passed to the script.
        """
        self.target = args["target"]

        if not str(self.target).startswith("http") and not str(self.target).startswith(
            "https://"
        ):
            self.target = "http://" + str(self.target)  # TODO: check if http or https

        self.output_dir = args["output_dir"]
        if not self.output_dir:
            self.output_dir = OUTPUT_DIR

        self.target_name = urlparse(self.target).netloc

        if self.target_name:
            self.base_output_dir = os.path.join(self.output_dir, self.target_name)
        else:
            self.base_output_dir = self.output_dir

        named_dir = str(self.index) + "-" + self.name.lower()
        self.output_dir = os.path.join(self.base_output_dir, named_dir)

        self.verbose = args["verbose"]

        self.script_dir = os.path.dirname(
            sys.modules[self.__class__.__module__].__file__
        )
        self.urls_file = os.path.join(self.base_output_dir, URLS_FILE)
        self.directories_file = os.path.join(self.base_output_dir, DIRECTORIES_FILE)
        self.json_file = os.path.join(self.base_output_dir, JSON_FILE)

        self.rate_limit: Optional[str] = args["rate_limit"]
        self.proxy: Optional[str] = args["proxy"]

        # Ensure the output directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def has_run_before(self) -> bool:
        """Checks if the module has run before by checking the existence of the output file."""
        return os.path.exists(self.output_file)

    @abstractmethod
    def pre(self) -> bool:
        """Checks preconditions before running the module."""
        return True

    @abstractmethod
    def run(self):
        """Runs the module's main functionality."""
        pass

    @abstractmethod
    def post(self):
        """Performs post-processing after the module has run."""
        pass

    def add_vulnerability(self, vuln: Vuln):
        """Adds a vulnerability to the JSON file."""
        if not os.path.exists(self.json_file):
            with open(self.json_file, "w") as f:
                json.dump([], f, indent=4)

        with open(self.json_file, "r") as f:
            vulns = json.load(f)

        # Check if the vulnerability already exists
        for existing_vuln in vulns:
            if (
                existing_vuln.get("title") == vuln.title
                and existing_vuln.get("affected_item") == vuln.affected_item
                and existing_vuln.get("host") == vuln.host
            ):
                return
        vulns.append(vuln.to_dict())

        with open(self.json_file, "w") as f:
            json.dump(vulns, f, indent=4)


def build_parser(parser, add_arguments):
    """
    Adds common arguments to the parser for all modules.

    :param parser: The argument parser to which arguments will be added.
    """
    parser.add_argument("target", help="The target domain")
    parser.add_argument(
        "-o", "--output", help="Output directory to save results", default=OUTPUT_DIR
    )
    parser.add_argument(
        "-rl",
        "--rate-limit",
        help="Maximum requests to send per second",
        default=DEFAULT_RATE_LIMIT,
    )
    parser.add_argument("-p", "--proxy", help="HTTP proxy to use for the requests")
    parser.add_argument(
        "-v", "--verbose", help="Enable verbose output", action="store_true"
    )
    add_arguments(parser)

    return parser


def main(name, module_class, add_arguments):
    """Main function to run module as a script."""
    parser = build_parser(
        argparse.ArgumentParser(description=f"{name} Module"), add_arguments
    )
    args = parser.parse_args()

    if not args.target:
        print("No target specified. Please provide a target domain.")
        sys.exit(1)

    args = vars(args)
    args["output_dir"] = args["output"]

    module = module_class(args)

    if not module.pre():
        print("Preconditions not met. Exiting.")
        sys.exit(1)

    try:
        module.run()
        module.post()
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
