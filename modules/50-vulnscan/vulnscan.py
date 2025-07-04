import json
import os
import sys
import shutil
import requests
from typing import Optional

# Add the grandparent directory to sys.path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from config import VULNSCAN_OUTPUT_SIZE, SEARCH_VULNS_API_KEY
from modules.utils import logger, add_argument_if_not_exists, run_command
from modules.base_module import BaseModule, main


class SearchVulnsAPI:
    """A class to interact with the search_vulns API."""

    def __init__(self, api_key: str, proxy: Optional[str] = None):
        """
        Initializes the SearchVulnsAPI class with the given API key.

        :param api_key: The API key for search_vulns.
        """
        self.url = "https://search-vulns.com/api/"
        self.api_key = api_key

        if proxy:
            self.proxies = {
                "http": proxy,
                "https": proxy,
            }
            self.verify = False
            # disable urllib ssl warnings
            requests.packages.urllib3.disable_warnings(
                requests.packages.urllib3.exceptions.InsecureRequestWarning
            )
        else:
            self.proxies = None
            self.verify = True

    def is_updating(self) -> bool:
        """
        Checks if the search_vulns database is currently being updated.

        :return: True if the database is updating, False otherwise.
        """
        path = "is-updating"
        r = requests.get(f"{self.url}{path}", proxies=self.proxies, verify=self.verify)
        status = r.json().get("status")
        if status != "ok":
            logger.critical(
                f"search_vulns API is currently unavailable (status: {status}). Please try again later."
            )
            return True
        return False

    def check_key_status(self) -> bool:
        """
        Checks if the API key is valid.

        :return: True if the API key is valid, False otherwise.
        """
        path = "check-key-status"
        body = {"key": "673803cb-21b5-42da-90aa-060704a4ed04"}
        r = requests.post(
            f"{self.url}{path}",
            json=body,
            proxies=self.proxies,
            verify=self.verify,
        )
        status = r.json().get("status")
        if status == "valid":
            return True
        logger.critical(
            "API key is invalid or expired. Please generate a new API key at: https://search-vulns.com/api/setup"
        )
        return False

    def cpe_suggestions(self, query: str):
        """
        Gets CPE suggestions for a given query.

        :param query: The query string to search for CPEs.
        :return: A list of CPE suggestions.
        """
        path = "cpe-suggestions"
        r = requests.get(
            f"{self.url}{path}?query={requests.utils.quote(query)}",
            headers={"Api-Key": self.api_key},
            proxies=self.proxies,
            verify=self.verify,
        )
        return r.json()

    def cpe_suggestion(self, query: str):
        """
        Gets a single CPE suggestion for a given query.

        :param query: The query string to search for a CPE.
        :return: A single CPE suggestion.
        """
        res = self.cpe_suggestions(query)
        return res[0][0]

    def search_vulns(
        self,
        query: str,
        is_good_cpe: bool = False,
        include_single_version_vulns: bool = True,
    ):
        """
        Searches for vulnerabilities based on a query.

        :param query: The query string to search for vulnerabilities.
        :param is_good_cpe: If True, the query is treated as a CPE.
        :return: A list of vulnerabilities found.
        """
        path = "search-vulns"
        r = requests.get(
            f"{self.url}{path}?query={requests.utils.quote(query)}&is-good-cpe={str(is_good_cpe).lower()}&include-single-version-vulns={str(include_single_version_vulns).lower()}",
            headers={"Api-Key": self.api_key},
            proxies=self.proxies,
            verify=self.verify,
        )
        return r.json().get(query).get("vulns", {})


class VulnscanModule(BaseModule):
    """A class to encapsulate Vulnscan functionality for finding version-based vulnerabilities."""

    name = "Vulnscan"
    index = 50
    is_default_module = True
    description = "Runs Wappalyzer and search_vulns for vulnerability scanning"

    def __init__(self, args):
        """
        Initializes the VulnscanModule class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)

        self.search_vulns_api = SearchVulnsAPI(SEARCH_VULNS_API_KEY, proxy=self.proxy)

        self.size: Optional[str] = args["size"]

        self.output_file: str = f"{self.output_dir}/vulnscan.txt"
        self.wappalyzer_output_file: str = f"{self.output_dir}/wappalyzer.json"

    def pre(self) -> bool:
        """Checks preconditions before running Vulnscan."""
        if not shutil.which("wappalyzer"):
            logger.critical(
                "Wappalyzer is not installed or not in PATH. Please install it before running."
            )
            return False

        if (
            self.search_vulns_api.is_updating()
            or not self.search_vulns_api.check_key_status()
        ):
            return False

        return True

    def run(self):
        """Runs Wappalyzer and search_vulns to find vulnerabilities."""
        # Construct the Wappalyzer command as a list
        cmd_wappalyzer = [
            "wappalyzer",
            "-i",
            self.target,
            "-oJ",
            self.wappalyzer_output_file,
        ]
        logger.info("Running Wappalyzer...")
        run_command(cmd_wappalyzer, verbose=self.verbose)

        # Load Wappalyzer results
        wappalyzer_results = {}
        with open(self.wappalyzer_output_file, "r") as f:
            wappalyzer_results = json.load(f)

        # Process each technology and run search_vulns
        out = ""
        for tech, data in list(wappalyzer_results.values())[0].items():
            version = data.get("version") if data.get("version") else "N/A"
            logger.info(f"{tech} - version {version}")

            if not data.get("version") and tech not in [
                "Adobe Flash"
            ]:  # Add edge case for Adobe Flash as it is EOL
                logger.info(f"No version found for {tech}, skipping...")
                logger.info("")
                continue

            logger.debug("Looking up CPE...")
            cpe = self.search_vulns_api.cpe_suggestion(
                tech + " " + data.get("version", "")
            )

            if cpe:
                vulns = self.search_vulns_api.search_vulns(cpe)
            else:
                vulns = self.search_vulns_api.search_vulns(
                    f"{tech} {data.get('version', '')}"
                )

            if vulns:
                found_vulns = True
                out += f"{len(vulns)} vulnerabilities found for {tech}, showing top {self.size}:\n"
                logger.success(
                    f"{len(vulns)} vulnerabilities found for {tech}, showing top {self.size}:"
                )
                vulns_sorted = sorted(
                    vulns.values(),
                    key=lambda x: x.get("cvss", 0),
                    reverse=True,
                )
                for vuln in vulns_sorted[: int(self.size)]:
                    out += f"{vuln.get('id')} - CVSS: {vuln.get('cvss')} - {vuln.get('published')} - {vuln.get('description')}\n"
                    logger.info(
                        f"{vuln.get('id')} - CVSS: {vuln.get('cvss')} - {vuln.get('published')} - {vuln.get('description')}"
                    )

            if not found_vulns:
                out += f"No vulnerabilities found for {tech}.\n"
                logger.info(f"No vulnerabilities found for {tech}.")

            logger.info("")
            out += "\n"

        if out:
            with open(self.output_file, "w") as f:
                f.write(out)
                logger.info(f"Results saved to {self.output_file}")
        else:
            logger.info("No vulnerabilities found.")

    def post(self):
        pass


def add_arguments(parser):
    """Adds Vulnscan-specific arguments to the main argument parser."""
    group = parser.add_argument_group("vulnscan")
    add_argument_if_not_exists(
        group,
        "-s",
        "--size",
        help="Max number of outputs by search_vulns",
        default=VULNSCAN_OUTPUT_SIZE,
    )


if __name__ == "__main__":
    main("Vulnscan", VulnscanModule, add_arguments)
