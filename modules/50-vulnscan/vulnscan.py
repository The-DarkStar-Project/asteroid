import argparse
import json
import os
import sys
import shutil
from typing import Optional

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import logger, add_argument_if_not_exists, run_command
from base_module import BaseModule


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
        self.size: Optional[str] = args["size"]
        self.update = args["update"]

        self.output_file: str = f"{self.output_dir}/vulnscan.txt"
        self.wappalyzer_output_file: str = f"{self.output_dir}/wappalyzer.json"

    def has_run_before(self) -> bool:
        """Checks if the module has run before by checking the existence of the output file."""
        return os.path.exists(self.output_file)

    def pre(self) -> bool:
        """Checks preconditions before running Vulnscan."""
        if not shutil.which("wappalyzer"):
            logger.critical(
                "Wappalyzer is not installed or not in PATH. Please install it before running."
            )
            return False

        if not os.path.exists(f"{self.script_dir}/search_vulns/search_vulns.py"):
            logger.critical(
                "search_vulns script is missing. Please ensure it is available."
            )
            return False

        if not os.path.exists(f"{self.script_dir}/technologies"):
            logger.critical(
                "Technologies directory is missing. Please ensure it is available."
            )
            return False

        # Update search_vulns database
        if self.update:
            cmd_search_vulns = [
                "python3",
                f"{self.script_dir}/search_vulns/search_vulns.py",
                "-u",
            ]
            logger.info("Updating search_vulns database...")
            run_command(cmd_search_vulns, verbose=self.verbose)

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
            cpe = ""
            first_letter = tech[0].lower() if tech[0].isalpha() else "_"
            with open(f"{self.script_dir}/technologies/{first_letter}.json", "r") as f:
                technologies = json.loads(f.read())
                if tech in technologies:
                    if "cpe" in technologies[tech]:
                        cpe = technologies[tech]["cpe"]
                        cpe_split = cpe.split(":")
                        cpe_split[5] = (
                            data.get("version") if data.get("version") else "*"
                        )
                        cpe = ":".join(cpe_split)
                        logger.debug(f"Found CPE: {cpe}")

            if cpe:
                cmd_search_vulns = [
                    "python3",
                    f"{self.script_dir}/search_vulns/search_vulns.py",
                    "-q",
                    cpe,
                    "--use-created-cpes",
                    "-f",
                    "json",
                ]
            else:
                cmd_search_vulns = [
                    "python3",
                    f"{self.script_dir}/search_vulns/search_vulns.py",
                    "-q",
                    f"{tech} {data.get('version', '')}",
                    "--use-created-cpes",
                    "-f",
                    "json",
                ]

            stdout, _ = run_command(cmd_search_vulns, capture_output=True)
            found_vulns = False
            if stdout:
                try:
                    data = list(json.loads(stdout).values())[0]
                    if isinstance(data, dict) and "vulns" in data:
                        vulns = data["vulns"]
                    else:
                        vulns = None
                except json.JSONDecodeError:
                    logger.error("Failed to decode JSON from stdout.")
                except Exception as e:
                    logger.error(f"An error occurred: {e}")

                if vulns:
                    found_vulns = True
                    out += f"{len(vulns)} vulnerabilities found for {tech}, showing top {self.size}:\n"
                    logger.success(
                        f"{len(vulns)} vulnerabilities found for {tech}, showing top {self.size}:"
                    )
                    for vuln in list(vulns.values())[: int(self.size)]:
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
    """Adds Gau-specific arguments to the main argument parser."""
    group = parser.add_argument_group("vulnscan")
    add_argument_if_not_exists(
        group, "-s", "--size", help="Max number of outputs by search_vulns", default=5
    )
    add_argument_if_not_exists(
        group,
        "-up",
        "--update",
        help="Update search_vulns CVE database",
        action="store_true",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnscan Module")
    parser.add_argument("target", help="The target domain")
    parser.add_argument("-o", "--output", help="Output directory to save results")
    add_arguments(parser)

    args = parser.parse_args()

    if not args.target:
        logger.critical("No target specified. Please provide a target domain.")
        sys.exit(1)

    vulnscan_module = VulnscanModule(args)
    if not vulnscan_module.pre():
        logger.critical("Preconditions not met. Exiting.")
        sys.exit(1)

    try:
        vulnscan_module.run()
        vulnscan_module.post()
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)
