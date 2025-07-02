# Python 3 adaptation from https://github.com/ghostlulzhacks/RetireJs
import argparse
import os
import sys
import json
import requests
from bs4 import BeautifulSoup
import re
from packaging import version as versionLib
from typing import Dict

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import logger
from base_module import BaseModule


class RetireJSModule(BaseModule):
    """A class to encapsulate RetireJS functionality for finding vulnerabilities in JavaScript files."""

    name = "RetireJS"
    index = 55
    is_default_module = True
    description = "Runs RetireJS for vulnerability scanning of JavaScript files"

    def __init__(self, args):
        """
        Initializes the VulnscanModule class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)

        self.js_repository_path: str = f"{self.script_dir}/jsrepository.json"
        self.output_file: str = f"{self.output_dir}/retirejs.txt"

        self.update_url = "https://raw.githubusercontent.com/RetireJS/retire.js/refs/heads/master/repository/jsrepository.json"

    def has_run_before(self) -> bool:
        """Checks if the module has run before by checking the existence of the output file."""
        return os.path.exists(self.output_file)

    def pre(self) -> bool:
        """Checks preconditions before running RetireJS."""
        if not os.path.exists(self.js_repository_path):
            logger.critical(
                f"JavaScript repository file {self.js_repository_path} does not exist."
            )
            return False

        # Check for updates
        update = False

        with open(self.js_repository_path, "r") as f:
            content = f.read()
            try:
                r = requests.get(self.update_url)
                if r.status_code == 200:
                    if content != r.text:
                        update = True
                    else:
                        logger.info("JavaScript repository file is up to date.")
            except requests.RequestException as e:
                logger.error(f"Failed to fetch update URL: {e}")
                return False

        if update:
            with open(self.js_repository_path, "w") as f:
                logger.info("JavaScript repository file is outdated. Updating...")
                f.write(r.text)

        return True

    def openJSONFile(self) -> Dict:
        with open(f"{self.script_dir}/jsrepository.json", "r", encoding="utf-8") as f:
            return json.load(f)

    def retire_js(self):
        """Scans a website for vulnerable JavaScript files."""
        requests.packages.urllib3.disable_warnings()  # Disable SSL warnings
        foundvulns = []
        dataJson = self.openJSONFile()
        scanDomain = self.target

        if not self.target.startswith("http"):
            try:
                r = requests.get(f"https://{self.target}", timeout=5, verify=False)
            except requests.RequestException:
                try:
                    r = requests.get(f"http://{self.target}", timeout=5)
                except requests.RequestException:
                    logger.critical(f"Failed to connect to {self.target}.")
                    return
        else:
            r = requests.get(self.target, timeout=5)

        self.target = (
            r.request.url.split("//")[0]
            + "//"
            + r.request.url.split("//")[-1].split("/")[0]
        )
        soup = BeautifulSoup(r.content, "html.parser")
        scripts = soup.find_all("script")

        for script in scripts:
            try:
                src = script.attrs["src"]
                if "http" in src:
                    foundvulns += self.javascriptFile(src, dataJson, scanDomain)
                elif src.startswith("//"):
                    foundvulns += self.javascriptFile(
                        self.target + src.replace("//", "/"), dataJson, scanDomain
                    )
                elif not src.startswith("/"):
                    foundvulns += self.javascriptFile(
                        self.target + "/" + src, dataJson, scanDomain
                    )
                elif src.startswith("/"):
                    foundvulns += self.javascriptFile(
                        self.target + src, dataJson, scanDomain
                    )
            except KeyError:
                pass
        return foundvulns

    def javascriptFile(self, url, dataJson, scanDomain):
        """Scans a JavaScript file for vulnerabilities."""
        foundvulns = []
        vreg = r"[0-9][0-9.a-z_\\-]+"
        try:
            r = requests.get(url, timeout=25, verify=False)
        except requests.RequestException as e:
            logger.error(f"Failed to retrieve JavaScript file {url}: {e}")
            return

        for name in dataJson:
            try:
                if dataJson[name]["extractors"].get("filecontent"):
                    for regg in dataJson[name]["extractors"]["filecontent"]:
                        try:
                            reg = re.sub(r"[^\x00-\x7f]", "", regg).replace(
                                "version", vreg
                            )
                            if reg.startswith("/"):
                                reg = reg[1:]

                            match = re.search(reg, r.text)
                            if match:
                                version_match = re.search(vreg, match.group(0))
                                if version_match:
                                    version = version_match.group(0)
                                    foundvulns += self.vulnerableVersion(
                                        dataJson, name, version, url, scanDomain
                                    )
                        except re.error:
                            pass
            except Exception as e:
                logger.error(f"Error processing JavaScript file {url}: {e}")
        return foundvulns

    def vulnerableVersion(self, dataJson, name, version, url, scanDomain):
        """Checks if a JavaScript version is vulnerable."""
        foundvulns = []
        for vuln in dataJson[name]["vulnerabilities"]:
            below = vuln.get("below", "9999")
            atAbove = vuln.get("atOrAbove", "1")

            try:
                if versionLib.parse(version) < versionLib.parse(
                    below
                ) and versionLib.parse(version) >= versionLib.parse(atAbove):
                    jsonArray = {
                        "name": name,
                        "version": version,
                        "vulnerabilities": vuln["identifiers"].get(
                            "summary", "Unknown"
                        ),
                        "url": url,
                        "domain": scanDomain,
                        "CVE": " ".join(vuln["identifiers"].get("CVE", ["None"])),
                    }

                    json_string = json.dumps(jsonArray)
                    if json_string not in foundvulns:
                        # print(json_string)
                        foundvulns.append(json_string)
            except Exception as e:
                logger.error(f"Error processing vulnerability check: {e}")
        return foundvulns

    def run(self):
        """Runs the RetireJS vulnerability scanner."""
        foundvulns = self.retire_js()
        if foundvulns:
            logger.success(f"Found {len(foundvulns)} vulnerabilities with RetireJS:")
            with open(self.output_file, "w") as f:
                for vuln in foundvulns:
                    vuln = json.loads(vuln)
                    out = f"{vuln['name']} - {vuln['version']}\n{vuln['vulnerabilities']}\n{vuln['url']}\n{vuln['CVE']}\n"
                    logger.info(out)
                    f.write(out + "\n")
        else:
            logger.info("No vulnerabilities found with RetireJS.")

    def post(self):
        pass


def add_arguments(parser):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RetireJS Module")
    parser.add_argument("target", help="The target domain")
    parser.add_argument("-o", "--output", help="Output directory to save results")
    add_arguments(parser)

    args = parser.parse_args()

    if not args.target:
        logger.critical("No target specified. Please provide a target domain.")
        sys.exit(1)

    retirejs_module = RetireJSModule(args)
    if not retirejs_module.pre():
        logger.critical("Preconditions not met. Exiting.")
        sys.exit(1)

    try:
        retirejs_module.run()
        retirejs_module.post()
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)
