import argparse
import subprocess
import os
from urllib.parse import urlparse
import sys
import json
import base64
import requests
from typing import Optional

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from constants import DEFAULT_RATE_LIMIT
from utils import (
    logger,
    add_argument_if_not_exists,
    run_command,
    merge_list_with_file,
    match_urls_with_params,
)
from base_module import BaseModule


class NucleiModule(BaseModule):
    """A class to encapsulate Nuclei functionality for DAST vulnerability scanning."""

    name = "Nuclei"
    index = 60
    is_default_module = True
    description = "Runs Nuclei DAST for vulnerability scanning"

    def __init__(self, args):
        """
        Initializes the NucleiModule class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)
        self.rate_limit: Optional[str] = args.rate_limit
        self.headers: Optional[str] = args.headers
        self.proxy: Optional[str] = args.proxy

        self.run_on_forms: bool = True

        self.katana_output_file: str = f"{self.output}/katana.jsonl"
        self.forms_output_file: str = f"{self.output}/forms.xml"

        self.urls_with_params: str = f"{self.output}/urls-with-params.txt"

        self.output_file: str = f"{self.output}/nuclei.txt"
        self.output_file_urls: str = f"{self.output}/nuclei-urls.txt"
        self.output_file_forms: str = f"{self.output}/nuclei-forms.txt"  # TODO: better name? see forms_output_file
        self.output_file_ssl: str = f"{self.output}/nuclei-ssl.txt"
        self.output_file_headers: str = f"{self.output}/nuclei-headers.txt"
        self.output_file_cookies: str = f"{self.output}/nuclei-cookies.txt"
        self.output_file_file_uploads: str = f"{self.output}/nuclei-file-uploads.txt"

    def has_run_before(self) -> bool:
        """Checks if the module has run before by checking the existence of the output file."""
        return os.path.exists(self.output_file)

    def convert_to_xml(self, jsonl_file: str, output_file: str):
        """Converts Katana JSONL output to XML format for Nuclei."""
        new_urls = []
        out = '<?xml version="1.0"?>\n'

        with open(jsonl_file, "r") as f:
            out += "<items>\n"
            lines = f.readlines()
            for line in lines:
                json_line = json.loads(line)
                if "response" not in json_line:
                    continue
                elif "forms" not in json_line["response"]:
                    continue
                forms = json_line["response"]["forms"]

                for form in forms:
                    if "parameters" in form:
                        data = {p: "x" for p in form["parameters"]}
                        req_headers = {"Host": urlparse(form["action"]).netloc}

                        if form["method"] == "GET":
                            url = (
                                form["action"]
                                + "?"
                                + "&".join([f"{k}={v}" for k, v in data.items()])
                            )
                            new_urls.append(url)
                            continue

                        if form["enctype"] == "multipart/form-data":
                            req = requests.Request(
                                form["method"],
                                form["action"],
                                headers=req_headers,
                                files=data,
                            )
                        else:
                            req = requests.Request(
                                form["method"],
                                form["action"],
                                headers=req_headers,
                                data=data,
                            )
                            req_headers["Content-Type"] = (
                                form["enctype"]
                                if "enctype" in form
                                else "application/x-www-form-urlencoded"
                            )

                        prepared = req.prepare()

                        if not prepared.body:
                            prepared.body = b""
                        elif isinstance(prepared.body, str):
                            prepared.body = prepared.body.encode()

                        raw = (
                            prepared.method.encode()
                            + b" "
                            + prepared.url.encode()
                            + b" HTTP/1.1\r\n"
                            + b"".join(
                                [
                                    f"{k}: {v}\r\n".encode()
                                    for k, v in prepared.headers.items()
                                ]
                            )
                            + b"\r\n"
                            + prepared.body
                        )
                        raw_b64 = base64.b64encode(raw).decode()

                        out += "<item>\n"
                        out += "<url><![CDATA[" + form["action"] + "]]></url>\n"
                        out += (
                            '<request base64="true"><![CDATA['
                            + raw_b64
                            + "]]></request>\n"
                        )
                        out += '<response base64="true"><![CDATA[]]></response>\n'

                        out += "</item>\n"

            out += "</items>\n"

        with open(output_file, "w") as f_out:
            f_out.write(out)

        merge_list_with_file(new_urls, self.urls_file, self.urls_file)

    def pre(self) -> bool:
        """Preconditions for running the module."""
        if not os.path.exists(self.katana_output_file):
            logger.warning(
                f"Katana output file {self.katana_output_file} does not exist, continuing without forms"
            )
            self.run_on_forms = False
        else:
            logger.info(
                f"Converting Katana output to XML format: {self.forms_output_file}"
            )
            self.convert_to_xml(self.katana_output_file, self.forms_output_file)

        if not os.path.exists(self.urls_with_params):
            # Filter out non-dynamic URLs from the URLs file
            match_urls_with_params(self.urls_file, self.urls_with_params)

        return True

    def run(self):
        """Runs Nuclei scans for URLs, forms, SSL, and headers."""
        logger.info("Running Nuclei on URLs...")
        cmd_nuclei_urls = [
            "nuclei",
            "-l",
            self.urls_with_params,
            "-rl",
            self.rate_limit,
            "-dast",
            "-t",
            f"{self.script_dir}/custom-templates",
            "-o",
            self.output_file_urls,
        ]
        if self.headers:
            cmd_nuclei_urls.extend(["-H", self.headers])
        if self.proxy:
            cmd_nuclei_urls.extend(["-proxy", self.proxy])
        run_command(
            cmd_nuclei_urls, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        if self.run_on_forms:
            logger.info("Running Nuclei on forms...")
            cmd_nuclei_forms = [
                "nuclei",
                "-im",
                "burp",
                "-l",
                self.forms_output_file,
                "-rl",
                self.rate_limit,
                "-dast",
                "-t",
                f"{self.script_dir}/custom-templates",
                "-o",
                self.output_file_forms,
            ]
            if self.headers:
                cmd_nuclei_forms.extend(["-H", self.headers])
            if self.proxy:
                cmd_nuclei_forms.extend(["-proxy", self.proxy])
            run_command(
                cmd_nuclei_forms, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

        logger.info("Running Nuclei SSL checks...")
        cmd_nuclei_ssl = [
            "nuclei",
            "-u",
            self.target,
            "-rl",
            self.rate_limit,
            "-t",
            "ssl",
            "-o",
            self.output_file_ssl,
        ]
        if self.headers:
            cmd_nuclei_ssl.extend(["-H", self.headers])
        if self.proxy:
            cmd_nuclei_ssl.extend(["-proxy", self.proxy])
        run_command(
            cmd_nuclei_ssl, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        logger.info("Checking for missing security headers...")
        cmd_nuclei_headers = [
            "nuclei",
            "-u",
            self.target,
            "-rl",
            self.rate_limit,
            "-o",
            self.output_file_headers,
            "-t",
            "http/misconfiguration/http-missing-security-headers.yaml",
        ]
        if self.headers:
            cmd_nuclei_headers.extend(["-H", self.headers])
        if self.proxy:
            cmd_nuclei_headers.extend(["-proxy", self.proxy])
        run_command(
            cmd_nuclei_headers, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        logger.info("Checking cookies...")
        cmd_nuclei_cookies = [
            "nuclei",
            "-u",
            self.target,
            "-rl",
            self.rate_limit,
            "-o",
            self.output_file_cookies,
            "-t",
            "http/misconfiguration/cookies-without-httponly.yaml",
            "-t",
            "http/misconfiguration/cookies-without-secure.yaml",
            "-t",
            "custom-templates/cookies",
        ]
        logger.debug("Skipping headers for cookies check")
        # if self.headers:
        #     cmd_nuclei_cookies.extend(["-H", self.headers])
        if self.proxy:
            cmd_nuclei_cookies.extend(["-proxy", self.proxy])
        run_command(
            cmd_nuclei_cookies, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        logger.info("Looking for file uploads...")
        cmd_nuclei_file_uploads = [
            "nuclei",
            "-l",
            self.urls_file,
            "-rl",
            self.rate_limit,
            "-t",
            f"{self.script_dir}/custom-templates/upload/file-upload-endpoint.yaml",
            "-o",
            self.output_file_file_uploads,
            "-nm",
        ]
        if self.headers:
            cmd_nuclei_file_uploads.extend(["-H", self.headers])
        if self.proxy:
            cmd_nuclei_file_uploads.extend(["-proxy", self.proxy])
        run_command(
            cmd_nuclei_file_uploads,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def post(self):
        """Merge all Nuclei results into a single file and sort them."""
        results = []
        for file_path in [
            self.output_file_urls,
            self.output_file_forms,
            self.output_file_ssl,
            self.output_file_headers,
            self.output_file_cookies,
        ]:
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    results += [line.strip() for line in f.readlines()]
            else:
                logger.warning(f"Result file {file_path} does not exist.")

        # Parse and deduplicate results
        parsed_results = []

        for res in results:
            try:
                elements = res.split(" ")
                parsed_results.append(
                    {
                        "type": elements[0].strip("[]"),
                        "severity": elements[2].strip("[]"),
                        "url": elements[3].split("?")[0],
                        "parameter": elements[-2].strip("[]"),
                        "method": elements[-1].strip("[]"),
                    }
                )
            except IndexError:
                logger.warning(f"Failed to parse result: {res}")

        unique_results = {json.dumps(res, sort_keys=True) for res in parsed_results}

        # Sort on severity, then by URL, then by name
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        sorted_results = sorted(
            [json.loads(res) for res in unique_results],
            key=lambda x: (
                severity_order.get(
                    x["severity"], 5
                ),  # Default to 5 if severity is not found
                x["url"],
                x["type"],
            ),
            reverse=True,
        )

        if sorted_results:
            logger.success("All nuclei results:")
            with open(self.output_file, "w") as f:
                for result in sorted_results:
                    line = f"[{result['type']}] [{result['severity']}] {result['url']} [{result['parameter']}] [{result['method']}]"
                    f.write(line + "\n")
                    logger.info(line)
        else:
            logger.info("No Nuclei results found.")

def add_arguments(parser):
    """Adds Nuclei-specific arguments to the main argument parser."""
    group = parser.add_argument_group("nuclei")
    add_argument_if_not_exists(group, "-H", "--headers", help="Headers to use")
    add_argument_if_not_exists(group, "--proxy", help="Proxy to use")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nuclei Module")
    parser.add_argument("target", help="The target domain")
    parser.add_argument("-o", "--output", help="Output directory to save results")
    parser.add_argument(
        "-rl",
        "--rate-limit",
        help="Maximum requests to send per second",
        default=DEFAULT_RATE_LIMIT,
    )
    add_arguments(parser)

    args = parser.parse_args()

    if not args.target:
        logger.critical("No target specified. Please provide a target domain.")
        sys.exit(1)

    nuclei_module = NucleiModule(args)
    if not nuclei_module.pre():
        logger.critical("Preconditions not met. Exiting.")
        sys.exit(1)

    try:
        nuclei_module.run()
        nuclei_module.post()
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)
