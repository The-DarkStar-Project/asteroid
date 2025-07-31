import os
from urllib.parse import urlparse
import sys
import json
import base64
import requests
import shutil
from typing import Optional

# Add the grandparent directory to sys.path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from modules.utils import (
    logger,
    add_argument_if_not_exists,
    run_command,
    merge_list_with_file,
    match_urls_with_params,
)
from modules.base_module import BaseModule, main, Vuln


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

        self.headers: Optional[str] = args.get("headers")

        self.run_on_forms: bool = args.get("forms", False)

        self.katana_output_file: str = os.path.join(
            os.path.join(self.base_output_dir, "10-katana"), "katana.jsonl"
        )
        self.forms_output_file: str = os.path.join(
            os.path.join(self.base_output_dir, "10-katana"), "forms.xml"
        )

        self.urls_with_params: str = os.path.join(
            self.output_dir, "urls-with-params.txt"
        )

        self.output_file: str = os.path.join(self.output_dir, "nuclei.txt")
        self.output_file_urls: str = os.path.join(self.output_dir, "nuclei-urls.txt")
        self.output_file_forms: str = os.path.join(
            self.output_dir, "nuclei-forms.txt"
        )  # TODO: better name? see forms_output_file
        self.output_file_ssl: str = os.path.join(self.output_dir, "nuclei-ssl.txt")
        self.output_file_headers: str = os.path.join(
            self.output_dir, "nuclei-headers.txt"
        )
        self.output_file_cookies: str = os.path.join(
            self.output_dir, "nuclei-cookies.txt"
        )
        self.output_file_file_uploads: str = os.path.join(
            self.output_dir, "nuclei-file-uploads.txt"
        )

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
        if not shutil.which("nuclei"):
            logger.critical(
                "Nuclei is not installed or not in PATH. Please install it before running."
            )
            return False

        if self.run_on_forms:
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
        else:
            logger.info("Skipping form fuzzing as --forms is not set.")

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
        run_command(cmd_nuclei_urls, verbose=self.verbose)

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
            run_command(cmd_nuclei_forms, verbose=self.verbose)

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
        run_command(cmd_nuclei_ssl, verbose=self.verbose)

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
        run_command(cmd_nuclei_headers, verbose=self.verbose)

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
        run_command(cmd_nuclei_cookies, verbose=self.verbose)

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
        run_command(cmd_nuclei_file_uploads, verbose=self.verbose)

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

                    vuln = Vuln(
                        title=f"{result['type']} vulnerability",
                        affected_item=result["url"],
                        confidence=80,
                        severity=result["severity"],
                        host=self.target,
                        summary=f"Found {result['type']} vulnerability in {result['url']} with parameter {result['parameter']} and method {result['method']}",
                    )
                    self.add_vulnerability(vuln)
        else:
            logger.info("No Nuclei results found.")


def add_arguments(parser):
    """Adds Nuclei-specific arguments to the main argument parser."""
    group = parser.add_argument_group("nuclei")
    add_argument_if_not_exists(group, "-H", "--headers", help="Headers to use")
    add_argument_if_not_exists(
        group,
        "--forms",
        action="store_true",
        help="Run Nuclei on forms extracted by Katana",
    )


if __name__ == "__main__":
    main("Nuclei", NucleiModule, add_arguments)
