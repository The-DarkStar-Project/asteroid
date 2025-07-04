import os
import sys
import re
from typing import Dict, Pattern

# Add the grandparent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from modules.base_module import BaseModule, main
from modules.utils import logger


class ExtensionInspectorModule(BaseModule):
    """A class to encapsulate the functionality of the Extension Inspector module."""

    name = "ExtensionInspector"
    index = 45
    is_default_module = True
    description = "Inspects found URLs for interesting extensions"

    def __init__(self, args):
        """
        Initializes the ExtensionInspectorModule class with the given parameters.

        :param args: The command line arguments passed to the script.
        """
        super().__init__(args)
        self.regexes: Dict[str, Pattern] = {
            "Hot finding": re.compile(
                r"(?i)(htdocs|www|html|web|webapps|public|public_html|uploads|website|api|test|app|backup|bin|bak|old|release|sql)\.(7z|bz2|gz|lz|rar|tar\.gz|tar\.bz2|xz|zip|z)"
            ),
            "Backup file": re.compile(r"(?i)(\.bak|\.backup|\.bkp|\._bkp|\.bk|\.BAK)"),
            "PHP Source": re.compile(
                r"(?i)(\.php)(\.~|\.bk|\.bak|\.bkp|\.BAK|\.swp|\.swo|\.swn|\.tmp|\.save|\.old|\.new|\.orig|\.dist|\.txt|\.disabled|\.original|\.backup|\._back|\._1\.bak|~|!|\.0|\.1|\.2|\.3)"
            ),
            "ASP Source": re.compile(
                r"(?i)(\.asp)(\.~|\.bk|\.bak|\.bkp|\.BAK|\.swp|\.swo|\.swn|\.tmp|\.save|\.old|\.new|\.orig|\.dist|\.txt|\.disabled|\.original|\.backup|\._back|\._1\.bak|~|!|\.0|\.1|\.2|\.3)"
            ),
            "Database file": re.compile(r"(?i)\.db|\.sql"),
            "Bash script": re.compile(r"(?i)(\.sh|\.bashrc|\.zshrc)"),
            "1Password password manager database file": re.compile(
                r"(?i)\.agilekeychain"
            ),
            "ASP configuration file": re.compile(r"(?i)\.asa"),
            "Apple Keychain database file": re.compile(r"(?i)\.keychain"),
            "Azure service configuration schema file": re.compile(r"(?i)\.cscfg"),
            "Compressed archive file": re.compile(
                r"(?i)(\.zip|\.gz|\.tar|\.rar|\.tgz)"
            ),
            "Configuration file": re.compile(r"(?i)(\.ini|\.config|\.conf)"),
            "Day One journal file": re.compile(r"(?i)\.dayone"),
            "Document file": re.compile(r"(?i)(\.doc|\.docx|\.rtf)"),
            "GnuCash database file": re.compile(r"(?i)\.gnucash"),
            "Include file": re.compile(r"(?i)\.inc"),
            "XML file": re.compile(r"(?i)\.xml"),
            "Old file": re.compile(r"(?i)\.old"),
            "Log file": re.compile(r"(?i)\.log"),
            "Java file": re.compile(r"(?i)\.java"),
            "SQL dump file": re.compile(r"(?i)\.sql"),
            "Excel file": re.compile(r"(?i)(\.xls|\.xlsx|\.csv)"),
            "Certificate file": re.compile(r"(?i)(\.cer|\.crt|\.p7b)"),
            "Java key store": re.compile(r"(?i)\.jks"),
            "KDE Wallet Manager database file": re.compile(r"(?i)\.kwallet"),
            "Little Snitch firewall configuration file": re.compile(r"(?i)\.xpl"),
            "Microsoft BitLocker Trusted Platform Module password file": re.compile(
                r"(?i)\.tpm"
            ),
            "Microsoft BitLocker recovery key file": re.compile(r"(?i)\.bek"),
            "Microsoft SQL database file": re.compile(r"(?i)\.mdf"),
            "Microsoft SQL server compact database file": re.compile(r"(?i)\.sdf"),
            "Network traffic capture file": re.compile(r"(?i)\.pcap"),
            "OpenVPN client configuration file": re.compile(r"(?i)\.ovpn"),
            "PDF file": re.compile(r"(?i)\.pdf"),
            "PHP file": re.compile(r"(?i)\.pcap"),
            "Password Safe database file": re.compile(r"(?i)\.psafe3"),
            "Potential configuration file": re.compile(r"(?i)\.yml"),
            "Potential cryptographic key bundle": re.compile(
                r"(?i)(\.pkcs12|\.p12|\.pfx|\.asc|\.pem)"
            ),
            "Potential private key": re.compile(r"(?i)otr.private_key"),
            "Presentation file": re.compile(r"(?i)(\.ppt|\.pptx)"),
            "Python file": re.compile(r"(?i)\.py"),
            "Remote Desktop connection file": re.compile(r"(?i)\.rdp"),
            "Ruby On Rails file": re.compile(r"(?i)\.rb"),
            "SQLite database file": re.compile(r"(?i)\.sqlite|\.sqlitedb"),
            "SQLite3 database file": re.compile(r"(?i)\.sqlite3"),
            "Sequel Pro MySQL database manager bookmark file": re.compile(
                r"(?i)\.plist"
            ),
            "Shell configuration file": re.compile(
                r"(?i)(\.exports|\.functions|\.extra)"
            ),
            "Temporary file": re.compile(r"(?i)\.tmp"),
            "Terraform variable config file": re.compile(r"(?i)\.tfvars"),
            "Text file": re.compile(r"(?i)\.txt"),
            "Tunnelblick VPN configuration file": re.compile(r"(?i)\.tblk"),
            "Windows BitLocker full volume encrypted data file": re.compile(
                r"(?i)\.fve"
            ),
        }

        self.output_file: str = f"{self.output_dir}/extension-inspector.txt"

    def pre(self) -> bool:
        """Preconditions for running the module."""
        if not os.path.exists(self.urls_file):
            logger.critical(f"URLs file {self.urls_file} does not exist")
            return False

        return True

    def run(self):
        """Detects interesting extensions in the URLs found in previous modules."""
        target_urls = []
        with open(self.urls_file, "r") as f:
            target_urls = [url.strip() for url in f.readlines()]

        results = {
            name: list(filter(regex.search, target_urls))
            for name, regex in self.regexes.items()
            if any(regex.search(url) for url in target_urls)
        }

        out = ""
        if results:
            out += "Interesting extensions found:\n"
            for name in results:
                out += f"{name}:\n"
                for match in results[name]:
                    out += f"    {match}\n"
                out += "\n"
            logger.info(out)
        else:
            logger.info("No interesting extensions found.")

        if out:
            with open(self.output_file, "w") as f:
                f.write(out)

    def post(self):
        pass


def add_arguments(parser):
    pass


if __name__ == "__main__":
    main("ExtensionInspector", ExtensionInspectorModule, add_arguments)
