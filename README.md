# Asteroid - Web Application Security Scanner
Asteroid is a web application security scanner that combines multiple open source tools to gather URLs and detect vulnerabilities. It uses a modular structure to separate functionality for each tool.

Developed during an internship at [SURF](https://www.surf.nl/).

**Disclaimer**: Do not run Asteroid on a website without explicit permission of the owner.

## Features
| Module     | License | Default      | Comment |
| ------------- | ------------- | ------------- | ------------- |
| [Katana](https://github.com/projectdiscovery/katana) | [MIT](https://github.com/projectdiscovery/katana/blob/main/LICENSE.md) | ✅ | Uses Katana to crawl the target domain, extracts forms to use with Nuclei |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | [MIT](https://github.com/epi052/feroxbuster/blob/main/LICENSE) |  ✅ | Runs Feroxbuster for URL bruteforcing using [raft-small-words.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-small-words.txt) |
| [Gau](https://github.com/lc/gau) | [MIT](https://github.com/lc/gau/blob/master/LICENSE) | ✅ | Runs Gau to collect URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl |
| [Arjun](https://github.com/s0md3v/Arjun) | [AGPL-3.0](https://github.com/s0md3v/Arjun/blob/master/LICENSE) | ❌ | Fuzzes for GET query parameters with Arjun using [params wordlist from param-miner](https://github.com/PortSwigger/param-miner/blob/master/resources/params) |
| Directory Listing | [MIT](https://github.com/epi052/feroxbuster/blob/main/LICENSE) | ✅ | Scans Feroxbuster output for open directory listings | 
| Sensitive Files | [MIT](https://github.com/epi052/feroxbuster/blob/main/LICENSE) |  ✅ | Runs Feroxbuster with a dangerous files wordlist from [Bo0oM](https://github.com/Bo0oM/fuzz.txt) |
| [Trufflehog](https://github.com/trufflesecurity/trufflehog) | [AGPL-3.0](https://github.com/trufflesecurity/trufflehog/blob/main/LICENSE) | ❌ | Downloads all URLs with [curl](https://github.com/curl/curl) and scans them for secrets using Trufflehog |
| Extension Inspector | - | ✅ | Reports sensitive file extensions, Python implementation of a [Nuclei template](https://github.com/projectdiscovery/nuclei-templates/blob/main/file/url-analyse/url-extension-inspector.yaml) by ayadim |
| Vulnscan | [GPL-3.0](https://github.com/s0md3v/wappalyzer-next/blob/main/LICENSE) | ✅ | Detects technologies using [wappalyzer-next](https://github.com/s0md3v/wappalyzer-next) and scans for CVEs using [search_vulns](https://github.com/ra1nb0rn/search_vulns)|
| [RetireJS](https://github.com/retirejs/retire.js/) | [Apache-2.0](https://github.com/RetireJS/retire.js/blob/master/LICENSE.md) | ✅ | Runs RetireJS to detect use of vulnerable JavaScript libraries using Python 3 adaptation from [ghostlulzhacks](https://github.com/ghostlulzhacks/RetireJs) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | [MIT](https://github.com/projectdiscovery/nuclei/blob/dev/LICENSE.md) | ✅ | Fuzzes for vulnerabilities like XSS and SQLi in URLs and forms using Nuclei DAST templates | 
| File Upload | - | ✅ | Detects vulnerable file uploads. Custom tool and work-in-progress |

False positives and duplicate URLs are filtered using [httpx](https://github.com/projectdiscovery/httpx) ([MIT](https://github.com/projectdiscovery/httpx/blob/main/LICENSE.md)) and [uro](https://github.com/s0md3v/uro) ([Apache-2;0](https://github.com/s0md3v/uro/blob/main/LICENSE)).
## Installation
To run the Vulnscan module, you should first generate an API key at https://search-vulns.com/api/setup and put it in `config.py`.
### Docker
Build with docker (takes ~8 min):
```bash
docker build -t asteroid:latest .
```

Run with docker:
```bash
docker run -it -v ./asteroid_output:/asteroid/asteroid_output asteroid -h
```
for help menu, or
```bash
docker run -it -v ./asteroid_output:/asteroid/asteroid_output asteroid http://testphp.vulnweb.com
```
to run on a target, e.g. http://testphp.vulnweb.com
### Local
Run `install.sh` on a debian-testing based (e.g. Kali Linux) distribution.
```bash
bash install.sh
```
Now you can run Asteroid using uv:
```bash
uv run asteroid.py
```
## Usage
Read the help menu or visit the Wiki.
```
$ uv run asteroid.py -h                                                                                 
usage: asteroid [-h] [-o OUTPUT] [--modules MODULES] [--skip-modules SKIP_MODULES] [--list-modules] [--rerun] [--continue] [-v] [-rl RATE_LIMIT] [-p PROXY] [-s SIZE] [-headless] [-tl TIME_LIMIT] [-H HEADERS]
                [--dont-scan DONT_SCAN] [-w WORDLIST] [-d DEPTH] [-C C] [-x EXTENSIONS] [-aw ARJUN_WORDLIST] [-sfw SENSITIVE_FILES_WORDLIST] [--keep-downloads] [--max-download-size MAX_DOWNLOAD_SIZE]
                [target]

Runs all Asteroid Web Application Security Scanner modules.

positional arguments:
  target                The target domain to crawl, or a file containing domains

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output directory to save results
  --modules MODULES     Comma-separated list of modules to run
  --skip-modules SKIP_MODULES
                        Comma-separated list of modules to skip
  --list-modules        List all modules and exit
  --rerun               Rerun even if previous output is detected
  --continue            Continue from the last module run
  -v, --verbose         Enable verbose output
  -rl RATE_LIMIT, --rate-limit RATE_LIMIT
                        Maximum requests to send per second
  -p PROXY, --proxy PROXY
                        HTTP proxy to use for the requests, not supported by Vulnscan and RetireJS

vulnscan:
  -s SIZE, --size SIZE  Max number of outputs by search_vulns

katana:
  -headless             Run in headless mode in Katana
  -tl TIME_LIMIT, --time-limit TIME_LIMIT
                        Time limit for the Katana scan
  -H HEADERS, --headers HEADERS
                        Headers to use
  --dont-scan DONT_SCAN
                        Do not scan URLs matching this regex

feroxbuster:
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist to use for feroxbuster
  -d DEPTH, --depth DEPTH
                        Recursive depth for feroxbuster
  -C C                  Filter status codes for feroxbuster
  -x EXTENSIONS, --extensions EXTENSIONS
                        Extensions to use for feroxbuster, reads values (newline-separated) from file if input starts with an @ (ex: @ext.txt)

arjun:
  -aw ARJUN_WORDLIST, --arjun-wordlist ARJUN_WORDLIST
                        Wordlist to use for parameter mining

sensitive files:
  -sfw SENSITIVE_FILES_WORDLIST, --sensitive-files-wordlist SENSITIVE_FILES_WORDLIST
                        Wordlist to use for Feroxbuster sensitive files scan

trufflehog:
  --keep-downloads      Do not cleanup the output directory
  --max-download-size MAX_DOWNLOAD_SIZE
                        Maximum file size to download, e.g. 5M
```

## Contributing & bug reports
Feel free to open issues or pull requests. You can even create your own modules by extending the BaseModule class, which I might add to Asteroid after review.
