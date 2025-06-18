# Asteroid - Web Application Security Scanner
Developed during an internship at [SURF](https://www.surf.nl/).

Asteroid is a web application security scanner that combines multiple open source tools to gather URLs and detect vulnerabilities. It uses a modular structure to separate functionality for each tool.

## Features
| Module     | Default      | Comment |
| ------------- | ------------- | ------------- |
| [Katana](https://github.com/projectdiscovery/katana) | ✅ | Uses Katana to crawl the target domain, extracts forms to use with Nuclei |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | ✅ | Runs Feroxbuster for URL bruteforcing using [raft-small-words.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-small-words.txt) |
| [Gau](https://github.com/lc/gau) | ✅ | Runs Gau to collect URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl and filters false positives with [httpx](https://github.com/projectdiscovery/httpx) |
| [Arjun](https://github.com/s0md3v/Arjun) | ❌ | Fuzzes for GET query parameters with Arjun |
| Directory Listing | ✅ | Scans Feroxbuster output for open directory listings | 
| Sensitive Files | ✅ | Runs Feroxbuster with a dangerous files wordlist from [Bo0oM](https://github.com/Bo0oM/fuzz.txt) |
| [Trufflehog](https://github.com/trufflesecurity/trufflehog) | ❌ | Downloads all URLs with [curl](https://github.com/curl/curl) and scans them for secrets using Trufflehog |
| Extension Inspector | ✅ | Reports sensitive file extensions, Python implementation of a [Nuclei template](https://github.com/projectdiscovery/nuclei-templates/blob/main/file/url-analyse/url-extension-inspector.yaml) by ayadim |
| Vulnscan | ✅ | Detects technologies using [wappalyzer-next](https://github.com/s0md3v/wappalyzer-next) and scans for CVEs using [search_vulns](https://github.com/ra1nb0rn/search_vulns)|
| [RetireJS](https://github.com/retirejs/retire.js/) | ✅ | Runs RetireJS to detect use of vulnerable JavaScript libraries using Python 3 adaptation from [ghostlulzhacks](https://github.com/ghostlulzhacks/RetireJs) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | ✅ | Fuzzes for vulnerabilities like XSS and SQLi in URLs and forms using Nuclei DAST templates | 
| File Upload | ✅ | Detects vulnerable file uploads. Custom tool and work-in-progress |

## Installation
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
Read the help menu or visit the Wiki (TODO).
```
$ uv run asteroid.py -h
usage: asteroid [-h] [-o OUTPUT] [--modules MODULES] [--skip-modules SKIP_MODULES] [--list-modules] [--rerun] [--continue] [-v] [-rl RATE_LIMIT] [-s SIZE] [-up] [-headless]
                [-tl TIME_LIMIT] [-H HEADERS] [--proxy PROXY] [--dont-scan DONT_SCAN] [-w WORDLIST] [-d DEPTH] [-C C] [-x EXTENSIONS] [-aw ARJUN_WORDLIST] [--cleanup]
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

vulnscan:
  -s SIZE, --size SIZE  Max number of outputs by search_vulns
  -up, --update         Update search_vulns CVE database

katana:
  -headless             Run in headless mode in Katana
  -tl TIME_LIMIT, --time-limit TIME_LIMIT
                        Time limit for the Katana scan
  -H HEADERS, --headers HEADERS
                        Headers to use
  --proxy PROXY         HTTP/SOCKS5 proxy to use for the requests
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

trufflehog:
  --cleanup             Cleanup the output directory
```

## Contributing & bug reports
Feel free to open issues or pull requests. You can even create your own modules by extending the BaseModule class, which I might add to Asteroid after review.
