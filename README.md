## Installation
Build with docker (takes ~5 min):
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