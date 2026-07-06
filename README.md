# SentinelScan

SentinelScan is a professional, modular, cross-platform network security auditing framework built in Python. Designed for authorized security assessments and asset inventory, it provides a clean, layered architecture for efficient network discovery and analysis.

## Features

- **Modular Architecture:** Separate modules for discovery, scanning, and analysis.
- **Asynchronous Engine:** High-performance scanning using `asyncio`.
- **Host Discovery:** Identify live hosts on the network.
- **TCP/UDP Scanning:** Comprehensive port scanning capabilities.
- **Service & Version Detection:** Identify running services and their versions.
- **Banner Analysis:** Extract and analyze service banners.
- **TLS Inspection:** Inspect SSL/TLS certificates and configurations.
- **HTTP Enumeration:** Enumerate web services and grab headers.
- **OS Fingerprinting:** Heuristic operating system estimation based on TTL and banners.
- **Plugin System:** Non-destructive plugin architecture for safe security checks.
- **REST API:** Control scans and retrieve results via a web interface.
- **Reporting:** Export results in JSON, TXT, CSV, XML, and Markdown.

## Installation

```bash
pip install -r requirements.txt
pip install .
```

## Usage

### Command-Line Interface

```bash
sentinel-scan 192.168.1.0/24 --output report.md --format md
```

Options:
- `targets`: IP addresses, CIDR ranges, or hostnames.
- `--concurrency`: Number of concurrent scans (default: 100).
- `--output`: File path to save the report.
- `--format`: Output format (json, txt, csv, md, xml).
- `--verbose`: Enable verbose logging.

### REST API

Start the API server:
```bash
uvicorn sentinel_scan.api.app:app --reload
```

## Plugin Development

New security checks can be added by creating a new Python file in the `sentinel_scan/plugins/` directory that inherits from `BasePlugin`.

```python
from sentinel_scan.core.base import BasePlugin
from sentinel_scan.core.models import Host, Finding

class MyCustomPlugin(BasePlugin):
    def __init__(self):
        super().__init__("MyCustomPlugin", "Description of what it checks")

    async def check(self, host: Host):
        # Implement check logic here
        pass
```

## Ethical Use and Disclaimer

SentinelScan is intended for use only on systems the operator is authorized to assess. Unauthorized use of this tool against systems without permission is illegal and unethical. The authors are not responsible for any misuse of this tool.

Note: This framework is designed for transparent auditing and does not include features for evading detection or bypassing network defenses.
