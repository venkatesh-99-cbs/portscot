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

## Project Structure

```text
sentinel_scan/
├── api/             # FastAPI REST API implementation
├── cli/             # Click-based Command Line Interface
├── core/            # Core engine, base classes, and models
├── modules/         # Scanning and discovery modules (TCP, UDP, HTTP, TLS, OS)
├── plugins/         # Extensible security check plugins
├── reporting/       # Multi-format report generators
└── utils/           # Helper utilities (logger, target parser)
tests/               # Unit and integration tests
```

## Installation

### Prerequisites
- Python 3.9 or higher

### Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-repo/sentinel-scan.git
   cd sentinel-scan
   ```

2. **Create and activate a virtual environment (recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install the package in editable mode:**
   ```bash
   pip install -e .
   ```

## Usage

### Command-Line Interface (CLI)

The CLI is the primary way to interact with SentinelScan.

**Basic Scan:**
```bash
sentinel-scan 192.168.1.1
```

**Scan a Network Range with Markdown Output:**
```bash
sentinel-scan 192.168.1.0/24 --output report.md --format md
```

**High Concurrency Scan with Verbose Logging:**
```bash
sentinel-scan 10.0.0.0/16 --concurrency 500 --verbose
```

**Options:**
- `targets`: One or more IP addresses, CIDR ranges, or hostnames.
- `--concurrency`: Number of concurrent scan tasks (default: 100).
- `--output`: File path to save the generated report.
- `--format`: Report format (`json`, `txt`, `csv`, `md`, `xml`).
- `--plugins-dir`: Custom directory to load plugins from.
- `--verbose`: Enable detailed debug logging.

### REST API

SentinelScan includes a FastAPI-based REST API for programmatic control.

**Start the API Server:**
```bash
uvicorn sentinel_scan.api.app:app --host 0.0.0.0 --port 8000
```

**Start a Scan via API:**
```bash
curl -X POST "http://localhost:8000/scan" \
     -H "Content-Type: application/json" \
     -d '{"targets": ["127.0.0.1"], "concurrency": 50}'
```

**Retrieve Scan Results:**
```bash
curl "http://localhost:8000/scan/<scan_id>"
```

## Plugin Development

SentinelScan is designed to be easily extensible. To add a new security check:

1. Create a new `.py` file in `sentinel_scan/plugins/`.
2. Inherit from `BasePlugin`.
3. Implement the `check` method.

Example:
```python
from sentinel_scan.core.base import BasePlugin
from sentinel_scan.core.models import Host, Finding

class ExamplePlugin(BasePlugin):
    def __init__(self):
        super().__init__("ExamplePlugin", "Detects a specific configuration issue")

    async def check(self, host: Host):
        for service in host.services:
            if service.port == 1234:
                host.findings.append(Finding(
                    title="Insecure Service Detected",
                    description="Service on port 1234 is known to be insecure.",
                    severity="high",
                    remediation="Disable this service or restrict access.",
                    plugin_name=self.name
                ))
```

## Running Tests

To run the test suite, ensure `pytest` and `pytest-asyncio` are installed:

```bash
PYTHONPATH=. python3 -m pytest
```

## Ethical Use and Disclaimer

SentinelScan is intended for use only on systems the operator is authorized to assess. Unauthorized use of this tool against systems without permission is illegal and unethical. The authors are not responsible for any misuse of this tool.

Note: This framework is designed for transparent auditing and does not include features for evading detection or bypassing network defenses.
