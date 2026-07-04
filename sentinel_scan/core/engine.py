import asyncio
from datetime import datetime
from typing import List, Set, Type
from sentinel_scan.core.models import ScanResult, Host
from sentinel_scan.core.base import BaseModule
from sentinel_scan.utils.target_parser import TargetParser

from sentinel_scan.core.base import BaseModule, BasePlugin
from sentinel_scan.utils.logger import logger

class ScannerEngine:
    def __init__(self, concurrency: int = 100):
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)
        self.modules: List[BaseModule] = []
        self.plugins: List[BasePlugin] = []

    def add_module(self, module: BaseModule):
        self.modules.append(module)

    def add_plugin(self, plugin: BasePlugin):
        self.plugins.append(plugin)

    async def scan_host(self, ip: str) -> Host:
        host = Host(address=ip)
        async with self.semaphore:
            # First run discovery and enumeration modules
            for module in self.modules:
                try:
                    await module.run(host)
                except Exception as e:
                    logger.error(f"Error running module {module.name} on {ip}: {e}")

            # Then run security plugins
            if host.services: # Only run plugins if host seems alive/has open ports
                for plugin in self.plugins:
                    try:
                        logger.debug(f"Running plugin {plugin.name} on {ip}")
                        await plugin.check(host)
                    except Exception as e:
                        logger.error(f"Error running plugin {plugin.name} on {ip}: {e}")
        return host

    async def run(self, targets: List[str]) -> ScanResult:
        start_time = datetime.now()
        parsed_ips = await TargetParser.parse_targets(targets)

        tasks = [self.scan_host(ip) for ip in parsed_ips]
        hosts = await asyncio.gather(*tasks)

        end_time = datetime.now()

        all_findings = []
        for host in hosts:
            all_findings.extend(host.findings)

        result = ScanResult(
            target=", ".join(targets),
            start_time=start_time,
            end_time=end_time,
            hosts=hosts,
            findings=all_findings,
            summary={
                "total_hosts": len(hosts),
                "total_findings": len(all_findings)
            }
        )
        return result
