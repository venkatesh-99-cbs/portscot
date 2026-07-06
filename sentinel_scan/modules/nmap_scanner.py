import nmap
import asyncio
from typing import Any, Dict
from sentinel_scan.core.base import BaseModule
from sentinel_scan.core.models import Host, Service
from sentinel_scan.utils.logger import logger

class NmapScanner(BaseModule):
    def __init__(self, arguments: str = "-sV -sC"):
        super().__init__("NmapScanner", "High-fidelity Nmap-based scanning module")
        self.arguments = arguments
        self.nm = nmap.PortScanner()

    async def run(self, host: Host):
        logger.info(f"Starting professional Nmap scan on {host.address}...")

        # Run Nmap in a thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        try:
            scan_data = await loop.run_in_executor(
                None,
                lambda: self.nm.scan(host.address, arguments=self.arguments)
            )

            if host.address in scan_data['scan']:
                data = scan_data['scan'][host.address]

                # OS Detection
                if 'osmatch' in data and data['osmatch']:
                    best_match = data['osmatch'][0]
                    host.os_name = best_match['name']
                    host.os_accuracy = int(best_match['accuracy'])

                # Services
                for proto in ['tcp', 'udp']:
                    if proto in data:
                        for port, port_data in data[proto].items():
                            service = Service(
                                port=port,
                                protocol=proto,
                                state=port_data['state'],
                                service_name=port_data.get('name'),
                                product=port_data.get('product'),
                                version=port_data.get('version'),
                                extrainfo=port_data.get('extrainfo'),
                                banner=port_data.get('banner')
                            )
                            # Avoid duplicates if other modules already found it
                            existing = [s for s in host.services if s.port == port and s.protocol == proto]
                            if not existing:
                                host.services.append(service)
                            else:
                                # Update existing with more info
                                existing[0].product = service.product or existing[0].product
                                existing[0].version = service.version or existing[0].version
                                existing[0].service_name = service.service_name or existing[0].service_name

                host.status = data.get('status', {}).get('state', 'unknown')

        except Exception as e:
            logger.error(f"Nmap scan failed for {host.address}: {e}")
