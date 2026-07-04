import asyncio
import socket
from typing import List
from sentinel_scan.core.base import BaseModule
from sentinel_scan.core.models import Host, Service

class TCPScanner(BaseModule):
    def __init__(self, ports: List[int] = None, timeout: float = 1.0):
        super().__init__("TCPScanner", "Asynchronous TCP port scanner")
        self.ports = ports or [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]
        self.timeout = timeout

    async def scan_port(self, host: Host, port: int):
        try:
            conn = asyncio.open_connection(host.address, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)

            service = Service(port=port, protocol="tcp", state="open")

            # Simple banner grab
            try:
                # Some protocols require us to send something first,
                # but many send a banner on connect.
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if banner:
                    service.banner = banner.decode('utf-8', errors='ignore').strip()
            except:
                pass

            host.services.append(service)
            writer.close()
            await writer.wait_closed()
        except:
            # Port closed or timeout
            pass

    async def run(self, host: Host):
        tasks = [self.scan_port(host, port) for port in self.ports]
        await asyncio.gather(*tasks)
