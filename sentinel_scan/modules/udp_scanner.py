import asyncio
import socket
from typing import List
from sentinel_scan.core.base import BaseModule
from sentinel_scan.core.models import Host, Service

class UDPScanner(BaseModule):
    def __init__(self, ports: List[int] = None, timeout: float = 2.0):
        super().__init__("UDPScanner", "Basic UDP port scanner")
        self.ports = ports or [53, 67, 68, 69, 123, 161, 162, 443, 500, 514, 520]
        self.timeout = timeout

    async def scan_port(self, host: Host, port: int):
        try:
            # For UDP, "open" is hard to determine without protocol-specific probes.
            # Here we just try to send a packet. If we get ICMP unreachable (hard to catch with sockets),
            # it's closed. If nothing, it's open|filtered.

            # This is a very naive implementation.
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)

            # Try sending an empty packet
            await asyncio.get_event_loop().sock_sendall(sock, b"")

            # In a real scanner, we'd wait for ICMP responses using raw sockets (scapy).
            # For this modular framework, we'll mark it as open|filtered if no error.
            service = Service(port=port, protocol="udp", state="open|filtered")
            host.services.append(service)
            sock.close()
        except Exception:
            pass

    async def run(self, host: Host):
        tasks = [self.scan_port(host, port) for port in self.ports]
        await asyncio.gather(*tasks)
