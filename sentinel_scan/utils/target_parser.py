import ipaddress
import socket
import asyncio
from typing import List, Set

class TargetParser:
    @staticmethod
    async def parse_targets(targets: List[str]) -> Set[str]:
        """
        Parses a list of targets which can be single IPs, CIDR ranges, or hostnames.
        Returns a unique set of IP addresses.
        """
        parsed_ips = set()
        loop = asyncio.get_event_loop()

        for target in targets:
            target = target.strip()
            if not target:
                continue

            # Check if it's a CIDR range
            if "/" in target:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    for ip in network:
                        parsed_ips.add(str(ip))
                except ValueError:
                    pass
            else:
                # Try to parse as single IP
                try:
                    ipaddress.ip_address(target)
                    parsed_ips.add(target)
                except ValueError:
                    # Likely a hostname, attempt resolution asynchronously
                    try:
                        # Use run_in_executor to avoid blocking the event loop
                        ip = await loop.run_in_executor(None, socket.gethostbyname, target)
                        parsed_ips.add(ip)
                    except (socket.gaierror, Exception):
                        pass
        return parsed_ips
