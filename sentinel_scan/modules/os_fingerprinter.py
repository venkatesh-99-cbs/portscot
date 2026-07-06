import subprocess
import platform
import re
from sentinel_scan.core.base import BaseModule
from sentinel_scan.core.models import Host

class OSFingerprinter(BaseModule):
    def __init__(self):
        super().__init__("OSFingerprinter", "Heuristic OS fingerprinting based on TTL and banners")

    def get_ttl(self, ip: str) -> int:
        try:
            # Use ping to get TTL.
            # Note: subprocess.check_output might block, but we'll try to keep it minimal.
            # On Linux: ping -c 1
            # On Windows: ping -n 1
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            output = subprocess.check_output(['ping', param, '1', ip], stderr=subprocess.STDOUT, timeout=2).decode()

            ttl_match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
            if ttl_match:
                return int(ttl_match.group(1))
        except:
            pass
        return -1

    async def run(self, host: Host):
        ttl = self.get_ttl(host.address)

        if ttl != -1:
            if ttl <= 64:
                host.os_name = "Linux/Unix"
                host.os_accuracy = 70
            elif ttl <= 128:
                host.os_name = "Windows"
                host.os_accuracy = 70
            elif ttl <= 255:
                host.os_name = "Solaris/AIX"
                host.os_accuracy = 60

        # Refine with banners
        for service in host.services:
            if service.banner:
                banner_lower = service.banner.lower()
                if "ubuntu" in banner_lower or "debian" in banner_lower:
                    host.os_name = "Linux (Ubuntu/Debian)"
                    host.os_accuracy = 90
                elif "win32" in banner_lower or "microsoft" in banner_lower:
                    host.os_name = "Windows"
                    host.os_accuracy = 85
