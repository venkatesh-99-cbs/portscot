from sentinel_scan.core.base import BasePlugin
from sentinel_scan.core.models import Host, Finding

class InsecureBannerPlugin(BasePlugin):
    def __init__(self):
        super().__init__("InsecureBanner", "Checks for banners that might reveal too much information")

    async def check(self, host: Host):
        for service in host.services:
            if service.banner:
                # Example: checking for version numbers in banner
                if any(char.isdigit() for char in service.banner):
                    host.findings.append(Finding(
                        title="Information Exposure in Banner",
                        description=f"Service on port {service.port} exposes version information in its banner: {service.banner}",
                        severity="info",
                        remediation="Configure the service to hide version information in banners.",
                        plugin_name=self.name
                    ))

    async def run(self, host: Host):
        # BaseModule.run is called by check in our simplified engine logic
        await self.check(host)
