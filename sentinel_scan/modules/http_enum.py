import aiohttp
from sentinel_scan.core.base import BaseModule
from sentinel_scan.core.models import Host

class HTTPEnumeration(BaseModule):
    def __init__(self, timeout: float = 2.0):
        super().__init__("HTTPEnumeration", "Enumerates HTTP services and grabs headers")
        self.timeout = timeout

    async def run(self, host: Host):
        for service in host.services:
            if service.port in [80, 443, 8080, 8443] or "http" in (service.service_name or "").lower():
                protocol = "https" if service.port in [443, 8443] else "http"
                url = f"{protocol}://{host.address}:{service.port}"

                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, timeout=self.timeout, ssl=False) as response:
                            server = response.headers.get("Server")
                            if server:
                                service.product = server

                            # Store some headers or title in extrainfo
                            service.extrainfo = f"Status: {response.status}, Title: {url}"
                except Exception as e:
                    pass
