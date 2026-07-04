import asyncio
import ssl
import socket
from datetime import datetime
from sentinel_scan.core.base import BaseModule
from sentinel_scan.core.models import Host, Service

class TLSInspector(BaseModule):
    def __init__(self, timeout: float = 3.0):
        super().__init__("TLSInspector", "Inspects TLS certificates and configurations")
        self.timeout = timeout

    async def inspect_tls(self, host: Host, service: Service):
        if service.port not in [443, 8443, 993, 995, 465] and "ssl" not in (service.service_name or "").lower():
            if service.port != 443: # common enough to check anyway
                return

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host.address, service.port, ssl=context),
                timeout=self.timeout
            )

            # Get the peer certificate
            cert = writer.get_extra_info('peercert')
            cipher = writer.get_extra_info('cipher')

            tls_info = {
                "cipher": cipher,
                "version": writer.get_extra_info('ssl_object').version()
            }

            if cert:
                # cert will be empty if we used ssl.CERT_NONE and didn't call getpeercert(True)
                # but with open_connection, it might be different.
                # Let's try to get raw cert if needed.
                pass

            service.tls_info = tls_info
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            pass

    async def run(self, host: Host):
        tasks = [self.inspect_tls(host, service) for service in host.services]
        await asyncio.gather(*tasks)
