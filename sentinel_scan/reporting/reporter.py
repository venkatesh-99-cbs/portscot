import json
import csv
import xml.etree.ElementTree as ET
from sentinel_scan.core.models import ScanResult

class Reporter:
    @staticmethod
    def to_json(result: ScanResult, filepath: str):
        with open(filepath, 'w') as f:
            f.write(result.model_dump_json(indent=4))

    @staticmethod
    def to_txt(result: ScanResult, filepath: str):
        with open(filepath, 'w') as f:
            f.write(f"SentinelScan Report\n")
            f.write(f"===================\n")
            f.write(f"Target: {result.target}\n")
            f.write(f"Start Time: {result.start_time}\n")
            f.write(f"End Time: {result.end_time}\n")
            f.write(f"\nSummary:\n")
            for k, v in result.summary.items():
                f.write(f"  {k}: {v}\n")

            f.write(f"\nHosts:\n")
            for host in result.hosts:
                f.write(f"\n- Host: {host.address} ({host.status})\n")
                if host.os_name:
                    f.write(f"  Estimated OS: {host.os_name} ({host.os_accuracy}% accuracy)\n")
                if host.services:
                    f.write(f"  Services:\n")
                    for svc in host.services:
                        f.write(f"    - {svc.port}/{svc.protocol} {svc.state} {svc.service_name or ''} {svc.banner or ''}\n")

            if result.findings:
                f.write(f"\nFindings:\n")
                for finding in result.findings:
                    f.write(f"\n- [{finding.severity.upper()}] {finding.title}\n")
                    f.write(f"  Description: {finding.description}\n")
                    f.write(f"  Remediation: {finding.remediation}\n")

    @staticmethod
    def to_csv(result: ScanResult, filepath: str):
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Host", "Port", "Protocol", "State", "Service", "Version", "Finding Title", "Finding Severity"])
            for host in result.hosts:
                if not host.services and not host.findings:
                    writer.writerow([host.address, "", "", "", "", "", "", ""])

                # Combine services and findings in rows? Or just services first.
                for svc in host.services:
                    writer.writerow([host.address, svc.port, svc.protocol, svc.state, svc.service_name, svc.version, "", ""])

                for finding in host.findings:
                    writer.writerow([host.address, "", "", "", "", "", finding.title, finding.severity])

    @staticmethod
    def to_markdown(result: ScanResult, filepath: str):
        with open(filepath, 'w') as f:
            f.write(f"# SentinelScan Report\n\n")
            f.write(f"**Target:** {result.target}  \n")
            f.write(f"**Start Time:** {result.start_time}  \n")
            f.write(f"**End Time:** {result.end_time}  \n\n")

            f.write(f"## Summary\n\n")
            for k, v in result.summary.items():
                f.write(f"- **{k}:** {v}\n")

            f.write(f"\n## Hosts\n\n")
            for host in result.hosts:
                f.write(f"### {host.address}\n")
                f.write(f"- **Status:** {host.status}\n")
                if host.os_name:
                    f.write(f"- **Estimated OS:** {host.os_name} ({host.os_accuracy}% accuracy)\n")

                if host.services:
                    f.write(f"\n#### Services\n\n")
                    f.write(f"| Port | Protocol | State | Service | Banner |\n")
                    f.write(f"| --- | --- | --- | --- | --- |\n")
                    for svc in host.services:
                        f.write(f"| {svc.port} | {svc.protocol} | {svc.state} | {svc.service_name or ''} | {svc.banner or ''} |\n")

                if host.findings:
                    f.write(f"\n#### Findings\n\n")
                    for finding in host.findings:
                        f.write(f"- **[{finding.severity.upper()}] {finding.title}**\n")
                        f.write(f"  - *Description:* {finding.description}\n")
                        f.write(f"  - *Remediation:* {finding.remediation}\n")
            f.write("\n")

    @staticmethod
    def to_xml(result: ScanResult, filepath: str):
        root = ET.Element("SentinelScanReport")
        summary = ET.SubElement(root, "Summary")
        for k, v in result.summary.items():
            ET.SubElement(summary, k).text = str(v)

        hosts_elem = ET.SubElement(root, "Hosts")
        for host in result.hosts:
            host_elem = ET.SubElement(hosts_elem, "Host")
            ET.SubElement(host_elem, "Address").text = host.address
            ET.SubElement(host_elem, "OS").text = host.os_name or "Unknown"

            services_elem = ET.SubElement(host_elem, "Services")
            for svc in host.services:
                svc_elem = ET.SubElement(services_elem, "Service")
                ET.SubElement(svc_elem, "Port").text = str(svc.port)
                ET.SubElement(svc_elem, "Protocol").text = svc.protocol
                ET.SubElement(svc_elem, "Banner").text = svc.banner or ""

            findings_elem = ET.SubElement(host_elem, "Findings")
            for finding in host.findings:
                f_elem = ET.SubElement(findings_elem, "Finding")
                ET.SubElement(f_elem, "Title").text = finding.title
                ET.SubElement(f_elem, "Severity").text = finding.severity

        tree = ET.ElementTree(root)
        tree.write(filepath, encoding="utf-8", xml_declaration=True)
