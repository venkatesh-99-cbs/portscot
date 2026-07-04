import asyncio
import click
import os
import logging
from sentinel_scan.core.engine import ScannerEngine
from sentinel_scan.modules.port_scanner import TCPScanner
from sentinel_scan.modules.udp_scanner import UDPScanner
from sentinel_scan.modules.http_enum import HTTPEnumeration
from sentinel_scan.modules.tls_inspector import TLSInspector
from sentinel_scan.modules.os_fingerprinter import OSFingerprinter
from sentinel_scan.core.plugin_loader import PluginLoader
from sentinel_scan.reporting.reporter import Reporter
from sentinel_scan.utils.logger import setup_logging

@click.command()
@click.argument('targets', nargs=-1)
@click.option('--concurrency', default=100, help='Number of concurrent scans.')
@click.option('--output', help='Output file path.')
@click.option('--format', type=click.Choice(['json', 'txt', 'csv', 'md', 'xml']), default='txt', help='Output format.')
@click.option('--plugins-dir', default='sentinel_scan/plugins', help='Directory to load plugins from.')
@click.option('--verbose', is_flag=True, help='Enable verbose logging.')
def main(targets, concurrency, output, format, plugins_dir, verbose):
    """SentinelScan - Professional Network Security Auditing Framework"""
    setup_logging(level=logging.DEBUG if verbose else logging.INFO)
    if not targets:
        click.echo("No targets specified.")
        return

    async def run_scan():
        engine = ScannerEngine(concurrency=concurrency)

        # Add core modules
        engine.add_module(TCPScanner())
        engine.add_module(UDPScanner())
        engine.add_module(HTTPEnumeration())
        engine.add_module(TLSInspector())
        engine.add_module(OSFingerprinter())

        # Load plugins
        plugins = PluginLoader.load_plugins(plugins_dir)
        for plugin in plugins:
            engine.add_plugin(plugin)
            click.echo(f"Loaded plugin: {plugin.name}")

        click.echo(f"Starting scan on {len(targets)} targets...")
        result = await engine.run(list(targets))

        if output:
            if format == 'json':
                Reporter.to_json(result, output)
            elif format == 'csv':
                Reporter.to_csv(result, output)
            elif format == 'md':
                Reporter.to_markdown(result, output)
            elif format == 'xml':
                Reporter.to_xml(result, output)
            else:
                Reporter.to_txt(result, output)
            click.echo(f"Report saved to {output}")
        else:
            # Print summary to stdout if no output file
            click.echo("\nScan Summary:")
            click.echo(f"Total Hosts: {result.summary['total_hosts']}")
            click.echo(f"Total Findings: {result.summary['total_findings']}")
            for host in result.hosts:
                if host.services:
                    click.echo(f"\nHost {host.address} is UP")
                    for svc in host.services:
                        click.echo(f"  Port {svc.port} ({svc.protocol}) is {svc.state}")

    asyncio.run(run_scan())

if __name__ == '__main__':
    main()
