from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Any
import uuid
from sentinel_scan.core.engine import ScannerEngine
from sentinel_scan.modules.port_scanner import TCPScanner
from sentinel_scan.modules.udp_scanner import UDPScanner
from sentinel_scan.modules.http_enum import HTTPEnumeration
from sentinel_scan.modules.tls_inspector import TLSInspector
from sentinel_scan.modules.os_fingerprinter import OSFingerprinter
from sentinel_scan.modules.nmap_scanner import NmapScanner
from sentinel_scan.core.plugin_loader import PluginLoader

app = FastAPI(title="SentinelScan API")

# Simple in-memory storage for results
results = {}

class ScanRequest(BaseModel):
    targets: List[str]
    concurrency: int = 100
    use_nmap: bool = False

@app.post("/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    results[scan_id] = {"status": "running", "result": None}

    background_tasks.add_task(run_scan_task, scan_id, request.targets, request.concurrency, request.use_nmap)

    return {"scan_id": scan_id, "status": "running"}

@app.get("/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    if scan_id not in results:
        return {"error": "Scan not found"}, 404
    return results[scan_id]

async def run_scan_task(scan_id: str, targets: List[str], concurrency: int, use_nmap: bool):
    engine = ScannerEngine(concurrency=concurrency)
    if use_nmap:
        engine.add_module(NmapScanner())
    else:
        engine.add_module(TCPScanner())
        engine.add_module(UDPScanner())
        engine.add_module(HTTPEnumeration())
        engine.add_module(TLSInspector())
        engine.add_module(OSFingerprinter())

    plugins = PluginLoader.load_plugins('sentinel_scan/plugins')
    for plugin in plugins:
        engine.add_plugin(plugin)

    result = await engine.run(targets)
    results[scan_id] = {"status": "completed", "result": result.model_dump()}
