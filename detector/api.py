import asyncio
import sys

# Necessary for Playwright/Subprocesses on Windows
# Must be set before any loops are created
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os
import json
import asyncio
import sys
import logging
import time
from pydantic import BaseModel
from typing import List, Optional
from . import scan_link, scan_links_async, scan_link_sync, load_popular_domains
from .database import ScanCache, DB_PATH
from .reports import generate_url_report
import hashlib

# Institutional Logging Setup
audit_logger = logging.getLogger("vault_audit")
audit_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("vault_audit.log")
formatter = logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}')
file_handler.setFormatter(formatter)
audit_logger.addHandler(file_handler)

def log_audit_event(event_type, data):
    event = {"type": event_type, "data": data}
    audit_logger.info(json.dumps(event))

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Malicious Link Detector API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Enable CORS for the React dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize scanner helpers
popular_domains = load_popular_domains()
cache = ScanCache()

@app.get("/")
@limiter.limit("5/minute")
async def root(request: Request):
    """API Root with service information."""
    return {
        "status": "online",
        "service": "FinLink Institutional API",
        "version": "1.1.0",
        "documentation": "/docs",
        "message": "Institutional security active. Real-time audit trail syncing."
    }

class ScanRequest(BaseModel):
    url: str
    trace_redirects: bool = True
    check_whois: bool = True
    check_intel: bool = True
    check_ssl: bool = True
    check_visual: bool = True
    check_geo: bool = True
    google_api_key: Optional[str] = None
    vt_api_key: Optional[str] = None

class BatchScanRequest(BaseModel):
    urls: List[str]
    trace_redirects: bool = True
    check_whois: bool = True
    check_intel: bool = True
    check_ssl: bool = True
    check_visual: bool = True
    google_api_key: Optional[str] = None
    vt_api_key: Optional[str] = None
    
class WebhookRequest(BaseModel):
    url: str
    description: str
    secret: Optional[str] = None

class SettingsUpdateRequest(BaseModel):
    settings: dict

async def trigger_webhooks(url: str, report: dict):
    """Notify institutional endpoints of threat detections."""
    import aiohttp
    import hmac
    import hashlib
    
    webhooks = cache.get_active_webhooks()
    if not webhooks:
        return
        
    payload = {
        "event": "malicious_link_detected",
        "timestamp": time.time(),
        "url": url,
        "report": report
    }
    
    async with aiohttp.ClientSession() as session:
        for wh in webhooks:
            headers = {"Content-Type": "application/json"}
            if wh["secret"]:
                signature = hmac.new(
                    wh["secret"].encode(),
                    json.dumps(payload).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers["X-FinLink-Signature"] = signature
                
            try:
                await session.post(wh["url"], json=payload, headers=headers, timeout=5)
            except Exception as e:
                log_audit_event("webhook_failure", {"url": wh["url"], "error": str(e)})

@app.post("/scan")
@limiter.limit("30/minute")
async def api_scan(request: ScanRequest, fastapi_req: Request, background_tasks: BackgroundTasks):
    """Scan a single URL and return the report."""
    start_time = time.time()
    url = request.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    check_visual = request.check_visual
    # NOTE: Re-enabled on Windows via sync worker
    # if sys.platform == 'win32':
    #     check_visual = False
    #     print("DEBUG INFO: Visual analysis disabled on Windows to prevent event loop crash.")

    print(f"DEBUG: Processing scan: {url} (Platform: {sys.platform})")
    try:
        report = None
        cached = False
        
        # Institutional Grade settings Injection
        node_settings = cache.get_all_settings()
        
        if sys.platform == 'win32':
             print("DEBUG: Using Direct Windows Sync Path")
             # COMPLETE BYPASS: Avoid Scanner init and scan_links_async
             try:
                 loop = asyncio.get_event_loop()
                 report = await loop.run_in_executor(
                     None, 
                     scan_link_sync, 
                     url, 
                     popular_domains, 
                     request.trace_redirects,
                     request.check_whois,
                     request.check_intel,
                     request.check_ssl,
                     check_visual,
                     "screenshots", # dir
                     node_settings # settings dict
                 )
                 # ROBUST PERSISTENCE: Save to cache immediately
                 cache.set(url, report)
                 print("DEBUG: Direct sync scan successful and cached.")
             except Exception as direct_e:
                 print(f"DEBUG ERROR: Direct sync scan failed: {type(direct_e).__name__}: {direct_e}")
                 import traceback
                 traceback.print_exc()
                 log_audit_event("scan_failure", {"url": url, "error": str(direct_e)})
                 raise direct_e
        else:
            # Standard async path for other OSs
            print("DEBUG: Entering standard async path")
            results = await scan_links_async(
                [url],
                trace_redirects=request.trace_redirects,
                check_whois=request.check_whois,
                check_intel=request.check_intel,
                check_ssl=request.check_ssl,
                check_visual=check_visual,
                google_api_key=request.google_api_key,
                vt_api_key=request.vt_api_key
            )
            report, cached = results[0]

        duration = time.time() - start_time
        log_audit_event("scan_completion", {
            "url": url, 
            "is_malicious": report.get("is_malicious", False),
            "latency_ms": int(duration * 1000),
            "cached": cached,
            "ip": fastapi_req.client.host
        })

        # Trigger Institutional Webhooks on Threat
        if report.get("is_malicious"):
            background_tasks.add_task(trigger_webhooks, url, report)
        
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        return {"report": report, "cached": cached, "hash": url_hash}
    except Exception as e:
        import traceback
        print(f"DEBUG ERROR: Scan failed with {type(e).__name__}: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)}")

@app.post("/scan/batch")
@limiter.limit("10/minute")
async def api_scan_batch(request: BatchScanRequest, fastapi_req: Request, background_tasks: BackgroundTasks):
    """Scan multiple URLs in a single request."""
    reports = []
    node_settings = cache.get_all_settings()
    
    if sys.platform == 'win32':
        # Sequential on Windows to avoid Playwright/asyncio conflicts
        for url in request.urls:
            try:
                loop = asyncio.get_event_loop()
                report = await loop.run_in_executor(
                    None,
                    scan_link_sync,
                    url,
                    popular_domains,
                    request.trace_redirects,
                    request.check_whois,
                    request.check_intel,
                    request.check_ssl,
                    request.check_visual,
                    "screenshots", # dir
                    node_settings # settings dict
                )
                cache.set(url, report)
                if report.get("is_malicious"):
                    background_tasks.add_task(trigger_webhooks, url, report)
                reports.append({"url": url, "report": report})
            except Exception as e:
                reports.append({"url": url, "error": str(e)})
    else:
        # Standard async path
        from . import scan_links_async
        results = await scan_links_async(
            request.urls,
            trace_redirects=request.trace_redirects,
            check_whois=request.check_whois,
            check_intel=request.check_intel,
            check_ssl=request.check_ssl,
            check_visual=request.check_visual,
            google_api_key=request.google_api_key,
            vt_api_key=request.vt_api_key
        )
        for i, (report, cached) in enumerate(results):
            url = request.urls[i]
            if report.get("is_malicious"):
                background_tasks.add_task(trigger_webhooks, url, report)
            reports.append({"url": url, "report": report})

    return {"reports": reports}

@app.get("/settings")
async def get_settings():
    """Retrieve node configuration."""
    return cache.get_all_settings()

@app.post("/settings")
async def update_settings(request: SettingsUpdateRequest):
    """Update node configuration."""
    for k, v in request.settings.items():
        cache.set_setting(k, v)
    return {"status": "success", "settings": cache.get_all_settings()}

@app.get("/history")
async def get_history(limit: int = 20):
    """Retrieve recent scan results from cache."""
    history = cache.get_history(limit=limit)
    return {"history": history}

@app.get("/stats")
async def get_stats():
    """Aggregate stats for institutional dashboard."""
    return cache.get_stats()

@app.get("/screenshot/{filename}")
async def get_screenshot(filename: str):
    """Serve a captured screenshot."""
    path = os.path.join("screenshots", filename)
    if os.path.exists(path):
        return FileResponse(path)
    raise HTTPException(status_code=404, detail="Screenshot not found")

@app.get("/report/{url_hash}")
async def get_pdf_report(url_hash: str):
    """Generate and return a PDF report for a given scan."""
    # Find the scan in the database
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute("SELECT url, report_json FROM scans WHERE url_hash = ?", (url_hash,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found in archive")
        
        url, report_json = row
        report_data = json.loads(report_json)
        
        # Create temporary report file
        os.makedirs("reports", exist_ok=True)
        report_filename = f"report_{url_hash}.pdf"
        report_path = os.path.join("reports", report_filename)
        
        generate_url_report(url, report_data, report_path)
        
        return FileResponse(
            report_path, 
            media_type="application/pdf", 
            filename=f"FinLink_Report_{url_hash[:8]}.pdf"
        )
    finally:
        conn.close()

@app.post("/webhooks/register")
async def register_webhook(request: WebhookRequest):
    """Register an external institutional endpoint."""
    cache.register_webhook(request.url, request.description, request.secret)
    log_audit_event("webhook_registered", {"url": request.url})
    return {"status": "success", "message": f"Endpoint {request.url} active."}

@app.get("/webhooks")
async def list_webhooks():
    """List all registered corporate endpoints."""
    return {"webhooks": cache.get_active_webhooks()}

if __name__ == "__main__":
    import uvicorn
    # Necessary for Playwright/Subprocesses on Windows
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
