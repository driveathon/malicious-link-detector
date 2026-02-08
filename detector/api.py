from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import os
import json
import asyncio
from pydantic import BaseModel
from typing import List, Optional
from . import scan_link, scan_links_async, load_popular_domains
from .database import ScanCache

app = FastAPI(title="Malicious Link Detector API")

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

class ScanRequest(BaseModel):
    url: str
    trace_redirects: bool = True
    check_whois: bool = True
    check_intel: bool = True
    check_ssl: bool = True
    check_visual: bool = True
    google_api_key: Optional[str] = None
    vt_api_key: Optional[str] = None

@app.post("/scan")
async def api_scan(request: ScanRequest):
    """Scan a single URL and return the report."""
    try:
        # We use scan_links_async since it's already async and handles Scanner init
        results = await scan_links_async(
            [request.url],
            trace_redirects=request.trace_redirects,
            check_whois=request.check_whois,
            check_intel=request.check_intel,
            check_ssl=request.check_ssl,
            check_visual=request.check_visual,
            google_api_key=request.google_api_key,
            vt_api_key=request.vt_api_key
        )
        report, cached = results[0]
        return {"report": report, "cached": cached}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history")
async def get_history(limit: int = 20):
    """Retrieve recent scan results from cache."""
    history = cache.get_history(limit=limit)
    return {"history": history}

@app.get("/screenshot/{filename}")
async def get_screenshot(filename: str):
    """Serve a captured screenshot."""
    path = os.path.join("screenshots", filename)
    if os.path.exists(path):
        return FileResponse(path)
    raise HTTPException(status_code=404, detail="Screenshot not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
