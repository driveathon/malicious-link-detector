from playwright.async_api import async_playwright
import os
import logging
from urllib.parse import urlparse

async def capture_screenshot(url, output_path, shared_browser=None):
    """Capture a screenshot of a webpage using Playwright."""
    if shared_browser:
        return await _capture_with_browser(shared_browser, url, output_path)
        
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        try:
            return await _capture_with_browser(browser, url, output_path)
        finally:
            await browser.close()

async def _capture_with_browser(browser, url, output_path):
    """Internal helper to capture using an existing browser."""
    page = await browser.new_page()
    try:
        await page.goto(url, timeout=15000, wait_until="networkidle")
        await page.screenshot(path=output_path)
        return True
    except Exception as e:
        logging.error(f"Failed to capture screenshot for {url}: {e}")
        return False
    finally:
        await page.close()

def capture_screenshot_sync(url, output_path):
    """Synchronous version of screenshot capture for Windows/Sync paths."""
    from playwright.sync_api import sync_playwright
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=15000, wait_until="networkidle")
            page.screenshot(path=output_path)
            browser.close()
            return True
    except Exception as e:
        logging.error(f"Sync screenshot failed: {e}")
        return False

async def analyze_visual_impersonation(url, screenshot_path):
    # Skeleton...
    return {
        "impersonation_risk": "Low", 
        "details": "Visual analysis requires connection to a Vision API."
    }

def analyze_visual_impersonation_sync(url, screenshot_path):
    """Sync version of visual impersonation analysis."""
    return {
        "impersonation_risk": "Low", 
        "details": "Visual analysis requires connection to a Vision API."
    }
