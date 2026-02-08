# Skeleton for Discord Bot Integration
import os
import requests

def scan_url_via_api(url):
    api_url = "http://localhost:8000/scan"
    payload = {"url": url}
    try:
        response = requests.post(api_url, json=payload)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

# Placeholder for Discord library integration (e.g. discord.py)
# On message: 
#   Extract URL -> scan_url_via_api(url) -> Reply with report
