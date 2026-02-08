import socket
import logging
import requests as sync_requests
from urllib.parse import urlparse

def get_geo_info(domain):
    """
    Fetch geolocation and ASN information for a domain.
    Uses free ip-api.com service.
    """
    info = {
        "ip": "Unknown",
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "lat": 0,
        "lon": 0,
        "status": "fail"
    }

    if not domain:
        return info

    try:
        # 1. Resolve domain to IP
        ip_addr = socket.gethostbyname(domain)
        info["ip"] = ip_addr

        # 2. Query ip-api for metadata
        # Documentation: https://ip-api.com/docs/api:json
        endpoint = f"http://ip-api.com/json/{ip_addr}?fields=status,message,country,city,lat,lon,isp,query"
        resp = sync_requests.get(endpoint, timeout=5)
        
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                info["country"] = data.get("country", "Unknown")
                info["city"] = data.get("city", "Unknown")
                info["isp"] = data.get("isp", "Unknown")
                info["lat"] = data.get("lat", 0)
                info["lon"] = data.get("lon", 0)
                info["status"] = "success"
            else:
                logging.warning(f"GeoIP query failed: {data.get('message')}")
    except socket.gaierror:
        logging.error(f"DNS resolution failed for domain: {domain}")
    except Exception as e:
        logging.error(f"GeoIP generic error: {e}")

    return info
