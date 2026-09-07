"""
geo_tracer.py — Email Hop-by-Hop Geolocation Tracer

Traces the physical transmission path of an email by:
1. Extracting IPs from Received: headers in chronological order
2. Filtering out private/loopback/reserved IP ranges (RFC 1918)
3. Resolving each public IP to geographic coordinates via:
   - MaxMind GeoLite2 offline database (primary)
   - ipinfo.io free API (fallback, 100K requests/month)
   - Demo mock data (offline fallback)
4. Detecting geographic anomalies (sender vs origin mismatch)
5. Generating a GeoJSON-compatible hop path for map rendering
"""

import re
import ipaddress
import os
import json
from typing import Optional


# ═══════════════════════════════════════════════
#  IP Classification
# ═══════════════════════════════════════════════

def is_public_ip(ip_str: str) -> bool:
    """Check if an IP address is routable on the public internet."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_reserved or
            ip_obj.is_multicast or
            ip_obj.is_link_local or
            ip_obj.is_unspecified
        )
    except ValueError:
        return False


def filter_public_ips(ip_list: list) -> list:
    """Filter a list of IPs to only public, routable addresses."""
    return [ip for ip in ip_list if is_public_ip(ip)]


# ═══════════════════════════════════════════════
#  Geolocation Resolvers
# ═══════════════════════════════════════════════

# Well-known demo IPs with realistic geolocation data for offline demos
DEMO_GEO_DATA = {
    "185.220.101.5": {
        "ip": "185.220.101.5",
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "asn": 205100,
        "org": "F3 Netze e.V.",
        "isp": "Tor Exit Node Operator",
        "is_tor": True,
        "is_vpn": False,
        "is_datacenter": True
    },
    "198.51.100.25": {
        "ip": "198.51.100.25",
        "country": "United States",
        "country_code": "US",
        "city": "New York",
        "latitude": 40.7128,
        "longitude": -74.0060,
        "asn": 14061,
        "org": "DigitalOcean LLC",
        "isp": "DigitalOcean",
        "is_tor": False,
        "is_vpn": False,
        "is_datacenter": True
    },
    "203.0.113.50": {
        "ip": "203.0.113.50",
        "country": "India",
        "country_code": "IN",
        "city": "Mumbai",
        "latitude": 19.0760,
        "longitude": 72.8777,
        "asn": 9498,
        "org": "BHARTI Airtel Ltd",
        "isp": "Airtel",
        "is_tor": False,
        "is_vpn": False,
        "is_datacenter": False
    },
    "104.16.132.229": {
        "ip": "104.16.132.229",
        "country": "United States",
        "country_code": "US",
        "city": "San Francisco",
        "latitude": 37.7749,
        "longitude": -122.4194,
        "asn": 13335,
        "org": "Cloudflare Inc",
        "isp": "Cloudflare",
        "is_tor": False,
        "is_vpn": False,
        "is_datacenter": True
    },
    "142.250.190.46": {
        "ip": "142.250.190.46",
        "country": "United States",
        "country_code": "US",
        "city": "Mountain View",
        "latitude": 37.4220,
        "longitude": -122.0841,
        "asn": 15169,
        "org": "Google LLC",
        "isp": "Google",
        "is_tor": False,
        "is_vpn": False,
        "is_datacenter": True
    },
    "45.33.32.156": {
        "ip": "45.33.32.156",
        "country": "United States",
        "country_code": "US",
        "city": "Fremont",
        "latitude": 37.5485,
        "longitude": -121.9886,
        "asn": 63949,
        "org": "Akamai Connected Cloud",
        "isp": "Linode",
        "is_tor": False,
        "is_vpn": False,
        "is_datacenter": True
    },
    "77.247.181.163": {
        "ip": "77.247.181.163",
        "country": "Netherlands",
        "country_code": "NL",
        "city": "Amsterdam",
        "latitude": 52.3676,
        "longitude": 4.9041,
        "asn": 43350,
        "org": "NForce Entertainment B.V.",
        "isp": "NFOrce",
        "is_tor": True,
        "is_vpn": False,
        "is_datacenter": True
    },
    "31.13.71.36": {
        "ip": "31.13.71.36",
        "country": "Ireland",
        "country_code": "IE",
        "city": "Dublin",
        "latitude": 53.3498,
        "longitude": -6.2603,
        "asn": 32934,
        "org": "Facebook Inc",
        "isp": "Meta Platforms",
        "is_tor": False,
        "is_vpn": False,
        "is_datacenter": True
    }
}

# Known Tor exit node ASNs and indicators
TOR_INDICATORS = {'tor', 'exit node', 'relay'}
VPN_INDICATORS = {'vpn', 'proxy', 'anonymizer', 'mullvad', 'nordvpn', 'expressvpn', 'protonvpn'}
DATACENTER_INDICATORS = {
    'digitalocean', 'aws', 'amazon', 'google cloud', 'azure', 'linode',
    'vultr', 'ovh', 'hetzner', 'contabo', 'choopa', 'rackspace'
}


def geolocate_maxmind(ip_str: str, city_db_path: str = None, asn_db_path: str = None) -> Optional[dict]:
    """
    Resolve IP geolocation using MaxMind GeoLite2 offline databases.
    Returns None if database files are not available.
    """
    if not city_db_path:
        # Check default locations
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        city_db_path = os.path.join(base, 'data', 'GeoLite2-City.mmdb')
        asn_db_path = os.path.join(base, 'data', 'GeoLite2-ASN.mmdb')
    
    if not os.path.exists(city_db_path):
        return None
    
    try:
        import geoip2.database
    except ImportError:
        return None
    
    geo_info = {
        "ip": ip_str,
        "country": "Unknown",
        "country_code": "",
        "city": "Unknown",
        "latitude": None,
        "longitude": None,
        "asn": None,
        "org": "Unknown",
        "isp": "Unknown",
        "is_tor": False,
        "is_vpn": False,
        "is_datacenter": False
    }
    
    try:
        with geoip2.database.Reader(city_db_path) as reader:
            resp = reader.city(ip_str)
            geo_info["country"] = resp.country.name or "Unknown"
            geo_info["country_code"] = resp.country.iso_code or ""
            geo_info["city"] = resp.city.name or "Unknown"
            geo_info["latitude"] = resp.location.latitude
            geo_info["longitude"] = resp.location.longitude
    except Exception:
        pass
    
    if asn_db_path and os.path.exists(asn_db_path):
        try:
            with geoip2.database.Reader(asn_db_path) as reader:
                resp = reader.asn(ip_str)
                geo_info["asn"] = resp.autonomous_system_number
                org = resp.autonomous_system_organization or ""
                geo_info["org"] = org
                geo_info["isp"] = org
                
                # Check for anonymizer indicators
                org_lower = org.lower()
                geo_info["is_tor"] = any(ind in org_lower for ind in TOR_INDICATORS)
                geo_info["is_vpn"] = any(ind in org_lower for ind in VPN_INDICATORS)
                geo_info["is_datacenter"] = any(ind in org_lower for ind in DATACENTER_INDICATORS)
        except Exception:
            pass
    
    return geo_info


def geolocate_ipinfo(ip_str: str) -> Optional[dict]:
    """
    Resolve IP geolocation using ipinfo.io free API (100K requests/month).
    """
    try:
        import requests
        resp = requests.get(f"https://ipinfo.io/{ip_str}/json", timeout=5)
        if resp.status_code != 200:
            return None
        
        data = resp.json()
        
        # Parse "loc" field: "lat,lng"
        lat, lng = None, None
        loc = data.get("loc", "")
        if loc and "," in loc:
            parts = loc.split(",")
            lat = float(parts[0])
            lng = float(parts[1])
        
        org_str = data.get("org", "")
        org_lower = org_str.lower()
        
        return {
            "ip": ip_str,
            "country": data.get("country", "Unknown"),
            "country_code": data.get("country", ""),
            "city": data.get("city", "Unknown"),
            "latitude": lat,
            "longitude": lng,
            "asn": org_str.split(" ")[0] if org_str.startswith("AS") else None,
            "org": org_str,
            "isp": org_str,
            "is_tor": any(ind in org_lower for ind in TOR_INDICATORS),
            "is_vpn": any(ind in org_lower for ind in VPN_INDICATORS),
            "is_datacenter": any(ind in org_lower for ind in DATACENTER_INDICATORS)
        }
    except Exception:
        return None


def geolocate_demo(ip_str: str) -> dict:
    """
    Fallback: return demo geolocation data for known IPs,
    or generate plausible mock data for unknown IPs.
    """
    if ip_str in DEMO_GEO_DATA:
        return DEMO_GEO_DATA[ip_str].copy()
    
    # Generate deterministic mock location based on IP octets
    octets = ip_str.split('.')
    if len(octets) == 4:
        # Use octets to seed pseudo-random coordinates
        lat = (int(octets[0]) % 90) * (1 if int(octets[1]) % 2 == 0 else -1)
        lng = (int(octets[2]) % 180) * (1 if int(octets[3]) % 2 == 0 else -1)
    else:
        lat, lng = 0, 0
    
    return {
        "ip": ip_str,
        "country": "Unknown",
        "country_code": "XX",
        "city": "Unknown",
        "latitude": float(lat),
        "longitude": float(lng),
        "asn": None,
        "org": "Unknown Organization",
        "isp": "Unknown ISP",
        "is_tor": False,
        "is_vpn": False,
        "is_datacenter": False
    }


def geolocate_ip(ip_str: str) -> dict:
    """
    Resolve IP geolocation using cascading fallback strategy:
    1. MaxMind GeoLite2 offline DB (fastest, no rate limits)
    2. ipinfo.io free API (online fallback)
    3. Demo mock data (offline fallback for hackathon demos)
    """
    # Try MaxMind first
    result = geolocate_maxmind(ip_str)
    if result and result.get("latitude") is not None:
        result["source"] = "maxmind"
        return result
    
    # Try ipinfo.io
    result = geolocate_ipinfo(ip_str)
    if result and result.get("latitude") is not None:
        result["source"] = "ipinfo"
        return result
    
    # Fall back to demo data
    result = geolocate_demo(ip_str)
    result["source"] = "demo"
    return result


# ═══════════════════════════════════════════════
#  Full Trace Pipeline
# ═══════════════════════════════════════════════

def trace_email_hops(received_hops: list, all_ips: list) -> dict:
    """
    Build a complete geographic trace of an email's transmission path.
    
    Args:
        received_hops: Parsed Received: headers from header_parser
        all_ips: List of all IPs extracted from headers
    
    Returns:
        {
            "hop_path": [...],           # Geolocated hop sequence
            "origin_node": {...},        # First public hop (likely source)
            "destination_node": {...},   # Last hop (recipient's MX)
            "total_public_hops": int,
            "geo_risk_score": float (0-1),
            "geo_indicators": [str],
            "geo_anomalies": [str],
            "geojson": {...}             # GeoJSON FeatureCollection for map
        }
    """
    # Filter to public IPs only
    public_ips = filter_public_ips(all_ips)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_public_ips = []
    for ip in public_ips:
        if ip not in seen:
            seen.add(ip)
            unique_public_ips.append(ip)
    
    # Geolocate each public IP
    hop_path = []
    for idx, ip in enumerate(unique_public_ips):
        geo = geolocate_ip(ip)
        geo["hop_index"] = idx + 1
        
        # Determine role
        if idx == 0:
            geo["role"] = "origin"
        elif idx == len(unique_public_ips) - 1:
            geo["role"] = "destination"
        else:
            geo["role"] = "relay"
        
        hop_path.append(geo)
    
    # Identify origin and destination
    origin = hop_path[0] if hop_path else None
    destination = hop_path[-1] if hop_path else None
    
    # --- Detect Geographic Anomalies ---
    geo_indicators = []
    geo_anomalies = []
    geo_risk = 0.0
    
    if origin:
        # Check if origin is a Tor exit node
        if origin.get("is_tor"):
            geo_risk += 0.40
            geo_anomalies.append(f"Email originates from a Tor exit node ({origin['ip']} in {origin['city']}, {origin['country']})")
            geo_indicators.append("Origin IP is a known Tor exit node — sender is anonymized")
        
        # Check if origin is a VPN
        if origin.get("is_vpn"):
            geo_risk += 0.25
            geo_anomalies.append(f"Email originates from a VPN/proxy server ({origin['org']})")
            geo_indicators.append("Origin IP belongs to a known VPN/proxy service")
        
        # Check if origin is a datacenter (not residential/corporate)
        if origin.get("is_datacenter") and not origin.get("is_tor"):
            geo_risk += 0.15
            geo_indicators.append(f"Origin IP belongs to cloud/datacenter infrastructure ({origin['org']})")
    
    # Check for large geographic spread (possible header forgery)
    if len(hop_path) >= 2:
        countries = set(h.get("country", "") for h in hop_path if h.get("country"))
        if len(countries) > 3:
            geo_risk += 0.10
            geo_indicators.append(f"Email traversed {len(countries)} different countries — unusually complex routing")
    
    geo_risk = min(1.0, geo_risk)
    
    # --- Build GeoJSON for map rendering ---
    geojson = build_geojson(hop_path)
    
    return {
        "hop_path": hop_path,
        "origin_node": origin,
        "destination_node": destination,
        "total_public_hops": len(hop_path),
        "geo_risk_score": round(geo_risk, 3),
        "geo_indicators": geo_indicators,
        "geo_anomalies": geo_anomalies,
        "geojson": geojson
    }


def build_geojson(hop_path: list) -> dict:
    """
    Build a GeoJSON FeatureCollection from the hop path for Leaflet rendering.
    """
    features = []
    coordinates = []
    
    for hop in hop_path:
        lat = hop.get("latitude")
        lng = hop.get("longitude")
        
        if lat is None or lng is None:
            continue
        
        coordinates.append([lng, lat])  # GeoJSON uses [lng, lat]
        
        # Point feature for each hop
        marker_color = "#ef4444"  # red for origin
        if hop.get("role") == "relay":
            marker_color = "#f97316"  # orange
        elif hop.get("role") == "destination":
            marker_color = "#22c55e"  # green
        
        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [lng, lat]
            },
            "properties": {
                "hop_index": hop.get("hop_index", 0),
                "ip": hop.get("ip", ""),
                "city": hop.get("city", "Unknown"),
                "country": hop.get("country", "Unknown"),
                "org": hop.get("org", "Unknown"),
                "role": hop.get("role", ""),
                "is_tor": hop.get("is_tor", False),
                "is_vpn": hop.get("is_vpn", False),
                "is_datacenter": hop.get("is_datacenter", False),
                "marker_color": marker_color
            }
        })
    
    # LineString feature for the path
    if len(coordinates) >= 2:
        features.append({
            "type": "Feature",
            "geometry": {
                "type": "LineString",
                "coordinates": coordinates
            },
            "properties": {
                "type": "route",
                "hop_count": len(coordinates)
            }
        })
    
    return {
        "type": "FeatureCollection",
        "features": features
    }
