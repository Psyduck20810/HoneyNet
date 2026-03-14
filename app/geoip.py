import requests

# IPs to ignore for geolocation (localhost, private ranges)
PRIVATE_IPS = {"127.0.0.1", "::1", "localhost"}


def get_location(ip: str) -> dict:
    """
    Look up geolocation for an IP using ip-api.com (free, no key needed).
    Returns dict with country, city, isp, lat, lon.
    Falls back to defaults on error.
    """
    default = {
        "country": "Unknown",
        "countryCode": "XX",
        "city": "Unknown",
        "isp": "Unknown",
        "lat": 0,
        "lon": 0,
    }

    if ip in PRIVATE_IPS or ip.startswith("192.168.") or ip.startswith("10."):
        default["country"] = "Local Network"
        default["city"] = "Localhost"
        return default

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=3,
            params={"fields": "country,countryCode,city,isp,lat,lon,status"}
        )
        data = response.json()

        if data.get("status") == "success":
            return {
                "country": data.get("country", "Unknown"),
                "countryCode": data.get("countryCode", "XX"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
            }
    except Exception as e:
        print(f"[GeoIP] Lookup failed for {ip}: {e}")

    return default
