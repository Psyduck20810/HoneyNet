import requests
import time

# IPs to ignore for geolocation (localhost, private ranges)
PRIVATE_IPS = {"127.0.0.1", "::1", "localhost"}

# In-memory cache — avoids hitting ip-api.com rate limit (45 req/min on free tier)
_geo_cache: dict = {}
_GEO_CACHE_TTL = 3600  # 1 hour
_GEO_CACHE_MAX = 1000  # evict oldest 20% when full


def get_location(ip: str) -> dict:
    """
    Look up geolocation for an IP using ip-api.com (free, no key needed).
    Returns dict with country, city, isp, lat, lon.
    Falls back to defaults on error or rate limit.
    Results are cached for 1 hour per IP.
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

    # Return cached result if still fresh
    now = time.time()
    if ip in _geo_cache and now - _geo_cache[ip].get("_cached_at", 0) < _GEO_CACHE_TTL:
        cached = dict(_geo_cache[ip])
        cached.pop("_cached_at", None)
        return cached

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=3,
            params={"fields": "country,countryCode,city,isp,lat,lon,status"}
        )
        data = response.json()

        if data.get("status") == "success":
            result = {
                "country": data.get("country", "Unknown"),
                "countryCode": data.get("countryCode", "XX"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
            }
            # Evict oldest entries if cache is full
            if len(_geo_cache) >= _GEO_CACHE_MAX:
                evict_count = _GEO_CACHE_MAX // 5
                oldest = sorted(_geo_cache, key=lambda k: _geo_cache[k].get("_cached_at", 0))
                for k in oldest[:evict_count]:
                    del _geo_cache[k]
            _geo_cache[ip] = {**result, "_cached_at": now}
            return result
    except Exception as e:
        print(f"[GeoIP] Lookup failed for {ip}: {e}")

    return default
