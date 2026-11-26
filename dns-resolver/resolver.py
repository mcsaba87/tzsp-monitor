"""Tiny reverse-DNS (PTR) sidecar for Grafana.

Grafana / InfluxDB Flux cannot resolve hostnames, so this service does it at
display time. It only resolves the IPs a panel explicitly asks for (the top-10
talkers / the selected IP), and caches every answer, so the upstream DNS server
is never flooded: at most a handful of unique lookups, once each.

    GET /resolve?ips=1.2.3.4,5.6.7.8
    -> [{"ip": "1.2.3.4", "host": "host-a.example.com"}, ...]

When an IP has no PTR record (or the lookup fails/times out) the host falls back
to the raw IP so the caller always gets a value.

Every answer also carries the address's country, from a LOCAL GeoIP database
(see geoip.py and updater below) -- no lookup ever leaves this host:

    -> [{"ip": "8.8.8.8", "host": "dns.google", "cc": "US",
         "country": "United States (US)"}, ...]

    GET /countries  -> [{"cc": "DE", "country": "Germany",
                         "label": "Germany (DE)"}, ...]          (every code)
    GET /geoip      -> which database is loaded, and when it was last updated

And the vendor of a MAC address, from a LOCAL copy of the IEEE registry (see
oui.py and oui_updater below):

    GET /vendor?macs=48:a9:8a:01:02:03,da:a1:19:00:00:01
    -> [{"mac": "48:a9:8a:01:02:03", "vendor": "Routerboard.com"}, ...]
    GET /oui        -> entries loaded, the file's age, the last update attempt

A MAC is the same device whichever site saw it, so like the country this is
not gated on `site=`.

Unlike the PTR, the country is answered for every site: a public address is in
the same country whichever site saw it, and a private one is "local" anywhere.
"""
import gzip
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Bound the system resolver so a slow/absent DNS server can't hang a request.
socket.setdefaulttimeout(2)

_cache = {}
# /resolve: at most this many addresses per request, looked up this many at a time.
RESOLVE_MAX_IPS = 2000
RESOLVE_PARALLEL = 32

# Pinned in grafana/provisioning/datasources/datasource.yml.
LOCAL_SITE_UID = "InfluxDB_Flux"

from geoip import GeoIP  # noqa: E402
from oui import OUI, normalize as normalize_mac  # noqa: E402

# --- GeoIP database --------------------------------------------------------
# The file lives in the `geoip` volume, which the collector mounts read-only:
# this service is the only writer, so the two always agree on a country.
GEOIP_DB = os.getenv("GEOIP_DB", "/geoip/country.mmdb")
# {month} is YYYY-MM. DB-IP publishes a new edition at the start of every month
# under that name; the default is their free "IP to Country Lite" (CC BY 4.0,
# attribution: "IP Geolocation by DB-IP", https://db-ip.com). Anything that
# serves a GeoIP2-compatible country .mmdb (optionally gzipped) works.
GEOIP_URL = os.getenv(
    "GEOIP_URL",
    "https://download.db-ip.com/free/dbip-country-lite-{month}.mmdb.gz")
# false: never download -- for an offline host, or a database dropped into the
# volume by hand (e.g. MaxMind's GeoLite2-Country.mmdb) that must not be
# replaced by the DB-IP one.
GEOIP_UPDATE = os.getenv("GEOIP_UPDATE", "true").strip().lower() not in ("0", "false", "no", "off")
GEOIP_CHECK_SECONDS = int(os.getenv("GEOIP_CHECK_SECONDS", "21600"))
EDITION_FILE = GEOIP_DB + ".edition"

geo = GeoIP(GEOIP_DB)
geo_status = {"last_attempt": None, "last_error": None, "edition": None}


def _month(offset=0):
    now = datetime.now(timezone.utc)
    y, m = now.year, now.month + offset
    while m < 1:
        y, m = y - 1, m + 12
    return f"{y:04d}-{m:02d}"


def _read_edition():
    try:
        with open(EDITION_FILE) as f:
            return f.read().strip() or None
    except OSError:
        return None


def _download(month):
    """Fetch one edition into a temp file next to the target, verify, swap."""
    url = GEOIP_URL.format(month=month)
    d = os.path.dirname(GEOIP_DB) or "."
    fd, tmp = tempfile.mkstemp(prefix=".geoip-", dir=d)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "tzsp-monitor"})
        with urllib.request.urlopen(req, timeout=120) as r, os.fdopen(fd, "wb") as out:
            src = gzip.GzipFile(fileobj=r) if url.endswith(".gz") else r
            shutil.copyfileobj(src, out, 1 << 20)
        # Refuse anything that does not answer like a country database: a
        # captive portal's HTML must never replace a working file.
        probe = GeoIP(tmp)
        if not probe.loaded or probe.country("8.8.8.8")[0] in (None, "unknown"):
            raise ValueError(probe.error or "downloaded file answers no country for 8.8.8.8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, GEOIP_DB)
        with open(EDITION_FILE, "w") as f:
            f.write(month + "\n")
        return url
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def update_once():
    """Bring the database to the current month's edition, if it is not."""
    have = _read_edition()
    geo_status["edition"] = have
    want = _month()
    if geo.loaded and have == want:
        return
    geo_status["last_attempt"] = time.time()
    # The new month's file appears some hours into the month; until then the
    # previous one is current. Only fall back when there is nothing at all.
    tries = [want] if geo.loaded and have else [want, _month(-1)]
    errors = []
    for month in tries:
        if month == have and geo.loaded:
            break
        try:
            url = _download(month)
        except Exception as e:  # noqa: BLE001 -- any failure keeps the old file
            errors.append(f"{month}: {e}")
            continue
        geo.maybe_reload(force=True)
        geo_status.update(edition=month, last_error=None)
        print(f"geoip: installed {url} ({geo.meta.get('database_type')}, "
              f"{geo.meta.get('node_count')} nodes)", flush=True)
        return
    if errors:
        geo_status["last_error"] = "; ".join(errors)
        print(f"geoip: update failed, keeping {'the current file' if geo.loaded else 'NO database'}: "
              f"{geo_status['last_error']}", flush=True)


def updater():
    while True:
        try:
            update_once()
        except Exception as e:  # noqa: BLE001 -- never let the thread die
            print(f"geoip: updater error: {e}", flush=True)
        time.sleep(GEOIP_CHECK_SECONDS)


# --- OUI (MAC vendor) database -------------------------------------------
# Wireshark's `manuf`: the IEEE MA-L/MA-M/MA-S registries merged into one file,
# regenerated weekly -- and the file asks not to be fetched more often than
# that, so the age of the copy on disk is the whole update policy. It lives in
# the `oui` volume, which arp-watch mounts read-only to tag every binding with
# its vendor; this service is the only writer, so the two always agree.
OUI_DB = os.getenv("OUI_DB", "/oui/manuf")
OUI_URL = os.getenv("OUI_URL", "https://www.wireshark.org/download/automated/data/manuf.gz")
OUI_UPDATE = os.getenv("OUI_UPDATE", "true").strip().lower() not in ("0", "false", "no", "off")
OUI_MAX_AGE = int(os.getenv("OUI_MAX_AGE_SECONDS", str(7 * 86400)))
# Cap on one request's MAC list; a dashboard asks for a table's worth.
OUI_MAX_MACS = 1000

oui = OUI(OUI_DB)
oui_status = {"last_attempt": None, "last_error": None}


def _oui_download():
    """Fetch, verify, swap -- the same discipline as the GeoIP download."""
    d = os.path.dirname(OUI_DB) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".oui-", dir=d)
    try:
        req = urllib.request.Request(OUI_URL, headers={"User-Agent": "tzsp-monitor"})
        with urllib.request.urlopen(req, timeout=120) as r, os.fdopen(fd, "wb") as out:
            src = gzip.GzipFile(fileobj=r) if OUI_URL.endswith(".gz") else r
            shutil.copyfileobj(src, out, 1 << 20)
        # A captive portal's HTML parses to nothing, and a truncated download
        # parses to too little: neither may replace a working file.
        probe = OUI(tmp)
        if not probe.loaded or probe.entries < 10000:
            raise ValueError(f"only {probe.entries} entries in the download")
        if "cisco" not in (probe.vendor("00:00:0c:00:00:00") or "").lower():
            raise ValueError("download does not know 00:00:0C (Cisco)")
        os.chmod(tmp, 0o644)
        os.replace(tmp, OUI_DB)
        return probe.entries
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def oui_update_once():
    try:
        age = time.time() - os.stat(OUI_DB).st_mtime
    except OSError:
        age = None
    if oui.loaded and age is not None and age < OUI_MAX_AGE:
        return
    oui_status["last_attempt"] = time.time()
    try:
        entries = _oui_download()
    except Exception as e:  # noqa: BLE001 -- any failure keeps the old file
        oui_status["last_error"] = str(e)
        print(f"oui: update failed, keeping {'the current file' if oui.loaded else 'NO database'}: "
              f"{e}", flush=True)
        return
    oui.maybe_reload(force=True)
    oui_status["last_error"] = None
    print(f"oui: installed {OUI_URL} ({entries} blocks)", flush=True)


def oui_updater():
    while True:
        try:
            oui_update_once()
        except Exception as e:  # noqa: BLE001 -- never let the thread die
            print(f"oui: updater error: {e}", flush=True)
        time.sleep(GEOIP_CHECK_SECONDS)


def country_of(ip):
    geo.maybe_reload()
    code, name = geo.country(ip)
    if code is None:
        return "", ""
    if code in ("local", "unknown"):
        return code, name
    return code, f"{name} ({code})"


def resolve(ip):
    host = _cache.get(ip)
    if host is not None:
        return host
    try:
        host = socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        host = ip  # no PTR / lookup failed -> keep the IP
    _cache[ip] = host
    return host


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/countries":
            geo.maybe_reload()
            return self._json([{"cc": c, "country": n, "label": f"{n} ({c})"}
                               for c, n in sorted(geo.countries().items())])
        if parsed.path == "/geoip":
            return self._json({
                "path": GEOIP_DB, "loaded": geo.loaded, "error": geo.error,
                "update": GEOIP_UPDATE, "url": GEOIP_URL, **geo.meta, **geo_status})
        if parsed.path == "/oui":
            oui.maybe_reload()
            try:
                mtime = os.stat(OUI_DB).st_mtime
            except OSError:
                mtime = None
            return self._json({
                "path": OUI_DB, "loaded": oui.loaded, "entries": oui.entries,
                "error": oui.error, "update": OUI_UPDATE, "url": OUI_URL,
                "file_time": mtime,
                "age_days": round((time.time() - mtime) / 86400, 1) if mtime else None,
                **oui_status})
        if parsed.path == "/vendor":
            oui.maybe_reload()
            result, seen = [], set()
            raw = parse_qs(parsed.query).get("macs", [""])[0]
            for mac in raw.split(",")[:OUI_MAX_MACS]:
                norm = normalize_mac(mac.strip())
                if norm is None or norm in seen:
                    continue
                seen.add(norm)
                result.append({"mac": norm, "vendor": oui.vendor(norm) or ""})
            return self._json(result)
        if parsed.path != "/resolve":
            self.send_response(404)
            self.end_headers()
            return

        query = parse_qs(parsed.query)
        raw = query.get("ips", [""])[0]
        # The dashboards send the uid of the datasource their Site box points
        # at. Another site's private addresses mean nothing to this site's DNS
        # -- 10.0.1.5 there is a different machine from 10.0.1.5 here -- so a
        # PTR from here would be confidently wrong. Answer with the IP instead.
        local = query.get("site", [LOCAL_SITE_UID])[0] in ("", LOCAL_SITE_UID)
        ips, seen = [], set()
        for ip in raw.split(",")[:RESOLVE_MAX_IPS]:
            ip = ip.strip()
            if ip and ip not in seen:
                seen.add(ip)
                ips.append(ip)
        # Uncached addresses are looked up in parallel: a whole subnet asked
        # for at once (the Subnet Hosts board) is hundreds of PTR lookups, and
        # one after another a resolver that times out on each would outlast
        # Grafana's request. Cached answers -- negative ones too -- cost nothing.
        missing = [ip for ip in ips if local and ip not in _cache]
        if len(missing) > 1:
            with ThreadPoolExecutor(max_workers=min(RESOLVE_PARALLEL, len(missing))) as pool:
                list(pool.map(resolve, missing))
        result = []
        for ip in ips:
            cc, country = country_of(ip)
            result.append({"ip": ip, "host": resolve(ip) if local else ip,
                           "cc": cc, "country": country})
        self._json(result)

    def _json(self, result):
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # keep the container logs quiet


if __name__ == "__main__":
    print(f"geoip: {GEOIP_DB} " + (f"loaded ({geo.meta.get('database_type')})" if geo.loaded
          else f"not loaded: {geo.error}") + ("" if GEOIP_UPDATE else "; updates disabled"),
          flush=True)
    if GEOIP_UPDATE:
        threading.Thread(target=updater, name="geoip-updater", daemon=True).start()
    print(f"oui: {OUI_DB} " + (f"loaded ({oui.entries} blocks)" if oui.loaded
          else f"not loaded: {oui.error}") + ("" if OUI_UPDATE else "; updates disabled"),
          flush=True)
    if OUI_UPDATE:
        threading.Thread(target=oui_updater, name="oui-updater", daemon=True).start()
    print("dns-resolver listening on :8000 (GET /resolve?ips=..., /countries, /geoip, "
          "/vendor?macs=..., /oui)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
