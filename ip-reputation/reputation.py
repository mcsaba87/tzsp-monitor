r"""Public IP reputation feeds -> one Mikrotik address list, driven from Grafana.

    Spamhaus DROP, abuse.ch Feodo, ... --> [this service] --> /ip/firewall/address-list
                                                         '-> InfluxDB (audit, counters)

The responder blocks what *this* network's IDS saw; this blocks what the rest
of the internet already knows about, before it gets here. Same control-surface
trick as dns-filter: the Infinity datasource fetches `/apply?enable=<feed>` on a
panel refresh, so one click on a feed is one HTTP call, and the panel renders
the state that call produced.

Things that are easy to get wrong, and why the code is shaped the way it is:

* **Feeds contain addresses you must never block.** FireHOL level1 ships the
  bogons -- 10.0.0.0/8, 192.168.0.0/16, 0.0.0.0/8 -- on purpose, and a
  `src-address-list` drop rule built on it cuts off the LAN. Every entry that
  *overlaps* a private, reserved, multicast or CGNAT range, `suricata.home_net`,
  `whitelist.*`, the router itself or `ip_reputation.never` is dropped before
  anything reaches the router, and prefixes shorter than
  `ip_reputation.min_prefix` are refused outright. Dropped counts are shown
  per feed, so the filtering is visible rather than silent.

* **A broken download must not empty the list.** A feed host that answers 200
  with an error page parses to nothing, and reconciling that would delete
  thousands of entries and re-add them an hour later. A feed that parses to
  zero, or to less than half of its last good copy, is refused and the last
  good copy is kept -- the feed reads ERROR with the reason, and still serves.

* **Entries expire router-side** (`ip_reputation.entry_timeout`, 3d), so the
  list fails open if this stack stops, and a router reboot (timeout entries
  are dynamic, not saved) is healed on the next pass rather than leaving a
  stale permanent list. Each pass refreshes entries with less than a third of
  their timeout left, which spreads the PATCHes out over days.

* **The list blocks nothing until a firewall rule references it**, exactly
  like the responder's -- and that rule is made by hand on purpose. Unlike the
  responder, this service *checks* for it: `/ip/firewall/raw` and `/filter` are
  read for enabled rules naming the list, and the tile reads NO FIREWALL RULE
  instead of looking healthy. Their packet counters are the only evidence that
  the list is doing anything.

* **The router is talked to over one kept-alive connection.** A first load is
  thousands of REST calls, one per entry (RouterOS has no bulk add), and a
  fresh TLS handshake per call would make that take most of an hour.

* **Only rows whose comment starts with `ip_reputation.comment_prefix:` are
  ever touched**, so a hand-made entry on the same list survives everything.
"""
import base64
import csv
import http.client
import io
import ipaddress
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROPERTIES_FILE = os.getenv("PROPERTIES_FILE", "/etc/tzsp-monitor/suricata.properties")
STATE_DIR = os.getenv("STATE_DIR", "/var/lib/ip-reputation")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8070"))     # control, not published

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "my-org")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")

STATE_FILE = os.path.join(STATE_DIR, "state.json")
CACHE_DIR = os.path.join(STATE_DIR, "feeds")        # last good copy of each feed

# The catalogue. Every URL and format here was fetched and checked: `cidr`
# takes the first IPv4 address or CIDR on each line (plain lists, netsets, and
# Spamhaus' one-JSON-object-per-line format alike); `dshield` is
# start/end/prefix-length columns, where the first column alone would block
# one address of each /24.
FEEDS = {
    "spamhaus_drop": {
        "title": "Spamhaus DROP",
        "url": "https://www.spamhaus.org/drop/drop_v4.json", "format": "cidr",
        "about": "Netblocks hijacked or leased by professional spam and "
                 "cybercrime operations (EDROP was merged into it in 2024). "
                 "Small and very low on false positives -- the safe first choice.",
    },
    "feodo": {
        "title": "abuse.ch Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "format": "cidr",
        "about": "Live botnet C2 servers (the Emotet/Dridex/QakBot family). Tiny "
                 "and high-confidence; the outbound (dst) rule is the one that "
                 "matters for it.",
    },
    "et_compromised": {
        "title": "Emerging Threats compromised hosts",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "format": "cidr",
        "about": "Hosts known to be compromised and seen attacking. A few "
                 "hundred addresses.",
    },
    "dshield": {
        "title": "DShield top attackers",
        "url": "https://feeds.dshield.org/block.txt", "format": "dshield",
        "about": "The 20 /24 networks reported most for attacks in the last "
                 "three days, from the SANS Internet Storm Center.",
    },
    "firehol_level1": {
        "title": "FireHOL level 1",
        "url": "https://iplists.firehol.org/files/firehol_level1.netset",
        "format": "cidr",
        "about": "An aggregate of Spamhaus DROP, Feodo, DShield and others, "
                 "tuned for few false positives. It also lists the bogons "
                 "(private and reserved ranges); those are always dropped here.",
    },
    "cinsscore": {
        "title": "CINS Army",
        "url": "https://cinsscore.com/list/ci-badguys.txt", "format": "cidr",
        "about": "15,000 addresses with a poor reputation on Sentinel IPS "
                 "sensors. Larger and noisier than the above.",
    },
    "blocklist_de": {
        "title": "blocklist.de (all)",
        "url": "https://lists.blocklist.de/lists/all.txt", "format": "cidr",
        "about": "~25,000 addresses reported for SSH, mail and web-login attacks "
                 "in the last 48 h. Large and churns hourly -- mind "
                 "ip_reputation.max_entries.",
    },
    "tor_exit": {
        "title": "Tor exit nodes",
        "url": "https://check.torproject.org/torbulkexitlist", "format": "cidr",
        "about": "Policy, not threat: the Tor network's exits. Blocking them "
                 "breaks legitimate Tor users as well as abuse.",
    },
}

# Never blocked whatever a feed says. Overlap, not containment: a feed's
# 10.0.0.0/7 contains no protected network but covers half of one.
PROTECTED = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
             "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
             "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
             "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"]

CIDR_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?(?![\d.])")

_state_lock = threading.Lock()
_log_lock = threading.Lock()
_wake = threading.Event()
_syncing = threading.Event()
_progress = {}              # router name -> live counters of its reconcile
_router_views = {}          # router name -> last probe, rules and result
_desired_lock = threading.Lock()
_desired = {}               # the last merge: {address: feed}, for the hit watcher
_desired_index = {}         # the same, keyed for a supernet lookup


def log(msg):
    with _log_lock:
        sys.stdout.write(f"{datetime.now().strftime('%H:%M:%S')} {msg}\n")
        sys.stdout.flush()


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def age_seconds(stamp):
    if not stamp:
        return -1
    try:
        when = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S UTC").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return -1
    return int((datetime.now(timezone.utc) - when).total_seconds())


def duration_seconds(text, default=0):
    """RouterOS duration -- `3d`, `2d23h59m51s`, `1w`, `23:59:58`, `1d02:00:00`."""
    text = (text or "").strip().lower()
    if not text:
        return default
    total = 0
    clock = re.search(r"(\d+):(\d\d):(\d\d)$", text)
    if clock:
        h, m, s = (int(x) for x in clock.groups())
        total += h * 3600 + m * 60 + s
        text = text[:clock.start()]
    units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    parts = re.findall(r"(\d+)(ms|[wdhms]?)", text)
    if "".join(n + u for n, u in parts) != text:
        return default
    for number, unit in parts:
        if unit != "ms":
            total += int(number) * units[unit or "s"]
    return total


# ---------------------------------------------------------------------------
# Property file -- the same `key = value` file the responder reads
# ---------------------------------------------------------------------------
class Config:
    def __init__(self, path):
        self.values = {}
        self.present = os.path.isfile(path)
        if not self.present:
            log(f"no property file at {path}: nothing is sent to a router. "
                f"Copy suricata.properties.example.")
            return
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith(("#", "!")) or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                self.values[key.strip()] = value.strip()

    def get(self, key, default=""):
        return self.values.get(key, default)

    def get_int(self, key, default):
        try:
            return int(self.get(key, "") or default)
        except ValueError:
            log(f"{key}: not an integer, using {default}")
            return default

    def get_bool(self, key, default):
        value = self.get(key, "").lower()
        if value in ("true", "yes", "1", "on"):
            return True
        if value in ("false", "no", "0", "off"):
            return False
        return default

    def get_list(self, key):
        return [item.strip() for item in self.get(key).split(",") if item.strip()]


# ---------------------------------------------------------------------------
# Several routers. The same block in responder.py, dns-filter/filter.py and
# ip-reputation/reputation.py (each service is its own build context, and they
# are stdlib-only single files) -- keep them in step.
# ---------------------------------------------------------------------------
ROLES = ("block", "quarantine", "dns_filter", "ip_reputation", "scanners")
_warned = set()


def warn_once(msg):
    """Config complaints are found on every lookup; say each one once."""
    if msg not in _warned:
        _warned.add(msg)
        log(msg)


class RouterConfig(Config):
    """One router's view of the property file.

    The unprefixed `mikrotik.*` keys are the first router (named by
    `mikrotik.name`, default `main`), exactly as before there was more than
    one. `mikrotik.routers` names the rest; each reads `mikrotik.<name>.<key>`
    first and falls back to the unprefixed key, so a second router usually
    needs only a host and a password. `host` and `roles` are never inherited:
    a router nobody named must not be reached by accident, and narrowing the
    first router's roles must not narrow everyone's.
    """

    NOT_INHERITED = ("host", "roles")

    def __init__(self, base, name, primary):          # noqa: super not called
        self.path = getattr(base, "path", "")
        self.values, self.present = base.values, base.present
        self.name, self.primary = name, primary

    def get(self, key, default=""):
        if key.startswith("mikrotik.") and not self.primary:
            sub = key[len("mikrotik."):]
            own = self.values.get(f"mikrotik.{self.name}.{sub}")
            if own is not None:
                return own
            if sub in self.NOT_INHERITED:
                return default
        return self.values.get(key, default)

    @property
    def roles(self):
        """`mikrotik[.<name>].roles`; empty means every role."""
        listed = {r.strip().lower() for r in self.get("mikrotik.roles").split(",")
                  if r.strip()}
        unknown = listed - set(ROLES)
        if unknown:
            warn_once(f"router {self.name}: unknown role(s) {', '.join(sorted(unknown))} "
                f"ignored (known: {', '.join(ROLES)})")
        return (listed & set(ROLES)) or set(ROLES)


def router_hosts(cfg):
    """The address of every router, whatever its roles -- never to be blocked
    or quarantined by anything here."""
    hosts = []
    for role in ROLES:
        for rc in router_configs(cfg, role):
            host = rc.get("mikrotik.host")
            if host and host not in hosts:
                hosts.append(host)
    return hosts


def router_configs(cfg, role):
    """Every router that has `role`, the first router first. The first one is
    left out only when it has no host and others are listed -- a setup that
    names its routers explicitly does not need the unprefixed ones."""
    names = [(cfg.get("mikrotik.name", "main").strip().lower() or "main")]
    for name in cfg.get_list("mikrotik.routers"):
        name = name.lower()
        if not re.fullmatch(r"[a-z0-9_\-]{1,32}", name) or name in names:
            warn_once(f"mikrotik.routers: ignoring {name!r} (bad or duplicate name)")
            continue
        names.append(name)
    routers = [RouterConfig(cfg, name, i == 0) for i, name in enumerate(names)]
    if len(routers) > 1 and not routers[0].get("mikrotik.host"):
        routers = routers[1:]
    return [rc for rc in routers if role in rc.roles]


# ---------------------------------------------------------------------------
# InfluxDB
# ---------------------------------------------------------------------------
def esc_tag(value):
    return (str(value).replace("\\", "\\\\").replace(" ", "\\ ")
            .replace(",", "\\,").replace("=", "\\="))


def esc_str(value):
    flat = str(value).replace("\r", " ").replace("\n", " ")
    return '"' + flat.replace("\\", "\\\\").replace('"', '\\"') + '"'


def influx_write(lines):
    if not lines:
        return
    endpoint = (f"{INFLUX_URL.rstrip('/')}/api/v2/write"
                f"?org={urllib.parse.quote(INFLUX_ORG)}"
                f"&bucket={urllib.parse.quote(INFLUX_BUCKET)}&precision=s")
    req = urllib.request.Request(
        endpoint, data="\n".join(lines).encode(), method="POST",
        headers={"Authorization": f"Token {INFLUX_TOKEN}",
                 "Content-Type": "text/plain; charset=utf-8"})
    try:
        urllib.request.urlopen(req, timeout=10).close()
    except urllib.error.HTTPError as exc:
        log(f"influx write rejected ({exc.code}): {exc.read()[:300]!r}")
    except (urllib.error.URLError, OSError) as exc:
        log(f"influx write failed: {exc}")


def audit(action, feed, detail=""):
    """When a feed was switched on or off. Like every audit trail in this
    stack it can say when, never who: Infinity calls run as the datasource."""
    influx_write([f"ip_reputation_control,action={esc_tag(action)},"
                  f"feed={esc_tag(feed or 'all')} count=1i,"
                  f"detail={esc_str((detail or 'from the dashboard')[:200])}"])


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
def read_state():
    try:
        with open(STATE_FILE) as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        state = {}
    state.setdefault("feeds", {})
    state.setdefault("last_update", {})
    state.setdefault("last_sync", {})
    return state


def write_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=1, sort_keys=True)
    os.replace(tmp, STATE_FILE)


# ---------------------------------------------------------------------------
# Feeds: download, parse, filter, merge -- all pure but the download
# ---------------------------------------------------------------------------
def parse_feed(text, fmt):
    """Every IPv4 network in a feed. Comments (`#`, `;`) and IPv6 are skipped;
    host bits are cleared rather than refused, since feeds are not careful."""
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        if fmt == "dshield":
            cols = line.split()
            if len(cols) < 3 or not cols[2].isdigit() or not CIDR_RE.fullmatch(cols[0]):
                continue                     # the column header, or junk
            token = f"{cols[0]}/{cols[2]}"
        else:
            match = CIDR_RE.search(line)
            if not match:
                continue
            token = match.group(1) + (match.group(2) or "")
        try:
            nets.append(ipaddress.IPv4Network(token, strict=False))
        except ValueError:
            continue
    return nets


def protected_networks(cfg):
    """PROTECTED plus everything the operator called ours."""
    items = list(PROTECTED)
    items += cfg.get("suricata.home_net").strip("[]").split(",")
    for key in ("whitelist.networks", "whitelist.ips", "ip_reputation.never"):
        items += cfg.get_list(key)
    items += router_hosts(cfg)              # every router, whatever its roles
    return v4_networks(items)


def home_networks(cfg):
    """`suricata.home_net` alone: what the hit watcher calls internal. The
    negations (`!10.9.0.0/16`) are skipped, as protected_networks skips them --
    erring towards calling a host ours, which only ever costs a hit, never
    attributes one to the wrong side."""
    return v4_networks(cfg.get("suricata.home_net").strip("[]").split(","))


def v4_networks(items):
    nets = []
    for item in items:
        item = item.strip()
        if not item or item.startswith(("!", "$")):
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue                        # a host name, or a typo
        if net.version == 4:
            nets.append(net)
    return list(ipaddress.collapse_addresses(nets))


def address_of(net):
    """What RouterOS shows in `address`: a bare IP for a /32, a CIDR otherwise."""
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def build_desired(parsed, protected, min_prefix, budget):
    """Merge feeds into {address: feed}.

    `parsed` is {feed: [networks]}. Smallest feed first, the same reasoning as
    dns-filter's render order: whoever goes first keeps an address two feeds
    share, so the order decides who survives the budget, and smallest-first
    buys the most whole feeds and leaves the single biggest one to truncate
    itself. A network already covered by an earlier, broader one is skipped --
    found by looking its supernets up, not by comparing against every entry.

    Returns (desired, stats) where stats[feed] has raw/dropped/duplicate/
    kept/capped.
    """
    desired, chosen, stats = {}, set(), {}
    order = sorted(parsed, key=lambda f: (len(parsed[f]), f))
    for feed in order:
        raw = parsed[feed]
        stat = {"raw": len(raw), "dropped": 0, "duplicate": 0, "kept": 0,
                "merged": 0, "capped": False}
        stats[feed] = stat
        safe = []
        for net in raw:
            if net.prefixlen < min_prefix or any(net.overlaps(p) for p in protected):
                stat["dropped"] += 1
                continue
            safe.append(net)
        collapsed = list(ipaddress.collapse_addresses(safe))
        stat["merged"] = len(safe) - len(collapsed)   # adjacent blocks joined
        for net in collapsed:
            if any(net.supernet(new_prefix=plen) in chosen
                   for plen in range(net.prefixlen, min_prefix - 1, -1)):
                stat["duplicate"] += 1
                continue
            if len(desired) >= budget:
                stat["capped"] = True
                break
            chosen.add(net)
            desired[address_of(net)] = feed
            stat["kept"] += 1
    return desired, stats


def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "tzsp-monitor/ip-reputation"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(32 * 1024 * 1024).decode("utf-8", "replace")


def cache_path(feed):
    return os.path.join(CACHE_DIR, f"{feed}.txt")


def update_feed(feed, entry):
    """Download one feed, keeping the last good copy if the new one is
    implausible. Mutates `entry` (the feed's state) and returns nothing."""
    spec = FEEDS[feed]
    previous = entry.get("raw", 0)
    try:
        text = fetch(spec["url"])
    except (urllib.error.URLError, OSError, ValueError) as exc:
        entry.update(state="error", detail=f"download failed: {exc}"[:200]
                     + ("" if os.path.isfile(cache_path(feed))
                        else " -- no earlier copy, contributing nothing"))
        return
    count = len(parse_feed(text, spec["format"]))
    if count == 0:
        entry.update(state="error",
                     detail="the download parsed to no addresses -- an error "
                            "page? keeping the last good copy")
        return
    if previous >= 100 and count < previous / 2:
        entry.update(state="error",
                     detail=f"shrank from {previous} to {count} entries at once "
                            f"-- refused, keeping the last good copy")
        return
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp = cache_path(feed) + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, cache_path(feed))
    entry.update(state="ok", detail=f"{count} networks in the feed",
                 raw=count, fetched_at=now_utc())


def load_cached(feed):
    try:
        with open(cache_path(feed)) as fh:
            return parse_feed(fh.read(), FEEDS[feed]["format"])
    except OSError:
        return []


# ---------------------------------------------------------------------------
# RouterOS REST, over one kept-alive connection
# ---------------------------------------------------------------------------
class RouterError(Exception):
    pass


class Mikrotik:
    def __init__(self, cfg):
        self.name = getattr(cfg, "name", "main")
        self.enabled = cfg.get_bool("mikrotik.enabled", True)
        self.host = cfg.get("mikrotik.host")
        self.user = cfg.get("mikrotik.user")
        self.password = cfg.get("mikrotik.password")
        self.scheme = cfg.get("mikrotik.scheme", "https")
        self.port = cfg.get_int("mikrotik.port", 443 if self.scheme == "https" else 80)
        self.request_timeout = cfg.get_int("mikrotik.request_timeout", 5)
        self.dry_run = cfg.get_bool("ip_reputation.dry_run", False)
        if self.scheme == "https" and not cfg.get_bool("mikrotik.verify_tls", False):
            self.context = ssl._create_unverified_context()
        else:
            self.context = ssl.create_default_context()
        token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}",
                        "Content-Type": "application/json",
                        "Connection": "keep-alive"}
        self.lock = threading.Lock()
        self.conn = None

    @property
    def configured(self):
        return bool(self.enabled and self.host and self.user and self.password)

    def _connect(self, timeout):
        if self.scheme == "https":
            return http.client.HTTPSConnection(self.host, self.port, timeout=timeout,
                                               context=self.context)
        return http.client.HTTPConnection(self.host, self.port, timeout=timeout)

    def call(self, method, path, body=None, timeout=None):
        data = json.dumps(body).encode() if body is not None else None
        timeout = timeout or self.request_timeout
        with self.lock:
            for attempt in (1, 2):
                if self.conn is None:
                    self.conn = self._connect(timeout)
                self.conn.timeout = timeout
                if self.conn.sock is not None:
                    self.conn.sock.settimeout(timeout)
                try:
                    self.conn.request(method, "/rest" + path, body=data,
                                      headers=self.headers)
                    resp = self.conn.getresponse()
                    raw = resp.read()
                except (http.client.HTTPException, OSError, ssl.SSLError) as exc:
                    # A kept-alive connection the router closed in between looks
                    # exactly like this; one retry on a fresh one tells it apart
                    # from a router that is really gone.
                    self.conn.close()
                    self.conn = None
                    if attempt == 2:
                        raise RouterError(str(exc) or type(exc).__name__) from exc
                    continue
                if resp.status >= 400:
                    raise RouterError(f"HTTP {resp.status} "
                                      f"{raw.decode('utf-8', 'replace')[:300]}")
                return json.loads(raw) if raw.strip() else None
        return None

    def probe(self):
        started = time.monotonic()
        resource = self.call("GET", "/system/resource") or {}
        return {"up": 1, "latency_ms": (time.monotonic() - started) * 1000.0,
                "version": resource.get("version", "unknown"), "probed_at": now_utc()}

    def rules(self, list_name):
        """Enabled raw/filter rules that reference the list, with counters."""
        found = []
        for table in ("raw", "filter"):
            rows = self.call("GET", f"/ip/firewall/{table}", timeout=30) or []
            for row in rows:
                if list_name not in (row.get("src-address-list"),
                                     row.get("dst-address-list")):
                    continue
                if str(row.get("disabled", "false")).lower() == "true":
                    continue
                found.append({"table": table, "chain": row.get("chain", ""),
                              "action": row.get("action", ""),
                              "side": "src" if row.get("src-address-list") == list_name
                                      else "dst",
                              "packets": int(str(row.get("packets", 0) or 0)),
                              "bytes": int(str(row.get("bytes", 0) or 0))})
        return found

    def list_rows(self, list_name):
        query = urllib.parse.urlencode({
            "list": list_name, ".proplist": ".id,address,comment,timeout,disabled"})
        return self.call("GET", f"/ip/firewall/address-list?{query}", timeout=180) or []


def reconcile(router, list_name, prefix, desired, rows, timeout, refresh_below,
              progress=None, stop_after_errors=20):
    """Make the managed rows of `list_name` equal `desired`. Returns counters.

    Pure apart from `router.call`, so the selftest drives it with a stub.
    """
    progress = progress if progress is not None else {}
    counts = {"added": 0, "removed": 0, "refreshed": 0, "foreign": 0, "errors": 0,
              "kept": 0}
    managed = {}
    for row in rows:
        if str(row.get("comment", "")).startswith(prefix + ":"):
            managed[row.get("address", "")] = row
    progress.update(phase="removing", todo=0, done=0)

    def run(method, path, body=None):
        if router.dry_run:
            return True
        try:
            router.call(method, path, body)
            return True
        except RouterError as exc:
            if "already have such entry" in str(exc):
                counts["foreign"] += 1      # a hand-made row with this address
                return False
            counts["errors"] += 1
            if counts["errors"] <= 3:
                log(f"router: {method} {path} failed: {exc}")
            if counts["errors"] >= stop_after_errors:
                raise
            return False

    going = [row for address, row in managed.items() if address not in desired]
    adding = [address for address in desired if address not in managed]
    stale = [row for address, row in managed.items()
             if address in desired
             and duration_seconds(row.get("timeout"), -1) >= 0
             and duration_seconds(row.get("timeout")) < refresh_below] if timeout else []
    progress.update(todo=len(going) + len(adding) + len(stale))

    for row in going:
        row_id = urllib.parse.quote(row.get(".id", ""), safe="*")
        if run("DELETE", f"/ip/firewall/address-list/{row_id}"):
            counts["removed"] += 1
        progress["done"] = progress.get("done", 0) + 1
    progress["phase"] = "adding"
    for address in adding:
        entry = {"list": list_name, "address": address,
                 "comment": f"{prefix}:{desired[address]}"}
        if timeout:
            entry["timeout"] = timeout
        if run("PUT", "/ip/firewall/address-list", entry):
            counts["added"] += 1
        progress["done"] = progress.get("done", 0) + 1
    progress["phase"] = "refreshing"
    for row in stale:
        row_id = urllib.parse.quote(row.get(".id", ""), safe="*")
        patch = {"timeout": timeout,
                 "comment": f"{prefix}:{desired[row.get('address')]}"}
        if run("PATCH", f"/ip/firewall/address-list/{row_id}", patch):
            counts["refreshed"] += 1
        progress["done"] = progress.get("done", 0) + 1
    counts["kept"] = len(managed) - len(going)
    progress["phase"] = "done"
    return counts


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CFG = Config(PROPERTIES_FILE)
CONTROL_ENABLED = CFG.get_bool("ip_reputation.control_enabled", True)
LIST_NAME = CFG.get("ip_reputation.address_list", "reputation-blocked")
PREFIX = CFG.get("ip_reputation.comment_prefix", "iprep")
ENTRY_TIMEOUT = CFG.get("ip_reputation.entry_timeout", "3d")
REFRESH_BELOW = duration_seconds(ENTRY_TIMEOUT, 3 * 86400) // 3
MAX_ENTRIES = CFG.get_int("ip_reputation.max_entries", 30000)
MIN_PREFIX = max(1, min(CFG.get_int("ip_reputation.min_prefix", 8), 32))
UPDATE_INTERVAL = CFG.get_int("ip_reputation.update_interval_hours", 12) * 3600
MIN_UPDATE_INTERVAL = CFG.get_int("ip_reputation.min_update_seconds", 1800)
SYNC_INTERVAL = CFG.get_int("ip_reputation.sync_minutes", 15) * 60
HEALTH_INTERVAL = CFG.get_int("ip_reputation.health_interval", 60)
SEED_FEEDS = [f.lower() for f in CFG.get_list("ip_reputation.feeds")]
PROTECTED_NETS = protected_networks(CFG)
HOME_NETS = home_networks(CFG)
HITS_INTERVAL = CFG.get_int("ip_reputation.hits_interval", 60)
ROUTERS = [Mikrotik(rc) for rc in router_configs(CFG, "ip_reputation")]
DRY_RUN = CFG.get_bool("ip_reputation.dry_run", False)


def view_of(router):
    return _router_views.setdefault(router.name, {})


# ---------------------------------------------------------------------------
# Actions -- idempotent, because Grafana re-sends them on every refresh
# ---------------------------------------------------------------------------
def apply_actions(params):
    enable = (params.get("enable", [""])[0] or "").strip().lower()
    disable = (params.get("disable", [""])[0] or "").strip().lower()
    update = (params.get("update", [""])[0] or "").strip().lower()
    note = (params.get("note", [""])[0] or "")[:200]
    messages = []
    if not (enable or disable or update):
        return messages
    if not CONTROL_ENABLED:
        return ["ip_reputation.control_enabled = false: read-only"]
    dirty = False
    with _state_lock:
        state = read_state()
        feeds = state["feeds"]
        if disable == "all":
            if feeds:
                for name in list(feeds):
                    audit("disable", name, note)
                messages.append(f"removed all {len(feeds)} feeds")
                state["feeds"] = feeds = {}
                dirty = True
        elif disable in feeds:
            del feeds[disable]
            messages.append(f"removed {disable}")
            audit("disable", disable, note)
            dirty = True
        # The add box is re-sent every refresh; a stale remove box would
        # otherwise take a feed away again on the next one.
        if enable and enable not in FEEDS:
            messages.append(f"unknown feed {enable!r}")
        elif enable and enable not in feeds:
            feeds[enable] = {"since": now_utc(), "note": note, "state": "pending",
                             "detail": "queued", "raw": 0}
            messages.append(f"added {enable}")
            audit("enable", enable, note)
            dirty = True
        if update in ("now", "1", "true", "yes"):
            since = age_seconds(state["last_update"].get("at"))
            if 0 <= since < MIN_UPDATE_INTERVAL:
                messages.append(f"update skipped: last one was {since // 60} min ago "
                                f"(ip_reputation.min_update_seconds)")
            else:
                state["last_update"]["requested"] = now_utc()
                messages.append("update requested")
                audit("update", "", note)
                dirty = True
        if dirty:
            write_state(state)
    if dirty:
        _wake.set()
    return messages


# ---------------------------------------------------------------------------
# Worker: downloads, merges, reconciles
# ---------------------------------------------------------------------------
def sync_once():
    _syncing.set()
    try:
        with _state_lock:
            state = read_state()
        wanted = {name: dict(entry) for name, entry in state["feeds"].items()
                  if name in FEEDS}
        forced = bool(state["last_update"].get("requested"))
        stale = age_seconds(state["last_update"].get("at"))
        due = forced or stale < 0 or stale > UPDATE_INTERVAL
        downloaded = []
        for name, entry in sorted(wanted.items()):
            if due or not os.path.isfile(cache_path(name)) or entry.get("state") == "pending":
                update_feed(name, entry)
                downloaded.append(f"{name}:{entry.get('raw', 0)}")

        parsed = {name: load_cached(name) for name in wanted}
        desired, stats = build_desired(parsed, PROTECTED_NETS, MIN_PREFIX, MAX_ENTRIES)
        publish_desired(desired)
        for name, entry in wanted.items():
            stat = stats.get(name, {})
            entry.update(entries=stat.get("kept", 0), dropped=stat.get("dropped", 0),
                         duplicate=stat.get("duplicate", 0))
            if entry.get("state") == "error":
                continue
            if stat.get("capped"):
                entry.update(state="capped",
                             detail=f"only {stat['kept']} fit inside "
                                    f"ip_reputation.max_entries ({MAX_ENTRIES})")
            elif parsed[name]:
                entry.update(state="ok",
                             detail=f"{stat.get('raw', 0)} networks; "
                                    f"{stat.get('dropped', 0)} dropped as ours/reserved, "
                                    f"{stat.get('merged', 0)} merged with a neighbour, "
                                    f"{stat.get('duplicate', 0)} already listed by "
                                    f"another feed")

        # Every router at once, one thread each: a first load is minutes of
        # one-call-per-entry, and doing routers in turn would multiply it --
        # or let one dead router hold the rest back for its timeouts.
        results, totals = {}, {}
        threads = [threading.Thread(target=sync_router, args=(router, desired, results),
                                    daemon=True) for router in ROUTERS]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for router in ROUTERS:
            for key, value in results.get(router.name, ("", {}))[1].items():
                totals[key] = totals.get(key, 0) + value
        if not ROUTERS:
            result = "no router has the ip_reputation role: nothing was sent"
        elif len(ROUTERS) == 1:
            result = results[ROUTERS[0].name][0]
        else:
            result = "; ".join(f"{r.name}: {results[r.name][0]}" for r in ROUTERS)
        counts = totals
        summary = (f"{len(wanted)} feeds | {len(desired)} entries "
                   f"(max {MAX_ENTRIES}) | {result}")
        log(f"sync: {summary}")

        with _state_lock:
            latest = read_state()
            for name, entry in latest["feeds"].items():
                if name in wanted:
                    entry.update({k: v for k, v in wanted[name].items()
                                  if k not in ("since", "note")})
            latest["last_sync"] = {"at": now_utc(), "result": summary,
                                   "desired": len(desired), **counts}
            if due and wanted:
                latest["last_update"] = {"at": now_utc(),
                                         "result": ", ".join(downloaded) or "no feeds"}
            latest["last_update"].pop("requested", None)
            write_state(latest)

        influx_write([f"ip_reputation_feed,feed={esc_tag(name)} "
                      f"entries={entry.get('entries', 0)}i,raw={entry.get('raw', 0)}i,"
                      f"dropped={entry.get('dropped', 0)}i,"
                      f"duplicate={entry.get('duplicate', 0)}i"
                      for name, entry in wanted.items()]
                     + [f"ip_reputation_sync desired={len(desired)}i,"
                        + ",".join(f"{k}={v}i" for k, v in counts.items())
                        if counts else f"ip_reputation_sync desired={len(desired)}i"])
    finally:
        _syncing.clear()


def sync_router(router, desired, results):
    """Reconcile one router; leaves (summary, counts) in results[name]."""
    view = view_of(router)
    if not router.configured:
        results[router.name] = ("mikrotik.* not configured: nothing was sent", {})
        view["result"] = results[router.name][0]
        return
    progress = _progress.setdefault(router.name, {})
    progress.clear()
    try:
        view.update(router.probe())
        rows = router.list_rows(LIST_NAME)
        started = time.monotonic()
        counts = reconcile(router, LIST_NAME, PREFIX, desired, rows,
                           ENTRY_TIMEOUT, REFRESH_BELOW, progress)
        result = (f"{'[dry-run] ' if router.dry_run else ''}"
                  f"+{counts['added']} -{counts['removed']} "
                  f"~{counts['refreshed']} in {time.monotonic() - started:.0f}s"
                  + (f", {counts['errors']} errors" if counts["errors"] else "")
                  + (f", {counts['foreign']} already listed by hand"
                     if counts["foreign"] else ""))
        view["on_router"] = counts["kept"] + counts["added"] if not router.dry_run else 0
        results[router.name] = (result, counts)
    except RouterError as exc:
        view["up"] = 0
        results[router.name] = (f"router unreachable: {exc}", {})
    view["result"] = results[router.name][0]
    view["synced_at"] = now_utc()
    progress["phase"] = "done"


def worker_forever():
    while True:
        _wake.wait(timeout=SYNC_INTERVAL)
        _wake.clear()
        try:
            sync_once()
        except Exception as exc:                      # noqa: BLE001
            log(f"sync failed: {exc!r}")
            time.sleep(30)


def health_forever():
    """Router reachability and the firewall rules' counters, every minute --
    the counters are the only proof the list is blocking anything."""
    previous = {}
    while True:
        lines = []
        for router in ROUTERS:
            if not router.configured:
                continue
            tag = f",router={esc_tag(router.name)}"
            try:
                view = router.probe()
                rules = router.rules(LIST_NAME)
                view_of(router).update(view, rules=rules)
                packets = sum(rule["packets"] for rule in rules)
                before = previous.get(router.name)
                delta = packets - before if before is not None and packets >= before else 0
                previous[router.name] = packets
                lines.append(f"ip_reputation_router{tag} up=1i,"
                             f"latency_ms={view['latency_ms']:.1f},"
                             f"rules={len(rules)}i,rule_packets={delta}i,"
                             f"rule_packets_total={packets}i,"
                             f"on_router={view_of(router).get('on_router', 0)}i")
            except RouterError as exc:
                view_of(router)["up"] = 0
                lines.append(f"ip_reputation_router{tag} up=0i,latency_ms=0")
                log(f"router {router.name}: probe failed: {exc}")
        status = status_row()[0]
        lines.append(f"ip_reputation_status state_code={status['state_code']}i,"
                     f"desired={status['desired']}i,on_router={status['on_router']}i,"
                     f"feeds={status['feeds']}i")
        influx_write(lines)
        time.sleep(HEALTH_INTERVAL)


# ---------------------------------------------------------------------------
# Hit watcher: which of OUR hosts talked to a listed address
#
# The rules' packet counters say the list is doing something, router-wide; they
# cannot say who. The collector's flow records can: every network_flow point
# carries both ends as tags. So once a minute the last window of flows is
# summed per (src_ip, dst_ip) -- a pushed-down group + sum/count, the one shape
# that stays cheap on the production mirror -- and each pair is matched here,
# in Python, against the merge the router was last handed. Joining in Python
# rather than Flux is deliberate: a Flux join or a map over every pair does not
# push down, and the listed set (tens of thousands of networks) cannot be
# turned into a regex that would.
#
# A hit says a flow *was seen*, not that it got through: with the firewall rule
# in place the mirror still carries the SYN that the router then dropped, and
# that attempt is exactly what an alert on "host X is calling a botnet C2"
# wants. `direction` tells the two cases apart -- outbound means our host
# opened it (nfstream's src_ip is the initiator), which is the one that
# matters; inbound is the internet knocking.
# ---------------------------------------------------------------------------
HITS_LAG = 15               # flows are written when they close, not when they start
HITS_MAX_WINDOW = 3600      # after an outage, catch up on at most this much
HITS_MAX_POINTS = 500       # per run; the biggest by bytes are the ones kept
HITS_LOG_LINES = 5

_MASKS = [(0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF for plen in range(33)]


def index_desired(desired):
    """{address: feed} -> {(network int, prefixlen): (feed, address)}. Integer
    keys make a supernet lookup 25 dict probes of cheap arithmetic rather than
    25 IPv4Network constructions -- it runs for every remote address of every
    flow pair in the window."""
    index = {}
    for address, feed in desired.items():
        try:
            net = ipaddress.IPv4Network(address, strict=False)
        except ValueError:
            continue
        index[(int(net.network_address), net.prefixlen)] = (feed, address)
    return index


def publish_desired(desired):
    index = index_desired(desired)
    global _desired, _desired_index
    with _desired_lock:
        _desired, _desired_index = dict(desired), index


def join_flow_rows(rows):
    """Flux rows from the two yields ("bytes", "flows") -> one record per pair."""
    pairs = {}
    for row in rows:
        src, dst = row.get("src_ip", ""), row.get("dst_ip", "")
        if not src or not dst:
            continue
        rec = pairs.setdefault((src, dst), {"src_ip": src, "dst_ip": dst,
                                            "bytes": 0, "flows": 0})
        try:
            value = int(float(row.get("_value") or 0))
        except ValueError:
            continue
        key = "flows" if row.get("result") == "flows" else "bytes"
        rec[key] += value
    return list(pairs.values())


def match_hits(rows, desired, internal, min_prefix, index=None):
    """Pure: the pairs with exactly one internal end whose other end is listed.

    `rows` are {src_ip, dst_ip, bytes, flows}; `desired` is build_desired's
    {address: feed}; `internal` the home networks. Internal-to-internal and
    external-to-external pairs are skipped before any lookup -- the latter are
    transit or mirror noise, nothing of ours talked. The remote end is looked
    up by its supernets, /32 down to `min_prefix`, as build_desired dedupes:
    never a scan of every entry. IPv6 is skipped; the feeds are IPv4 only.
    """
    if index is None:
        index = index_desired(desired)
    homes = [(int(n.network_address), _MASKS[n.prefixlen]) for n in internal]
    seen = {}

    def v4(text):
        try:
            return int(ipaddress.IPv4Address(text))
        except ValueError:
            return None

    def listed(ip):
        if ip not in seen:
            seen[ip] = next((index[(ip & _MASKS[plen], plen)]
                             for plen in range(32, min_prefix - 1, -1)
                             if (ip & _MASKS[plen], plen) in index), None)
        return seen[ip]

    hits = []
    for row in rows:
        src, dst = v4(row["src_ip"]), v4(row["dst_ip"])
        if src is None or dst is None:
            continue
        src_in = any(src & mask == net for net, mask in homes)
        dst_in = any(dst & mask == net for net, mask in homes)
        if src_in == dst_in:
            continue
        found = listed(dst if src_in else src)
        if not found:
            continue
        hits.append({"internal_ip": row["src_ip"] if src_in else row["dst_ip"],
                     "remote_ip": row["dst_ip"] if src_in else row["src_ip"],
                     "direction": "outbound" if src_in else "inbound",
                     "feed": found[0], "listed": found[1],
                     "flows": int(row.get("flows", 0)), "bytes": int(row.get("bytes", 0))})
    return hits


def flux_rows(query, timeout=30):
    """Run a Flux query, return its rows as dicts (strings). Plain CSV with a
    header per table and a blank line between tables -- no annotations. The
    same reader as the responder's; each service is a stdlib single file."""
    body = json.dumps({"query": query, "type": "flux",
                       "dialect": {"header": True, "annotations": []}}).encode()
    req = urllib.request.Request(
        f"{INFLUX_URL.rstrip('/')}/api/v2/query?org={urllib.parse.quote(INFLUX_ORG)}",
        data=body, method="POST",
        headers={"Authorization": f"Token {INFLUX_TOKEN}",
                 "Content-Type": "application/json", "Accept": "application/csv"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        rows = parse_flux_csv(resp.read().decode("utf-8", "replace"))
    # A runtime error arrives as a 200 whose only table is (error, reference).
    if rows and "error" in rows[0] and "_value" not in rows[0]:
        raise ValueError(f"flux: {rows[0]['error'][:200]}")
    return rows


def parse_flux_csv(text):
    rows, header = [], None
    for record in csv.reader(io.StringIO(text)):
        if not record or not any(record):
            header = None                    # the next table brings its own header
            continue
        if header is None:
            header = record
            continue
        rows.append(dict(zip(header, record)))
    return rows


def hits_query(start, stop):
    """Two pushed-down aggregates over one window, as two yields: bytes summed
    and flows counted per pair. `group` + `sum`/`count` straight after the
    filter is a ReadGroupAggregate, so the storage engine does the work."""
    def rfc(ts):
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    base = (f'from(bucket: "{INFLUX_BUCKET}")\n'
            f'  |> range(start: {rfc(start)}, stop: {rfc(stop)})\n'
            f'  |> filter(fn: (r) => r._measurement == "network_flow" and r._field == "bytes")\n'
            f'  |> group(columns: ["src_ip", "dst_ip"])\n')
    return (base + '  |> sum()\n  |> yield(name: "bytes")\n'
            + base + '  |> count()\n  |> yield(name: "flows")\n')


def hits_once(start, stop):
    """One window [start, stop). Returns False only when the query failed, so
    the caller keeps `start` and the next run covers the gap."""
    with _desired_lock:
        desired, index = _desired, _desired_index
    pairs, error, query_ms, hits = 0, "", 0.0, []
    if desired:                              # nothing to match before the first sync
        began = time.monotonic()
        try:
            flows = join_flow_rows(flux_rows(hits_query(start, stop)))
            pairs = len(flows)
            hits = match_hits(flows, desired, HOME_NETS, MIN_PREFIX, index)
        except urllib.error.HTTPError as exc:
            error = f"HTTP {exc.code}: {exc.read()[:200].decode('utf-8', 'replace')}"
        except (urllib.error.URLError, OSError, ValueError) as exc:
            error = str(exc)
        query_ms = (time.monotonic() - began) * 1000
    hits.sort(key=lambda h: (-h["bytes"], h["internal_ip"], h["remote_ip"]))
    overflow = max(0, len(hits) - HITS_MAX_POINTS)
    lines = [f"ip_reputation_hit,internal_ip={esc_tag(h['internal_ip'])},"
             f"remote_ip={esc_tag(h['remote_ip'])},direction={h['direction']},"
             f"feed={esc_tag(h['feed'])} count=1i,flows={h['flows']}i,"
             f"bytes={h['bytes']}i,listed={esc_str(h['listed'])} {stop}"
             for h in hits[:HITS_MAX_POINTS]]
    # Every run, hits or not: "nothing matched", "nothing to match" (entries=0)
    # and "the query is failing" have to be three different readings.
    lines.append(f"ip_reputation_hits pairs={pairs}i,hits={len(hits)}i,"
                 f"entries={len(desired)}i,query_ms={query_ms:.1f},"
                 f"error={esc_str(error[:300])}")
    influx_write(lines)
    if error:
        log(f"hits: query failed after {query_ms:.0f} ms: {error}")
    elif hits:
        for h in hits[:HITS_LOG_LINES]:
            arrow = "->" if h["direction"] == "outbound" else "<-"
            log(f"[HIT] {h['internal_ip']} {arrow} {h['remote_ip']} "
                f"({h['feed']}, {h['direction']}, {h['flows']} flows)")
        log(f"hits: {len(hits)} of {pairs} pairs in {query_ms:.0f} ms"
            + (f", {len(hits) - HITS_LOG_LINES} more not logged"
               if len(hits) > HITS_LOG_LINES else "")
            + (f", {overflow} over the {HITS_MAX_POINTS}-point cap not written"
               if overflow else ""))
    return not error


def hits_forever():
    """Contiguous windows: each run starts where the last one stopped, so no
    flow is counted twice or skipped, whatever the sleep drifts by."""
    start = None
    while True:
        stop = int(time.time()) - HITS_LAG
        if start is None:
            start = stop - HITS_INTERVAL
        start = max(start, stop - HITS_MAX_WINDOW)
        if start >= stop:                    # the clock stepped back
            time.sleep(HITS_INTERVAL)
            continue
        try:
            if hits_once(start, stop):
                start = stop
        except Exception as exc:                      # noqa: BLE001
            log(f"hits: run failed: {exc!r}")
            start = stop                     # a bug must not grow the window forever
        time.sleep(HITS_INTERVAL)


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------
def feed_rows():
    state = read_state()
    rows = []
    for name, entry in sorted(state["feeds"].items()):
        spec = FEEDS.get(name, {})
        rows.append({"feed": name, "title": spec.get("title", name),
                     "state": entry.get("state", "pending"),
                     "detail": entry.get("detail", ""),
                     "raw": entry.get("raw", 0), "entries": entry.get("entries", 0),
                     "dropped": entry.get("dropped", 0),
                     "duplicate": entry.get("duplicate", 0),
                     "fetched_at": entry.get("fetched_at", ""),
                     "since": entry.get("since", ""), "note": entry.get("note", "")})
    return rows


def catalog_rows():
    state = read_state()
    return [{"feed": name, "title": spec["title"], "about": spec["about"],
             "url": spec["url"], "enabled": 1 if name in state["feeds"] else 0}
            for name, spec in FEEDS.items()]


def router_row(router, desired=None):
    """One router's state for /routers, and the input to the worst-of tile."""
    view = view_of(router)
    if desired is None:
        desired = read_state()["last_sync"].get("desired", 0)
    progress = _progress.get(router.name, {})
    loading = progress.get("phase") not in (None, "done")
    rules = view.get("rules", [])
    if not router.configured:
        code = 0
    elif not view.get("up", 0):
        code = 1
    elif loading or (desired and view.get("on_router", 0) < desired and not router.dry_run):
        code = 3
    elif not rules:
        code = 4
    else:
        code = 5
    return {"router": router.name, "host": router.host, "state_code": code,
            "up": view.get("up", 0), "version": view.get("version", ""),
            "on_router": view.get("on_router", 0), "rules": len(rules),
            "rule_sides": ",".join(sorted({r["side"] for r in rules})),
            "rule_packets_total": sum(r["packets"] for r in rules),
            "progress_phase": progress.get("phase", "") if loading else "",
            "progress_done": progress.get("done", 0) if loading else 0,
            "progress_todo": progress.get("todo", 0) if loading else 0,
            "last_result": view.get("result", ""), "synced_at": view.get("synced_at", "")}


def status_row():
    """Every tile state, reduced to a number here: a value mapping can print
    NO FIREWALL RULE, it cannot work out that it applies. With several routers
    the worst one decides -- a list missing on one router is a network that
    is not protected behind it."""
    state = read_state()
    desired = state["last_sync"].get("desired", 0)
    routers = [router_row(r, desired) for r in ROUTERS]
    configured = [r for r in routers if r["state_code"] != 0]
    codes = {r["state_code"] for r in configured}
    if not configured:
        code = 0                               # mikrotik.* missing everywhere
    elif 1 in codes:
        code = 1                               # one is not answering
    elif not state["feeds"]:
        code = 2                               # nothing enabled
    elif _syncing.is_set() or 3 in codes:
        code = 3                               # loading
    elif 4 in codes:
        code = 4                               # loaded, but nothing uses the list
    else:
        code = 5
    sides = [set(filter(None, r["rule_sides"].split(","))) for r in configured]
    return [{
        "state_code": code,
        "feeds": len(state["feeds"]),
        "desired": desired,
        "on_router": min([r["on_router"] for r in configured] or [0]),
        "max_entries": MAX_ENTRIES,
        "routers": len(ROUTERS),
        "routers_blocking": sum(1 for r in configured if r["state_code"] == 5),
        "rules": sum(r["rules"] for r in configured),
        # Sides every router covers; a side only some have is not "covered".
        "rule_sides": ",".join(sorted(set.intersection(*sides))) if sides else "",
        "rule_packets_total": sum(r["rule_packets_total"] for r in configured),
        "router_up": 1 if configured and all(r["up"] for r in configured) else 0,
        "router_version": ", ".join(r["version"] for r in configured),
        "address_list": LIST_NAME,
        "entry_timeout": ENTRY_TIMEOUT,
        "control_enabled": 1 if CONTROL_ENABLED else 0,
        "dry_run": 1 if DRY_RUN else 0,
        "syncing": 1 if _syncing.is_set() else 0,
        "progress_done": sum(r["progress_done"] for r in routers),
        "progress_todo": sum(r["progress_todo"] for r in routers),
        "last_update": state["last_update"].get("at", ""),
        "last_update_result": state["last_update"].get("result", ""),
        "list_age_seconds": age_seconds(state["last_update"].get("at")),
        "last_sync": state["last_sync"].get("at", ""),
        "last_sync_result": state["last_sync"].get("result", ""),
    }]


# ---------------------------------------------------------------------------
# HTTP: control listener only (never published)
# ---------------------------------------------------------------------------
class ControlHandler(BaseHTTPRequestHandler):
    server_version = "ip-reputation"

    def reply(self, payload, code=200):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if parsed.path in ("/apply", "/feeds", "/catalog", "/messages"):
            messages = apply_actions(params)
            if messages:
                log(" | ".join(messages))
            if parsed.path == "/catalog":
                self.reply(catalog_rows())
            elif parsed.path == "/messages":
                self.reply([{"message": m} for m in messages] or [{"message": "no change"}])
            else:
                self.reply(feed_rows())
        elif parsed.path == "/status":
            self.reply(status_row())
        elif parsed.path == "/routers":
            self.reply([router_row(r) for r in ROUTERS])
        else:
            self.reply({"error": "not found"}, code=404)


def main():
    os.makedirs(CACHE_DIR, exist_ok=True)
    with _state_lock:
        state = read_state()
        if not os.path.isfile(STATE_FILE):
            # First start only; the dashboard owns the set from here on.
            for name in SEED_FEEDS:
                if name in FEEDS:
                    state["feeds"][name] = {"since": now_utc(),
                                            "note": "ip_reputation.feeds seed",
                                            "state": "pending", "detail": "queued",
                                            "raw": 0}
                    audit("enable", name, "ip_reputation.feeds seed")
                else:
                    log(f"ip_reputation.feeds: unknown feed {name!r} ignored")
            write_state(state)
    log(f"ip-reputation: control on :{LISTEN_PORT} | list '{LIST_NAME}' | "
        f"{len(state['feeds'])} feeds | max {MAX_ENTRIES} entries | "
        f"timeout {ENTRY_TIMEOUT or 'none'} | "
        f"{len(PROTECTED_NETS)} protected networks | "
        f"actions {'enabled' if CONTROL_ENABLED else 'DISABLED (read-only)'}"
        + (" | DRY RUN" if DRY_RUN else ""))
    for router in ROUTERS:
        log(f"router {router.name}: {router.host or '(no host)'}"
            + ("" if router.configured else " -- not configured, nothing reaches it"))
    if not ROUTERS:
        log("no router has the ip_reputation role: feeds are downloaded and "
            "merged, but nothing reaches a router")
    threading.Thread(target=worker_forever, daemon=True).start()
    threading.Thread(target=health_forever, daemon=True).start()
    if HITS_INTERVAL > 0:
        threading.Thread(target=hits_forever, daemon=True).start()
    else:
        log("ip_reputation.hits_interval = 0: hit watcher off")
    _wake.set()
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), ControlHandler).serve_forever()


if __name__ == "__main__":
    main()
