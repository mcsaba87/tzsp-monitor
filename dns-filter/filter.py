r"""DNS-based web filtering on the Mikrotik router, driven from the Grafana UI.

    UT1 blacklists --> [this service] --> hosts files over HTTP
                                     |        ^
                                     |        '-- fetched by RouterOS
                                     '-> /ip/dns/adlist  (one row per category)
                                     '-> InfluxDB        (audit + per-category hits)

Same trick as rule-control: Grafana cannot write anything by itself, but the
Infinity datasource fetches a URL server-side on every panel refresh, and a
table data link can reload the dashboard with a variable pre-filled. One click
on a category therefore becomes one HTTP call here, and the panel renders the
state that call produced.

RouterOS blocks a name by *fetching a hosts file itself*, so this service is
both a control API and a static file server -- and those two things must not be
reachable by the same people:

  * the **control** listener (LISTEN_PORT, unpublished) has /apply, /status,
    /categories, /catalog, /which. Grafana reaches it by name inside the compose
    network, exactly like rule-control.
  * the **list** listener (LIST_PORT, published on the host) serves nothing but
    /lists/<category>.txt, because the router has to reach it from outside this
    machine. If both lived on the published port, anyone who could reach the
    host could turn the filter off.

Four things about this are easy to get wrong, and all four are load-bearing:

* **Adlist matching is exact, and UT1 lists bare registrable domains.** Measured
  on the 4.6M-name `adult` list: zero entries carry a `www.` label. Without
  expansion the filter blocks `example.com` and lets `www.example.com` straight
  through, which is most of the web -- hence `dns_filter.expand_www`.

* **Adlist names are stored in the router's DNS cache**, so the real limit is
  `/ip dns cache-size` (KiB, default 2048 -- far too small). The budget is
  therefore derived from what the router actually reports rather than guessed,
  and a category that would not fit is refused with the number it needed.

* **UT1 ships the same list under several names.** `MD5SUM.LST` proves it:
  ads==publicite, malware==phishing, adult==porn, drugs==drogue,
  aggressive==agressif==violence, proxy==redirector. Enabling both halves of a
  pair would cost twice the cache for the same names, so an alias of an already
  enabled category is refused -- and it costs nothing to detect, because the
  md5 file is 4.5 KB and answers it without a download.

* **Only `domains` is used from each archive.** UT1 also ships `urls` and
  `expressions`; a DNS filter cannot act on a path, and pretending otherwise
  would be a filter that silently misses what its own list contains.

`/which?names=a,b` answers, for names the router refused, which list refused
them -- a category, or `_blacklist` with whether a person or the responder
(`automatic`, an entry with an expiry) put the name there. A refused lookup
carries no reason of its own, and the alerting service grades it by this:
`malware` is serious, `ads` is not. It reads the rendered hosts files, i.e.
what the router actually loaded, and it is read-only, so it answers with
`dns_filter.control_enabled = false` too.

**Anyone who can view the dashboard can turn the filter off.** Infinity queries
run with the datasource's identity, not the viewer's -- see the note in
CLAUDE.md, and set `dns_filter.control_enabled = false` to make this read-only.
"""
import base64
import hashlib
import io
import json
import os
import re
import shutil
import ssl
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.utils import formatdate, parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROPERTIES_FILE = os.getenv("PROPERTIES_FILE", "/etc/tzsp-monitor/suricata.properties")
STATE_DIR = os.getenv("STATE_DIR", "/var/lib/dns-filter")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8040"))   # control, not published
LIST_PORT = int(os.getenv("LIST_PORT", "8041"))       # hosts files, published

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "my-org")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")

STATE_FILE = os.path.join(STATE_DIR, "state.json")
CATALOG_FILE = os.path.join(STATE_DIR, "catalog.json")
MIRROR_DIR = os.path.join(STATE_DIR, "mirror")   # extracted UT1 `domains` files
LIST_DIR = os.path.join(STATE_DIR, "lists")      # rendered hosts files

UT1_BASE = "https://dsi.ut-capitole.fr/blacklists/download"

# The explicit blacklist is served as one more hosts file and one more adlist
# row, under a name no UT1 category can have: UT1 names never start with `_`
# (and the catalogue refuses any that would), so the row, the file and the
# per-list match-count can never be confused with a category's.
BLACKLIST = "_blacklist"

# Aggregate/bookkeeping archives in the UT1 directory that are not categories.
# `all`/`blacklists*` are every category at once (24 MB) and would blow any
# router's DNS cache; the rest are not blacklists at all.
NOT_A_CATEGORY = {"all", "blacklists", "blacklists_for_dansguardian",
                  "blacklists_for_fortigate", "blacklists_for_pfsense",
                  "blacklists_for_smoothwall", "blacklists_for_squidguard",
                  "blacklists_for_pfsense_reducted",
                  "LICENSE.pdf", "cc-by-sa-4-0.pdf", "liste_blanche",
                  "listes_blanches",
                  "indisponible", "reaffected", "special", "local",
                  # Only in MD5SUM.LST, which is now the catalogue's source:
                  # `good` and `exceptions_liste_bu` are whitelists too.
                  "README", "good", "exceptions_liste_bu", "scripts"}

# Registrable-domain shapes that a `www.` label is worth adding to. UT1 lists
# `app.holmesbot.com` as well as `holmesbot.com`, and expanding the first into
# `www.app.holmesbot.com` buys a name nobody will ever look up while costing the
# same slot of router DNS cache as a real one: 62k of the 253k malware entries
# and 4.0M of the 4.6M adult entries have three labels or more. So expansion is
# limited to entries that are already a registrable domain -- two labels, or
# three where the middle one is a known two-part public suffix.
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.za", "co.il", "co.in", "co.jp", "ne.jp", "or.jp", "co.kr",
    "com.br", "com.ar", "com.mx", "com.co", "com.pe", "com.ve", "com.cn",
    "com.hk", "com.tw", "com.sg", "com.my", "com.ph", "com.vn", "com.pk",
    "com.bd", "com.tr", "com.ua", "com.pl", "com.eg", "com.sa", "com.ng",
}


def expandable(domain):
    """Whether `www.<domain>` is a name a browser might actually ask for."""
    labels = domain.split(".")
    if len(labels) == 2:
        return True
    return len(labels) == 3 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES


# One label per level, letters/digits/hyphen only. UT1's `domains` files are
# clean enough that this rejects 1 line in 253k (a stray .zip filename), but a
# malformed entry reaching the router's hosts file is a whole list refused.
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?"
                       r"(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$")

# Apache autoindex: <a href="ads.tar.gz">ads.tar.gz</a> ... 2026-09-02 22:50 ... 29K
INDEX_RE = re.compile(r'href="([A-Za-z0-9_.\-]+)\.tar\.gz"[^>]*>[^<]*</a>\s*'
                      r'</td><td[^>]*>\s*([0-9:\- ]+?)\s*</td><td[^>]*>\s*([0-9.]+[KMG]?)')

_state_lock = threading.Lock()
_log_lock = threading.Lock()
_wake = threading.Event()   # set when the router/lists need reconciling
_router_views = {}          # router name -> last probe, for /status and /routers
_syncing = threading.Event()


def log(msg):
    with _log_lock:
        sys.stdout.write(f"{datetime.now().strftime('%H:%M:%S')} {msg}\n")
        sys.stdout.flush()


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def age_seconds(stamp):
    """Seconds since a `now_utc()` string, or -1 if there isn't one."""
    if not stamp:
        return -1
    try:
        when = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S UTC").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return -1
    return int((datetime.now(timezone.utc) - when).total_seconds())


# ---------------------------------------------------------------------------
# Property file -- same `key = value` format the responder reads
# ---------------------------------------------------------------------------
class Config:
    """`#` starts a comment only at the start of a line: a password may hold one."""

    def __init__(self, path):
        self.values = {}
        self.present = os.path.isfile(path)
        if not self.present:
            log(f"no property file at {path}: the filter stays off and nothing "
                f"is sent to a router. Copy suricata.properties.example.")
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
# InfluxDB -- a handful of points a minute, so no batching thread is needed
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


def audit(action, category, detail="", names=0):
    detail = detail or "from the dashboard"
    """Permanent record of every change. The container log rotates away, and
    "when did we stop filtering malware, and who decided that" is an audit
    question -- the dashboard cannot tell you *who*, but it can tell you when."""
    influx_write([f"dns_filter_control,action={esc_tag(action)},"
                  f"category={esc_tag(category or 'all')} "
                  f"count=1i,names={int(names)}i,detail={esc_str(detail[:200])}"])


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
def read_state():
    try:
        with open(STATE_FILE) as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        state = {}
    state.setdefault("enabled", False)
    state.setdefault("categories", {})
    state.setdefault("last_update", {})
    state.setdefault("last_sync", {})
    state.setdefault("allow", {})      # dashboard whitelist {domain: {since, note}}
    state.setdefault("block", {})      # dashboard blacklist {domain: {since, note}}
    return state


def write_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=1, sort_keys=True)
    os.replace(tmp, STATE_FILE)  # atomic: a torn state file loses every category


def read_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def write_json(path, payload):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(payload, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# UT1 catalog
# ---------------------------------------------------------------------------
def human_bytes(count):
    for unit in ("B", "K", "M", "G"):
        if count < 1024 or unit == "G":
            return f"{count:.0f}{unit}" if unit == "B" else f"{count:.1f}{unit}"
        count /= 1024.0
    return f"{count:.1f}G"


def parse_size(text):
    """Apache prints "29K" / "17M", not bytes. Only used for the size guard and
    the catalog column, so the rounding does not matter."""
    text = text.strip()
    scale = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}.get(text[-1:], 1)
    try:
        return int(float(text.rstrip("KMG")) * scale)
    except ValueError:
        return 0


def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "tzsp-monitor/dns-filter"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def refresh_catalog():
    """The list of UT1 categories, with the archive size and md5 of each.

    Two cheap requests (an autoindex page and a 4.5 KB md5 file) buy the whole
    catalogue: sizes to refuse a list the router cannot hold *before* spending
    the bandwidth, and md5s to skip unchanged downloads and to spot the aliased
    categories UT1 publishes under several names.

    **MD5SUM.LST is what decides which categories exist; the index only adds
    sizes and dates.** Since 2026-10 the UT1 server answers the autoindex page
    with 503 while still serving MD5SUM.LST and every archive, and when the
    index was required that one page froze the md5s in catalog.json for four
    weeks -- so every category UT1 updated in the meantime failed its md5 check
    and could be neither enabled nor updated. Without the index, sizes and
    dates are carried over from the previous catalogue (0 for a category never
    seen with one: the size guard then applies after the download, in
    mirror_category, instead of before it).
    """
    md5s = {}
    for line in fetch(f"{UT1_BASE}/MD5SUM.LST").decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].endswith(".tar.gz"):
            md5s[parts[1][:-len(".tar.gz")]] = parts[0]

    index_note = ""
    try:
        listed = {name: (modified.strip(), parse_size(size))
                  for name, modified, size in INDEX_RE.findall(
                      fetch(f"{UT1_BASE}/").decode("utf-8", "replace"))}
    except (OSError, ValueError, urllib.error.URLError) as exc:
        listed, index_note = {}, f"index unavailable ({exc}), sizes from the last catalogue"
    previous = get_catalog()["categories"]

    categories = {}
    for name, md5 in md5s.items():
        if name in NOT_A_CATEGORY or "." in name or name.startswith("_"):
            continue
        old = previous.get(name, {})
        modified, size = listed.get(name, (old.get("modified", ""),
                                           old.get("archive_bytes", 0)))
        categories[name] = {"archive_bytes": size, "modified": modified, "md5": md5}
    if not categories:
        raise OSError("UT1 MD5SUM.LST parsed to zero categories")

    # Alias groups, straight out of MD5SUM.LST: identical archives are the same
    # list under a different name, and enabling both costs the cache twice.
    by_md5 = {}
    for name, entry in categories.items():
        if entry["md5"]:
            by_md5.setdefault(entry["md5"], []).append(name)
    for name, entry in categories.items():
        peers = by_md5.get(entry["md5"], [])
        entry["aliases"] = sorted(peer for peer in peers if peer != name)

    catalog = {"fetched_at": now_utc(), "categories": categories,
               "note": index_note}
    write_json(CATALOG_FILE, catalog)
    log(f"catalog: {len(categories)} UT1 categories "
        f"({sum(1 for c in categories.values() if c['aliases'])} aliased)"
        + (f" | {index_note}" if index_note else ""))
    return catalog


def get_catalog():
    return read_json(CATALOG_FILE, {"fetched_at": "", "categories": {}})


# ---------------------------------------------------------------------------
# Mirror: download one category archive and keep its `domains` file
# ---------------------------------------------------------------------------
def mirror_path(category):
    return os.path.join(MIRROR_DIR, f"{category}.domains")


class Md5Mismatch(ValueError):
    """The archive is not the one MD5SUM.LST named -- usually a newer one."""


def mirror_category(category, expected_md5, max_bytes):
    """Download <category>.tar.gz, verify it, keep only the `domains` member.

    Returns (domain_count, source_dir). The archive's inner directory is *not*
    always the category name -- malware.tar.gz extracts to phishing/ -- so the
    member is found by suffix rather than by an assumed path.
    """
    raw = fetch(f"{UT1_BASE}/{category}.tar.gz", timeout=180)
    if max_bytes and len(raw) > max_bytes:
        raise ValueError(f"archive is {human_bytes(len(raw))}, over "
                         f"dns_filter.max_archive_bytes "
                         f"({human_bytes(max_bytes)})")
    digest = hashlib.md5(raw).hexdigest()
    if expected_md5 and digest != expected_md5:
        raise Md5Mismatch(f"md5 mismatch: MD5SUM.LST says {expected_md5[:8]}, "
                         f"the download is {digest[:8]}")

    count, source_dir = 0, ""
    tmp = mirror_path(category) + ".tmp"
    os.makedirs(MIRROR_DIR, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        member = next((m for m in archive.getmembers()
                       if m.isfile() and m.name.endswith("/domains")), None)
        if member is None:
            raise ValueError("archive contains no `domains` file")
        source_dir = member.name.rsplit("/", 1)[0]
        with archive.extractfile(member) as src, open(tmp, "wb") as dst:
            for line in src:
                dst.write(line)
                count += 1
    os.replace(tmp, mirror_path(category))
    return count, source_dir


# ---------------------------------------------------------------------------
# Whitelist / blacklist
# ---------------------------------------------------------------------------
def clean_domain(text, wildcard_ok):
    """A normalised domain, or (None, reason).

    `*.example.com` is accepted for the whitelist only, and means the same as
    `example.com` there, because a whitelist entry already covers every name
    under it. On the blacklist it is refused: adlist matching is exact, so a
    wildcard would be a promise the router cannot keep.
    """
    domain = (text or "").strip().lower().rstrip(".")
    if domain.startswith("*."):
        if not wildcard_ok:
            return None, ("wildcards cannot be blocked: RouterOS adlist "
                          "matching is exact, so list each name")
        domain = domain[2:]
    if len(domain) > 253 or not DOMAIN_RE.match(domain):
        return None, "not a domain name (needs at least two labels)"
    return domain, ""


def split_domains(text):
    """`a.com, b.com c.com` -> [a.com, b.com, c.com]: one box can carry a few."""
    return [part for part in re.split(r"[\s,;]+", text or "") if part]


def allowed_by(name, allow):
    """The whitelist entry that covers `name` -- itself or a parent -- or None.

    Suffix matching, so `example.com` exempts `ads.example.com` too: a
    whitelist entry means "nothing under this is ours to block". One set
    lookup per label, so it costs little even across a multi-million-line list.
    """
    index = 0
    while True:
        if name[index:] in allow:
            return name[index:]
        dot = name.find(".", index)
        if dot < 0:
            return None
        index = dot + 1


# ---------------------------------------------------------------------------
# Render: the hosts files RouterOS downloads
# ---------------------------------------------------------------------------
def render_order(categories):
    """The order the budget is spent in: smallest mirrored list first, ties
    alphabetically.

    Whichever category renders first gets its names, so this order decides who
    survives the budget -- and alphabetical order, which is what this used to
    be, decided it by spelling. Measured on the seed set with the 200k-name
    fallback budget: `malware` (253k domains, 446k names after expansion) took
    all of it and `stalkerware` (525 domains, a 3.7 KB list that fits 400 times
    over) rendered *zero* names, purely because s sorts after m. One big
    category silently switched off every category spelled later than it.

    Smallest-first buys the most categories the budget can pay for and leaves
    the single largest list to truncate itself, which is also the only case
    where the `capped` badge points at the category actually responsible. It is
    no more of a priority ranking than alphabetical was -- it is a ranking of
    what fits -- but it is stable across renders, because a mirror only changes
    size when its md5 does, and that is already in the render signature.

    A side effect worth knowing: names are deduplicated in this same order, so
    a name in both `stalkerware` and `malware` is now credited to the smaller,
    more specific list on the router's per-list match-count.
    """
    def cost(category):
        try:
            return os.path.getsize(mirror_path(category))
        except OSError:
            return 0            # not mirrored yet: renders as an empty list
    return sorted(categories, key=lambda c: (cost(c), c))


def render_lists(categories, expand_www, allow_domains, budget, block_domains=()):
    """Write one hosts file per enabled category, plus the explicit blacklist.

    Returns ({list: names}, total, {lists that ran out of budget},
    {whitelist entry: names it kept off the router}).

    The explicit blacklist renders *first*: it is a handful of names someone
    asked for by hand, and it must never be the list a big UT1 category
    truncates. The whitelist applies to the UT1 categories only -- an explicit
    block of `tracker.example.com` beats a whitelisted `example.com`, which is
    the "allow this site except that one name" case. The same exact domain on
    both lists is refused when it is added, so the two never contradict.

    Domains already emitted by an earlier list are skipped, so a name is
    served by exactly one list even where UT1 categories overlap. That keeps the
    router's cache honest and makes its per-list match-count mean "this list
    is what blocked the query".

    Rendering stops at `budget` names, in `render_order` -- smallest list
    first, so a category far bigger than the router's DNS cache truncates
    itself instead of the ones that would have fitted. It is the caller's job
    to refuse a category before it gets here; the cap is the backstop that
    keeps a mis-set property from filling the router's DNS cache.
    """
    os.makedirs(LIST_DIR, exist_ok=True)
    allow = set(allow_domains)
    allow_hits = {name: 0 for name in allow}
    seen = set()
    counts, truncated = {}, []
    total = 0

    def domains_of(name):
        if name == BLACKLIST:
            return iter(sorted(block_domains))
        try:
            return open(mirror_path(name), encoding="utf-8", errors="replace")
        except OSError:
            return io.StringIO("")   # not mirrored yet: serve an empty list

    lists = ([BLACKLIST] if block_domains else []) + render_order(categories)
    for name in lists:
        path = os.path.join(LIST_DIR, f"{name}.txt")
        tmp = path + ".tmp"
        written = 0
        label = ("explicit blacklist" if name == BLACKLIST
                 else f"UT1 '{name}'")
        with open(tmp, "w") as out:
            out.write(f"# {label} via tzsp-monitor dns-filter, {now_utc()}\n")
            source = domains_of(name)
            try:
                for line in source:
                    domain = line.strip().lower()
                    if not domain or domain.startswith("#"):
                        continue
                    if not DOMAIN_RE.match(domain):
                        continue
                    room = budget - total
                    if room <= 0:
                        truncated.append(name)
                        break
                    forms = [domain]
                    if expand_www and expandable(domain):
                        forms.append("www." + domain)
                    # Trims at most the www. form of the last domain that fits,
                    # so the total never overshoots the budget the router was
                    # measured for.
                    for form in forms[:room]:
                        if form in seen:
                            continue
                        if allow and name != BLACKLIST:
                            exempt = allowed_by(form, allow)
                            if exempt:
                                allow_hits[exempt] += 1
                                continue
                        seen.add(form)
                        out.write(f"0.0.0.0 {form}\n")
                        written += 1
                        total += 1
            finally:
                if hasattr(source, "close"):
                    source.close()
        os.replace(tmp, path)
        counts[name] = written

    # Anything left over from a list that has since been disabled or emptied:
    # the router must get a 404 for it, not a stale list it keeps on serving.
    keep = {f"{name}.txt" for name in lists}
    for stale in os.listdir(LIST_DIR):
        if stale.endswith(".txt") and stale not in keep:
            os.remove(os.path.join(LIST_DIR, stale))

    if truncated:
        log(f"rendering hit the {budget}-name budget in "
            f"{', '.join(sorted(set(truncated)))}")
    return counts, total, set(truncated), allow_hits


# ---------------------------------------------------------------------------
# RouterOS REST client -- /ip/dns and /ip/dns/adlist only
# ---------------------------------------------------------------------------
class RouterError(Exception):
    pass


def is_disabled(row):
    """RouterOS answers `true`/`false`; accept the `yes`/`no` it is sent too."""
    return str(row.get("disabled", "false")).lower() in ("true", "yes")


def kib(value):
    """`2048`, `2048KiB` or `2MiB` -> KiB. install.py strips a KiB suffix from
    the same field, so both shapes are accepted rather than one assumed."""
    m = re.match(r"\s*(\d+)\s*([KMG]i?B)?", str(value or 0))
    if not m:
        return 0
    return int(m.group(1)) * {"MiB": 1024, "GiB": 1024 * 1024}.get(m.group(2) or "", 1)


class Mikrotik:
    """Just enough of the RouterOS v7 REST API to own a set of adlist rows.

    Rows this service manages are the ones whose comment starts with
    `<comment_prefix>:`; every other adlist row is left completely alone, so a
    hand-made list on the router survives everything here.
    """

    MIN_VERSION = (7, 15)   # /ip/dns/adlist does not exist before this

    def __init__(self, cfg):
        self.name = getattr(cfg, "name", "main")
        # The URL *this* router fetches the lists from. Routers in different
        # networks can reach this host by different addresses, so each may
        # say its own; the first router uses dns_filter.base_url.
        self.base_url = (cfg.get("mikrotik.dns_filter_base_url")
                         if not getattr(cfg, "primary", True) else ""
                         ) or cfg.get("dns_filter.base_url")
        self.base_url = self.base_url.rstrip("/")
        self.enabled = cfg.get_bool("mikrotik.enabled", True)
        self.host = cfg.get("mikrotik.host")
        self.user = cfg.get("mikrotik.user")
        self.password = cfg.get("mikrotik.password")
        self.prefix = cfg.get("dns_filter.comment_prefix", "ut1")
        self.request_timeout = cfg.get_int("mikrotik.request_timeout", 5)
        self.dry_run = cfg.get_bool("dns_filter.dry_run", False)

        scheme = cfg.get("mikrotik.scheme", "https")
        port = cfg.get_int("mikrotik.port", 443 if scheme == "https" else 80)
        self.base = f"{scheme}://{self.host}:{port}/rest"

        if scheme == "https" and not cfg.get_bool("mikrotik.verify_tls", False):
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context))
        token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}",
                        "Content-Type": "application/json"}

    @property
    def configured(self):
        # A password is required, exactly as the responder requires it: an
        # unconfigured install must not spend a 5 s timeout on every probe, and
        # "router unreachable" on the dashboard would be the wrong answer to
        # "you have not filled in suricata.properties".
        return bool(self.enabled and self.host and self.user and self.password)

    def _call(self, method, path, body=None, timeout=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=self.headers, method=method)
        try:
            with self.opener.open(req, timeout=timeout or self.request_timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise RouterError(f"HTTP {exc.code} {detail}") from exc
        except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
            raise RouterError(str(exc)) from exc
        return json.loads(raw) if raw.strip() else None

    @staticmethod
    def parse_version(text):
        parts = re.findall(r"\d+", str(text))[:3]
        return tuple(int(part) for part in parts) if parts else (0,)

    def probe(self):
        """Version, DNS settings and adlist rows: everything the tiles need."""
        started = time.monotonic()
        resource = self._call("GET", "/system/resource") or {}
        latency_ms = (time.monotonic() - started) * 1000.0
        version = resource.get("version", "unknown")
        supported = self.parse_version(version) >= self.MIN_VERSION
        dns = self._call("GET", "/ip/dns") or {}
        rows = (self._call("GET", "/ip/dns/adlist") or []) if supported else []
        return {"up": 1, "latency_ms": latency_ms, "version": version,
                "adlist_supported": 1 if supported else 0,
                "free_memory": int(resource.get("free-memory", 0) or 0),
                "cache_size_kib": kib(dns.get("cache-size")),
                "cache_used_kib": kib(dns.get("cache-used")),
                "allow_remote": 1 if str(dns.get("allow-remote-requests")) == "true" else 0,
                "rows": rows, "probed_at": now_utc()}

    def managed(self, rows):
        """{category: row} for the rows this service owns."""
        owned = {}
        for row in rows:
            comment = row.get("comment", "")
            if comment.startswith(self.prefix + ":"):
                owned[comment[len(self.prefix) + 1:].strip()] = row
        return owned

    def reconcile(self, categories, active, base_url, rows, reload=False):
        """Make the router's adlist rows match `categories`.

        `active` is the master switch: the rows stay in place either way and
        only their `disabled` flag moves, so turning the filter off and on again
        does not lose the per-category match counts -- and the router's own
        `pause` command is not used, because its state cannot be read back.

        `reload` asks for a reload even when no row moved: a whitelist or
        blacklist edit changes what a file *contains* without touching the
        row that points at it, and the router does not notice that by itself.
        """
        changes = []
        owned = self.managed(rows)

        for category in sorted(categories):
            url = f"{base_url.rstrip('/')}/lists/{category}.txt"
            row = owned.get(category)
            if row is None:
                entry = {"url": url, "comment": f"{self.prefix}:{category}",
                         "disabled": "no" if active else "yes"}
                if url.startswith("https"):
                    # Only meaningful for TLS, and the list server here speaks
                    # plain HTTP; a proxy in front of it would almost certainly
                    # present a certificate the router does not trust.
                    entry["ssl-verify"] = "no"
                if self.dry_run:
                    changes.append(f"[dry-run] would add {category}")
                    continue
                self._call("PUT", "/ip/dns/adlist", entry)
                changes.append(f"added {category}")
                continue
            patch = {}
            if row.get("url") != url:
                patch["url"] = url
            if is_disabled(row) == active:
                patch["disabled"] = "no" if active else "yes"
            if patch:
                if self.dry_run:
                    changes.append(f"[dry-run] would patch {category} {patch}")
                    continue
                row_id = urllib.parse.quote(row.get(".id", ""), safe="*")
                self._call("PATCH", f"/ip/dns/adlist/{row_id}", patch)
                changes.append(f"updated {category} ({', '.join(patch)})")

        for category, row in owned.items():
            if category in categories:
                continue
            if self.dry_run:
                changes.append(f"[dry-run] would remove {category}")
                continue
            row_id = urllib.parse.quote(row.get(".id", ""), safe="*")
            self._call("DELETE", f"/ip/dns/adlist/{row_id}")
            changes.append(f"removed {category}")

        if (changes or reload) and not self.dry_run:
            # Downloads the changed lists and swaps them in. Slow enough on a
            # big list to deserve its own timeout, but it is the only thing that
            # makes a category change visible to a client.
            self._call("POST", "/ip/dns/adlist/reload", {}, timeout=120)
            changes.append("router reloaded its adlists")
        return changes


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CFG = Config(PROPERTIES_FILE)
CONTROL_ENABLED = CFG.get_bool("dns_filter.control_enabled", True)
EXPAND_WWW = CFG.get_bool("dns_filter.expand_www", True)
# Whitelist entries from the property file. They apply on top of the ones the
# dashboard manages and cannot be removed from it -- the file is the place to
# put a name that must never be blocked whatever anyone clicks.
ALLOW_DOMAINS = sorted({d for d in (clean_domain(raw, True)[0] for raw in
                                    CFG.get_list("dns_filter.allow_domains")) if d})
MAX_LIST_ENTRIES = CFG.get_int("dns_filter.max_list_entries", 1000)
MAX_TTL = 30 * 86400        # an automatic block longer than a month is a permanent one
MAX_CATEGORIES = CFG.get_int("dns_filter.max_categories", 12)
MAX_ARCHIVE_BYTES = CFG.get_int("dns_filter.max_archive_bytes", 4 * 1024 * 1024)
MAX_NAMES = CFG.get_int("dns_filter.max_names", 0)          # 0 = derive from cache
BYTES_PER_NAME = CFG.get_int("dns_filter.bytes_per_name", 150)
CACHE_RESERVE_PCT = CFG.get_int("dns_filter.cache_reserve_pct", 25)
FALLBACK_NAMES = CFG.get_int("dns_filter.fallback_max_names", 200000)
UPDATE_INTERVAL = CFG.get_int("dns_filter.update_interval_hours", 24) * 3600
MIN_UPDATE_INTERVAL = CFG.get_int("dns_filter.min_update_seconds", 1800)
HEALTH_INTERVAL = CFG.get_int("dns_filter.health_interval", 60)
SEED_CATEGORIES = [c.lower() for c in CFG.get_list("dns_filter.categories")]
ROUTERS = [Mikrotik(rc) for rc in router_configs(CFG, "dns_filter")]


def view_of(router):
    return _router_views.get(router.name, {})


def ready_routers():
    """Routers that answered and can hold an adlist."""
    return [r for r in ROUTERS if r.configured and view_of(r).get("up")
            and view_of(r).get("adlist_supported")]


def name_budget():
    """How many names the router can hold, from what it reports about itself.

    Adlist entries live in the DNS cache, so `/ip dns cache-size` is the real
    ceiling -- not RAM, and not a number we can pick from here. A quarter of the
    cache is left for actual DNS caching, which is what the cache is for.
    """
    if MAX_NAMES:
        return MAX_NAMES, "dns_filter.max_names"
    # With several routers the lists have to fit the smallest cache: every
    # router fetches the same files, and one that overflows loads a partial list.
    sizes = [(view_of(r).get("cache_size_kib", 0), r.name) for r in ROUTERS
             if view_of(r).get("cache_size_kib")]
    if not sizes:
        return FALLBACK_NAMES, "fallback (router not probed yet)"
    cache_kib, smallest = min(sizes)
    usable = cache_kib * 1024 * (100 - CACHE_RESERVE_PCT) / 100.0
    where = f" on {smallest}" if len(ROUTERS) > 1 else ""
    return (max(1000, int(usable / BYTES_PER_NAME)),
            f"/ip dns cache-size {cache_kib} KiB{where}")


# ---------------------------------------------------------------------------
# Actions -- what /apply does. Every one of them is idempotent, because Grafana
# re-sends the same request on every panel refresh with the variables still set.
# ---------------------------------------------------------------------------
def valid_category(name, catalog):
    """A category name, or None. Anything not in the catalogue is None, which
    also keeps `../..` out of the served file paths."""
    name = (name or "").strip().lower()
    if not name or not re.fullmatch(r"[a-z0-9_\-]{1,64}", name):
        return None
    return name if name in catalog.get("categories", {}) else None


def apply_actions(params):
    """Apply the switch/enable/disable/update arguments. Returns messages."""
    switch = (params.get("filter", [""])[0] or "").strip().lower()
    enable = (params.get("enable", [""])[0] or "").strip().lower()
    disable = (params.get("disable", [""])[0] or "").strip().lower()
    update = (params.get("update", [""])[0] or "").strip().lower()
    note = (params.get("note", [""])[0] or "")[:200]
    lists = {key: (params.get(key, [""])[0] or "").strip()
             for key in ("allow", "unallow", "block", "unblock")}
    try:
        ttl = max(0, min(int(params.get("ttl", ["0"])[0] or 0), MAX_TTL))
    except ValueError:
        ttl = 0

    messages = []
    if not (switch or enable or disable or update or any(lists.values())):
        return messages
    if not CONTROL_ENABLED:
        return ["dns_filter.control_enabled = false: read-only"]

    catalog = get_catalog()
    dirty = False
    with _state_lock:
        state = read_state()
        categories = state["categories"]

        if switch in ("on", "off"):
            want = switch == "on"
            if state["enabled"] != want:
                state["enabled"] = want
                dirty = True
                messages.append(f"filtering turned {switch}")
                audit("filter_on" if want else "filter_off", "", note)
        elif switch and switch != "-":
            messages.append(f"ignored filter={switch!r} (expected on/off)")

        if disable == "all":
            if categories:
                for name in list(categories):
                    audit("disable", name, note)
                messages.append(f"removed all {len(categories)} categories")
                state["categories"] = categories = {}
                dirty = True
        else:
            name = disable if re.fullmatch(r"[a-z0-9_\-]{1,64}", disable or "") else None
            if name and name in categories:
                del categories[name]
                messages.append(f"removed {name}")
                audit("disable", name, note)
                dirty = True

        name = valid_category(enable, catalog)
        if enable and not name:
            messages.append(f"unknown UT1 category {enable!r}")
        elif name and name not in categories:
            entry = catalog["categories"][name]
            alias = next((peer for peer in entry.get("aliases", [])
                          if peer in categories), None)
            if len(categories) >= MAX_CATEGORIES:
                messages.append(f"refused {name}: already {len(categories)} "
                                f"categories (dns_filter.max_categories)")
            elif alias:
                messages.append(f"refused {name}: identical list to the "
                                f"already-enabled {alias} (same md5)")
            elif MAX_ARCHIVE_BYTES and entry["archive_bytes"] > MAX_ARCHIVE_BYTES:
                messages.append(
                    f"refused {name}: {human_bytes(entry['archive_bytes'])} "
                    f"archive is over dns_filter.max_archive_bytes "
                    f"({human_bytes(MAX_ARCHIVE_BYTES)}) -- a list that size "
                    f"needs more DNS cache than a router has")
            else:
                categories[name] = {"since": now_utc(), "note": note,
                                    "state": "pending", "detail": "queued",
                                    "domains": 0, "names": 0, "md5": ""}
                messages.append(f"added {name}")
                audit("enable", name, note)
                dirty = True

        if disable == BLACKLIST:
            messages.append("the explicit blacklist is not a category: empty it "
                            "from the Blacklist table (unblock=all)")

        if any(lists.values()):
            dirty |= apply_list_actions(state, lists, note, messages, ttl)

        if update in ("now", "1", "true", "yes"):
            since = age_seconds(state["last_update"].get("at"))
            if 0 <= since < MIN_UPDATE_INTERVAL:
                messages.append(f"update skipped: last one was {since // 60} min "
                                f"ago (dns_filter.min_update_seconds)")
            else:
                state["last_update"]["requested"] = now_utc()
                dirty = True
                messages.append("update requested")
                audit("update", "", note)

        if dirty:
            write_state(state)

    if dirty:
        _wake.set()
    return messages


def apply_list_actions(state, lists, note, messages, ttl=0):
    """allow / unallow / block / unblock. Returns whether anything changed;
    the caller holds the state lock.

    Every box is re-sent on every refresh, so a name in both the add and the
    remove box of the same list would be removed and re-added once a minute,
    with an audit row each time. The add box wins: a remove link clears it, so
    a remove that was meant goes through, and a stale remove box left over
    from an earlier click cannot undo a name typed in since. Removes run
    before adds, so moving a name from one list to the other works in one call.

    `ttl` (seconds, blacklist only) makes an *automatic* entry -- the
    responder's, for a domain an IDS alert named. It carries an `until` and is
    expired by the worker; re-sending it pushes `until` out, without an audit
    row, so a C2 domain that keeps alerting stays blocked. Two rules keep the
    automation below the people: an automatic entry is refused for anything a
    whitelist entry *covers* (suffix match, unlike a hand-made block, which
    may deliberately carve one name out of a whitelisted domain), and it never
    downgrades a hand-made entry -- while a hand-made add of an automatic
    entry makes it permanent.
    """
    dirty = False
    word = {"allow": "whitelist", "block": "blacklist"}
    for key, kind, other, audit_as in (("unallow", "allow", None, "unallow"),
                                       ("unblock", "block", None, "unblock")):
        entries = state[kind]
        values = split_domains(lists[key])
        keep = {clean_domain(raw, kind == "allow")[0]
                for raw in split_domains(lists[kind])}
        if [v.lower() for v in values] == ["all"]:
            going = sorted(set(entries) - keep)
            if going:
                for domain in going:
                    audit(audit_as, domain, note)
                    del entries[domain]
                messages.append(f"cleared the {word[kind]} ({len(going)} entries)")
                dirty = True
            continue
        for raw in values:
            domain, _ = clean_domain(raw, kind == "allow")
            if domain and domain in entries and domain not in keep:
                del entries[domain]
                messages.append(f"removed {domain} from the {word[kind]}")
                audit(audit_as, domain, note)
                dirty = True
            elif domain in ALLOW_DOMAINS and kind == "allow":
                messages.append(f"{domain} is whitelisted in suricata.properties "
                                f"(dns_filter.allow_domains), not here")

    for key, other in (("allow", "block"), ("block", "allow")):
        entries = state[key]
        for raw in split_domains(lists[key]):
            domain, reason = clean_domain(raw, key == "allow")
            if not domain:
                messages.append(f"refused {raw[:80]!r} for the {word[key]}: {reason}")
                continue
            auto = key == "block" and ttl > 0
            if domain in entries:
                entry = entries[domain]
                if auto and "until" in entry:
                    until = int(time.time()) + ttl
                    if until > entry["until"] + 60:   # not on every repeat
                        entry["until"] = until
                        messages.append(f"extended {domain} until "
                                        f"{stamp(until)}")
                        dirty = True
                elif not auto and "until" in entry:
                    del entry["until"]
                    entry["note"] = note or entry.get("note", "")
                    messages.append(f"made {domain} a permanent blacklist entry")
                    audit("block", domain, note or "made permanent")
                    dirty = True
                continue                       # re-sent on every refresh
            if key == "allow" and domain in ALLOW_DOMAINS:
                continue
            if domain in state[other] or (key == "block" and domain in ALLOW_DOMAINS):
                messages.append(f"refused {domain} for the {word[key]}: it is on "
                                f"the {word[other]} -- remove it there first")
                continue
            if auto:
                cover = allowed_by(domain, set(state["allow"]) | set(ALLOW_DOMAINS))
                if cover:
                    messages.append(f"refused {domain} for the blacklist: "
                                    f"covered by the whitelist entry {cover}")
                    continue
            if len(entries) >= MAX_LIST_ENTRIES:
                messages.append(f"refused {domain}: the {word[key]} already holds "
                                f"{len(entries)} entries "
                                f"(dns_filter.max_list_entries)")
                continue
            entries[domain] = {"since": now_utc(), "note": note}
            if auto:
                entries[domain]["until"] = int(time.time()) + ttl
            messages.append(f"added {domain} to the {word[key]}"
                            + (f" until {stamp(entries[domain]['until'])}"
                               if auto else ""))
            audit(key, domain, note)
            dirty = True
    return dirty


def stamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def expire_blacklist():
    """Drop automatic blacklist entries whose `until` has passed. Runs on every
    worker pass (five minutes at most), so an entry outlives its ttl by at most
    that, and the render that follows takes the name off the router."""
    now = int(time.time())
    with _state_lock:
        state = read_state()
        gone = sorted(d for d, e in state["block"].items()
                      if e.get("until") and e["until"] <= now)
        if not gone:
            return
        for domain in gone:
            del state["block"][domain]
            audit("unblock", domain, "automatic block expired")
        write_state(state)
    log(f"expired {len(gone)} automatic blacklist entr"
        f"{'y' if len(gone) == 1 else 'ies'}: {', '.join(gone[:10])}"
        + (" ..." if len(gone) > 10 else ""))


# ---------------------------------------------------------------------------
# Worker: the only place that downloads, renders and talks to the router
# ---------------------------------------------------------------------------
def sync_once():
    """Bring the mirror, the rendered lists and the router in line with state.

    All of it happens here rather than in the request handler because a UT1
    download plus a router reload is tens of seconds, and Grafana's datasource
    gives up long before that. /apply records the *intent* and returns; this
    records the *outcome*, and the table shows both -- the same split as the
    responder's decision-vs-result.
    """
    _syncing.set()
    try:
        expire_blacklist()
        with _state_lock:
            state = read_state()
        catalog = get_catalog()
        wanted = dict(state["categories"])
        forced = bool(state["last_update"].pop("requested", None))
        stale = age_seconds(state["last_update"].get("at"))
        refresh_all = forced or stale < 0 or stale > UPDATE_INTERVAL

        # `catalog_error` is None once the catalogue has been fetched in this
        # pass. A failed refresh must not count as an update: last_update.at is
        # what decides the next refresh, and setting it after a failure is what
        # let a stale catalogue read "updated today" for four weeks.
        catalog_error = "not refreshed"

        def refresh():
            nonlocal catalog, catalog_error
            try:
                catalog, catalog_error = refresh_catalog(), None
            except (OSError, ValueError, urllib.error.URLError) as exc:
                catalog_error = f"catalog refresh failed: {exc}"
                log(catalog_error)

        if refresh_all or not catalog["categories"]:
            refresh()

        # --- mirror what is enabled -----------------------------------------
        results = []
        for name in sorted(wanted):
            entry = catalog["categories"].get(name)
            if entry is None:
                wanted[name].update(state="error",
                                    detail="not published by UT1 under that name")
                continue
            have_md5 = wanted[name].get("md5")
            fresh = os.path.isfile(mirror_path(name))
            if fresh and have_md5 == entry["md5"] and not forced:
                wanted[name].setdefault("state", "ok")
                continue
            try:
                try:
                    count, source = mirror_category(name, entry["md5"],
                                                    MAX_ARCHIVE_BYTES)
                except Md5Mismatch:
                    # UT1 replaced the archive after our catalogue was taken.
                    # One fresh MD5SUM.LST settles it; a second mismatch is a
                    # real one (or UT1 mid-upload) and stays an error.
                    if catalog_error is None:
                        raise
                    refresh()
                    entry = catalog["categories"].get(name) or entry
                    count, source = mirror_category(name, entry["md5"],
                                                    MAX_ARCHIVE_BYTES)
                # `source` is kept, not just formatted into `detail`: the render
                # below overwrites `detail` when a category caps or un-caps, and
                # has to be able to put this back without re-downloading.
                wanted[name].update(state="ok", detail=f"from {source}/domains",
                                    source=source, domains=count,
                                    md5=entry["md5"], mirrored_at=now_utc())
                results.append(f"{name}:{count}")
            except (OSError, ValueError, urllib.error.URLError) as exc:
                wanted[name].update(state="error", detail=str(exc)[:200])
                log(f"mirror {name} failed: {exc}")

        # --- render ----------------------------------------------------------
        # Only when something that shapes the output moved. This pass runs every
        # five minutes to heal drift on the router, and rewriting 400k lines
        # each time would churn the files' mtimes -- which is exactly what the
        # router's reload uses to decide whether it has to download them again.
        budget, budget_source = name_budget()
        # Anything with a mirrored copy, including a category that was
        # capped last pass: `capped` describes how much of it fits, not whether
        # it is filtered, and dropping it here would quietly stop serving a
        # list the dashboard still shows as enabled.
        usable = [name for name in wanted
                  if os.path.isfile(mirror_path(name))
                  and wanted[name].get("state") != "error"]
        allow = sorted(set(ALLOW_DOMAINS) | set(state["allow"]))
        block = sorted(state["block"])
        served = ([BLACKLIST] if block else []) + usable   # what the router gets
        signature = json.dumps({"lists": {name: wanted[name].get("md5", "")
                                          for name in usable},
                                "www": EXPAND_WWW, "allow": allow,
                                "block": block,
                                "budget": budget}, sort_keys=True)
        # `capped is None` means a state file written before the truncation
        # verdict was persisted: it cannot say which categories were cut, so
        # spend one render to find out rather than showing them all as healthy.
        remembered = state.get("capped")
        rendered = (all(os.path.isfile(os.path.join(LIST_DIR, f"{name}.txt"))
                        for name in served)
                    and signature == state.get("render_sig")
                    and remembered is not None)
        if rendered:
            counts = {name: wanted[name].get("names", 0) for name in usable}
            counts[BLACKLIST] = state.get("block_names", 0)
            total_names = state["last_sync"].get("names", sum(counts.values()))
            capped = set(remembered) & set(served)
            allow_hits = state.get("allow_hits", {})
        else:
            counts, total_names, capped, allow_hits = render_lists(
                usable, EXPAND_WWW, allow, budget, block)
            for name in wanted:
                wanted[name]["names"] = counts.get(name, 0)

        # The verdict runs on every pass, not only after a render, and the
        # capped set is persisted so it can. The mirror step above optimistically
        # sets state="ok", so a forced update -- which re-downloads even when no
        # md5 moved, and therefore does not re-render -- otherwise cleared every
        # `capped` badge and left a truncated list reading as a working one.
        for name in usable:
            # Set on every pass, both ways: a category that fits again
            # after another one was removed has to stop saying `capped`.
            if name in capped:
                # A category serving fewer names than it has domains, or
                # none at all, must not keep saying "ok" -- that reads as a
                # working filter.
                wanted[name].update(
                    state="capped",
                    detail=f"only {counts[name]} names fit inside the "
                           f"{budget}-name budget (from {budget_source}); "
                           f"drop a category or raise the budget")
            elif not counts[name]:
                wanted[name].update(
                    state="ok",
                    detail="every name already served by another enabled "
                           "category")
            else:
                # detail too, not just state: a category that stops being
                # capped -- which is the normal outcome of removing another
                # one, or of a bigger list moving behind it in render order
                # -- would otherwise keep displaying the "only 0 names fit"
                # text next to a healthy name count.
                source = wanted[name].get("source")
                wanted[name].update(
                    state="ok",
                    detail=f"from {source}/domains" if source else "mirrored")

        # --- router ----------------------------------------------------------
        # A render changed what at least one file holds; until a reload has
        # actually reached the router that stays owed, across passes.
        # Owed per router: one that was down during a re-render still needs
        # its reload when it comes back, while the others have had theirs.
        # (`True` is the single-router format this state file used to have.)
        pending = state.get("reload_pending")
        if not rendered or pending is True:
            owed = {r.name for r in ROUTERS}
        else:
            owed = set(pending or []) & {r.name for r in ROUTERS}
        router_messages = []
        if not ROUTERS:
            router_messages.append("no router has the dns_filter role: nothing was sent")
        for router in ROUTERS:
            label = f"{router.name}: " if len(ROUTERS) > 1 else ""
            if not router.base_url:
                router_messages.append(f"{label}dns_filter.base_url is not set: the "
                                       f"router has no URL to fetch, nothing was sent")
                continue
            if not router.configured:
                router_messages.append(f"{label}mikrotik.* not configured: "
                                       f"nothing was sent")
                continue
            try:
                view = router.probe()
                _router_views.setdefault(router.name, {}).update(view)
                if not view["adlist_supported"]:
                    router_messages.append(
                        f"{label}RouterOS {view['version']} has no /ip/dns/adlist "
                        f"(needs 7.15+); nothing was sent")
                    continue
                changes = router.reconcile(served, state["enabled"], router.base_url,
                                           view["rows"], reload=router.name in owed)
                router_messages += [label + change for change in changes]
                owed.discard(router.name)
            except RouterError as exc:
                router_messages.append(f"{label}router unreachable: {exc}")
                _router_views.setdefault(router.name, {})["up"] = 0
        budget, budget_source = name_budget()

        summary = " | ".join(filter(None, [
            f"{len(usable)} categor{'y' if len(usable) == 1 else 'ies'}",
            f"{len(block)} blacklisted, {len(allow)} whitelisted"
            if block or allow else None,
            f"{total_names} names (budget {budget} from {budget_source})",
            f"filter {'ON' if state['enabled'] else 'OFF'}",
            "; ".join(router_messages) or None]))
        log(f"sync: {summary}")

        with _state_lock:
            latest = read_state()
            # Only the fields this pass owns: /apply may have added a category
            # while the download was running.
            for name, entry in latest["categories"].items():
                if name in wanted:
                    entry.update({k: v for k, v in wanted[name].items()
                                  if k not in ("since", "note")})
            latest["render_sig"] = signature
            latest["capped"] = sorted(capped)
            latest["block_names"] = counts.get(BLACKLIST, 0)
            latest["reload_pending"] = sorted(owed)
            latest["allow_hits"] = allow_hits
            latest["last_sync"] = {"at": now_utc(), "result": summary,
                                   "names": total_names, "budget": budget,
                                   "budget_source": budget_source}
            if refresh_all and catalog_error is None:
                latest["last_update"] = {"at": now_utc(),
                                         "result": ", ".join(results) or "no change"}
            elif refresh_all:
                # `at` stays where it was, so the next pass (five minutes) tries
                # again, and the dashboard's list age keeps growing honestly.
                latest["last_update"]["result"] = catalog_error[:200]
            latest["last_update"].pop("requested", None)
            write_state(latest)

        influx_write([
            f"dns_filter_status enabled={1 if state['enabled'] else 0}i,"
            f"categories={len(usable)}i,names={total_names}i,budget={budget}i"])
    finally:
        _syncing.clear()


def worker_forever():
    while True:
        _wake.wait(timeout=300)
        _wake.clear()
        try:
            sync_once()
        except Exception as exc:                      # noqa: BLE001
            # A worker that dies takes the whole write path with it and the
            # dashboard would keep rendering yesterday's state as if it were now.
            log(f"sync failed: {exc!r}")
            time.sleep(30)


def health_forever():
    """Probe the router for the tiles and for the per-category hit counters.

    `match-count` resets whenever a list is reloaded, so it is shipped as a
    per-interval delta plus the raw total -- same reason as suricata_stats.
    """
    previous = {}
    while True:
        lines = []
        for router in ROUTERS:
            if router.configured:
                lines += probe_router_lines(router, previous)
        influx_write(lines)
        time.sleep(HEALTH_INTERVAL)


def probe_router_lines(router, previous):
    tag = f",router={esc_tag(router.name)}"
    try:
        view = router.probe()
    except RouterError as exc:
        _router_views.setdefault(router.name, {})["up"] = 0
        log(f"router {router.name}: probe failed: {exc}")
        return [f"dns_filter_router{tag} up=0i,latency_ms=0"]
    _router_views.setdefault(router.name, {}).update(view)
    lines = [f"dns_filter_router{tag} up=1i,latency_ms={view['latency_ms']:.1f},"
             f"cache_size_kib={view['cache_size_kib']}i,"
             f"cache_used_kib={view['cache_used_kib']}i,"
             f"adlist_supported={view['adlist_supported']}i,"
             f'version="{view["version"]}"']
    for category, row in router.managed(view["rows"]).items():
        names = int(str(row.get("name-count", 0) or 0))
        matches = int(str(row.get("match-count", 0) or 0))
        key = (router.name, category)
        before = previous.get(key)
        delta = matches - before if before is not None and matches >= before else 0
        previous[key] = matches
        active = 0 if is_disabled(row) else 1
        lines.append(f"dns_filter_list,category={esc_tag(category)}{tag} "
                     f"names={names}i,matches={delta}i,"
                     f"matches_total={matches}i,active={active}i")
    return lines


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------
def router_side(name):
    """One list's numbers across every dns_filter router: Loaded is the
    *smallest* name-count (a list is only fully live if every router read it),
    Blocked is the sum, Active only if it is enabled on all of them."""
    loaded, blocked, active, seen = [], 0, [], 0
    for router in ROUTERS:
        if not router.configured:
            continue
        row = router.managed(view_of(router).get("rows", [])).get(name)
        seen += 1
        if not row:
            loaded.append(0)
            active.append(0)
            continue
        loaded.append(int(str(row.get("name-count", 0) or 0)))
        blocked += int(str(row.get("match-count", 0) or 0))
        active.append(0 if is_disabled(row) else 1)
    return {"router_names": min(loaded) if loaded else 0, "blocked": blocked,
            "on_router": 1 if seen and all(active) else 0}


def category_rows():
    """The enabled categories, as the control dashboard's main table."""
    state = read_state()
    rows = []
    for name, entry in sorted(state["categories"].items()):
        side = router_side(name)
        rows.append({
            "category": name,
            "state": entry.get("state", "pending"),
            "detail": entry.get("detail", ""),
            "domains": entry.get("domains", 0),
            "names": entry.get("names", 0),
            **side,
            "since": entry.get("since", ""),
            "note": entry.get("note", ""),
            "updated": entry.get("mirrored_at", ""),
        })
    return rows + blacklist_row(state)


def blacklist_row(state):
    """The explicit blacklist as one more row of the categories table, so its
    router-side numbers (loaded, blocked) sit next to the categories' own."""
    if not state["block"]:
        return []
    capped = BLACKLIST in (state.get("capped") or [])
    auto = sum(1 for e in state["block"].values() if e.get("until"))
    return [{
        "category": BLACKLIST,
        "state": "capped" if capped else "custom",
        "detail": f"{len(state['block'])} domain(s), {auto} of them automatic "
                  f"(IDS alerts, expiring) -- managed in the Blacklist table",
        "domains": len(state["block"]),
        "names": state.get("block_names", 0),
        **router_side(BLACKLIST),
        "since": min(e.get("since", "") for e in state["block"].values()),
        "note": "",
        "updated": state["last_sync"].get("at", ""),
    }]


def whitelist_rows():
    """Dashboard entries first-class, property-file entries alongside them so
    the table is the whole answer to "what will never be blocked"."""
    state = read_state()
    hits = state.get("allow_hits", {})
    rows = []
    for domain in sorted(set(state["allow"]) | set(ALLOW_DOMAINS)):
        entry = state["allow"].get(domain)
        rows.append({
            "domain": domain,
            "source": "dashboard" if entry else "suricata.properties",
            "exempted": hits.get(domain, 0),
            "since": (entry or {}).get("since", ""),
            "note": (entry or {}).get("note", ""),
        })
    return rows


def blacklist_rows():
    state = read_state()
    rows = []
    for domain, entry in sorted(state["block"].items()):
        names = [domain] + (["www." + domain]
                            if EXPAND_WWW and expandable(domain) else [])
        rows.append({
            "domain": domain,
            "names": ", ".join(names),
            "source": "automatic" if entry.get("until") else "dashboard",
            "until": stamp(entry["until"]) if entry.get("until") else "",
            "since": entry.get("since", ""),
            "note": entry.get("note", ""),
        })
    return rows


# ---------------------------------------------------------------------------
# /which: which list refused a name
# ---------------------------------------------------------------------------
# A refused lookup (the router answers 0.0.0.0) says nothing about *why*, and
# the alerting service that grades those lookups needs exactly that: `malware`
# is serious, `ads` is not, and an automatic blacklist entry -- one the IDS put
# there because an alert named the domain -- is the most serious of all.
#
# The answer is read from the rendered hosts files rather than from the mirror
# or the state, because those files are exactly what the router loaded: they
# are already deduplicated (a name is in one list only), whitelisted names are
# already gone, and a capped category holds only the names that fit. Anything
# computed from the inputs instead could name a list the router never matched.
WHICH_MAX_NAMES = 200        # per request
WHICH_CACHE_MAX = 10000      # cached answers before the cache is simply dropped


def normalize_name(raw):
    """How a DNS name is compared against the lists: resolvers that use 0x20
    encoding randomise case, and a trailing dot is the same name."""
    return raw.strip().lower().rstrip(".")


def list_signature(list_dir):
    """(file, mtime_ns, size) for every rendered list. render_lists replaces a
    file atomically, so any re-render moves its mtime, and a disabled list's
    file disappears -- either way the signature changes."""
    try:
        files = sorted(f for f in os.listdir(list_dir) if f.endswith(".txt"))
    except OSError:
        return ()
    sig = []
    for fname in files:
        try:
            st = os.stat(os.path.join(list_dir, fname))
        except OSError:
            continue   # removed between listdir and stat
        sig.append((fname, st.st_mtime_ns, st.st_size))
    return tuple(sig)


def scan_lists(list_dir, wanted):
    """{name: list} for every name in `wanted` found in a rendered list.

    One pass over all files for the whole set, because a single list can be
    millions of lines and scanning once per name would make a batch of 200
    names cost 200 full reads. Stops early once every name is found."""
    wanted = set(wanted)
    found = {}
    if not wanted:
        return found
    try:
        files = sorted(f for f in os.listdir(list_dir) if f.endswith(".txt"))
    except OSError:
        return found
    for fname in files:
        try:
            fh = open(os.path.join(list_dir, fname), encoding="utf-8",
                      errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                if line.startswith("#"):
                    continue
                name = line[8:].strip()   # "0.0.0.0 <name>"
                if name in wanted and name not in found:
                    found[name] = fname[:-4]
                    if len(found) == len(wanted):
                        return found
    return found


def describe_hit(name, list_name, block_state):
    """One /which answer. Source and note exist only for the explicit
    blacklist, where they say whether a person or the responder put it there;
    a `www.` form is reported against the domain it was expanded from."""
    row = {"name": name, "list": list_name or "", "source": "", "note": ""}
    if not list_name:
        return row
    if list_name != BLACKLIST:
        row["source"] = "category"
        return row
    entry = block_state.get(name)
    if entry is None and name.startswith("www."):
        entry = block_state.get(name[4:])
    entry = entry or {}
    # An entry removed since the last render is still on the router until the
    # next one, so it is reported as what it most likely was: hand-made.
    row["source"] = "automatic" if entry.get("until") else "dashboard"
    row["note"] = entry.get("note", "")
    return row


class ListLookup:
    """Answers /which, with a cache keyed by the list files' signature.

    The cache holds the list name only (negative answers included, as ""):
    source and note come from the state on every request, because a blacklist
    entry's note or expiry can change without its file being re-rendered. The
    lock makes concurrent requests queue behind one scan rather than each
    reading the same millions of lines in parallel."""

    def __init__(self, list_dir, max_cache=WHICH_CACHE_MAX):
        self.list_dir = list_dir
        self.max_cache = max_cache
        self.lock = threading.Lock()
        self.signature = None
        self.cache = {}
        self.scans = 0           # full passes made, for the selftest

    def which(self, names, block_state):
        with self.lock:
            sig = list_signature(self.list_dir)
            if sig != self.signature:
                self.cache, self.signature = {}, sig
            missing = {n for n in names if n not in self.cache}
            if missing:
                self.scans += 1
                found = scan_lists(self.list_dir, missing)
                # A render that landed during the scan may have answered half
                # the names from the old files: answer them, but do not keep
                # them under a signature they no longer describe.
                if list_signature(self.list_dir) == sig:
                    if len(self.cache) + len(missing) > self.max_cache:
                        self.cache = {}
                    for name in missing:
                        self.cache[name] = found.get(name, "")
                answers = {**self.cache, **{n: found.get(n, "") for n in missing}}
            else:
                answers = self.cache
            return [describe_hit(n, answers.get(n, ""), block_state)
                    for n in names]


LOOKUP = ListLookup(LIST_DIR)


def which_names(params):
    """names= values, comma-separated and/or repeated, normalised, in request
    order, empties dropped, capped at WHICH_MAX_NAMES."""
    names = []
    for value in params.get("names", []):
        for raw in value.split(","):
            name = normalize_name(raw)
            if name:
                names.append(name)
    return names[:WHICH_MAX_NAMES]


def catalog_rows():
    """Every UT1 category, for the "add a category" table."""
    state = read_state()
    catalog = get_catalog()["categories"]
    rows = []
    for name, entry in sorted(catalog.items()):
        rows.append({
            "category": name,
            "size": human_bytes(entry["archive_bytes"]),
            "archive_bytes": entry["archive_bytes"],
            "published": entry.get("modified", ""),
            "aliases": ", ".join(entry.get("aliases", [])),
            "enabled": 1 if name in state["categories"] else 0,
            "fits": 0 if (MAX_ARCHIVE_BYTES
                          and entry["archive_bytes"] > MAX_ARCHIVE_BYTES) else 1,
        })
    return rows


def router_row(router):
    """One router's state, for /routers and for the worst-of tiles."""
    view = view_of(router)
    if not router.configured:
        state = 3
    elif not view.get("up", 0):
        state = 0
    elif not view.get("adlist_supported", 0):
        state = 1
    else:
        state = 2
    owned = router.managed(view.get("rows", []))
    return {"router": router.name, "host": router.host, "state": state,
            "up": view.get("up", 0), "version": view.get("version", ""),
            "adlist_supported": view.get("adlist_supported", 0),
            "cache_size_kib": view.get("cache_size_kib", 0),
            "cache_used_kib": view.get("cache_used_kib", 0),
            "allow_remote": view.get("allow_remote", 0),
            "lists": len(owned),
            "names_loaded": sum(int(str(r.get("name-count", 0) or 0))
                                for r in owned.values()),
            "blocked": sum(int(str(r.get("match-count", 0) or 0))
                           for r in owned.values()),
            "base_url": router.base_url, "probed_at": view.get("probed_at", "")}


def status_row():
    """One row, for the tiles. Every state a tile shows is reduced to a number
    here rather than in the panel: a Grafana value mapping can say READY or
    UNREACHABLE, but it cannot work out which of the two applies."""
    state = read_state()
    catalog = get_catalog()
    budget, budget_source = name_budget()
    names = state["last_sync"].get("names", 0)
    cache_needed = int(names * BYTES_PER_NAME / 1024)
    routers = [router_row(r) for r in ROUTERS]
    configured = [r for r in routers if r["state"] != 3]
    sizes = [r["cache_size_kib"] for r in configured if r["cache_size_kib"]]
    cache_size = min(sizes) if sizes else 0
    # The worst router decides the tile: one unreachable router is a filter
    # that is not in force for the clients behind it.
    if not configured:
        router_state = 3            # mikrotik.* unset or disabled everywhere
    elif any(r["state"] == 0 for r in configured):
        router_state = 0            # one did not answer
    elif any(r["state"] == 1 for r in configured):
        router_state = 1            # one is older than 7.15
    else:
        router_state = 2
    # `names` is what was *rendered*, i.e. already clipped to the budget, so it
    # can never exceed the cache on its own -- a list 15x too big to fit ends up
    # reported as exactly fitting. What "TOO SMALL" means is that names had to
    # be dropped, and the categories that lost them are the only record of it.
    if any(entry.get("state") == "capped"
           for entry in state["categories"].values()) \
            or BLACKLIST in (state.get("capped") or []):
        cache_state = 2             # names were dropped: they will not all load
    elif not cache_size:
        cache_state = 0             # the router has not been read yet
    elif cache_needed < cache_size:
        cache_state = 1
    else:
        cache_state = 2
    return [{
        "router_state": router_state,
        "cache_state": cache_state,
        "filter_enabled": 1 if state["enabled"] else 0,
        "control_enabled": 1 if CONTROL_ENABLED else 0,
        "categories": len(state["categories"]),
        "whitelisted": len(set(state["allow"]) | set(ALLOW_DOMAINS)),
        "blacklisted": len(state["block"]),
        "names": names,
        "budget": budget,
        "budget_source": budget_source,
        "budget_used_pct": round(100.0 * names / budget, 1) if budget else 0,
        "routers": len(ROUTERS),
        "routers_ready": sum(1 for r in routers if r["state"] == 2),
        "router_up": 1 if configured and all(r["up"] for r in configured) else 0,
        "router_version": ", ".join(f"{r['router']} {r['version']}" if len(routers) > 1
                                    else r["version"] for r in configured),
        "adlist_supported": 1 if configured and all(
            r["adlist_supported"] for r in configured) else 0,
        "cache_size_kib": cache_size,
        "cache_used_kib": max([r["cache_used_kib"] for r in configured] or [0]),
        "cache_needed_kib": cache_needed,
        "allow_remote": 1 if configured and all(r["allow_remote"] for r in configured) else 0,
        "base_url_set": 1 if ROUTERS and all(r.base_url for r in ROUTERS) else 0,
        "base_url": ", ".join(sorted({r.base_url for r in ROUTERS if r.base_url})),
        "list_age_seconds": age_seconds(state["last_update"].get("at")),
        "last_update": state["last_update"].get("at", ""),
        "last_update_result": state["last_update"].get("result", ""),
        "last_sync": state["last_sync"].get("at", ""),
        "last_sync_result": state["last_sync"].get("result", ""),
        "catalog_size": len(catalog["categories"]),
        "catalog_fetched_at": catalog.get("fetched_at", ""),
        "catalog_note": catalog.get("note", ""),
        "syncing": 1 if _syncing.is_set() else 0,
        "expand_www": 1 if EXPAND_WWW else 0,
    }]


# ---------------------------------------------------------------------------
# HTTP: control listener (never published) and list listener (published)
# ---------------------------------------------------------------------------
class JSONHandler(BaseHTTPRequestHandler):
    server_version = "dns-filter"

    def reply(self, payload, code=200):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # actions log themselves; reads are one a minute per panel


class ControlHandler(JSONHandler):
    """The write path. Reachable only from inside the compose network."""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path in ("/apply", "/categories", "/"):
            messages = apply_actions(params)
            if messages:
                log(" | ".join(messages))
            self.reply(category_rows())
        elif parsed.path == "/catalog":
            messages = apply_actions(params)
            if messages:
                log(" | ".join(messages))
            self.reply(catalog_rows())
        elif parsed.path in ("/whitelist", "/blacklist"):
            # The same actions again, answered with the list the panel shows,
            # so each table performs its own change and renders the result.
            messages = apply_actions(params)
            if messages:
                log(" | ".join(messages))
            self.reply(whitelist_rows() if parsed.path == "/whitelist"
                       else blacklist_rows())
        elif parsed.path == "/which":
            # Read-only, deliberately outside apply_actions: the alerting
            # service asks this for every refused lookup, and it has to keep
            # answering when dns_filter.control_enabled = false.
            self.reply(LOOKUP.which(which_names(params), read_state()["block"]))
        elif parsed.path == "/status":
            self.reply(status_row())
        elif parsed.path == "/routers":
            self.reply([router_row(r) for r in ROUTERS])
        elif parsed.path == "/messages":
            # Same actions as /apply, but it answers with what happened rather
            # than the resulting table -- the readable form for a person with a
            # shell, and what the selftest asserts against.
            messages = apply_actions(params)
            if messages:
                log(" | ".join(messages))
            self.reply([{"message": m} for m in messages] or
                       [{"message": "no change"}])
        else:
            self.reply({"error": "not found"}, code=404)


class ListHandler(JSONHandler):
    """Serves the rendered hosts files, and nothing else.

    This is the listener the router reaches, so it is published on a host port
    -- and that is exactly why it must not carry /apply: on a published port,
    anyone who can reach this machine could switch the filter off.

    Last-Modified/ETag are answered properly because `/ip/dns/adlist reload`
    checks whether a list changed before re-reading it; a 304 here is what makes
    a reload of an unchanged category free.
    """

    def _resolve(self):
        parsed = urllib.parse.urlparse(self.path)
        match = re.fullmatch(r"/lists/([a-z0-9_\-]{1,64})\.txt", parsed.path)
        if not match:
            return None
        path = os.path.join(LIST_DIR, f"{match.group(1)}.txt")
        return path if os.path.isfile(path) else None

    def do_HEAD(self):
        self.do_GET(body=False)

    def do_GET(self, body=True):
        path = self._resolve()
        if path is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        stat = os.stat(path)
        etag = f'"{stat.st_mtime_ns:x}-{stat.st_size:x}"'
        modified = formatdate(stat.st_mtime, usegmt=True)
        if self.headers.get("If-None-Match") == etag or self._not_modified(stat):
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Last-Modified", modified)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(stat.st_size))
        self.send_header("Last-Modified", modified)
        self.send_header("ETag", etag)
        self.end_headers()
        if body:
            with open(path, "rb") as fh:
                shutil.copyfileobj(fh, self.wfile)

    def _not_modified(self, stat):
        header = self.headers.get("If-Modified-Since")
        if not header:
            return False
        try:
            since = parsedate_to_datetime(header).timestamp()
        except (TypeError, ValueError):
            return False
        return int(stat.st_mtime) <= int(since)


# ---------------------------------------------------------------------------
def main():
    for directory in (STATE_DIR, MIRROR_DIR, LIST_DIR):
        os.makedirs(directory, exist_ok=True)

    with _state_lock:
        state = read_state()
        if not os.path.isfile(STATE_FILE) and SEED_CATEGORIES:
            # First start only: the dashboard owns this list from here on, so
            # editing the property later changes nothing.
            for name in SEED_CATEGORIES[:MAX_CATEGORIES]:
                state["categories"][name] = {
                    "since": now_utc(), "note": "dns_filter.categories seed",
                    "state": "pending", "detail": "queued", "domains": 0,
                    "names": 0, "md5": ""}
                audit("enable", name, "dns_filter.categories seed")
            count = len(state["categories"])
            log(f"seeded {count} categor{'y' if count == 1 else 'ies'} from "
                f"dns_filter.categories")
            write_state(state)

    log(f"dns-filter: control on :{LISTEN_PORT}, lists on :{LIST_PORT} | "
        f"filter {'ON' if state['enabled'] else 'OFF'} | "
        f"{len(state['categories'])} categor{'y' if len(state['categories']) == 1 else 'ies'} | "
        f"actions {'enabled' if CONTROL_ENABLED else 'DISABLED (read-only)'} | "
        f"www expansion {'on' if EXPAND_WWW else 'off'}")
    for router in ROUTERS:
        log(f"router {router.name}: {router.host or '(no host)'} "
            f"lists from {router.base_url or '(no base_url)'}"
            + ("" if router.configured else " -- not configured"))
    if any(not r.base_url for r in ROUTERS):
        log("dns_filter.base_url is empty. Set it to a URL this machine serves "
            f"on port {LIST_PORT} that the ROUTER can reach, e.g. "
            f"http://<this-host-ip>:{LIST_PORT} -- until then the router gets "
            "no adlist rows.")

    threading.Thread(target=worker_forever, daemon=True).start()
    threading.Thread(target=health_forever, daemon=True).start()
    threading.Thread(
        target=ThreadingHTTPServer(("0.0.0.0", LIST_PORT), ListHandler)
        .serve_forever, daemon=True).start()
    _wake.set()   # reconcile once at start: state and router can have drifted
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), ControlHandler).serve_forever()


if __name__ == "__main__":
    main()
