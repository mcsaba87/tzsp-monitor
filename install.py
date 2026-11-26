#!/usr/bin/env python3
"""tzsp-monitor setup assistant.

    python3 install.py            # interactive; Enter keeps the value in [brackets]
    python3 install.py --check    # only probe the host and the router, write nothing

Asks for everything that differs from one installation to the next and writes
it to the three git-ignored files that hold it:

  .env                  COMPOSE_FILE (TZSP or VXLAN mirror), SNIFF_INTERFACE,
                        PCAP_DIR -- the values docker compose interpolates
  suricata.properties   router credentials, address list, HOME_NET, never-block
                        list, dns_filter.base_url, pcap budget, retention
  properties.yml        the Grafana admin login

Re-running it is safe: every question defaults to what is already configured,
nothing is written before the summary is confirmed, and each file it changes
is copied to <file>.bak first. Files are rewritten in place (same inode) on
purpose -- suricata.properties is a single-file bind mount, and a file replaced
by rename would leave the running containers looking at the old copy.

What it deliberately does NOT do:
  - write anything to the router. It reads it (version, REST access, whether a
    firewall rule uses the address list, DNS cache, sniffer target) and prints
    the RouterOS commands still missing. The firewall rule that turns the list
    into a block is manual by design -- see mikrotik-responder in CLAUDE.md.
  - change the InfluxDB credentials. They are shared dev defaults spread over
    many files, and the influxdb service must not be edited casually (its data
    is in an anonymous volume -- see CLAUDE.md).

Stdlib only, like the sidecars, so it runs on any host with python3.
"""

import argparse
import base64
import datetime
import getpass
import ipaddress
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(HERE, ".env")
PROPS_FILE = os.path.join(HERE, "suricata.properties")
PROPS_EXAMPLE = os.path.join(HERE, "suricata.properties.example")
GRAFANA_FILE = os.path.join(HERE, "properties.yml")
VXLAN_COMPOSE = "docker-compose.yml:docker-compose.vxlan.yml"
COMPOSE_DEFAULT_IFACE = "wlp0s20f3"   # docker-compose.yml's fallback

GRAFANA_TEMPLATE = """\
# Local Grafana credentials. This file is git-ignored so your password is not
# committed. It is loaded by the grafana service via `env_file` in
# docker-compose.yml, so each line must be a KEY=VALUE pair.
#
# Apply a change with: docker compose up -d grafana
GF_SECURITY_ADMIN_USER=admin
GF_SECURITY_ADMIN_PASSWORD=

# --- Other tzsp-monitor instances, browsable from this Grafana --------------
# One line per site; each appears in the dashboards' "Site" dropdown. Nothing
# is copied: the dashboards query that site's InfluxDB directly, so this host
# must be able to reach it on 8086. Token and org are optional and default to
# the stack's my-super-secret-token / my-org; a read-only token is better:
#   influx auth create --org my-org --read-bucket <network_traffic id>
# The name is the part after REMOTE_SITE_ (underscores show as spaces).
#REMOTE_SITE_BUDAPEST=http://10.1.0.10:8086
#REMOTE_SITE_LONDON=https://10.2.0.10:8086 <read-only-token> my-org
# Optional, same NAME: that site's own Grafana. Boards whose controls act on
# this instance only (Packet Capture) link to the other sites' boards with it.
#REMOTE_GRAFANA_BUDAPEST=https://grafana.budapest.example
# What this instance itself is called in the dropdown (default InfluxDB_Flux).
#LOCAL_SITE_NAME=Lab
"""

# Which running services read which property prefix -- what has to be
# restarted after the file changes on a stack that is already up.
PROP_READERS = {
    "mikrotik.": ["mikrotik-responder", "dns-filter", "ip-reputation"],
    "whitelist.": ["mikrotik-responder", "ip-reputation"],
    "block.": ["mikrotik-responder"],
    "quarantine.": ["mikrotik-responder"],
    "domain_block.": ["mikrotik-responder"],
    "scanners.": ["mikrotik-responder"],
    "ip_reputation.": ["ip-reputation"],
    "suricata.": ["suricata", "mikrotik-responder", "ip-reputation"],
    "rule_control.": ["rule-control"],
    "disk_guard.": ["disk-guard"],
    "dns_filter.": ["dns-filter"],
    "dns_monitor.": ["dns-monitor"],
    "pcap_dump.": ["pcap-dump"],
}

SECRET_KEYS = {"mikrotik.password", "GF_SECURITY_ADMIN_PASSWORD"}


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text


def section(title):
    print("\n" + _c("1;36", f"== {title} " + "=" * max(0, 70 - len(title))))


def info(text):
    print("   " + text)


def ok(text):
    print(_c("32", " ok ") + text)


def warn(text):
    print(_c("33", "  ! ") + text)


def bad(text):
    print(_c("31", "  x ") + text)


def ask(prompt, default="", validate=None, allow_empty=True):
    """One line of input. Enter takes the default; `validate` returns an
    error string (re-ask) or None. A single '-' clears a non-empty default."""
    while True:
        shown = f" [{default}]" if default else ""
        try:
            raw = input(f" ? {prompt}{shown}: ").strip()
        except EOFError:
            print()
            sys.exit("aborted")
        value = default if raw == "" else ("" if raw == "-" else raw)
        if not value and not allow_empty:
            print("   a value is required")
            continue
        error = validate(value) if (validate and value) else None
        if error:
            print(f"   {error}")
            continue
        return value


def ask_yes(prompt, default=True):
    hint = "Y/n" if default else "y/N"
    while True:
        try:
            raw = input(f" ? {prompt} [{hint}]: ").strip().lower()
        except EOFError:
            print()
            sys.exit("aborted")
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False


def ask_secret(prompt, current):
    """Hidden input. Enter keeps the current secret if there is one."""
    hint = " (Enter keeps the current one)" if current else ""
    while True:
        first = getpass.getpass(f" ? {prompt}{hint}: ")
        if not first:
            if current:
                return current
            print("   a value is required")
            continue
        if "\n" in first:
            print("   a newline cannot be stored in this file")
            continue
        if getpass.getpass("   again: ") == first:
            return first
        print("   the two did not match")


def choose(prompt, options, default_index=0):
    """Numbered menu of (value, label); returns the value."""
    for i, (_, label) in enumerate(options, 1):
        print(f"   {i}) {label}")
    while True:
        raw = ask(prompt, str(default_index + 1))
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        for value, _ in options:
            if raw == value:
                return value
        print(f"   pick 1-{len(options)}")


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def v_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "not an IP address"
    return None


def v_host(value):
    if v_ip(value) is None or re.fullmatch(r"[A-Za-z0-9.-]+", value):
        return None
    return "not an IP address or host name"


def v_port(value):
    return None if value.isdigit() and 0 < int(value) < 65536 else "not a port"


def v_cidr_list(value):
    for part in split_list(value):
        try:
            ipaddress.ip_network(part, strict=False)
        except ValueError:
            return f"{part!r} is not an address or CIDR"
    return None


def v_ip_list(value):
    for part in split_list(value):
        if v_ip(part):
            return f"{part!r} is not an IP address"
    return None


def v_size(value):
    return None if parse_size(value) is not None else "use e.g. 500M, 20G or 1T"


def v_int(value):
    return None if value.isdigit() and int(value) > 0 else "a positive whole number"


def v_duration(value):
    if re.fullmatch(r"(\d+[wdhms])+", value):
        return None
    return "RouterOS duration, e.g. 1h, 30m, 1d (or '-' for permanent)"


def split_list(value):
    return [p.strip() for p in re.split(r"[,\s]+", value.strip("[] ")) if p.strip()]


def parse_size(value):
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([KMGT]?)i?B?\s*", value or "", re.I)
    if not m:
        return None
    return int(float(m.group(1)) * 1024 ** " KMGT".index(m.group(2).upper() or " "))


def fmt_size(n):
    for unit in ("T", "G", "M", "K"):
        step = 1024 ** " KMGT".index(unit)
        if n >= step:
            return f"{n / step:.0f}{unit}" if n % step == 0 or n >= 10 * step \
                else f"{n / step:.1f}{unit}"
    return str(n)


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

class PropertyFile:
    """`key = value` lines with comments, edited without disturbing either.

    A new suricata.properties starts as a copy of the example. An existing one
    is *rebased* onto the current example -- its values carried over, the
    example's comments and any keys added since kept -- so a host set up before
    pcap_dump.* or dns_monitor.* existed gets those sections documented instead
    of silently running on built-in defaults. Keys the example does not know are
    appended at the end, never dropped."""

    KEY_RE = re.compile(r"^\s*([A-Za-z0-9_.]+)\s*=\s?(.*?)\s*$")

    def __init__(self, path, example):
        self.path = path
        with open(example) as fh:
            self.lines = fh.read().splitlines()
        self.original = {}
        self.rebased = False
        self.existed = os.path.isfile(path)
        if self.existed:
            with open(path) as fh:
                for line in fh.read().splitlines():
                    m = self.KEY_RE.match(line)
                    if m and not line.lstrip().startswith("#"):
                        self.original.setdefault(m.group(1), m.group(2))
            example_keys = set(self._keys())
            for key, value in self.original.items():
                self.set(key, value)
            self.rebased = bool(example_keys - set(self.original))
        self.initial = {k: self.get(k) for k in self._keys()}

    def _keys(self):
        for line in self.lines:
            m = self.KEY_RE.match(line)
            if m and not line.lstrip().startswith("#"):
                yield m.group(1)

    def _index(self, key):
        for i, line in enumerate(self.lines):
            m = self.KEY_RE.match(line)
            if m and m.group(1) == key and not line.lstrip().startswith("#"):
                return i
        return None

    def get(self, key, default=""):
        i = self._index(key)
        return self.KEY_RE.match(self.lines[i]).group(2) if i is not None else default

    def set(self, key, value):
        line = f"{key} = {value}" if value != "" else f"{key} ="
        i = self._index(key)
        if i is None:
            if not any("added by install.py" in l for l in self.lines):
                self.lines += ["", "", "# --- keys not in suricata.properties.example, "
                               "added by install.py ---"]
            self.lines.append(line)
        else:
            self.lines[i] = line

    def changes(self):
        """(key, old, new) for every value that differs from the file on disk
        -- or, for a new file, from the example. Keys a rebase merely adds at
        their default are not changes."""
        before = self.original if self.existed else self.initial
        out = []
        for key in self._keys():
            old, new = before.get(key), self.get(key)
            if old == new or (old is None and new == self.initial.get(key)):
                continue
            out.append((key, old, new))
        return out

    def text(self):
        return "\n".join(self.lines) + "\n"


class EnvFile:
    """KEY=VALUE lines (.env, properties.yml). Unknown lines are preserved."""

    def __init__(self, path, template=""):
        self.path = path
        if os.path.isfile(path):
            with open(path) as fh:
                self.lines = fh.read().splitlines()
        else:
            self.lines = template.splitlines()
        self.original = dict(self._pairs())

    def _pairs(self):
        for line in self.lines:
            m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
            if m:
                yield m.group(1), m.group(2)

    def get(self, key, default=""):
        return dict(self._pairs()).get(key, default)

    def set(self, key, value):
        for i, line in enumerate(self.lines):
            if re.match(rf"^\s*{key}=", line):
                self.lines[i] = f"{key}={value}"
                return
        self.lines.append(f"{key}={value}")

    def unset(self, key):
        self.lines = [l for l in self.lines if not re.match(rf"^\s*{key}=", l)]

    def changes(self):
        now = dict(self._pairs())
        keys = list(dict.fromkeys(list(self.original) + list(now)))
        return [(k, self.original.get(k), now.get(k)) for k in keys
                if self.original.get(k) != now.get(k)]

    def text(self):
        return "\n".join(self.lines) + "\n"


def write_in_place(path, text, mode=None):
    """Back up, then truncate-and-write so the inode survives (see top)."""
    existed = os.path.isfile(path)
    if existed:
        shutil.copy2(path, path + ".bak")
    with open(path, "w") as fh:
        fh.write(text)
    if mode is not None and not existed:
        os.chmod(path, mode)
    return existed


# ---------------------------------------------------------------------------
# Host inspection
# ---------------------------------------------------------------------------

def run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           cwd=HERE)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


SKIP_IFACE = re.compile(r"^(lo|docker\d*|br-.*|veth.*|virbr.*|tzsp\d*|tun\d*|tap\d*)$")


def interfaces():
    """[(name, state, [ipv4/len ...])] for the physical-looking interfaces."""
    code, out, _ = run(["ip", "-j", "addr"])
    found = []
    if code == 0:
        for item in json.loads(out or "[]"):
            name = item.get("ifname", "")
            if SKIP_IFACE.match(name):
                continue
            addrs = [f"{a['local']}/{a['prefixlen']}" for a in item.get("addr_info", [])
                     if a.get("family") == "inet"]
            found.append((name, item.get("operstate", "?"), addrs))
    else:
        for name in sorted(os.listdir("/sys/class/net")):
            if not SKIP_IFACE.match(name):
                found.append((name, "?", []))
    return found


def route_to(address):
    """(interface, source ip) the kernel would use to reach `address`."""
    code, out, _ = run(["ip", "-j", "route", "get", address])
    if code != 0 or not out:
        return None, None
    entry = (json.loads(out) or [{}])[0]
    return entry.get("dev"), entry.get("prefsrc")


def nearest_existing(path):
    while not os.path.exists(path):
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return path


def preflight():
    section("Host checks")
    good = True
    code, out, err = run(["docker", "version", "--format", "{{.Server.Version}}"])
    if code == 0:
        ok(f"docker engine {out}")
    else:
        bad("docker engine not reachable: " + (err.splitlines() or ["?"])[-1])
        info("install Docker, and add this user to the docker group "
             "(sudo usermod -aG docker $USER, then log in again)")
        good = False
    code, out, _ = run(["docker", "compose", "version", "--short"])
    if code == 0:
        ok(f"docker compose {out}")
    else:
        bad("the docker compose plugin is missing (docker-compose-plugin)")
        good = False
    if os.path.exists("/dev/net/tun"):
        ok("/dev/net/tun present (tzsp-decap's tap)")
    else:
        bad("/dev/net/tun missing -- tzsp-decap cannot create its tap "
            "(sudo modprobe tun)")
        good = False
    if os.path.isdir(PROPS_FILE):
        # Docker creates a directory when a bind mount's source is missing --
        # the gotcha in CLAUDE.md. It has to go before a file can be written.
        if not os.listdir(PROPS_FILE):
            warn("suricata.properties is an empty DIRECTORY -- Docker made it "
                 "because the stack was started before the file existed")
            if ask_yes("remove it so the real file can be written?"):
                try:
                    os.rmdir(PROPS_FILE)
                    ok("removed")
                except OSError as exc:
                    bad(f"{exc} -- run: sudo rmdir {PROPS_FILE}")
                    good = False
            else:
                good = False
        else:
            bad("suricata.properties is a non-empty directory -- move it away by hand")
            good = False
    return good


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

ROLES = ("block", "quarantine", "dns_filter", "ip_reputation", "scanners")


class RouterProps:
    """One router's view of suricata.properties, with the services' lookup
    rule (RouterConfig there): `mikrotik.<name>.<key>` first, then the
    unprefixed key -- except `host` and `roles`, which are never inherited.
    The unprefixed keys are the first router, named by `mikrotik.name`."""

    def __init__(self, props, name, primary):
        self.props, self.name, self.primary = props, name, primary

    def get(self, key, default=""):
        if key.startswith("mikrotik.") and not self.primary:
            sub = key[len("mikrotik."):]
            own = f"mikrotik.{self.name}.{sub}"
            if self.props._index(own) is not None:
                return self.props.get(own, default)
            if sub in ("host", "roles"):
                return default
        return self.props.get(key, default)

    @property
    def roles(self):
        listed = {r.strip().lower() for r in self.get("mikrotik.roles").split(",")
                  if r.strip()}
        return (listed & set(ROLES)) or set(ROLES)


def routers_of(props):
    names = [props.get("mikrotik.name", "main").strip().lower() or "main"]
    for name in props.get("mikrotik.routers").split(","):
        name = name.strip().lower()
        if name and name not in names and re.fullmatch(r"[a-z0-9_\-]{1,32}", name):
            names.append(name)
    routers = [RouterProps(props, n, i == 0) for i, n in enumerate(names)]
    if len(routers) > 1 and not routers[0].get("mikrotik.host"):
        routers = routers[1:]
    return routers


class Router:
    """Read-only RouterOS REST client, built the same way as the responder's."""

    def __init__(self, props):
        self.scheme = props.get("mikrotik.scheme", "https")
        port = props.get("mikrotik.port") or ("443" if self.scheme == "https" else "80")
        self.base = f"{self.scheme}://{props.get('mikrotik.host')}:{port}/rest"
        verify = props.get("mikrotik.verify_tls", "false").lower() == "true"
        context = ssl.create_default_context() if verify else ssl._create_unverified_context()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        token = base64.b64encode(f"{props.get('mikrotik.user')}:"
                                 f"{props.get('mikrotik.password')}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}"}

    def get(self, path):
        req = urllib.request.Request(self.base + path, headers=self.headers)
        with self.opener.open(req, timeout=6) as resp:
            return json.loads(resp.read() or b"null")


def version_tuple(text):
    m = re.match(r"(\d+)\.(\d+)", text or "")
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def probe_router(props, monitor_ip, vxlan, roles=ROLES, sniffer=True):
    """Read what can be read and return the RouterOS commands still needed.

    `props` may be a RouterProps; only what `roles` need is checked, and the
    sniffer only where this router is the one expected to stream the mirror."""
    todo = []
    rtr = Router(props)
    try:
        res = rtr.get("/system/resource")
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            bad("router refused the login (HTTP 401) -- user name or password")
        else:
            bad(f"router answered HTTP {exc.code}")
        return None
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        bad(f"cannot reach {rtr.base}: {reason}")
        info("is the REST service on? /ip/service enable www-ssl  (or www for http)")
        return None

    version = res.get("version", "?")
    ok(f"REST API answers: RouterOS {version} on {res.get('board-name', '?')}")
    vt = version_tuple(version)
    if vt < (7, 1):
        bad("RouterOS 7.1+ is required for the REST API -- the responder cannot work")
    elif vt < (7, 15):
        warn("RouterOS < 7.15 has no /ip/dns/adlist: blocking works, DNS filtering will not")

    # Every list this stack writes blocks nothing until a rule names it, and
    # that rule is made by hand on purpose. Raw/prerouting runs before
    # connection tracking, so it also cuts connections already open.
    q = props.get("quarantine.list", "suricata-quarantine")
    rep = props.get("ip_reputation.address_list", "reputation-blocked")
    lists = [
        (props.get("mikrotik.address_list", "suricata-blocked"), "IDS block",
         ["src-address-list={l}"], "block"),
        # dst-address-type=!local keeps the router itself reachable, so a
        # quarantined host still gets DNS (and DHCP) from it -- nothing else.
        (q, "quarantine", ["src-address-list={l} dst-address-type=!local",
                           "dst-address-list={l} src-address-type=!local"], "quarantine"),
        (rep, "IP reputation", ["src-address-list={l}", "dst-address-list={l}"],
         "ip_reputation"),
        # Inbound only: a scanner is a source. (With scanners.scope = all an
        # internal host can be listed too; add dst-address-type=!local for it
        # to keep reaching the router, as for the quarantine.)
        (props.get("scanners.list", "port-scanners"), "port scanner",
         ["src-address-list={l}"], "scanners"),
    ]
    lists = [item[:3] for item in lists if item[3] in roles]
    rules = {}
    for table in ("raw", "filter"):
        try:
            for rule in rtr.get(f"/ip/firewall/{table}") or []:
                if rule.get("disabled") == "true":
                    continue
                for side in ("src-address-list", "dst-address-list"):
                    if rule.get(side):
                        rules.setdefault(rule[side], []).append(
                            f"{table}: {rule.get('chain')} {rule.get('action')}")
        except Exception as exc:  # read permission, mostly
            warn(f"could not read /ip/firewall/{table}: {exc}")
    for lst, purpose, matchers in lists:
        if rules.get(lst):
            ok(f"{purpose} list '{lst}' is used by: " + "; ".join(rules[lst]))
            continue
        warn(f"no enabled firewall rule uses the {purpose} list '{lst}' -- "
             "listed addresses are NOT blocked yet")
        for matcher in matchers:
            todo.append(f"/ip/firewall/raw add chain=prerouting action=drop "
                        f"{matcher.format(l=lst)} comment=\"tzsp-monitor {purpose}\"")

    try:
        if "dns_filter" not in roles:
            raise LookupError("not a dns_filter router")
        dns = rtr.get("/ip/dns") or {}
        cache = int(str(dns.get("cache-size", "0")).rstrip("KiB") or 0)
        remote = dns.get("allow-remote-requests") == "true"
        (ok if remote else warn)(f"DNS: allow-remote-requests={'yes' if remote else 'no'}, "
                                 f"cache-size={cache} KiB")
        if not remote or cache < 65536:
            todo.append("/ip/dns set allow-remote-requests=yes cache-size=65536"
                        "   # adlist names live in the DNS cache")
    except LookupError:
        pass
    except Exception as exc:
        warn(f"could not read /ip/dns: {exc}")

    if not vxlan and monitor_ip and sniffer:
        target = f"{monitor_ip}:37008"
        try:
            sniff = rtr.get("/tool/sniffer") or {}
        except Exception as exc:
            warn(f"could not read /tool/sniffer: {exc}")
            sniff = None
        if sniff is not None:
            streaming = sniff.get("streaming-enabled") == "true"
            server = sniff.get("streaming-server", "")
            running = sniff.get("running") == "true"
            if streaming and running and server.split(":")[0] == monitor_ip:
                ok(f"sniffer streams TZSP to {server}")
            # arp-watch reads ARP out of the same stream; a MAC-protocol filter
            # that leaves it out starves the Ethernet Attacks board silently.
            macp = sniff.get("filter-mac-protocol", "")
            if macp and "arp" not in macp.split(","):
                warn(f"sniffer filter-mac-protocol={macp} leaves out ARP -- "
                     "arp-watch (Ethernet Attacks) will read NO ARP")
            else:
                warn(f"sniffer: streaming={'yes' if streaming else 'no'}, "
                     f"server={server or '-'}, running={'yes' if running else 'no'} "
                     f"-- this host expects {target}")
        if sniff is None or not (sniff.get("streaming-enabled") == "true"
                                 and sniff.get("running") == "true"
                                 and sniff.get("streaming-server", "").split(":")[0]
                                 == monitor_ip):
            todo.append(f"/tool/sniffer set streaming-enabled=yes streaming-server={target} "
                        "filter-stream=yes filter-interface=<the port to mirror>")
            todo.append("/tool/sniffer start")
    return todo


# ---------------------------------------------------------------------------
# The questions
# ---------------------------------------------------------------------------

def step_mirror(env):
    section("1. How does the mirror arrive?")
    current = "vxlan" if env.get("COMPOSE_FILE") == VXLAN_COMPOSE else "tzsp"
    mode = choose("mirror type", [
        ("tzsp", "TZSP on UDP 37008 -- a MikroTik /tool/sniffer stream (normal case)"),
        ("vxlan", "VXLAN on UDP 4789 -- e.g. an  virtual network TAP"),
    ], 0 if current == "tzsp" else 1)
    if mode == "vxlan":
        env.set("COMPOSE_FILE", VXLAN_COMPOSE)
    elif env.get("COMPOSE_FILE") == VXLAN_COMPOSE:
        env.unset("COMPOSE_FILE")
    return mode == "vxlan"


def step_router(props):
    section("2. MikroTik router (IDS blocking and DNS filtering)")
    info("Needs RouterOS 7.1+ with the REST API (7.15+ for DNS filtering).")
    enabled = ask_yes("let the stack talk to a MikroTik router?",
                      props.get("mikrotik.enabled", "true") == "true")
    props.set("mikrotik.enabled", "true" if enabled else "false")
    host = ask("router address (as reachable from this host)",
               props.get("mikrotik.host", "192.168.88.1"), v_host, allow_empty=False)
    props.set("mikrotik.host", host)
    if not enabled:
        info("blocking and DNS filtering stay off; alerts still reach the dashboards")
        return host, False

    scheme = choose("REST service", [
        ("https", "https (www-ssl) -- recommended"),
        ("http", "http (www) -- only over a trusted management path"),
    ], 0 if props.get("mikrotik.scheme", "https") == "https" else 1)
    props.set("mikrotik.scheme", scheme)
    default_port = props.get("mikrotik.port") or "443"
    if scheme == "http" and default_port == "443":
        default_port = "80"
    if scheme == "https" and default_port == "80":
        default_port = "443"
    props.set("mikrotik.port", ask("REST port", default_port, v_port))
    if scheme == "https":
        verify = ask_yes("verify the router's TLS certificate? (no for the usual self-signed one)",
                         props.get("mikrotik.verify_tls", "false") == "true")
        props.set("mikrotik.verify_tls", "true" if verify else "false")
    props.set("mikrotik.user", ask("API user", props.get("mikrotik.user", "ids-responder"),
                                   allow_empty=False))
    props.set("mikrotik.password", ask_secret("API password", props.get("mikrotik.password")))

    info("")
    info("Blocked addresses go on a firewall address list. Being on it blocks")
    info("nothing until a firewall rule references it (you add that by hand).")
    props.set("mikrotik.address_list",
              ask("address list name", props.get("mikrotik.address_list", "suricata-blocked"),
                  lambda v: None if re.fullmatch(r"[\w.-]+", v) else "letters, digits, _ . - only"))
    props.set("mikrotik.timeout",
              ask("how long an entry stays on the list ('-' = permanent, not advised)",
                  props.get("mikrotik.timeout", "1h"), v_duration))
    dry = ask_yes("dry run? (log what would be blocked, never touch the list)",
                  props.get("mikrotik.dry_run", "false") == "true")
    props.set("mikrotik.dry_run", "true" if dry else "false")
    extra = [n.strip() for n in props.get("mikrotik.routers").split(",") if n.strip()]
    if extra:
        info(f"also configured in suricata.properties: {', '.join(extra)} "
             "(mikrotik.routers) -- `install.py --check` probes them too")
    else:
        info("More routers: list them in mikrotik.routers in suricata.properties, "
             "each with mikrotik.<name>.host / .password (see the example file).")
    return host, True


def step_interface(env, props, vxlan, router_host):
    section("3. Capture interface and this host's address")
    route_dev, route_src = route_to(router_host)
    if vxlan:
        info("VXLAN mode: the collector reads the decapsulated tap (tzsp0) --")
        info("docker-compose.vxlan.yml sets that, nothing to choose here.")
        env.unset("SNIFF_INTERFACE")
    else:
        info("The NIC the TZSP stream from the router arrives on. The collector")
        info("sniffs it directly; the IDS branch does not care (it binds UDP 37008).")
        ifaces = interfaces()
        for name, state, addrs in ifaces:
            mark = "  <- route to the router" if name == route_dev else ""
            info(f"  {name:<16} {state:<8} {', '.join(addrs) or '-'}{mark}")
        names = [n for n, _, _ in ifaces]
        current = env.get("SNIFF_INTERFACE")
        default = current if current in names else (route_dev if route_dev in names
                                                    else (names[0] if names else ""))
        iface = ask("interface to sniff", default,
                    lambda v: None if os.path.exists(f"/sys/class/net/{v}")
                    else "no such interface on this host", allow_empty=False)
        env.set("SNIFF_INTERFACE", iface)
        addrs = next((a for n, _, a in ifaces if n == iface), [])
        if addrs and not route_src:
            route_src = addrs[0].split("/")[0]

    info("")
    info("The address of THIS host as the router sees it: the router streams the")
    info("mirror to it and downloads the DNS filter lists from it (port 8041).")
    current_url = props.get("dns_filter.base_url")
    m = re.match(r"https?://([^:/]+)", current_url)
    monitor_ip = ask("this host's address", m.group(1) if m else (route_src or ""),
                     v_host, allow_empty=False)
    props.set("dns_filter.base_url", f"http://{monitor_ip}:8041")
    return monitor_ip


def step_networks(props, monitor_ip, router_host):
    section("4. Your networks")
    info("HOME_NET tells the Suricata rules inbound from outbound. List every")
    info("internal range, comma-separated.")
    home = ask("internal networks (HOME_NET)",
               ",".join(split_list(props.get("suricata.home_net"))) or
               "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", v_cidr_list, allow_empty=False)
    props.set("suricata.home_net", "[" + ",".join(split_list(home)) + "]")

    info("")
    info("Never-block list: these are refused by the responder whatever fires.")
    info("Defaults cover all private ranges; add your own PUBLIC addresses")
    info("(office WAN, VPN gateways, monitoring) so an alert cannot lock you out.")
    nets = ask("never-block networks", props.get("whitelist.networks"), v_cidr_list)
    props.set("whitelist.networks", ", ".join(split_list(nets)))
    ips = split_list(props.get("whitelist.ips"))
    for must in (monitor_ip, router_host):
        if must and v_ip(must) is None and must not in ips \
                and not any(ipaddress.ip_address(must) in ipaddress.ip_network(n, strict=False)
                            for n in split_list(nets)):
            ips.append(must)
    ips = ask("never-block single IPs", ", ".join(ips), v_ip_list)
    props.set("whitelist.ips", ", ".join(split_list(ips)))

    info("")
    info("DNS visibility: if clients could also reach a filtering resolver other")
    info("than the router, name the router's DNS address(es) here so only *its*")
    info("0.0.0.0 answers count as blocks. Empty = any resolver.")
    props.set("dns_monitor.resolvers",
              ", ".join(split_list(ask("resolver addresses", props.get("dns_monitor.resolvers"),
                                       v_ip_list))))


def step_pcap(env, props):
    section("5. Full packet capture storage")
    info("pcap-dump keeps every mirrored frame in a ring of pcap files -- every")
    info("cleartext credential included. It is off until switched on in Grafana")
    info("(3 · Security -> Packet Capture). Ideally a disk of its own.")
    while True:
        path = ask("host directory for pcap files", env.get("PCAP_DIR", "./pcap"),
                   allow_empty=False)
        full = os.path.normpath(os.path.join(HERE, os.path.expanduser(path)))
        base = nearest_existing(full)
        usage = shutil.disk_usage(base)
        info(f"{full}: {fmt_size(usage.free)} free of {fmt_size(usage.total)}")
        code, docker_root, _ = run(["docker", "info", "-f", "{{.DockerRootDir}}"])
        try:
            if code == 0 and os.stat(base).st_dev == os.stat(docker_root).st_dev:
                warn(f"same filesystem as Docker's data ({docker_root}): a busy capture")
                warn("competes with InfluxDB for the disk (pcap yields at 80% used)")
        except OSError:
            pass
        if ask_yes("use it?"):
            break
    if path != "./pcap" or env.get("PCAP_DIR"):
        env.set("PCAP_DIR", path)

    suggest = props.get("pcap_dump.max_bytes", "10G")
    if (parse_size(suggest) or 0) > usage.free * 0.5:
        suggest = fmt_size(max(1024 ** 3, int(usage.free * 0.5) // 1024 ** 3 * 1024 ** 3))
        info(f"suggesting half the free space: {suggest}")
    props.set("pcap_dump.max_bytes", ask("total size budget for pcap files", suggest, v_size))
    props.set("pcap_dump.max_disk_percent",
              ask("never let the disk go past this % used",
                  props.get("pcap_dump.max_disk_percent", "80"),
                  lambda v: None if v.isdigit() and 10 <= int(v) <= 85
                  else "10-85 (disk-guard starts cutting at 85)"))
    on = ask_yes("start capturing on the first start? (normally switched on from Grafana)",
                 props.get("pcap_dump.enabled", "false") == "true")
    props.set("pcap_dump.enabled", "true" if on else "false")
    if on:
        props.set("pcap_dump.cidr", ", ".join(split_list(
            ask("only these networks (empty = everything)", props.get("pcap_dump.cidr"),
                v_cidr_list))))
    return full


def step_storage(props):
    section("6. History kept in InfluxDB")
    info("Flows and alerts are kept this long; disk-guard shortens it by itself")
    info("if the disk fills (never below 2 days).")
    props.set("disk_guard.influx_retention_days",
              ask("retention in days", props.get("disk_guard.influx_retention_days", "30"), v_int))




def step_cert():
    section("5. TLS certificate for HAProxy")
    cert_path = ask("path to fullchain PEM file", None, allow_empty=True)
    if cert_path:
        full_path = os.path.abspath(cert_path)
        dest_dir = os.path.join(HERE, "haproxy")
        dest = os.path.join(dest_dir, "fullchain.pem")
        if not os.path.isfile(full_path):
            bad(f"certificate file {full_path} not found")
            return False
        # ensure destination directory exists
        os.makedirs(dest_dir, exist_ok=True)
        shutil.copy2(full_path, dest)
        info(f"copied {full_path} to {dest}")
        ok("certificate imported")
        return True
    else:
        info("no certificate provided")
        return False


# existing function

def step_grafana(gf):
    section("4. Grafana and alerting")
    info("Grafana runs on port 3000 and shows alerts")
    # ... existing code continues"
    section("7. Grafana login")
    user = ask("admin user", gf.get("GF_SECURITY_ADMIN_USER", "admin"), allow_empty=False)
    gf.set("GF_SECURITY_ADMIN_USER", user)
    current = gf.get("GF_SECURITY_ADMIN_PASSWORD")
    while True:
        pw = ask_secret("admin password", current)
        if pw.lower() in ("admin", "changeme", "password") or len(pw) < 8:
            warn("that is guessable -- at least 8 characters, not a default")
            if not ask_yes("use it anyway?", False):
                current = ""
                continue
        break
    gf.set("GF_SECURITY_ADMIN_PASSWORD", pw)
    name = ask("what this site is called in the Site dropdown (optional)",
               gf.get("LOCAL_SITE_NAME"))
    if name:
        gf.set("LOCAL_SITE_NAME", name)
    else:
        gf.unset("LOCAL_SITE_NAME")
    info("Other sites to browse from here: REMOTE_SITE_<NAME>=<url> lines in properties.yml,")
    info("and REMOTE_GRAFANA_<NAME>=<url> for links to their own Grafana (Packet Capture).")


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def show_changes(title, changes):
    if not changes:
        return
    print(_c("1", f"   {title}"))
    for key, old, new in changes:
        if key in SECRET_KEYS or (key.startswith("mikrotik.")
                                  and key.endswith(".password")):
            old = "********" if old else old
            new = "********" if new else new
        old = "(unset)" if old is None else (old or "(empty)")
        new = "(removed)" if new is None else (new or "(empty)")
        print(f"     {key}: {old} -> {_c('1', new)}")


def stack_running():
    code, out, _ = run(["docker", "compose", "ps", "-q"])
    return code == 0 and bool(out)


def apply(env, props, gf, pcap_full):
    section("Summary")
    if props.rebased:
        info("suricata.properties will be rebased onto the current example: your values")
        info("are kept, sections added since it was written appear with their defaults.")
    env_changes, prop_changes, gf_changes = env.changes(), props.changes(), gf.changes()
    if not os.path.isfile(PROPS_FILE):
        info("suricata.properties will be created from the example.")
    show_changes(".env", env_changes)
    show_changes("suricata.properties", prop_changes)
    show_changes("properties.yml", gf_changes)
    if not (env_changes or prop_changes or gf_changes or props.rebased
            or not os.path.isfile(PROPS_FILE)):
        info("nothing to change.")
    elif not ask_yes("write these changes? (each file is backed up to .bak first)"):
        sys.exit("nothing written")
    else:
        if env_changes:
            write_in_place(ENV_FILE, env.text())
            ok(".env written")
        if prop_changes or props.rebased or not os.path.isfile(PROPS_FILE):
            write_in_place(PROPS_FILE, props.text(), mode=0o600)
            ok("suricata.properties written")
        if gf_changes:
            write_in_place(GRAFANA_FILE, gf.text(), mode=0o600)
            ok("properties.yml written")

    if not os.path.isdir(pcap_full):
        try:
            os.makedirs(pcap_full)
            ok(f"created {pcap_full}")
        except OSError:
            warn(f"could not create {pcap_full} -- Docker will, as root, on first start;"
                 f" or: sudo mkdir -p {pcap_full}")

    code, _, err = run(["docker", "compose", "config", "-q"])
    if code == 0:
        ok("docker compose config is valid")
    else:
        bad("docker compose config: " + err)
        return

    restart = sorted({svc for key, _, _ in prop_changes
                      for prefix, svcs in PROP_READERS.items() if key.startswith(prefix)
                      for svc in svcs})
    running = stack_running()
    section("Start")
    if ask_yes("run `docker compose up -d --build` now?" if not running else
               "stack is running: apply with `up -d --build`"
               + (f" and restart {', '.join(restart)}" if restart else "") + "?"):
        if subprocess.call(["docker", "compose", "up", "-d", "--build"], cwd=HERE) != 0:
            bad("docker compose up failed -- see above")
            return
        if running and restart:
            # Property files are read once at start, and a restart is enough:
            # the file was rewritten in place, so the bind mount still points at
            # it. `restart` (not `up --force-recreate`) keeps tzsp-decap's
            # namespace intact for suricata and pcap-dump.
            subprocess.call(["docker", "compose", "restart"] + restart, cwd=HERE)
    elif running and restart:
        info(f"to apply later: docker compose up -d --build && "
             f"docker compose restart {' '.join(restart)}")


def next_steps(todo, monitor_ip, vxlan, router_enabled):
    section("Still to do by hand")
    if router_enabled and todo is None:
        info("the router could not be checked -- see the INSTALL file, step 4")
    elif todo:
        info("On the router (RouterOS terminal):")
        for cmd in todo:
            print("     " + cmd)
    if vxlan:
        info("Point the virtual network TAP at this host, UDP 4789, and allow that")
        info("port in the VM's network security group.")
    info("")
    info("Host firewall: allow in "
         + ("4789/udp (mirror)" if vxlan else "37008/udp (mirror)")
         + ", 8041/tcp (router fetches lists), 3000/tcp (Grafana).")
    info("")
    info("Once it is up:")
    info(f"  Grafana:  http://{monitor_ip}:3000")
    info("  docker compose logs --tail=3 tzsp-decap            # pps > 0 = mirror arrives")
    info("  python3 tzsp-decap/selftest.py" + (" --vxlan" if vxlan else "")
         + "                     # IDS path end to end")
    info("  docker compose exec dns-filter python selftest.py  # filtering path")
    info("  docker compose exec mikrotik-responder python selftest.py  # responses")
    info("  docker compose exec ip-reputation python selftest.py --feeds")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="probe the host and the router with the current config; write nothing")
    args = ap.parse_args()

    print(_c("1", "tzsp-monitor setup assistant") +
          " -- Enter keeps [the value shown], '-' clears it, Ctrl-C aborts.")
    if not preflight() and not ask_yes("continue anyway?", False):
        sys.exit(1)

    env = EnvFile(ENV_FILE)
    props = PropertyFile(PROPS_FILE, PROPS_EXAMPLE)
    gf = EnvFile(GRAFANA_FILE, GRAFANA_TEMPLATE)

    if args.check:
        vxlan = env.get("COMPOSE_FILE") == VXLAN_COMPOSE
        m = re.match(r"https?://([^:/]+)", props.get("dns_filter.base_url"))
        monitor_ip = m.group(1) if m else route_to(props.get("mikrotik.host"))[1]
        todo = []
        routers = routers_of(props)
        for i, rp in enumerate(routers):
            section(f"Router {rp.name}" if len(routers) > 1 else "Router")
            if len(routers) > 1:
                info(f"{rp.get('mikrotik.host') or '(no host)'}, roles: "
                     f"{', '.join(r for r in ROLES if r in rp.roles)}")
            if not rp.get("mikrotik.host") or not rp.get("mikrotik.password"):
                bad(f"mikrotik{'' if rp.primary else '.' + rp.name}.host/password "
                    "not set -- " + ("run install.py without --check" if rp.primary
                                     else "add them to suricata.properties"))
                todo = None if todo is None or rp.primary else todo
                continue
            # The mirror is expected from the first router only.
            found = probe_router(rp, monitor_ip, vxlan, rp.roles, sniffer=i == 0)
            if found is None:
                todo = None if rp.primary else todo
                continue
            if todo is not None:
                prefix = f"[{rp.name}] " if len(routers) > 1 else ""
                todo += [prefix + cmd for cmd in found]
        next_steps(todo, monitor_ip or "<this host>", vxlan, True)
        return

    vxlan = step_mirror(env)
    router_host, router_enabled = step_router(props)
    monitor_ip = step_interface(env, props, vxlan, router_host)
    todo = []
    if router_enabled:
        section("Router check")
        if ask_yes("test the router login now? (read-only)"):
            todo = probe_router(props, monitor_ip, vxlan)
            if todo is None and not ask_yes("carry on with these settings anyway?", True):
                sys.exit("nothing written")
    step_networks(props, monitor_ip, router_host)
    pcap_full = step_pcap(env, props)
    step_storage(props)
    step_cert()
    step_grafana(gf)
    apply(env, props, gf, pcap_full)
    next_steps(todo, monitor_ip, vxlan, router_enabled)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit("aborted")
