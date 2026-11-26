r"""Full traffic retention: every mirrored frame, written to rotating pcap files.

    TZSP/VXLAN mirror -> tzsp-decap -> tap tzsp0 --> [tcpdump] --> /pcap/*.pcap
                                                         ^
                                     [this service] -----+-- budget, ceiling,
                                       :8050 control         on/off, CIDR filter
                                       (Grafana Infinity)    --> InfluxDB

What lands in the files is the *decapsulated* traffic -- the inner Ethernet
frames, exactly what Suricata and the collector see -- not the TZSP datagrams.
Wireshark could undo TZSP itself, but a capture restricted to a CIDR has to look
inside the tunnel to decide anything, and every tool opens a plain Ethernet
pcap. The tap is the one place every mirror (TZSP or VXLAN) converges, which is
why this service lives in tzsp-decap's network namespace, like Suricata.

Things that shape it:

* **tcpdump does the per-packet work.** One Python loop per packet is already
  the IDS's throughput ceiling (tzsp-decap); a second one in front of a disk
  would be a worse one. tcpdump captures, filters in the kernel's BPF engine
  and rotates by size (`-C`). This service only decides *whether* it runs and
  with which filter, and deletes what it wrote.
* **Bounded by bytes twice.** `pcap_dump.max_bytes` is the operator's budget;
  `pcap_dump.max_disk_percent` (80, below disk-guard's 85/90 on purpose) makes
  the budget shrink when the filesystem fills for any other reason. The files
  are a ring: the oldest *closed* file goes first, the one tcpdump is writing is
  never touched. When even one file no longer fits, capture is paused rather
  than allowed to fill the disk, and resumes when there is room again. Full
  packet capture is the most expendable data on this host, so it yields first.
* **The budget is enforced every `check_seconds`, so it can overshoot by what
  the mirror writes in that time** (a few hundred MB at line rate on 1 Gbps).
  The reserve kept for the live file absorbs most of it.
* **Changing the filter restarts tcpdump**, which starts a new *session*: a new
  file name prefix, so every file was captured under exactly one filter, and
  the listing says which.
* **The control API is not published.** It shares tzsp-decap's namespace, so
  Grafana reaches it as `tzsp-decap:8050`. Anyone who can view the dashboard
  can switch capture on -- and a full packet capture holds every cleartext
  credential on the wire -- so `pcap_dump.control_enabled = false` makes it
  read-only, and every change is written to `pcap_dump_control`.
* **Extraction is a second listener (:8051), reached through Grafana's
  datasource proxy, never a published port.** A browser cannot call
  tzsp-decap:8050, and an Infinity panel can only render a table, so a download
  goes `browser -> Grafana /api/datasources/proxy/uid/pcap-extract/... ->
  tzsp-decap:8051`: only a logged-in Grafana user gets a byte, and Grafana
  names that user in `X-Grafana-User` (`send_user_header`), which is what the
  audit records. The split mirrors dns-filter's 8040/8041: the proxied
  datasource points at a server that can only read, so it cannot become a
  second way to switch capture on.
"""
import ipaddress
import json
import os
import re
import signal
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROPERTIES_FILE = os.getenv("PROPERTIES_FILE", "/etc/tzsp-monitor/suricata.properties")
STATE_FILE = os.getenv("STATE_FILE", "/var/lib/pcap-dump/state.json")
INTERFACE = os.getenv("TAP_INTERFACE", "tzsp0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8050"))    # control, not published
EXTRACT_PORT = int(os.getenv("EXTRACT_PORT", "8051"))  # downloads, via Grafana's proxy
# Where the destination directory is on the *host*, for the dashboard only. A
# container cannot see which host path is bind-mounted into it, so compose
# passes the same value it mounts.
HOST_DIR = os.getenv("PCAP_HOST_DIR", "")
TCPDUMP = os.getenv("TCPDUMP", "tcpdump")

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "my-org")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")

KIB = 1024
MIB = 1024 * 1024
GIB = 1024 * 1024 * 1024

# tcpdump -C names the first file exactly as -w says and the next ones with a
# counter appended (`x.pcap`, `x.pcap1`, `x.pcap2`, ...). Closed files are
# renamed to FINISHED so they sort, and open in anything that keys on `.pcap`.
SESSION_FMT = "%Y%m%dT%H%M%SZ"
WRITING = re.compile(r"^tzsp-(\d{8}T\d{6}Z)\.pcap(\d*)$")
FINISHED = re.compile(r"^tzsp-(\d{8}T\d{6}Z)-(\d{4,})\.pcap$")

STATE_NAMES = {0: "off", 1: "capturing", 2: "paused_disk", 3: "error"}

# How long the old tcpdump keeps running after a filter change (see reconcile).
OVERLAP_SECONDS = 2.0

# Words that clear the CIDR filter. An empty box means "change nothing",
# because the dashboard re-sends it on every refresh.
CLEAR_WORDS = ("all", "any", "*", "none")


def log(msg):
    sys.stdout.write(f"{datetime.now().strftime('%H:%M:%S')} {msg}\n")
    sys.stdout.flush()


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def human(num):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024 or unit == "TiB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024.0


# ---------------------------------------------------------------------------
# Property file
# ---------------------------------------------------------------------------
class Config:
    """`key = value`, same parser and same file as the other services; `#` is
    a comment only at the start of a line."""

    def __init__(self, path):
        self.values = {}
        if not os.path.isfile(path):
            log(f"no property file at {path}: using built-in defaults "
                f"(capture off, 10 GiB budget)")
            return
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("!"):
                    continue
                if "=" not in line:
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

    def get_float(self, key, default):
        try:
            return float(self.get(key, "") or default)
        except ValueError:
            log(f"{key}: not a number, using {default}")
            return default

    def get_bool(self, key, default):
        value = self.get(key, "").lower()
        if value in ("true", "yes", "1", "on"):
            return True
        if value in ("false", "no", "0", "off"):
            return False
        return default

    def get_bytes(self, key, default):
        """`512M` / `20G`, binary suffixes, like disk-guard; bare = bytes."""
        raw = self.get(key, "").strip()
        if not raw:
            return default
        match = re.fullmatch(r"(?i)\s*(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?\s*", raw)
        if not match:
            log(f"{key}: not a size, using {human(default)}")
            return default
        scale = {"": 1, "k": KIB, "m": MIB, "g": GIB, "t": GIB * 1024}
        return int(float(match.group(1)) * scale[match.group(2).lower()])


class Settings:
    def __init__(self, cfg):
        self.path = cfg.get("pcap_dump.path", "/pcap") or "/pcap"
        self.max_bytes = cfg.get_bytes("pcap_dump.max_bytes", 10 * GIB)
        self.file_bytes = cfg.get_bytes("pcap_dump.file_bytes", 100 * MIB)
        # A ring of fewer than two files cannot rotate without deleting the
        # file it is writing, so the file size gives way to the budget.
        if self.file_bytes * 2 > self.max_bytes:
            clamped = max(MIB, self.max_bytes // 2)
            log(f"pcap_dump.file_bytes {human(self.file_bytes)} is more than half "
                f"of max_bytes {human(self.max_bytes)}; using {human(clamped)}")
            self.file_bytes = clamped
        self.max_disk_percent = cfg.get_float("pcap_dump.max_disk_percent", 80.0)
        self.control_enabled = cfg.get_bool("pcap_dump.control_enabled", True)
        self.seed_enabled = cfg.get_bool("pcap_dump.enabled", False)
        self.seed_cidr = cfg.get("pcap_dump.cidr", "")
        self.snaplen = max(0, cfg.get_int("pcap_dump.snaplen", 0))
        self.check_seconds = max(1, cfg.get_int("pcap_dump.check_seconds", 2))
        self.stats_seconds = max(10, cfg.get_int("pcap_dump.stats_seconds", 30))
        self.download_enabled = cfg.get_bool("pcap_dump.download_enabled", True)
        self.download_parallel = max(1, cfg.get_int("pcap_dump.download_parallel", 2))

    def describe(self):
        return (f"dir={self.path} budget={human(self.max_bytes)} "
                f"file={human(self.file_bytes)} ceiling={self.max_disk_percent:.0f}% "
                f"snaplen={self.snaplen or 'full'} "
                f"actions {'enabled' if self.control_enabled else 'DISABLED (read-only)'} "
                f"downloads {'enabled' if self.download_enabled else 'DISABLED'}")


# ---------------------------------------------------------------------------
# CIDR filter -> BPF
# ---------------------------------------------------------------------------
def parse_cidrs(text):
    """'10.0.0.0/16, 192.168.1.5' -> (['10.0.0.0/16', '192.168.1.5/32'], error).

    Host bits are dropped rather than refused (`10.1.2.3/16` means 10.1.0.0/16),
    because that is what anyone typing it into a box means. Unlike the
    dashboards' cidr box, any prefix length is exact here: BPF does the
    masking, so nothing has to round to an octet boundary.
    """
    nets = []
    for part in re.split(r"[,\s]+", text.strip()):
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            return [], f"not a CIDR: {part!r}"
        if str(net) not in nets:
            nets.append(str(net))
    if len(nets) > 32:
        return [], "more than 32 networks"
    return nets, ""


def bpf_filter(nets, extra=""):
    """Either endpoint in any of the networks -- the same rule as the
    dashboards' cidr box. The `vlan and (...)` half is what matches a tagged
    frame: a plain `net` reads the IP header at the untagged offset, and a
    mirror of a trunk port carries 802.1Q tags on most of its frames.

    `extra` is a hand-written expression ANDed on (extraction only). It is
    written as for an untagged frame and gets the same doubling -- unless it
    names `vlan`/`mpls` itself, because each of those keywords moves the offset
    everything after it reads, and a second one would look for a QinQ tag."""
    expr = " or ".join(f"net {n}" for n in nets)
    extra = extra.strip()
    if extra:
        if re.search(r"\b(vlan|mpls)\b", extra):
            return f"({extra}) and ({expr})" if expr else extra
        expr = f"({expr}) and ({extra})" if expr else extra
    if not expr:
        return ""
    return f"({expr}) or (vlan and ({expr}))"


# What the dashboard's Download protocol box offers, as BPF. Each one covers
# IPv4 and IPv6: tcpdump's bare `tcp`/`udp` already do, but `icmp` is IPv4
# only and `ip proto N` reads only an IPv4 header, so the v6 form is spelled
# out. `ip6 proto` checks the first next-header only -- an extension header in
# front of it hides the protocol, which for these five is vanishingly rare.
PROTOCOLS = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp or icmp6",
    "gre": "ip proto 47 or ip6 proto 47",
    "ospf": "ip proto 89 or ip6 proto 89",
}
# Only these carry ports. A port with any other protocol matches nothing,
# which is refused rather than handed back as an empty file.
PORTED = ("tcp", "udp")


def proto_port_filter(proto, port):
    """(expression, error) for the Download protocol/port boxes.

    proto: one of PROTOCOLS, or ""/any for every protocol. port: N, or a range
    N-M; it matches either end (source or destination), like tcpdump's `port`,
    so both directions of a conversation come out. Without a protocol a port
    means TCP or UDP (tcpdump's `port` also takes SCTP, harmlessly)."""
    proto = (proto or "").strip().lower()
    port = (port or "").strip().replace(" ", "")
    if proto in ("", "-", "any", "all", "$__all"):
        proto = ""
    if proto and proto not in PROTOCOLS:
        return "", f"protocol: expected one of {', '.join(PROTOCOLS)}"
    parts = [f"({PROTOCOLS[proto]})"] if proto else []
    if port:
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", port)
        lo, hi = (int(m.group(1)), int(m.group(2) or m.group(1))) if m else (0, 0)
        if not m or not 1 <= lo <= hi <= 65535:
            return "", "port: expected a port (443) or a range (8000-8100), 1-65535"
        if proto and proto not in PORTED:
            return "", f"port: {proto} has no ports -- clear the port box, or pick tcp/udp"
        parts.append(f"port {lo}" if lo == hi else f"portrange {lo}-{hi}")
    return " and ".join(parts), ""


# ---------------------------------------------------------------------------
# Files on disk
# ---------------------------------------------------------------------------
def scan(directory):
    """Every dump file, as dicts, oldest first."""
    files = []
    try:
        names = os.listdir(directory)
    except OSError:
        return files
    for name in names:
        match = WRITING.match(name)
        if match:
            session, index = match.group(1), int(match.group(2) or 0)
            writing = True
        else:
            match = FINISHED.match(name)
            if not match:
                continue
            session, index = match.group(1), int(match.group(2))
            writing = False
        try:
            st = os.stat(os.path.join(directory, name))
        except OSError:
            continue    # deleted between listdir and stat
        files.append({"name": name, "session": session, "index": index,
                      "writing": writing, "bytes": st.st_size,
                      "mtime": st.st_mtime})
    files.sort(key=lambda f: (f["session"], f["index"]))
    return files


def finished_name(session, index):
    return f"tzsp-{session}-{index:04d}.pcap"


def finalize(directory, files, running_session):
    """Rename every file tcpdump has closed to its finished name.

    A file is closed if its session is not the one running, or if the running
    session has already opened a later one -- tcpdump opens N+1 before writing
    to it, so the highest index is the only file it can still be writing.
    Renaming is safe even if that guess were wrong: tcpdump writes to its fd,
    not to the name.
    """
    newest = {}
    for f in files:
        if f["writing"]:
            newest[f["session"]] = max(newest.get(f["session"], -1), f["index"])
    for f in files:
        if not f["writing"]:
            continue
        if f["session"] == running_session and f["index"] == newest[f["session"]]:
            continue
        target = finished_name(f["session"], f["index"])
        try:
            os.rename(os.path.join(directory, f["name"]),
                      os.path.join(directory, target))
            f["name"], f["writing"] = target, False
        except OSError as exc:
            log(f"could not rename {f['name']}: {exc}")
    return files


def first_packet_time(path):
    """The first record's timestamp, from the pcap header -- when the file
    starts, which its mtime (when it ends) cannot say. 0 if there is none."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(32)
    except OSError:
        return 0
    if len(head) < 32:
        return 0
    magic = head[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        order = "little"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        order = "big"
    else:
        return 0
    return int.from_bytes(head[24:28], order)


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------
def disk(path):
    """(used_percent, bytes that may still be written before `percent`)
    -- signed, so a filesystem already over the ceiling gives a negative room.
    used/(used+avail), which is what `df` prints, same as disk-guard."""
    st = os.statvfs(path)
    avail = st.f_bavail * st.f_frsize
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    denominator = used + avail
    percent = (used / denominator * 100.0) if denominator else 0.0
    return percent, used, denominator


def room_to(used, denominator, percent):
    return int(denominator * percent / 100.0 - used)


def plan(closed, live_bytes, max_bytes, file_bytes, room):
    """Which closed files to delete, and whether capture can continue.

    closed      sizes of the closed files, oldest first
    live_bytes  what the file being written already holds (0 if none)
    room        bytes the filesystem may still take before the ceiling --
                negative when it is already over

    The allowance is the budget, or what the files hold now plus what the disk
    can still take, whichever is smaller. What has to fit inside it is the
    closed files plus a whole file's worth for the live one, since that is how
    big it grows before tcpdump rotates. Returns (delete_count, allowance, fits).
    Kept pure: it decides what gets deleted, so the selftest drives it directly.
    """
    total = sum(closed) + live_bytes
    allowance = min(max_bytes, total + room)
    reserve = max(file_bytes, live_bytes)
    kept = sum(closed)
    delete = 0
    while delete < len(closed) and kept + reserve > allowance:
        kept -= closed[delete]
        delete += 1
    return delete, allowance, kept + reserve <= allowance


# ---------------------------------------------------------------------------
# State: what the dashboard asked for (authoritative, survives restarts)
# ---------------------------------------------------------------------------
_state_lock = threading.Lock()


def read_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        state = {}
    state.setdefault("enabled", False)
    state.setdefault("cidrs", [])
    state.setdefault("sessions", {})
    return state


def write_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=1, sort_keys=True)
    os.replace(tmp, STATE_FILE)


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
    url = (f"{INFLUX_URL.rstrip('/')}/api/v2/write?org={urllib.parse.quote(INFLUX_ORG)}"
           f"&bucket={urllib.parse.quote(INFLUX_BUCKET)}&precision=ns")
    req = urllib.request.Request(url, data="\n".join(lines).encode(), method="POST",
                                 headers={"Authorization": f"Token {INFLUX_TOKEN}",
                                          "Content-Type": "text/plain; charset=utf-8"})
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except (urllib.error.URLError, OSError) as exc:
        log(f"influx write failed: {exc}")


def audit(action, detail, note=""):
    """pcap_dump_control: when capture was switched, re-filtered or paused.
    Same reason as rule-control's audit -- the container log rotates away, and
    'when did we start recording everything, and for which network' is a
    question someone will ask."""
    text = detail + (f" -- {note}" if note else "")
    influx_write([f"pcap_dump_control,action={esc_tag(action)} "
                  f"count=1i,detail={esc_str(text)} {time.time_ns()}"])


# ---------------------------------------------------------------------------
# tcpdump
# ---------------------------------------------------------------------------
STAT_LINE = re.compile(r"(\d+) packets? (captured|received by filter|dropped by kernel)")


class Capture:
    """One tcpdump process, i.e. one session: one filter, one file prefix."""

    def __init__(self, settings, session, cidrs):
        self.session = session
        self.cidrs = list(cidrs)
        self.counters = {"captured": 0, "received by filter": 0, "dropped by kernel": 0}
        self.last_error = ""
        self.started = time.time()
        base = os.path.join(settings.path, f"tzsp-{session}.pcap")
        size_mb = max(1, round(settings.file_bytes / 1_000_000))   # -C is 10^6 bytes
        cmd = [TCPDUMP, "-i", INTERFACE, "-n", "-q", "-Z", "root",
               "-s", str(settings.snaplen or 262144), "-B", "32768",
               "-C", str(size_mb), "-w", base]
        expr = bpf_filter(cidrs)
        if expr:
            cmd.append(expr)
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, text=True)
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stderr(self):
        for line in self.proc.stderr:
            line = line.strip()
            # The SIGUSR1 answer is all three counters on one line; the exit
            # summary is one per line.
            matches = STAT_LINE.findall(line)
            for count, name in matches:
                self.counters[name] = int(count)
            if line and not matches:
                self.last_error = line
                log(f"tcpdump: {line}")

    def alive(self):
        return self.proc.poll() is None

    def request_stats(self):
        """tcpdump prints its counters on SIGUSR1 (Linux's stand-in for SIGINFO);
        the stderr reader picks them up."""
        if self.alive():
            try:
                self.proc.send_signal(signal.SIGUSR1)
            except OSError:
                pass

    def stop(self):
        if self.alive():
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


# ---------------------------------------------------------------------------
# Supervisor: the only thread that starts, stops and deletes
# ---------------------------------------------------------------------------
class Supervisor:
    def __init__(self, settings):
        self.settings = settings
        self.capture = None
        self.last_session = ""
        self.paused = False          # by the disk ceiling, not by anyone's click
        self.error = ""
        self.restarts = []           # recent unexpected exits, for backoff
        self.wake = threading.Event()
        self.view = {}               # last pass, for /status
        self.deleted_files = 0
        self.deleted_bytes = 0
        self.last_counters = {}
        self.last_total = None

    # -- checks -------------------------------------------------------------
    def target_problem(self):
        path = self.settings.path
        if not os.path.isdir(path):
            return f"{path} does not exist"
        try:
            if os.stat(path).st_dev == os.stat("/").st_dev:
                # Not a mount: the files would go into the container's writable
                # layer, on Docker's data-root, where nothing can find them and
                # a recreate silently throws them away.
                return f"{path} is not a mounted directory"
        except OSError as exc:
            return str(exc)
        if not os.access(path, os.W_OK):
            return f"{path} is not writable"
        if not os.path.exists(f"/sys/class/net/{INTERFACE}"):
            return (f"no {INTERFACE} in this namespace (tzsp-decap not up yet, "
                    f"or it was recreated and this container needs a restart)")
        return ""

    # -- lifecycle ----------------------------------------------------------
    def start(self, cidrs):
        session = datetime.now(timezone.utc).strftime(SESSION_FMT)
        if session <= self.last_session:
            time.sleep(1.1)     # one session per second: the name is the key
            session = datetime.now(timezone.utc).strftime(SESSION_FMT)
        self.last_session = session
        with _state_lock:
            state = read_state()
            state["sessions"][session] = {"cidrs": list(cidrs), "started": now_utc()}
            write_state(state)
        self.capture = Capture(self.settings, session, cidrs)
        self.last_counters = {}
        log(f"capture started: session {session}, "
            f"{'filter ' + ', '.join(cidrs) if cidrs else 'all traffic'}")

    def stop(self, why):
        if self.capture:
            self.capture.stop()
            log(f"capture stopped ({why}): session {self.capture.session}")
            self.capture = None

    def reconcile(self, state, problem):
        wanted = state["enabled"] and not self.paused and not problem
        cap = self.capture
        if cap and not cap.alive():
            self.error = cap.last_error or f"tcpdump exited ({cap.proc.returncode})"
            log(f"capture died: {self.error}")
            self.capture = cap = None
            self.restarts = [t for t in self.restarts if time.time() - t < 300] + [time.time()]
        if not wanted:
            self.stop("switched off" if not state["enabled"] else
                      "disk ceiling" if self.paused else problem)
            return
        if cap and cap.cidrs != state["cidrs"]:
            # The new session starts first and the old one stops a little
            # later. libpcap hands frames over in ring blocks, up to a second
            # late, and a terminated tcpdump never drains its ring -- so
            # stop-then-start loses the last second before every filter change.
            # Overlapping puts those frames in both files instead of neither.
            old = cap
            threading.Timer(OVERLAP_SECONDS, old.stop).start()
            log(f"filter changed: session {old.session} stops in "
                f"{OVERLAP_SECONDS:.0f}s")
            self.capture = None
            self.start(state["cidrs"])
            return
        if not cap:
            # Back off a crash loop: a bad interface or a full disk would
            # otherwise restart tcpdump every pass and spray the log.
            if len(self.restarts) >= 5:
                if time.time() - self.restarts[-1] < 60:
                    return
            self.start(state["cidrs"])

    # -- one pass -----------------------------------------------------------
    def run_pass(self):
        s = self.settings
        with _state_lock:
            state = read_state()
        problem = self.target_problem()

        files = []
        if os.path.isdir(s.path):
            files = finalize(s.path, scan(s.path),
                             self.capture.session if self.capture else None)
        closed = [f for f in files if not f["writing"]]
        live = sum(f["bytes"] for f in files if f["writing"])

        if not state["enabled"]:
            self.paused = False     # a pause belongs to a capture that is wanted
        percent, used, denominator = (0.0, 0, 0)
        if not problem:
            percent, used, denominator = disk(s.path)
            room = room_to(used, denominator, s.max_disk_percent)
            delete, allowance, fits = plan([f["bytes"] for f in closed], live,
                                           s.max_bytes, s.file_bytes, room)
            for f in closed[:delete]:
                try:
                    os.unlink(os.path.join(s.path, f["name"]))
                    self.deleted_files += 1
                    self.deleted_bytes += f["bytes"]
                except OSError as exc:
                    log(f"could not delete {f['name']}: {exc}")
            closed = closed[delete:]
            kept = sum(f["bytes"] for f in closed)
            if not fits and not self.paused and state["enabled"]:
                self.paused = True
                detail = (f"disk {percent:.1f}% (ceiling {s.max_disk_percent:.0f}%), "
                          f"room for {human(max(0, allowance))}, one file needs "
                          f"{human(s.file_bytes)}")
                log(f"pausing capture: {detail}")
                audit("pause", detail)
            elif self.paused and kept + 2 * s.file_bytes <= allowance:
                # Hysteresis: resuming at exactly one file's room would pause
                # again as soon as that file filled.
                self.paused = False
                log(f"resuming capture: disk {percent:.1f}%")
                audit("resume", f"disk {percent:.1f}%")
        else:
            allowance = 0

        self.reconcile(state, problem)
        if self.capture:
            self.error = ""
        elif problem:
            self.error = problem

        if not state["enabled"]:
            code = 0
        elif self.paused:
            code = 2
        elif self.capture and self.capture.alive():
            code = 1
        else:
            code = 3

        # Forget sessions whose files are all gone, so the state file is
        # bounded by what is on disk.
        live_sessions = {f["session"] for f in files}
        if self.capture:
            live_sessions.add(self.capture.session)
        with _state_lock:
            state = read_state()
            stale = [k for k in state["sessions"] if k not in live_sessions]
            if stale:
                for k in stale:
                    del state["sessions"][k]
                write_state(state)

        self.view = {
            "state_code": code, "state": STATE_NAMES[code], "error": self.error,
            "enabled": 1 if state["enabled"] else 0,
            "cidrs": state["cidrs"],
            "files": len(closed) + sum(1 for f in files if f["writing"]),
            "bytes": sum(f["bytes"] for f in closed) + live,
            "budget_bytes": s.max_bytes, "allowance_bytes": max(0, allowance),
            "disk_percent": round(percent, 1),
            # Files are sorted oldest first, and deletions only ever took the
            # head of the closed ones, so this is the oldest still on disk.
            "oldest_file": closed[0]["name"] if closed else
                           next((f["name"] for f in files if f["writing"]), ""),
            "session": self.capture.session if self.capture else "",
        }
        return self.view

    def stats_point(self):
        """One `pcap_dump` point. Counters are deltas, for the same reason as
        suricata_stats: tcpdump's restart with every filter change zeroes them."""
        v = self.view
        if not v:
            return None
        counters = dict(self.capture.counters) if self.capture else {}
        delta = {}
        for key in ("captured", "dropped by kernel"):
            now = counters.get(key, 0)
            prev = self.last_counters.get(key, 0)
            delta[key] = now - prev if now >= prev else now
        self.last_counters = counters
        # Bytes written: what is on disk now, plus what was deleted since the
        # last point, minus what was on disk then.
        total = v["bytes"] + self.deleted_bytes
        written = 0 if self.last_total is None else max(0, total - self.last_total)
        self.last_total = total
        fields = {
            "up": "1i", "state_code": f"{v['state_code']}i",
            "state": esc_str(v["state"]), "enabled": f"{v['enabled']}i",
            "files": f"{v['files']}i", "bytes": f"{v['bytes']}i",
            "budget_bytes": f"{v['budget_bytes']}i",
            "allowance_bytes": f"{v['allowance_bytes']}i",
            "disk_percent": f"{float(v['disk_percent'])}",
            "written_bytes": f"{written}i",
            "packets": f"{delta['captured']}i",
            "dropped": f"{delta['dropped by kernel']}i",
            "deleted_files": f"{self.deleted_files}i",
            "deleted_bytes": f"{self.deleted_bytes}i",
            "filter": esc_str(", ".join(v["cidrs"]) or "all"),
        }
        self.deleted_files = 0
        self.deleted_bytes = 0
        return ("pcap_dump " + ",".join(f"{k}={val}" for k, val in fields.items())
                + f" {time.time_ns()}")

    def forever(self):
        next_stats = time.time() + self.settings.stats_seconds
        while True:
            try:
                self.run_pass()
            except Exception as exc:    # noqa: BLE001 -- the loop must not die
                log(f"pass failed: {exc!r}")
            if time.time() >= next_stats:
                if self.capture:
                    self.capture.request_stats()
                    time.sleep(0.2)    # let the reader thread catch the reply
                point = self.stats_point()
                if point:
                    influx_write([point])
                next_stats = time.time() + self.settings.stats_seconds
            self.wake.wait(self.settings.check_seconds)
            self.wake.clear()


# ---------------------------------------------------------------------------
# Extraction: the ring, re-filtered by tcpdump, as one pcap or as text
# ---------------------------------------------------------------------------
PCAP_MAGIC = {  # first four bytes -> (struct byte order, ticks per second)
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
FORMATS = ("pcap", "text", "hex")
COPY_CHUNK = 256 * KIB


class ExtractError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Request:
    """What /extract and /check were asked for, validated. Raises ExtractError."""

    def __init__(self, params):
        def one(key):
            return (params.get(key, [""])[0] or "").strip()

        host = one("host")
        if host in ("", "-"):
            host = ""
        self.nets, error = parse_cidrs(host)
        if error:
            raise ExtractError(400, f"host: {error}")
        self.bpf = one("bpf")
        if len(self.bpf) > 500 or any(ord(c) < 32 for c in self.bpf):
            raise ExtractError(400, "bpf: too long, or has control characters")
        self.proto = one("proto").lower()
        if self.proto in ("-", "any", "all", "$__all"):
            self.proto = ""
        self.port = one("port").replace(" ", "")
        self.pp_expr, error = proto_port_filter(self.proto, self.port)
        if error:
            raise ExtractError(400, error)
        if not self.nets and not self.bpf:
            # The whole ring is on the host already; the point of this is a
            # *slice*, and one forgotten box should not start a 10 GB stream.
            raise ExtractError(400, "no host given: type an IP or CIDR into the Host box")
        self.format = one("format").lower() or "pcap"
        if self.format not in FORMATS:
            raise ExtractError(400, f"format: expected one of {', '.join(FORMATS)}")
        try:
            # Grafana's ${__from}/${__to}: epoch milliseconds.
            self.t0 = int(one("from") or 0) / 1000.0
            self.t1 = int(one("to") or 0) / 1000.0 or time.time() + 86400
        except ValueError:
            raise ExtractError(400, "from/to: expected epoch milliseconds") from None
        if self.t1 <= self.t0:
            raise ExtractError(400, "the time range is empty")
        # The boxes go AFTER a hand-written expression: if that names `vlan`,
        # everything following it reads past the tag, which is where the
        # protocol and port of a tagged frame are.
        extra = " and ".join(f"({e})" for e in (self.bpf, self.pp_expr) if e)
        self.expr = bpf_filter(self.nets, extra)

    def scope(self):
        parts = [", ".join(self.nets)] if self.nets else []
        if self.proto:
            parts.append(self.proto)
        if self.port:
            parts.append(f"port {self.port}")
        if self.bpf:
            parts.append(f"bpf '{self.bpf}'")
        return " and ".join(parts)

    def window(self):
        fmt = "%Y-%m-%d %H:%M:%S"
        return (f"{datetime.fromtimestamp(self.t0, timezone.utc).strftime(fmt)} - "
                f"{datetime.fromtimestamp(self.t1, timezone.utc).strftime(fmt)} UTC")

    def filename(self):
        label = "_".join(n.replace("/32", "").replace("/128", "").replace("/", "-")
                         .replace(":", ".") for n in self.nets) or "bpf"
        label += "".join(f"-{x}" for x in (self.proto, self.port and f"port{self.port}") if x)
        stamp = "%Y%m%dT%H%M%SZ"
        span = (f"{datetime.fromtimestamp(self.t0, timezone.utc).strftime(stamp)}-"
                f"{datetime.fromtimestamp(min(self.t1, time.time()), timezone.utc).strftime(stamp)}")
        return f"{label}-{span}.{'pcap' if self.format == 'pcap' else 'txt'}"


def networks_overlap(a_list, b_list):
    a_nets = [ipaddress.ip_network(n) for n in a_list]
    b_nets = [ipaddress.ip_network(n) for n in b_list]
    return any(a.version == b.version and a.overlaps(b) for a in a_nets for b in b_nets)


def select_files(directory, sessions, nets, t0, t1):
    """Every file whose span touches [t0, t1], oldest first, each marked with
    whether it is read and why not.

    A file spans its first packet (from its header) to its mtime, which is
    never earlier than its last packet. `trim` is set when the span sticks out
    of the window, so only those files pay for per-record parsing; the rest
    are copied as tcpdump writes them. A file captured under a filter that
    cannot contain the host is skipped without being opened -- the capture
    filter already proved it holds none of its packets."""
    out = []
    for f in scan(directory):
        start = first_packet_time(os.path.join(directory, f["name"]))
        if not start:
            continue    # header only, nothing captured yet
        if start > t1 or f["mtime"] < t0:
            continue
        cidrs = sessions.get(f["session"], {}).get("cidrs", [])
        f["start"] = start
        f["filter"] = ", ".join(cidrs) or "all traffic"
        f["trim"] = not (start >= t0 and f["mtime"] <= t1)
        f["use"] = True
        f["why"] = "partly in range: trimmed" if f["trim"] else "read"
        if nets and cidrs and not networks_overlap(nets, cidrs):
            f["use"] = False
            f["why"] = "skipped: captured under a filter that excludes the host"
        out.append(f)
    return out


def validate_expr(expr, sample_file):
    """Compile the filter against a real file, so a typo is a 400 with
    tcpdump's own words instead of a download that ends after 24 bytes."""
    if not expr:
        return ""
    proc = subprocess.run([TCPDUMP, "-d", "-r", sample_file, expr],
                          capture_output=True, text=True, timeout=30)
    if proc.returncode == 0:
        return ""
    lines = [ln for ln in proc.stderr.splitlines()
             if ln.strip() and not ln.startswith("reading from file")]
    return (lines[-1] if lines else f"tcpdump exited {proc.returncode}").replace("tcpdump: ", "")


def read_exact(stream, size):
    data = stream.read(size)
    return data if len(data) == size else None


def stream_filtered(files, expr, t0, t1, write):
    """Run tcpdump -r over each file in turn and write one pcap stream: the
    first file's global header, then the matching records of every file.
    Returns (packets, bytes). Packets are counted only on trimmed files, the
    rest go through as opaque bytes -- -1 then means 'not counted'.

    Records inside one file are in capture order, so on a trimmed file the
    first record past t1 ends that file early. Two sessions overlap by
    OVERLAP_SECONDS at a filter change, so a frame from that overlap can
    appear twice; Wireshark's 'remove duplicates' or `editcap -D` handles it.
    """
    wrote_header = False
    total, packets, counted = 0, 0, True
    for f in files:
        cmd = ["nice", "-n", "10", TCPDUMP, "-r", f["path"], "-w", "-", "-n"]
        if expr:
            cmd.append(expr)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        errors = []
        reader = threading.Thread(target=lambda p=proc: errors.extend(
            ln.decode(errors="replace").strip() for ln in p.stderr), daemon=True)
        reader.start()
        try:
            header = read_exact(proc.stdout, 24)
            if header is None:
                continue
            order, ticks = PCAP_MAGIC.get(header[:4], ("<", 1_000_000))
            if not wrote_header:
                write(header)
                total += 24
                wrote_header = True
            if not f["trim"]:
                counted = False
                while True:
                    chunk = proc.stdout.read(COPY_CHUNK)
                    if not chunk:
                        break
                    write(chunk)
                    total += len(chunk)
                continue
            rec_fmt = order + "IIII"
            while True:
                rec = read_exact(proc.stdout, 16)
                if rec is None:
                    break
                sec, frac, incl, _orig = struct.unpack(rec_fmt, rec)
                body = read_exact(proc.stdout, incl)
                if body is None:
                    break     # the live file, cut mid-record
                ts = sec + frac / ticks
                if ts > t1:
                    break
                if ts >= t0:
                    write(rec + body)
                    total += 16 + incl
                    packets += 1
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            reader.join(timeout=2)
            for line in errors:
                # Expected noise: the banner, and the live file being cut short.
                if line and not line.startswith("reading from file") \
                        and "truncated dump file" not in line:
                    log(f"extract {f['name']}: {line}")
    if not wrote_header:
        # Nothing at all was read: still a valid, empty capture.
        write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        total += 24
    return (packets if counted else -1), total


_extract_slots = None


class ExtractHandler(BaseHTTPRequestHandler):
    """Read-only. Reached by browsers through Grafana's datasource proxy
    (`pcap-extract`), and by the dashboard's Infinity panels for /check and
    /plan. Nothing here can change what is captured."""
    server_version = "pcap-dump-extract"

    def log_message(self, *args):
        pass

    def text(self, code, message):
        body = (message + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def json(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def plan(self, params):
        """(request, files to read, every file in the window). Raises ExtractError."""
        req = Request(params)
        with _state_lock:
            sessions = read_state()["sessions"]
        listed = select_files(SETTINGS.path, sessions, req.nets, req.t0, req.t1)
        for f in listed:
            f["path"] = os.path.join(SETTINGS.path, f["name"])
        files = [f for f in listed if f["use"]]
        if files:
            problem = validate_expr(req.expr, files[0]["path"])
            if problem:
                raise ExtractError(400, f"filter: {problem}")
        return req, files, listed

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        route = parsed.path.rstrip("/")
        if route == "/check":
            self.json([self.check(params)])
        elif route == "/plan":
            try:
                _, _, listed = self.plan(params)
            except ExtractError:
                listed = []
            self.json([{
                "file": f["name"], "bytes": f["bytes"], "filter": f["filter"],
                "first_packet": datetime.fromtimestamp(f["start"], timezone.utc)
                                .strftime("%Y-%m-%d %H:%M:%S"),
                "last_write": datetime.fromtimestamp(f["mtime"], timezone.utc)
                              .strftime("%Y-%m-%d %H:%M:%S"),
                "use": f["why"],
            } for f in reversed(listed)])
        elif route == "/extract":
            self.extract(params)
        else:
            self.text(404, "not found")

    def check(self, params):
        """One row for the Download tile: 0 waiting for a host, 1 ready,
        2 nothing in the window, 3 refused (bad input, or downloads off)."""
        if not SETTINGS.download_enabled:
            return {"state_code": 3, "message": "pcap_dump.download_enabled = false",
                    "files": 0, "scan_bytes": 0}
        try:
            req, files, _ = self.plan(params)
        except ExtractError as exc:
            waiting = str(exc).startswith("no host given")
            return {"state_code": 0 if waiting else 3, "message": str(exc),
                    "files": 0, "scan_bytes": 0}
        if not files:
            return {"state_code": 2, "files": 0, "scan_bytes": 0,
                    "message": f"no capture file covers {req.window()} for {req.scope()}"}
        size = sum(f["bytes"] for f in files)
        return {"state_code": 1, "files": len(files), "scan_bytes": size,
                "message": f"{len(files)} file(s), {human(size)} to scan for {req.scope()}"}

    def extract(self, params):
        if not SETTINGS.download_enabled:
            self.text(403, "downloads are switched off (pcap_dump.download_enabled = false)")
            return
        try:
            req, files, _ = self.plan(params)
        except ExtractError as exc:
            self.text(exc.code, str(exc))
            return
        except subprocess.TimeoutExpired:
            self.text(503, "tcpdump did not answer while checking the filter")
            return
        if not files:
            self.text(404, f"no capture file covers {req.window()} for {req.scope()}"
                           f" -- widen the dashboard's time range")
            return
        if not _extract_slots.acquire(blocking=False):
            self.text(429, f"{SETTINGS.download_parallel} extraction(s) already running; "
                           f"try again when one has finished")
            return
        # Grafana adds this on proxied requests (send_user_header); a call
        # made by hand inside the namespace has none.
        user = self.headers.get("X-Grafana-User", "") or "(no Grafana user)"
        started = time.time()
        outcome, packets, sent = "complete", -1, 0
        try:
            # Headers go out before the first file is read: Grafana's proxy
            # gives up on a backend that is silent for [dataproxy] timeout,
            # and scanning a ring for one quiet host can take longer.
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap"
                             if req.format == "pcap" else "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{req.filename()}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if req.format == "pcap":
                packets, sent = stream_filtered(files, req.expr, req.t0, req.t1,
                                                self.wfile.write)
            else:
                packets, sent = self.stream_text(req, files)
        except (BrokenPipeError, ConnectionResetError):
            outcome = "aborted by the client"
        except Exception as exc:    # noqa: BLE001 -- report it, keep serving
            outcome = f"failed: {exc!r}"
        finally:
            _extract_slots.release()
            detail = (f"{req.format} of {req.scope()}, {req.window()}, "
                      f"{len(files)} file(s), {human(sent)} sent"
                      f"{'' if packets < 0 else f', {packets} packets'}, "
                      f"{time.time() - started:.0f}s, {outcome}, by {user}")
            log(f"download: {detail}")
            audit("download", detail)

    def stream_text(self, req, files):
        """The same filtered pcap, fed through a second tcpdump that prints it.
        -tttt is an absolute timestamp (UTC: the container has no zone), -e
        adds the link layer, which is where the VLAN tag is; hex adds -X."""
        self.wfile.write((f"# {req.scope()} | {req.window()} | {len(files)} file(s) "
                          f"| filter: {req.expr}\n").encode())
        cmd = ["nice", "-n", "10", TCPDUMP, "-r", "-", "-nn", "-tttt", "-e"]
        if req.format == "hex":
            cmd.append("-X")
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        result = {}

        def feed():
            try:
                result["counts"] = stream_filtered(files, req.expr, req.t0, req.t1,
                                                   proc.stdin.write)
            except (BrokenPipeError, OSError):
                pass        # the printer went away: the client did
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

        feeder = threading.Thread(target=feed, daemon=True)
        feeder.start()
        sent = 0
        try:
            while True:
                chunk = proc.stdout.read1(COPY_CHUNK)
                if not chunk:
                    break
                self.wfile.write(chunk)
                sent += len(chunk)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            feeder.join(timeout=10)
        return result.get("counts", (-1, 0))[0], sent


SETTINGS = None
SUPERVISOR = None


# ---------------------------------------------------------------------------
# Control
# ---------------------------------------------------------------------------
def apply_actions(params):
    dump = (params.get("dump", [""])[0] or "").strip().lower()
    cidr = (params.get("cidr", [""])[0] or "").strip()
    note = (params.get("note", [""])[0] or "")[:200]

    if dump in ("", "-") and cidr in ("", "-"):
        return []
    if not SETTINGS.control_enabled:
        return ["pcap_dump.control_enabled = false: read-only"]

    messages = []
    dirty = False
    with _state_lock:
        state = read_state()
        if dump in ("on", "off"):
            want = dump == "on"
            if state["enabled"] != want:
                state["enabled"] = want
                dirty = True
                scope = ", ".join(state["cidrs"]) or "all traffic"
                messages.append(f"capture turned {dump}")
                audit(dump, f"capture {dump} ({scope})", note)
        elif dump not in ("", "-"):
            messages.append(f"ignored dump={dump!r} (expected on/off)")

        if cidr and cidr != "-":
            if cidr.lower() in CLEAR_WORDS:
                nets, error = [], ""
            else:
                nets, error = parse_cidrs(cidr)
            if error:
                messages.append(f"filter unchanged: {error}")
            elif nets != state["cidrs"]:
                state["cidrs"] = nets
                dirty = True
                scope = ", ".join(nets) or "all traffic"
                messages.append(f"filter set to {scope}")
                audit("filter", scope, note)
        if dirty:
            write_state(state)
    if dirty:
        SUPERVISOR.wake.set()
    return messages


def file_rows():
    s = SETTINGS
    with _state_lock:
        sessions = read_state()["sessions"]
    rows = []
    for f in reversed(scan(s.path)):
        meta = sessions.get(f["session"], {})
        first = first_packet_time(os.path.join(s.path, f["name"]))
        rows.append({
            "file": f["name"],
            "state": "writing" if f["writing"] else "complete",
            "bytes": f["bytes"],
            "first_packet": (datetime.fromtimestamp(first, timezone.utc)
                             .strftime("%Y-%m-%d %H:%M:%S") if first else ""),
            "last_write": datetime.fromtimestamp(f["mtime"], timezone.utc)
                          .strftime("%Y-%m-%d %H:%M:%S"),
            "filter": ", ".join(meta.get("cidrs", [])) or
                      ("all traffic" if meta else "(unknown)"),
            "session": f["session"],
            "host_path": os.path.join(HOST_DIR, f["name"]) if HOST_DIR else "",
        })
    return rows


def status_row():
    v = SUPERVISOR.view or {}
    oldest = 0
    if v.get("oldest_file"):
        oldest = first_packet_time(os.path.join(SETTINGS.path, v["oldest_file"]))
    return [{
        "state_code": v.get("state_code", 3),
        "state": v.get("state", "error"),
        "error": v.get("error", "starting"),
        "enabled": v.get("enabled", 0),
        "control_enabled": 1 if SETTINGS.control_enabled else 0,
        "filter": ", ".join(v.get("cidrs", [])) or "all traffic",
        "files": v.get("files", 0),
        "bytes": v.get("bytes", 0),
        "budget_bytes": SETTINGS.max_bytes,
        "allowance_bytes": v.get("allowance_bytes", 0),
        "budget_used_pct": round(100.0 * v.get("bytes", 0) / SETTINGS.max_bytes, 1)
                           if SETTINGS.max_bytes else 0,
        "disk_percent": v.get("disk_percent", 0),
        "disk_ceiling": SETTINGS.max_disk_percent,
        # How far back the ring reaches: the first packet of the oldest file
        # still on disk. -1 = nothing captured yet.
        "retained_seconds": int(time.time() - oldest) if oldest else -1,
        "file_bytes": SETTINGS.file_bytes,
        "path": SETTINGS.path,
        "host_dir": HOST_DIR,
        "session": v.get("session", ""),
    }]


class ControlHandler(BaseHTTPRequestHandler):
    server_version = "pcap-dump"

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

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if parsed.path in ("/apply", "/files", "/"):
            messages = apply_actions(params) if parsed.path != "/files" else []
            if messages:
                log(" | ".join(messages))
                # Let the supervisor act before the table is drawn, so the
                # click's own refresh already shows the new session.
                time.sleep(0.5)
            self.reply(file_rows())
        elif parsed.path == "/status":
            self.reply(status_row())
        elif parsed.path == "/messages":
            messages = apply_actions(params)
            if messages:
                log(" | ".join(messages))
            self.reply([{"message": m} for m in messages] or [{"message": "no change"}])
        else:
            self.reply({"error": "not found"}, code=404)


def main():
    global SETTINGS, SUPERVISOR, _extract_slots
    SETTINGS = Settings(Config(PROPERTIES_FILE))
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)

    with _state_lock:
        first_start = not os.path.isfile(STATE_FILE)
        state = read_state()
        if first_start:
            # First start only: from here on the dashboard owns both, like
            # dns-filter's categories. Editing the property later changes
            # nothing; the dashboard does.
            nets, error = parse_cidrs(SETTINGS.seed_cidr)
            if error:
                log(f"pcap_dump.cidr ignored: {error}")
            state["enabled"] = SETTINGS.seed_enabled
            state["cidrs"] = nets
            log(f"seeded from the property file: capture "
                f"{'on' if state['enabled'] else 'off'}, "
                f"{', '.join(nets) or 'all traffic'}")
        write_state(state)

    SUPERVISOR = Supervisor(SETTINGS)
    log(f"pcap-dump: control on :{LISTEN_PORT}, extract on :{EXTRACT_PORT} | "
        f"{SETTINGS.describe()} | "
        f"capture {'ON' if state['enabled'] else 'OFF'} "
        f"({', '.join(state['cidrs']) or 'all traffic'})"
        f"{' | host dir ' + HOST_DIR if HOST_DIR else ''}")

    def shutdown(*_):
        SUPERVISOR.stop("container stopping")
        # Whatever tcpdump had open is closed now; give it its final name.
        if os.path.isdir(SETTINGS.path):
            finalize(SETTINGS.path, scan(SETTINGS.path), None)
        sys.exit(0)
    signal.signal(signal.SIGTERM, shutdown)

    # The namespace is tzsp-decap's, and so is its tap -- which has no address
    # and only ever carries mirrored frames addressed to other machines' MACs,
    # so binding all addresses is reachable from the compose network alone.
    threading.Thread(
        target=ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), ControlHandler)
        .serve_forever, daemon=True).start()
    _extract_slots = threading.BoundedSemaphore(SETTINGS.download_parallel)
    threading.Thread(
        target=ThreadingHTTPServer(("0.0.0.0", EXTRACT_PORT), ExtractHandler)
        .serve_forever, daemon=True).start()
    SUPERVISOR.forever()


if __name__ == "__main__":
    main()
