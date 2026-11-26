r"""Keep the disk under a ceiling: Suricata's logs, and InfluxDB's retention.

    /var/log/suricata  (eve.json + rotations)  --\
                                                  >-- [this service] --> InfluxDB
    InfluxDB bucket retention (/api/v2/buckets) --/     (disk_guard points)

Nothing else in this stack has an upper bound, and a full disk stops the
capture, the responder, the router writes and Grafana at the same moment:

* **eve.json is written forever.** `rotate-interval: day` in suricata.yaml is
  accepted by the config parser -- `conf-get outputs.0.eve-log.rotate-interval`
  answers "day" -- but measured on Suricata 8.0.6 it never rolls the file over:
  one eve.json held 14 days and 105 MB here, and no rotated copy was ever
  created. Even where it does work, a *daily* rollover bounds nothing inside a
  day: one noisy rule, or `stats` at a 30s interval (~9 KB a record, which was
  99.7% of that 105 MB), writes gigabytes in an afternoon.
* **The InfluxDB bucket is created with infinite retention.** Every flow the
  collector has ever seen is still on disk; on the production mirror
  (~200k flows/hour) that is hundreds of MB a day, forever.

Two rules shape everything below.

* **Bounded by bytes, not by age.** `eve.retain_days` was the old answer and it
  cannot keep a promise about a disk: three days of a quiet week is 20 MB and
  three days of an incident is 40 GB. Every limit here is a byte count, and the
  byte counts are re-derived from what the filesystem actually has left, so the
  ceiling holds even when something *outside* this stack is what filled the
  disk.
* **Delete the oldest evidence, never the live file.** eve.json is Suricata's
  open fd: unlinking it frees nothing (the space returns only when Suricata
  exits) and blinds the responder. So the live file is *rotated* -- renamed,
  then `reopen-log-files` on the command socket -- and only the rotations are
  ever deleted, oldest first. Suricata recreates the file lazily, on its next
  write (measured: ~13s, on the next stats tick), which is why both this
  service and the responder tolerate eve.json being briefly absent.

What this service does NOT do: it never deletes InfluxDB points directly. A
delete inside a shard rewrites it and frees nothing until compaction, whereas
dropping the bucket's retention makes InfluxDB expire whole shard groups, which
does return the space. So the only lever pulled here is `retentionRules`, and
the shard group duration is pulled down to a day at the same time so that
expiry has something better than 7-day granularity to work with.
"""
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

PROPERTIES_FILE = os.getenv("PROPERTIES_FILE", "/etc/tzsp-monitor/suricata.properties")
LOG_DIR = os.getenv("SURICATA_LOG_DIR", "/var/log/suricata")
STATE_FILE = os.getenv("STATE_FILE", "/var/lib/disk-guard/state.json")
COMMAND_SOCKET = os.getenv("SURICATA_SOCKET",
                           "/var/lib/suricata-control/suricata-command.socket")

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "my-org")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")

KIB = 1024
MIB = 1024 * 1024
GIB = 1024 * 1024 * 1024

# The files Suricata holds open. Everything else in LOG_DIR that starts with one
# of these names is a rotation of it, and rotations are what may be deleted.
LIVE_LOGS = ("eve.json", "suricata.log")

STATE_NAMES = {0: "ok", 1: "tight", 2: "reclaiming", 3: "exhausted"}


def log(msg):
    sys.stdout.write(f"{datetime.now().strftime('%H:%M:%S')} {msg}\n")
    sys.stdout.flush()


def human(num):
    """Byte counts are the whole subject here, so they are never printed raw."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024 or unit == "TiB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024.0


# ---------------------------------------------------------------------------
# Property file
# ---------------------------------------------------------------------------
class Config:
    """`key = value` property file, same parser and same file as the responder.

    `#` only starts a comment at the start of a line: the shared mikrotik
    password lives in this file and passwords contain `#` often enough that
    stripping trailing comments would be a support call.
    """

    def __init__(self, path):
        self.path = path
        self.values = {}
        self.present = os.path.isfile(path)
        if not self.present:
            # -f, not -r: a missing bind-mount source makes Docker create a
            # *directory* here, and a directory is readable.
            log(f"no property file at {path}: using built-in defaults "
                f"(disk ceiling 90%, 30d InfluxDB retention)")
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
        """Sizes are written `512M` / `2G`, because a disk budget spelled out in
        bytes is a number nobody can check at a glance. Suffixes are binary
        (1G = 1024 MiB); a bare number is bytes."""
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
    """Every limit, resolved once, so the log line at startup is the whole policy."""

    def __init__(self, cfg):
        self.enabled = cfg.get_bool("disk_guard.enabled", True)
        self.interval = max(10, cfg.get_int("disk_guard.interval_seconds", 60))

        # The ceiling the operator asked for, and where a reclaim run stops.
        # The gap is hysteresis: reclaiming exactly to the ceiling would put the
        # next pass back over it and delete something every minute forever.
        self.max_percent = cfg.get_float("disk_guard.max_disk_percent", 90.0)
        self.target_percent = cfg.get_float("disk_guard.target_disk_percent",
                                            max(1.0, self.max_percent - 5.0))
        if self.target_percent >= self.max_percent:
            self.target_percent = max(1.0, self.max_percent - 5.0)
        # Where "TIGHT" starts on the dashboard: nothing is deleted yet, but the
        # headroom is worth looking at.
        self.warn_percent = cfg.get_float("disk_guard.warn_disk_percent",
                                          max(1.0, self.target_percent - 5.0))

        self.logs_max = cfg.get_bytes("disk_guard.logs_max_bytes", 2 * GIB)
        self.eve_max = cfg.get_bytes("disk_guard.eve_max_bytes", 512 * MIB)
        self.suricata_log_max = cfg.get_bytes("disk_guard.suricata_log_max_bytes",
                                              32 * MIB)
        # A rotation younger than this is never deleted by the *byte* budget, so
        # a burst cannot delete alerts the responder has not read yet. The disk
        # ceiling overrides it -- a full disk loses more than an alert.
        self.min_keep_seconds = cfg.get_int("disk_guard.min_keep_seconds", 300)
        # Kept for compatibility with the responder's old key, which is what
        # existing property files have.
        self.retain_days = cfg.get_int("disk_guard.eve_retain_days",
                                       cfg.get_int("eve.retain_days", 3))

        self.influx_enabled = cfg.get_bool("disk_guard.influx_enabled", True)
        self.influx_days = max(1, cfg.get_int("disk_guard.influx_retention_days", 30))
        self.influx_min_days = max(1, cfg.get_int(
            "disk_guard.influx_min_retention_days", 2))
        self.influx_shard_hours = max(1, cfg.get_int("disk_guard.influx_shard_hours", 24))
        # 0 = only the disk ceiling governs. Set it to give InfluxDB a hard slice
        # of the disk regardless of how much free space there happens to be.
        self.influx_max = cfg.get_bytes("disk_guard.influx_max_bytes", 0)
        self.shrink_percent = min(90, max(5, cfg.get_int(
            "disk_guard.influx_shrink_percent", 25)))
        # InfluxDB's own retention enforcement runs every 30 minutes by default,
        # so a cut is not even visible before then. Cutting again on the next
        # 60s pass would be cutting blind: 30 days becomes the floor inside ten
        # minutes, on one reading, for space that was already on its way back.
        self.shrink_cooldown = max(0, cfg.get_int(
            "disk_guard.influx_shrink_cooldown_seconds", 1800))
        if self.influx_min_days > self.influx_days:
            self.influx_min_days = self.influx_days

    def describe(self):
        return (f"ceiling={self.max_percent:.0f}% (reclaim to "
                f"{self.target_percent:.0f}%, warn at {self.warn_percent:.0f}%) "
                f"logs<={human(self.logs_max)} eve<={human(self.eve_max)} "
                f"retain={self.retain_days}d influx={self.influx_days}d"
                f"{'' if self.influx_enabled else ' (influx untouched)'}"
                f"{'' if not self.influx_max else ' <=' + human(self.influx_max)}")


# ---------------------------------------------------------------------------
# InfluxDB: line protocol out, bucket administration in
# ---------------------------------------------------------------------------
def esc_tag(value):
    return (str(value).replace("\\", "\\\\").replace(" ", "\\ ")
            .replace(",", "\\,").replace("=", "\\="))


def esc_str(value):
    flat = str(value).replace("\r", " ").replace("\n", " ")
    return '"' + flat.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Influx:
    """Stdlib-only InfluxDB v2 client: line-protocol writes, plus the two
    /api/v2 calls needed to read and set the bucket's retention."""

    def __init__(self, url, token, org, bucket):
        self.url = url.rstrip("/")
        self.token = token
        self.org = org
        self.bucket = bucket
        self.pending = []
        self._bucket_id = None

    # -- writes --------------------------------------------------------------
    def point(self, measurement, tags, fields, ts_ns=None):
        parts = [measurement] + [f"{esc_tag(k)}={esc_tag(v)}"
                                 for k, v in sorted(tags.items()) if v != ""]
        body = ",".join(parts) + " " + ",".join(
            f"{k}={v}" for k, v in fields.items())
        self.pending.append(f"{body} {ts_ns or time.time_ns()}")

    def flush(self):
        if not self.pending:
            return
        payload = "\n".join(self.pending).encode()
        self.pending = []
        url = (f"{self.url}/api/v2/write?org={urllib.parse.quote(self.org)}"
               f"&bucket={urllib.parse.quote(self.bucket)}&precision=ns")
        req = urllib.request.Request(url, data=payload, method="POST",
                                     headers={"Authorization": f"Token {self.token}",
                                              "Content-Type": "text/plain; charset=utf-8"})
        try:
            urllib.request.urlopen(req, timeout=10).read()
        except (urllib.error.URLError, OSError) as exc:
            # Losing a measurement is not worth stopping the guard for: the
            # deleting and the reporting are independent.
            log(f"influx write failed: {exc}")

    # -- administration ------------------------------------------------------
    def _api(self, path, method="GET", body=None):
        req = urllib.request.Request(
            f"{self.url}{path}", method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Token {self.token}",
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else {}

    def bucket_info(self):
        """The bucket row, or None if InfluxDB is not answering yet."""
        try:
            found = self._api("/api/v2/buckets?name="
                              + urllib.parse.quote(self.bucket)).get("buckets") or []
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log(f"could not read bucket {self.bucket}: {exc}")
            return None
        if not found:
            log(f"bucket {self.bucket} does not exist (yet?)")
            return None
        self._bucket_id = found[0].get("id")
        return found[0]

    def set_retention(self, bucket_id, seconds, shard_seconds):
        """PATCH retentionRules. The shard group duration is sent with it and
        retried without it: InfluxDB refuses a shard group longer than the
        retention it belongs to, and applying the retention matters more than
        the granularity it expires at."""
        rule = {"type": "expire", "everySeconds": int(seconds),
                "shardGroupDurationSeconds": int(shard_seconds)}
        try:
            self._api(f"/api/v2/buckets/{bucket_id}", "PATCH",
                      {"retentionRules": [rule]})
            return True
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log(f"retention PATCH with shard group {shard_seconds}s failed: {exc}")
        try:
            self._api(f"/api/v2/buckets/{bucket_id}", "PATCH",
                      {"retentionRules": [{"type": "expire",
                                           "everySeconds": int(seconds)}]})
            return True
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log(f"retention PATCH failed: {exc}")
            return False

    def shard_bytes(self):
        """(bytes for our bucket, bytes for the whole engine) from /metrics.

        `storage_shard_disk_size` is the only place InfluxDB reports what it is
        actually using on disk; the engine directory itself is inside the
        influxdb container, which this service deliberately cannot see.
        """
        try:
            req = urllib.request.Request(
                f"{self.url}/metrics",
                headers={"Authorization": f"Token {self.token}"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as exc:
            log(f"could not read influx /metrics: {exc}")
            return 0, 0
        ours = total = 0.0
        for line in body.splitlines():
            if not line.startswith("storage_shard_disk_size{"):
                continue
            labels, _, value = line.rpartition("}")
            try:
                size = float(value)
            except ValueError:
                continue
            total += size
            if self._bucket_id and f'bucket="{self._bucket_id}"' in labels:
                ours += size
        return int(ours), int(total)


# ---------------------------------------------------------------------------
# Suricata command socket
# ---------------------------------------------------------------------------
class SuricataControl:
    """Just enough of the unix-socket protocol to ask for `reopen-log-files`.

    Two framing rules, both learned the hard way (see rule-control):
    * the message must end with a newline -- Suricata checks the last byte of
      what it read and closes the connection if it is not `\n`, logging
      "incomplete client message" on its side while the client sees only a dead
      socket;
    * replies are read the other way round, by accumulating until the bytes
      parse as JSON, because the server does not frame them reliably.
    """

    def __init__(self, path, timeout=30):
        self.path = path
        self.timeout = timeout

    def available(self):
        return os.path.exists(self.path)

    def _send(self, command):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.path)
            sock.sendall(json.dumps({"version": "0.2"}).encode() + b"\n")
            sock.recv(4096)
            sock.sendall(json.dumps({"command": command}).encode() + b"\n")
            buf = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    raise OSError("socket closed before a complete reply")
                buf += chunk
                try:
                    return json.loads(buf)
                except ValueError:
                    continue
        finally:
            sock.close()

    def reopen(self):
        """True when Suricata has closed the renamed files and opened fresh ones.
        The new file appears on Suricata's next write, not here."""
        if not self.available():
            log(f"no command socket at {self.path}: cannot rotate")
            return False
        try:
            reply = self._send("reopen-log-files")
        except (OSError, ValueError) as exc:
            log(f"reopen-log-files failed: {exc}")
            return False
        if reply.get("return") != "OK":
            log(f"reopen-log-files refused: {reply}")
            return False
        return True


# ---------------------------------------------------------------------------
# The log directory
# ---------------------------------------------------------------------------
class LogWarden:
    """Owns everything in /var/log/suricata: rotation, ageing out, and the byte
    budget. Single owner on purpose -- the responder used to prune rotated
    copies as well, and two services deleting the same files is how a race
    turns into "the alert was there yesterday"."""

    def __init__(self, directory, control, settings, audit):
        self.dir = directory
        self.control = control
        self.cfg = settings
        self.audit = audit

    # -- inspection ----------------------------------------------------------
    def live(self):
        sizes = {}
        for name in LIVE_LOGS:
            try:
                sizes[name] = os.path.getsize(os.path.join(self.dir, name))
            except OSError:
                sizes[name] = 0  # rotated a moment ago and not yet recreated
        return sizes

    def rotations(self):
        """Rotated copies, oldest first -- which is also deletion order."""
        found = []
        try:
            names = os.listdir(self.dir)
        except OSError as exc:
            log(f"cannot read {self.dir}: {exc}")
            return found
        for name in names:
            if name in LIVE_LOGS or name.endswith(".tmp"):
                continue
            if not any(name.startswith(live + ".") for live in LIVE_LOGS):
                continue
            path = os.path.join(self.dir, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if os.path.isdir(path):
                continue
            found.append((st.st_mtime, st.st_size, path, name))
        found.sort()
        return found

    def total_bytes(self):
        return sum(self.live().values()) + sum(r[1] for r in self.rotations())

    # -- actions -------------------------------------------------------------
    def rotate(self, names):
        """Rename each live file, then one `reopen-log-files` for all of them.

        On failure every rename is undone: Suricata still holds the same inode,
        so renaming it back restores the file it is writing to without losing a
        line. Doing the renames first and signalling once is also what keeps the
        window in which eve.json does not exist down to a few milliseconds.
        """
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        renamed = []
        for name in names:
            src = os.path.join(self.dir, name)
            dest = f"{src}.{stamp}"
            suffix = 1
            while os.path.exists(dest):  # two rotations inside one second
                dest = f"{src}.{stamp}-{suffix}"
                suffix += 1
            try:
                os.rename(src, dest)
                renamed.append((src, dest))
            except OSError as exc:
                log(f"could not rotate {name}: {exc}")
        if not renamed:
            return []
        if not self.control.reopen():
            for src, dest in renamed:
                try:
                    os.rename(dest, src)
                except OSError as exc:
                    log(f"could not undo the rotation of {dest}: {exc}")
            log("rotation rolled back; Suricata keeps writing to the original "
                "files, so nothing was lost -- but the log is still growing")
            return []
        for src, dest in renamed:
            size = 0
            try:
                size = os.path.getsize(dest)
            except OSError:
                pass
            log(f"rotated {os.path.basename(src)} -> {os.path.basename(dest)} "
                f"({human(size)})")
            self.audit("rotate", os.path.basename(dest), size)
        return [dest for _, dest in renamed]

    def _delete(self, path, size, reason):
        try:
            os.remove(path)
        except OSError as exc:
            log(f"could not delete {path}: {exc}")
            return 0
        log(f"deleted {os.path.basename(path)} ({human(size)}): {reason}")
        self.audit("delete", os.path.basename(path), size)
        return size

    def prune_aged(self):
        """Rotations older than eve_retain_days. This is the ordinary, boring
        case: it runs when there is plenty of disk, so the byte budget below
        never has to."""
        if self.cfg.retain_days <= 0:
            return 0
        cutoff = time.time() - self.cfg.retain_days * 86400
        freed = 0
        for mtime, size, path, _name in self.rotations():
            if mtime < cutoff:
                freed += self._delete(path, size, f"older than {self.cfg.retain_days}d")
        return freed

    def prune_to_budget(self, budget, respect_min_keep=True):
        """Delete rotations, oldest first, until the directory fits `budget`.

        The live files are counted but never deleted, so a budget smaller than
        eve.json itself cannot be met here -- `rotate_oversize` is what bounds
        that, and the caller loops.
        """
        rotations = self.rotations()
        total = sum(self.live().values()) + sum(r[1] for r in rotations)
        if total <= budget:
            return 0
        now = time.time()
        freed = 0
        for mtime, size, path, _name in rotations:
            if total - freed <= budget:
                break
            if respect_min_keep and now - mtime < self.cfg.min_keep_seconds:
                # Young enough that the responder may still be reading it.
                continue
            freed += self._delete(path, size,
                                  f"log budget {human(budget)} exceeded")
        return freed

    def rotate_oversize(self):
        """Rotate whichever live file has outgrown its own cap. This frees
        nothing by itself -- it turns unbounded growth into a file the budget
        rules above are allowed to delete."""
        sizes = self.live()
        due = [name for name, size in sizes.items()
               if size > (self.cfg.eve_max if name == "eve.json"
                          else self.cfg.suricata_log_max)]
        if not due:
            return []
        for name in due:
            log(f"{name} is {human(sizes[name])}, over its cap; rotating")
        return self.rotate(due)


# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------
def disk(path):
    """(total, used, avail, used_percent) for the filesystem holding `path`.

    used_percent is computed the way `df` prints it -- used/(used+avail), which
    excludes the blocks reserved for root -- so that a number here matches what
    an operator sees on the host and the 90% means the same thing to both.
    """
    st = os.statvfs(path)
    total = st.f_blocks * st.f_frsize
    avail = st.f_bavail * st.f_frsize
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    denominator = used + avail
    percent = (used / denominator * 100.0) if denominator else 0.0
    return total, used, avail, percent


def bytes_over(path, percent):
    """How many bytes have to go for `path`'s filesystem to sit at `percent`."""
    total, used, avail, _ = disk(path)
    denominator = used + avail
    return max(0, int(used - denominator * percent / 100.0))


def bytes_free_to(path, percent):
    """How many bytes may still be written before `path` reaches `percent`."""
    total, used, avail, _ = disk(path)
    denominator = used + avail
    return max(0, int(denominator * percent / 100.0 - used))


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------
def shrink_days(current, floor, percent):
    """The next, smaller retention. Steps down by a percentage rather than to a
    computed "right" value: how many bytes a day of history costs is only known
    after it has been deleted, and stepping means the guard converges instead of
    over-deleting on one bad reading."""
    step = max(1, int(round(current * percent / 100.0)))
    return max(floor, current - step)


def cut_decision(over, too_big, bucket_bytes, need, since_cut, cooldown):
    """Whether to cut the bucket's retention, and if not, what to say instead.

    Pure, and separate from the pass, because this is the one decision here that
    destroys something a rebuild cannot bring back. Two ways to answer no, and
    both are about not deleting history that was never the problem:

    * **the bucket is a rounding error next to what has to go.** Expiring all of
      it would not clear the ceiling either, so something outside this stack
      filled the disk -- pruning weeks of alert history would cost real evidence
      and fix nothing. The tile reads NO SPACE LEFT instead, which is the truth.
    * **the last cut is too recent to have been measured.** InfluxDB's retention
      enforcement runs every 30 minutes by default, so the space from the
      previous cut may still be on its way back; cutting again on the next 60s
      pass would take 30 days to the floor inside ten minutes on one reading.

    `too_big` (disk_guard.influx_max_bytes) is a deliberate hard slice of the
    disk rather than a symptom, so it skips the first test -- but not the second.
    """
    if not (over or too_big):
        return False, ""
    if over and not too_big and bucket_bytes * 10 < need:
        return False, (f"the bucket is {human(bucket_bytes)} and {human(need)} "
                       f"has to go, so InfluxDB is not what filled this disk")
    if since_cut < cooldown:
        return False, (f"the last cut was {since_cut / 60:.0f} min ago; waiting "
                       f"for InfluxDB to expire those shards before cutting again")
    return True, ""


class State:
    """The effective retention, persisted.

    It has to survive a restart: a guard that forgot it had cut retention to 6
    days would put 30 back on the next start, refill the disk and cut it again.
    The configured value is stored alongside it, so editing the property file is
    what re-expands it -- an operator changing the number is a decision, this
    service raising it again on its own is a loop.
    """

    def __init__(self, path):
        self.path = path
        self.data = {}
        try:
            with open(path) as fh:
                self.data = json.load(fh)
        except (OSError, ValueError):
            pass

    def retention_days(self, configured):
        if self.data.get("configured_days") != configured:
            self.data["configured_days"] = configured
            self.data["retention_days"] = configured
            self.save()
        return int(self.data.get("retention_days", configured))

    def set_retention_days(self, days):
        self.data["retention_days"] = int(days)
        self.data["last_cut"] = time.time()
        self.save()

    def seconds_since_cut(self):
        last = self.data.get("last_cut")
        # No cut on record: treat it as long ago, so the first one is free.
        return 1e9 if not last else max(0.0, time.time() - last)

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(self.data, fh)
            os.replace(tmp, self.path)
        except OSError as exc:
            log(f"could not save state: {exc}")


# ---------------------------------------------------------------------------
def main():
    cfg = Config(PROPERTIES_FILE)
    settings = Settings(cfg)
    influx = Influx(INFLUX_URL, INFLUX_TOKEN, INFLUX_ORG, INFLUX_BUCKET)
    state = State(STATE_FILE)

    audited = []

    def audit(action, detail, size):
        # Written only when something is actually deleted, rotated or shrunk:
        # "when did this stack start throwing data away, and what" is an audit
        # question, and the container log rotates away.
        audited.append((action, detail, size))

    warden = LogWarden(LOG_DIR, SuricataControl(COMMAND_SOCKET), settings, audit)

    if not settings.enabled:
        log("disk_guard.enabled = false: nothing is pruned and no retention is "
            "applied. The disk is unbounded again -- this is only sensible if "
            "something outside this stack keeps it in check.")
        return

    log(f"policy: {settings.describe()}")
    log(f"logs {LOG_DIR}, influx {INFLUX_URL} bucket {INFLUX_BUCKET}")

    while True:
        started = time.monotonic()
        try:
            run_pass(settings, warden, influx, state, audited, audit)
        except Exception as exc:  # a guard that dies is worse than a noisy one
            log(f"pass failed: {exc!r}")
        time.sleep(max(1.0, settings.interval - (time.monotonic() - started)))


def run_pass(settings, warden, influx, state, audited, audit):
    del audited[:]
    freed = 0

    # --- 1. the ordinary housekeeping ---------------------------------------
    # The budget is the configured one *or* whatever still fits under the
    # target, whichever is smaller. That is what makes this proactive rather
    # than a reaction: as the disk fills -- for any reason, including something
    # else entirely -- the logs' allowance shrinks with it and they are pruned
    # before they are what pushes it over the ceiling. Young rotations are still
    # spared here; only the ceiling branch below overrides that.
    headroom = min(bytes_free_to(LOG_DIR, settings.target_percent),
                   bytes_free_to("/", settings.target_percent))
    freed += warden.prune_aged()
    warden.rotate_oversize()
    budget = min(settings.logs_max, warden.total_bytes() + headroom)
    freed += warden.prune_to_budget(budget)

    # --- 2. where the filesystems stand ------------------------------------
    # Two of them, in the general case: the log volume, and the container's own
    # root -- which is the overlay on Docker's data-root, i.e. the filesystem
    # holding InfluxDB's engine, since that data lives in influxdb's writable
    # layer rather than in a volume. On a default install they are the same
    # device and these two readings are identical.
    log_total, _, log_avail, log_percent = disk(LOG_DIR)
    root_total, _, root_avail, root_percent = disk("/")
    percent = max(log_percent, root_percent)

    # --- 3. reclaim, if we are over the ceiling ----------------------------
    over = percent >= settings.max_percent
    need = max(bytes_over(LOG_DIR, settings.target_percent),
               bytes_over("/", settings.target_percent)) if over else 0
    if over:
        log(f"disk at {percent:.1f}% (ceiling {settings.max_percent:.0f}%): "
            f"reclaiming {human(need)}")
        # Ignore min_keep_seconds now: a full disk costs more than the tail of
        # one rotation the responder had not finished reading.
        freed += warden.prune_to_budget(max(0, warden.total_bytes() - need),
                                        respect_min_keep=False)
        # Still over, and the only thing left is the file Suricata has open.
        # Rotating it makes the *next* pass able to delete it.
        if bytes_over(LOG_DIR, settings.target_percent) > 0:
            sizes = warden.live()
            if sizes.get("eve.json", 0) > 16 * MIB:
                log("still over the ceiling with no rotations left to delete; "
                    "rotating eve.json so the next pass can drop it")
                warden.rotate(["eve.json"])

    # --- 4. InfluxDB retention ---------------------------------------------
    bucket_bytes = engine_bytes = 0
    cut = False
    retention = state.retention_days(settings.influx_days)
    if settings.influx_enabled:
        info = influx.bucket_info()
        if info:
            bucket_bytes, engine_bytes = influx.shard_bytes()
            too_big = 0 < settings.influx_max < bucket_bytes
            do_cut, why_not = cut_decision(over, too_big, bucket_bytes, need,
                                           state.seconds_since_cut(),
                                           settings.shrink_cooldown)
            if why_not:
                log(f"not cutting retention: {why_not}")
            elif do_cut:
                nxt = shrink_days(retention, settings.influx_min_days,
                                  settings.shrink_percent)
                if nxt < retention:
                    why = (f"bucket is {human(bucket_bytes)}, over "
                           f"{human(settings.influx_max)}" if too_big
                           else f"disk at {percent:.1f}%")
                    log(f"cutting InfluxDB retention {retention}d -> {nxt}d: {why}")
                    audit("retention", f"{retention}d -> {nxt}d", 0)
                    state.set_retention_days(nxt)
                    retention = nxt
                    cut = True
                elif retention <= settings.influx_min_days:
                    log(f"InfluxDB retention is already at the "
                        f"{settings.influx_min_days}d floor; not cutting further")
            rules = (info.get("retentionRules") or [{}])[0]
            want = retention * 86400
            # InfluxDB rejects a shard group longer than the retention it sits
            # in, and a shard group is the unit that actually frees disk when it
            # expires -- so it is clamped rather than trusted.
            shard = min(settings.influx_shard_hours * 3600, max(3600, want // 2))
            if (rules.get("everySeconds") != want
                    or rules.get("shardGroupDurationSeconds") != shard):
                had = rules.get("everySeconds", 0)
                if influx.set_retention(info["id"], want, shard):
                    log(f"bucket {INFLUX_BUCKET} retention "
                        f"{'infinite' if not had else str(had // 86400) + 'd'}"
                        f" -> {retention}d, shard group {shard // 3600}h")

    # --- 5. say so ---------------------------------------------------------
    logs_bytes = warden.total_bytes()
    live = warden.live()
    rotations = warden.rotations()
    still_over = max(bytes_over(LOG_DIR, settings.max_percent),
                     bytes_over("/", settings.max_percent))
    if over and still_over > 0:
        code = 3   # everything above has run and the disk is still over
    elif over:
        code = 2
    elif percent >= settings.warn_percent:
        code = 1
    else:
        code = 0
    if cut and code < 2:
        # disk_guard.influx_max_bytes can cut retention with the disk at 40%.
        # "RECLAIMING" has to mean "this stack is throwing data away right now",
        # whichever limit asked for it, or the tile is worse than no tile.
        code = 2

    for action, detail, size in audited:
        influx.point("disk_guard_action", {"action": action},
                     {"count": "1i", "bytes": f"{int(size)}i",
                      "detail": esc_str(detail)})
    influx.point("disk_guard", {"fs": LOG_DIR}, {
        "used_percent": f"{percent:.2f}",
        "logs_fs_percent": f"{log_percent:.2f}",
        "root_fs_percent": f"{root_percent:.2f}",
        "free_bytes": f"{min(log_avail, root_avail)}i",
        "total_bytes": f"{min(log_total, root_total)}i",
        "logs_bytes": f"{logs_bytes}i",
        "eve_bytes": f"{live.get('eve.json', 0)}i",
        "rotations": f"{len(rotations)}i",
        "influx_bytes": f"{engine_bytes}i",
        "bucket_bytes": f"{bucket_bytes}i",
        "retention_days": f"{retention}i",
        "retention_configured": f"{settings.influx_days}i",
        "freed_bytes": f"{int(freed)}i",
        "state_code": f"{code}i",
        "state": esc_str(STATE_NAMES[code]),
    })
    influx.flush()

    if code == 3:
        log(f"DISK STILL AT {percent:.1f}% after reclaiming {human(freed)}. "
            f"Logs are down to {human(logs_bytes)} and InfluxDB retention to "
            f"{retention}d, so what is filling this filesystem is outside this "
            f"stack -- look at docker container logs and images.")
    elif freed:
        log(f"reclaimed {human(freed)}; logs {human(logs_bytes)}, "
            f"disk {percent:.1f}%")


if __name__ == "__main__":
    main()
