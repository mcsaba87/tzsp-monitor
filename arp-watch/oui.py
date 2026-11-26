# --- BEGIN shared OUI reader: identical copies in dns-resolver/oui.py and
# --- arp-watch/oui.py (each is its own build context). Change one, change
# --- both; `diff dns-resolver/oui.py arp-watch/oui.py` prints nothing.
"""MAC address -> vendor, from a local copy of the IEEE registry. Stdlib only.

Reads Wireshark's `manuf` file (the IEEE MA-L, MA-M and MA-S registries merged
into one tab-separated list, regenerated weekly) and answers one question: who
was this address block assigned to. No network calls, ever: the file is read
into memory once and re-read when it changes on disk.

    db = OUI("/oui/manuf")
    db.vendor("48:a9:8a:12:34:56")   -> "Routerboard.com"
    db.vendor("70:b3:d5:00:00:01")   -> the MA-S (/36) holder, not the MA-L one
    db.vendor("02:42:ac:11:00:02")   -> "(randomized)"   locally administered
    db.vendor("01:00:5e:00:00:fb")   -> "(multicast)"
    db.vendor("<unassigned block>")  -> "(unknown)"
    no database loaded               -> None

The parenthesised answers are not vendors, and are written that way on purpose
so that a dashboard can tell them from a company name at a glance -- and so
that `/^\\(/` selects them and nothing else.

A locally administered address (bit 1 of the first octet) is checked against
the registry first and only then called randomized: the IEEE assigns no such
blocks, so a hit there is a CID or a vendor's private convention worth showing,
and everything else is a phone, laptop or VM that made its address up -- which
is the common case on Wi-Fi today, not an anomaly.
"""
import os
import threading
import time

RANDOMIZED = "(randomized)"
MULTICAST = "(multicast)"
BROADCAST = "(broadcast)"
UNKNOWN = "(unknown)"


def normalize(mac):
    """Any common spelling -> 'aa:bb:cc:dd:ee:ff', or None if it is not a MAC.

    Accepts colons, dashes, Cisco dots and bare hex, in either case."""
    if not isinstance(mac, str):
        return None
    digits = "".join(c for c in mac if c not in ":-. ").lower()
    if len(digits) != 12:
        return None
    try:
        int(digits, 16)
    except ValueError:
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _parse(path):
    """`manuf` -> {bits: {prefix_int: name}}. Also reads the IEEE CSV exports.

    `manuf` lines are `00:00:0C<TAB>Cisco<TAB>Cisco Systems, Inc`, padded with
    spaces, with `/28` or `/36` after the address for MA-M and MA-S blocks. The
    third column (the registry's full name) is preferred over Wireshark's
    12-character abbreviation, which is unreadable on a dashboard. The IEEE's
    own oui.csv / mam.csv / oui36.csv (`Registry,Assignment,Organization Name,
    ...`) are accepted too, so a hand-placed IEEE file works without conversion.
    """
    table = {24: {}, 28: {}, 36: {}}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "\t" in line:
                cols = [c.strip() for c in line.split("\t")]
                addr, name = cols[0], (cols[2] if len(cols) > 2 and cols[2] else cols[1])
                bits = 24
                if "/" in addr:
                    addr, _, b = addr.partition("/")
                    try:
                        bits = int(b)
                    except ValueError:
                        continue
                digits = addr.replace(":", "").replace("-", "").replace(".", "")
            elif line.startswith(("MA-L,", "MA-M,", "MA-S,")):
                # Organization names are quoted when they contain a comma.
                reg, _, rest = line.partition(",")
                digits, _, rest = rest.partition(",")
                if rest.startswith('"'):
                    name = rest[1:].partition('"')[0]
                else:
                    name = rest.partition(",")[0]
                bits = {"MA-L": 24, "MA-M": 28, "MA-S": 36}[reg]
            else:
                continue
            if bits not in table or not name:
                continue
            nibbles = bits // 4
            if len(digits) < nibbles:
                continue
            try:
                prefix = int(digits[:nibbles], 16)
            except ValueError:
                continue
            table[bits][prefix] = " ".join(name.split())
    return table


class OUI:
    """Thread-safe, reloads itself when the file on disk changes."""

    def __init__(self, path, check_seconds=60):
        self.path = path
        self.check_seconds = check_seconds
        self.lock = threading.Lock()
        self.table = None
        self.entries = 0
        self.error = "not loaded yet"
        self.mtime = None
        self.next_check = 0.0
        self.maybe_reload(force=True)

    def maybe_reload(self, force=False):
        now = time.monotonic()
        if not force and now < self.next_check:
            return False
        self.next_check = now + self.check_seconds
        try:
            st = os.stat(self.path)
        except OSError as exc:
            if self.table is None:
                self.error = f"{self.path}: {exc.strerror}"
            return False
        if not force and self.mtime == st.st_mtime_ns:
            return False
        try:
            table = _parse(self.path)
        except OSError as exc:
            self.error = f"{self.path}: {exc}"
            return False
        entries = sum(len(t) for t in table.values())
        if entries == 0:
            # Keep a working table rather than swap in an empty one: an HTML
            # error page written over the file must not erase every vendor.
            self.error = f"{self.path}: no OUI entries in it"
            self.mtime = st.st_mtime_ns
            return False
        with self.lock:
            self.table, self.entries = table, entries
            self.mtime, self.error = st.st_mtime_ns, None
        return True

    @property
    def loaded(self):
        return self.table is not None

    def vendor(self, mac):
        """Vendor name, one of the parenthesised classes, or None (no database).

        Multicast and broadcast are answered without the database: they are a
        property of the address, not of an assignment."""
        norm = normalize(mac)
        if norm is None:
            return None
        value = int(norm.replace(":", ""), 16)
        if value == 0xFFFFFFFFFFFF:
            return BROADCAST
        first = value >> 40
        if first & 0x01:
            return MULTICAST
        with self.lock:
            table = self.table
        if table is None:
            return None
        for bits in (36, 28, 24):
            name = table[bits].get(value >> (48 - bits))
            if name:
                return name
        return RANDOMIZED if first & 0x02 else UNKNOWN
# --- END shared OUI reader
