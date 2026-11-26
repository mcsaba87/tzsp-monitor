# --- BEGIN shared geoip reader: identical copies in dns-resolver/geoip.py and
# --- collector/geoip.py (each is its own build context). Change one, change
# --- both; `diff dns-resolver/geoip.py collector/geoip.py` prints nothing.
"""Country lookup from a local MaxMind-format (.mmdb) database, stdlib only.

Reads any GeoIP2/GeoLite2-compatible country database -- the shipped default is
DB-IP's free "IP to Country Lite" (CC BY 4.0), which uses the same layout -- and
answers one question: which country is this address in. No network calls, ever:
the file is read into memory once and re-read when it changes on disk.

    db = GeoIP("/geoip/country.mmdb")
    db.country("8.8.8.8")    -> ("US", "United States")
    db.country("10.0.0.1")   -> ("local", "private network")
    db.country("192.0.2.1")  -> ("local", ...)   (non-global: TEST-NET, etc.)
    db.country("<unlisted>") -> ("unknown", "unknown")
    no database loaded       -> (None, None)

The codes are ISO 3166-1 alpha-2 in upper case; "local" and "unknown" are lower
case on purpose, so /^[A-Z]{2}$/ selects real countries and nothing else.
"""
import ipaddress
import os
import struct
import threading
import time

METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"
LOCAL = ("local", "private network")
UNKNOWN = ("unknown", "unknown")


class MMDBError(ValueError):
    pass


class _Reader:
    """The parts of the MaxMind DB format a country lookup needs."""

    def __init__(self, buf):
        self.buf = buf
        idx = buf.rfind(METADATA_MARKER, max(0, len(buf) - 128 * 1024))
        if idx < 0:
            raise MMDBError("not a MaxMind DB file (no metadata marker)")
        self.meta, _ = self._decode(idx + len(METADATA_MARKER), base=0)
        try:
            self.node_count = self.meta["node_count"]
            self.record_size = self.meta["record_size"]
            self.ip_version = self.meta["ip_version"]
        except (KeyError, TypeError):
            raise MMDBError("metadata is missing node_count/record_size")
        if self.record_size not in (24, 28, 32):
            raise MMDBError(f"unsupported record size {self.record_size}")
        self.node_bytes = self.record_size // 4
        self.tree_size = self.node_bytes * self.node_count
        self.data_start = self.tree_size + 16
        self.data_end = idx
        # IPv4 addresses live under ::/96 of an IPv6 tree; find that node once.
        self.ipv4_start = 0
        if self.ip_version == 6:
            node = 0
            for _ in range(96):
                if node >= self.node_count:
                    break
                node = self._record(node, 0)
            self.ipv4_start = node
        self._cache = {}

    # -- search tree -------------------------------------------------------
    def _record(self, node, bit):
        b, off = self.buf, node * self.node_bytes
        if self.record_size == 24:
            o = off + 3 * bit
            return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]
        if self.record_size == 28:
            if bit == 0:
                return ((b[off + 3] & 0xF0) << 20) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]
            return ((b[off + 3] & 0x0F) << 24) | (b[off + 4] << 16) | (b[off + 5] << 8) | b[off + 6]
        return struct.unpack_from(">I", b, off + 4 * bit)[0]

    def lookup(self, packed):
        """The decoded record for a packed address, or None if unlisted."""
        bits = len(packed) * 8
        if bits == 32 and self.ip_version == 6:
            node = self.ipv4_start
        elif bits == 128 and self.ip_version == 4:
            return None
        else:
            node = 0
        value = int.from_bytes(packed, "big")
        n = self.node_count
        for i in range(bits - 1, -1, -1):
            if node >= n:
                break
            node = self._record(node, (value >> i) & 1)
        if node <= n:  # == n: no data; < n: ran out of bits mid-tree
            return None
        offset = node - n - 16
        hit = self._cache.get(offset)
        if hit is None:
            hit, _ = self._decode(self.data_start + offset, base=self.data_start)
            self._cache[offset] = hit
        return hit

    # -- data section ------------------------------------------------------
    def _decode(self, off, base):
        b = self.buf
        ctrl = b[off]
        off += 1
        typ = ctrl >> 5
        if typ == 1:  # pointer
            ss, vvv = (ctrl >> 3) & 3, ctrl & 7
            if ss == 0:
                p = (vvv << 8) | b[off]
            elif ss == 1:
                p = ((vvv << 16) | (b[off] << 8) | b[off + 1]) + 2048
            elif ss == 2:
                p = ((vvv << 24) | int.from_bytes(b[off:off + 3], "big")) + 526336
            else:
                p = int.from_bytes(b[off:off + 4], "big")
            value, _ = self._decode(base + p, base)
            return value, off + ss + 1
        if typ == 0:  # extended type
            typ = 7 + b[off]
            off += 1
        size = ctrl & 0x1F
        if size >= 29:
            if size == 29:
                size = 29 + b[off]
                off += 1
            elif size == 30:
                size = 285 + int.from_bytes(b[off:off + 2], "big")
                off += 2
            else:
                size = 65821 + int.from_bytes(b[off:off + 3], "big")
                off += 3
        if typ == 2:  # utf-8 string
            return bytes(b[off:off + size]).decode("utf-8", "replace"), off + size
        if typ == 7:  # map
            out = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                v, off = self._decode(off, base)
                out[k] = v
            return out, off
        if typ == 11:  # array
            out = []
            for _ in range(size):
                v, off = self._decode(off, base)
                out.append(v)
            return out, off
        if typ in (5, 6, 9, 10):  # unsigned ints
            return int.from_bytes(b[off:off + size], "big"), off + size
        if typ == 8:  # int32
            return int.from_bytes(b[off:off + size], "big", signed=True), off + size
        if typ == 3:  # double
            return struct.unpack_from(">d", b, off)[0], off + 8
        if typ == 15:  # float
            return struct.unpack_from(">f", b, off)[0], off + 4
        if typ == 14:  # boolean: the value is the size
            return bool(size), off
        if typ == 4:  # bytes
            return bytes(b[off:off + size]), off + size
        raise MMDBError(f"unsupported data type {typ} at {off - 1}")

    def countries(self):
        """{code: name} for every country the data section holds.

        The data section is a run of encoded values with no gaps, so decoding
        it front to back sees every record without walking 1M+ tree nodes.
        """
        if getattr(self, "_countries", None) is not None:
            return self._countries
        out, off = {}, self.data_start
        while off < self.data_end - 16:
            try:
                value, off = self._decode(off, base=self.data_start)
            except (IndexError, MMDBError):
                break
            code, name = _country_of(value)
            if code:
                out[code] = name
        self._countries = out
        return out


def _country_of(record):
    if not isinstance(record, dict):
        return None, None
    c = record.get("country") or record.get("registered_country") or {}
    if not isinstance(c, dict):
        return None, None
    code = c.get("iso_code")
    if not isinstance(code, str) or not code:
        return None, None
    names = c.get("names") or {}
    name = names.get("en") if isinstance(names, dict) else None
    return code.upper(), name or code.upper()


def is_local(ip):
    """True for anything that is not a routable public address."""
    return not ip.is_global or ip.is_multicast


class GeoIP:
    """Thread-safe country lookups that follow the file on disk.

    The file is stat()ed at most every `check_seconds`; a new mtime/size/inode
    swaps in a fresh reader, so an updated database is picked up without a
    restart. A broken new file keeps the old one in use.
    """

    def __init__(self, path, check_seconds=60):
        self.path = path
        self.check_seconds = check_seconds
        self._lock = threading.Lock()
        self._reader = None
        self._sig = None
        self._checked = 0.0
        self.error = None
        self.meta = {}
        self.maybe_reload(force=True)

    def maybe_reload(self, force=False):
        now = time.monotonic()
        if not force and now - self._checked < self.check_seconds:
            return False
        self._checked = now
        try:
            st = os.stat(self.path)
        except OSError:
            if self._reader is None:
                self.error = f"{self.path} does not exist"
            return False
        sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        if sig == self._sig:
            return False
        try:
            with open(self.path, "rb") as f:
                reader = _Reader(f.read())
        except (OSError, MMDBError, IndexError, struct.error) as e:
            self.error = f"cannot read {self.path}: {e}"
            self._sig = sig  # do not retry a broken file every minute
            return False
        with self._lock:
            self._reader, self._sig, self.error = reader, sig, None
            self.meta = {
                "database_type": reader.meta.get("database_type"),
                "build_epoch": reader.meta.get("build_epoch"),
                "node_count": reader.node_count,
            }
        return True

    @property
    def loaded(self):
        return self._reader is not None

    def country(self, ip):
        """(code, name) -- see the module docstring for the special values."""
        try:
            addr = ipaddress.ip_address(ip.strip() if isinstance(ip, str) else ip)
        except ValueError:
            return None, None
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if is_local(addr):
            return LOCAL
        reader = self._reader
        if reader is None:
            return None, None
        try:
            code, name = _country_of(reader.lookup(addr.packed))
        except (IndexError, MMDBError, struct.error):
            return UNKNOWN
        return (code, name) if code else UNKNOWN

    def countries(self):
        reader = self._reader
        return reader.countries() if reader else {}
# --- END shared geoip reader
