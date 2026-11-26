"""Prove the DNS-filter path without waiting for a router, or for a real query.

    docker compose exec dns-filter python selftest.py

What it exercises, in order: the UT1 catalogue parse, the size and alias guards,
a real download of the smallest category UT1 publishes, the hosts-file render
(including the `www.` expansion rule), and the file listener the router fetches
from -- conditional requests included, because a 304 here is what makes the
router's reload of an unchanged list free -- and the whitelist and blacklist:
a whitelisted domain disappears from the category that listed it, a
blacklisted one is served in `_blacklist.txt`, and the guards refuse a
wildcard block and the same domain on both lists. /which, the lookup the
alerting service uses to say which list refused a name, is checked offline
against synthetic list files first (so it runs even when the control API is
read-only), and then against the real lists.

It does not touch the router, and it does not need one. The category and the
list entries it adds are removed again at the end, so a run leaves the service
exactly as it found it.
`ai` is used because it is the smallest archive UT1 ships (694 bytes), so a run
costs one negligible download.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

CONTROL = os.getenv("CONTROL_URL", "http://127.0.0.1:8040")
LISTS = os.getenv("LIST_URL", "http://127.0.0.1:8041")
PROBE = os.getenv("PROBE_CATEGORY", "ai")

failures = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  -- {detail}" if detail else ""))
    if not ok:
        failures.append(label)
    return ok


def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def get_json(url):
    status, _, body = get(url)
    return status, json.loads(body or b"null")


def offline_which():
    """/which's lookup against synthetic list files in a temporary directory:
    no service, no router, no state file. Imports filter.py for the functions
    themselves, so this tests the code the endpoint runs, not a copy."""
    import tempfile
    import filter as dnsfilter

    print("0. which list refused a name (offline)")
    with tempfile.TemporaryDirectory() as tmp:
        def write(name, names):
            with open(os.path.join(tmp, f"{name}.txt"), "w") as fh:
                fh.write(f"# {name} selftest\n")
                fh.writelines(f"0.0.0.0 {n}\n" for n in names)

        write("malware", ["evil.example", "www.evil.example"])
        write("ads", ["tracker.example.net"])
        write("_blacklist", ["c2.example.org", "www.c2.example.org",
                             "hand.example.com"])
        block = {"c2.example.org": {"until": int(time.time()) + 3600,
                                    "note": "sid 2027757"},
                 "hand.example.com": {"note": "ticket 42"}}
        lookup = dnsfilter.ListLookup(tmp)
        names = dnsfilter.which_names({"names": [
            " WWW.Evil.Example. ,tracker.example.net", "www.c2.example.org",
            "hand.example.com,,nothing.example"]})
        check("names are normalised, split and kept in order",
              names == ["www.evil.example", "tracker.example.net",
                        "www.c2.example.org", "hand.example.com",
                        "nothing.example"], str(names))
        got = {r["name"]: r for r in lookup.which(names, block)}
        check("a category hit names the category",
              got["tracker.example.net"]["list"] == "ads"
              and got["tracker.example.net"]["source"] == "category")
        check("a www. form is found in its list",
              got["www.evil.example"]["list"] == "malware")
        c2 = got["www.c2.example.org"]
        check("a www. form of an automatic blacklist entry maps to its domain",
              c2["list"] == "_blacklist" and c2["source"] == "automatic"
              and c2["note"] == "sid 2027757", str(c2))
        hand = got["hand.example.com"]
        check("a hand-made blacklist entry is 'dashboard'",
              hand["source"] == "dashboard" and hand["note"] == "ticket 42",
              str(hand))
        check("a miss answers an empty list",
              got["nothing.example"] == {"name": "nothing.example", "list": "",
                                         "source": "", "note": ""})
        scans = lookup.scans
        lookup.which(names, block)
        check("a repeat (misses included) is answered from the cache",
              lookup.scans == scans, f"{lookup.scans - scans} extra scan(s)")
        # A re-render moves a name to another list: the cache must notice.
        # The mtime is pushed forward by hand so a coarse-timestamp filesystem
        # cannot hide the change.
        write("ads", ["tracker.example.net", "nothing.example"])
        later = os.path.getmtime(os.path.join(tmp, "ads.txt")) + 5
        os.utime(os.path.join(tmp, "ads.txt"), (later, later))
        row = lookup.which(["nothing.example"], block)[0]
        check("a changed list file drops the cache",
              row["list"] == "ads" and lookup.scans == scans + 1, str(row))
        check("a request is capped at 200 names",
              len(dnsfilter.which_names(
                  {"names": [",".join(f"n{i}.example" for i in range(300))]}))
              == dnsfilter.WHICH_MAX_NAMES)


def main():
    # Check if a recent control API is available; if not, skip control tests.
    # Some tests rely on a running service at CONTROL_URL.
    try:
        import urllib.request, urllib.error
        req = urllib.request.Request(f"{CONTROL}/status")
        with urllib.request.urlopen(req, timeout=5) as resp:
            _ = resp.read()  # just attempt to connect
        control_available = True
    except Exception:
        control_available = False
    offline_which()

    print("1. control API")
    status, rows = get_json(f"{CONTROL}/status")
    check("/status answers", status == 200 and isinstance(rows, list) and rows)
    state = rows[0] if rows else {}
    check("catalogue is loaded", state.get("catalog_size", 0) > 50,
          f"{state.get('catalog_size')} UT1 categories")
    if not state.get("control_enabled"):
        print("dns_filter.control_enabled = false: the write half cannot be "
              "tested, stopping here.")
        return 0
    if not state.get("base_url_set"):
        print("  note: dns_filter.base_url is unset, so nothing would reach a "
              "router. Everything below still applies.")

    print("2. guards")
    _, msgs = get_json(f"{CONTROL}/messages?enable=no-such-category")
    check("an unknown category is refused",
          any("unknown" in m["message"] for m in msgs), str(msgs))
    # Which category trips the size guard depends on dns_filter.max_archive_bytes,
    # so it is read out of the catalogue rather than hardcoded: an install that
    # has deliberately raised the guard to take `adult`/`porn` would otherwise
    # fail a check on a guard that is doing exactly what it was told.
    _, catalog = get_json(f"{CONTROL}/catalog")
    enabled = {row["category"] for row in catalog if row["enabled"]}
    oversized = next((row["category"] for row in sorted(
        catalog, key=lambda r: -r["archive_bytes"])
        if not row["fits"] and not row["enabled"]
        and not (set(filter(None, row["aliases"].split(", "))) & enabled)), None)
    if oversized:
        _, msgs = get_json(f"{CONTROL}/messages?enable={oversized}")
        check(f"the oversized '{oversized}' is refused before it is downloaded",
              any("max_archive_bytes" in m["message"] for m in msgs), str(msgs))
    else:
        print("  note: no category is over dns_filter.max_archive_bytes, so the "
              "size guard has nothing to refuse here.")

    # The alias guard, which is the one that stops the same list being paid for
    # twice in the router's DNS cache. Needs a category that is enabled and has
    # an alias -- true of the seed set (ads==publicite, malware==phishing).
    twin = next(((row["category"], alias) for row in catalog if row["enabled"]
                 for alias in filter(None, row["aliases"].split(", "))
                 if alias not in enabled), None)
    if twin:
        _, msgs = get_json(f"{CONTROL}/messages?enable={twin[1]}")
        check(f"'{twin[1]}' is refused as a duplicate of the enabled '{twin[0]}'",
              any("identical list" in m["message"] for m in msgs), str(msgs))
    else:
        print("  note: no enabled category has an alias, so the duplicate guard "
              "has nothing to refuse here.")

    print(f"3. enable '{PROBE}' and wait for the mirror")
    get_json(f"{CONTROL}/messages?enable={PROBE}&note=selftest")
    row, waited = None, 0
    while waited < 120:
        _, rows = get_json(f"{CONTROL}/categories")
        row = next((r for r in rows if r["category"] == PROBE), None)
        if row and row["state"] in ("ok", "error"):
            break
        time.sleep(2)
        waited += 2
    check("the category was mirrored", bool(row) and row["state"] == "ok",
          (row or {}).get("detail", "no row"))
    check("it has domains and rendered names",
          bool(row) and row["domains"] > 0 and row["names"] >= row["domains"],
          f"{(row or {}).get('domains')} domains -> {(row or {}).get('names')} names")

    print("4. the file the router downloads")
    status, headers, body = get(f"{LISTS}/lists/{PROBE}.txt")
    text = body.decode("utf-8", "replace")
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    check("the list is served", status == 200, f"HTTP {status}, {len(lines)} lines")
    check("every line is hosts format",
          bool(lines) and all(line.startswith("0.0.0.0 ") for line in lines))
    check("a registrable domain got its www. form",
          any(line.startswith("0.0.0.0 www.") for line in lines))
    check("Last-Modified and ETag are set",
          "Last-Modified" in headers and "ETag" in headers)
    status, _, _ = get(f"{LISTS}/lists/{PROBE}.txt",
                       {"If-None-Match": headers.get("ETag", "")})
    check("a conditional request answers 304", status == 304, f"HTTP {status}")
    status, _, _ = get(f"{LISTS}/apply?filter=off")
    check("the published listener has no control API", status == 404,
          f"HTTP {status} -- anything but 404 means the filter can be switched "
          f"off by anyone who can reach this port")

    print("5. whitelist and blacklist")
    victim = next((line.split()[1] for line in lines
                   if not line.startswith("0.0.0.0 www.")), None)
    block = "tzsp-selftest-block.example"
    _, msgs = get_json(f"{CONTROL}/messages?block={block},*.wild.example"
                       f"&note=selftest")
    check("a domain is added to the blacklist",
          any(f"added {block}" in m["message"] for m in msgs), str(msgs))
    check("a wildcard block is refused (adlist matching is exact)",
          any("wildcards cannot be blocked" in m["message"] for m in msgs))
    _, msgs = get_json(f"{CONTROL}/messages?allow={block}")
    check("a blacklisted domain cannot also be whitelisted",
          any("remove it there first" in m["message"] for m in msgs), str(msgs))
    _, msgs = get_json(f"{CONTROL}/messages?block={block}")
    check("adding it again is a no-op (the box is re-sent every refresh)",
          msgs == [{"message": "no change"}], str(msgs))
    if victim:
        get_json(f"{CONTROL}/messages?allow={victim}&note=selftest")
    served, exempted = "", -1
    for _ in range(30):
        time.sleep(2)
        _, _, body = get(f"{LISTS}/lists/_blacklist.txt")
        served = body.decode("utf-8", "replace")
        _, wl = get_json(f"{CONTROL}/whitelist")
        exempted = next((r["exempted"] for r in wl if r["domain"] == victim), -1)
        if f" {block}\n" in served and (not victim or exempted > 0):
            break
    check("the blacklist is served to the router",
          f"0.0.0.0 {block}\n" in served and f"0.0.0.0 www.{block}\n" in served)
    # Not the victim, and not under it either: a whitelist entry exempts every
    # name below it, so its www. form -- often the very next line -- is gone too.
    keep = next((line.split()[1] for line in lines
                 if not victim or (line.split()[1] != victim
                                   and not line.split()[1].endswith("." + victim))),
                None)
    _, rows = get_json(f"{CONTROL}/which?names=www.{block.upper()}.,"
                       f"{keep or ''}&names=tzsp-selftest-miss.example")
    got = {r["name"]: r for r in rows or []}
    check("/which names the blacklist for a blocked www. form",
          got.get(f"www.{block}", {}).get("source") == "dashboard"
          and got[f"www.{block}"]["note"] == "selftest", str(rows))
    if keep:
        check(f"/which names '{PROBE}' for a name in it",
              got.get(keep, {}).get("list") == PROBE, str(got.get(keep)))
    check("/which answers a miss with an empty list",
          got.get("tzsp-selftest-miss.example", {}).get("list") == "", str(rows))
    if victim:
        _, _, body = get(f"{LISTS}/lists/{PROBE}.txt")
        check(f"the whitelisted '{victim}' is gone from '{PROBE}'",
              f" {victim}\n" not in body.decode("utf-8", "replace")
              and exempted > 0, f"exempted {exempted}")
        get_json(f"{CONTROL}/messages?unallow={victim}")
    _, rows = get_json(f"{CONTROL}/blacklist?unblock={block}")
    check("the blacklist entry is removed again",
          all(r["domain"] != block for r in rows))

    # The responder's path: an automatic entry carries an expiry, and the
    # whitelist covers it by suffix (a hand-made block is allowed to carve a
    # name out of a whitelisted domain; an automatic one is not).
    auto, shield = "c2.tzsp-selftest-auto.example", "tzsp-selftest-auto.example"
    _, msgs = get_json(f"{CONTROL}/messages?block={auto}&ttl=3600&note=selftest")
    _, rows = get_json(f"{CONTROL}/blacklist")
    row = next((r for r in rows if r["domain"] == auto), {})
    check("an automatic (ttl) entry is added with an expiry",
          row.get("source") == "automatic" and row.get("until"), str(msgs))
    get_json(f"{CONTROL}/messages?unblock={auto}&allow={shield}")
    _, msgs = get_json(f"{CONTROL}/messages?block={auto}&ttl=3600")
    check("an automatic entry is refused under a whitelisted parent",
          any("covered by the whitelist entry" in m["message"] for m in msgs), str(msgs))
    get_json(f"{CONTROL}/messages?unallow={shield}")

    print(f"6. disable '{PROBE}' again")
    _, rows = get_json(f"{CONTROL}/categories?disable={PROBE}")
    check("the category is gone", all(r["category"] != PROBE for r in rows))
    time.sleep(3)
    status, _, _ = get(f"{LISTS}/lists/{PROBE}.txt")
    check("and its list is no longer served", status == 404, f"HTTP {status}")

    print()
    if failures:
        print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
