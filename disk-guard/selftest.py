"""Prove the disk guard's decisions without filling a disk to find out.

    docker compose exec disk-guard python selftest.py

Everything here runs against a throwaway directory and a stubbed command
socket, so a run touches neither the real logs nor InfluxDB. What it exercises
is the part that is dangerous to get wrong -- *which file gets deleted, and
when*:

  * a rotation older than the retain window goes;
  * the byte budget deletes oldest-first, and stops as soon as it fits;
  * a rotation younger than min_keep_seconds is spared by the byte budget (the
    responder may still be reading it) but not by the disk ceiling;
  * the live file Suricata holds open is never deleted, only rotated -- and a
  * failed `reopen-log-files` puts the rename back, because Suricata is still
    writing to that inode;
  * retention steps down towards the floor and stops there;
  * the size parser reads `512M` the same way a human does.

The one thing it cannot check is the ceiling itself: that needs a filesystem
that is genuinely 90% full. `disk()` is checked against the real mount instead,
which at least proves the reading is sane and matches `df`.
"""
import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guard  # noqa: E402

failures = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  -- {detail}" if detail else ""))
    if not ok:
        failures.append(label)
    return ok


class StubControl:
    """Stands in for Suricata: `reopen-log-files` recreates the live file, which
    is what the real engine does on its next write."""

    def __init__(self, directory, succeed=True):
        self.dir = directory
        self.succeed = succeed
        self.calls = 0

    def available(self):
        return True

    def reopen(self):
        self.calls += 1
        if not self.succeed:
            return False
        for name in guard.LIVE_LOGS:
            path = os.path.join(self.dir, name)
            if not os.path.exists(path):
                with open(path, "w") as fh:
                    fh.write("fresh\n")
        return True


def write(path, size, age_seconds=0):
    with open(path, "wb") as fh:
        fh.write(b"x" * size)
    if age_seconds:
        when = time.time() - age_seconds
        os.utime(path, (when, when))
    return path


def settings(**overrides):
    values = {
        "disk_guard.eve_retain_days": "3",
        "disk_guard.logs_max_bytes": "4K",
        "disk_guard.eve_max_bytes": "2K",
        "disk_guard.suricata_log_max_bytes": "1K",
        "disk_guard.min_keep_seconds": "300",
    }
    values.update(overrides)
    cfg = guard.Config("/nonexistent-on-purpose")
    cfg.values = values
    return guard.Settings(cfg)


def main():
    print("1. the size parser")
    cfg = guard.Config("/nonexistent-on-purpose")
    cfg.values = {"a": "512M", "b": "2G", "c": "4096", "d": "1MiB", "e": "banana"}
    check("512M", cfg.get_bytes("a", 0) == 512 * guard.MIB)
    check("2G", cfg.get_bytes("b", 0) == 2 * guard.GIB)
    check("a bare number is bytes", cfg.get_bytes("c", 0) == 4096)
    check("1MiB", cfg.get_bytes("d", 0) == guard.MIB)
    check("nonsense falls back to the default", cfg.get_bytes("e", 7) == 7)

    print("2. this filesystem, as df sees it")
    total, used, avail, percent = guard.disk("/")
    check("a plausible reading", total > 0 and 0 < percent < 100,
          f"{guard.human(used)} of {guard.human(total)} used, {percent:.1f}%")
    check("bytes_over is 0 below the target",
          guard.bytes_over("/", min(99.0, percent + 5)) == 0)
    check("bytes_over is positive above it",
          guard.bytes_over("/", max(0.1, percent - 5)) > 0)
    # The log budget is derived from bytes_free_to, so the two have to be
    # complementary: one of them is always zero, never both, never neither.
    target = min(99.0, percent + 5)
    check("bytes_free_to is what bytes_over is not",
          guard.bytes_free_to("/", target) > 0 and guard.bytes_over("/", target) == 0,
          guard.human(guard.bytes_free_to("/", target)) + " before " +
          f"{target:.1f}%")
    check("and it is zero once the mark is passed",
          guard.bytes_free_to("/", max(0.1, percent - 5)) == 0)

    print("3. ageing rotations out")
    tmp = tempfile.mkdtemp(prefix="disk-guard-selftest-")
    try:
        cfgset = settings()
        control = StubControl(tmp)
        warden = guard.LogWarden(tmp, control, cfgset, lambda *a: None)
        write(os.path.join(tmp, "eve.json"), 100)
        old = write(os.path.join(tmp, "eve.json.20260101-000000"), 500, 5 * 86400)
        young = write(os.path.join(tmp, "eve.json.20260908-000000"), 500, 3600)
        freed = warden.prune_aged()
        check("the old rotation is gone", not os.path.exists(old))
        check("the young one is kept", os.path.exists(young))
        check("and the freed bytes are reported", freed == 500, str(freed))

        print("4. the byte budget, oldest first")
        for name, size, age in (("eve.json.a", 1000, 4000), ("eve.json.b", 1000, 3000),
                                ("eve.json.c", 1000, 2000), ("eve.json.d", 1000, 100)):
            write(os.path.join(tmp, name), size, age)
        os.remove(young)
        # 4 rotations + a 100 B live file against a 4 KiB budget: one has to go.
        freed = warden.prune_to_budget(cfgset.logs_max)
        check("the oldest rotation went", not os.path.exists(os.path.join(tmp, "eve.json.a")))
        check("the others stayed", all(os.path.exists(os.path.join(tmp, "eve.json." + n))
                                       for n in "bcd"))
        check("it stopped as soon as it fitted", freed == 1000, str(freed))
        check("the directory now fits", warden.total_bytes() <= cfgset.logs_max,
              guard.human(warden.total_bytes()))

        print("5. a rotation the responder may still be reading")
        # 'd' is 100s old, min_keep_seconds is 300: the byte budget must leave it
        # alone even when that means staying over budget.
        freed = warden.prune_to_budget(1000)
        check("the young rotation survived the byte budget",
              os.path.exists(os.path.join(tmp, "eve.json.d")))
        check("the older ones did not", not any(
            os.path.exists(os.path.join(tmp, "eve.json." + n)) for n in "bc"))
        freed = warden.prune_to_budget(1000, respect_min_keep=False)
        check("but the disk ceiling takes it",
              not os.path.exists(os.path.join(tmp, "eve.json.d")), f"freed {freed}")

        print("6. rotating the file Suricata holds open")
        write(os.path.join(tmp, "eve.json"), 4096)          # over eve_max (2K)
        write(os.path.join(tmp, "suricata.log"), 64)        # under its cap
        rotated = warden.rotate_oversize()
        check("eve.json was rotated", len(rotated) == 1 and os.path.exists(rotated[0]))
        check("suricata.log was left alone", not any("suricata.log" in p for p in rotated))
        check("a fresh eve.json exists", os.path.exists(os.path.join(tmp, "eve.json")))
        check("the live file itself was never deleted",
              os.path.getsize(rotated[0]) == 4096)
        check("Suricata was asked exactly once", control.calls == 1, str(control.calls))

        print("7. a rotation Suricata refuses")
        failing = guard.LogWarden(tmp, StubControl(tmp, succeed=False), cfgset,
                                  lambda *a: None)
        write(os.path.join(tmp, "eve.json"), 4096)
        before = sorted(os.listdir(tmp))
        check("nothing claims to have rotated", failing.rotate_oversize() == [])
        check("the rename was put back", sorted(os.listdir(tmp)) == before)
        check("eve.json is still the file being written",
              os.path.getsize(os.path.join(tmp, "eve.json")) == 4096)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("8. retention steps down to the floor, and no further")
    steps = []
    days = 30
    for _ in range(20):
        days = guard.shrink_days(days, 2, 25)
        steps.append(days)
    check("the first cut is a quarter", steps[0] == 22, str(steps[0]))
    check("it reaches the floor", steps[-1] == 2, str(steps[-1]))
    check("and stops there", guard.shrink_days(2, 2, 25) == 2)
    check("a 1-day step is the minimum", guard.shrink_days(3, 1, 1) == 2)

    print("9. when NOT to cut the retention")
    GIB = guard.GIB
    cut, why = guard.cut_decision(over=False, too_big=False, bucket_bytes=5 * GIB,
                                  need=0, since_cut=1e9, cooldown=1800)
    check("no pressure, no cut", not cut and not why)
    cut, why = guard.cut_decision(over=True, too_big=False, bucket_bytes=5 * GIB,
                                  need=8 * GIB, since_cut=1e9, cooldown=1800)
    check("a bucket that is most of the problem is cut", cut and not why)
    cut, why = guard.cut_decision(over=True, too_big=False, bucket_bytes=20 * guard.MIB,
                                  need=8 * GIB, since_cut=1e9, cooldown=1800)
    check("a bucket that is a rounding error is not", not cut and "not what filled" in why,
          "deleting weeks of alerts would not have freed the disk either")
    cut, why = guard.cut_decision(over=True, too_big=False, bucket_bytes=5 * GIB,
                                  need=8 * GIB, since_cut=120, cooldown=1800)
    check("and neither is one cut two minutes ago", not cut and "expire those shards" in why,
          "InfluxDB expires shards every 30 min; a 60s pass would cut blind")
    cut, why = guard.cut_decision(over=False, too_big=True, bucket_bytes=20 * guard.MIB,
                                  need=0, since_cut=1e9, cooldown=1800)
    check("influx_max_bytes cuts whatever the disk says", cut and not why)
    cut, why = guard.cut_decision(over=False, too_big=True, bucket_bytes=20 * guard.MIB,
                                  need=0, since_cut=60, cooldown=1800)
    check("but it still waits out the cooldown", not cut and why)

    print("10. the effective retention survives a restart")
    tmp = tempfile.mkdtemp(prefix="disk-guard-state-")
    try:
        path = os.path.join(tmp, "state.json")
        state = guard.State(path)
        check("it starts at the configured value", state.retention_days(30) == 30)
        state.set_retention_days(11)
        check("a cut is remembered", guard.State(path).retention_days(30) == 11,
              "a guard that forgot would refill the disk and cut again")
        check("changing the property file re-expands it",
              guard.State(path).retention_days(14) == 14)
        check("and a cut is timestamped, so the cooldown survives too",
              guard.State(path).seconds_since_cut() < 60)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if failures:
        print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
