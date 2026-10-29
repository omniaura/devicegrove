#!/usr/bin/env python3
"""Local, experimental osquery evidence collector. No daemon or network client."""

import datetime as dt
import json
import re
import subprocess
import sys

QUERIES = {
    "filevault": "SELECT DISTINCT filevault_status FROM disk_encryption;",
    "screen_lock": "SELECT enabled, grace_period FROM screenlock;",
    "os_version": "SELECT version, build FROM os_version;",
}


def query(binary, sql):
    try:
        proc = subprocess.run(
            [binary, "--json", "--disable_extensions", "--disable_events", sql],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False,
        )
        if proc.returncode or len(proc.stdout) > 65536:
            return None
        rows = json.loads(proc.stdout)
        return rows if isinstance(rows, list) and all(isinstance(r, dict) for r in rows) else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def result(status, reason, evidence=None):
    return {"status": status, "reason": reason, "evidence": evidence or {}}


def evaluate(data):
    rows = data.get("filevault")
    values = {r["filevault_status"] for r in rows} if rows and all(isinstance(r.get("filevault_status"), str) for r in rows) else set()
    if values == {"on"}:
        filevault = result("unknown", "FileVault reports on; startup-volume coverage is not validated", {"filevault_status": "on"})
    elif values == {"off"}:
        filevault = result("fail", "FileVault reports off")
    else:
        filevault = result("unknown", "missing, conflicting, or unrecognized FileVault evidence")

    rows = data.get("screen_lock")
    lock = result("unknown", "user-context measurement does not establish effective lock policy")
    if rows and len(rows) == 1:
        enabled, grace = rows[0].get("enabled"), rows[0].get("grace_period")
        if str(enabled) in ("0", "1") and re.fullmatch(r"[0-9]{1,7}", str(grace)):
            lock["evidence"] = {"password_required": str(enabled) == "1", "grace_seconds": int(grace)}

    rows = data.get("os_version")
    os_result = result("unknown", "OS version alone does not establish update compliance")
    if rows and len(rows) == 1:
        version, build = rows[0].get("version"), rows[0].get("build")
        if isinstance(version, str) and isinstance(build, str) and re.fullmatch(r"[0-9.]{1,24}", version) and re.fullmatch(r"[A-Za-z0-9.]{1,24}", build):
            os_result["evidence"] = {"version": version, "build": build}
    return {
        "filevault": filevault,
        "screen_lock": lock,
        "os_updates": os_result,
        "endpoint_protection": result("unknown", "health and protection cannot be inferred from application presence"),
        "password_manager": result("unknown", "installation cannot establish account use or vault security"),
    }


def collect(binary):
    data = {name: query(binary, sql) for name, sql in QUERIES.items()}
    return {
        "schema": 1,
        "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "checks": evaluate(data),
    }


def main():
    if sys.platform != "darwin":
        print("This collector requires macOS; no queries were run.", file=sys.stderr)
        return 2
    if len(sys.argv) != 2 or not sys.argv[1].startswith("/"):
        print("Usage: collector.py /absolute/path/to/osqueryi", file=sys.stderr)
        return 2
    print(json.dumps(collect(sys.argv[1]), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
