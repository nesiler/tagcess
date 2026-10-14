#!/usr/bin/env python3
"""tagcess installer backup (F6-003). Runs on the target host as root.

Copies every configured path (files and whole directories, mode/owner kept) into <root>/<id>/files/<path>,
takes consistent SQLite copies with `.backup` (as the database owner, so the live database never gets a
root-owned -wal/-shm file), exports the Headscale policy when it lives in the database, and writes
<root>/<id>/manifest.json (path, type, sha256, mode, owner). A path that does not exist is recorded as
"existed": false. The backup stays on the host: nothing here is sent anywhere, and the printed summary
carries no file content. Old backups beyond `keep` are removed (newest kept).
Argument: base64 JSON {root, id, phase, paths, sqlite: [{path, name, owner}], headscale_policy_db, keep}.
"""
import base64
import grp
import hashlib
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def meta(path):
    st = os.lstat(path)
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return {"mode": "%04o" % (st.st_mode & 0o7777), "owner": owner, "group": group, "uid": st.st_uid, "gid": st.st_gid}


def copy_entry(src, dst_root, entries):
    dst = os.path.join(dst_root, src.lstrip("/"))
    os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
    if os.path.islink(src):
        os.symlink(os.readlink(src), dst)
        e = {"path": src, "type": "link", "target": os.readlink(src), "existed": True}
        e.update(meta(src))
        entries.append(e)
    elif os.path.isdir(src):
        os.makedirs(dst, exist_ok=True)
        shutil.copystat(src, dst)
        os.chown(dst, os.lstat(src).st_uid, os.lstat(src).st_gid)
        e = {"path": src, "type": "dir", "existed": True}
        e.update(meta(src))
        entries.append(e)
        for name in sorted(os.listdir(src)):
            copy_entry(os.path.join(src, name), dst_root, entries)
    elif os.path.isfile(src):
        shutil.copy2(src, dst)
        os.chown(dst, os.lstat(src).st_uid, os.lstat(src).st_gid)
        e = {"path": src, "type": "file", "sha256": sha256(dst), "existed": True}
        e.update(meta(src))
        entries.append(e)
    # sockets, fifos, devices are not configuration: skipped


def sqlite_backup(src, dst, owner):
    """Consistent copy with sqlite3 .backup, run as the database owner."""
    st = os.stat(src)
    tmpdir = tempfile.mkdtemp(prefix="tagcess-backup-")
    os.chown(tmpdir, st.st_uid, st.st_gid)
    tmp = os.path.join(tmpdir, "db.sqlite")
    cmd = ["sqlite3", src, ".backup '%s'" % tmp]
    if shutil.which("setpriv"):
        cmd = ["setpriv", "--reuid", str(st.st_uid), "--regid", str(st.st_gid), "--clear-groups"] + cmd
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    if p.returncode != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError("sqlite3 .backup %s failed: %s" % (src, (p.stderr or p.stdout).strip()[:200]))
    os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
    shutil.move(tmp, dst)
    shutil.rmtree(tmpdir, ignore_errors=True)
    os.chown(dst, st.st_uid, st.st_gid)
    os.chmod(dst, st.st_mode & 0o777)


def main():
    a = json.loads(base64.b64decode(sys.argv[1]))
    root = a["root"]
    os.makedirs(root, mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    bdir = os.path.join(root, a["id"])
    if os.path.exists(bdir):
        raise SystemExit("backup %s already exists" % a["id"])
    os.makedirs(bdir, mode=0o700)
    files_root = os.path.join(bdir, "files")
    os.makedirs(files_root, mode=0o700)
    entries = []
    for p in a["paths"]:
        if os.path.lexists(p):
            copy_entry(p, files_root, entries)
        else:
            entries.append({"path": p, "type": "missing", "existed": False})
    # Probe paths: recorded (existence, mode, owner) but not copied: data directories a rollback may move aside when
    # they did not exist before the installer ran.
    for p in a.get("probe_paths", []):
        if os.path.lexists(p):
            e = {"path": p, "type": "probe", "existed": True}
            e.update(meta(p))
            entries.append(e)
        else:
            entries.append({"path": p, "type": "missing", "existed": False})
    dbs = []
    for db in a.get("sqlite", []):
        if os.path.exists(db["path"]):
            dst = os.path.join(bdir, "db", db["name"])
            sqlite_backup(db["path"], dst, db.get("owner"))
            d = {"path": db["path"], "backup": "db/" + db["name"], "sha256": sha256(dst), "existed": True}
            d.update(meta(db["path"]))
            dbs.append(d)
        else:
            dbs.append({"path": db["path"], "existed": False})
    policy_db = None
    if a.get("headscale_policy_db"):
        p = subprocess.run(["headscale", "policy", "get"], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        if p.returncode == 0:
            dst = os.path.join(bdir, "policy-db.hujson")
            with open(dst, "w", encoding="utf-8") as f:
                f.write(p.stdout)
            os.chmod(dst, 0o600)
            policy_db = {"backup": "policy-db.hujson", "sha256": sha256(dst)}
    manifest = {"id": a["id"], "phase": a["phase"], "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "entries": entries, "sqlite": dbs, "policy_db": policy_db}
    mpath = os.path.join(bdir, "manifest.json")
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    os.chmod(mpath, 0o600)

    # Retention: keep the newest `keep` backups (ids start with a sortable UTC time). A backup the installer state still
    # points at (the one a rollback returns to) is never removed.
    removed = []
    keep = int(a.get("keep", 10))
    protect = set(a.get("protect", [])) | {a["id"]}
    ids = sorted(d for d in os.listdir(root) if os.path.isfile(os.path.join(root, d, "manifest.json")) and d not in protect)
    for old in ids[:-keep] if keep > 0 else []:
        shutil.rmtree(os.path.join(root, old), ignore_errors=True)
        removed.append(old)

    print(json.dumps({"id": a["id"], "dir": bdir, "files": sum(1 for e in entries if e["type"] == "file"),
                      "missing": [e["path"] for e in entries if not e["existed"]],
                      "sqlite": [d["path"] for d in dbs if d["existed"]], "policy_db": policy_db is not None,
                      "removed_old": removed}))


if __name__ == "__main__":
    main()
