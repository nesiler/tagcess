#!/usr/bin/env python3
"""tagcess installer restore (F6-003). Runs on the target host as root; restore.yml calls it.

Puts the files of <root>/<id> back: every file, directory and link the manifest recorded is returned to its
sha256, mode and owner; a file that appeared later inside a backed-up directory is moved to
<root>/<id>/restore-removed/ (never deleted outright); a path that did not exist at backup time is left alone
and reported. The backup's own files are verified against the manifest first (a tampered backup restores
nothing). With `sqlite`, the listed databases are copied back too (the caller stops their service first).
Prints JSON: restored, removed, left (did not exist at backup time but exist now), db_restored. No content.
Modes (argument `mode`, default "restore"): "verify" checks the backup is whole for what would be restored (the backup
directory and manifest exist and parse, every file matches its sha256, each requested database copy matches and is a
readable SQLite database) and changes nothing; "restore" (with `undo_id`) first saves every file/database it is about to
replace or move aside under <root>/<id>/undo-<undo_id>/; "undo" puts that saved state back (a failed restore leaves
the host as it was); "drop_undo" removes the saved state after a successful restore.
With `remove_absent`, a selected path that did not exist at backup time but exists now is moved aside too (rollback:
the installer created it). Argument: base64 JSON {root, id, only (path prefixes, optional), sqlite (paths, optional),
remove_absent, dry_run}.
"""
import base64
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import sys


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def move_aside(p, trash):
    """Move p under trash (kept with the backup, not deleted). Runtime state under /run (sockets, tmpfs) is deleted:
    it holds no data and sockets cannot be copied across file systems."""
    if p == "/run" or p.startswith("/run/"):
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.remove(p)
        return
    dst = os.path.join(trash, p.lstrip("/"))
    os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
    if os.path.lexists(dst):
        if os.path.isdir(dst) and not os.path.islink(dst):
            shutil.rmtree(dst)
        else:
            os.remove(dst)
    shutil.move(p, dst)


def selected(path, only):
    return not only or any(path == p or path.startswith(p.rstrip("/") + "/") for p in only)


def same_meta(path, e):
    st = os.lstat(path)
    return "%04o" % (st.st_mode & 0o7777) == e["mode"] and st.st_uid == e["uid"] and st.st_gid == e["gid"]


def load_manifest(a):
    bdir = os.path.join(a["root"], a["id"])
    mpath = os.path.join(bdir, "manifest.json")
    if not os.path.isfile(mpath):
        raise SystemExit("backup %s does not exist (%s)" % (a["id"], mpath))
    try:
        with open(mpath, encoding="utf-8") as f:
            man = json.load(f)
        man["entries"]
    except (ValueError, KeyError, OSError) as e:
        raise SystemExit("backup %s has an unreadable manifest: %s" % (a["id"], type(e).__name__))
    return bdir, man


def verify_backup(a, bdir, man):
    """The backup itself must be intact for everything a restore would use; nothing is changed."""
    files_root = os.path.join(bdir, "files")
    for e in man["entries"]:
        if e["type"] == "file":
            src = os.path.join(files_root, e["path"].lstrip("/"))
            if not os.path.isfile(src) or sha256(src) != e["sha256"]:
                raise SystemExit("backup %s is damaged: %s does not match its manifest" % (a["id"], e["path"]))
    listed = {d["path"] for d in man.get("sqlite", [])}
    for want in a.get("sqlite", []):
        if want not in listed:
            raise SystemExit("backup %s has no copy of the database %s" % (a["id"], want))
    for d in man.get("sqlite", []):
        if d.get("existed") and d["path"] in a.get("sqlite", []):
            copy = os.path.join(bdir, d["backup"])
            if not os.path.isfile(copy) or sha256(copy) != d["sha256"]:
                raise SystemExit("backup %s is damaged: %s does not match its manifest" % (a["id"], d["path"]))
            try:
                con = sqlite3.connect("file:%s?mode=ro&immutable=1" % copy, uri=True)
                try:
                    ok = con.execute("PRAGMA integrity_check").fetchone()
                finally:
                    con.close()
            except sqlite3.Error:
                ok = None
            if not ok or ok[0] != "ok":
                raise SystemExit("backup %s is damaged: the copy of %s is not a sound SQLite database" % (a["id"], d["path"]))


def chown_like(dst, st):
    os.chown(dst, st.st_uid, st.st_gid, follow_symlinks=False)


def copy_owned(src, dst):
    """Copy a file, link or tree with mode and owner (what shutil.copy2 alone does not keep)."""
    st = os.lstat(src)
    if stat.S_ISSOCK(st.st_mode) or stat.S_ISFIFO(st.st_mode) or stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
        return  # runtime objects (sockets, fifos, devices) hold no data and cannot be copied
    if os.path.islink(src):
        os.symlink(os.readlink(src), dst)
        chown_like(dst, st)
    elif os.path.isdir(src):
        os.makedirs(dst, exist_ok=True)
        for name in sorted(os.listdir(src)):
            copy_owned(os.path.join(src, name), os.path.join(dst, name))
        shutil.copystat(src, dst)
        chown_like(dst, st)
    else:
        shutil.copy2(src, dst)
        chown_like(dst, st)


def remove_any(p):
    if os.path.isdir(p) and not os.path.islink(p):
        shutil.rmtree(p)
    elif os.path.lexists(p):
        os.remove(p)


class Undo:
    """What a restore replaces, moves aside or creates is saved first, so a failed restore can be undone."""

    def __init__(self, bdir, token, enabled):
        self.dir = os.path.join(bdir, "undo-" + token) if token else ""
        self.enabled = enabled and bool(token)
        self.items = []
        if self.enabled:
            os.makedirs(os.path.join(self.dir, "files"), mode=0o700, exist_ok=True)

    def _flush(self):
        tmp = os.path.join(self.dir, "journal.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.items, f)
        os.replace(tmp, os.path.join(self.dir, "journal.json"))

    def save(self, p):
        """Call before p is replaced, moved aside, removed or created."""
        if not self.enabled or any(i["path"] == p for i in self.items):
            return
        if not os.path.lexists(p):
            self.items.append({"path": p, "existed": False})
        else:
            dst = os.path.join(self.dir, "files", p.lstrip("/"))
            os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
            copy_owned(p, dst)
            self.items.append({"path": p, "existed": True})
        self._flush()

    def save_meta(self, p):
        """Call before only the mode/owner of an existing path changes."""
        if not self.enabled or any(i["path"] == p for i in self.items):
            return
        st = os.lstat(p)
        self.items.append({"path": p, "existed": True, "meta": {"mode": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid}})
        self._flush()


def undo_restore(a, bdir):
    d = os.path.join(bdir, "undo-" + a["undo_id"])
    jp = os.path.join(d, "journal.json")
    if not os.path.isfile(jp):
        print(json.dumps({"id": a["id"], "undone": []}))
        return
    with open(jp, encoding="utf-8") as f:
        items = json.load(f)
    undone = []
    for it in reversed(items):
        p = it["path"]
        if not it["existed"]:
            remove_any(p)
        elif "meta" in it:
            os.chown(p, it["meta"]["uid"], it["meta"]["gid"])
            os.chmod(p, it["meta"]["mode"])
        else:
            src = os.path.join(d, "files", p.lstrip("/"))
            if not os.path.lexists(src):
                continue  # a runtime object (socket, fifo) was never copied
            os.makedirs(os.path.dirname(p), exist_ok=True)
            tmp = p + ".tagcess-undo"
            remove_any(tmp)
            copy_owned(src, tmp)
            remove_any(p)
            os.replace(tmp, p)
        undone.append(p)
    print(json.dumps({"id": a["id"], "undone": undone}))


def main():
    a = json.loads(base64.b64decode(sys.argv[1]))
    mode = a.get("mode", "restore")
    bdir, man = load_manifest(a)
    if mode == "drop_undo":
        shutil.rmtree(os.path.join(bdir, "undo-" + a["undo_id"]), ignore_errors=True)
        print(json.dumps({"id": a["id"], "dropped": True}))
        return
    if mode == "undo":
        undo_restore(a, bdir)
        return
    files_root = os.path.join(bdir, "files")
    only = a.get("only") or []
    dry = bool(a.get("dry_run"))

    # 1. The backup itself must be intact.
    verify_backup(a, bdir, man)
    if mode == "verify":
        print(json.dumps({"id": a["id"], "phase": man["phase"], "verified": True}))
        return
    undo = Undo(bdir, a.get("undo_id", ""), not dry)

    restored, removed, left, dbs = [], [], [], []
    known = {e["path"] for e in man["entries"]}
    trash = os.path.join(bdir, "restore-removed")

    # 2. Directories and links first, then files.
    for e in man["entries"]:
        p = e["path"]
        if not selected(p, only):
            continue
        if not e["existed"]:
            if os.path.lexists(p):
                if a.get("remove_absent"):
                    removed.append(p)
                    if not dry:
                        undo.save(p)
                        move_aside(p, trash)
                else:
                    left.append(p)
            continue
        if e["type"] == "probe":
            continue
        if e["type"] == "dir":
            if not os.path.isdir(p):
                restored.append(p)
                if not dry:
                    undo.save(p)
                    os.makedirs(p, exist_ok=True)
            if not dry and not same_meta(p, e):
                undo.save_meta(p)
                os.chown(p, e["uid"], e["gid"])
                os.chmod(p, int(e["mode"], 8))
        elif e["type"] == "link":
            if not (os.path.islink(p) and os.readlink(p) == e["target"]):
                restored.append(p)
                if not dry:
                    undo.save(p)
                    if os.path.lexists(p):
                        os.remove(p)
                    os.symlink(e["target"], p)
    for e in man["entries"]:
        p = e["path"]
        if e["type"] != "file" or not e["existed"] or not selected(p, only):
            continue
        current_ok = os.path.isfile(p) and not os.path.islink(p) and sha256(p) == e["sha256"] and same_meta(p, e)
        if current_ok:
            continue
        restored.append(p)
        if dry:
            continue
        src = os.path.join(files_root, p.lstrip("/"))
        undo.save(p)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tagcess-restore"
        shutil.copy2(src, tmp)
        os.chown(tmp, e["uid"], e["gid"])
        os.chmod(tmp, int(e["mode"], 8))
        os.replace(tmp, p)

    # 3. Files that appeared later inside a backed-up directory leave (moved aside, not deleted).
    for e in man["entries"]:
        if e["type"] != "dir" or not e["existed"] or not selected(e["path"], only):
            continue
        for dirpath, dirnames, filenames in os.walk(e["path"], topdown=False):
            for name in filenames + dirnames:
                p = os.path.join(dirpath, name)
                if p in known:
                    continue
                if os.path.isdir(p) and not os.path.islink(p):
                    # An unknown directory: its unknown children were handled first (bottom-up).
                    if not dry and not os.listdir(p):
                        undo.save(p)
                        os.rmdir(p)
                    removed.append(p)
                    continue
                removed.append(p)
                if not dry:
                    undo.save(p)
                    dst = os.path.join(trash, p.lstrip("/"))
                    os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
                    shutil.move(p, dst)

    # 3b. A selected path the manifest does not list, inside a directory the backup recorded as existing, did not exist
    # at backup time either (e.g. a file the installer added later): with remove_absent it is moved aside as well.
    if a.get("remove_absent"):
        dirs = {e["path"] for e in man["entries"] if e["type"] == "dir" and e["existed"]}
        for p in only:
            if p in known or not os.path.lexists(p) or p in removed:
                continue
            parent = os.path.dirname(p.rstrip("/"))
            while parent not in ("", "/") and parent not in dirs:
                parent = os.path.dirname(parent)
            if parent in dirs:
                removed.append(p)
                if not dry:
                    undo.save(p)
                    move_aside(p, trash)

    # 4. Databases on request (the caller stopped their service).
    for d in man.get("sqlite", []):
        if not d.get("existed") or d["path"] not in a.get("sqlite", []):
            continue
        dbs.append(d["path"])
        if dry:
            continue
        for suffix in ("-wal", "-shm"):
            if os.path.exists(d["path"] + suffix):
                undo.save(d["path"] + suffix)
                os.remove(d["path"] + suffix)
        undo.save(d["path"])
        tmp = d["path"] + ".tagcess-restore"
        shutil.copy2(os.path.join(bdir, d["backup"]), tmp)
        os.chown(tmp, d["uid"], d["gid"])
        os.chmod(tmp, int(d["mode"], 8))
        os.replace(tmp, d["path"])

    print(json.dumps({"id": a["id"], "phase": man["phase"], "restored": restored, "removed": removed, "left": left,
                      "db_restored": dbs, "dry_run": dry}))


if __name__ == "__main__":
    main()
