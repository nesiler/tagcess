#!/usr/bin/env python3
"""tagcess installer preflight probe (F6-002). Runs on the target host, READ-ONLY.

It only lists, stats and asks: package/unit/process state, versions, `headscale configtest` and `policy check`
(as the headscale user, so no root-owned database file can appear), `caddy validate`/`caddy adapt` (as the
caddy user), the Caddy admin API (GET only), certificate dates, listeners, free disk and the untouchable
components. It never reads a secret file's content: secret paths are only stat()ed (exists, mode, owner).
Its only argument is base64 JSON with the paths to look at; it prints one JSON object.
"""
import base64
import grp
import json
import os
import pwd
import re
import shutil
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone


def run(argv, user=None, timeout=20):
    """Run a command, return (rc, stdout, stderr); rc 127 when the tool is missing."""
    if shutil.which(argv[0]) is None:
        return 127, "", argv[0] + ": not installed"
    if user is not None:
        try:
            pwd.getpwnam(user)
        except KeyError:
            return 126, "", "user " + user + " does not exist"
        if os.geteuid() == 0 and shutil.which("runuser"):
            argv = ["runuser", "-u", user, "--"] + argv
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %ss" % timeout
    except OSError as e:
        return 126, "", str(e)


def last_line(s):
    lines = [x for x in s.strip().splitlines() if x.strip()]
    return lines[-1][:300] if lines else ""


def unit(name):
    """systemd unit state: present (unit file exists), active, enabled."""
    rc, out, _ = run(["systemctl", "list-unit-files", name + ".service", "--no-legend", "--no-pager"])
    present = rc == 0 and out.strip() != ""
    act = run(["systemctl", "is-active", name + ".service"])[1].strip() if present else "absent"
    ena = run(["systemctl", "is-enabled", name + ".service"])[1].strip() if present else "absent"
    return {"unit": present, "active": act == "active", "state": act or "unknown", "enabled": ena}


def fstat(path):
    try:
        st = os.lstat(path)
    except OSError:
        return {"path": path, "exists": False}
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    kind = "dir" if stat.S_ISDIR(st.st_mode) else ("link" if stat.S_ISLNK(st.st_mode) else "file")
    return {"path": path, "exists": True, "type": kind, "mode": "%04o" % stat.S_IMODE(st.st_mode), "owner": owner, "group": group}


def http_get(url, timeout=5, verify=True):
    ctx = None
    if url.startswith("https://") and not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout, context=ctx) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception as e:  # noqa: BLE001 - unreachable for any reason
        return -1, str(e).encode()[:300]


def docker_container(name):
    if shutil.which("docker") is None:
        return {"present": False, "running": False}
    rc, out, _ = run(["docker", "inspect", "-f", "{{.State.Running}} {{.Config.Image}}", name], timeout=10)
    if rc != 0:
        return {"present": False, "running": False}
    running, _, image = out.strip().partition(" ")
    return {"present": True, "running": running == "true", "image": image}


def listeners():
    """Listening TCP sockets: 'addr:port' -> process name (ss)."""
    rc, out, _ = run(["ss", "-ltnpH"])
    res = {}
    if rc != 0:
        return res
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        proc = ""
        m = re.search(r'users:\(\("([^"]+)"', line)
        if m:
            proc = m.group(1)
        res[local] = proc
    return res


def port_owner(lst, port):
    for local, proc in lst.items():
        if local.rsplit(":", 1)[-1] == str(port):
            return {"listening": True, "address": local, "process": proc}
    return {"listening": False}


def norm_json(b):
    try:
        return json.dumps(json.loads(b), sort_keys=True)
    except Exception:  # noqa: BLE001
        return None


def cert_info(name):
    base = "/etc/letsencrypt/live/" + name
    info = {"name": name, "fullchain": os.path.exists(base + "/fullchain.pem"), "privkey": os.path.exists(base + "/privkey.pem")}
    if info["fullchain"]:
        rc, out, _ = run(["openssl", "x509", "-enddate", "-noout", "-in", base + "/fullchain.pem"])
        if rc == 0 and "=" in out:
            when = out.strip().split("=", 1)[1]
            try:
                t = datetime.strptime(when, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                info["not_after"] = t.strftime("%Y-%m-%dT%H:%M:%SZ")
                info["days_left"] = int((t - datetime.now(timezone.utc)).total_seconds() // 86400)
            except ValueError:
                info["not_after"] = when
    return info


def oauth2_cfg_cookie(path):
    """Only the non-secret cookie/identity settings of oauth2-proxy.cfg (never *_secret)."""
    keys = ("cookie_name", "cookie_expire", "cookie_refresh", "cookie_domains", "whitelist_domains", "client_id",
            "cookie_secure", "cookie_samesite", "oidc_issuer_url", "client_secret_file", "cookie_secret_file",
            "insecure_oidc_allow_unverified_email")
    out = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"\s*([a-z_]+)\s*=\s*(.+?)\s*$", line)
                if m and m.group(1) in keys:
                    v = m.group(2)
                    try:
                        out[m.group(1)] = json.loads(v.replace("'", '"'))
                    except ValueError:
                        out[m.group(1)] = v.strip('"')
    except OSError:
        return None
    return out


def main():
    a = json.loads(base64.b64decode(sys.argv[1]))
    r = {}

    osr = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                k, _, v = line.strip().partition("=")
                osr[k] = v.strip('"')
    except OSError:
        pass
    r["os"] = {"id": osr.get("ID", ""), "version": osr.get("VERSION_ID", ""), "python": sys.version.split()[0]}
    r["tools"] = {t: shutil.which(t) is not None for t in ("sqlite3", "openssl", "docker", "ss", "systemctl", "curl")}

    # Docker
    d = {"present": shutil.which("docker") is not None or unit("docker")["unit"]}
    if d["present"]:
        rc, out, _ = run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=15)
        d.update({"running": rc == 0, "version": out.strip() if rc == 0 else ""})
    r["docker"] = d

    # Headscale
    hs = {"present": shutil.which("headscale") is not None}
    if hs["present"]:
        hs.update(unit("headscale"))
        hs["version"] = (run(["headscale", "version"])[1].strip().splitlines() or [""])[0].replace("headscale version ", "").strip().lstrip("v")
        hs["config"] = fstat(a["headscale_config"])
        rc, out, err = run(["headscale", "-c", a["headscale_config"], "configtest"], user="headscale", timeout=30)
        hs["configtest"] = {"ok": rc == 0, "detail": "" if rc == 0 else last_line(err or out)}
        rc, out, err = run(["headscale", "-c", a["headscale_config"], "users", "list", "-o", "json"], timeout=10)
        hs["grpc"] = {"ok": rc == 0, "detail": "" if rc == 0 else last_line(err or out)}
        pol = a["headscale_policy_path"]
        hs["policy_file"] = fstat(pol)
        if hs["policy_file"]["exists"]:
            rc, out, err = run(["headscale", "-c", a["headscale_config"], "policy", "check", "-f", pol], user="headscale", timeout=20)
            hs["policy_check"] = {"ok": rc == 0, "detail": "" if rc == 0 else last_line(err or out)}
            rc, out, _ = run(["sha256sum", pol])
            hs["policy_sha256"] = out.split()[0] if rc == 0 else ""
        status, _ = http_get(a["headscale_health_url"], timeout=5)
        hs["health"] = status
        hs["db"] = fstat(a["headscale_db_path"])
        hs["dns_records"] = fstat(a["headscale_dns_records_path"])
        hs["socket"] = fstat(a["headscale_socket"])
    r["headscale"] = hs

    # Caddy
    cd = {"present": shutil.which("caddy") is not None}
    if cd["present"]:
        cd.update(unit("caddy"))
        cd["version"] = run(["caddy", "version"])[1].strip().split(" ")[0].lstrip("v")
        cd["caddyfile"] = fstat(a["caddyfile_path"])
        if a.get("caddy_sites_dir"):
            cd["sites_dir"] = fstat(a["caddy_sites_dir"])
        rc, out, err = run(["caddy", "validate", "--config", a["caddyfile_path"], "--adapter", "caddyfile"], user="caddy", timeout=60)
        cd["validate"] = {"ok": rc == 0, "detail": "" if rc == 0 else last_line(err or out)}
        rc, adapted, err = run(["caddy", "adapt", "--config", a["caddyfile_path"], "--adapter", "caddyfile"], user="caddy", timeout=60)
        status, live = http_get(a["caddy_admin_url"].rstrip("/") + "/config/", timeout=5)
        cd["admin"] = status
        if rc == 0 and status == 200:
            na, nl = norm_json(adapted), norm_json(live)
            cd["disk_equals_running"] = na is not None and na == nl
        else:
            cd["disk_equals_running"] = None
            cd["drift_detail"] = "adapt rc %d, admin %s" % (rc, status)
        cd["tagcess_marker"] = False
        try:
            with open(a["caddyfile_path"], encoding="utf-8") as f:
                cd["tagcess_marker"] = f.readline().startswith("# Generated by tagcess")
        except OSError:
            pass
    r["caddy"] = cd

    # certbot and certificates
    r["certbot"] = {"present": shutil.which("certbot") is not None, "timer": unit("certbot")["enabled"] if shutil.which("systemctl") else ""}
    r["certs"] = [cert_info(n) for n in a.get("cert_names", [])]

    # oauth2-proxy (systemd binary or container)
    op = {"unit": unit("oauth2-proxy"), "binary": shutil.which("oauth2-proxy") is not None or os.path.exists("/usr/local/bin/oauth2-proxy"),
          "container": docker_container("oauth2-proxy")}
    op["present"] = op["unit"]["unit"] or op["binary"] or op["container"]["present"]
    op["running"] = op["unit"]["active"] or op["container"]["running"]
    cfgp = a["oauth2_proxy_dir"] + "/oauth2-proxy.cfg"
    op["config"] = fstat(cfgp)
    op["settings"] = oauth2_cfg_cookie(cfgp) if op["config"]["exists"] else None
    r["oauth2_proxy"] = op

    # Tailscale
    ts = {"present": shutil.which("tailscale") is not None}
    if ts["present"]:
        ts.update(unit("tailscaled"))
        rc, out, _ = run(["tailscale", "ip", "-4"], timeout=10)
        ts["ip4"] = out.strip().splitlines()[0] if rc == 0 and out.strip() else ""
        rc, out, _ = run(["tailscale", "status", "--json"], timeout=10)
        try:
            st = json.loads(out) if rc == 0 else {}
        except ValueError:
            st = {}
        ts["backend_state"] = st.get("BackendState", "")
        ts["tags"] = (st.get("Self") or {}).get("Tags") or []
    r["tailscale"] = ts

    # hshelper, tagcess
    r["hshelper"] = {"present": os.path.exists("/usr/local/bin/tagcess-hshelper"),
                     "path_enabled": run(["systemctl", "is-enabled", "tagcess-hshelper.path"])[1].strip()}
    tg = {"config": fstat("/etc/tagcess/config.yaml"), "db": fstat("/var/lib/tagcess/tagcess.db"), "container": docker_container("tagcess")}
    tg["present"] = tg["config"]["exists"] or tg["container"]["present"]
    r["tagcess"] = tg

    # Ports and disk
    lst = listeners()
    r["ports"] = {str(p): port_owner(lst, p) for p in (a["hook_port"], 4180, 2019, 8080)}
    try:
        sv = os.statvfs("/var/lib")
        r["disk_free_mb"] = sv.f_bavail * sv.f_frsize // (1024 * 1024)
    except OSError:
        r["disk_free_mb"] = -1

    # Zitadel discovery (from the host, as tagcess/oauth2-proxy/Headscale will reach it)
    status, _ = http_get(a["zitadel_discovery_url"], timeout=5, verify=a.get("validate_certs", True))
    r["zitadel"] = {"url": a["zitadel_discovery_url"], "status": status}

    # Untouchables: detected and reported, never changed
    hp = docker_container("headplane")
    r["untouched"] = {
        "headplane": {"present": os.path.isdir("/etc/headplane") or hp["present"], "detail": "container" if hp["present"] else ("/etc/headplane" if os.path.isdir("/etc/headplane") else "")},
        "wireguard": {"present": os.path.isdir("/etc/wireguard") or shutil.which("wg") is not None, "detail": "/etc/wireguard" if os.path.isdir("/etc/wireguard") else ""},
        "wireguard-ui": {"present": unit("wireguard-ui")["unit"], "detail": "wireguard-ui.service" if unit("wireguard-ui")["unit"] else ""},
        "dnsmasq": {"present": unit("dnsmasq")["unit"], "detail": "dnsmasq.service" if unit("dnsmasq")["unit"] else ""},
        "nftables": {"present": os.path.exists("/etc/nftables.conf"), "detail": "/etc/nftables.conf" if os.path.exists("/etc/nftables.conf") else ""},
    }

    # Secret files already on the host: existence, mode, owner only.
    r["host_secret_files"] = [fstat(p) for p in a.get("host_secret_paths", [])]
    print(json.dumps(r, sort_keys=True))


if __name__ == "__main__":
    main()
