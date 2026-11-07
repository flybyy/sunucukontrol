import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API = "https://api.cloudflare.com/client/v4"


def _cfg():
    return {
        "token": os.environ.get("CF_API_TOKEN", "").strip(),
        "account": os.environ.get("CF_ACCOUNT_ID", "").strip(),
        "zone": os.environ.get("CF_ZONE_ID", "").strip(),
        "tunnel": os.environ.get("CF_TUNNEL_ID", "").strip(),
    }


def configured():
    c = _cfg()
    return bool(c["token"] and c["account"] and c["zone"] and c["tunnel"])


def _request(method: str, path: str, payload=None):
    c = _cfg()
    if not c["token"]:
        raise RuntimeError("Cloudflare API token yapılandırılmamış")
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {c['token']}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"Cloudflare API {e.code}: {raw[:1000]}")
    if not body.get("success"):
        raise RuntimeError("Cloudflare API hatası: " + json.dumps(body.get("errors", []), ensure_ascii=False))
    return body.get("result")


def tunnel_target():
    c = _cfg()
    return f"{c['tunnel']}.cfargotunnel.com" if c["tunnel"] else ""


def upsert_dns(hostname: str):
    c = _cfg()
    target = tunnel_target()
    params = urllib.parse.urlencode({"type": "CNAME", "name": hostname})
    records = _request("GET", f"/zones/{c['zone']}/dns_records?{params}")
    payload = {"type": "CNAME", "name": hostname, "content": target, "proxied": True, "ttl": 1}
    if records:
        return _request("PUT", f"/zones/{c['zone']}/dns_records/{records[0]['id']}", payload)
    return _request("POST", f"/zones/{c['zone']}/dns_records", payload)


def get_tunnel_config():
    c = _cfg()
    result = _request("GET", f"/accounts/{c['account']}/cfd_tunnel/{c['tunnel']}/configurations")
    return result or {"config": {"ingress": [{"service": "http_status:404"}]}}


def upsert_tunnel_hostname(hostname: str, service: str):
    c = _cfg()
    result = get_tunnel_config()
    config = result.get("config") or {}
    ingress = list(config.get("ingress") or [])
    catch_all = None
    regular = []
    for rule in ingress:
        if not rule.get("hostname"):
            catch_all = rule
        elif rule.get("hostname") != hostname:
            regular.append(rule)
    regular.append({"hostname": hostname, "service": service})
    regular.append(catch_all or {"service": "http_status:404"})
    config["ingress"] = regular
    return _request("PUT", f"/accounts/{c['account']}/cfd_tunnel/{c['tunnel']}/configurations", {"config": config})


def remove_tunnel_hostname(hostname: str):
    c = _cfg()
    result = get_tunnel_config()
    config = result.get("config") or {}
    ingress = [r for r in (config.get("ingress") or []) if r.get("hostname") != hostname]
    if not any(not r.get("hostname") for r in ingress):
        ingress.append({"service": "http_status:404"})
    config["ingress"] = ingress
    return _request("PUT", f"/accounts/{c['account']}/cfd_tunnel/{c['tunnel']}/configurations", {"config": config})


def public_domain_status(hostname: str):
    result = {
        "hostname": hostname,
        "dns_ok": False,
        "addresses": [],
        "https_ok": False,
        "cert_days": None,
        "cert_expires": None,
        "error": "",
    }
    try:
        addrs = sorted({x[4][0] for x in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)})
        result["addresses"] = addrs
        result["dns_ok"] = bool(addrs)
    except Exception as e:
        result["error"] = f"DNS: {e}"
        return result
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
        result["https_ok"] = True
        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            result["cert_expires"] = exp.isoformat()
            result["cert_days"] = max(0, int((exp - datetime.now(timezone.utc)).total_seconds() // 86400))
    except Exception as e:
        result["error"] = (result["error"] + " | " if result["error"] else "") + f"HTTPS: {e}"
    return result
