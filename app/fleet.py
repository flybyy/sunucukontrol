"""SSH fleet: known_hosts verification and fixed, read-only status commands only."""
import ipaddress
import json
import os
import re
import socket
import uuid
from pathlib import Path
from fastapi import HTTPException

DATA = Path(os.environ.get("PANEL_DATA_DIR", "/data"))
STORE = DATA / "fleet.json"
KEY = os.environ.get("PANEL_SSH_KEY", "/run/secrets/fleet_ssh_key")
KNOWN = os.environ.get("PANEL_SSH_KNOWN_HOSTS", "/run/secrets/fleet_known_hosts")

def _load():
    try:
        return json.loads(STORE.read_text())
    except FileNotFoundError:
        return []

def _save(items):
    DATA.mkdir(parents=True, exist_ok=True)
    tmp = STORE.with_suffix('.tmp')
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(STORE)

def _validate_host(hostname):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", hostname):
        raise HTTPException(422, "Geçersiz host adı")
    if hostname.lower() in {"localhost", "localhost.localdomain"}:
        raise HTTPException(422, "Yerel adres yasak")
    try:
        resolved = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError:
        raise HTTPException(422, "Host DNS çözümlemesi başarısız")
    if not resolved:
        raise HTTPException(422, "Host çözümlenemedi")
    # Public internet hosts only by default: limits SSH SSRF to internal services.
    for r in resolved:
        ip = ipaddress.ip_address(r[4][0])
        if not ip.is_global:
            raise HTTPException(422, "Özel/yerel IP'ler varsayılan olarak engelli")

def list_hosts():
    return _load()

def add_host(host):
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", host['username']):
        raise HTTPException(422, "Geçersiz SSH kullanıcı adı")
    _validate_host(host['hostname'])
    items = _load()
    if len(items) >= 30:
        raise HTTPException(409, "En fazla 30 sunucu")
    host['id'] = uuid.uuid4().hex
    items.append(host)
    _save(items)
    return host

def delete_host(host_id):
    items = _load()
    updated = [h for h in items if h['id'] != host_id]
    if len(updated) == len(items):
        raise HTTPException(404, "Sunucu bulunamadı")
    _save(updated)

def get_status(host_id):
    host = next((h for h in _load() if h['id'] == host_id), None)
    if not host:
        raise HTTPException(404, "Sunucu bulunamadı")
    _validate_host(host['hostname'])
    if not Path(KEY).is_file() or not Path(KNOWN).is_file():
        raise HTTPException(503, "SSH anahtarı ve known_hosts dosyaları bağlanmalı")
    import paramiko
    client = paramiko.SSHClient()
    client.load_host_keys(KNOWN)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(host['hostname'], port=host['port'], username=host['username'],
                       key_filename=KEY, look_for_keys=False, allow_agent=False,
                       timeout=5, auth_timeout=5, banner_timeout=5)
        # No arbitrary user input in command.
        command = "uptime; free -m; df -h /"
        _, stdout, stderr = client.exec_command(command, timeout=8)
        out = stdout.read(8192).decode('utf-8', 'replace')
        err = stderr.read(2048).decode('utf-8', 'replace')
        return {"id":host_id, "name":host['name'], "output":out, "stderr":err}
    except (paramiko.SSHException, OSError) as exc:
        raise HTTPException(502, "SSH bağlantısı başarısız: " + type(exc).__name__)
    finally:
        client.close()

def check_totp(code):
    secret = os.environ.get('PANEL_TOTP_SECRET', '').strip()
    if not secret:
        return True
    import pyotp
    return bool(re.fullmatch(r'\d{6}', code or '')) and pyotp.TOTP(secret).verify(code, valid_window=1)
