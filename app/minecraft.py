import base64
import hashlib
import json
import os
import re
import secrets
import shlex
import subprocess
import tarfile
import time
from pathlib import Path

from . import db

DATA_DIR = Path(os.environ.get("PANEL_DATA_DIR", "/srv/veribayt"))
ROOT = DATA_DIR / "minecraft"
BACKUP_ROOT = DATA_DIR / "minecraft-backups"
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,31}$")
ALLOWED_TYPES = {"VANILLA", "PAPER", "PURPUR"}
ALLOWED_DIFFICULTIES = {"peaceful", "easy", "normal", "hard"}
ALLOWED_ACCESS_MODES = {"public", "password"}
PLAYER_RE = re.compile(r"^[A-Za-z0-9_]{3,16}$")
PUBLIC_HOST_DEFAULT = os.environ.get("MINECRAFT_PUBLIC_HOST", "mc.veribayt.com").strip()



def _hash_password(password: str) -> str:
    password = (password or "").strip()
    if len(password) < 4 or len(password) > 64:
        raise ValueError("Paylaşım şifresi 4-64 karakter olmalı")
    iterations = 220_000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (
        iterations,
        base64.urlsafe_b64encode(salt).decode().rstrip("="),
        base64.urlsafe_b64encode(digest).decode().rstrip("="),
    )


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_b64, digest_b64 = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        pad = lambda v: v + "=" * (-len(v) % 4)
        salt = base64.urlsafe_b64decode(pad(salt_b64))
        expected = base64.urlsafe_b64decode(pad(digest_b64))
        got = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, int(rounds))
        return secrets.compare_digest(got, expected)
    except Exception:
        return False


def _clean_players(value) -> str:
    if isinstance(value, list):
        parts = value
    else:
        parts = re.split(r"[,\n\r ]+", str(value or ""))
    out = []
    seen = set()
    for raw in parts:
        name = str(raw).strip()
        if not name:
            continue
        if not PLAYER_RE.fullmatch(name):
            raise ValueError(f"Geçersiz Minecraft kullanıcı adı: {name}")
        low = name.lower()
        if low not in seen:
            out.append(name)
            seen.add(low)
    return ",".join(out)


def _public_address(row: dict) -> str:
    host = (row.get("public_host") or PUBLIC_HOST_DEFAULT or "").strip()
    if not host:
        return ""
    port = int(row.get("port", 25565))
    return host if port == 25565 else f"{host}:{port}"


def _admin_safe(row: dict) -> dict:
    row = dict(row)
    row["published"] = bool(row.get("published", 1))
    row["online_mode"] = bool(row.get("online_mode", 1))
    row["auto_start"] = bool(row.get("auto_start", 1))
    row["whitelist_enabled"] = bool(row.get("whitelist_enabled", 0))
    row["has_access_password"] = bool(row.get("access_password_hash"))
    row["public_address"] = _public_address(row)
    row.pop("access_password_hash", None)
    return row


def _ensure_dirs():
    ROOT.mkdir(parents=True, exist_ok=True)
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)


def normalize_slug(value: str) -> str:
    slug = (value or "").strip().lower()
    if not SLUG_RE.fullmatch(slug):
        raise ValueError("Sunucu kısa adı 2-32 karakter; yalnızca a-z, 0-9 ve - kullanabilir")
    return slug


def container_name(slug: str) -> str:
    return f"vb-mc-{normalize_slug(slug)}"


def server_dir(slug: str) -> Path:
    return ROOT / normalize_slug(slug)


def _compose_cmd(slug: str, *args: str):
    path = server_dir(slug) / "compose.yml"
    if not path.exists():
        raise RuntimeError("Minecraft compose dosyası bulunamadı")
    return ["docker", "compose", "-f", str(path), "-p", f"vb-mc-{slug}", *args]


def _run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError("Docker komutu bulunamadı")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Docker işlemi zaman aşımına uğradı")
    if p.returncode != 0:
        raise RuntimeError((p.stdout or "Docker işlemi başarısız")[-5000:])
    return p.stdout or ""


def _yaml_quote(value) -> str:
    # JSON quoting is valid YAML and keeps MOTD/version text from becoming YAML syntax.
    return json.dumps(str(value), ensure_ascii=False)


def _write_compose(row: dict):
    d = server_dir(row["slug"])
    (d / "data").mkdir(parents=True, exist_ok=True)
    secret_path = d / ".rcon-secret"
    if secret_path.exists():
        rcon_password = secret_path.read_text(encoding="utf-8").strip()
    else:
        rcon_password = secrets.token_urlsafe(24)
        secret_path.write_text(rcon_password, encoding="utf-8")
        try:
            secret_path.chmod(0o600)
        except OSError:
            pass

    restart_policy = "unless-stopped" if row.get("auto_start") else "no"
    env = {
        "EULA": "TRUE",
        "TYPE": row["server_type"],
        "VERSION": row["version"],
        "MEMORY": f'{row["memory_mb"]}M',
        "MAX_PLAYERS": row["max_players"],
        "MOTD": row["motd"],
        "DIFFICULTY": row["difficulty"],
        "ONLINE_MODE": "TRUE" if row["online_mode"] else "FALSE",
        "ENABLE_WHITELIST": "TRUE" if row.get("whitelist_enabled") else "FALSE",
        "ENFORCE_WHITELIST": "TRUE" if row.get("whitelist_enabled") else "FALSE",
        "WHITELIST": row.get("whitelist_players", ""),
        "ENABLE_RCON": "true",
        "RCON_PASSWORD": rcon_password,
        "USE_AIKAR_FLAGS": "true",
        "TZ": "Europe/Istanbul",
    }
    lines = [
        "services:",
        "  minecraft:",
        "    image: itzg/minecraft-server:latest",
        f"    container_name: {container_name(row['slug'])}",
        f"    restart: {_yaml_quote(restart_policy)}",
        "    tty: true",
        "    stdin_open: true",
        "    ports:",
        f'      - {_yaml_quote(str(row["port"]) + ":25565")}',
        "    environment:",
    ]
    for key, value in env.items():
        lines.append(f"      {key}: {_yaml_quote(value)}")
    lines.extend([
        "    volumes:",
        '      - "./data:/data"',
        "    stop_grace_period: 60s",
        "",
    ])
    (d / "compose.yml").write_text("\n".join(lines), encoding="utf-8")


def runtime(slug: str) -> dict:
    name = container_name(slug)
    try:
        p = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}|{{.State.StartedAt}}", name],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8,
        )
        if p.returncode != 0:
            return {"state": "not-created", "players": None, "cpu": None, "memory": None}
        state, _, started = p.stdout.strip().partition("|")
        out = {"state": state or "unknown", "started_at": started or None, "players": None, "cpu": None, "memory": None}
        if state == "running":
            try:
                stats = subprocess.run(
                    ["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}", name],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8,
                )
                if stats.returncode == 0:
                    cpu, _, memory = stats.stdout.strip().partition("|")
                    out["cpu"], out["memory"] = cpu or None, memory or None
            except Exception:
                pass
            try:
                r = subprocess.run(
                    ["docker", "exec", name, "rcon-cli", "list"],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=6,
                )
                if r.returncode == 0:
                    m = re.search(r"There are\s+(\d+)\s+of a max of\s+(\d+)", r.stdout)
                    if m:
                        out["players"] = {"online": int(m.group(1)), "max": int(m.group(2))}
            except Exception:
                pass
        return out
    except Exception as e:
        return {"state": "unknown", "error": str(e)[:300], "players": None, "cpu": None, "memory": None}


def list_servers() -> list[dict]:
    rows = db.query("SELECT * FROM minecraft_servers ORDER BY created_at DESC")
    out = []
    for row in rows:
        safe = _admin_safe(row)
        safe["runtime"] = runtime(row["slug"])
        out.append(safe)
    return out


def get_server(slug: str) -> dict | None:
    slug = normalize_slug(slug)
    row = db.one("SELECT * FROM minecraft_servers WHERE slug=?", (slug,))
    if not row:
        return None
    safe = _admin_safe(row)
    safe["runtime"] = runtime(slug)
    return safe


def save_server(data: dict) -> dict:
    _ensure_dirs()
    slug = normalize_slug(data["slug"])
    server_type = str(data.get("server_type", "PAPER")).upper()
    if server_type not in ALLOWED_TYPES:
        raise ValueError("Desteklenmeyen Minecraft sunucu türü")
    difficulty = str(data.get("difficulty", "normal")).lower()
    if difficulty not in ALLOWED_DIFFICULTIES:
        raise ValueError("Geçersiz zorluk seviyesi")
    access_mode = str(data.get("access_mode", "public")).lower()
    if access_mode not in ALLOWED_ACCESS_MODES:
        raise ValueError("Erişim türü herkese açık veya şifreli olmalı")
    port = int(data.get("port", 25565))
    if not 1024 <= port <= 65535:
        raise ValueError("Port 1024-65535 aralığında olmalı")
    memory_mb = int(data.get("memory_mb", 4096))
    if not 1024 <= memory_mb <= 32768:
        raise ValueError("RAM 1024-32768 MB aralığında olmalı")
    max_players = int(data.get("max_players", 20))
    if not 1 <= max_players <= 500:
        raise ValueError("Oyuncu limiti 1-500 aralığında olmalı")
    version = str(data.get("version", "LATEST")).strip()[:40] or "LATEST"
    motd = str(data.get("motd", "Veribayt Minecraft Server")).replace("\n", " ").replace("\r", " ")[:180]
    name = str(data.get("name", slug)).strip()[:80] or slug
    description = str(data.get("description", "")).replace("\r", " ").replace("\n", " ").strip()[:220]
    public_host = str(data.get("public_host", "")).strip()[:180]
    whitelist_players = _clean_players(data.get("whitelist_players", ""))
    whitelist_enabled = bool(data.get("whitelist_enabled", False))
    published = bool(data.get("published", True))
    now = int(time.time())

    clash = db.one("SELECT slug FROM minecraft_servers WHERE port=? AND slug<>?", (port, slug))
    if clash:
        raise ValueError(f"Port {port} başka bir Minecraft sunucusunda kullanılıyor")

    existing = db.one("SELECT * FROM minecraft_servers WHERE slug=?", (slug,))
    password_hash = (existing or {}).get("access_password_hash", "")
    incoming_password = str(data.get("access_password", "") or "").strip()
    if access_mode == "password":
        if incoming_password:
            password_hash = _hash_password(incoming_password)
        elif not password_hash:
            raise ValueError("Şifreli paylaşım için bir erişim şifresi belirle")

    db.execute(
        """
        INSERT INTO minecraft_servers(
          slug,name,server_type,version,memory_mb,max_players,port,motd,difficulty,online_mode,auto_start,
          published,access_mode,access_password_hash,public_host,whitelist_enabled,whitelist_players,description,created_at,updated_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(slug) DO UPDATE SET
          name=excluded.name,server_type=excluded.server_type,version=excluded.version,
          memory_mb=excluded.memory_mb,max_players=excluded.max_players,port=excluded.port,
          motd=excluded.motd,difficulty=excluded.difficulty,online_mode=excluded.online_mode,
          auto_start=excluded.auto_start,published=excluded.published,access_mode=excluded.access_mode,
          access_password_hash=excluded.access_password_hash,public_host=excluded.public_host,
          whitelist_enabled=excluded.whitelist_enabled,whitelist_players=excluded.whitelist_players,
          description=excluded.description,updated_at=excluded.updated_at
        """,
        (slug, name, server_type, version, memory_mb, max_players, port, motd, difficulty,
         1 if data.get("online_mode", True) else 0, 1 if data.get("auto_start", True) else 0,
         1 if published else 0, access_mode, password_hash, public_host,
         1 if whitelist_enabled else 0, whitelist_players, description,
         int((existing or {}).get("created_at", now)), now),
    )
    row = db.one("SELECT * FROM minecraft_servers WHERE slug=?", (slug,))
    _write_compose(row)
    return get_server(slug)


def public_servers() -> list[dict]:
    rows = db.query("SELECT * FROM minecraft_servers WHERE published=1 ORDER BY created_at DESC")
    out = []
    for row in rows:
        rt = runtime(row["slug"])
        item = {
            "slug": row["slug"],
            "name": row["name"],
            "server_type": row["server_type"],
            "version": row["version"],
            "max_players": row["max_players"],
            "motd": row["motd"],
            "description": row.get("description", ""),
            "difficulty": row["difficulty"],
            "access_mode": row.get("access_mode", "public"),
            "requires_password": row.get("access_mode") == "password",
            "whitelist_enabled": bool(row.get("whitelist_enabled", 0)),
            "runtime": {
                "state": rt.get("state"),
                "players": rt.get("players"),
            },
        }
        if row.get("access_mode") == "public":
            item["address"] = _public_address(row)
        out.append(item)
    return out


def reveal_public_address(slug: str, password: str) -> dict:
    slug = normalize_slug(slug)
    row = db.one("SELECT * FROM minecraft_servers WHERE slug=? AND published=1", (slug,))
    if not row:
        raise ValueError("Sunucu bulunamadı veya sitede yayınlanmıyor")
    if row.get("access_mode") == "password":
        if not _verify_password(password, row.get("access_password_hash", "")):
            raise PermissionError("Erişim şifresi yanlış")
    address = _public_address(row)
    if not address:
        raise ValueError("Sunucu için public hostname/IP tanımlanmamış")
    return {"slug": slug, "name": row["name"], "address": address, "whitelist_enabled": bool(row.get("whitelist_enabled", 0))}


def action(slug: str, verb: str) -> dict:
    slug = normalize_slug(slug)
    if not db.one("SELECT slug FROM minecraft_servers WHERE slug=?", (slug,)):
        raise ValueError("Minecraft sunucusu bulunamadı")
    if verb == "start":
        output = _run(_compose_cmd(slug, "up", "-d"), timeout=180)
    elif verb == "stop":
        output = _run(_compose_cmd(slug, "stop"), timeout=120)
    elif verb == "restart":
        output = _run(_compose_cmd(slug, "restart"), timeout=120)
    else:
        raise ValueError("Geçersiz Minecraft işlemi")
    return {"ok": True, "output": output[-5000:], "runtime": runtime(slug)}


def logs(slug: str, lines: int = 300) -> str:
    slug = normalize_slug(slug)
    name = container_name(slug)
    lines = max(20, min(int(lines), 2000))
    try:
        p = subprocess.run(["docker", "logs", "--tail", str(lines), name], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        if p.returncode != 0:
            return p.stdout or "Container henüz oluşturulmadı."
        return (p.stdout or "")[-120000:]
    except Exception as e:
        return str(e)


def console(slug: str, command: str) -> str:
    slug = normalize_slug(slug)
    command = (command or "").strip()
    if not command or len(command) > 240 or "\n" in command or "\r" in command:
        raise ValueError("Komut tek satır ve en fazla 240 karakter olmalı")
    if runtime(slug).get("state") != "running":
        raise ValueError("Minecraft sunucusu çalışmıyor")
    # The command is passed as one argv item to Minecraft RCON; no host shell is involved.
    try:
        argv = shlex.split(command)
    except ValueError as e:
        raise ValueError("Komut biçimi geçersiz") from e
    return _run(["docker", "exec", container_name(slug), "rcon-cli", *argv], timeout=15)[-5000:]


def backup(slug: str) -> dict:
    slug = normalize_slug(slug)
    row = db.one("SELECT * FROM minecraft_servers WHERE slug=?", (slug,))
    if not row:
        raise ValueError("Minecraft sunucusu bulunamadı")
    _ensure_dirs()
    data = server_dir(slug) / "data"
    data.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target_dir = BACKUP_ROOT / slug
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{slug}-{stamp}.tar.gz"
    with tarfile.open(target, "w:gz") as t:
        t.add(data, arcname="data")
    return {"ok": True, "path": str(target), "bytes": target.stat().st_size, "created_at": int(time.time())}


def list_backups(slug: str) -> list[dict]:
    slug = normalize_slug(slug)
    root = BACKUP_ROOT / slug
    if not root.exists():
        return []
    out = []
    for p in sorted(root.glob("*.tar.gz"), key=lambda x: x.stat().st_mtime, reverse=True)[:50]:
        out.append({"name": p.name, "bytes": p.stat().st_size, "mtime": int(p.stat().st_mtime)})
    return out


def backup_path(slug: str, name: str) -> Path:
    slug = normalize_slug(slug)
    safe_name = Path(name).name
    root = (BACKUP_ROOT / slug).resolve()
    path = (root / safe_name).resolve()
    if not str(path).startswith(str(root)) or not path.exists() or path.suffix != ".gz":
        raise FileNotFoundError(name)
    return path
