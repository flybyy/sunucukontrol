import asyncio
import json
import os
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from . import db
from . import fleet
from .cloudflare import configured as cf_configured, public_domain_status, upsert_dns, upsert_tunnel_hostname
from .deploy import (
    BACKUPS,
    FILES,
    PROJECTS,
    UPLOADS,
    create_backup,
    deploy,
    list_projects,
    project_detail,
    rollback,
    save_shared_env,
    sha256_file,
    slugify,
    upsert_project,
)
from .maintenance import firewall_status, power as host_power, update_apply, update_check
from . import minecraft
from .monitor import start_monitor, stop_monitor
from .notify import configured_channels, send_notification
from .scheduler import start_scheduler, stop_scheduler
from .security import (
    check_login_rate,
    check_origin,
    clear_login_rate,
    client_ip,
    ensure_csrf,
    enforce_cf_access,
    record_failed_login,
    require_auth,
    verify_password,
)
from .system_info import compose_projects, docker_containers, system_status, ups_status

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("PANEL_DATA_DIR", "/srv/veribayt"))
AUDIT_DIR = Path(os.environ.get("PANEL_AUDIT_DIR", str(DATA_DIR / "audit")))
AUDIT_DIR.mkdir(parents=True, exist_ok=True)
MAX_MB = int(os.environ.get("PANEL_UPLOAD_MAX_MB", "2048"))
USERNAME = os.environ.get("PANEL_USERNAME", "admin")
SESSION_HOURS = int(os.environ.get("PANEL_SESSION_HOURS", "8"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.environ.get("PANEL_ENV", "production") == "production":
        secret = os.environ.get("SESSION_SECRET", "")
        password_hash = os.environ.get("PANEL_PASSWORD_HASH", "")
        if len(secret) < 32 or secret.startswith("REPLACE_") or not password_hash.startswith("$argon2"):
            raise RuntimeError("SESSION_SECRET (32+ karakter) ve PANEL_PASSWORD_HASH (Argon2) ayarlanmalı")
    db.init_db()
    start_monitor()
    start_scheduler()
    db.event("info", "serverhub_start", "SunucuKontrol başlatıldı")
    yield
    stop_scheduler()
    stop_monitor()


app = FastAPI(title="SunucuKontrol", docs_url=None, redoc_url=None, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET", "development-only-change-this-secret"),
    https_only=os.environ.get("PANEL_SECURE_COOKIES", "true").lower() in {"1", "true", "yes"},
    same_site="strict",
    max_age=SESSION_HOURS * 3600,
)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    origin = request.headers.get("origin", "")
    public_api = request.url.path.startswith("/api/public/")
    allowed_origins = {
        "https://veribayt.com",
        "https://www.veribayt.com",
        "http://localhost",
        "http://127.0.0.1",
    }
    allowed_origins.update(x.strip() for x in os.environ.get("PANEL_PUBLIC_ORIGINS", "").split(",") if x.strip())
    if public_api and request.method == "OPTIONS" and origin in allowed_origins:
        response = Response(status_code=204)
    else:
        response = await call_next(request)
    if public_api and origin in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def audit(request: Request, action: str, detail=None):
    row = {"ts": int(time.time()), "ip": client_ip(request), "user": request.session.get("username"), "action": action, "detail": detail or {}}
    with open(AUDIT_DIR / "audit.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def require_confirm(request: Request, expected: str):
    got = request.headers.get("x-confirm-action", "")
    if not secrets.compare_digest(got, expected):
        raise HTTPException(409, f"İşlem onayı gerekli: {expected}")


@app.get("/")
@app.get("/admin")
def index():
    return FileResponse(BASE / "templates" / "index.html")


@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "sunucukontrol", "version": "4.0.0"}


class LoginBody(BaseModel):
    username: str
    password: str
    otp: str = ""


@app.post("/api/login")
def login(body: LoginBody, request: Request):
    check_origin(request)
    enforce_cf_access(request)
    check_login_rate(request)
    if body.username != USERNAME or not verify_password(body.password):
        record_failed_login(request)
        audit(request, "login_failed", {"username": body.username})
        raise HTTPException(401, "Kullanıcı adı veya şifre yanlış")
    if not fleet.check_totp(body.otp):
        record_failed_login(request)
        audit(request, "login_otp_failed")
        raise HTTPException(401, "İki aşamalı doğrulama kodu geçersiz")
    clear_login_rate(request)
    csrf = secrets.token_urlsafe(32)
    request.session.clear()
    request.session.update({"authenticated": True, "username": body.username, "csrf": csrf, "login_at": int(time.time())})
    audit(request, "login_success")
    return {"ok": True, "csrf": csrf, "username": body.username}


@app.post("/api/logout")
def logout(request: Request):
    check_origin(request)
    ensure_csrf(request)
    audit(request, "logout")
    request.session.clear()
    return {"ok": True}


@app.get("/api/me")
def me(request: Request):
    require_auth(request)
    return {"username": request.session.get("username"), "csrf": request.session.get("csrf"), "session_hours": SESSION_HOURS}


@app.get("/api/status")
def status(request: Request):
    require_auth(request)
    s = system_status()
    s["internet"] = db.get_kv("internet_state", {"online": None, "since": None})
    s["notifications"] = configured_channels()
    s["cloudflare_api"] = cf_configured()
    s["cloudflare_access_required"] = os.environ.get("PANEL_REQUIRE_CF_ACCESS", "false").strip().lower() in {"1","true","yes","on"}
    s["ups"] = ups_status()
    try:
        s["firewall"] = firewall_status()
    except Exception as e:
        s["firewall"] = {"available": False, "error": str(e)}
    return s


@app.get("/api/metrics")
def metrics(request: Request, minutes: int = 60):
    require_auth(request)
    minutes = max(5, min(2880, minutes))
    since = int(time.time()) - minutes * 60
    rows = db.query("SELECT ts,cpu,ram,disk,temp,load1,net_sent,net_recv FROM metrics WHERE ts>=? ORDER BY ts", (since,))
    # Downsample to at most ~400 points for the browser.
    if len(rows) > 400:
        step = max(1, len(rows) // 400)
        rows = rows[::step]
    return rows


@app.get("/api/events")
def events(request: Request, limit: int = 100):
    require_auth(request)
    limit = max(1, min(500, limit))
    rows = db.query("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
    for row in rows:
        try:
            row["detail"] = json.loads(row["detail"])
        except Exception:
            pass
    return rows


@app.get("/api/outages")
def outages(request: Request, limit: int = 100):
    require_auth(request)
    return db.query("SELECT * FROM internet_events ORDER BY started_at DESC LIMIT ?", (max(1, min(500, limit)),))


@app.get("/api/audit")
def audit_log(request: Request, limit: int = 100):
    require_auth(request)
    path = AUDIT_DIR / "audit.jsonl"
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-max(1, min(500, limit)):]
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


@app.get("/api/containers")
def containers(request: Request):
    require_auth(request)
    return docker_containers()


@app.get("/api/overview")
def overview(request: Request):
    require_auth(request)
    items = docker_containers()
    if not isinstance(items, list):
        items = []
    return {"containers": {"total": len(items), "running": sum(str(c.get("status", "")).lower().startswith(("up", "running")) for c in items)}, "version": "4.0.0", "docker_enabled": bool(os.environ.get("PANEL_DOCKER_ENABLED", "true").lower() in {"1", "true", "yes"})}


def _known_container(name: str):
    if name not in [c.get("name") for c in docker_containers()]:
        raise HTTPException(404, "Container bulunamadı")
    return name


@app.get("/api/container/{name}/inspect")
def container_inspect(name: str, request: Request):
    require_auth(request)
    _known_container(name)
    try:
        p = subprocess.run(["docker", "inspect", "--format", "{{json .State}}", name], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        raise HTTPException(503, "Docker servisine erişilemiyor")
    if p.returncode:
        raise HTTPException(502, "Container bilgileri alınamadı")
    return json.loads(p.stdout)


@app.post("/api/container/{name}/action/{action}")
def container_action(name: str, action: str, request: Request):
    check_origin(request)
    ensure_csrf(request)
    if action not in {"start", "stop", "restart"}:
        raise HTTPException(400, "Geçersiz işlem")
    _known_container(name)
    require_confirm(request, action.upper())
    try:
        p = subprocess.run(["docker", action, name], capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired):
        raise HTTPException(503, "Docker komutu tamamlanamadı")
    audit(request, "container_" + action, {"name": name, "ok": p.returncode == 0})
    if p.returncode:
        raise HTTPException(502, "Container işlemi başarısız")
    return {"ok": True, "name": name, "action": action}


@app.get("/api/compose-projects")
def docker_compose_projects(request: Request):
    require_auth(request)
    return compose_projects()


@app.post("/api/container/{name}/restart")
def container_restart(name: str, request: Request):
    check_origin(request)
    ensure_csrf(request)
    names = [c["name"] for c in docker_containers()]
    if name not in names:
        raise HTTPException(404, "Container bulunamadı")
    p = subprocess.run(["docker", "restart", name], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
    audit(request, "container_restart", {"name": name, "rc": p.returncode})
    if p.returncode != 0:
        raise HTTPException(500, p.stdout[-3000:])
    return {"ok": True, "output": p.stdout}


@app.get("/api/container/{name}/logs")
def container_logs(name: str, request: Request, lines: int = 300):
    require_auth(request)
    names = [c["name"] for c in docker_containers()]
    if name not in names:
        raise HTTPException(404, "Container bulunamadı")
    lines = max(20, min(2000, lines))
    p = subprocess.run(["docker", "logs", "--tail", str(lines), name], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    return PlainTextResponse(p.stdout[-100000:])


class ProjectBody(BaseModel):
    slug: str
    name: str
    compose_project: str
    domain: str = ""
    health_url: str = ""
    db_engine: str = Field(default="none", pattern="^(none|mysql|mariadb|postgres)$")
    db_service: str = "db"
    app_service: str = "app"
    uploads_path: str = "/var/www/html/uploads"
    auto_backup: bool = True
    backup_hour: int = Field(default=3, ge=0, le=23)
    keep_backups: int = Field(default=7, ge=1, le=60)


@app.get("/api/projects")
def projects(request: Request):
    require_auth(request)
    return list_projects()


@app.get("/api/projects/{slug}")
def project_get(slug: str, request: Request):
    require_auth(request)
    return project_detail(slugify(slug))


@app.post("/api/projects")
def project_save(body: ProjectBody, request: Request):
    check_origin(request)
    ensure_csrf(request)
    result = upsert_project(body.model_dump())
    audit(request, "project_save", {"slug": result["slug"], "compose_project": result["compose_project"]})
    return result


@app.post("/api/projects/{slug}/env")
async def project_env(slug: str, request: Request, file: UploadFile = File(...)):
    check_origin(request)
    ensure_csrf(request)
    data = await file.read(512 * 1024 + 1)
    result = save_shared_env(slugify(slug), data)
    audit(request, "project_env_upload", {"slug": slug, "bytes": result["bytes"]})
    return result


@app.post("/api/projects/{slug}/backup")
def project_backup(slug: str, request: Request):
    check_origin(request)
    ensure_csrf(request)
    result = create_backup(slugify(slug), note="manual")
    audit(request, "backup_manual", {"slug": slug, "bytes": result["bytes"]})
    return result


@app.post("/api/projects/{slug}/rollback/{release_id}")
def project_rollback(slug: str, release_id: int, request: Request):
    check_origin(request)
    ensure_csrf(request)
    require_confirm(request, "ROLLBACK")
    result = rollback(slugify(slug), release_id)
    audit(request, "rollback", {"slug": slug, "release_id": release_id})
    return result


@app.post("/api/upload")
async def upload(request: Request, file: UploadFile = File(...)):
    check_origin(request)
    ensure_csrf(request)
    name = Path(file.filename or "upload.zip").name
    if not name.lower().endswith(".zip"):
        raise HTTPException(400, "Deploy için yalnızca ZIP kabul edilir")
    target = UPLOADS / name
    total = 0
    with open(target, "wb") as f:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_MB * 1024 * 1024:
                f.close()
                target.unlink(missing_ok=True)
                raise HTTPException(413, f"Dosya limiti {MAX_MB} MB")
            f.write(chunk)
    digest = sha256_file(target)
    audit(request, "deploy_zip_upload", {"name": name, "bytes": total, "sha256": digest})
    return {"ok": True, "name": name, "bytes": total, "sha256": digest}


@app.get("/api/uploads")
def uploads(request: Request):
    require_auth(request)
    return [
        {"name": p.name, "bytes": p.stat().st_size, "mtime": int(p.stat().st_mtime), "sha256": sha256_file(p)}
        for p in sorted(UPLOADS.glob("*.zip"), key=lambda x: x.stat().st_mtime, reverse=True)[:100]
    ]


class DeployBody(BaseModel):
    upload_name: str
    project_slug: str
    version_label: str = ""


@app.post("/api/deploy")
def deploy_api(body: DeployBody, request: Request):
    check_origin(request)
    ensure_csrf(request)
    try:
        result = deploy(body.upload_name, body.project_slug, body.version_label)
        audit(request, "deploy", {"project": body.project_slug, "release": result["release"], "sha256": result["sha256"]})
        return result
    except Exception as e:
        audit(request, "deploy_failed", {"project": body.project_slug, "error": str(e)[:1000]})
        raise HTTPException(500, str(e))


@app.get("/api/backups/{backup_id}/download")
def backup_download(backup_id: int, request: Request):
    require_auth(request)
    row = db.one("SELECT * FROM backups WHERE id=? AND status='success'", (backup_id,))
    if not row:
        raise HTTPException(404, "Yedek bulunamadı")
    source = Path(row["path"]).resolve()
    if not source.exists() or not str(source).startswith(str(BACKUPS.resolve())):
        raise HTTPException(404, "Yedek dosyaları bulunamadı")
    bundle = source.parent / f"{source.name}.tar.gz"
    if not bundle.exists():
        with tarfile.open(bundle, "w:gz") as t:
            t.add(source, arcname=source.name)
    audit(request, "backup_download", {"backup_id": backup_id})
    return FileResponse(bundle, filename=f"veribayt-backup-{row['project_slug']}-{source.name}.tar.gz")


@app.get("/api/files")
def vault_files(request: Request):
    require_auth(request)
    out = []
    for p in sorted(FILES.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if p.is_file():
            out.append({"name": p.name, "bytes": p.stat().st_size, "mtime": int(p.stat().st_mtime)})
    return out[:500]


@app.post("/api/files")
async def vault_upload(request: Request, file: UploadFile = File(...)):
    check_origin(request)
    ensure_csrf(request)
    name = Path(file.filename or "file.bin").name
    target = FILES / name
    total = 0
    with open(target, "wb") as f:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_MB * 1024 * 1024:
                target.unlink(missing_ok=True)
                raise HTTPException(413, f"Dosya limiti {MAX_MB} MB")
            f.write(chunk)
    audit(request, "vault_upload", {"name": name, "bytes": total})
    return {"ok": True, "name": name, "bytes": total}


@app.get("/api/files/{name}/download")
def vault_download(name: str, request: Request):
    require_auth(request)
    safe = Path(name).name
    target = (FILES / safe).resolve()
    if not target.exists() or target.parent != FILES.resolve():
        raise HTTPException(404, "Dosya bulunamadı")
    audit(request, "vault_download", {"name": safe})
    return FileResponse(target, filename=safe)


@app.delete("/api/files/{name}")
def vault_delete(name: str, request: Request):
    check_origin(request)
    ensure_csrf(request)
    safe = Path(name).name
    target = (FILES / safe).resolve()
    if not target.exists() or target.parent != FILES.resolve():
        raise HTTPException(404, "Dosya bulunamadı")
    target.unlink()
    audit(request, "vault_delete", {"name": safe})
    return {"ok": True}


@app.get("/api/domain/{hostname}")
def domain_status(hostname: str, request: Request):
    require_auth(request)
    if not re_hostname(hostname):
        raise HTTPException(400, "Geçersiz hostname")
    return public_domain_status(hostname)


def re_hostname(hostname: str):
    import re
    return bool(re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}", hostname))


class CloudflarePublishBody(BaseModel):
    hostname: str
    service: str


@app.post("/api/cloudflare/publish")
def cloudflare_publish(body: CloudflarePublishBody, request: Request):
    check_origin(request)
    ensure_csrf(request)
    require_confirm(request, "PUBLISH")
    if not cf_configured():
        raise HTTPException(400, "Cloudflare API entegrasyonu yapılandırılmamış")
    if not re_hostname(body.hostname):
        raise HTTPException(400, "Geçersiz hostname")
    if not (body.service.startswith("http://localhost:") or body.service.startswith("http://127.0.0.1:")):
        raise HTTPException(400, "Service yalnızca localhost HTTP origin olabilir")
    dns = upsert_dns(body.hostname)
    tunnel = upsert_tunnel_hostname(body.hostname, body.service)
    audit(request, "cloudflare_publish", {"hostname": body.hostname, "service": body.service})
    return {"ok": True, "dns": dns, "tunnel": tunnel}


@app.post("/api/notifications/test")
def notification_test(request: Request):
    check_origin(request)
    ensure_csrf(request)
    result = send_notification("SunucuKontrol test", "Bildirim kanalı başarıyla çalışıyor.", "info")
    audit(request, "notification_test", {"result": result})
    return {"ok": True, "result": result}


@app.get("/api/maintenance/updates")
def maintenance_updates(request: Request):
    require_auth(request)
    try:
        return update_check()
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/maintenance/updates/apply")
def maintenance_updates_apply(request: Request):
    check_origin(request)
    ensure_csrf(request)
    require_confirm(request, "UPDATE")
    if os.environ.get("PANEL_CONTAINER_MODE", "true").lower() == "true":
        raise HTTPException(501, "Host güncellemesi container içinden desteklenmiyor")
    audit(request, "os_update_start")
    try:
        out = update_apply()
        audit(request, "os_update_success")
        return {"ok": True, "output": out[-30000:]}
    except Exception as e:
        audit(request, "os_update_failed", {"error": str(e)[:1000]})
        raise HTTPException(500, str(e))


@app.post("/api/power/{action}")
def power(action: str, request: Request):
    check_origin(request)
    ensure_csrf(request)
    if action not in {"reboot", "poweroff"}:
        raise HTTPException(400, "Geçersiz güç işlemi")
    require_confirm(request, "REBOOT" if action == "reboot" else "POWEROFF")
    if os.environ.get("PANEL_CONTAINER_MODE", "true").lower() == "true":
        raise HTTPException(501, "Host güç yönetimi container içinden desteklenmiyor")
    audit(request, f"power_{action}")
    host_power(action)
    return {"ok": True, "action": action}


class MinecraftServerBody(BaseModel):
    slug: str
    name: str
    server_type: str = Field(default="PAPER", pattern="^(VANILLA|PAPER|PURPUR)$")
    version: str = "LATEST"
    memory_mb: int = Field(default=4096, ge=1024, le=32768)
    max_players: int = Field(default=20, ge=1, le=500)
    port: int = Field(default=25565, ge=1024, le=65535)
    motd: str = Field(default="Veribayt Minecraft Server", max_length=180)
    difficulty: str = Field(default="normal", pattern="^(peaceful|easy|normal|hard)$")
    online_mode: bool = True
    auto_start: bool = True
    published: bool = True
    access_mode: str = "public"
    access_password: str = ""
    public_host: str = ""
    whitelist_enabled: bool = False
    whitelist_players: str = ""
    description: str = ""


class MinecraftCommandBody(BaseModel):
    command: str = Field(min_length=1, max_length=240)


class MinecraftPublicAccessBody(BaseModel):
    password: str = Field(default="", max_length=64)


@app.get("/api/public/minecraft/servers")
def public_minecraft_servers():
    return minecraft.public_servers()


@app.post("/api/public/minecraft/servers/{slug}/access")
def public_minecraft_access(slug: str, body: MinecraftPublicAccessBody):
    try:
        return minecraft.reveal_public_address(slug, body.password)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except (ValueError, RuntimeError) as e:
        raise HTTPException(400, str(e))


@app.get("/api/minecraft/servers")
def minecraft_servers(request: Request):
    require_auth(request)
    return minecraft.list_servers()


@app.post("/api/minecraft/servers")
def minecraft_server_save(body: MinecraftServerBody, request: Request):
    check_origin(request)
    ensure_csrf(request)
    try:
        result = minecraft.save_server(body.model_dump())
        audit(request, "minecraft_save", {"slug": result["slug"], "port": result["port"], "memory_mb": result["memory_mb"]})
        db.event("info", "minecraft_save", f"Minecraft profili kaydedildi: {result['name']}", {"slug": result["slug"]})
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/minecraft/servers/{slug}/action/{action}")
def minecraft_server_action(slug: str, action: str, request: Request):
    check_origin(request)
    ensure_csrf(request)
    if action not in {"start", "stop", "restart"}:
        raise HTTPException(404, "Minecraft işlemi bulunamadı")
    try:
        result = minecraft.action(slug, action)
        audit(request, f"minecraft_{action}", {"slug": slug})
        db.event("info", f"minecraft_{action}", f"Minecraft {action}: {slug}")
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/minecraft/servers/{slug}/logs")
def minecraft_server_logs(slug: str, request: Request, lines: int = 400):
    require_auth(request)
    try:
        return PlainTextResponse(minecraft.logs(slug, lines))
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/minecraft/servers/{slug}/command")
def minecraft_server_command(slug: str, body: MinecraftCommandBody, request: Request):
    check_origin(request)
    ensure_csrf(request)
    try:
        output = minecraft.console(slug, body.command)
        audit(request, "minecraft_command", {"slug": slug, "command": body.command[:80]})
        return {"ok": True, "output": output}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/minecraft/servers/{slug}/backup")
def minecraft_server_backup(slug: str, request: Request):
    check_origin(request)
    ensure_csrf(request)
    try:
        result = minecraft.backup(slug)
        audit(request, "minecraft_backup", {"slug": slug, "bytes": result["bytes"]})
        db.event("info", "minecraft_backup", f"Minecraft yedeği alındı: {slug}", {"bytes": result["bytes"]})
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/minecraft/servers/{slug}/backups")
def minecraft_server_backups(slug: str, request: Request):
    require_auth(request)
    try:
        return minecraft.list_backups(slug)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/minecraft/servers/{slug}/backups/{name}/download")
def minecraft_server_backup_download(slug: str, name: str, request: Request):
    require_auth(request)
    try:
        path = minecraft.backup_path(slug, name)
        audit(request, "minecraft_backup_download", {"slug": slug, "name": path.name})
        return FileResponse(path, filename=path.name)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "Minecraft yedeği bulunamadı")


# v4: kayıtlı SSH anahtarları ile uzak makine izleme; keyfi komut/terminal çalıştırılmaz.
class FleetHostBody(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    hostname: str = Field(min_length=1, max_length=253)
    username: str = Field(min_length=1, max_length=32)
    port: int = Field(default=22, ge=1, le=65535)

@app.get("/api/fleet")
def fleet_list(request: Request):
    require_auth(request)
    return fleet.list_hosts()

@app.post("/api/fleet")
def fleet_add(body: FleetHostBody, request: Request):
    check_origin(request)
    ensure_csrf(request)
    require_confirm(request, "ADD_HOST")
    result = fleet.add_host(body.model_dump())
    audit(request, "fleet_add", {"name": result["name"]})
    return result

@app.delete("/api/fleet/{host_id}")
def fleet_delete(host_id: str, request: Request):
    check_origin(request)
    ensure_csrf(request)
    require_confirm(request, "DELETE_HOST")
    fleet.delete_host(host_id)
    audit(request, "fleet_delete", {"id": host_id})
    return {"ok": True}

@app.get("/api/fleet/{host_id}/status")
def fleet_status(host_id: str, request: Request):
    require_auth(request)
    return fleet.get_status(host_id)

@app.get("/api/catalog")
def app_catalog(request: Request):
    require_auth(request)
    return [{"id":"nginx","name":"Nginx","image":"nginx:stable-alpine","description":"Web sunucusu"},
            {"id":"redis","name":"Redis","image":"redis:7-alpine","description":"Önbellek servisi"},
            {"id":"postgres","name":"PostgreSQL","image":"postgres:17-alpine","description":"Veritabanı; parola ve kalıcı volume gerekir"}]
