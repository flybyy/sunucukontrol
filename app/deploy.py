import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile
from pathlib import Path
from . import db
from .notify import send_notification

DATA_DIR = Path(os.environ.get("PANEL_DATA_DIR", "/srv/veribayt"))
UPLOADS = DATA_DIR / "uploads"
PROJECTS = DATA_DIR / "projects"
BACKUPS = DATA_DIR / "backups"
FILES = DATA_DIR / "files"
for p in (UPLOADS, PROJECTS, BACKUPS, FILES):
    p.mkdir(parents=True, exist_ok=True)

_locks = {}
_global_lock = threading.Lock()


def _lock_for(slug: str):
    with _global_lock:
        return _locks.setdefault(slug, threading.RLock())


def slugify(v: str) -> str:
    v = re.sub(r"[^a-zA-Z0-9._-]+", "-", (v or "").strip()).strip("-.")
    if not v or len(v) > 64:
        raise ValueError("Geçersiz proje adı")
    return v.lower()


def sha256_file(path: Path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_extract(zip_path: Path, target: Path, max_entries=20000, max_uncompressed_gb=8):
    total = 0
    target_resolved = target.resolve()
    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        if len(infos) > max_entries:
            raise ValueError("ZIP çok fazla dosya içeriyor")
        for m in infos:
            total += m.file_size
            if total > max_uncompressed_gb * 1024**3:
                raise ValueError("ZIP açılmış boyutu güvenlik limitini aşıyor")
            dest = (target / m.filename).resolve()
            if dest != target_resolved and not str(dest).startswith(str(target_resolved) + os.sep):
                raise ValueError("ZIP içinde geçersiz yol bulundu")
            mode = (m.external_attr >> 16) & 0xFFFF
            if mode & 0o120000 == 0o120000:
                raise ValueError("ZIP içinde sembolik link kabul edilmiyor")
        z.extractall(target)


def find_compose(root: Path) -> Path:
    candidates = ["compose.production.yaml", "compose.prod.yaml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"]
    for name in candidates:
        found = sorted(root.rglob(name), key=lambda p: len(p.parts))
        if found:
            return found[0]
    raise FileNotFoundError("Compose dosyası bulunamadı")


def run(cmd, cwd=None, timeout=1200, input_bytes=None):
    p = subprocess.run(
        cmd,
        cwd=cwd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        text=input_bytes is None,
    )
    out = p.stdout
    if isinstance(out, bytes):
        out = out.decode("utf-8", "replace")
    return p.returncode, (out or "")[-50000:]


def upsert_project(payload: dict):
    now = int(time.time())
    slug = slugify(payload["slug"])
    existing = db.one("SELECT slug FROM projects WHERE slug=?", (slug,))
    vals = (
        slug,
        payload.get("name") or slug,
        slugify(payload.get("compose_project") or f"vb-{slug}"),
        (payload.get("domain") or "").strip().lower(),
        (payload.get("health_url") or "").strip(),
        payload.get("db_engine") or "none",
        payload.get("db_service") or "db",
        payload.get("app_service") or "app",
        payload.get("uploads_path") or "/var/www/html/uploads",
        1 if payload.get("auto_backup", True) else 0,
        max(0, min(23, int(payload.get("backup_hour", 3)))),
        max(1, min(60, int(payload.get("keep_backups", 7)))),
        now,
        now,
    )
    if existing:
        db.execute(
            """UPDATE projects SET name=?,compose_project=?,domain=?,health_url=?,db_engine=?,db_service=?,app_service=?,uploads_path=?,auto_backup=?,backup_hour=?,keep_backups=?,updated_at=? WHERE slug=?""",
            (vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7], vals[8], vals[9], vals[10], vals[11], now, slug),
        )
    else:
        db.execute(
            """INSERT INTO projects(slug,name,compose_project,domain,health_url,db_engine,db_service,app_service,uploads_path,auto_backup,backup_hour,keep_backups,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            vals,
        )
    (PROJECTS / slug / "releases").mkdir(parents=True, exist_ok=True)
    (PROJECTS / slug / "shared").mkdir(parents=True, exist_ok=True)
    return project_detail(slug)


def project_detail(slug: str):
    p = db.one("SELECT * FROM projects WHERE slug=?", (slug,))
    if not p:
        raise FileNotFoundError("Proje bulunamadı")
    p["releases"] = db.query("SELECT * FROM releases WHERE project_slug=? ORDER BY created_at DESC LIMIT 20", (slug,))
    p["backups"] = db.query("SELECT * FROM backups WHERE project_slug=? ORDER BY created_at DESC LIMIT 20", (slug,))
    p["deployments"] = db.query("SELECT * FROM deployments WHERE project_slug=? ORDER BY started_at DESC LIMIT 20", (slug,))
    current = PROJECTS / slug / "current"
    p["current"] = str(current.resolve()) if current.is_symlink() else None
    return p


def list_projects():
    out = []
    for p in db.query("SELECT * FROM projects ORDER BY name"):
        current = PROJECTS / p["slug"] / "current"
        p["current"] = str(current.resolve()) if current.is_symlink() else None
        p["last_backup"] = db.one("SELECT created_at,status,bytes FROM backups WHERE project_slug=? ORDER BY created_at DESC LIMIT 1", (p["slug"],))
        p["last_deployment"] = db.one("SELECT started_at,status FROM deployments WHERE project_slug=? ORDER BY started_at DESC LIMIT 1", (p["slug"],))
        out.append(p)
    return out


def save_shared_env(slug: str, content: bytes):
    p = db.one("SELECT slug FROM projects WHERE slug=?", (slug,))
    if not p:
        raise FileNotFoundError("Proje bulunamadı")
    if len(content) > 512 * 1024:
        raise ValueError(".env dosyası çok büyük")
    path = PROJECTS / slug / "shared" / ".env"
    path.write_bytes(content)
    os.chmod(path, 0o600)
    return {"ok": True, "bytes": len(content)}


def _current_release(slug: str):
    current = PROJECTS / slug / "current"
    if current.is_symlink():
        try:
            p = current.resolve()
            if p.exists():
                return p
        except Exception:
            pass
    return None


def _compose_for_release(release: Path):
    compose = find_compose(release)
    return compose, compose.parent


def _http_health(url: str, timeout=8):
    if not url:
        return True, "Health URL tanımlı değil"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Veribayt-ServerHub/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code = r.status
        return 200 <= code < 400, f"HTTP {code}"
    except Exception as e:
        return False, str(e)


def _wait_health(url: str, seconds=60):
    if not url:
        return True, "Health URL tanımlı değil"
    deadline = time.time() + seconds
    last = ""
    while time.time() < deadline:
        ok, last = _http_health(url)
        if ok:
            return True, last
        time.sleep(3)
    return False, last


def deploy(upload_name: str, project_slug: str, version_label=""):
    slug = slugify(project_slug)
    project = db.one("SELECT * FROM projects WHERE slug=?", (slug,))
    if not project:
        raise FileNotFoundError("Önce projeyi panelden kaydet")
    upload = (UPLOADS / Path(upload_name).name).resolve()
    if not upload.exists() or upload.suffix.lower() != ".zip":
        raise FileNotFoundError("Yüklenen ZIP bulunamadı")
    with _lock_for(slug):
        base = PROJECTS / slug
        releases = base / "releases"
        shared = base / "shared"
        release = releases / (time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time()*1000)%1000:03d}")
        release.mkdir(parents=True, exist_ok=False)
        digest = sha256_file(upload)
        dep_id = db.execute("INSERT INTO deployments(project_slug,started_at,status) VALUES(?,?,?)", (slug, int(time.time()), "running"))
        rel_id = None
        prev = _current_release(slug)
        output_parts = []
        try:
            safe_extract(upload, release)
            compose, app_dir = _compose_for_release(release)
            shared_env = shared / ".env"
            app_env = app_dir / ".env"
            if shared_env.exists():
                shutil.copy2(shared_env, app_env)
            elif app_env.exists():
                shutil.copy2(app_env, shared_env)
                os.chmod(shared_env, 0o600)
            project_name = project["compose_project"]
            code, out = run(["docker", "compose", "-p", project_name, "-f", str(compose), "config"], cwd=app_dir)
            output_parts.append("$ docker compose config\n" + out)
            if code != 0:
                raise RuntimeError("Compose doğrulaması başarısız")

            # Automatic pre-deploy backup when a live release exists.
            if prev and project.get("auto_backup"):
                try:
                    b = create_backup(slug, note="pre-deploy")
                    output_parts.append(f"Pre-deploy backup: {b['path']}")
                except Exception as e:
                    output_parts.append(f"UYARI: pre-deploy backup alınamadı: {e}")
                    raise RuntimeError("Güncelleme öncesi yedek alınamadığı için deploy durduruldu")

            rel_id = db.execute(
                "INSERT INTO releases(project_slug,release_path,version_label,sha256,status,created_at) VALUES(?,?,?,?,?,?)",
                (slug, str(release), version_label or upload.stem, digest, "building", int(time.time())),
            )
            code, out = run(["docker", "compose", "-p", project_name, "-f", str(compose), "up", "-d", "--build", "--remove-orphans"], cwd=app_dir)
            output_parts.append("$ docker compose up -d --build\n" + out)
            if code != 0:
                raise RuntimeError("Docker deploy başarısız")

            ok, health = _wait_health(project.get("health_url") or "", 60)
            output_parts.append("Health: " + health)
            if not ok:
                raise RuntimeError("Yeni sürüm health-check başarısız: " + health)

            tmp_link = base / ".current-new"
            if tmp_link.exists() or tmp_link.is_symlink():
                tmp_link.unlink()
            tmp_link.symlink_to(release)
            tmp_link.replace(base / "current")
            db.execute("UPDATE releases SET status='active',deployed_at=? WHERE id=?", (int(time.time()), rel_id))
            if prev:
                db.execute("UPDATE releases SET status='previous' WHERE project_slug=? AND release_path=?", (slug, str(prev)))
            db.execute("UPDATE deployments SET ended_at=?,status='success',output=? WHERE id=?", (int(time.time()), "\n\n".join(output_parts)[-50000:], dep_id))
            db.event("info", "deploy_success", f"{project['name']} başarıyla yayınlandı", {"project": slug, "version": version_label or upload.stem})
            try:
                send_notification("Deploy başarılı", f"{project['name']} → {version_label or upload.stem}", "info")
            except Exception:
                pass
            return {"project": slug, "release_id": rel_id, "release": str(release), "sha256": digest, "output": "\n\n".join(output_parts)}
        except Exception as e:
            output_parts.append("HATA: " + str(e))
            if rel_id:
                db.execute("UPDATE releases SET status='failed' WHERE id=?", (rel_id,))
            rollback_msg = ""
            if prev and prev.exists():
                try:
                    prev_compose, prev_dir = _compose_for_release(prev)
                    code, out = run(["docker", "compose", "-p", project["compose_project"], "-f", str(prev_compose), "up", "-d", "--build", "--remove-orphans"], cwd=prev_dir)
                    rollback_msg = "\nRollback:\n" + out
                    if code == 0:
                        db.event("warning", "deploy_rollback", f"{project['name']} eski sürüme geri alındı")
                except Exception as rexc:
                    rollback_msg = "\nRollback hatası: " + str(rexc)
            final_out = ("\n\n".join(output_parts) + rollback_msg)[-50000:]
            db.execute("UPDATE deployments SET ended_at=?,status='failed',output=? WHERE id=?", (int(time.time()), final_out, dep_id))
            db.event("critical", "deploy_failed", f"{project['name']} deploy başarısız", {"error": str(e)[:1000]})
            try:
                send_notification("Deploy başarısız", f"{project['name']}: {e}", "critical")
            except Exception:
                pass
            raise RuntimeError(str(e) + rollback_msg)


def rollback(slug: str, release_id: int):
    slug = slugify(slug)
    project = db.one("SELECT * FROM projects WHERE slug=?", (slug,))
    release = db.one("SELECT * FROM releases WHERE id=? AND project_slug=?", (release_id, slug))
    if not project or not release:
        raise FileNotFoundError("Proje veya release bulunamadı")
    path = Path(release["release_path"])
    if not path.exists():
        raise FileNotFoundError("Release klasörü bulunamadı")
    with _lock_for(slug):
        create_backup(slug, note="pre-rollback")
        compose, app_dir = _compose_for_release(path)
        code, out = run(["docker", "compose", "-p", project["compose_project"], "-f", str(compose), "up", "-d", "--build", "--remove-orphans"], cwd=app_dir)
        if code != 0:
            raise RuntimeError(out)
        ok, health = _wait_health(project.get("health_url") or "", 60)
        if not ok:
            raise RuntimeError("Rollback health-check başarısız: " + health)
        base = PROJECTS / slug
        tmp = base / ".current-new"
        if tmp.exists() or tmp.is_symlink():
            tmp.unlink()
        tmp.symlink_to(path)
        tmp.replace(base / "current")
        db.execute("UPDATE releases SET status='previous' WHERE project_slug=? AND status='active'", (slug,))
        db.execute("UPDATE releases SET status='active',deployed_at=? WHERE id=?", (int(time.time()), release_id))
        db.event("warning", "manual_rollback", f"{project['name']} release #{release_id} sürümüne geri alındı")
        return {"ok": True, "output": out, "health": health}


def _compose_context_for_project(project):
    current = _current_release(project["slug"])
    if not current:
        raise RuntimeError("Panel tarafından yönetilen aktif release yok")
    compose, app_dir = _compose_for_release(current)
    return compose, app_dir


def _container_env(compose: Path, app_dir: Path, project_name: str, service: str):
    code, cid = run(["docker", "compose", "-p", project_name, "-f", str(compose), "ps", "-q", service], cwd=app_dir, timeout=20)
    cid = cid.strip()
    if code != 0 or not cid:
        return {}
    code, raw = run(["docker", "inspect", cid, "--format", "{{json .Config.Env}}"], timeout=10)
    if code != 0:
        return {}
    try:
        arr = json.loads(raw)
        return dict(x.split("=", 1) for x in arr if "=" in x)
    except Exception:
        return {}


def create_backup(slug: str, note="manual"):
    slug = slugify(slug)
    project = db.one("SELECT * FROM projects WHERE slug=?", (slug,))
    if not project:
        raise FileNotFoundError("Proje bulunamadı")
    with _lock_for(slug):
        compose, app_dir = _compose_context_for_project(project)
        stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time()*1000)%1000:03d}"
        dest = BACKUPS / slug / stamp
        dest.mkdir(parents=True, exist_ok=False)
        meta = {"project": slug, "created_at": int(time.time()), "db_engine": project["db_engine"], "note": note}
        try:
            engine = project["db_engine"]
            if engine in {"mysql", "mariadb"}:
                env = _container_env(compose, app_dir, project["compose_project"], project["db_service"])
                dbname = env.get("MYSQL_DATABASE")
                rootpw = env.get("MYSQL_ROOT_PASSWORD")
                user = "root" if rootpw else env.get("MYSQL_USER")
                pw = rootpw or env.get("MYSQL_PASSWORD")
                if not dbname or not user or not pw:
                    raise RuntimeError("MySQL backup için gerekli container env değerleri bulunamadı")
                shell = f'exec mysqldump -u{shlex_quote(user)} -p"$VB_PW" --single-transaction --routines --triggers {shlex_quote(dbname)}'
                p = subprocess.Popen(
                    ["docker", "compose", "-p", project["compose_project"], "-f", str(compose), "exec", "-T", "-e", f"VB_PW={pw}", project["db_service"], "sh", "-c", shell],
                    cwd=app_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                sql, err = p.communicate(timeout=600)
                if p.returncode != 0:
                    raise RuntimeError(err.decode("utf-8", "replace")[-2000:])
                with gzip.open(dest / "database.sql.gz", "wb") as gz:
                    gz.write(sql)
                meta["database"] = "database.sql.gz"
            elif engine == "postgres":
                env = _container_env(compose, app_dir, project["compose_project"], project["db_service"])
                user = env.get("POSTGRES_USER", "postgres")
                dbname = env.get("POSTGRES_DB", user)
                code, out = run(["docker", "compose", "-p", project["compose_project"], "-f", str(compose), "exec", "-T", project["db_service"], "pg_dump", "-U", user, dbname], cwd=app_dir, timeout=600)
                if code != 0:
                    raise RuntimeError(out)
                with gzip.open(dest / "database.sql.gz", "wb") as gz:
                    gz.write(out.encode("utf-8"))
                meta["database"] = "database.sql.gz"

            uploads = (project.get("uploads_path") or "").rstrip("/")
            if uploads:
                parent, name = os.path.split(uploads)
                cmd = ["docker", "compose", "-p", project["compose_project"], "-f", str(compose), "exec", "-T", project["app_service"], "tar", "-C", parent or "/", "-czf", "-", name]
                p = subprocess.Popen(cmd, cwd=app_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                blob, err = p.communicate(timeout=600)
                if p.returncode == 0:
                    (dest / "uploads.tar.gz").write_bytes(blob)
                    meta["uploads"] = "uploads.tar.gz"
                else:
                    meta["uploads_warning"] = err.decode("utf-8", "replace")[-1000:]

            # Optional second-copy targets. Local backup remains authoritative even if a remote copy fails.
            offsite_dir = os.environ.get("BACKUP_OFFSITE_DIR", "").strip()
            if offsite_dir:
                try:
                    target = Path(offsite_dir).expanduser().resolve() / slug / stamp
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(dest, target, dirs_exist_ok=True)
                    meta["offsite_dir"] = str(target)
                except Exception as e:
                    meta["offsite_warning"] = str(e)[:1000]
            rclone_remote = os.environ.get("BACKUP_RCLONE_REMOTE", "").strip().rstrip("/")
            if rclone_remote and shutil.which("rclone"):
                try:
                    cmd = ["rclone", "copy", str(dest), f"{rclone_remote}/{slug}/{stamp}", "--checksum"]
                    rclone_cfg = os.environ.get("RCLONE_CONFIG", "").strip()
                    if rclone_cfg:
                        cmd.extend(["--config", rclone_cfg])
                    code, rout = run(cmd, timeout=1800)
                    if code == 0:
                        meta["rclone"] = f"{rclone_remote}/{slug}/{stamp}"
                    else:
                        meta["rclone_warning"] = rout[-1000:]
                except Exception as e:
                    meta["rclone_warning"] = str(e)[:1000]
            elif rclone_remote:
                meta["rclone_warning"] = "rclone binary bulunamadı"

            (dest / "metadata.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            total = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file())
            bid = db.execute("INSERT INTO backups(project_slug,created_at,path,bytes,status,kind,note) VALUES(?,?,?,?,?,?,?)", (slug, int(time.time()), str(dest), total, "success", "full", note))
            prune_backups(slug, project["keep_backups"])
            db.event("info", "backup_success", f"{project['name']} yedeği alındı", {"bytes": total})
            return {"id": bid, "path": str(dest), "bytes": total, "meta": meta}
        except Exception as e:
            db.execute("INSERT INTO backups(project_slug,created_at,path,bytes,status,kind,note) VALUES(?,?,?,?,?,?,?)", (slug, int(time.time()), str(dest), 0, "failed", "full", str(e)[:500]))
            db.event("critical", "backup_failed", f"{project['name']} yedeği alınamadı", {"error": str(e)[:1000]})
            raise


def shlex_quote(s: str):
    import shlex
    return shlex.quote(s)


def prune_backups(slug: str, keep: int):
    rows = db.query("SELECT * FROM backups WHERE project_slug=? AND status='success' ORDER BY created_at DESC", (slug,))
    for row in rows[int(keep):]:
        path = Path(row["path"])
        if path.exists() and str(path).startswith(str((BACKUPS / slug).resolve())):
            shutil.rmtree(path, ignore_errors=True)
        bundle = path.parent / f"{path.name}.tar.gz"
        if bundle.exists():
            bundle.unlink(missing_ok=True)
        db.execute("DELETE FROM backups WHERE id=?", (row["id"],))


def run_due_backups():
    now = time.localtime()
    today = time.strftime("%Y-%m-%d")
    for p in db.query("SELECT * FROM projects WHERE auto_backup=1"):
        if now.tm_hour != int(p["backup_hour"]):
            continue
        key = f"backup_last_day:{p['slug']}"
        if db.get_kv(key) == today:
            continue
        try:
            create_backup(p["slug"], note="scheduled")
            db.set_kv(key, today)
        except Exception:
            db.set_kv(key, today)
