import os
import socket
import threading
import time
from datetime import datetime
from . import db
from .notify import send_notification
from .system_info import system_status

_stop = threading.Event()
_thread = None
_last_alert = {}
_last_internet = None


def internet_ok():
    for host, port in [("1.1.1.1", 443), ("8.8.8.8", 53)]:
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            continue
    return False


def _threshold(name, default):
    try:
        return float(os.environ.get(name, default))
    except Exception:
        return float(default)


def _maybe_alert(kind: str, level: str, message: str, detail=None):
    cooldown = int(os.environ.get("ALERT_COOLDOWN_MINUTES", "30")) * 60
    now = int(time.time())
    if now - _last_alert.get(kind, 0) < cooldown:
        return
    _last_alert[kind] = now
    db.event(level, kind, message, detail)
    try:
        send_notification("Veribayt ServerHub", message, level)
    except Exception:
        pass


def _record_internet(state: bool):
    global _last_internet
    now = int(time.time())
    if _last_internet is None:
        _last_internet = state
        db.set_kv("internet_state", {"online": state, "since": now})
        return
    if state == _last_internet:
        return
    if not state:
        db.execute("INSERT INTO internet_events(started_at,status,detail) VALUES(?,?,?)", (now, "down", "{}"))
        db.event("critical", "internet_down", "Sunucunun internet bağlantısı kesildi")
        try:
            send_notification("Sunucu internet bağlantısı kesildi", "Veribayt ServerHub internet erişimini kaybetti.", "critical")
        except Exception:
            pass
    else:
        row = db.one("SELECT id,started_at FROM internet_events WHERE ended_at IS NULL ORDER BY id DESC LIMIT 1")
        if row:
            db.execute("UPDATE internet_events SET ended_at=?, status='recovered' WHERE id=?", (now, row["id"]))
            duration = now - row["started_at"]
            db.event("info", "internet_recovered", f"İnternet bağlantısı geri geldi ({duration} sn kesinti)", {"duration": duration})
            try:
                send_notification("İnternet geri geldi", f"Kesinti süresi: {duration} saniye.", "info")
            except Exception:
                pass
    _last_internet = state
    db.set_kv("internet_state", {"online": state, "since": now})


def _sample():
    s = system_status(include_containers=False)
    ts = int(time.time())
    db.execute(
        "INSERT OR REPLACE INTO metrics(ts,cpu,ram,disk,temp,load1,net_sent,net_recv) VALUES(?,?,?,?,?,?,?,?)",
        (ts, s["cpu_percent"], s["memory"]["percent"], s["disk"]["percent"], s["temperature_c"], s["load"][0], s["network"]["sent_bytes"], s["network"]["recv_bytes"]),
    )
    db.execute("DELETE FROM metrics WHERE ts < ?", (ts - 172800,))

    if s["cpu_percent"] >= _threshold("ALERT_CPU_PERCENT", 90):
        _maybe_alert("cpu_high", "warning", f"CPU kullanımı %{s['cpu_percent']:.0f} seviyesine çıktı", {"cpu": s["cpu_percent"]})
    if s["memory"]["percent"] >= _threshold("ALERT_RAM_PERCENT", 90):
        _maybe_alert("ram_high", "warning", f"RAM kullanımı %{s['memory']['percent']:.0f} seviyesine çıktı", {"ram": s["memory"]["percent"]})
    if s["disk"]["percent"] >= _threshold("ALERT_DISK_PERCENT", 85):
        _maybe_alert("disk_high", "critical", f"Disk doluluğu %{s['disk']['percent']:.0f}. Boş alan {s['disk']['free']}", {"disk": s["disk"]["percent"]})
    temp = s.get("temperature_c")
    if temp is not None and temp >= _threshold("ALERT_TEMP_C", 80):
        _maybe_alert("temp_high", "critical", f"Sunucu sıcaklığı {temp:.1f}°C seviyesine çıktı", {"temp": temp})


def _run():
    last_internet_check = 0
    while not _stop.is_set():
        try:
            _sample()
        except Exception as e:
            db.event("warning", "monitor_error", "Metrik toplama hatası", {"error": str(e)[:500]})
        now = time.time()
        if now - last_internet_check >= 20:
            try:
                _record_internet(internet_ok())
            except Exception:
                pass
            last_internet_check = now
        _stop.wait(5)


def start_monitor():
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_run, name="serverhub-monitor", daemon=True)
    _thread.start()


def stop_monitor():
    _stop.set()
    if _thread:
        _thread.join(timeout=3)
