import threading
import time
from .deploy import run_due_backups
from . import db

_stop = threading.Event()
_thread = None


def _loop():
    while not _stop.is_set():
        try:
            run_due_backups()
        except Exception as e:
            db.event("warning", "scheduler_error", "Yedek zamanlayıcı hatası", {"error": str(e)[:500]})
        _stop.wait(60)


def start_scheduler():
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="serverhub-scheduler", daemon=True)
    _thread.start()


def stop_scheduler():
    _stop.set()
    if _thread:
        _thread.join(timeout=3)
