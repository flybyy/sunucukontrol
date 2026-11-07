import json
import subprocess

HELPER = "/usr/local/sbin/veribayt-serverhub-helper"


def helper(action: str, timeout=1800):
    p = subprocess.run(["sudo", "-n", HELPER, action], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(p.stdout[-5000:])
    return p.stdout.strip()


def firewall_status():
    raw = helper("firewall-status", timeout=10)
    try:
        return json.loads(raw)
    except Exception:
        return {"available": True, "raw": raw}


def update_check():
    raw = helper("update-check", timeout=300)
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


def update_apply():
    return helper("update-apply", timeout=3600)


def power(action: str):
    if action not in {"reboot", "poweroff"}:
        raise ValueError("Geçersiz güç işlemi")
    subprocess.Popen(["sudo", "-n", HELPER, action], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
