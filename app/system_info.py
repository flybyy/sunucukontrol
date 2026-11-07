import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
import psutil


def human(n):
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    n = float(n or 0)
    for u in units:
        if n < 1024 or u == units[-1]:
            return f"{n:.1f} {u}"
        n /= 1024


def temperature_c():
    values = []
    try:
        temps = psutil.sensors_temperatures(fahrenheit=False)
        for entries in temps.values():
            for e in entries:
                if e.current and 0 < e.current < 130:
                    values.append(float(e.current))
    except Exception:
        pass
    if not values:
        for p in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
            try:
                v = float(p.read_text().strip()) / 1000
                if 0 < v < 130:
                    values.append(v)
            except Exception:
                pass
    return round(max(values), 1) if values else None


def _run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except Exception as e:
        return 1, str(e)


def docker_containers():
    cmd = ["docker", "ps", "-a", "--format", "{{json .}}"]
    code, out = _run(cmd)
    if code != 0:
        return [{"name": "Docker erişilemedi", "image": "", "status": out, "state": "error", "ports": "", "compose_project": ""}]
    stats = {}
    try:
        scode, sout = _run(["docker", "stats", "--no-stream", "--format", "{{json .}}"], timeout=12)
        if scode == 0:
            for sline in sout.splitlines():
                try:
                    sr = json.loads(sline)
                    stats[sr.get("Name", "")] = sr
                except Exception:
                    pass
    except Exception:
        pass
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        name = r.get("Names") or ""
        compose_project = ""
        health = ""
        try:
            inspect = subprocess.check_output(
                ["docker", "inspect", name, "--format", '{{json .Config.Labels}}|{{json .State.Health}}'],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=4,
            ).strip()
            labels_raw, health_raw = inspect.split("|", 1)
            labels = json.loads(labels_raw) if labels_raw and labels_raw != "null" else {}
            compose_project = labels.get("com.docker.compose.project", "")
            if health_raw and health_raw != "null":
                h = json.loads(health_raw)
                health = h.get("Status", "")
        except Exception:
            pass
        st = stats.get(name, {})
        rows.append({
            "name": name,
            "image": r.get("Image") or "",
            "status": r.get("Status") or "",
            "state": r.get("State") or "",
            "ports": r.get("Ports") or "",
            "compose_project": compose_project,
            "health": health,
            "cpu": st.get("CPUPerc", ""),
            "memory": st.get("MemUsage", ""),
            "memory_percent": st.get("MemPerc", ""),
            "net_io": st.get("NetIO", ""),
        })
    return rows


def compose_projects():
    items = {}
    for c in docker_containers():
        p = c.get("compose_project")
        if not p:
            continue
        items.setdefault(p, {"name": p, "containers": 0, "running": 0})
        items[p]["containers"] += 1
        if c.get("state") == "running":
            items[p]["running"] += 1
    return sorted(items.values(), key=lambda x: x["name"])


def local_ips():
    ips = []
    for ifname, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                ips.append({"interface": ifname, "address": a.address})
    return ips


def service_state(name: str):
    code, out = _run(["systemctl", "is-active", name], timeout=3)
    return out if out else ("active" if code == 0 else "unknown")


def docker_firewall_summary():
    code, out = _run(["sudo", "-n", "/usr/local/sbin/veribayt-serverhub-helper", "firewall-status"], timeout=5)
    if code != 0:
        return {"available": False, "summary": out or "helper unavailable"}
    try:
        return json.loads(out)
    except Exception:
        return {"available": True, "summary": out}


def ups_status():
    if shutil.which("upsc"):
        code, names = _run(["upsc", "-l"], timeout=4)
        if code == 0 and names.strip():
            name = names.splitlines()[0].strip()
            code, raw = _run(["upsc", name], timeout=4)
            if code == 0:
                data = {}
                for line in raw.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        data[k.strip()] = v.strip()
                return {
                    "available": True,
                    "driver": "NUT",
                    "name": name,
                    "status": data.get("ups.status", "unknown"),
                    "battery_charge": data.get("battery.charge"),
                    "runtime_seconds": data.get("battery.runtime"),
                    "input_voltage": data.get("input.voltage"),
                    "load_percent": data.get("ups.load"),
                }
    if shutil.which("apcaccess"):
        code, raw = _run(["apcaccess", "status"], timeout=4)
        if code == 0:
            data = {}
            for line in raw.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    data[k.strip()] = v.strip()
            return {
                "available": True,
                "driver": "APCUPSD",
                "status": data.get("STATUS", "unknown"),
                "battery_charge": data.get("BCHARGE"),
                "runtime": data.get("TIMELEFT"),
                "load": data.get("LOADPCT"),
            }
    return {"available": False, "status": "UPS agent not configured"}


def system_status(include_containers=True):
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    boot = psutil.boot_time()
    net = psutil.net_io_counters()
    try:
        load1, load5, load15 = os.getloadavg()
    except Exception:
        load1 = load5 = load15 = 0
    root_dev = ""
    try:
        for p in psutil.disk_partitions(all=False):
            if p.mountpoint == "/":
                root_dev = p.device
                break
    except Exception:
        pass
    status = {
        "hostname": socket.gethostname(),
        "cpu_percent": psutil.cpu_percent(interval=0.12),
        "cpu_count": psutil.cpu_count(logical=True),
        "memory": {
            "used": human(vm.used),
            "used_bytes": vm.used,
            "available": human(vm.available),
            "total": human(vm.total),
            "total_bytes": vm.total,
            "percent": vm.percent,
        },
        "disk": {
            "used": human(disk.used),
            "used_bytes": disk.used,
            "free": human(disk.free),
            "free_bytes": disk.free,
            "total": human(disk.total),
            "total_bytes": disk.total,
            "percent": disk.percent,
            "device": root_dev,
        },
        "temperature_c": temperature_c(),
        "uptime_seconds": int(time.time() - boot),
        "boot_time": int(boot),
        "load": [round(load1, 2), round(load5, 2), round(load15, 2)],
        "network": {
            "sent": human(net.bytes_sent),
            "recv": human(net.bytes_recv),
            "sent_bytes": net.bytes_sent,
            "recv_bytes": net.bytes_recv,
        },
        "ips": local_ips(),
        "services": {
            "docker": service_state("docker.service"),
            "ufw": service_state("ufw.service"),
            "serverhub": service_state("veribayt-serverhub.service"),
        },
    }
    if include_containers:
        status["containers"] = docker_containers()
    return status
