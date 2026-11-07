import json
import os
import urllib.parse
import urllib.request


def _post(url: str, data: bytes, headers=None, timeout=8):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read(2048).decode("utf-8", "replace")


def configured_channels():
    return {
        "telegram": bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID")),
        "ntfy": bool(os.environ.get("NTFY_TOPIC")),
        "webhook": bool(os.environ.get("NOTIFY_WEBHOOK_URL")),
    }


def send_notification(title: str, message: str, level: str = "info"):
    results = []
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if token and chat:
        try:
            body = urllib.parse.urlencode({"chat_id": chat, "text": f"{title}\n{message}"}).encode()
            status, _ = _post(f"https://api.telegram.org/bot{token}/sendMessage", body, {"Content-Type": "application/x-www-form-urlencoded"})
            results.append({"channel": "telegram", "ok": 200 <= status < 300})
        except Exception as e:
            results.append({"channel": "telegram", "ok": False, "error": str(e)})

    topic = os.environ.get("NTFY_TOPIC", "").strip()
    if topic:
        base = os.environ.get("NTFY_BASE_URL", "https://ntfy.sh").rstrip("/")
        try:
            status, _ = _post(
                f"{base}/{urllib.parse.quote(topic)}",
                message.encode("utf-8"),
                {"Title": title, "Priority": "4" if level in {"warning", "critical"} else "3", "Tags": "warning" if level in {"warning", "critical"} else "computer"},
            )
            results.append({"channel": "ntfy", "ok": 200 <= status < 300})
        except Exception as e:
            results.append({"channel": "ntfy", "ok": False, "error": str(e)})

    webhook = os.environ.get("NOTIFY_WEBHOOK_URL", "").strip()
    if webhook:
        try:
            payload = json.dumps({"title": title, "message": message, "level": level}).encode("utf-8")
            status, _ = _post(webhook, payload, {"Content-Type": "application/json"})
            results.append({"channel": "webhook", "ok": 200 <= status < 300})
        except Exception as e:
            results.append({"channel": "webhook", "ok": False, "error": str(e)})
    return results
