# Python 3.13 / FastAPI güvenlik notları

Python 3.13 taban imajını güvenlik yamaları için düzenli güncelleyin: `docker compose build --pull --no-cache`. CI Python 3.13 ile test ve pip-audit taraması yapar. Üretimde bağımlılık sürümlerini kilitleyin.

`.env` dosyasını GitHub'a yüklemeyin. Güçlü Argon2 parola hash'i ve 32+ karakterlik SESSION_SECRET zorunludur. HTTPS altında PANEL_SECURE_COOKIES=true kullanın.

**Kritik:** Docker socket mount host üzerinde root düzeyinde yetki verebilir. Container root olarak çalışır. Paneli internete doğrudan açmayın; SSH tüneli veya VPN kullanın. Cloudflare kimlik başlıklarına yalnızca doğrulanmış proxy üzerinden güvenin.

Gerçek Docker çalışma ve güvenlik testi bu ortamda doğrulanmadı.
