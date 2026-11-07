# SunucuKontrol 4.0 — yeni özellikler

FastAPI + Python 3.13 tabanlı önceki v3.1 sürümünün üzerine eklenmiştir.

## Eklenenler
- Çoklu uzak sunucu kayıtları ve salt okunur SSH durum kontrolü (`uptime`, `free`, `df`)
- SSH host key doğrulaması (known_hosts) ve yalnızca anahtar ile giriş
- İsteğe bağlı TOTP iki aşamalı oturum açma (6 haneli kod)
- Uygulama kataloğu: Nginx, Redis, PostgreSQL bilgi şablonları (kurulum yok)
- Mobil uyumlu uzak sunucular ve katalog sekmeleri
- Yeni API'ler `/api/fleet`, `/api/fleet/{id}/status`, `/api/catalog`

## Kurulum
1. Önce `README.md` dosyasındaki v3.1 kurulumu ve `.env` güvenlik ayarlarını tamamlayın.
2. İsteğe bağlı 2FA için `python -c "import pyotp; print(pyotp.random_base32())"` ile secret oluşturun, `.env` içindeki `PANEL_TOTP_SECRET` alanına yazın ve kendi authenticator uygulamanıza secret'ı manuel tanıtın. **Secret'ı kaybetmeyin; yedek kod yok.**
3. SSH izleme için `secrets/fleet_ssh_key` adlı *ayrı ve yetkileri sınırlandırılmış* SSH özel anahtarı oluşturun. `secrets/fleet_known_hosts` dosyasına sunucu anahtarını **bağımsız doğrulayarak** ekleyin. Compose dosyasındaki iki SSH volume satırını etkinleştirin.
4. `docker compose up -d --build`

**Güvenlik:** Docker socket host üzerinde tam yetki sağlayabilir; paneli internete doğrudan açmayın. SSH yalnızca global IP adresleri için etkinleştirilmiştir; private/VPN IP desteği bu sürümde yoktur. SSH anahtarı şifresiz ve ayrı, düşük yetkili izleme hesabına ait olmalıdır. Komut terminali, çok kullanıcılı RBAC, otomatik SSL kurma ve tek tıkla uygulama dağıtımı bu sürümde **uygulanmamıştır**. Sistem mevcut uygulamanın tüm özelliklerini uçtan uca doğrulamaz.
