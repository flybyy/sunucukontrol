# Security model

ServerHub güçlü bir yönetim aracıdır. Tasarım hedefi "internete root panel açmak" değil; Cloudflare Access arkasında, localhost origin üzerinde, sınırlandırılmış işlemler sağlamaktır.

- Uvicorn bind: 127.0.0.1:9090
- Root işlemleri: yalnız `/usr/local/sbin/veribayt-serverhub-helper` whitelist
- Docker erişimi: `veribayt-panel` kullanıcısı docker grubunda. Docker erişiminin host seviyesinde güçlü bir yetki olduğu kabul edilir; bu nedenle Cloudflare Access önemlidir.
- Secret'lar: `/etc/veribayt-serverhub.env`, root:root, 0600
- Shared project env: `/srv/veribayt/projects/<slug>/shared/.env`, panel user, 0600
- Arbitrary shell endpoint yoktur.
- Arbitrary host filesystem browser yoktur.
- Upload ZIP extraction path traversal/symlink/uncompressed-size kontrollerine tabidir.
- Destructive actions ek confirmation header gerektirir ve audit log'a yazılır.

Production kullanımında ayrıca Cloudflare Access, güçlü admin şifresi, UPS, off-site backup ve düzenli Ubuntu/Docker güncellemeleri kullanın.
