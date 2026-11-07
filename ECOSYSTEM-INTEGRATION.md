# Veribayt tek ekosistem bağlantısı

- Ana site: `https://veribayt.com/`
- Minecraft: `https://veribayt.com/minecraft`
- Yönetim: `https://server.veribayt.com/admin`
- Public Minecraft API: `https://server.veribayt.com/api/public/minecraft/servers`

Admin panelde Minecraft profili oluştururken **Veribayt /minecraft sayfasında yayınla** seçeneğini açın. Sunucu çalıştığında ana sayfa ve `/minecraft` canlı API'den durumu çeker.

## Erişim türleri
- **Şifresiz:** bağlantı adresi doğrudan görünür.
- **Şifreli:** IP/hostname sitede gizlenir; doğru paylaşım şifresi girilince gösterilir. Şifre PBKDF2-SHA256 ile hashlenir.
- **Whitelist:** Minecraft'ın oyun seviyesindeki erişim kontrolüdür. Kullanıcı adlarını panelde virgülle yazın. Site paylaşım şifresi ile whitelist birbirinden bağımsızdır.

> Minecraft Java sunucusunda yerleşik klasik bir “server password” özelliği yoktur. Bu nedenle paylaşım şifresi sitede adresi korur; oyuna gerçekten kimlerin gireceğini sınırlamak için whitelist kullanılır.

## Domainler
`server.veribayt.com` Cloudflare Tunnel ile panelin `http://127.0.0.1:9090` adresine yönlendirilmelidir. Minecraft oyun portu ise HTTP tunnel değildir; `mc.veribayt.com` DNS kaydı public IP'ye gitmeli ve kullanılan TCP port modem/firewall üzerinden sunucu kasasına yönlendirilmelidir.
