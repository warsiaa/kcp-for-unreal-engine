# kcp-for-unreal-engine
Unreal Engine 5 için KCP_CLIENT bileşeni. [warsiaa/KCP_SERVER](https://github.com/warsiaa/KCP_SERVER) ile uyumlu çalışacak şekilde şifreleme desteği ve bağlantı sürecini ayrıntılı loglama eklenmiştir.

## Özellikler
- KCP tabanlı UDP bağlantısı açma ve kapama.
- Mesaj gönderme/alma (Blueprint destekli) ve UE5 Output Log'a ayrıntılı durum mesajları.
- KCP pencere ve nodelay ayarları.
- AES-256 ile isteğe bağlı şifreleme (anahtar otomatik olarak SHA-256 ile 32 byte'a dönüştürülür).
- Blueprint'te paket oluşturmayı kolaylaştıran `Build KCP Packet` düğümü (UTF-8 string + ham byte ekleri).

## Kurulum
1. Depoyu indirin veya kopyalayın.
2. Projenizin `Plugins/` klasörüne taşıyın veya symlink oluşturun.
3. Projeyi açın ve plugin'i etkinleştirin.

## Blueprint Kullanımı

### Bağlantı açma
1. Bir Actor'a `KcpComponent` ekleyin.
2. Bağlanmadan önce **Settings** içindeki değerleri düzenleyin:
   - `SendWindowSize` / `ReceiveWindowSize`, `bNoDelay`, `IntervalMs`, `FastResend`, `bDisableCongestionControl` gibi KCP ayarları.
   - Şifreleme için `bEnableEncryption` değerini **true** yapın ve `EncryptionKey` alanına sunucudaki anahtarla aynı olacak şekilde bir string yazın. Bu string `SHA-256` ile 32 byte'lık bir anahtara çevrilir ve AES-256 için kullanılır.
3. `Connect(RemoteIp, RemotePort, LocalPort, ConversationId)` fonksiyonunu çağırın.
4. Output Log'da "KCP connected" mesajını gördüğünüzde UDP soketi hazırdır.

> İpucu: KCP_SERVER paketleri şifrelediği için şifreleme açık değilse mesajlar çözümlenemeyebilir. Anahtar string'inin sunucu ile aynı olduğundan emin olun.

### Paket gönderme
1. Göndermek istediğiniz stringi ve ek ham byte'ları `Build KCP Packet` düğümüyle birleştirin. Dönen `TArray<uint8>` doğrudan `SendMessage` fonksiyonuna verilebilir.
2. Şifreleme açıksa paket otomatik olarak AES-256 ile şifrelenir ve KCP üzerinden gönderilir.
3. Gönderim sonucu `bSendPacketSuccess` bayrağından ve Output Log satırlarından takip edilebilir.

### Paket alma
1. `OnMessageReceived` event'ine abone olun.
2. Şifreleme açıksa gelen paketler otomatik olarak AES-256 ile çözümlenir ve event'e ham (çözülmüş) byte dizisi olarak düşer.
3. Output Log'da alınan byte sayısını, çözme hatalarını veya bağlantı durumunu takip edebilirsiniz.

### Bağlantı kapatma
`Disconnect` fonksiyonunu çağırarak KCP kontrol bloğunu ve UDP soketini kapatabilirsiniz. Bu işlem de loglanır.

## Loglar
KCP bileşeni, bağlantı denemeleri, soket hataları, şifreleme anahtarı oluşturma ve paket gönderme/almayla ilgili her adımı `LogKcpComponent` kategorisi altında loglar. UE5 Output Log veya konsolda filtreleyerek takip edebilirsiniz.

## Geliştirme Notları
- Şifreleme veri boyutunu AES blok boyutuna (16 byte) yuvarlayarak gönderir. Sunucu tarafının aynı yöntemi kullandığından emin olun.
- `Build KCP Packet` düğümü, UTF-8 string ve isteğe bağlı ek byte'ları tek pakette toplamak için tasarlanmıştır; ek başlık, uzunluk veya şema gerekiyorsa burada oluşturabilirsiniz.
