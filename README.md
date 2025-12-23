# kcp-for-unreal-engine
Unreal Engine 5 için temel KCP integrasyon plugin'i.

## Özellikler
- KCP tabanlı UDP bağlantısı açma.
- Mesaj gönderme ve alma (Blueprint destekli).
- KCP pencere ve nodelay ayarları.

## Kullanım
1. Projeye plugin olarak ekleyin (Plugins klasörü altına taşıyın).
2. Bir Actor'a `KcpComponent` ekleyin.
3. `Connect` fonksiyonuyla sunucu IP/port/konuşma ID'sini verin.
4. `SendMessage` ile veri gönderin, `OnMessageReceived` ile dinleyin.
