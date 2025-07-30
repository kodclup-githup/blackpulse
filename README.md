# 🚀 BlackPulse v3.0 - Askeri Sınıf Ağ Test Aracı

<div align="center">

```
██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗ ██╗   ██╗██╗     ███████╗███████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
██████╔╝██║     ███████║██║     █████╔╝ ██████╔╝██║   ██║██║     ███████╗█████╗  
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║     ╚██████╔╝███████╗███████║█████��█╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝
```

**Profesyonel Seviye Ağ Performans Test Aracı**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Termux-green.svg)](https://github.com)
[![License](https://img.shields.io/badge/License-Sadece%20Eğitim%20Amaçlı-red.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.0%20Professional-purple.svg)](https://github.com)

</div>

---

## ⚠️ **YASAL UYARI VE SORUMLULUK REDDİ**

**BlackPulse v3.0** **YALNIZCA** eğitim amaçlı ve yetkili penetrasyon testleri için geliştirilmiştir. Bu araç **SADECE KENDİ SİSTEMLERİNİZİ** ve test etme izniniz olan ağları test etmek için tasarlanmıştır.

**🚨 ÖNEMLİ UYARILAR:**
- ❌ Bu aracı sahip olmadığınız sistemlere karşı **KULLANMAYIN**
- ❌ Bu aracı kötü niyetli amaçlar için **KULLANMAYIN**
- ❌ Bu aracı üçüncü taraf sistemlere saldırmak için **KULLANMAYIN**
- ✅ **SADECE** yetkili güvenlik testleri ve eğitim için kullanın
- ✅ **SADECE** sahip olduğunuz veya yazılı izniniz olan sistemlerde kullanın

**Geliştiriciler bu aracın kötüye kullanımından sorumlu DEĞİLDİR. BlackPulse'u kullanarak, bu şartları anladığınızı ve aracı sorumlu ve yasal bir şekilde kullanacağınızı kabul etmiş olursunuz.**

**⚖️ BİZİ TANIMIYORSUNUZ - KÖTÜYE KULLANIM DURUMUNDA HİÇBİR SORUMLULUĞUMUZ YOKTUR**

---

## 🎯 **Genel Bakış**

BlackPulse v3.0, siber güvenlik uzmanları, penetrasyon testçileri ve ağ yöneticileri için tasarlanmış **askeri sınıf bir ağ test paketidir**. Bu güçlü araç, birden fazla protokol üzerinde kapsamlı ağ performans analizi ve stres testi yetenekleri sağlar.

### 🌟 **Temel Özellikler**

- 🔥 **Çoklu Protokol Desteği**: TCP, UDP, HTTP/HTTPS, WebSocket, DNS, ICMP
- ⚡ **Yüksek Performans**: Asenkron mimari ile çoklu iş parçacığı
- 📊 **Gerçek Zamanlı Analitik**: Detaylı metriklerle canlı izleme
- 📈 **Gelişmiş Raporlama**: JSON, CSV ve grafik raporları
- 🎛️ **Profesyonel Arayüz**: Renk kodlu çıktı ile sezgisel menü sistemi
- 🔧 **Yüksek Yapılandırılabilirlik**: YAML/JSON yapılandırma desteği
- 🌍 **Çapraz Platform**: Windows, Linux, Termux uyumlu
- 🛡️ **Askeri Sınıf**: Kurumsal seviye performans ve güvenilirlik

---

## 🖥️ **Platform Uyumluluğu**

BlackPulse v3.0 tüm büyük platformlarda kusursuz çalışır:

### 🐧 **Linux**
- Ubuntu 18.04+
- Debian 10+
- CentOS 7+
- Kali Linux
- Arch Linux
- Parrot OS

### 🪟 **Windows**
- Windows 10/11
- Windows Server 2016+
- WSL (Windows Subsystem for Linux)

### 📱 **Termux (Android)**
- Termux son sürüm
- Android 7.0+

---

## 🚀 **Kurulum Kılavuzu**

### **Ön Gereksinimler**

Sisteminizde Python 3.8+ yüklü olduğundan emin olun.

### **Adım 1: Depoyu Klonlayın**

```bash
git clone https://github.com/kodclup-githup/blackpulse.git
cd blackpulse
```

### **Adım 2: Bağımlılıkları Yükleyin**

#### **🐧 Linux Kurulumu**

```bash
# Sistem paketlerini güncelleyin
sudo apt update && sudo apt upgrade -y

# Python ve pip yükleyin
sudo apt install python3 python3-pip python3-venv -y

# Sanal ortam oluşturun (önerilen)
python3 -m venv blackpulse-env
source blackpulse-env/bin/activate

# Gerekli paketleri yükleyin
pip install -r requirements.txt

# ICMP testi için (root gerektirir)
sudo apt install python3-scapy -y

# İsteğe bağlı: Tüm özellikler için ek bağımlılıklar
pip install matplotlib numpy tabulate websockets
```

#### **🪟 Windows Kurulumu**

```powershell
# Python'u python.org'dan yükleyin (3.8+)
# PowerShell'i Yönetici olarak açın

# Sanal ortam oluşturun
python -m venv blackpulse-env
blackpulse-env\Scripts\activate

# Gerekli paketleri yükleyin
pip install -r requirements.txt

# İsteğe bağlı bağımlılıkları yükleyin
pip install matplotlib numpy tabulate websockets scapy
```

#### **📱 Termux Kurulumu(root olmadan çalışmaz)**

```bash
# Termux paketlerini güncelleyin
pkg update && pkg upgrade -y

# Python ve bağımlılıkları yükleyin
pkg install python python-pip git -y

# Gerekli paketleri yükleyin
pip install -r requirements.txt

# İsteğe bağlı paketleri yükleyin
pip install matplotlib numpy tabulate websockets

# Not: Bazı özellikler root erişimi gerektirebilir
```

### **Adım 3: Sistem Bağımlılıklarını Yükleyin**

#### **Gerekli Python Paketleri**

`requirements.txt` dosyası oluşturun:

```txt
dnspython>=2.3.0
requests>=2.28.0
aiohttp>=3.8.0
psutil>=5.9.0
pyyaml>=6.0
asyncio>=3.4.3

# İsteğe bağlı ama önerilen
matplotlib>=3.5.0
numpy>=1.21.0
tabulate>=0.9.0
websockets>=10.4
scapy>=2.4.5
```

Şu komutla yükleyin:
```bash
pip install -r requirements.txt
```

---

## 🎮 **Kullanım Kılavuzu**

### **🚀 Hızlı Başlangıç**

1. **BlackPulse'u Başlatın:**
   ```bash
   python3 black_pulse.py
   ```

2. **Test Modunu Seçin:**
   - 7 farklı test modundan birini seçin
   - Hedef ve parametreleri yapılandırın
   - Test özetini gözden geçirin
   - Onaylayın ve testi başlatın

### **📋 Mevcut Test Modları**

| Mod | Açıklama | Kullanım Alanı |
|-----|----------|----------------|
| **TCP Flood** | Yüksek performanslı TCP bağlantı testi | Sunucu kapasite testi |
| **HTTP Flood** | HTTP/1.1 protokol stres testi | Web sunucu performansı |
| **HTTPS Flood** | SSL/TLS güvenli bağlantı testi | HTTPS sunucu analizi |
| **UDP Flood** | UDP paket bombardımanı testi | UDP servis testi |
| **WebSocket Test** | WebSocket protokol testi | Gerçek zamanlı uygulama testi |
| **DNS Flood** | DNS çözümleme stres testi | DNS sunucu performansı |
| **ICMP Ping** | ICMP ping flood testi | Ağ bağlantı testi |

### **⚙️ Yapılandırma Seçenekleri**

#### **Temel Yapılandırma**
- **Hedef**: IP adresi, domain veya URL
- **Port**: Hedef port numarası
- **Thread**: Eşzamanlı thread sayısı (1-2000)
- **Süre**: Test süresi saniye cinsinden (1-7200)
- **Timeout**: Bağlantı timeout süresi

#### **Gelişmiş Yapılandırma**
- **Veri İletimi**: Veri göndermeyi etkinleştir/devre dışı bırak
- **Yanıt Bekleme**: Sunucu yanıtlarını bekle
- **Socket Pool**: Socket pool boyutunu yapılandır
- **Özel Header'lar**: HTTP/HTTPS özel header'ları
- **SSL Seçenekleri**: SSL/TLS yapılandırması

### **📊 Komut Satırı Kullanımı**

```bash
# Temel kullanım
python3 black_pulse.py -t hedef.com -p 80 -m HTTP_FLOOD -d 60

# Yapılandırma dosyası ile gelişmiş kullanım
python3 black_pulse.py --config config.yaml

# Örnek yapılandırma oluştur
python3 black_pulse.py --create-config

# Sessiz mod (sadece sonuçlar)
python3 black_pulse.py -t hedef.com -p 80 -q
```

### **📁 Yapılandırma Dosyası Örneği**

```yaml
target:
  ip: "192.168.1.100"
  port: 80
  domain: "ornek.com"

test:
  mode: "HTTP_FLOOD"
  threads: 200
  duration: 300
  timeout: 10

advanced:
  send_data: true
  data_size: 2048
  wait_response: true
  socket_pool_size: 20

output:
  json_report: true
  csv_report: true
  graph_report: true
  console_report: true
```

---

## 📈 **Özellikler ve Yetenekler**

### **🔥 Performans Özellikleri**
- **Asenkron Mimari**: Engelleyici olmayan I/O işlemleri
- **Çoklu İş Parçacığı**: Eşzamanlı istek işleme
- **Bellek Verimli**: Deque'lar ile optimize edilmiş bellek kullanımı
- **Yüksek Verim**: Milyonlarca istek kapasitesi
- **Gerçek Zamanlı İzleme**: Canlı performans metrikleri

### **📊 Analitik ve Raporlama**
- **Gerçek Zamanlı İstatistikler**: RPS, gecikme, başarı oranı
- **Detaylı Metrikler**: Yanıt süreleri, bant genişliği kullanımı
- **Yüzdelik Analizi**: P50, P75, P90, P95, P99, P99.9
- **Hata Analizi**: Kategorize edilmiş hata raporlama
- **Sistem İzleme**: CPU, bellek, ağ kullanımı

### **📋 Rapor Formatları**
- **Konsol Raporu**: Renkli detaylı terminal çıktısı
- **JSON Raporu**: Makine tarafından okunabilir yapılandırılmış veri
- **CSV Raporu**: Elektronik tablo uyumlu veri dışa aktarımı
- **Grafik Raporu**: Görsel grafikler ve çizelgeler (PNG)
- **Yapılandırma Dışa Aktarımı**: Test yapılandırmalarını kaydet

### **🛡️ Güvenlik Özellikleri**
- **DNS Çözümleme**: Gelişmiş DNS analizi
- **SSL/TLS Testi**: Sertifika ve el sıkışma analizi
- **Protokol Desteği**: Birden fazla ağ protokolü
- **Hata İşleme**: Kapsamlı hata kategorizasyonu

---

## 🎯 **Performans Kıyaslamaları**

BlackPulse v3.0 tüm platformlarda olağanüstü performans sunar:

### **🏆 Kıyaslama Sonuçları**

| Platform | Maks RPS | Maks Thread | Bellek Kullanımı | CPU Verimliliği |
|----------|----------|-------------|------------------|-----------------|
| **Linux** | 50,000+ | 2,000 | < 500MB | %95+ |
| **Windows** | 35,000+ | 1,500 | < 750MB | %90+ |
| **Termux** | 15,000+ | 500 | < 300MB | %85+ |

### **⚡ Optimizasyon Özellikleri**
- Otomatik sistem optimizasyon tespiti
- Kaynak kullanım izleme
- Performans önerileri
- Bellek sızıntısı önleme
- CPU kullanım optimizasyonu

---

## 🔧 **Sistem Gereksinimleri**

### **Minimum Gereksinimler**
- **CPU**: 2 çekirdek, 1.5 GHz
- **RAM**: 2 GB
- **Depolama**: 100 MB boş alan
- **Ağ**: Kararlı internet bağlantısı
- **Python**: 3.8+

### **Önerilen Gereksinimler**
- **CPU**: 4+ çekirdek, 2.5+ GHz
- **RAM**: 8+ GB
- **Depolama**: 1+ GB boş alan
- **Ağ**: Yüksek hızlı bağlantı
- **Python**: 3.10+

### **Maksimum Performans İçin**
- **CPU**: 8+ çekirdek, 3.0+ GHz
- **RAM**: 16+ GB
- **Ağ**: Gigabit bağlantı
- **OS**: Linux (en iyi performans)

---

## 📚 **Gelişmiş Kullanım Örnekleri**

### **Örnek 1: Web Sunucu Stres Testi**
```bash
# Web sunucu kapasitesini test et
python3 black_pulse.py -t websunucu.com -p 80 -m HTTP_FLOOD -d 300 --threads 500
```

### **Örnek 2: HTTPS Performans Analizi**
```bash
# HTTPS performansını analiz et
python3 black_pulse.py -t guvenli.ornek.com -p 443 -m HTTPS_FLOOD -d 600 --threads 200
```

### **Örnek 3: DNS Sunucu Testi**
```bash
# DNS sunucu performansını test et
python3 black_pulse.py -t dns.ornek.com -m DNS_FLOOD -d 120 --threads 100
```

### **Örnek 4: Özel Yapılandırma**
```bash
# Özel yapılandırma dosyası kullan
python3 black_pulse.py --config kurumsal_test.yaml
```

---

## 🛠️ **Sorun Giderme**

### **Yaygın Sorunlar ve Çözümler**

#### **🔴 İzin Reddedildi (ICMP)**
```bash
# ICMP testi için sudo ile çalıştır
sudo python3 black_pulse.py
```

#### **🔴 Çok Fazla Açık Dosya**
```bash
# Dosya tanımlayıcı limitini artır
ulimit -n 65536
```

#### **🔴 Modül Bulunamadı**
```bash
# Eksik bağımlılıkları yükle
pip install -r requirements.txt
```

#### **🔴 Yüksek Bellek Kullanımı**
```bash
# Thread sayısını azalt
python3 black_pulse.py -t hedef.com --threads 100
```

### **🔧 Sistem Optimizasyonu**

#### **Linux Optimizasyonu**
```bash
# TCP optimizasyonu
echo 'net.core.somaxconn = 65535' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_max_syn_backlog = 65535' >> /etc/sysctl.conf
sysctl -p

# Dosya tanımlayıcı limiti
echo '* soft nofile 65535' >> /etc/security/limits.conf
echo '* hard nofile 65535' >> /etc/security/limits.conf
```

#### **Windows Optimizasyonu**
```powershell
# PowerShell'i Yönetici olarak çalıştır
# TCP bağlantılarını artır
netsh int tcp set global autotuninglevel=normal
```

---

## 📖 **Dokümantasyon**

### **📋 Komut Referansı**

| Parametre | Kısa | Açıklama | Örnek |
|-----------|------|----------|-------|
| `--target` | `-t` | Hedef IP/domain | `-t ornek.com` |
| `--port` | `-p` | Hedef port | `-p 80` |
| `--mode` | `-m` | Test modu | `-m HTTP_FLOOD` |
| `--threads` | | Thread sayısı | `--threads 200` |
| `--duration` | `-d` | Test süresi | `-d 300` |
| `--config` | `-c` | Yapılandırma dosyası | `-c test.yaml` |
| `--quiet` | `-q` | Sessiz mod | `-q` |

### **📊 Rapor Metrikleri**

| Metrik | Açıklama | Birim |
|--------|----------|-------|
| **RPS** | Saniye başına istek | req/s |
| **Gecikme** | Yanıt süresi | milisaniye |
| **Başarı Oranı** | Başarılı istekler | yüzde |
| **Bant Genişliği** | Veri transfer hızı | Mbps |
| **Eşzamanlı** | Aktif bağlantılar | sayı |

---

## ⚠️ **Önemli Güvenlik Notları**

### **🛡️ Sorumlu Kullanım**
1. **Yetkilendirme Gerekli**: Sadece sahip olduğunuz veya açık yazılı izniniz olan sistemleri test edin
2. **Eğitim Amaçlı**: Bu araç sadece öğrenme ve yetkili test için
3. **Yasal Uyumluluk**: Yerel yasalar ve düzenlemelere uygunluğu sağlayın
4. **Etik Kurallar**: Sorumlu açıklama uygulamalarını takip edin

### **🚨 Uyarı İşaretleri**
- **Aşırı Kaynak Kullanımı**: Test sırasında sistem kaynaklarını izleyin
- **Ağ Tıkanıklığı**: Ağ etkisinin farkında olun
- **Servis Kesintisi**: Servisler kullanılamaz hale gelirse testi durdurun
- **Yasal Sorunlar**: Yasal endişeler varsa kullanımı durdurun

### **✅ En İyi Uygulamalar**
- Düşük thread sayıları ve kısa sürelerle başlayın
- Test sırasında hedef sistem sağlığını izleyin
- Üretim sistemleri için hız sınırlaması kullanın
- Tüm test faaliyetlerini belgeleyin
- Test öncesi uygun yetkilendirme alın

---

## 🤝 **Katkıda Bulunma**

Siber güvenlik topluluğundan katkıları memnuniyetle karşılıyoruz! Lütfen tüm katkıların bu projenin eğitim ve etik odağını koruduğundan emin olun.

### **📝 Kurallar**
- Sorumlu açıklama uygulamalarını takip edin
- Eğitim odağını koruyun
- Uygun dokümantasyon ekleyin
- Göndermeden önce kapsamlı test yapın
- Yasal ve etik sınırlara saygı gösterin

---

## 📞 **Destek ve İletişim**

Eğitim ve yetkili test desteği için:

- **Dokümantasyon**: Bu README ve satır içi yardımı kontrol edin
- **Sorunlar**: Hataları ve özellik isteklerini sorumlu bir şekilde bildirin
- **Topluluk**: Etik hacking topluluklarına katılın
- **Eğitim**: Siber güvenlik kavramlarını öğrenmek için kullanın

---

## 📄 **Lisans**

Bu proje **Sadece Eğitim Amaçlı** lisanslanmıştır. Ticari kullanım, kötü niyetli kullanım veya yetkisiz sistemlere karşı kullanım kesinlikle yasaktır.

---

<div align="center">

**⚡ BlackPulse v3.0 - Profesyonel Ağ Test Paketi ⚡**

*Siber güvenlik eğitimi ve yetkili testler için geliştirilmiştir*

**Unutmayın: Büyük güç, büyük sorumluluk getirir**

</div>

---

## 🔥 **Neden BlackPulse v3.0'ı Seçmelisiniz?**

- ✅ **Askeri Sınıf Performans**: Kurumsal seviye yetenekler
- ✅ **Çapraz Platform Uyumluluğu**: Her yerde çalışır
- ✅ **Profesyonel Raporlar**: Detaylı analiz ve içgörüler
- ✅ **Eğitim Odaklı**: Siber güvenlik öğrenmek için mükemmel
- ✅ **Etik Tasarım**: Sorumlu kullanım göz önünde bulundurularak yapılmış
- ✅ **Aktif Geliştirme**: Sürekli iyileştirilen ve güncellenen
- ✅ **Topluluk Destekli**: Siber güvenlik uzmanları tarafından desteklenen

**⚠️ DİKKATLİ KULLANIN - ÇOK GÜÇLÜ BİR ARAÇTIR!**

**BlackPulse v3.0 ile yetkili ağ test yolculuğunuza bugün başlayın!**
