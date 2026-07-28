# Specter: Asenkron Ağ Keşif, Derin El Sıkışma, JARM ve Exploit-DB Motoru

Specter, yüksek performanslı dağıtık sistemler ve sızma testi keşif operasyonları için geliştirilmiş açık kaynaklı bir CLI aracıdır. Nmap veya Wappalyzer gibi harici alt süreç bağımlılıklarını ortadan kaldırarak; doğrudan katman 4 soket ikili el sıkışmaları (binary handshakes), katman 7 HTTP/HTTPS gözetim mekanizmaları, Salesforce JARM TLS parmak izi algoritması, Exploit-DB çevrimdışı CVE eşleştirme ve aktif Python betik (scripting) denetimleri ile çalışır.

## Temel Özellikler

*   **Salesforce JARM TLS Fingerprinting:** TLS portlarına 10 özel Client Hello göndererek sunucuların SSL/TLS konfigürasyonlarından 62 karakterlik benzersiz parmak izi çıkarma.
*   **Exploit-DB Çevrimdışı İndeksleyici (`--exploitdb`):** `files_exploits.csv` dosyasını bellek içinde indeksleyip tespit edilen servis versiyonları ile doğrudan EDB-ID ve zafiyet başlığı eşleştirme.
*   **Aktif Betik Motoru (`--run-scripts`):** Redis yetkisiz erişim, MySQL el sıkışma parametreleri, SMB2 diyalekt kontrolü, PostgreSQL yetki denetimi, HTTP güvenlik başlıkları (HSTS, CSP, CORS) ve Ollama AI model enumerasyon betikleri.
*   **Verbose Modu (`-v`):** Soket bağlantıları, paket bayt miktarları ve imza eşleşmeleri için anlık debug takibi.

## Kurulum ve Kullanım

### Kurulum

```bash
git clone https://github.com/example/specter.git
cd Specter
pip install -r requirements.txt
pip install -e .
```

### Exploit-DB ve Aktif Betik Taraması

```bash
specter -t 127.0.0.1 -p 80,443,3306,5432,6379,11434 -v --run-scripts --exploitdb
```

### Raporlama

```bash
specter -t 192.168.1.0/24 -p 80,443 --json output.json --html report.html
```

## Sonuç

Yenilenen Specter mimarisi; genişletilmiş imza kütüphanesi (`signatures/db.py`), Salesforce JARM TLS parmak izi tarayıcısı, Exploit-DB çevrimdışı zafiyet indeksleyicisi ve gelişmiş aktif betik kontrol motoru ile donatılmıştır. Paket mimarisi `pyproject.toml` standartlarında yapılandırılmış olup yüksek performanslı ve modüler bir keşif çözümü sunmaktadır.
