#Specter: Asenkron Ağ Keşif ve Derin Parmak İzi Tarama Motoru
Specter, yüksek performanslı dağıtık sistemler ve güvenlik keşif operasyonları için geliştirilmiş açık kaynaklı bir CLI aracıdır. Nmap, Masscan, WhatWeb veya Wappalyzer gibi harici alt süreç bağımlılıklarını tamamen ortadan kaldırarak; doğrudan katman 4 soket işlemleri ve katman 7 HTTP/HTTPS gözetim mekanizmaları ile çalışır.Temel ÖzelliklerNon-blocking Asenkron Mimari: asyncio altyapısı sayesinde binlerce portu aynı anda yüksek hızla tarar.Dinamik Akış Kontrolü: Token Bucket algoritması tabanlı hız sınırlama (Rate Limiting) ve otomatik yeniden deneme (Retry) mekanizması.Ham Soket Banner Analizi: SSH, FTP, SMTP, Redis, PostgreSQL, MySQL, MongoDB, RDP gibi protokoller için özel ikili paketler (binary probes) ile sürüm tespiti.Derin Web Parmak İzi: HTTP Header, Cookie, DOM başlığı, Meta etiketleri, Favicon MMH3 hash eşleşmesi ve statik uç nokta enumerasyonu.Genişletilebilir İmza Veritabanı: CMS, ERP, CRM, Modern AI Stack (Ollama, Flowise, LangChain), Web Frameworks ve DevOps araçlarını tespit eden kütüphane.Çoklu Çıktı Formatları: Terminal tablosu (rich), JSON, CSV ve bağımsız HTML rapor desteği.KurulumYerel Kurulumbashgit clone https://github.com/example/specter.gitcd specterpip install -r requirements.txtpip install -e .
### Docker Kurulumu

```bash
docker build -t specter .
docker run --rm specter -t 192.168.1.1 -p 80,443,5432
Kullanım ParametreleriParametreKısa KodAçıklama--target-tHedef IP (192.168.1.1), Aralık (10.0.0.1-50), CIDR (192.168.1.0/24) veya Domain (example.com).--ports-pTarayacak port aralığı (Örn: 22,80,443,8000-8080).--concurrency-cEşzamanlı asenkron iş parçacığı sayısı (Varsayılan: 500).--rate-limit-rSaniyedeki maksimum istek/paket limiti.--timeout-Soket zaman aşımı süresi (saniye).--json-JSON çıktı dosya yolu.--csv-CSV çıktı dosya yolu.--html-HTML rapor dosya yolu.Terminal Çıktı ÖrneğiPlaintext=== SPECTER RECONNAISSANCE SCAN RESULTS ===

┌──────────────────────────────────────────────────────────┐
│ Target: 192.168.1.100                                    │
│ Discovered Open Ports: 80, 5432, 11434                   │
└──────────────────────────────────────────────────────────┘
┌──────┬────────────────┬────────────────────────────────┬──────────────────────────────────────────┐
│ Port │ Protocol/Mode  │ Banner / Server Header         │ Fingerprinted Stack                      │
├──────┼────────────────┼────────────────────────────────┼──────────────────────────────────────────┤
│ 80   │ HTTP/HTTPS     │ HTTP Server: nginx/1.24.0      │ WordPress (Detected), PHP Runtime (8.2.10)│
│ 5432 │ RAW Socket     │ FATAL: database "postgres"...  │ PostgreSQL (Database Engine)             │
│ 11434│ HTTP/HTTPS     │ Ollama is running              │ Ollama AI Engine (Detected)              │
└──────┴────────────────┴────────────────────────────────┴──────────────────────────────────────────┘
JSON Çıktı ÖrneğiJSON[
    {
        "target": "192.168.1.100",
        "open_ports": [80, 5432, 11434],
        "details": [
            {
                "port": 80,
                "raw_socket": {
                    "port": 80,
                    "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Powered-By: PHP/8.2.10\r\n",
                    "service_hint": "unknown",
                    "extracted_version": null
                },
                "http_data": {
                    "is_http": true,
                    "status_code": 200,
                    "headers": {
                        "Server": "nginx/1.24.0",
                        "X-Powered-By": "PHP/8.2.10"
                    },
                    "cookies": {},
                    "dom_title": "Corporate Portal",
                    "favicon_mmh3": "116323821",
                    "endpoint_responses": {
                        "/wp-json/": {
                            "status": 200,
                            "body_snippet": "{\"name\":\"Corporate Portal\",\"namespaces\":[\"wp/v2\"]}"
                        }
                    }
                },
                "technologies": [
                    {
                        "name": "Web Server",
                        "category": "Infrastructure",
                        "version": "nginx/1.24.0"
                    },
                    {
                        "name": "PHP Runtime",
                        "category": "Web Runtime",
                        "version": "8.2.10"
                    },
                    {
                        "name": "WordPress",
                        "category": "CMS",
                        "version": "Detected"
                    }
                ]
            }
        ]
    }
]

---

## Sonuç

Geliştirilen **Specter** mimarisi, ağ ve uygulama katmanındaki keşif süreçlerini tek bir asenkron çalışma zamanı altında birleştirmiştir. Alt süreç çalıştırma kısıtlamalarını ortadan kaldıran saf Python tasarımı, dağıtık sistemlerde ve yüksek bant genişlikli tarama senaryolarında sistem kaynaklarının minimum düzeyde tüketilmesini sağlar. Veritabanı başlangıç paketlerinin ikili düzeyde işlenmesi, Favicon MurmurHash3 algoritmasının uygulanması ve esnek imza motoru sayesinde Specter, modern saldırı yüzeyi yönetiminde kapsamlı bir keşif yeteneği sunmaktadır.
