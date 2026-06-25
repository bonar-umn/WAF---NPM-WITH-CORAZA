# WAF - NGINX PROXY MANAGER DENGAN CORAZA WAF
Prosedur ini menyediakan panduan untuk menggabungkan Nginx Proxy Manager (NPM) bersama Coraza WAF (Web Application Firewall) menggunakan OWASP Core Rule Set (CRS) bagi melindungi aplikasi web daripada pelbagai ancaman keselamatan seperti serangan SQL Injection (SQLi) dan Cross-Site Scripting (XSS).

## 🚀 Struktur Direktori Projek
```
WAFNPM/
├── CORAZA/                 # Konfigurasi dan fail berkaitan Coraza WAF
├── NPM/                    # Konfigurasi Nginx Proxy Manager
├── custom-rules/           # direktori aturan tersuai
│   └── custom.conf         # Fail konfigurasi aturan WAF tambahan
├── docker-compose.yml      # Fail orkestrasi perkhidmatan Docker
└── coraza-monitor.sh       # Skrip pemantauan log Coraza WAF
```

## Architecture

```
        Internet
           │
           ▼
  ┌─────────────────────┐      ┌──────────────────────────┐
  │  Coraza             │ ───► │  Your protected upstream │
  │  WAF engine (8090)  │      │  app(s)                  │
  └─────────────────────┘      └──────────────────────────┘
           ▲  
           │
  ┌─────────────────────┐    ┌────────────┐
  │ Nginx Proxy Manager │ ◄─►│ Route      │
  │  (81, internal)     │    └────────────┘
  └─────────────────────┘
           ▲
           │
  ┌─────────────────────┐
  │       APPS          │   
  │                     │
  └─────────────────────┘
```
