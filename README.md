# ⚫ Thanálink – OSINT Intelligence Platform

> **Author:** Leonardo Teixeira Parchão  
> **Version:** 1.7  
> **License:** MIT  
> **Date:** 30/07/2025

**Thanálink** is a Python-based Open Source Intelligence (OSINT) platform designed to trace and reveal digital footprints across multiple vectors. Named after *Thanatos*, the Greek personification of death, Thanálink follows quiet, fatal connections in open data — where every link might lead to revelation.

Built for ethical hackers, security researchers, investigative journalists, and digital sleuths.

---

## 🕵️‍♂️ Features

### 📧 Email OSINT
- Breach lookup via [HaveIBeenPwned](https://haveibeenpwned.com/)
- MX record & SMTP validation
- Associated link discovery via public username directories

### 🌐 Domain Intelligence
- WHOIS lookup
- Subdomain enumeration
- Lightweight port scanner (top common ports)

### 🧍 Username Search
- Profile presence check across:
  - GitHub
  - Twitter
  - Instagram
  - Facebook
  - Reddit
  - Twitch

### 📄 Document Scanner
- Metadata extraction from PDFs and images (EXIF, PDF meta)
- Email, domain, and URL harvesting from PDF content

### 🔍 Google Dorking (with Selenium)
- Headless Google search automation
- Supports filetype and domain filtering
- Exportable result list

### 🖥️ Interface & Architecture
- PyQt5-based GUI (tabbed interface)
- Asynchronous worker threads
- Integrated progress feedback
- Modular and extendable design

---

## 🎯 Use Cases

- Red teaming & penetration testing
- Threat intelligence gathering
- OSINT training & research
- Doxxing defense (personal threat assessment)
- Investigative journalism

---

## 🚀 Getting Started

### ✅ Prerequisites

- Python 3.8+
- Google Chrome (for Selenium headless browsing)

### 📦 Installation

```bash
git clone https://github.com/your-username/Thanalink.git
cd Thanalink
pip install -r requirements.txt
```
