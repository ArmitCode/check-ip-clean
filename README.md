# IP Connectivity Checker - Iran Access Test

<div align="center">

🔍 **بررسی جامع دسترسی IP سرور از ایران**

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)]()

[English](#english) | [فارسی](#persian)

</div>

---

<a name="persian"></a>
## 🇮🇷 فارسی

### 📋 معرفی

این ابزار پایتون برای **بررسی تمیزی و دسترسی IP سرور مجازی از داخل ایران** طراحی شده است. اگر سرور مجازی (VPS) خریداری کرده‌اید و می‌خواهید مطمئن شوید که IP آن از ایران فیلتر نیست و پورت‌های TCP/UDP به درستی کار می‌کنند، این ابزار دقیقاً همان چیزی است که نیاز دارید.

### ✨ ویژگی‌ها

| تست | توضیحات | وضعیت |
|-----|---------|-------|
| **TCP** | اتصال به 14 پورت رایج (80, 443, 22, 25, 53, 8080 و...) | ✅ |
| **UDP** | تست DNS روی پورت 53 و UDP روی پورت‌های دیگر | ✅ |
| **Ping** | 10 بسته ICMP با محاسبه میانگین تاخیر | ✅ |
| **DNS** | بررسی Reverse DNS و تست با DNS سرورهای ایران | ✅ |
| **HTTP/HTTPS** | تست دسترسی وب روی پورت 80 و 443 | ✅ |
| **Traceroute** | بررسی مسیر شبکه تا IP شما | ✅ |
| **MTU** | تست اندازه بهینه بسته (مهم برای VPN) | ✅ |
| **Download** | تست سرعت دانلود | ✅ |

### 🚀 نصب سریع

```bash
# کلون کردن ریپوزیتوری
git clone https://github.com/yourusername/ip-checker-iran.git
cd ip-checker-iran

# نصب پیش‌نیازها
pip install -r requirements.txt
```

### 🎮 نحوه استفاده

#### روش 1: ورودی تعاملی (توصیه می‌شود)
```bash
python3 ip_checker_iran.py
```
سپس IP سرور را وارد کنید یا Enter بزنید برای تشخیص خودکار.

#### روش 2: آرگومان خط فرمان
```bash
python3 ip_checker_iran.py 185.123.456.78
```

#### روش 3: IP ثابت در کد
در فایل `ip_checker_iran.py`، متغیر `TARGET_IP` را تنظیم کنید:
```python
TARGET_IP = "185.123.456.78"
```

### 📊 نمونه خروجی

```
============================================================
🔌 تست اتصال TCP (TCP Connection Test)
============================================================
  هدف: 185.123.456.78
  پورت‌های تست: 80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443, 3389, 5900

  ✅ Port 80 - Connected (45.2ms)
  ✅ Port 443 - Connected (48.1ms)
  ❌ Port 22 - Connection refused
  ...

============================================================
📋 گزارش نهایی (Final Report)
============================================================

  IP مورد بررسی: 185.123.456.78
  زمان بررسی: 2026-06-03 18:30:00

  TCP: 8/14 پورت باز و قابل دسترسی
  UDP: 1/4 پورت پاسخ داد
  Ping: 10/10 received, Loss: 0%, Avg: 85.3ms

  ✅ IP شما از نظر اتصال TCP/UDP و Ping در وضعیت خوبی است.
     دسترسی از ایران به نظر می‌رسد بدون مشکل باشد.
```

### ⚠️ نکات مهم

- **این اسکریپت را باید از داخل ایران اجرا کنید** (نه روی سرور مجازی خودتان). برای تست واقعی، به یک سرور/ماشین مجازی در ایران نیاز دارید یا از اینترنت خانگی/موبایل ایرانی استفاده کنید.
- **Ping مسدود است؟** نگران نباشید! خیلی از ISPهای ایران ICMP را فیلتر می‌کنند. مهم این است که **TCP پورت 443 یا 80** باز باشد.
- **برای VPN:** اگر می‌خواهید VPN راه بیندازید، پورت‌های **UDP 443** (QUIC/WireGuard) یا **UDP 51820** (WireGuard) باید تست شوند.
- **تست از چند ISP:** تست را از چندین ISP ایرانی (همراه اول، ایرانسل، مخابرات، شاتل) تکرار کنید تا نتیجه دقیق‌تر شود.

### 🔧 پیش‌نیازها

- Python 3.7 یا بالاتر
- `requests` (برای تست HTTP/HTTPS)
- `dnspython` (برای تست DNS)
- دسترسی root/admin (برای ping و traceroute در بعضی سیستم‌ها)

### 📁 ساختار پروژه

```
ip-checker-iran/
├── ip_checker_iran.py    # فایل اصلی برنامه
├── requirements.txt       # پیش‌نیازهای پایتون
├── README.md             # همین فایل
└── LICENSE               # مجوز MIT
```

### 🤝 مشارکت

مشارکت شما خوشحالمان می‌کند! اگر ایده یا باگی دارید، Issue باز کنید یا Pull Request بفرستید.

### 📜 مجوز

این پروژه تحت مجوز **MIT** منتشر شده است. برای جزئیات بیشتر، فایل [LICENSE](LICENSE) را ببینید.

---

<a name="english"></a>
## 🇺🇸 English

### 📋 Introduction

This Python tool is designed to **check the accessibility and cleanliness of a VPS IP address from inside Iran**. If you have purchased a virtual server and want to make sure its IP is not filtered from Iran and TCP/UDP ports are working correctly, this tool is exactly what you need.

### ✨ Features

| Test | Description | Status |
|------|-------------|--------|
| **TCP** | Connection to 14 common ports (80, 443, 22, 25, 53, 8080, etc.) | ✅ |
| **UDP** | DNS test on port 53 and UDP on other ports | ✅ |
| **Ping** | 10 ICMP packets with average latency calculation | ✅ |
| **DNS** | Reverse DNS check and test with Iranian DNS servers | ✅ |
| **HTTP/HTTPS** | Web accessibility test on ports 80 and 443 | ✅ |
| **Traceroute** | Network path check to your IP | ✅ |
| **MTU** | Optimal packet size test (important for VPN) | ✅ |
| **Download** | Download speed test | ✅ |

### 🚀 Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/ip-checker-iran.git
cd ip-checker-iran

# Install dependencies
pip install -r requirements.txt
```

### 🎮 Usage

#### Method 1: Interactive Input (Recommended)
```bash
python3 ip_checker_iran.py
```
Then enter the server IP or press Enter for auto-detection.

#### Method 2: Command Line Argument
```bash
python3 ip_checker_iran.py 185.123.456.78
```

#### Method 3: Fixed IP in Code
In `ip_checker_iran.py`, set the `TARGET_IP` variable:
```python
TARGET_IP = "185.123.456.78"
```

### 📊 Sample Output

```
============================================================
🔌 TCP Connection Test
============================================================
  Target: 185.123.456.78
  Test ports: 80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443, 3389, 5900

  ✅ Port 80 - Connected (45.2ms)
  ✅ Port 443 - Connected (48.1ms)
  ❌ Port 22 - Connection refused
  ...

============================================================
📋 Final Report
============================================================

  Target IP: 185.123.456.78
  Check time: 2026-06-03 18:30:00

  TCP: 8/14 ports open and accessible
  UDP: 1/4 ports responded
  Ping: 10/10 received, Loss: 0%, Avg: 85.3ms

  ✅ Your IP is in good condition regarding TCP/UDP and Ping.
     Access from Iran appears to be without issues.
```

### ⚠️ Important Notes

- **You must run this script from inside Iran** (not on your VPS). For real testing, you need a server/VM in Iran or use Iranian home/mobile internet.
- **Ping blocked?** Don't worry! Many Iranian ISPs filter ICMP. What matters is that **TCP port 443 or 80** is open.
- **For VPN:** If you want to set up a VPN, ports **UDP 443** (QUIC/WireGuard) or **UDP 51820** (WireGuard) need to be tested.
- **Test from multiple ISPs:** Repeat the test from several Iranian ISPs (Hamrah Aval, Irancell, Mokhaberat, Shatel) for more accurate results.

### 🔧 Requirements

- Python 3.7 or higher
- `requests` (for HTTP/HTTPS testing)
- `dnspython` (for DNS testing)
- root/admin access (for ping and traceroute on some systems)

### 📁 Project Structure

```
ip-checker-iran/
├── ip_checker_iran.py    # Main program file
├── requirements.txt       # Python dependencies
├── README.md             # This file
└── LICENSE               # MIT License
```

### 🤝 Contributing

Contributions are welcome! If you have ideas or bugs, open an Issue or send a Pull Request.

### 📜 License

This project is released under the **MIT** License. For more details, see the [LICENSE](LICENSE) file.

---

<div align="center">

**Made with ❤️ for the Iranian tech community**

</div>
