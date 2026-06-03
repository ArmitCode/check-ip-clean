#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Connectivity Checker - TCP/UDP/Ping Test for Iran Access
بررسی دسترسی IP سرور از ایران
"""

import socket
import time
import struct
import random
import select
import subprocess
import sys
import threading
import concurrent.futures
from urllib.parse import urlparse
import ipaddress

# ==================== تنظیمات ====================
TARGET_IP = None  # اگر None باشد، IP عمومی سرور را تشخیص می‌دهد
TARGET_PORTS_TCP = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443, 3389, 5900]
TARGET_PORTS_UDP = [53, 123, 161, 443]  # DNS, NTP, SNMP, QUIC
PING_COUNT = 10
TIMEOUT = 5

# لیست DNS سرورهای ایران برای تست
IRAN_DNS_SERVERS = [
    ("8.8.8.8", "Google DNS"),
    ("1.1.1.1", "Cloudflare DNS"),
    ("9.9.9.9", "Quad9 DNS"),
    ("185.51.200.2", "Shecan DNS"),
    ("178.22.122.100", "Electro DNS"),
    ("10.202.10.202", "Radar Game"),
    ("10.202.10.102", "Radar Game 2"),
]

# ==================== توابع کمکی ====================

def get_public_ip():
    """دریافت IP عمومی سرور"""
    import requests
    services = [
        "https://api.ipify.org?format=json",
        "https://httpbin.org/ip",
        "https://ip.seeip.org/json",
        "https://api.my-ip.io/ip.json"
    ]
    for service in services:
        try:
            response = requests.get(service, timeout=10)
            if response.status_code == 200:
                if 'ipify' in service or 'seeip' in service or 'my-ip' in service:
                    return response.json().get('ip')
                elif 'httpbin' in service:
                    return response.json().get('origin')
        except:
            continue
    return None

def colored(text, color):
    """افزودن رنگ به متن ترمینال"""
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'bold': '\033[1m',
        'reset': '\033[0m'
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

def print_header(text):
    """چاپ هدر بخش"""
    print(f"\n{colored('='*60, 'cyan')}")
    print(f"{colored(text, 'bold')}")
    print(f"{colored('='*60, 'cyan')}")

def print_result(label, status, detail=""):
    """چاپ نتیجه با رنگ"""
    if status == "OK":
        icon = colored("✅", "green")
        color = "green"
    elif status == "FAIL":
        icon = colored("❌", "red")
        color = "red"
    elif status == "WARN":
        icon = colored("⚠️", "yellow")
        color = "yellow"
    else:
        icon = colored("ℹ️", "blue")
        color = "blue"

    print(f"  {icon} {colored(label, color)} {detail}")

# ==================== تست TCP ====================

def test_tcp_port(ip, port, timeout=TIMEOUT):
    """تست اتصال TCP به یک پورت"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.time()
        result = sock.connect_ex((ip, port))
        elapsed = (time.time() - start) * 1000
        sock.close()

        if result == 0:
            return True, f"{elapsed:.1f}ms", elapsed
        else:
            return False, f"Connection refused/timeout (code: {result})", None
    except socket.timeout:
        return False, "Timeout", None
    except Exception as e:
        return False, str(e), None

def test_tcp_ports(ip, ports):
    """تست چندین پورت TCP"""
    print_header("🔌 تست اتصال TCP (TCP Connection Test)")
    print(f"  هدف: {ip}")
    print(f"  پورت‌های تست: {', '.join(map(str, ports))}")
    print()

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {executor.submit(test_tcp_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                success, detail, latency = future.result()
                results[port] = (success, detail, latency)
                if success:
                    print_result(f"Port {port}", "OK", f"- Connected ({detail})")
                else:
                    print_result(f"Port {port}", "FAIL", f"- {detail}")
            except Exception as e:
                results[port] = (False, str(e), None)
                print_result(f"Port {port}", "FAIL", f"- {e}")

    return results

# ==================== تست UDP ====================

def test_udp_dns(ip, port=53, timeout=TIMEOUT):
    """تست UDP با ارسال یک Query DNS"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # ساخت یک DNS Query ساده برای google.com
        transaction_id = random.randint(0, 65535)
        flags = 0x0100  # Standard query
        questions = 1
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0

        # Header
        header = struct.pack('!HHHHHH', transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs)

        # Question: google.com A
        domain = b'\x06google\x03com\x00'
        q_type = 1  # A record
        q_class = 1  # IN
        question = domain + struct.pack('!HH', q_type, q_class)

        packet = header + question

        start = time.time()
        sock.sendto(packet, (ip, port))

        # انتظار برای پاسخ
        ready, _, _ = select.select([sock], [], [], timeout)
        if ready:
            data, addr = sock.recvfrom(512)
            elapsed = (time.time() - start) * 1000
            sock.close()

            # بررسی اینکه پاسخ معتبر است
            if len(data) > 12:
                response_id = struct.unpack('!H', data[:2])[0]
                if response_id == transaction_id:
                    return True, f"DNS response received ({elapsed:.1f}ms)", elapsed
            return True, f"UDP response received ({elapsed:.1f}ms)", elapsed
        else:
            sock.close()
            return False, "No response (timeout)", None
    except socket.timeout:
        return False, "Timeout", None
    except Exception as e:
        return False, str(e), None

def test_udp_port(ip, port, timeout=TIMEOUT):
    """تست UDP به یک پورت"""
    if port == 53:
        return test_udp_dns(ip, port, timeout)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # ارسال یک بسته داده ساده
        message = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        start = time.time()
        sock.sendto(message, (ip, port))

        ready, _, _ = select.select([sock], [], [], timeout)
        if ready:
            data, addr = sock.recvfrom(1024)
            elapsed = (time.time() - start) * 1000
            sock.close()
            return True, f"UDP response received ({elapsed:.1f}ms)", elapsed
        else:
            sock.close()
            return False, "No response (timeout) - Port may be filtered or closed", None
    except socket.timeout:
        return False, "Timeout", None
    except Exception as e:
        return False, str(e), None

def test_udp_ports(ip, ports):
    """تست چندین پورت UDP"""
    print_header("📡 تست اتصال UDP (UDP Connection Test)")
    print(f"  هدف: {ip}")
    print(f"  پورت‌های تست: {', '.join(map(str, ports))}")
    print(f"  {colored('نکته:', 'yellow')} UDP connectionless است. 'No response' به معنای فیلتر یا بسته بودن پورت است.")
    print()

    results = {}
    for port in ports:
        success, detail, latency = test_udp_port(ip, port)
        results[port] = (success, detail, latency)
        if success:
            print_result(f"Port {port}", "OK", f"- {detail}")
        else:
            print_result(f"Port {port}", "WARN", f"- {detail}")

    return results

# ==================== تست Ping ====================

def ping_host(ip, count=PING_COUNT, timeout=2):
    """تست ping با استفاده از پروتکل ICMP"""
    try:
        # استفاده از subprocess برای ping سیستمی
        if sys.platform == "win32":
            cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * timeout + 5)
        output = result.stdout + result.stderr

        # Parse ping statistics
        if sys.platform == "win32":
            # Windows parsing
            if "Received = 0" in output or "100% loss" in output:
                return False, "100% packet loss", None, None, output

            # Extract times
            times = []
            for line in output.split('\n'):
                if "time=" in line or "time<" in line:
                    try:
                        if "time<" in line:
                            times.append(0.1)
                        else:
                            time_str = line.split("time=")[1].split("ms")[0].strip()
                            times.append(float(time_str))
                    except:
                        pass

            if times:
                avg_time = sum(times) / len(times)
                min_time = min(times)
                max_time = max(times)
                loss = (count - len(times)) / count * 100
                return True, f"{len(times)}/{count} received, Loss: {loss:.0f}%", avg_time, (min_time, max_time), output
            else:
                return False, "No response received", None, None, output
        else:
            # Linux/Unix parsing
            if "100% packet loss" in output or "0 received" in output:
                return False, "100% packet loss", None, None, output

            # Extract statistics from last line
            lines = output.split('\n')
            stats_line = None
            for line in lines:
                if "rtt min/avg/max" in line or "round-trip" in line:
                    stats_line = line
                    break

            times = []
            for line in lines:
                if "time=" in line:
                    try:
                        time_str = line.split("time=")[1].split(" ")[0].strip()
                        times.append(float(time_str))
                    except:
                        pass

            if times:
                avg_time = sum(times) / len(times)
                min_time = min(times)
                max_time = max(times)
                loss = (count - len(times)) / count * 100
                return True, f"{len(times)}/{count} received, Loss: {loss:.0f}%", avg_time, (min_time, max_time), output
            else:
                return False, "No response received", None, None, output

    except subprocess.TimeoutExpired:
        return False, "Ping command timed out", None, None, ""
    except FileNotFoundError:
        return False, "ping command not found", None, None, ""
    except Exception as e:
        return False, str(e), None, None, ""

def test_ping(ip):
    """تست ping"""
    print_header("🏓 تست Ping (ICMP)")
    print(f"  هدف: {ip}")
    print(f"  تعداد بسته‌ها: {PING_COUNT}")
    print()

    success, detail, avg_time, time_range, raw_output = ping_host(ip, PING_COUNT)

    if success:
        min_time, max_time = time_range
        print_result("Ping Status", "OK", f"- {detail}")
        print(f"  {colored('📊 آمار:', 'cyan')}")
        print(f"     میانگین تاخیر: {colored(f'{avg_time:.1f}ms', 'green')}")
        print(f"     حداقل تاخیر: {colored(f'{min_time:.1f}ms', 'green')}")
        print(f"     حداکثر تاخیر: {colored(f'{max_time:.1f}ms', 'yellow')}")

        if avg_time < 50:
            quality = colored("عالی (Excellent)", "green")
        elif avg_time < 100:
            quality = colored("خوب (Good)", "green")
        elif avg_time < 200:
            quality = colored("متوسط (Average)", "yellow")
        else:
            quality = colored("ضعیف (Poor)", "red")

        print(f"     کیفیت اتصال: {quality}")
    else:
        print_result("Ping Status", "FAIL", f"- {detail}")
        print(f"  {colored('⚠️ هشدار:', 'yellow')} Ping از ایران ممکن است به دلیل فیلترینگ ICMP مسدود شود.")
        print(f"  این به معنای فیلتر IP نیست، بلکه ممکن است فقط ICMP مسدود باشد.")

    return success, detail, avg_time

# ==================== تست DNS Resolution ====================

def test_dns_resolution(ip):
    """تست اینکه IP از طریق DNS قابل resolve است"""
    print_header("🔍 تست DNS Resolution")
    print(f"  بررسی Reverse DNS برای {ip}")
    print()

    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print_result("Reverse DNS", "OK", f"- {hostname}")
    except socket.herror:
        print_result("Reverse DNS", "WARN", "- No PTR record found")
    except Exception as e:
        print_result("Reverse DNS", "FAIL", f"- {e}")

    # تست DNS از سرورهای ایران
    print(f"\n  {colored('تست DNS از سرورهای مختلف:', 'cyan')}")
    for dns_ip, dns_name in IRAN_DNS_SERVERS:
        try:
            # استفاده از dig یا nslookup
            if sys.platform == "win32":
                cmd = ["nslookup", "google.com", dns_ip]
            else:
                cmd = ["dig", "@" + dns_ip, "google.com", "+short"]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0 or "Address" in result.stdout:
                print_result(f"DNS {dns_name} ({dns_ip})", "OK", "- Responding")
            else:
                print_result(f"DNS {dns_name} ({dns_ip})", "FAIL", "- Not responding")
        except Exception as e:
            print_result(f"DNS {dns_name} ({dns_ip})", "FAIL", f"- {e}")

# ==================== تست HTTP/HTTPS ====================

def test_http_https(ip):
    """تست دسترسی HTTP/HTTPS"""
    print_header("🌐 تست HTTP/HTTPS")
    print(f"  بررسی دسترسی وب به IP {ip}")
    print()

    import requests

    # تست HTTP
    try:
        url = f"http://{ip}"
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
        print_result("HTTP (Port 80)", "OK", f"- Status: {response.status_code}, Time: {response.elapsed.total_seconds()*1000:.1f}ms")
    except requests.exceptions.ConnectionError:
        print_result("HTTP (Port 80)", "FAIL", "- Connection refused/timeout")
    except requests.exceptions.Timeout:
        print_result("HTTP (Port 80)", "FAIL", "- Timeout")
    except Exception as e:
        print_result("HTTP (Port 80)", "FAIL", f"- {type(e).__name__}")

    # تست HTTPS
    try:
        url = f"https://{ip}"
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=False, verify=False)
        print_result("HTTPS (Port 443)", "OK", f"- Status: {response.status_code}, Time: {response.elapsed.total_seconds()*1000:.1f}ms")
    except requests.exceptions.SSLError:
        print_result("HTTPS (Port 443)", "WARN", "- SSL Error (certificate issue)")
    except requests.exceptions.ConnectionError:
        print_result("HTTPS (Port 443)", "FAIL", "- Connection refused/timeout")
    except requests.exceptions.Timeout:
        print_result("HTTPS (Port 443)", "FAIL", "- Timeout")
    except Exception as e:
        print_result("HTTPS (Port 443)", "FAIL", f"- {type(e).__name__}")

# ==================== تست Traceroute ====================

def test_traceroute(ip):
    """تست traceroute"""
    print_header("🛤️ تست Traceroute (مسیر شبکه)")
    print(f"  بررسی مسیر تا {ip}")
    print()

    try:
        if sys.platform == "win32":
            cmd = ["tracert", "-d", "-h", "15", ip]
        else:
            cmd = ["traceroute", "-n", "-m", "15", "-q", "1", "-w", "2", ip]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout

        # Parse hops
        hops = []
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Extract hop number and IP
            if sys.platform == "win32":
                # Windows format
                if "  " in line and not line.startswith("Tracing"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].isdigit():
                        hop_num = parts[0]
                        hop_ip = parts[-1] if parts[-1] != "*" else "*"
                        hops.append((hop_num, hop_ip))
            else:
                # Linux format
                parts = line.split()
                if len(parts) >= 2 and parts[0].isdigit():
                    hop_num = parts[0]
                    hop_ip = parts[1] if parts[1] != "*" else "*"
                    hops.append((hop_num, hop_ip))

        if hops:
            print(f"  {colored('Hop', 'cyan')}    {colored('IP Address', 'cyan')}")
            print(f"  {colored('---', 'cyan')}    {colored('----------', 'cyan')}")
            for hop_num, hop_ip in hops[:15]:
                if hop_ip == "*":
                    print(f"  {hop_num:3}    {colored('* * * (timeout)', 'yellow')}")
                else:
                    print(f"  {hop_num:3}    {hop_ip}")

            # Check if destination reached
            if hops[-1][1] != "*" and len(hops) > 1:
                print(f"\n  {colored('✅ مقصد در hop', 'green')} {hops[-1][0]} {colored('قابل دسترسی است.', 'green')}")
            else:
                print(f"\n  {colored('⚠️ ممکن است مسیر ناقص باشد.', 'yellow')}")
        else:
            print(f"  {colored('خطا در parse خروجی traceroute', 'red')}")
            print(f"  خروجی خام:\n{output[:500]}")

    except FileNotFoundError:
        print(f"  {colored('⚠️ دستور traceroute/tracert یافت نشد.', 'yellow')}")
    except subprocess.TimeoutExpired:
        print(f"  {colored('⏱️ Traceroute timeout', 'yellow')}")
    except Exception as e:
        print(f"  {colored(f'خطا: {e}', 'red')}")

# ==================== تست MTU ====================

def test_mtu(ip):
    """تست Maximum Transmission Unit"""
    print_header("📦 تست MTU (Maximum Transmission Unit)")
    print(f"  بررسی اندازه بسته‌های قابل ارسال به {ip}")
    print()

    sizes = [1500, 1472, 1400, 1300, 1200, 1000, 800, 576]

    for size in sizes:
        try:
            if sys.platform == "win32":
                cmd = ["ping", "-n", "1", "-f", "-l", str(size - 28), "-w", "3000", ip]
            else:
                cmd = ["ping", "-c", "1", "-M", "do", "-s", str(size - 28), "-W", "3", ip]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr

            if "Fragmentation needed" in output or "MTU" in output or "too long" in output or "Packet needs to be fragmented" in output:
                print(f"  {colored('❌', 'red')} Size {size}: Fragmentation needed")
            elif result.returncode == 0 or ("Reply" in output or "bytes from" in output or "1 received" in output):
                print(f"  {colored('✅', 'green')} Size {size}: OK (no fragmentation)")
                print(f"\n  {colored('✅ MTU بهینه:', 'green')} {size} bytes")
                break
            else:
                print(f"  {colored('⚠️', 'yellow')} Size {size}: No response")
        except Exception as e:
            print(f"  {colored('⚠️', 'yellow')} Size {size}: Error - {e}")
    else:
        print(f"\n  {colored('⚠️ نتایج MTU نامشخص.', 'yellow')}")

# ==================== تست سرعت دانلود ====================

def test_download_speed(ip):
    """تست سرعت دانلود از IP"""
    print_header("⚡ تست سرعت دانلود (Download Speed)")
    print(f"  بررسی سرعت دانلود از {ip}")
    print()

    import requests

    # تست با یک فایل کوچک (1MB test file)
    test_urls = [
        f"http://{ip}/test.zip",
        f"http://speedtest.tele2.net/1MB.zip",  # fallback
    ]

    for url in test_urls:
        try:
            start = time.time()
            response = requests.get(url, timeout=10, stream=True)
            total_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                total_size += len(chunk)
                if total_size > 5 * 1024 * 1024:  # Max 5MB
                    break
            elapsed = time.time() - start

            if total_size > 0 and elapsed > 0:
                speed_mbps = (total_size * 8) / (elapsed * 1024 * 1024)
                print_result(f"Download from {url}", "OK", f"- {speed_mbps:.2f} Mbps ({total_size/1024:.0f} KB in {elapsed:.1f}s)")
                return speed_mbps
            else:
                print_result(f"Download from {url}", "FAIL", "- No data received")
        except Exception as e:
            print_result(f"Download from {url}", "FAIL", f"- {type(e).__name__}")

    return None

# ==================== گزارش نهایی ====================

def print_final_report(ip, tcp_results, udp_results, ping_success, ping_detail, ping_avg):
    """چاپ گزارش نهایی"""
    print_header("📋 گزارش نهایی (Final Report)")

    print(f"\n  {colored('IP مورد بررسی:', 'bold')} {ip}")
    print(f"  {colored('زمان بررسی:', 'bold')} {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # TCP Summary
    tcp_ok = sum(1 for v in tcp_results.values() if v[0])
    tcp_total = len(tcp_results)
    print(f"\n  {colored('TCP:', 'cyan')} {tcp_ok}/{tcp_total} پورت باز و قابل دسترسی")

    # UDP Summary
    udp_ok = sum(1 for v in udp_results.values() if v[0])
    udp_total = len(udp_results)
    print(f"  {colored('UDP:', 'cyan')} {udp_ok}/{udp_total} پورت پاسخ داد")

    # Ping Summary
    if ping_success:
        print(f"  {colored('Ping:', 'cyan')} {ping_detail}, Avg: {ping_avg:.1f}ms")
    else:
        print(f"  {colored('Ping:', 'cyan')} {ping_detail}")

    # نتیجه‌گیری
    print(f"\n  {colored('نتیجه‌گیری برای دسترسی از ایران:', 'bold')}")

    issues = []
    warnings = []

    if tcp_ok == 0:
        issues.append("هیچ پورت TCP قابل دسترسی نیست - IP احتمالاً فیلتر شده است!")
    elif tcp_ok < 3:
        warnings.append("تعداد پورت‌های TCP قابل دسترسی کم است.")

    if not ping_success:
        warnings.append("Ping پاسخ نمی‌دهد (ممکن است ICMP فیلتر باشد).")
    elif ping_avg and ping_avg > 300:
        warnings.append(f"تاخیر بالا ({ping_avg:.0f}ms) - ممکن است کیفیت اتصال پایین باشد.")

    if issues:
        print(f"\n  {colored('❌ مشکلات جدی:', 'red')}")
        for issue in issues:
            print(f"     - {issue}")

    if warnings:
        print(f"\n  {colored('⚠️ هشدارها:', 'yellow')}")
        for warning in warnings:
            print(f"     - {warning}")

    if not issues and not warnings:
        print(f"\n  {colored('✅ IP شما از نظر اتصال TCP/UDP و Ping در وضعیت خوبی است.', 'green')}")
        print(f"  {colored('   دسترسی از ایران به نظر می‌رسد بدون مشکل باشد.', 'green')}")
    elif not issues:
        print(f"\n  {colored('⚠️ IP شما قابل دسترسی است اما چند نکته وجود دارد.', 'yellow')}")

    print(f"\n  {colored('💡 نکات:', 'cyan')}")
    print(f"     - فیلترینگ ICMP (Ping) رایج است و به معنای فیلتر IP نیست.")
    print(f"     - اگر پورت‌های خاصی (مثل 443, 80) باز هستند، IP برای وب/VPN قابل استفاده است.")
    print(f"     - برای VPN، پورت‌های UDP مهم هستند (مثل 443, 51820 برای WireGuard).")
    print(f"     - تست را از چندین ISP ایرانی (همراه اول، ایرانسل، مخابرات) تکرار کنید.")

# ==================== main ====================

def main():
    print(f"{colored('\n' + '='*60, 'magenta')}")
    print(f"{colored('  IP Connectivity Checker - Iran Access Test', 'bold')}")
    print(f"{colored('  بررسی دسترسی IP از ایران', 'bold')}")
    print(f"{colored('='*60, 'magenta')}")

    # دریافت IP
    if TARGET_IP:
        ip = TARGET_IP
        print(f"\n  IP تنظیم‌شده: {ip}")
    else:
        print(f"\n  در حال تشخیص IP عمومی سرور...")
        ip = get_public_ip()
        if ip:
            print(f"  ✅ IP شناسایی شد: {ip}")
        else:
            print(f"  ❌ خطا در تشخیص IP. لطفاً IP را به صورت دستی وارد کنید.")
            print(f"  نحوه استفاده: python3 script.py <IP_ADDRESS>")
            sys.exit(1)

    # تست‌ها
    tcp_results = test_tcp_ports(ip, TARGET_PORTS_TCP)
    udp_results = test_udp_ports(ip, TARGET_PORTS_UDP)
    ping_success, ping_detail, ping_avg = test_ping(ip)
    test_dns_resolution(ip)
    test_http_https(ip)
    test_traceroute(ip)
    test_mtu(ip)
    test_download_speed(ip)

    # گزارش نهایی
    print_final_report(ip, tcp_results, udp_results, ping_success, ping_detail, ping_avg)

    print(f"\n{colored('='*60, 'magenta')}")
    print(f"{colored('  بررسی به پایان رسید.', 'bold')}")
    print(f"{colored('='*60, 'magenta')}")

if __name__ == "__main__":
    # اگر IP به عنوان آرگومان داده شده
    if len(sys.argv) > 1:
        try:
            ipaddress.ip_address(sys.argv[1])
            TARGET_IP = sys.argv[1]
        except ValueError:
            print(f"❌ IP نامعتبر: {sys.argv[1]}")
            sys.exit(1)

    main()
