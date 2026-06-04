#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Connectivity Checker - Iran Access Test
Comprehensive TCP/UDP/Ping/DNS/HTTP/Traceroute/MTU testing tool
to verify server accessibility from Iran.

Author: Community
License: MIT
Python: 3.7+
"""

import socket
import time
import struct
import random
import select
import subprocess
import sys
import concurrent.futures
from urllib.parse import urlparse
import ipaddress

# ==================== CONFIGURATION ====================
TARGET_IP = None  # Set to None to prompt user, or hardcode an IP
TARGET_PORTS_TCP = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443, 3389, 5900]
TARGET_PORTS_UDP = [53, 123, 161, 443]  # DNS, NTP, SNMP, QUIC
PING_COUNT = 10
TIMEOUT = 5

# Iranian DNS servers for testing
IRAN_DNS_SERVERS = [
    ("8.8.8.8", "Google DNS"),
    ("1.1.1.1", "Cloudflare DNS"),
    ("9.9.9.9", "Quad9 DNS"),
    ("185.51.200.2", "Shecan DNS"),
    ("178.22.122.100", "Electro DNS"),
    ("10.202.10.202", "Radar Game"),
    ("10.202.10.102", "Radar Game 2"),
]

# ==================== UTILITY FUNCTIONS ====================

def get_public_ip():
    """Detect public IP of the current machine"""
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
    """Add ANSI color to terminal text"""
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
    """Print a section header"""
    print(f"\n{colored('='*60, 'cyan')}")
    print(f"{colored(text, 'bold')}")
    print(f"{colored('='*60, 'cyan')}")

def print_result(label, status, detail=""):
    """Print a colored result line"""
    if status == "OK":
        icon = colored("[PASS]", "green")
        color = "green"
    elif status == "FAIL":
        icon = colored("[FAIL]", "red")
        color = "red"
    elif status == "WARN":
        icon = colored("[WARN]", "yellow")
        color = "yellow"
    else:
        icon = colored("[INFO]", "blue")
        color = "blue"

    print(f"  {icon} {colored(label, color)} {detail}")

def get_ip_from_user():
    """Prompt user for IP with validation"""
    while True:
        print(f"\n{colored('Please enter the server IP address:', 'bold')}")
        print(f"  {colored('Example:', 'cyan')} 185.123.456.78  or  192.168.1.1")
        print(f"  {colored('Leave empty and press Enter to auto-detect public IP.', 'yellow')}")
        print(f"  {colored('Type q or quit to exit.', 'red')}")
        print()

        user_input = input(f"{colored('IP >>> ', 'magenta')} ").strip()

        # Exit
        if user_input.lower() in ['q', 'quit', 'exit']:
            print(f"\n{colored('Goodbye!', 'cyan')}")
            sys.exit(0)

        # Auto-detect
        if not user_input:
            print(f"  {colored('Auto-detecting public IP...', 'yellow')}")
            ip = get_public_ip()
            if ip:
                confirm = input(f"  {colored('Detected IP:', 'green')} {ip} \n  Confirm? (y/n): ").strip().lower()
                if confirm in ['y', 'yes', '']:
                    return ip
                else:
                    continue
            else:
                print(f"  {colored('Error: Could not detect public IP.', 'red')}")
                continue

        # Validate IP
        try:
            ipaddress.ip_address(user_input)
            return user_input
        except ValueError:
            print(f"  {colored('Invalid IP address! Please try again.', 'red')}")
            continue

# ==================== TCP TESTS ====================

def test_tcp_port(ip, port, timeout=TIMEOUT):
    """Test TCP connection to a specific port"""
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
    """Test multiple TCP ports concurrently"""
    print_header("TCP Connection Test")
    print(f"  Target: {ip}")
    print(f"  Testing ports: {', '.join(map(str, ports))}")
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

# ==================== UDP TESTS ====================

def test_udp_dns(ip, port=53, timeout=TIMEOUT):
    """Test UDP by sending a DNS query"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Build a simple DNS query for google.com
        transaction_id = random.randint(0, 65535)
        flags = 0x0100  # Standard query
        questions = 1
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0

        header = struct.pack('!HHHHHH', transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs)

        domain = b'\x06google\x03com\x00'
        q_type = 1  # A record
        q_class = 1  # IN
        question = domain + struct.pack('!HH', q_type, q_class)

        packet = header + question

        start = time.time()
        sock.sendto(packet, (ip, port))

        ready, _, _ = select.select([sock], [], [], timeout)
        if ready:
            data, addr = sock.recvfrom(512)
            elapsed = (time.time() - start) * 1000
            sock.close()

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
    """Test UDP connection to a port"""
    if port == 53:
        return test_udp_dns(ip, port, timeout)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

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
    """Test multiple UDP ports"""
    print_header("UDP Connection Test")
    print(f"  Target: {ip}")
    print(f"  Testing ports: {', '.join(map(str, ports))}")
    print(f"  {colored('Note:', 'yellow')} UDP is connectionless. 'No response' may mean filtered or closed port.")
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

# ==================== PING TESTS ====================

def ping_host(ip, count=PING_COUNT, timeout=2):
    """Test ICMP ping"""
    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * timeout + 5)
        output = result.stdout + result.stderr

        if sys.platform == "win32":
            if "Received = 0" in output or "100% loss" in output:
                return False, "100% packet loss", None, None, output

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
            if "100% packet loss" in output or "0 received" in output:
                return False, "100% packet loss", None, None, output

            lines = output.split('\n')
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
    """Run ping test and display results"""
    print_header("ICMP Ping Test")
    print(f"  Target: {ip}")
    print(f"  Packets: {PING_COUNT}")
    print()

    success, detail, avg_time, time_range, raw_output = ping_host(ip, PING_COUNT)

    if success:
        min_time, max_time = time_range
        print_result("Ping Status", "OK", f"- {detail}")
        print(f"  {colored('Statistics:', 'cyan')}")
        print(f"     Average latency: {colored(f'{avg_time:.1f}ms', 'green')}")
        print(f"     Minimum latency: {colored(f'{min_time:.1f}ms', 'green')}")
        print(f"     Maximum latency: {colored(f'{max_time:.1f}ms', 'yellow')}")

        if avg_time < 50:
            quality = colored("Excellent", "green")
        elif avg_time < 100:
            quality = colored("Good", "green")
        elif avg_time < 200:
            quality = colored("Average", "yellow")
        else:
            quality = colored("Poor", "red")

        print(f"     Connection quality: {quality}")
    else:
        print_result("Ping Status", "FAIL", f"- {detail}")
        print(f"  {colored('Warning:', 'yellow')} Ping may be blocked by Iranian ISPs due to ICMP filtering.")
        print(f"  This does NOT necessarily mean the IP is filtered - only ICMP might be blocked.")

    return success, detail, avg_time

# ==================== DNS TESTS ====================

def test_dns_resolution(ip):
    """Test DNS resolution capabilities"""
    print_header("DNS Resolution Test")
    print(f"  Checking Reverse DNS for {ip}")
    print()

    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print_result("Reverse DNS", "OK", f"- {hostname}")
    except socket.herror:
        print_result("Reverse DNS", "WARN", "- No PTR record found")
    except Exception as e:
        print_result("Reverse DNS", "FAIL", f"- {e}")

    print(f"\n  {colored('Testing DNS from various servers:', 'cyan')}")
    for dns_ip, dns_name in IRAN_DNS_SERVERS:
        try:
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

# ==================== HTTP/HTTPS TESTS ====================

def test_http_https(ip):
    """Test HTTP and HTTPS accessibility"""
    print_header("HTTP/HTTPS Accessibility Test")
    print(f"  Testing web access to {ip}")
    print()

    import requests

    # Test HTTP
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

    # Test HTTPS
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

# ==================== TRACEROUTE TESTS ====================

def test_traceroute(ip):
    """Test network path with traceroute"""
    print_header("Traceroute (Network Path)")
    print(f"  Tracing route to {ip}")
    print()

    try:
        if sys.platform == "win32":
            cmd = ["tracert", "-d", "-h", "15", ip]
        else:
            cmd = ["traceroute", "-n", "-m", "15", "-q", "1", "-w", "2", ip]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout

        hops = []
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            if sys.platform == "win32":
                if "  " in line and not line.startswith("Tracing"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].isdigit():
                        hop_num = parts[0]
                        hop_ip = parts[-1] if parts[-1] != "*" else "*"
                        hops.append((hop_num, hop_ip))
            else:
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

            if hops[-1][1] != "*" and len(hops) > 1:
                print(f"\n  {colored('[PASS]', 'green')} Destination reached at hop {hops[-1][0]}.")
            else:
                print(f"\n  {colored('[WARN]', 'yellow')} Path may be incomplete.")
        else:
            print(f"  {colored('Error parsing traceroute output', 'red')}")
            print(f"  Raw output:\n{output[:500]}")

    except FileNotFoundError:
        print(f"  {colored('[WARN] traceroute/tracert command not found.', 'yellow')}")
    except subprocess.TimeoutExpired:
        print(f"  {colored('[WARN] Traceroute timed out.', 'yellow')}")
    except Exception as e:
        print(f"  {colored(f'Error: {e}', 'red')}")

# ==================== MTU TESTS ====================

def test_mtu(ip):
    """Test Maximum Transmission Unit"""
    print_header("MTU (Maximum Transmission Unit) Test")
    print(f"  Testing optimal packet size to {ip}")
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
                print(f"  {colored('[FAIL]', 'red')} Size {size}: Fragmentation needed")
            elif result.returncode == 0 or ("Reply" in output or "bytes from" in output or "1 received" in output):
                print(f"  {colored('[PASS]', 'green')} Size {size}: OK (no fragmentation)")
                print(f"\n  {colored('[PASS] Optimal MTU:', 'green')} {size} bytes")
                break
            else:
                print(f"  {colored('[WARN]', 'yellow')} Size {size}: No response")
        except Exception as e:
            print(f"  {colored('[WARN]', 'yellow')} Size {size}: Error - {e}")
    else:
        print(f"\n  {colored('[WARN] MTU results inconclusive.', 'yellow')}")

# ==================== DOWNLOAD SPEED TESTS ====================

def test_download_speed(ip):
    """Test download speed from the IP"""
    print_header("Download Speed Test")
    print(f"  Testing download speed from {ip}")
    print()

    import requests

    test_urls = [
        f"http://{ip}/test.zip",
        f"http://speedtest.tele2.net/1MB.zip",
    ]

    for url in test_urls:
        try:
            start = time.time()
            response = requests.get(url, timeout=10, stream=True)
            total_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                total_size += len(chunk)
                if total_size > 5 * 1024 * 1024:
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

# ==================== FINAL REPORT ====================

def print_final_report(ip, tcp_results, udp_results, ping_success, ping_detail, ping_avg):
    """Print comprehensive final report"""
    print_header("FINAL REPORT")

    print(f"\n  {colored('Target IP:', 'bold')} {ip}")
    print(f"  {colored('Check time:', 'bold')} {time.strftime('%Y-%m-%d %H:%M:%S')}")

    tcp_ok = sum(1 for v in tcp_results.values() if v[0])
    tcp_total = len(tcp_results)
    print(f"\n  {colored('TCP:', 'cyan')} {tcp_ok}/{tcp_total} ports open and accessible")

    udp_ok = sum(1 for v in udp_results.values() if v[0])
    udp_total = len(udp_results)
    print(f"  {colored('UDP:', 'cyan')} {udp_ok}/{udp_total} ports responded")

    if ping_success:
        print(f"  {colored('Ping:', 'cyan')} {ping_detail}, Avg: {ping_avg:.1f}ms")
    else:
        print(f"  {colored('Ping:', 'cyan')} {ping_detail}")

    print(f"\n  {colored('Conclusion for Iran access:', 'bold')}")

    issues = []
    warnings = []

    if tcp_ok == 0:
        issues.append("No TCP ports accessible - IP is likely FILTERED from Iran!")
    elif tcp_ok < 3:
        warnings.append("Very few TCP ports accessible.")

    if not ping_success:
        warnings.append("Ping not responding (ICMP may be filtered).")
    elif ping_avg and ping_avg > 300:
        warnings.append(f"High latency ({ping_avg:.0f}ms) - connection quality may be poor.")

    if issues:
        print(f"\n  {colored('CRITICAL ISSUES:', 'red')}")
        for issue in issues:
            print(f"     - {issue}")

    if warnings:
        print(f"\n  {colored('WARNINGS:', 'yellow')}")
        for warning in warnings:
            print(f"     - {warning}")

    if not issues and not warnings:
        print(f"\n  {colored('[PASS] Your IP is in good condition for TCP/UDP and Ping.', 'green')}")
        print(f"  {colored('     Access from Iran appears to be without issues.', 'green')}")
    elif not issues:
        print(f"\n  {colored('[WARN] Your IP is accessible but there are some concerns.', 'yellow')}")

    print(f"\n  {colored('Tips:', 'cyan')}")
    print(f"     - ICMP filtering (Ping) is common and does NOT mean the IP is filtered.")
    print(f"     - If specific ports (like 443, 80) are open, the IP is usable for web/VPN.")
    print(f"     - For VPN, UDP ports matter (e.g., 443, 51820 for WireGuard).")
    print(f"     - Repeat the test from multiple Iranian ISPs (Hamrah Aval, Irancell, etc.).")

# ==================== MAIN ====================

def main():
    print(f"{colored('\n' + '='*60, 'magenta')}")
    print(f"{colored('  IP Connectivity Checker - Iran Access Test', 'bold')}")
    print(f"{colored('  Comprehensive TCP/UDP/Ping/DNS/HTTP/Traceroute/MTU Tool', 'bold')}")
    print(f"{colored('='*60, 'magenta')}")

    # Get IP with priority: CLI arg -> TARGET_IP -> user input -> auto-detect
    ip = None

    # Priority 1: Command line argument
    if len(sys.argv) > 1:
        try:
            ipaddress.ip_address(sys.argv[1])
            ip = sys.argv[1]
            print(f"\n  [PASS] IP from command line argument: {ip}")
        except ValueError:
            print(f"\n  [FAIL] Invalid IP in argument: {sys.argv[1]}")
            sys.exit(1)

    # Priority 2: TARGET_IP in code
    elif TARGET_IP:
        ip = TARGET_IP
        print(f"\n  [PASS] IP from code settings: {ip}")

    # Priority 3: Interactive user input
    else:
        ip = get_ip_from_user()
        print(f"\n  [PASS] Selected IP: {ip}")

    # Run all tests
    tcp_results = test_tcp_ports(ip, TARGET_PORTS_TCP)
    udp_results = test_udp_ports(ip, TARGET_PORTS_UDP)
    ping_success, ping_detail, ping_avg = test_ping(ip)
    test_dns_resolution(ip)
    test_http_https(ip)
    test_traceroute(ip)
    test_mtu(ip)
    test_download_speed(ip)

    # Final report
    print_final_report(ip, tcp_results, udp_results, ping_success, ping_detail, ping_avg)

    print(f"\n{colored('='*60, 'magenta')}")
    print(f"{colored('  Check completed.', 'bold')}")
    print(f"{colored('='*60, 'magenta')}")

if __name__ == "__main__":
    main()
