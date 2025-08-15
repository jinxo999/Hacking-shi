# 1599 TOOL - Ultimate Multi-Tool Console Application
# Made by Lethal
# Advanced ethical hacking and utility tool for educational purposes only.
# Run: `python 1599_tool.py` in CMD after installing dependencies (`pip install -r requirements.txt`).
# EXE: `pyinstaller --onefile 1599_tool.py` after installing pyinstaller.

import os
import sys
import subprocess
import socket
import requests
import hashlib
import base64
import string
import re
import random
import json
import platform
import psutil
import glob
from time import sleep
from urllib.parse import urlparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import zipfile
import shutil
import datetime
import webbrowser

# For colors in console
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Colorama not installed. Colors may not work.")
    Fore = Style = lambda x: ''  # Dummy if not installed

# Updated ASCII Art for 1599 TOOL
ASCII_ART = f"""
{Fore.CYAN + Style.BRIGHT}
  __ _____ ___   ___  
 /_ | ____/ _ \ / _ \ 
  | | |__| (_) | (_) |
  | |___ \\__, |\__, |
  | |___) | / /   / / 
  |_|____/ /_/   /_/  
                      
{Fore.RESET}
"""

# Function to clear screen
def clear_screen():
    os.system('chcp 65001 >nul')
    os.system('cls' if os.name == 'nt' else 'clear')
    # Ensure black background
    os.system('color 0f')

# Function to display menu with enhanced visuals
def display_menu(options, title):
    clear_screen()
    print("active code page: 65001")
    print(ASCII_ART)
    print(f"{Fore.WHITE + Style.BRIGHT}┌{'─' * 40}┐")
    print(f"{Fore.WHITE + Style.BRIGHT}│ {title.center(38)} │")
    print(f"{Fore.WHITE + Style.BRIGHT}└{'─' * 40}┘")
    for i, option in enumerate(options, 1):
        print(f"{Fore.WHITE + Style.BRIGHT}[{i}] {option}")
    print(f"{Fore.WHITE + Style.BRIGHT}[0] Back/Exit")
    print(f"{Fore.WHITE + Style.BRIGHT}{'─' * 42}")

# Network Tools (added more options)
def network_tools():
    options = ["Ping IP", "Get My IP", "Traceroute", "Advanced Port Scan", "DNS Lookup", "WHOIS Lookup", "HTTP Headers", "WiFi Networks (Basic)", "Check Network Speed (Placeholder)", "ARP Spoofing Demo (Educational)"]
    while True:
        display_menu(options, "Network Tools (Cyber Security)")
        choice = input(f"{Fore.WHITE + Style.BRIGHT}Select option: {Fore.CYAN}")
        if choice == '1':
            ip = input(f"{Fore.WHITE + Style.BRIGHT}Enter IP to ping: {Fore.CYAN}")
            subprocess.call(['ping', '-c', '4', ip] if os.name != 'nt' else ['ping', ip])
            input(f"{Fore.WHITE + Style.BRIGHT}Press Enter to continue...")
        elif choice == '2':
            try:
                ip = requests.get('https://api.ipify.org').text
                print(f"{Fore.CYAN + Style.BRIGHT}Your IP: {ip}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Failed to get IP.")
            sleep(2)
        elif choice == '3':
            ip = input(f"{Fore.WHITE + Style.BRIGHT}Enter IP/Domain for traceroute: {Fore.CYAN}")
            subprocess.call(['tracert' if os.name == 'nt' else 'traceroute', ip])
            input(f"{Fore.WHITE + Style.BRIGHT}Press Enter to continue...")
        elif choice == '4':
            ip = input(f"{Fore.WHITE + Style.BRIGHT}Enter IP to scan (e.g., 192.168.1.1): {Fore.CYAN}")
            try:
                start_port = int(input(f"{Fore.WHITE + Style.BRIGHT}Start port (e.g., 1): {Fore.CYAN}"))
                end_port = int(input(f"{Fore.WHITE + Style.BRIGHT}End port (e.g., 1000): {Fore.CYAN}"))
                print(f"{Fore.CYAN + Style.BRIGHT}Scanning {ip} ports {start_port}-{end_port}...")
                for port in range(start_port, end_port + 1):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        print(f"{Fore.CYAN + Style.BRIGHT}Port {port}: Open")
                    sock.close()
                print(f"{Fore.CYAN + Style.BRIGHT}Scan complete.")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Invalid input or scan failed.")
            sleep(2)
        elif choice == '5':
            domain = input(f"{Fore.WHITE + Style.BRIGHT}Enter domain for DNS lookup: {Fore.CYAN}")
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                print(f"{Fore.CYAN + Style.BRIGHT}IPs for {domain}: {', '.join(ips)}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Failed to lookup DNS.")
            sleep(2)
        elif choice == '6':
            domain = input(f"{Fore.WHITE + Style.BRIGHT}Enter domain for WHOIS: {Fore.CYAN}")
            try:
                response = requests.get(f"https://api.whois.vu/?q={domain}")
                print(f"{Fore.CYAN + Style.BRIGHT}{response.text}" if response.status_code == 200 else f"{Fore.WHITE + Style.BRIGHT}WHOIS lookup failed.")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}WHOIS failed. Try online tools.")
            sleep(2)
        elif choice == '7':
            url = input(f"{Fore.WHITE + Style.BRIGHT}Enter URL (e.g., https://example.com): {Fore.CYAN}")
            try:
                response = requests.get(url, timeout=5)
                print(f"{Fore.CYAN + Style.BRIGHT}HTTP Headers:")
                for key, value in response.headers.items():
                    print(f"{Fore.CYAN + Style.BRIGHT}{key}: {value}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Failed to fetch headers.")
            sleep(2)
        elif choice == '8':
            print(f"{Fore.WHITE + Style.BRIGHT}Basic WiFi scan (Windows only; requires admin).")
            try:
                output = subprocess.check_output(['netsh', 'wlan', 'show', 'networks']).decode('utf-8')
                print(f"{Fore.CYAN + Style.BRIGHT}{output}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}WiFi scan failed or not supported.")
            sleep(2)
        elif choice == '9':
            print(f"{Fore.CYAN + Style.BRIGHT}Network speed test requires external tools like speedtest-cli. Use online services.")
            sleep(2)
        elif choice == '10':
            print(f"{Fore.CYAN + Style.BRIGHT}ARP Spoofing demo for educational purposes only. Do not use on unauthorized networks.")
            print(f"{Fore.CYAN + Style.BRIGHT}This would require scapy library and admin rights. Placeholder for learning.")
            sleep(2)
        elif choice == '0':
            break
        else:
            print(f"{Fore.WHITE + Style.BRIGHT}Invalid choice.")
            sleep(1)

# OSINT Tools (added more options)
def osint_tools():
    options = ["IP Geolocation", "Reverse DNS", "Email Verification", "Phone Lookup (Placeholder)", "Social Media Username Check", "Reverse Image Search (Placeholder)", "Breach Check (Placeholder)"]
    while True:
        display_menu(options, "OSINT Tools")
        choice = input(f"{Fore.WHITE + Style.BRIGHT}Select option: {Fore.CYAN}")
        if choice == '1':
            ip = input(f"{Fore.WHITE + Style.BRIGHT}Enter IP for geolocation (leave blank for your IP): {Fore.CYAN}")
            if not ip:
                try:
                    ip = requests.get('https://api.ipify.org').text
                except:
                    print(f"{Fore.WHITE + Style.BRIGHT}Failed to get your IP.")
                    sleep(2)
                    continue
            try:
                response = requests.get(f'https://ipapi.co/{ip}/json/')
                data = response.json()
                if 'error' in data:
                    print(f"{Fore.WHITE + Style.BRIGHT}Error: {data.get('reason', 'Unknown')}")
                else:
                    print(f"{Fore.CYAN + Style.BRIGHT}City: {data.get('city')}, Region: {data.get('region')}, Country: {data.get('country_name')}")
                    print(f"{Fore.CYAN + Style.BRIGHT}ISP: {data.get('org')}, Lat/Lon: {data.get('latitude')}/{data.get('longitude')}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Failed to get geolocation.")
            sleep(2)
        elif choice == '2':
            ip = input(f"{Fore.WHITE + Style.BRIGHT}Enter IP for reverse DNS: {Fore.CYAN}")
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"{Fore.CYAN + Style.BRIGHT}Hostname: {hostname}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}No hostname found.")
            sleep(2)
        elif choice == '3':
            email = input(f"{Fore.WHITE + Style.BRIGHT}Enter email to verify format: {Fore.CYAN}")
            if re.match(r"[^@]+@[^@]+\.[^@]+", email):
                print(f"{Fore.CYAN + Style.BRIGHT}Email format valid.")
            else:
                print(f"{Fore.WHITE + Style.BRIGHT}Invalid email format.")
            print(f"{Fore.WHITE + Style.BRIGHT}For real verification, use APIs like Hunter.io.")
            sleep(2)
        elif choice == '4':
            print(f"{Fore.WHITE + Style.BRIGHT}Phone lookups require paid APIs (e.g., Numverify). Use online tools.")
            sleep(2)
        elif choice == '5':
            username = input(f"{Fore.WHITE + Style.BRIGHT}Enter username to check on social media: {Fore.CYAN}")
            sites = ["twitter.com/", "instagram.com/", "github.com/", "linkedin.com/in/"]
            for site in sites:
                url = f"https://{site}{username}"
                try:
                    response = requests.head(url, timeout=5)
                    status = "Exists" if response.status_code < 400 else "Not Found"
                    print(f"{Fore.CYAN + Style.BRIGHT}{site}: {status}")
                except:
                    print(f"{Fore.WHITE + Style.BRIGHT}{site}: Error checking.")
            sleep(2)
        elif choice == '6':
            print(f"{Fore.WHITE + Style.BRIGHT}Reverse image search: Upload to Google or use APIs.")
            webbrowser.open('https://images.google.com/')
            sleep(2)
        elif choice == '7':
            print(f"{Fore.WHITE + Style.BRIGHT}Breach check: Use HaveIBeenPwned API.")
            email = input(f"{Fore.WHITE + Style.BRIGHT}Enter email: {Fore.CYAN}")
            webbrowser.open(f'https://haveibeenpwned.com/account/{email}')
            sleep(2)
        elif choice == '0':
            break
        else:
            print(f"{Fore.WHITE + Style.BRIGHT}Invalid choice.")
            sleep(1)

# Crypto Tools (added more options)
def crypto_tools():
    options = ["Base64 Encode/Decode", "Hash Generator (MD5/SHA256/SHA512)", "Vigenère Cipher", "Password Strength Checker", "AES Encrypt/Decrypt (File)", "ROT13 Cipher", "RSA Key Generator (Basic)"]
    while True:
        display_menu(options, "Crypto Tools")
        choice = input(f"{Fore.WHITE + Style.BRIGHT}Select option: {Fore.CYAN}")
        if choice == '1':
            action = input(f"{Fore.WHITE + Style.BRIGHT}Encode (e) or Decode (d)? {Fore.CYAN}")
            text = input(f"{Fore.WHITE + Style.BRIGHT}Enter text: {Fore.CYAN}")
            if action.lower() == 'e':
                print(f"{Fore.CYAN + Style.BRIGHT}{base64.b64encode(text.encode()).decode()}")
            elif action.lower() == 'd':
                try:
                    print(f"{Fore.CYAN + Style.BRIGHT}{base64.b64decode(text).decode()}")
                except:
                    print(f"{Fore.WHITE + Style.BRIGHT}Invalid Base64.")
            sleep(2)
        elif choice == '2':
            text = input(f"{Fore.WHITE + Style.BRIGHT}Enter text to hash: {Fore.CYAN}")
            print(f"{Fore.CYAN + Style.BRIGHT}MD5: {hashlib.md5(text.encode()).hexdigest()}")
            print(f"{Fore.CYAN + Style.BRIGHT}SHA256: {hashlib.sha256(text.encode()).hexdigest()}")
            print(f"{Fore.CYAN + Style.BRIGHT}SHA512: {hashlib.sha512(text.encode()).hexdigest()}")
            sleep(2)
        elif choice == '3':
            text = input(f"{Fore.WHITE + Style.BRIGHT}Enter text: {Fore.CYAN}")
            key = input(f"{Fore.WHITE + Style.BRIGHT}Enter key: {Fore.CYAN}")
            result = ""
            key = key.upper()
            key_idx = 0
            for c in text.upper():
                if c.isalpha():
                    result += chr((ord(c) - 65 + (ord(key[key_idx % len(key)]) - 65)) % 26 + 65)
                    key_idx += 1
                else:
                    result += c
            print(f"{Fore.CYAN + Style.BRIGHT}Encrypted: {result}")
            sleep(2)
        elif choice == '4':
            password = input(f"{Fore.WHITE + Style.BRIGHT}Enter password: {Fore.CYAN}")
            score = 0
            if len(password) > 12:
                score += 2
            elif len(password) > 8:
                score += 1
            if re.search(r"[A-Z]", password):
                score += 1
            if re.search(r"[a-z]", password):
                score += 1
            if re.search(r"\d", password):
                score += 1
            if re.search(r"[^A-Za-z0-9]", password):
                score += 1
            strength = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"][min(score, 4)]
            print(f"{Fore.CYAN + Style.BRIGHT}Password Strength: {strength}")
            sleep(2)
        elif choice == '5':
            action = input(f"{Fore.WHITE + Style.BRIGHT}Encrypt (e) or Decrypt (d) file? {Fore.CYAN}")
            file_path = input(f"{Fore.WHITE + Style.BRIGHT}Enter file path: {Fore.CYAN}")
            password = input(f"{Fore.WHITE + Style.BRIGHT}Enter password for key: {Fore.CYAN}").encode()
            salt = b'salt_'  # Simple salt; in real use, generate random
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(password))
            fernet = Fernet(key)
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                if action.lower() == 'e':
                    encrypted = fernet.encrypt(data)
                    with open(file_path + '.enc', 'wb') as f:
                        f.write(encrypted)
                    print(f"{Fore.CYAN + Style.BRIGHT}File encrypted to {file_path}.enc")
                elif action.lower() == 'd':
                    decrypted = fernet.decrypt(data)
                    with open(file_path + '.dec', 'wb') as f:
                        f.write(decrypted)
                    print(f"{Fore.CYAN + Style.BRIGHT}File decrypted to {file_path}.dec")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Encryption/Decryption failed.")
            sleep(2)
        elif choice == '6':
            text = input(f"{Fore.WHITE + Style.BRIGHT}Enter text for ROT13: {Fore.CYAN}")
            rot13 = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')
            print(f"{Fore.CYAN + Style.BRIGHT}{text.translate(rot13)}")
            sleep(2)
        elif choice == '7':
            print(f"{Fore.CYAN + Style.BRIGHT}Basic RSA key generation requires cryptography library enhancements. Placeholder.")
            sleep(2)
        elif choice == '0':
            break
        else:
            print(f"{Fore.WHITE + Style.BRIGHT}Invalid choice.")
            sleep(1)

# Recon Tools (added more)
def recon_tools():
    options = ["Subdomain Enumerator", "Directory Scanner", "SSL Certificate Checker", "Vulnerability Check (Basic)", "CMS Detection (Placeholder)", "Firewall Detection"]
    while True:
        display_menu(options, "Recon Tools")
        choice = input(f"{Fore.WHITE + Style.BRIGHT}Select option: {Fore.CYAN}")
        if choice == '1':
            domain = input(f"{Fore.WHITE + Style.BRIGHT}Enter domain (e.g., example.com): {Fore.CYAN}")
            subdomains = ["www", "mail", "ftp", "api", "dev", "test", "staging", "blog", "shop", "forum"]
            found = []
            for sub in subdomains:
                try:
                    full_domain = f"{sub}.{domain}"
                    ips = socket.gethostbyname_ex(full_domain)[2]
                    found.append(full_domain)
                except:
                    continue
            if found:
                print(f"{Fore.CYAN + Style.BRIGHT}Found subdomains:")
                for sub in found:
                    print(f"{Fore.CYAN + Style.BRIGHT}- {sub}")
            else:
                print(f"{Fore.WHITE + Style.BRIGHT}No subdomains found.")
            sleep(2)
        elif choice == '2':
            url = input(f"{Fore.WHITE + Style.BRIGHT}Enter URL (e.g., https://example.com): {Fore.CYAN}")
            directories = ["/admin", "/login", "/wp-admin", "/config", "/backup", "/db", "/test", "/phpmyadmin"]
            print(f"{Fore.CYAN + Style.BRIGHT}Scanning {url} for common directories...")
            for dir in directories:
                try:
                    response = requests.get(url + dir, timeout=5)
                    if response.status_code < 400:
                        print(f"{Fore.CYAN + Style.BRIGHT}Found: {url}{dir} (Status: {response.status_code})")
                    else:
                        print(f"{Fore.WHITE + Style.BRIGHT}Not found: {url}{dir} (Status: {response.status_code})")
                except:
                    print(f"{Fore.WHITE + Style.BRIGHT}Error checking: {url}{dir}")
            sleep(2)
        elif choice == '3':
            domain = input(f"{Fore.WHITE + Style.BRIGHT}Enter domain (e.g., example.com): {Fore.CYAN}")
            try:
                import ssl
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        print(f"{Fore.CYAN + Style.BRIGHT}Issuer: {dict(cert['issuer'])}")
                        print(f"{Fore.CYAN + Style.BRIGHT}Subject: {dict(cert['subject'])}")
                        print(f"{Fore.CYAN + Style.BRIGHT}Expiry: {cert['notAfter']}")
            except Exception as e:
                print(f"{Fore.WHITE + Style.BRIGHT}Failed to fetch SSL certificate: {str(e)}")
            sleep(2)
        elif choice == '4':
            url = input(f"{Fore.WHITE + Style.BRIGHT}Enter URL to check for basic vulnerabilities (headers): {Fore.CYAN}")
            try:
                response = requests.get(url, timeout=5)
                headers = response.headers
                issues = []
                if 'X-Frame-Options' not in headers:
                    issues.append("Missing X-Frame-Options (Clickjacking risk)")
                if 'Strict-Transport-Security' not in headers:
                    issues.append("Missing HSTS (Man-in-the-Middle risk)")
                if 'Content-Security-Policy' not in headers:
                    issues.append("Missing CSP (XSS risk)")
                if issues:
                    print(f"{Fore.WHITE + Style.BRIGHT}Potential vulnerabilities:")
                    for issue in issues:
                        print(f"{Fore.WHITE + Style.BRIGHT}- {issue}")
                else:
                    print(f"{Fore.CYAN + Style.BRIGHT}No basic vulnerabilities detected in headers.")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Failed to check vulnerabilities.")
            sleep(2)
        elif choice == '5':
            print(f"{Fore.WHITE + Style.BRIGHT}CMS detection requires tools like WhatCMS or APIs.")
            url = input(f"{Fore.WHITE + Style.BRIGHT}Enter URL: {Fore.CYAN}")
            webbrowser.open(f'https://whatcms.org/?s={url}')
            sleep(2)
        elif choice == '6':
            print(f"{Fore.WHITE + Style.BRIGHT}Firewall detection via headers or tools like wafw00f.")
            sleep(2)
        elif choice == '0':
            break
        else:
            print(f"{Fore.WHITE + Style.BRIGHT}Invalid choice.")
            sleep(1)

# File Tools (added more)
def file_tools():
    options = ["Hash File", "Compress File (ZIP)", "Decompress File", "File Search", "File Encryption (See Crypto)", "View File Hex", "String Extraction from File"]
    while True:
        display_menu(options, "File Tools")
        choice = input(f"{Fore.WHITE + Style.BRIGHT}Select option: {Fore.CYAN}")
        if choice == '1':
            file_path = input(f"{Fore.WHITE + Style.BRIGHT}Enter file path to hash: {Fore.CYAN}")
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                print(f"{Fore.CYAN + Style.BRIGHT}MD5: {hashlib.md5(data).hexdigest()}")
                print(f"{Fore.CYAN + Style.BRIGHT}SHA256: {hashlib.sha256(data).hexdigest()}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Failed to hash file.")
            sleep(2)
        elif choice == '2':
            file_path = input(f"{Fore.WHITE + Style.BRIGHT}Enter file or folder to compress: {Fore.CYAN}")
            output_zip = file_path + '.zip'
            try:
                if os.path.isdir(file_path):
                    shutil.make_archive(file_path, 'zip', file_path)
                else:
                    with zipfile.ZipFile(output_zip, 'w') as zipf:
                        zipf.write(file_path)
                print(f"{Fore.CYAN + Style.BRIGHT}Compressed to {output_zip}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Compression failed.")
            sleep(2)
        elif choice == '3':
            zip_path = input(f"{Fore.WHITE + Style.BRIGHT}Enter ZIP file to decompress: {Fore.CYAN}")
            output_dir = zip_path.replace('.zip', '')
            try:
                with zipfile.ZipFile(zip_path, 'r') as zipf:
                    zipf.extractall(output_dir)
                print(f"{Fore.CYAN + Style.BRIGHT}Decompressed to {output_dir}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Decompression failed.")
            sleep(2)
        elif choice == '4':
            pattern = input(f"{Fore.WHITE + Style.BRIGHT}Enter search pattern (e.g., *.txt): {Fore.CYAN}")
            directory = input(f"{Fore.WHITE + Style.BRIGHT}Enter directory (leave blank for current): {Fore.CYAN}") or '.'
            files = glob.glob(os.path.join(directory, pattern))
            if files:
                print(f"{Fore.CYAN + Style.BRIGHT}Found files:")
                for file in files:
                    print(f"{Fore.CYAN + Style.BRIGHT}- {file}")
            else:
                print(f"{Fore.WHITE + Style.BRIGHT}No files found.")
            sleep(2)
        elif choice == '5':
            print(f"{Fore.CYAN + Style.BRIGHT}Use AES Encrypt/Decrypt in Crypto Tools for files.")
            sleep(2)
        elif choice == '6':
            file_path = input(f"{Fore.WHITE + Style.BRIGHT}Enter file for hex view: {Fore.CYAN}")
            try:
                with open(file_path, 'rb') as f:
                    hex_data = f.read().hex()[:100]  # First 100 bytes
                print(f"{Fore.CYAN + Style.BRIGHT}Hex: {hex_data}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Failed to view hex.")
            sleep(2)
        elif choice == '7':
            file_path = input(f"{Fore.WHITE + Style.BRIGHT}Enter file to extract strings: {Fore.CYAN}")
            try:
                with open(file_path, 'rb') as f:
                    data = f.read().decode('utf-8', errors='ignore')
                strings = re.findall(r'[\x20-\x7E]{4,}', data)
                print(f"{Fore.CYAN + Style.BRIGHT}Extracted strings: {strings[:10]}")  # First 10
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Failed to extract strings.")
            sleep(2)
        elif choice == '0':
            break
        else:
            print(f"{Fore.WHITE + Style.BRIGHT}Invalid choice.")
            sleep(1)

# System Tools (added more)
def system_tools():
    options = ["System Info", "Running Processes", "Disk Usage", "Network Interfaces", "Uptime", "CPU Usage", "Memory Stats"]
    while True:
        display_menu(options, "System Tools")
        choice = input(f"{Fore.WHITE + Style.BRIGHT}Select option: {Fore.CYAN}")
        if choice == '1':
            print(f"{Fore.CYAN + Style.BRIGHT}OS: {platform.system()} {platform.release()}")
            print(f"{Fore.CYAN + Style.BRIGHT}CPU: {platform.processor()}")
            print(f"{Fore.CYAN + Style.BRIGHT}RAM: {round(psutil.virtual_memory().total / (1024**3), 2)} GB")
            sleep(2)
        elif choice == '2':
            print(f"{Fore.CYAN + Style.BRIGHT}Running processes:")
            for proc in psutil.process_iter(['pid', 'name']):
                print(f"{Fore.CYAN + Style.BRIGHT}PID: {proc.info['pid']}, Name: {proc.info['name']}")
            sleep(2)
        elif choice == '3':
            usage = psutil.disk_usage('/')
            print(f"{Fore.CYAN + Style.BRIGHT}Total: {round(usage.total / (1024**3), 2)} GB")
            print(f"{Fore.CYAN + Style.BRIGHT}Used: {round(usage.used / (1024**3), 2)} GB")
            print(f"{Fore.CYAN + Style.BRIGHT}Free: {round(usage.free / (1024**3), 2)} GB")
            sleep(2)
        elif choice == '4':
            interfaces = psutil.net_if_addrs()
            for name, addrs in interfaces.items():
                print(f"{Fore.CYAN + Style.BRIGHT}Interface: {name}")
                for addr in addrs:
                    print(f"{Fore.CYAN + Style.BRIGHT}  - {addr.family.name}: {addr.address}")
            sleep(2)
        elif choice == '5':
            boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
            print(f"{Fore.CYAN + Style.BRIGHT}System uptime since: {boot_time}")
            sleep(2)
        elif choice == '6':
            print(f"{Fore.CYAN + Style.BRIGHT}CPU Usage: {psutil.cpu_percent()}%")
            sleep(2)
        elif choice == '7':
            mem = psutil.virtual_memory()
            print(f"{Fore.CYAN + Style.BRIGHT}Available Memory: {round(mem.available / (1024**3), 2)} GB")
            print(f"{Fore.CYAN + Style.BRIGHT}Used Memory: {round(mem.used / (1024**3), 2)} GB")
            sleep(2)
        elif choice == '0':
            break
        else:
            print(f"{Fore.WHITE + Style.BRIGHT}Invalid choice.")
            sleep(1)

# Web Tools (added more)
def web_tools():
    options = ["Web Scraper (Basic)", "URL Shortener (Placeholder)", "Download File", "Check Website Status", "SEO Checker (Placeholder)", "Proxy Checker"]
    while True:
        display_menu(options, "Web Tools")
        choice = input(f"{Fore.WHITE + Style.BRIGHT}Select option: {Fore.CYAN}")
        if choice == '1':
            url = input(f"{Fore.WHITE + Style.BRIGHT}Enter URL to scrape text: {Fore.CYAN}")
            try:
                response = requests.get(url, timeout=5)
                text = re.sub(r'<[^<]+?>', '', response.text)[:1000]  # Basic strip HTML
                print(f"{Fore.CYAN + Style.BRIGHT}Scraped text (first 1000 chars): {text}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Scraping failed.")
            sleep(2)
        elif choice == '2':
            print(f"{Fore.WHITE + Style.BRIGHT}URL shorteners require APIs (e.g., bit.ly). Use online services.")
            sleep(2)
        elif choice == '3':
            url = input(f"{Fore.WHITE + Style.BRIGHT}Enter URL to download: {Fore.CYAN}")
            file_name = url.split('/')[-1]
            try:
                response = requests.get(url, timeout=10)
                with open(file_name, 'wb') as f:
                    f.write(response.content)
                print(f"{Fore.CYAN + Style.BRIGHT}Downloaded to {file_name}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Download failed.")
            sleep(2)
        elif choice == '4':
            url = input(f"{Fore.WHITE + Style.BRIGHT}Enter URL to check: {Fore.CYAN}")
            try:
                response = requests.head(url, timeout=5)
                print(f"{Fore.CYAN + Style.BRIGHT}Status: {response.status_code}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Website check failed.")
            sleep(2)
        elif choice == '5':
            print(f"{Fore.WHITE + Style.BRIGHT}SEO checker: Use tools like Google Analytics or online checkers.")
            sleep(2)
        elif choice == '6':
            proxy = input(f"{Fore.WHITE + Style.BRIGHT}Enter proxy (ip:port): {Fore.CYAN}")
            try:
                response = requests.get('https://api.ipify.org', proxies={'http': proxy, 'https': proxy}, timeout=5)
                print(f"{Fore.CYAN + Style.BRIGHT}Proxy works. IP: {response.text}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Proxy failed.")
            sleep(2)
        elif choice == '0':
            break
        else:
            print(f"{Fore.WHITE + Style.BRIGHT}Invalid choice.")
            sleep(1)

# Password Tools (added more)
def password_tools():
    options = ["Generate Strong Password", "Brute Force Demo (Inefficient)", "Password Manager (Basic - Local)", "Hash Cracker Demo"]
    while True:
        display_menu(options, "Password Tools")
        choice = input(f"{Fore.WHITE + Style.BRIGHT}Select option: {Fore.CYAN}")
        if choice == '1':
            try:
                length = int(input(f"{Fore.WHITE + Style.BRIGHT}Enter length (min 12): {Fore.CYAN}"))
                chars = string.ascii_letters + string.digits + string.punctuation
                password = ''.join(random.choice(chars) for _ in range(max(length, 12)))
                print(f"{Fore.CYAN + Style.BRIGHT}Generated: {password}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Invalid input.")
            sleep(2)
        elif choice == '2':
            print(f"{Fore.WHITE + Style.BRIGHT}Demo brute force on a simple hash (very slow; for learning only).")
            target_hash = hashlib.md5(b'password').hexdigest()
            print(f"{Fore.CYAN + Style.BRIGHT}Target MD5: {target_hash}")
            for i in range(10000):
                guess = str(i).zfill(4)
                if hashlib.md5(guess.encode()).hexdigest() == target_hash:
                    print(f"{Fore.CYAN + Style.BRIGHT}Cracked: {guess}")
                    break
            else:
                print(f"{Fore.WHITE + Style.BRIGHT}Not cracked in demo limit.")
            sleep(2)
        elif choice == '3':
            print(f"{Fore.WHITE + Style.BRIGHT}Basic local password manager (stores in plain text - NOT secure!)")
            file = 'passwords.json'
            if os.path.exists(file):
                with open(file, 'r') as f:
                    pwds = json.load(f)
            else:
                pwds = {}
            action = input(f"{Fore.WHITE + Style.BRIGHT}Add (a), View (v), or Delete (d)? {Fore.CYAN}")
            if action == 'a':
                site = input(f"{Fore.WHITE + Style.BRIGHT}Site: {Fore.CYAN}")
                pwd = input(f"{Fore.WHITE + Style.BRIGHT}Password: {Fore.CYAN}")
                pwds[site] = pwd
                with open(file, 'w') as f:
                    json.dump(pwds, f)
                print(f"{Fore.CYAN + Style.BRIGHT}Added.")
            elif action == 'v':
                site = input(f"{Fore.WHITE + Style.BRIGHT}Site: {Fore.CYAN}")
                print(f"{Fore.CYAN + Style.BRIGHT}Password: {pwds.get(site, 'Not found')}")
            elif action == 'd':
                site = input(f"{Fore.WHITE + Style.BRIGHT}Site: {Fore.CYAN}")
                pwds.pop(site, None)
                with open(file, 'w') as f:
                    json.dump(pwds, f)
                print(f"{Fore.CYAN + Style.BRIGHT}Deleted.")
            sleep(2)
        elif choice == '4':
            print(f"{Fore.WHITE + Style.BRIGHT}Hash cracker demo: Use tools like Hashcat for real scenarios.")
            sleep(2)
        elif choice == '0':
            break
        else:
            print(f"{Fore.WHITE + Style.BRIGHT}Invalid choice.")
            sleep(1)

# Social Media Tools (Safe, Ethical Only) (added more)
def social_tools():
    options = ["Discord Info", "TikTok Search", "YouTube Search", "Instagram Profile Check (Placeholder)", "Twitter Sentiment Analysis (Placeholder)"]
    while True:
        display_menu(options, "Social Media Tools")
        choice = input(f"{Fore.WHITE + Style.BRIGHT}Select option: {Fore.CYAN}")
        if choice == '1':
            print(f"{Fore.WHITE + Style.BRIGHT}Discord is a chat app. Bots or automation violate TOS. Stay safe!")
            print(f"{Fore.CYAN + Style.BRIGHT}Visit https://discord.com for more.")
            sleep(2)
        elif choice == '2':
            query = input(f"{Fore.WHITE + Style.BRIGHT}Enter TikTok search query: {Fore.CYAN}")
            print(f"{Fore.CYAN + Style.BRIGHT}Search URL: https://www.tiktok.com/search?q={query.replace(' ', '%20')}")
            sleep(2)
        elif choice == '3':
            query = input(f"{Fore.WHITE + Style.BRIGHT}Enter YouTube search query: {Fore.CYAN}")
            print(f"{Fore.CYAN + Style.BRIGHT}Search URL: https://www.youtube.com/results?search_query={query.replace(' ', '+')}")
            sleep(2)
        elif choice == '4':
            print(f"{Fore.WHITE + Style.BRIGHT}Instagram checks require APIs. Use browser for profiles.")
            sleep(2)
        elif choice == '5':
            print(f"{Fore.WHITE + Style.BRIGHT}Twitter sentiment: Use APIs like Tweepy.")
            sleep(2)
        elif choice == '0':
            break
        else:
            print(f"{Fore.WHITE + Style.BRIGHT}Invalid choice.")
            sleep(1)

# Basic Utilities (added more)
def basic_utils():
    options = ["Calculator", "Text Editor (Basic)", "Timer", "Random Number Generator", "Unit Converter (Placeholder)", "QR Code Generator (Placeholder)"]
    while True:
        display_menu(options, "Basic Utilities")
        choice = input(f"{Fore.WHITE + Style.BRIGHT}Select option: {Fore.CYAN}")
        if choice == '1':
            expr = input(f"{Fore.WHITE + Style.BRIGHT}Enter expression (e.g., 2+2*3): {Fore.CYAN}")
            try:
                result = eval(expr)
                print(f"{Fore.CYAN + Style.BRIGHT}Result: {result}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Invalid expression.")
            sleep(2)
        elif choice == '2':
            file = input(f"{Fore.WHITE + Style.BRIGHT}Enter file name to edit/create: {Fore.CYAN}")
            text = input(f"{Fore.WHITE + Style.BRIGHT}Enter text (end with ENTER): {Fore.CYAN}")
            with open(file, 'w') as f:
                f.write(text)
            print(f"{Fore.CYAN + Style.BRIGHT}File saved.")
            sleep(2)
        elif choice == '3':
            try:
                seconds = int(input(f"{Fore.WHITE + Style.BRIGHT}Enter seconds for timer: {Fore.CYAN}"))
                sleep(seconds)
                print(f"{Fore.CYAN + Style.BRIGHT}Timer done!")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Invalid input.")
            sleep(2)
        elif choice == '4':
            try:
                min_val = int(input(f"{Fore.WHITE + Style.BRIGHT}Min value: {Fore.CYAN}"))
                max_val = int(input(f"{Fore.WHITE + Style.BRIGHT}Max value: {Fore.CYAN}"))
                print(f"{Fore.CYAN + Style.BRIGHT}Random: {random.randint(min_val, max_val)}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Invalid input.")
            sleep(2)
        elif choice == '5':
            print(f"{Fore.WHITE + Style.BRIGHT}Unit converter: Use libraries like pint or online tools.")
            sleep(2)
        elif choice == '6':
            print(f"{Fore.WHITE + Style.BRIGHT}QR code: Use qrcode library.")
            sleep(2)
        elif choice == '0':
            break
        else:
            print(f"{Fore.WHITE + Style.BRIGHT}Invalid choice.")
            sleep(1)

# Additional Tools (updated with Discord link)
def additional_tools():
    options = ["Open OSINT Framework", "Open NicheProwler", "Open Tracked.SH Dashboard", "What's My IP?", "Get Info on IPs (Check if IP is a VPN)", "Download Telegram (for VPN features)", "Join MemBIN (Placeholder)", "Join 1599 Discord", "View 1599 HARM Tool (Placeholder)", "More External Resources", "Download 1599 TOOL Batch", "Download 1599 TOOL Python"]
    while True:
        display_menu(options, "Additional Tools")
        choice = input(f"{Fore.WHITE + Style.BRIGHT}Select option: {Fore.CYAN}")
        if choice == '1':
            webbrowser.open('https://osintframework.com')
            print(f"{Fore.CYAN + Style.BRIGHT}Opening OSINT Framework...")
            sleep(2)
        elif choice == '2':
            webbrowser.open('https://www.nicheprowler.com/')
            print(f"{Fore.CYAN + Style.BRIGHT}Opening NicheProwler...")
            sleep(2)
        elif choice == '3':
            webbrowser.open('https://tracked.sh/')
            print(f"{Fore.CYAN + Style.BRIGHT}Opening Tracked.SH Dashboard...")
            sleep(2)
        elif choice == '4':
            try:
                ip = requests.get('https://api.ipify.org').text
                print(f"{Fore.CYAN + Style.BRIGHT}Your IP: {ip}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Failed to get IP.")
            sleep(2)
        elif choice == '5':
            ip = input(f"{Fore.WHITE + Style.BRIGHT}Enter IP: {Fore.CYAN}")
            try:
                response = requests.get(f'https://ipapi.co/{ip}/json/')
                data = response.json()
                if 'error' in data:
                    print(f"{Fore.WHITE + Style.BRIGHT}Error: {data.get('reason')}")
                else:
                    print(f"{Fore.CYAN + Style.BRIGHT}City: {data.get('city')}, Country: {data.get('country_name')}, ISP: {data.get('org')}")
                    print(f"{Fore.CYAN + Style.BRIGHT}Is VPN/Proxy: {data.get('proxy', 'Unknown')}")
            except:
                print(f"{Fore.WHITE + Style.BRIGHT}Failed to get info.")
            sleep(2)
        elif choice == '6':
            webbrowser.open('https://telegram.org/dl')
            print(f"{Fore.CYAN + Style.BRIGHT}Opening Telegram download...")
            sleep(2)
        elif choice == '7':
            print(f"{Fore.CYAN + Style.BRIGHT}Placeholder for Join MemBIN. Replace with actual link if known.")
            sleep(2)
        elif choice == '8':
            webbrowser.open('https://discord.gg/T7BntKfqYp')
            print(f"{Fore.CYAN + Style.BRIGHT}Joining 1599 Discord...")
            sleep(2)
        elif choice == '9':
            print(f"{Fore.CYAN + Style.BRIGHT}Placeholder for View 1599 HARM Tool. Replace with actual resource.")
            sleep(2)
        elif choice == '10':
            print(f"{Fore.CYAN + Style.BRIGHT}More resources: Explore xAI, Grok, etc.")
            sleep(2)
        elif choice == '11':
            webbrowser.open('https://example.com/1599_tool.bat')  # Replace with actual URL to host the batch file
            print(f"{Fore.CYAN + Style.BRIGHT}Downloading 1599 TOOL Batch file...")
            sleep(2)
        elif choice == '12':
            webbrowser.open('https://example.com/1599_tool.py')  # Replace with actual URL to host the Python file
            print(f"{Fore.CYAN + Style.BRIGHT}Downloading 1599 TOOL Python file...")
            sleep(2)
        elif choice == '0':
            break
        else:
            print(f"{Fore.WHITE + Style.BRIGHT}Invalid choice.")
            sleep(1)

# Main Menu (added Additional Tools)
def main():
    options = ["Network Tools", "OSINT Tools", "Crypto Tools", "Recon Tools", "File Tools", "System Tools", "Web Tools", "Password Tools", "Social Media Tools", "Basic Utilities", "Additional Tools"]
    while True:
        display_menu(options, "Main Menu - 1599 TOOL")
        choice = input(f"{Fore.WHITE + Style.BRIGHT}Select page: {Fore.CYAN}")
        if choice == '1':
            network_tools()
        elif choice == '2':
            osint_tools()
        elif choice == '3':
            crypto_tools()
        elif choice == '4':
            recon_tools()
        elif choice == '5':
            file_tools()
        elif choice == '6':
            system_tools()
        elif choice == '7':
            web_tools()
        elif choice == '8':
            password_tools()
        elif choice == '9':
            social_tools()
        elif choice == '10':
            basic_utils()
        elif choice == '11':
            additional_tools()
        elif choice == '0':
            clear_screen()
            print(ASCII_ART)
            print(f"{Fore.WHITE + Style.BRIGHT}Exiting 1599 TOOL. Stay ethical!")
            sleep(2)
            sys.exit()
        else:
            print(f"{Fore.WHITE + Style.BRIGHT}Invalid choice.")
            sleep(1)

if __name__ == "__main__":
    clear_screen()
    print(ASCII_ART)
    print(f"{Fore.WHITE + Style.BRIGHT}Welcome to 1599 TOOL! Install dependencies: pip install -r requirements.txt")
    print(f"{Fore.WHITE + Style.BRIGHT}This tool is for ethical hacking, learning, and basic utils only.")
    sleep(2)
    main()
