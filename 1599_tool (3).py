# 1599 TOOL - Ultimate Multi-Tool Console Application
# Made by Lethal
# This is an advanced educational Python script for ethical hacking, cybersecurity, and basic utilities.
# It includes real network, OSINT, crypto, recon, file, system, web, password tools, and more.
# Note: For learning purposes only. Do not use for illegal activities. All features are ethical and safe.
# To run: Save as 1599_tool.py and run with `python 1599_tool.py` in CMD.
# To make an EXE: Install pyinstaller (pip install pyinstaller) and run: pyinstaller --onefile 1599_tool.py
# Dependencies: Install via `pip install -r requirements.txt`

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

# For colors in console
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Colorama not installed. Colors may not work.")
    Fore = Style = lambda x: ''  # Dummy if not installed

# ASCII Art for 1599 TOOL
ASCII_ART = """
  ____ ___ ____ ___  
 | __ )_ _| __ )___ \\ 
 |  _ \\| ||  _ \\ __) |
 | |_) | || |_) / __/ 
 |____/___|____/_____| 
         TOOL v1.0
Made by Lethal
"""

# Function to clear screen
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to display menu with colors
def display_menu(options, title):
    clear_screen()
    print(Fore.RED + Style.BRIGHT + ASCII_ART)
    print(Fore.BLUE + Style.BRIGHT + f"==== {title} ====")
    for i, option in enumerate(options, 1):
        print(Fore.RED + f"{i}. {option}")
    print(Fore.BLUE + "0. Back/Exit")
    print(Fore.RED + "==================")

# Network Tools
def network_tools():
    options = ["Ping IP", "Get My IP", "Traceroute", "Advanced Port Scan", "DNS Lookup", "WHOIS Lookup", "HTTP Headers", "WiFi Networks (Basic)"]
    while True:
        display_menu(options, "Network Tools (Cyber Security)")
        choice = input(Fore.BLUE + "Select option: ")
        if choice == '1':
            ip = input(Fore.RED + "Enter IP to ping: ")
            subprocess.call(['ping', '-c', '4', ip] if os.name != 'nt' else ['ping', ip])
        elif choice == '2':
            try:
                ip = requests.get('https://api.ipify.org').text
                print(Fore.BLUE + f"Your IP: {ip}")
            except:
                print(Fore.RED + "Failed to get IP.")
            sleep(3)
        elif choice == '3':
            ip = input(Fore.RED + "Enter IP/Domain for traceroute: ")
            subprocess.call(['tracert' if os.name == 'nt' else 'traceroute', ip])
        elif choice == '4':
            ip = input(Fore.RED + "Enter IP to scan (e.g., 192.168.1.1): ")
            start_port = int(input(Fore.RED + "Start port (e.g., 1): "))
            end_port = int(input(Fore.RED + "End port (e.g., 1000): "))
            print(Fore.BLUE + f"Scanning {ip} ports {start_port}-{end_port}...")
            for port in range(start_port, end_port + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    print(Fore.BLUE + f"Port {port}: Open")
                sock.close()
            print(Fore.BLUE + "Scan complete.")
            sleep(3)
        elif choice == '5':
            domain = input(Fore.RED + "Enter domain for DNS lookup: ")
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                print(Fore.BLUE + f"IPs for {domain}: {', '.join(ips)}")
            except:
                print(Fore.RED + "Failed to lookup DNS.")
            sleep(3)
        elif choice == '6':
            domain = input(Fore.RED + "Enter domain for WHOIS: ")
            try:
                response = requests.get(f"https://api.whois.vu/?q={domain}")
                print(Fore.BLUE + response.text if response.status_code == 200 else Fore.RED + "WHOIS lookup failed.")
            except:
                print(Fore.RED + "WHOIS failed. Try online tools.")
            sleep(3)
        elif choice == '7':
            url = input(Fore.RED + "Enter URL (e.g., https://example.com): ")
            try:
                response = requests.get(url, timeout=5)
                print(Fore.BLUE + "HTTP Headers:")
                for key, value in response.headers.items():
                    print(Fore.BLUE + f"{key}: {value}")
            except:
                print(Fore.RED + "Failed to fetch headers.")
            sleep(3)
        elif choice == '8':
            print(Fore.RED + "Basic WiFi scan (Windows only; requires admin).")
            try:
                output = subprocess.check_output(['netsh', 'wlan', 'show', 'networks']).decode('utf-8')
                print(Fore.BLUE + output)
            except:
                print(Fore.RED + "WiFi scan failed or not supported.")
            sleep(3)
        elif choice == '0':
            break
        else:
            print(Fore.RED + "Invalid choice.")
            sleep(1)

# OSINT Tools
def osint_tools():
    options = ["IP Geolocation", "Reverse DNS", "Email Verification", "Phone Lookup (Placeholder)", "Social Media Username Check"]
    while True:
        display_menu(options, "OSINT Tools")
        choice = input(Fore.BLUE + "Select option: ")
        if choice == '1':
            ip = input(Fore.RED + "Enter IP for geolocation (leave blank for your IP): ")
            if not ip:
                try:
                    ip = requests.get('https://api.ipify.org').text
                except:
                    print(Fore.RED + "Failed to get your IP.")
                    sleep(3)
                    continue
            try:
                response = requests.get(f'https://ipapi.co/{ip}/json/')
                data = response.json()
                if 'error' in data:
                    print(Fore.RED + "Error: " + data.get('reason', 'Unknown'))
                else:
                    print(Fore.BLUE + f"City: {data.get('city')}, Region: {data.get('region')}, Country: {data.get('country_name')}")
                    print(Fore.BLUE + f"ISP: {data.get('org')}, Lat/Lon: {data.get('latitude')}/{data.get('longitude')}")
            except:
                print(Fore.RED + "Failed to get geolocation.")
            sleep(3)
        elif choice == '2':
            ip = input(Fore.RED + "Enter IP for reverse DNS: ")
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(Fore.BLUE + f"Hostname: {hostname}")
            except:
                print(Fore.RED + "No hostname found.")
            sleep(3)
        elif choice == '3':
            email = input(Fore.RED + "Enter email to verify format: ")
            if re.match(r"[^@]+@[^@]+\.[^@]+", email):
                print(Fore.BLUE + "Email format valid.")
            else:
                print(Fore.RED + "Invalid email format.")
            print(Fore.RED + "For real verification, use APIs like Hunter.io.")
            sleep(3)
        elif choice == '4':
            print(Fore.RED + "Phone lookups require paid APIs (e.g., Numverify). Use online tools.")
            sleep(3)
        elif choice == '5':
            username = input(Fore.RED + "Enter username to check on social media: ")
            sites = ["twitter.com/", "instagram.com/", "github.com/", "linkedin.com/in/"]
            for site in sites:
                url = f"https://{site}{username}"
                try:
                    response = requests.head(url, timeout=5)
                    status = "Exists" if response.status_code < 400 else "Not Found"
                    print(Fore.BLUE + f"{site}: {status}")
                except:
                    print(Fore.RED + f"{site}: Error checking.")
            sleep(3)
        elif choice == '0':
            break
        else:
            print(Fore.RED + "Invalid choice.")
            sleep(1)

# Crypto Tools
def crypto_tools():
    options = ["Base64 Encode/Decode", "Hash Generator (MD5/SHA256/SHA512)", "Vigenère Cipher", "Password Strength Checker", "AES Encrypt/Decrypt (File)"]
    while True:
        display_menu(options, "Crypto Tools")
        choice = input(Fore.BLUE + "Select option: ")
        if choice == '1':
            action = input(Fore.RED + "Encode (e) or Decode (d)? ")
            text = input(Fore.RED + "Enter text: ")
            if action.lower() == 'e':
                print(Fore.BLUE + base64.b64encode(text.encode()).decode())
            elif action.lower() == 'd':
                try:
                    print(Fore.BLUE + base64.b64decode(text).decode())
                except:
                    print(Fore.RED + "Invalid Base64.")
            sleep(3)
        elif choice == '2':
            text = input(Fore.RED + "Enter text to hash: ")
            print(Fore.BLUE + f"MD5: {hashlib.md5(text.encode()).hexdigest()}")
            print(Fore.BLUE + f"SHA256: {hashlib.sha256(text.encode()).hexdigest()}")
            print(Fore.BLUE + f"SHA512: {hashlib.sha512(text.encode()).hexdigest()}")
            sleep(3)
        elif choice == '3':
            text = input(Fore.RED + "Enter text: ")
            key = input(Fore.RED + "Enter key: ")
            result = ""
            key = key.upper()
            key_idx = 0
            for c in text.upper():
                if c.isalpha():
                    result += chr((ord(c) - 65 + (ord(key[key_idx % len(key)]) - 65)) % 26 + 65)
                    key_idx += 1
                else:
                    result += c
            print(Fore.BLUE + f"Encrypted: {result}")
            sleep(3)
        elif choice == '4':
            password = input(Fore.RED + "Enter password: ")
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
            print(Fore.BLUE + f"Password Strength: {strength}")
            sleep(3)
        elif choice == '5':
            action = input(Fore.RED + "Encrypt (e) or Decrypt (d) file? ")
            file_path = input(Fore.RED + "Enter file path: ")
            password = input(Fore.RED + "Enter password for key: ").encode()
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
                    print(Fore.BLUE + "File encrypted to " + file_path + '.enc')
                elif action.lower() == 'd':
                    decrypted = fernet.decrypt(data)
                    with open(file_path + '.dec', 'wb') as f:
                        f.write(decrypted)
                    print(Fore.BLUE + "File decrypted to " + file_path + '.dec')
            except:
                print(Fore.RED + "Encryption/Decryption failed.")
            sleep(3)
        elif choice == '0':
            break
        else:
            print(Fore.RED + "Invalid choice.")
            sleep(1)

# Recon Tools
def recon_tools():
    options = ["Subdomain Enumerator", "Directory Scanner", "SSL Certificate Checker", "Vulnerability Check (Basic)"]
    while True:
        display_menu(options, "Recon Tools")
        choice = input(Fore.BLUE + "Select option: ")
        if choice == '1':
            domain = input(Fore.RED + "Enter domain (e.g., example.com): ")
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
                print(Fore.BLUE + "Found subdomains:")
                for sub in found:
                    print(Fore.BLUE + f"- {sub}")
            else:
                print(Fore.RED + "No subdomains found.")
            sleep(3)
        elif choice == '2':
            url = input(Fore.RED + "Enter URL (e.g., https://example.com): ")
            directories = ["/admin", "/login", "/wp-admin", "/config", "/backup", "/db", "/test", "/phpmyadmin"]
            print(Fore.BLUE + f"Scanning {url} for common directories...")
            for dir in directories:
                try:
                    response = requests.get(url + dir, timeout=5)
                    if response.status_code < 400:
                        print(Fore.BLUE + f"Found: {url}{dir} (Status: {response.status_code})")
                    else:
                        print(Fore.RED + f"Not found: {url}{dir} (Status: {response.status_code})")
                except:
                    print(Fore.RED + f"Error checking: {url}{dir}")
            sleep(3)
        elif choice == '3':
            domain = input(Fore.RED + "Enter domain (e.g., example.com): ")
            try:
                import ssl
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        print(Fore.BLUE + f"Issuer: {dict(cert['issuer'])}")
                        print(Fore.BLUE + f"Subject: {dict(cert['subject'])}")
                        print(Fore.BLUE + f"Expiry: {cert['notAfter']}")
            except Exception as e:
                print(Fore.RED + f"Failed to fetch SSL certificate: {str(e)}")
            sleep(3)
        elif choice == '4':
            url = input(Fore.RED + "Enter URL to check for basic vulnerabilities (headers): ")
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
                    print(Fore.RED + "Potential vulnerabilities:")
                    for issue in issues:
                        print(Fore.RED + f"- {issue}")
                else:
                    print(Fore.BLUE + "No basic vulnerabilities detected in headers.")
            except:
                print(Fore.RED + "Failed to check vulnerabilities.")
            sleep(3)
        elif choice == '0':
            break
        else:
            print(Fore.RED + "Invalid choice.")
            sleep(1)

# File Tools
def file_tools():
    options = ["Hash File", "Compress File (ZIP)", "Decompress File", "File Search", "File Encryption (See Crypto)"]
    while True:
        display_menu(options, "File Tools")
        choice = input(Fore.BLUE + "Select option: ")
        if choice == '1':
            file_path = input(Fore.RED + "Enter file path to hash: ")
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                print(Fore.BLUE + f"MD5: {hashlib.md5(data).hexdigest()}")
                print(Fore.BLUE + f"SHA256: {hashlib.sha256(data).hexdigest()}")
            except:
                print(Fore.RED + "Failed to hash file.")
            sleep(3)
        elif choice == '2':
            file_path = input(Fore.RED + "Enter file or folder to compress: ")
            output_zip = file_path + '.zip'
            try:
                if os.path.isdir(file_path):
                    shutil.make_archive(file_path, 'zip', file_path)
                else:
                    with zipfile.ZipFile(output_zip, 'w') as zipf:
                        zipf.write(file_path)
                print(Fore.BLUE + f"Compressed to {output_zip}")
            except:
                print(Fore.RED + "Compression failed.")
            sleep(3)
        elif choice == '3':
            zip_path = input(Fore.RED + "Enter ZIP file to decompress: ")
            output_dir = zip_path.replace('.zip', '')
            try:
                with zipfile.ZipFile(zip_path, 'r') as zipf:
                    zipf.extractall(output_dir)
                print(Fore.BLUE + f"Decompressed to {output_dir}")
            except:
                print(Fore.RED + "Decompression failed.")
            sleep(3)
        elif choice == '4':
            pattern = input(Fore.RED + "Enter search pattern (e.g., *.txt): ")
            directory = input(Fore.RED + "Enter directory (leave blank for current): ") or '.'
            files = glob.glob(os.path.join(directory, pattern))
            if files:
                print(Fore.BLUE + "Found files:")
                for file in files:
                    print(Fore.BLUE + f"- {file}")
            else:
                print(Fore.RED + "No files found.")
            sleep(3)
        elif choice == '5':
            print(Fore.BLUE + "Use AES Encrypt/Decrypt in Crypto Tools for files.")
            sleep(3)
        elif choice == '0':
            break
        else:
            print(Fore.RED + "Invalid choice.")
            sleep(1)

# System Tools
def system_tools():
    options = ["System Info", "Process List", "Disk Usage", "Network Interfaces", "Uptime"]
    while True:
        display_menu(options, "System Tools")
        choice = input(Fore.BLUE + "Select option: ")
        if choice == '1':
            print(Fore.BLUE + f"OS: {platform.system()} {platform.release()}")
            print(Fore.BLUE + f"CPU: {platform.processor()}")
            print(Fore.BLUE + f"RAM: {round(psutil.virtual_memory().total / (1024**3), 2)} GB")
            sleep(3)
        elif choice == '2':
            print(Fore.BLUE + "Running processes:")
            for proc in psutil.process_iter(['pid', 'name']):
                print(Fore.BLUE + f"PID: {proc.info['pid']}, Name: {proc.info['name']}")
            sleep(3)
        elif choice == '3':
            usage = psutil.disk_usage('/')
            print(Fore.BLUE + f"Total: {round(usage.total / (1024**3), 2)} GB")
            print(Fore.BLUE + f"Used: {round(usage.used / (1024**3), 2)} GB")
            print(Fore.BLUE + f"Free: {round(usage.free / (1024**3), 2)} GB")
            sleep(3)
        elif choice == '4':
            interfaces = psutil.net_if_addrs()
            for name, addrs in interfaces.items():
                print(Fore.BLUE + f"Interface: {name}")
                for addr in addrs:
                    print(Fore.BLUE + f"  - {addr.family.name}: {addr.address}")
            sleep(3)
        elif choice == '5':
            boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
            print(Fore.BLUE + f"System uptime since: {boot_time}")
            sleep(3)
        elif choice == '0':
            break
        else:
            print(Fore.RED + "Invalid choice.")
            sleep(1)

# Web Tools
def web_tools():
    options = ["Web Scraper (Basic)", "URL Shortener (Placeholder)", "Download File", "Check Website Status"]
    while True:
        display_menu(options, "Web Tools")
        choice = input(Fore.BLUE + "Select option: ")
        if choice == '1':
            url = input(Fore.RED + "Enter URL to scrape text: ")
            try:
                response = requests.get(url, timeout=5)
                text = re.sub(r'<[^<]+?>', '', response.text)[:1000]  # Basic strip HTML
                print(Fore.BLUE + f"Scraped text (first 1000 chars): {text}")
            except:
                print(Fore.RED + "Scraping failed.")
            sleep(3)
        elif choice == '2':
            print(Fore.RED + "URL shorteners require APIs (e.g., bit.ly). Use online services.")
            sleep(3)
        elif choice == '3':
            url = input(Fore.RED + "Enter URL to download: ")
            file_name = url.split('/')[-1]
            try:
                response = requests.get(url, timeout=10)
                with open(file_name, 'wb') as f:
                    f.write(response.content)
                print(Fore.BLUE + f"Downloaded to {file_name}")
            except:
                print(Fore.RED + "Download failed.")
            sleep(3)
        elif choice == '4':
            url = input(Fore.RED + "Enter URL to check: ")
            try:
                response = requests.head(url, timeout=5)
                print(Fore.BLUE + f"Status: {response.status_code}")
            except:
                print(Fore.RED + "Website check failed.")
            sleep(3)
        elif choice == '0':
            break
        else:
            print(Fore.RED + "Invalid choice.")
            sleep(1)

# Password Tools
def password_tools():
    options = ["Generate Strong Password", "Brute Force Demo (Inefficient)", "Password Manager (Basic - Local)"]
    while True:
        display_menu(options, "Password Tools")
        choice = input(Fore.BLUE + "Select option: ")
        if choice == '1':
            length = int(input(Fore.RED + "Enter length (min 12): "))
            chars = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choice(chars) for _ in range(max(length, 12)))
            print(Fore.BLUE + f"Generated: {password}")
            sleep(3)
        elif choice == '2':
            print(Fore.RED + "Demo brute force on a simple hash (very slow; for learning only).")
            target_hash = hashlib.md5(b'password').hexdigest()  # Example
            print(Fore.BLUE + f"Target MD5: {target_hash}")
            for i in range(10000):  # Limited loop
                guess = str(i).zfill(4)
                if hashlib.md5(guess.encode()).hexdigest() == target_hash:
                    print(Fore.BLUE + f"Cracked: {guess}")
                    break
            else:
                print(Fore.RED + "Not cracked in demo limit.")
            sleep(3)
        elif choice == '3':
            print(Fore.RED + "Basic local password manager (stores in plain text - NOT secure!)")
            file = 'passwords.json'
            if os.path.exists(file):
                with open(file, 'r') as f:
                    pwds = json.load(f)
            else:
                pwds = {}
            action = input(Fore.RED + "Add (a), View (v), or Delete (d)? ")
            if action == 'a':
                site = input(Fore.RED + "Site: ")
                pwd = input(Fore.RED + "Password: ")
                pwds[site] = pwd
                with open(file, 'w') as f:
                    json.dump(pwds, f)
                print(Fore.BLUE + "Added.")
            elif action == 'v':
                site = input(Fore.RED + "Site: ")
                print(Fore.BLUE + f"Password: {pwds.get(site, 'Not found')}")
            elif action == 'd':
                site = input(Fore.RED + "Site: ")
                pwds.pop(site, None)
                with open(file, 'w') as f:
                    json.dump(pwds, f)
                print(Fore.BLUE + "Deleted.")
            sleep(3)
        elif choice == '0':
            break
        else:
            print(Fore.RED + "Invalid choice.")
            sleep(1)

# Social Media Tools (Safe, Ethical Only)
def social_tools():
    options = ["Discord Info", "TikTok Search", "YouTube Search", "Instagram Profile Check (Placeholder)"]
    while True:
        display_menu(options, "Social Media Tools")
        choice = input(Fore.BLUE + "Select option: ")
        if choice == '1':
            print(Fore.RED + "Discord is a chat app. Bots or automation violate TOS. Stay safe!")
            print(Fore.BLUE + "Visit https://discord.com for more.")
            sleep(3)
        elif choice == '2':
            query = input(Fore.RED + "Enter TikTok search query: ")
            print(Fore.BLUE + f"Search URL: https://www.tiktok.com/search?q={query.replace(' ', '%20')}")
            sleep(3)
        elif choice == '3':
            query = input(Fore.RED + "Enter YouTube search query: ")
            print(Fore.BLUE + f"Search URL: https://www.youtube.com/results?search_query={query.replace(' ', '+')}")
            sleep(3)
        elif choice == '4':
            print(Fore.RED + "Instagram checks require APIs. Use browser for profiles.")
            sleep(3)
        elif choice == '0':
            break
        else:
            print(Fore.RED + "Invalid choice.")
            sleep(1)

# Basic Utilities
def basic_utils():
    options = ["Calculator", "Text Editor (Basic)", "Timer", "Random Number Generator"]
    while True:
        display_menu(options, "Basic Utilities")
        choice = input(Fore.BLUE + "Select option: ")
        if choice == '1':
            expr = input(Fore.RED + "Enter expression (e.g., 2+2*3): ")
            try:
                result = eval(expr)
                print(Fore.BLUE + f"Result: {result}")
            except:
                print(Fore.RED + "Invalid expression.")
            sleep(3)
        elif choice == '2':
            file = input(Fore.RED + "Enter file name to edit/create: ")
            text = input(Fore.RED + "Enter text (end with ENTER): ")
            with open(file, 'w') as f:
                f.write(text)
            print(Fore.BLUE + "File saved.")
            sleep(3)
        elif choice == '3':
            seconds = int(input(Fore.RED + "Enter seconds for timer: "))
            sleep(seconds)
            print(Fore.BLUE + "Timer done!")
            sleep(3)
        elif choice == '4':
            min_val = int(input(Fore.RED + "Min value: "))
            max_val = int(input(Fore.RED + "Max value: "))
            print(Fore.BLUE + f"Random: {random.randint(min_val, max_val)}")
            sleep(3)
        elif choice == '0':
            break
        else:
            print(Fore.RED + "Invalid choice.")
            sleep(1)

# Main Menu
def main():
    options = ["Network Tools", "OSINT Tools", "Crypto Tools", "Recon Tools", "File Tools", "System Tools", "Web Tools", "Password Tools", "Social Media Tools", "Basic Utilities"]
    while True:
        display_menu(options, "Main Menu - 1599 TOOL")
        choice = input(Fore.BLUE + "Select page: ")
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
        elif choice == '0':
            print(Fore.RED + "Exiting 1599 TOOL. Stay ethical!")
            sys.exit()
        else:
            print(Fore.RED + "Invalid choice.")
            sleep(1)

if __name__ == "__main__":
    print(Fore.BLUE + "Welcome to 1599 TOOL! Install dependencies: pip install -r requirements.txt")
    print(Fore.RED + "This tool is for ethical hacking, learning, and basic utils only.")
    main()