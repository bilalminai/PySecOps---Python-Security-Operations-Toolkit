"""
PySecOps Demo - Single-file consolidation of all security features.
Domains: Network Scan, Web Scraper, Web Recon, Password Generator,
Clickjacking Tester, File Integrity, Phishing Link Scanner, File Scanner.
"""

from __future__ import annotations

import os
import sys
import re
import csv
import json
import time
import stat
import hashlib
import getpass
import secrets
import threading
import itertools
from datetime import datetime
from urllib.parse import urlparse
import socket

# Third-party (used across modules)
import requests
import nmap
from bs4 import BeautifulSoup
from tabulate import tabulate
from colorama import Fore, Back, Style, init as colorama_init
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.prompt import Prompt, Confirm

colorama_init(autoreset=True)
console = Console()

# Optional imports for features that may not be installed
try:
    import whois
except ImportError:
    whois = None
try:
    import builtwith
except ImportError:
    builtwith = None
try:
    import dns.resolver
except ImportError:
    dns = None
try:
    import pyfiglet
except ImportError:
    pyfiglet = None
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileMovedEvent
except ImportError:
    Observer = FileSystemEventHandler = FileMovedEvent = None
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
except ImportError:
    np = IsolationForest = None
try:
    from PyPDF2 import PdfReader
except ImportError:
    PdfReader = None

# =============================================================================
# LOGO, BANNER, HEADING (shared UI)
# =============================================================================

def print_logo():
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[38;2;0;255;0m"
    logo_template = [
        "  ┏━                ━┓  ",
        "        ▄▄████▄▄        ",
        "     ▄██▀▀    ▀▀██▄     ",
        "   ▄█▀    ▄▄▄▄    ▀█▄   ",
        "  █▀   ▄██▀▀▀▀██▄   ▀█  ",
        " █▀   █▀        ▀█   ▀█ ",
        " █    █          █    █ ",
        " ━━━━━━━━━━━━━━━━━━━━━━ ",
        " █    █          █    █ ",
        " █▄   █▄        ▄█   ▄█ ",
        "  █▄   ▀██▄▄▄▄██▀   ▄█  ",
        "   ▀█▄    ▀▀▀▀    ▄█▀   ",
        "     ▀██▄▄    ▄▄██▀     ",
        "        ▀▀████▀▀        ",
        "  ┗━                ━┛  "
    ]
    print("\n")
    for line in logo_template:
        colored_line = ""
        for x, char in enumerate(line):
            ratio = x / max(len(line), 1)
            r = int(120 + (100 * ratio))
            g = int(40 + (20 * ratio))
            b = int(200 - (20 * ratio))
            color = f"\033[38;2;{r};{g};{b}m"
            colored_line += f"{color}{char}"
        print("    " + colored_line + RESET)
    text = "PySecOps"
    print(" " * ((len(logo_template[0]) // 2) - (len(text) // 2) + 4) + BOLD + GREEN + text + RESET)
    print(f"\n\033[3;32;5m           by PySecOps Team \033[0m")
    print(f"\033[3;32;2m Vedant | Bilal | Pranjali | Umesh | Vignesh \n\033[0m")

def display_banner(logo_text: str, title: str):
    if pyfiglet:
        ascii_banner = pyfiglet.figlet_format(logo_text)
        styled = Text(ascii_banner, style="bold cyan")
        console.print(Panel.fit(styled, title=Text("🔍 " + title, style="bold green italic"),
                             border_style="cyan", subtitle=Text("By PySecOps", style="bold yellow"), padding=(1, 6)))
    else:
        console.print(Panel.fit(f"{logo_text}\n{title}", title="By PySecOps", border_style="cyan"))
    print("\n")

def header_print(heading: str):
    sep = "\n--------------------------------------------------------\n"
    print(f"\033[3;4;32;1m{sep}\n\033[0m")
    print(f"\033[3;4;34;1m{heading}\n\033[0m")

# =============================================================================
# 1. NETWORK SCAN
# =============================================================================

class ScannerEngine:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print(f"{Fore.RED}Error: Nmap not found. Install Nmap (https://nmap.org) and add to PATH.")
            sys.exit(1)

    def format_target(self, target: str) -> str:
        octets = target.split('.')
        if len(octets) == 3:
            return f"{target}.0/24"
        return target

    def get_color_state(self, state: str) -> str:
        if state == 'open': return f"{Fore.GREEN}open"
        if state == 'closed': return f"{Fore.RED}closed"
        if state == 'filtered': return f"{Fore.YELLOW}filtered"
        return f"{Fore.CYAN}{state}"

    def animate(self, stop_event):
        chars = itertools.cycle(['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'])
        for char in chars:
            if stop_event.is_set():
                break
            sys.stdout.write(f'\r{Fore.CYAN}[{char}] Scanning Engine Active... Please wait...')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * 50 + '\r')

    def execute_scan(self, target: str, args: str):
        target = self.format_target(target)
        print(f"\n{Fore.BLUE}[INFO] Initializing Detailed Scan...\n")
        print(f"{Fore.BLUE}[INFO] Target: {Fore.WHITE}{target}")
        print(f"{Fore.BLUE}[INFO] Parameters: {Fore.WHITE}{args}")
        stop_animation = threading.Event()
        animation_thread = threading.Thread(target=self.animate, args=(stop_animation,))
        animation_thread.start()
        start_time = datetime.now()
        try:
            self.nm.scan(hosts=target, arguments=f"{args} -T4")
        except Exception as e:
            print(f"{Fore.RED}\n[!] Scan Error: {e}\n")
        finally:
            stop_animation.set()
            animation_thread.join()
        end_time = datetime.now()
        duration = end_time - start_time
        scan_results = []
        for host in self.nm.all_hosts():
            h_obj = self.nm[host]
            hostname = h_obj.hostname() or "Unknown"
            mac = h_obj['addresses'].get('mac', 'N/A')
            vendor = h_obj['vendor'].get(mac, 'N/A')
            os_match = "N/A"
            if 'osmatch' in h_obj and h_obj['osmatch']:
                os_match = h_obj['osmatch'][0].get('name', 'N/A')
            if 'tcp' in h_obj:
                for port, info in h_obj['tcp'].items():
                    scan_results.append({
                        "IP Address": host, "Hostname": hostname, "Port": port,
                        "State": self.get_color_state(info['state']), "Service": info['name'],
                        "Version": f"{info.get('product', '')} {info.get('version', '')}".strip() or "N/A",
                        "Reason": info.get('reason', 'N/A'), "OS Guess": os_match,
                        "MAC / Vendor": f"{mac} ({vendor})" if mac != 'N/A' else "N/A"
                    })
            else:
                state = h_obj.state()
                scan_results.append({
                    "IP Address": host, "Hostname": hostname, "Port": "N/A",
                    "State": f"{Fore.GREEN}UP" if state == 'up' else f"{Fore.RED}DOWN",
                    "Service": "N/A", "Version": "N/A",
                    "Reason": h_obj.get('status', {}).get('reason', 'N/A'),
                    "OS Guess": os_match, "MAC / Vendor": f"{mac} ({vendor})" if mac != 'N/A' else "N/A"
                })
        print(f"{Fore.GREEN}\n[*] Scan completed in {duration.total_seconds():.2f} seconds.")
        return scan_results, target

    def export_data(self, data, target: str):
        choice = input(f"\n{Fore.WHITE}Export these results to a .txt document? (y/n): ").lower()
        if choice == 'y':
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            clean_ip = target.replace('/', '_').replace('.', '-')
            filename = f"Scan_{clean_ip}_{timestamp}.txt"
            if os.path.exists(filename):
                filename = f"Scan_{clean_ip}_{timestamp}_v2.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"NETWORK SCAN REPORT\nTarget Scope: {target}\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 80 + "\n")
                f.write(tabulate(data, headers="keys", tablefmt="grid"))
                f.write(f"\n\n[EOF] Total Records: {len(data)}")
            print(f"{Fore.CYAN}[+] Detailed report generated: {Fore.WHITE}{os.path.abspath(filename)}")

def _host_scan_menu(scanner: ScannerEngine):
    while True:
        print(f"\n{Fore.MAGENTA}--- HOST DISCOVERY OPTIONS ---\n")
        print(f"{Fore.CYAN}1. Ping Sweep (-sn -PE)")
        print(f"{Fore.CYAN}2. TCP SYN Ping (-sn -PS)")
        print(f"{Fore.CYAN}3. ARP Discovery (-sn -PR)")
        print(f"{Fore.CYAN}4. TCP ACK Ping (-sn -PA)")
        print(f"{Fore.RED}0. Back to Main Menu")
        choice = input(f"\n{Fore.WHITE}Select Option: ")
        if choice == '0':
            break
        args_map = {"1": "-sn -PE", "2": "-sn -PS", "3": "-sn -PR", "4": "-sn -PA"}
        if choice in args_map:
            target = input(f"{Fore.CYAN}Enter IP/Subnet (e.g. 192.168.1): ")
            results, final_target = scanner.execute_scan(target, args_map[choice])
            if results:
                print("\n" + tabulate(results, headers="keys", tablefmt="fancy_grid"))
                scanner.export_data(results, final_target)
            else:
                print(f"{Fore.RED}[!] No live hosts detected.")
        else:
            print(f"{Fore.RED}Invalid selection.")

def _port_scan_menu(scanner: ScannerEngine):
    options = {
        "1": ("TCP Connect Scan", "-sT"), "2": ("TCP Stealth (SYN)", "-sS"),
        "3": ("FIN Scan", "-sF"), "4": ("Xmas Scan", "-sX"), "5": ("Null Scan", "-sN"),
        "6": ("UDP Scan", "-sU"), "7": ("ACK Scan", "-sA"), "8": ("Service/Version", "-sV"),
        "9": ("OS Discovery", "-O"), "10": ("Aggressive", "-A"), "11": ("Zombie Scan", "-sI")
    }
    while True:
        print(f"\n{Fore.MAGENTA}--- PORT DISCOVERY & RECON ---\n")
        for k, (name, arg) in options.items():
            print(f"{k}. {Fore.CYAN}{name} ({arg})")
        print(f"{Fore.RED}0. Back to Main Menu")
        choice = input(f"\n{Fore.WHITE}Select Option: ")
        if choice == '0':
            break
        if choice in options:
            name, arg = options[choice]
            target = input(f"{Fore.WHITE}Enter Target IP: ")
            if choice == "11":
                zombie = input(f"{Fore.WHITE}Enter Zombie Host IP: ")
                arg = f"-sI {zombie}"
            results, final_target = scanner.execute_scan(target, arg)
            if results:
                print("\n" + tabulate(results, headers="keys", tablefmt="fancy_grid"))
                scanner.export_data(results, final_target)
        else:
            print(f"{Fore.RED}Invalid selection.")

def run_network_scan():
    scanner = ScannerEngine()
    while True:
        print(f"\n{Fore.CYAN}╔═══════════════════════════════════╗")
        print(f"{Fore.CYAN}║       NETWORK SCANNER (PySecOps) ~ ║")
        print(f"{Fore.CYAN}╚═══════════════════════════════════╝\n")
        print(f"{Fore.CYAN}1. Host Scan")
        print(f"{Fore.CYAN}2. Port Scan")
        print(f"{Fore.CYAN}3. Full Scan (-p- -A -sV)")
        print(f"{Fore.RED}0. Back to Main Menu")
        m_choice = input(f"\n{Fore.WHITE}Select Scan Type: ")
        if m_choice == '1':
            _host_scan_menu(scanner)
        elif m_choice == '2':
            _port_scan_menu(scanner)
        elif m_choice == '3':
            target = input(f"{Fore.WHITE}Enter Target (e.g. 10.0.0.1 or 192.168.1): ")
            if target:
                results, final_target = scanner.execute_scan(target, "-p- -A -sV")
                if results:
                    print("\n" + tabulate(results, headers="keys", tablefmt="fancy_grid"))
                    scanner.export_data(results, final_target)
        elif m_choice == '0':
            return "back"
        else:
            print(f"{Fore.RED}[!] Invalid option.")

# =============================================================================
# 2. WEB SCRAPER
# =============================================================================

def collect_website_info(url: str) -> dict:
    data = {}
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        print("\033[33;1m Examining Content...\n\033[0m")
        time.sleep(1)
        domain = url.split("//")[-1].split("/")[0]
        data['Domain'] = domain
        if whois:
            try:
                w = whois.whois(domain)
                data['Hosting Platform'] = w.registrar
                data['Hosting Date'] = str(w.creation_date)
                data['Location'] = w.country
            except Exception as e:
                data['Hosting Platform'] = f"Error: {e}"
                data['Hosting Date'] = data['Location'] = "Not available"
        else:
            data['Hosting Platform'] = data['Hosting Date'] = data['Location'] = "N/A (whois not installed)"
        if builtwith:
            try:
                data['Technologies'] = builtwith.parse(url)
            except Exception as e:
                data['Technologies'] = str(e)
        else:
            data['Technologies'] = "N/A (builtwith not installed)"
        title = soup.find('title')
        data['Page Title'] = title.text if title else 'N/A'
        header_print("Page Title : ")
        print(data['Page Title'])
        links = []
        header_print("Links found: ")
        for link in soup.find_all('a'):
            href = link.get('href')
            text = link.get_text(strip=True)
            if href:
                links.append({'text': text, 'href': href})
                print(f"\33[31;1m - \033[0m \33[91;3m{text}: {href}\033[0m")
        data['Links'] = links
        headings = [h.get_text(strip=True) for h in soup.find_all(['h1', 'h2', 'h3'])]
        data['Headings'] = headings
        header_print("Headings found: ")
        for h in headings:
            print(f"  - {h}")
        paras = [p.get_text(strip=True)[:100] for p in soup.find_all('p')[:3]]
        data['Paragraphs'] = paras
        data['Meta Tags'] = [m.get('content') for m in soup.find_all('meta') if m.get('content')]
        apis = [s.get('src') for s in soup.find_all('script') if s.get('src') and 'api' in s.get('src', '').lower()]
        data['API Integrations'] = apis or "No obvious API references"
        text = soup.get_text()
        data['Contact Details'] = {
            'Emails': [w for w in text.split() if '@' in w],
            'Phones': [w for w in text.split() if w.isdigit() and len(w) >= 10]
        }
        weak = []
        if "https://" not in url:
            weak.append("No HTTPS (insecure)")
        if "X-Powered-By" in response.headers:
            weak.append("Server reveals technology in headers")
        data['Weak Points'] = weak if weak else "No obvious weak points"
        return data
    except Exception as e:
        print(f"Error: {e}")
        return data

def _export_web_scraper_data(data: dict):
    default_name = (data.get('Domain', data.get('Page Title', 'website_data')) or 'website_data').replace('www.', '').split('/')[0]
    filename = default_name + ".txt"
    counter = 1
    orig = filename
    while os.path.exists(filename):
        name, ext = orig.rsplit('.', 1)
        filename = f"{name}_{counter}.{ext}"
        counter += 1
    with open(filename, 'w', encoding='utf-8') as f:
        for k, v in data.items():
            f.write(f"{k}: {v}\n")
    print(f"\033[42;1m.....Data exported to \033[42;3m {filename}\033[0m")

def run_web_scraper():
    display_banner("Web Scraper", "Python Web analyzer")
    target = input("Enter the domain url (http:// or https://): ").strip()
    if not target:
        print("No URL provided.")
        return "back"
    if target == "0":
        return "back"
    info = collect_website_info(target)
    header_print("Collected Website Information : ")
    for k, v in info.items():
        print(f"\033[35;1m{k}: \033[0m{v}")
    header_print("Export Options : ")
    choice = input("\n0 = export | 1 = exit : ")
    if choice == "0":
        _export_web_scraper_data(info)
    return "back"

# =============================================================================
# 3. WEB RECON
# =============================================================================

def _export_recon(target: str, ip: str, headers: dict, tech: set, dns_data: str, subdomains: set):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain_name = target.split('.')[0]
    filename = f"{domain_name}_{timestamp}.txt"
    with open(filename, 'w') as f:
        f.write(f"{'='*60}\nRECONNAISSANCE REPORT - {target}\n{'='*60}\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\nTarget: {target}\nResolved IP: {ip}\n\n")
        f.write("HTTP HEADERS\n")
        for h, v in headers.items():
            f.write(f"{h}: {v}\n")
        f.write("\nDETECTED TECHNOLOGIES\n")
        for t in sorted(tech):
            f.write(f"- {t}\n")
        f.write("\nDNS RECORDS\n" + dns_data + "\nSUBDOMAINS\n")
        for sub in subdomains:
            f.write(f"- {sub}\n")
    console.print(f"[bold green]✔ Data exported to: {filename}[/bold green]")

def _detect_technology(headers: dict, html: str) -> set:
    tech = set()
    server = headers.get("Server", "").lower()
    powered = headers.get("X-Powered-By", "").lower()
    if "apache" in server: tech.add("Apache Web Server")
    if "nginx" in server: tech.add("Nginx Web Server")
    if "iis" in server: tech.add("Microsoft IIS")
    if "php" in powered: tech.add("PHP Backend")
    if "asp.net" in powered: tech.add("ASP.NET Backend")
    if "express" in powered: tech.add("Node.js (Express)")
    html_l = html.lower()
    if "wordpress" in html_l or "wp-content" in html_l: tech.add("WordPress CMS")
    if "drupal" in html_l: tech.add("Drupal CMS")
    if "joomla" in html_l: tech.add("Joomla CMS")
    if "react" in html_l: tech.add("React.js")
    if "angular" in html_l: tech.add("Angular")
    if "vue" in html_l: tech.add("Vue.js")
    if "content-security-policy" in headers: tech.add("Content Security Policy Enabled")
    if "strict-transport-security" in headers: tech.add("HSTS Enabled")
    return tech

def _dns_records(domain: str) -> str:
    if not dns:
        console.print("[yellow]dnspython not installed - skipping DNS[/yellow]")
        return ""
    dns_data = ""
    for rtype in ["A", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                dns_data += f"{rtype}: {str(rdata)}\n"
        except Exception:
            pass
    return dns_data

def _subdomain_enum(domain: str) -> set:
    subs = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        data = requests.get(url, timeout=10).json()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                if domain in name:
                    subs.add(name.strip())
    except Exception:
        console.print("[yellow]⚠ Subdomain data unavailable[/yellow]")
    return subs

def gather_target_info_recon(target: str):
    console.print(Panel(f"Target Information Gathering\nTarget: {target}", title="Reconnaissance"))
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        console.print("[red]Invalid target[/red]")
        return
    basic = Table(title="Basic Target Info")
    basic.add_column("Field", style="cyan")
    basic.add_column("Value", style="green")
    basic.add_row("Target", target)
    basic.add_row("Resolved IP", ip)
    console.print(basic)
    headers = {}
    html = ""
    try:
        r = requests.get(f"http://{target}", timeout=5)
        headers, html = r.headers, r.text
    except Exception:
        pass
    header_table = Table(title="HTTP Headers")
    header_table.add_column("Header", style="yellow")
    header_table.add_column("Value", overflow="fold")
    for h, v in headers.items():
        header_table.add_row(h, v)
    console.print(header_table)
    tech = _detect_technology(headers, html)
    tech_table = Table(title="Detected Technologies")
    tech_table.add_column("Technology", style="green")
    for t in sorted(tech) or ["No technology fingerprint detected"]:
        tech_table.add_row(t)
    console.print(tech_table)
    try:
        geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        geo_table = Table(title="IP Geolocation")
        geo_table.add_column("Field", style="cyan")
        geo_table.add_column("Value", style="green")
        for key in ["country", "regionName", "city", "isp", "org"]:
            geo_table.add_row(key.capitalize(), geo.get(key, "N/A"))
        console.print(geo_table)
    except Exception:
        pass
    dns_data = _dns_records(target)
    subdomains = _subdomain_enum(target)
    console.print("[bold green]✔ Information gathering completed[/bold green]\n")
    export_choice = input("Do you want to export the results? (y/n): ").strip().lower()
    if export_choice == 'y':
        _export_recon(target, ip, headers, tech, dns_data, subdomains)
    choice = input("Do you want to perform another recon? (y/n): ").strip().lower()
    return choice == 'y'

def run_web_recon():
    display_banner("PyRecon", "Comprehensive Target Reconnaissance Tool")
    while True:
        target = console.input("Enter domain or IP: ").strip()
        if not target:
            return "back"
        if not gather_target_info_recon(target):
            return "back"

# =============================================================================
# 4. PASSWORD GENERATOR
# =============================================================================

SPECIALS = "!@#$%^&*"
platform_keywords = {
    "facebook": ["fb", "face", "book", "meta", "social", "friend", "like", "share"],
    "twitter": ["tweet", "bird", "chirp", "follow", "hashtag", "trend", "dm"],
    "instagram": ["insta", "gram", "photo", "story", "filter", "like", "follow"],
    "linkedin": ["link", "connect", "network", "professional", "job", "career"],
    "email": ["mail", "inbox", "send", "receive", "compose", "draft"],
    "github": ["code", "repo", "commit", "branch", "pull", "merge"],
    "amazon": ["ama", "zon", "prime", "shop", "cart", "order", "kindle", "aws"],
    "netflix": ["net", "flix", "stream", "binge", "movie", "series", "show", "watch"]
}

def password_strength(pwd: str) -> str:
    length = len(pwd)
    categories = sum([
        any(c.islower() for c in pwd),
        any(c.isupper() for c in pwd),
        any(c.isdigit() for c in pwd),
        any(c in SPECIALS for c in pwd)
    ])
    if length >= 12 and categories >= 4:
        return "Strong"
    if length >= 8 and categories >= 3:
        return "Medium"
    return "Weak"

def generate_personalized_password(name: str, sec_word: str, number: str, name_len: int, platform_name: str) -> str:
    n = name[:name_len].capitalize()
    name_part = (n[0].upper() + n[1:-1] + n[-1].upper()) if len(n) >= 2 else n.upper()
    word_part = sec_word.capitalize()
    number_part = secrets.choice([number[i:i+4] for i in range(len(number)-3)]) if len(number) >= 4 else number
    symbol = secrets.choice(SPECIALS)
    symbol_1 = secrets.choice(SPECIALS)
    platform_name = (platform_name or "other").lower()
    if platform_name in platform_keywords:
        keywords = platform_keywords[platform_name]
        social_kw = secrets.choice(keywords)
        if any(kw in name.lower() or kw in sec_word.lower() for kw in keywords):
            symbol = secrets.choice(SPECIALS.replace('@', '').replace('#', ''))
            symbol_1 = secrets.choice(SPECIALS.replace('@', '').replace('#', ''))
    else:
        social_kw = platform_name or "Secure"
    return f"{name_part}{symbol}{word_part}{number_part}{symbol_1}{str(social_kw).capitalize()}"

def run_password_generator():
    display_banner("Password Generator", "Secure and Personalized Passwords")
    platformlist = "Facebook\nTwitter\nInstagram\nLinkedIn\nEmail\nGitHub\nAmazon\nNetflix\nothers"
    while True:
        name = console.input("[bold dim]Enter your name: [/bold dim]").strip()
        sec_word = console.input("[bold dim]Enter your second word: [/bold dim]").strip()
        number = console.input("[bold dim]Enter your number: [/bold dim]").strip()
        if not number.isdigit():
            console.print("[red]Error: Please enter only numbers[/red]")
            continue
        name_len = int(console.input("[bold dim]How many characters from name to use? (min 3): [/bold dim]") or "4")
        console.print(f"[italic dim] {platformlist} [/italic dim]")
        platform = console.input("[bold dim]For which account will you use this password? [/bold dim]").strip()
        while True:
            password = generate_personalized_password(name, sec_word, number, name_len, platform)
            if password_strength(password) != "Weak":
                break
        strength = password_strength(password)
        console.print("\n[green bold]Generated Password:[/green bold]", password)
        console.print("[green bold]Password Strength:[/green bold]", strength)
        again = console.input("\n[bold dim]Generate another password? (y/n): [/bold dim]").strip().lower()
        if again != 'y':
            return "back"

# =============================================================================
# 5. CLICKJACKING TESTER
# =============================================================================

def _clickjacking_logo():
    logo = f"""
    {Fore.RED}
    ╔═══════════════════════════════════════╗
    ║     {Style.BRIGHT}CLICKJACKING VULNERABILITY TESTER ║
    ║     {Fore.LIGHTCYAN_EX}{Style.DIM}Detect and Mitigate Clickjacking{Fore.RED}{Style.NORMAL}  ║
    ╚═════════════{Fore.YELLOW}{Style.BRIGHT}By PySecOps{Fore.RED}{Style.NORMAL}═══════════════╝
    {Style.RESET_ALL}
    """
    print(logo)

class ClickjackingTester:
    def __init__(self):
        self.results = []
        self.stop_animation = False

    def _animate(self, message: str):
        chars = "\\|/-"
        idx = 0
        while not self.stop_animation:
            sys.stdout.write(f"\r{Fore.CYAN}{message} {chars[idx % len(chars)]}{Style.RESET_ALL}")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(message) + 2) + "\r")

    def log_result(self, detected: str, location: str, bypass: str, action: str):
        self.results.append([detected, location, bypass, action])

    def scan_global(self, url: str):
        if not url.startswith("http"):
            url = "https://" + url
        self.stop_animation = False
        t = threading.Thread(target=self._animate, args=("Scanning remote headers",))
        t.start()
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers
            self.stop_animation = True
            t.join()
            xfp = headers.get('X-Frame-Options', 'MISSING').upper()
            csp = headers.get('Content-Security-Policy', 'MISSING')
            if xfp == 'MISSING' and 'frame-ancestors' not in csp.lower():
                self.log_result(f"{Fore.RED}VULNERABLE: No Framing Protection{Style.RESET_ALL}",
                    f"{Fore.YELLOW}HTTP Headers (Remote){Style.RESET_ALL}", f"{Fore.YELLOW}Standard iframe embed{Style.RESET_ALL}",
                    f"{Fore.GREEN}Add 'X-Frame-Options: DENY' or CSP{Style.RESET_ALL}")
            else:
                self.log_result(f"{Fore.GREEN}PROTECTED: Headers Found{Style.RESET_ALL}", "HTTP Headers", "N/A", "Keep headers updated")
            print(f"\n{Fore.CYAN}Server Headers (Top 10):{Style.RESET_ALL}")
            for k, v in list(headers.items())[:10]:
                print(f"  {Fore.YELLOW}{k}{Style.RESET_ALL}: {v}")
        except Exception as e:
            self.stop_animation = True
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def scan_local(self, filepath: str):
        if not os.path.exists(filepath):
            print(f"{Fore.RED}File not found!{Style.RESET_ALL}")
            return
        self.stop_animation = False
        t = threading.Thread(target=self._animate, args=("Analyzing vulnerable segments",))
        t.start()
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            self.stop_animation = True
            t.join()
            found_protection = False
            for i, line in enumerate(lines):
                if "http-equiv=\"X-Frame-Options\"" in line or "frame-ancestors" in line:
                    self.log_result(f"{Fore.GREEN}PROTECTED: Meta/CSP Found{Style.RESET_ALL}", f"Line {i+1}", "N/A", "Verify server-side headers")
                    found_protection = True
                    break
            if not found_protection:
                for i, line in enumerate(lines):
                    if "<head>" in line.lower():
                        self.log_result(f"{Fore.RED}VULNERABLE: No Meta Protection{Style.RESET_ALL}", f"Line {i+1} (Header)", "UI Redressing", "Inject Protection after <head>")
                        break
        except Exception as e:
            self.stop_animation = True
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def display_results(self):
        headers = [f"{Fore.CYAN}Issue{Style.RESET_ALL}", f"{Fore.CYAN}Location{Style.RESET_ALL}", f"{Fore.CYAN}Bypass{Style.RESET_ALL}", f"{Fore.CYAN}Action{Style.RESET_ALL}"]
        print("\n" + tabulate(self.results, headers=headers, tablefmt="grid"))

    def export_report(self):
        choice = input(f"\n{Fore.CYAN}Export report to text? (y/n): {Style.RESET_ALL}").lower()
        if choice == 'y':
            filename = f"clickjacking_report_{int(time.time())}.txt"
            clean = [[str(item).replace('\x1b', '').split('m')[-1] for item in row] for row in self.results]
            with open(filename, 'w') as f:
                f.write(tabulate(clean, headers=["Issue", "Location", "Bypass", "Action"], tablefmt="grid"))
            print(f"{Fore.GREEN}Report saved: {filename}{Style.RESET_ALL}")

def run_clickjacking():
    _clickjacking_logo()
    while True:
        print(f"\n{Fore.LIGHTBLUE_EX}{Style.BRIGHT}--- Clickjacking Tester Menu ---{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}1. Global Domain Check")
        print(f"{Fore.GREEN}2. Local File Check (HTML/JS)")
        print(f"{Fore.RED}3. Back to Main Menu")
        choice = input(f"{Fore.CYAN}Select option: ")
        tester = ClickjackingTester()
        if choice == '1':
            url = input(f"\n{Fore.CYAN}Enter URL: {Style.RESET_ALL}")
            tester.scan_global(url)
            tester.display_results()
            tester.export_report()
        elif choice == '2':
            path = input(f"{Fore.CYAN}Enter file path: {Style.RESET_ALL}")
            tester.scan_local(path)
            tester.display_results()
            tester.export_report()
        elif choice == '3':
            return "back"
        else:
            print(f"{Fore.RED}Invalid selection.")

# =============================================================================
# 6. FILE INTEGRITY
# =============================================================================

BASELINE_FILE = "file_baseline.json"
IGNORE_FILES_FIM = ["file_baseline.json"]

def _normalize_path(path: str) -> str:
    return os.path.abspath(path)

def _calculate_hash(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def _get_metadata(path: str) -> dict:
    st = os.stat(path)
    return {"size": st.st_size, "mtime": st.st_mtime, "permissions": stat.filemode(st.st_mode), "owner": getpass.getuser()}

def _create_baseline(directory: str):
    directory = _normalize_path(directory)
    baseline = {"__root__": directory, "files": {}}
    for root, _, files in os.walk(directory):
        for file in files:
            if file in IGNORE_FILES_FIM:
                continue
            path = _normalize_path(os.path.join(root, file))
            h = _calculate_hash(path)
            if h:
                baseline["files"][path] = {"hash": h, "meta": _get_metadata(path)}
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)
    console.print("[green]✔ Baseline created successfully...[/green]")

def _ai_risk_assessment(m: int, d: int, n: int):
    if IsolationForest is None or np is None:
        if d > 0 or m > 3 or n > 2:
            return "HIGH", "Anomalous file activity"
        return "LOW", "Normal behavior"
    reasons = []
    if d > m and d > 0: reasons.append("High number of deletions")
    if m > 3: reasons.append("Multiple file modifications")
    if n > 2: reasons.append("Unexpected new files")
    ai_model = IsolationForest(n_estimators=150, contamination=0.25, random_state=42)
    ai_model.fit(np.array([[0, 0, 0], [1, 0, 0], [0, 1, 0], [0, 0, 1], [2, 1, 1]]))
    if ai_model.predict([[m, d, n]])[0] == -1:
        return "HIGH", "; ".join(reasons) or "Anomalous file activity"
    return "LOW", "Normal behavior"

def _check_integrity(directory: str):
    directory = _normalize_path(directory)
    if not os.path.exists(BASELINE_FILE):
        console.print("[red]Baseline not found[/red]")
        return
    with open(BASELINE_FILE) as f:
        baseline = json.load(f)
    if baseline["__root__"] != directory:
        console.print(Panel("Baseline directory mismatch. Use the SAME directory used during baseline creation.", title="Directory Error", style="red"))
        return
    current = {}
    for root, _, files in os.walk(directory):
        for file in files:
            if file in IGNORE_FILES_FIM:
                continue
            path = _normalize_path(os.path.join(root, file))
            h = _calculate_hash(path)
            if h:
                current[path] = {"hash": h, "meta": _get_metadata(path)}
    m = d = n = 0
    user = getpass.getuser()
    table = Table(title="File Integrity Report")
    table.add_column("File", overflow="fold")
    table.add_column("Status")
    table.add_column("Details")
    for path, base in baseline["files"].items():
        if path not in current:
            d += 1
            table.add_row(path, "[red]DELETED[/red]", f"Last known owner: {base['meta']['owner']} | Detected by: {user}")
        else:
            curr = current[path]
            changes = []
            if base["hash"] != curr["hash"]: changes.append("Content changed")
            if base["meta"] != curr["meta"]: changes.append("Metadata changed")
            if changes:
                m += 1
                when = datetime.fromtimestamp(curr["meta"]["mtime"]).isoformat()
                table.add_row(path, "[yellow]MODIFIED[/yellow]", f"{', '.join(changes)} | Modified at {when} | Detected by {user}")
    for path in current:
        if path not in baseline["files"]:
            n += 1
            table.add_row(path, "[green]NEW[/green]", f"Owner: {current[path]['meta']['owner']} | Detected by {user}")
    console.print(table)
    risk, reason = _ai_risk_assessment(m, d, n)
    console.print(Panel(f"Modified: {m}\nDeleted: {d}\nNew: {n}\n\nRisk Level: {risk}\nReason: {reason}", title="AI Security Assessment", style="red" if risk == "HIGH" else "green"))

def _live_monitor(directory: str):
    if Observer is None:
        console.print("[red]watchdog not installed - live monitor unavailable[/red]")
        return
    directory = _normalize_path(directory)

    class Monitor(FileSystemEventHandler):
        def on_any_event(self, event):
            if event.is_directory:
                return
            user = getpass.getuser()
            now = datetime.now().isoformat()
            if isinstance(event, FileMovedEvent):
                console.print(Panel(f"Event: File name changed\nOld: {_normalize_path(event.src_path)}\nNew: {_normalize_path(event.dest_path)}\nTime: {now}\nDetected by: {user}", title="Live File Event", style="magenta"))
                return
            if event.event_type == "deleted":
                console.print(Panel(f"Event: File deleted\nFile: {_normalize_path(event.src_path)}\nTime: {now}\nDetected by: {user}", title="Live File Event", style="red"))
            elif event.event_type == "created":
                console.print(Panel(f"Event: File created\nFile: {_normalize_path(event.src_path)}\nTime: {now}\nDetected by: {user}", title="Live File Event", style="green"))
            elif event.event_type == "modified":
                console.print(Panel(f"Event: File modified\nFile: {_normalize_path(event.src_path)}\nTime: {now}\nDetected by: {user}", title="Live File Event", style="yellow"))

    observer = Observer()
    observer.schedule(Monitor(), directory, recursive=True)
    observer.start()
    console.print("[green]Live monitoring started (Ctrl+C to stop)[/green]")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

_file_integrity_directory = None

def run_file_integrity():
    global _file_integrity_directory
    console.print("\n[bold green]File System Integrity Monitor[/bold green]\n")
    console.print("1. Create Baseline")
    console.print("2. Check File Integrity")
    console.print("3. Live File Monitoring")
    console.print("0. Back to Main Menu")
    choice = console.input("\nEnter choice: ").strip()
    if choice == "1":
        directory = console.input("Directory Path: ").strip()
        if not os.path.isdir(directory):
            console.print("[red]Invalid directory.[/red]")
            return run_file_integrity()
        _file_integrity_directory = directory
        _create_baseline(directory)
        return run_file_integrity()
    elif choice == "2":
        if _file_integrity_directory is None:
            console.print("[red]Create a baseline first (option 1).[/red]")
            return run_file_integrity()
        _check_integrity(_file_integrity_directory)
        return run_file_integrity()
    elif choice == "3":
        if _file_integrity_directory is None:
            console.print("[red]Create a baseline first (option 1).[/red]")
            return run_file_integrity()
        _live_monitor(_file_integrity_directory)
        return run_file_integrity()
    elif choice == "0":
        return "back"
    else:
        console.print("[red]Invalid choice[/red]")
        return run_file_integrity()

# =============================================================================
# 7. PHISHING LINK SCANNER
# =============================================================================

def extract_links_from_file(file_path: str) -> list:
    urls = []
    ext = file_path.lower()
    try:
        if ext.endswith('.pdf'):
            if PdfReader is None:
                console.print("[red]PyPDF2 not installed - PDF extraction unavailable[/red]")
                return []
            reader = PdfReader(file_path)
            text = "".join([p.extract_text() or "" for p in reader.pages])
        elif ext.endswith('.csv'):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                text = " ".join([",".join(row) for row in reader])
        else:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        found = re.findall(r'(https?://[^\s,]+)', text)
        return list(dict.fromkeys(found))
    except Exception as e:
        console.print(f"[bold red]Error reading file:[/] {e}")
        return []

def analyze_phishing_link(url: str):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    domain = parsed.netloc
    flags = []
    score = 0
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        flags.append("IP-Address Host")
        score += 40
    if len(url) > 75:
        flags.append("Excessive Length")
        score += 15
    if "@" in url:
        flags.append("Auth-Masking (@)")
        score += 30
    if parsed.scheme == 'http':
        flags.append("No Encryption")
        score += 20
    risky_tlds = ['.zip', '.mov', '.top', '.xyz', '.work', '.click', '.gdn']
    if any(domain.endswith(tld) for tld in risky_tlds):
        flags.append(f"Risky TLD ({domain.split('.')[-1]})")
        score += 15
    if whois:
        try:
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                days = (datetime.now() - creation).days
                if days < 60:
                    flags.append(f"New Domain ({days}d)")
                    score += 35
        except Exception:
            pass
    if score >= 65: verdict = "[bold red]MALICIOUS[/]"
    elif score >= 30: verdict = "[bold yellow]SUSPICIOUS[/]"
    else: verdict = "[bold green]CLEAN[/]"
    flag_str = ", ".join(flags) if flags else "[dim green]No Threats[/dim green]"
    return flag_str, score, verdict

def run_phishing_scanner():
    while True:
        console.clear()
        console.print(Panel.fit("[bold cyan]🛡️ ADVANCED LINK GUARDIAN INTERFACE[/]\n[dim]High-Speed Phishing Intelligence[/dim]", border_style="bright_blue", padding=(1, 5), subtitle="[bold yellow]By PySecOps[/bold yellow]"))
        console.print("\n[bold white]SELECT SCAN MODE:[/]")
        console.print("[bold green]1.[/] Single URL Scanner")
        console.print("[bold green]2.[/] Bulk Link Scanner (PDF/CSV/TXT)")
        mode = input("\nChoice (1/2): ").strip()
        targets = []
        if mode == "1":
            url = console.input("[bold white]➜ Paste URL to scan: [/]").strip()
            if url:
                targets.append(url)
        else:
            path = console.input("[bold white]➜ Enter file path: [/]").strip()
            targets = extract_links_from_file(path)
            console.print(f"[cyan]ℹ Found {len(targets)} unique links.[/cyan]")
        if not targets:
            console.print("[red]No valid links to process.[/]")
            if input("Try again? (y/n): ").strip().lower() != 'y':
                break
            continue
        from rich.table import Table as RichTable
        from rich import box as rich_box
        results_table = RichTable(title="\n[bold underline cyan]SEC-INTEL LIVE FEED[/]", box=rich_box.ROUNDED, expand=True, header_style="bold magenta")
        results_table.add_column("ID", width=4, justify="center")
        results_table.add_column("Target URL", ratio=3)
        results_table.add_column("Security Flags", ratio=3)
        results_table.add_column("Score", width=8, justify="center")
        results_table.add_column("Verdict", width=12, justify="right")
        console.print("\n[bold yellow]Initializing Security Engine...[/]")
        time.sleep(1)
        for i, link in enumerate(targets, 1):
            flags, score, verdict = analyze_phishing_link(link)
            s_color = "red" if score >= 60 else "yellow" if score >= 30 else "green"
            results_table.add_row(str(i), link[:50] + "..." if len(link) > 50 else link, flags, f"[{s_color}]{score}[/]", verdict)
        console.print(results_table)
        console.print("\n" + "━" * 50)
        if input("[bold cyan]Perform another scan? (y/n): [/]").strip().lower() != 'y':
            return "back"

# =============================================================================
# 8. FILE SCANNER (keyword)
# =============================================================================

def load_keywords(keywords_file: str) -> list:
    try:
        with open(keywords_file, 'r', encoding='utf-8') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: {keywords_file} not found.")
        return []

def scan_file_keywords(file_path: str, keywords: list) -> list:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
        return [kw for kw in keywords if kw in content]
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []

def run_file_scanner():
    display_banner("File_Scanner", "Comprehensive File Analysis Tool")
    file_path = input("\nEnter the file path to scan: ").strip()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    keywords_file = os.path.join(base_dir, "Keywords.txt")
    if not os.path.exists(file_path):
        console.print(f"[red]Error: File not found - {file_path}[/red]")
        return "back"
    keywords = load_keywords(keywords_file)
    if not keywords:
        console.print("[red]No keywords to scan (Keywords.txt missing or empty).[/red]")
        return "back"
    found = scan_file_keywords(file_path, keywords)
    if found:
        console.print(f"[yellow][ALERT] Suspicious keywords found in: {file_path}[/yellow]")
        for kw in found:
            console.print(f"  - Keyword found: '{kw}'")
    else:
        console.print("[green]Nothing suspicious found[/green]")
    console.print(Panel("[bold green]File scanning completed[/bold green]"))
    choice = input("Scan another file? (y/n): ").strip().lower()
    if choice != 'y':
        return "back"
    return run_file_scanner()

# =============================================================================
# MAIN MENU & ENTRY POINT
# =============================================================================

def main():
    console.print("\n[bold italic green]Select a feature from the list below:[/]\n")
    console.print(
        "1. Network Scanner\n"
        "2. Web Scraper\n"
        "3. Web Reconnaissance\n"
        "4. Password Generator\n"
        "5. Clickjacking Tester\n"
        "6. File Integrity Checker\n"
        "7. Phishing Link Scanner\n"
        "8. File Scanner (keywords)\n"
        "9. Exit\n",
        style="cyan"
    )
    choice = input("Select a feature to proceed (1-9): ").strip()
    runners = {
        "1": run_network_scan,
        "2": run_web_scraper,
        "3": run_web_recon,
        "4": run_password_generator,
        "5": run_clickjacking,
        "6": run_file_integrity,
        "7": run_phishing_scanner,
        "8": run_file_scanner,
    }
    if choice == "9":
        console.print("\n[bold red]Exiting PySecOps...[/bold red]")
        return
    if choice in runners:
        result = runners[choice]()
        if result == "back":
            console.print("\n[bold yellow]Returning to main menu...[/bold yellow]\n")
            main()
    else:
        console.print("[bold red]Invalid selection. Choose 1-9.[/bold red]")
        main()


if __name__ == "__main__":
    print_logo()
    print(f"\033[3;31;1m Welcome to PySecOps - Your Python Security Operations Toolkit! \n\033[0m")
    print("Initializing modules...\n")
    main()
