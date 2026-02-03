import socket
from timeit import main
import requests
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from Banner import *
from datetime import datetime

console = Console()

# ---------------- EXPORT DATA ----------------
def export_results(target, ip, headers, tech, dns_data, subdomains):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain_name = target.split('.')[0]
    filename = f"{domain_name}_{timestamp}.txt"
    
    try:
        with open(filename, 'w') as f:
            f.write(f"{'='*60}\n")
            f.write(f"RECONNAISSANCE REPORT - {target}\n")
            f.write(f"{'='*60}\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("BASIC INFORMATION\n")
            f.write(f"Target: {target}\n")
            f.write(f"Resolved IP: {ip}\n\n")
            
            f.write("HTTP HEADERS\n")
            for h, v in headers.items():
                f.write(f"{h}: {v}\n")
            f.write("\n")
            
            f.write("DETECTED TECHNOLOGIES\n")
            for t in sorted(tech):
                f.write(f"- {t}\n")
            f.write("\n")
            
            f.write("DNS RECORDS\n")
            f.write(dns_data)
            f.write("\n")
            
            f.write("SUBDOMAINS\n")
            for sub in subdomains:
                f.write(f"- {sub}\n")
            f.write("\n")
        
        console.print(f"[bold green]✔ Data exported to: {filename}[/bold green]")
        return True
    except Exception as e:
        console.print(f"[red]✘ Export failed: {e}[/red]")
        return False

# ---------------- TECHNOLOGY FINGERPRINTING ----------------
def detect_technology(headers, html):
    tech = set()

    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")

    if "apache" in server.lower():
        tech.add("Apache Web Server")
    if "nginx" in server.lower():
        tech.add("Nginx Web Server")
    if "iis" in server.lower():
        tech.add("Microsoft IIS")

    if "php" in powered.lower():
        tech.add("PHP Backend")
    if "asp.net" in powered.lower():
        tech.add("ASP.NET Backend")
    if "express" in powered.lower():
        tech.add("Node.js (Express)")

    if "wordpress" in html.lower():
        tech.add("WordPress CMS")
    if "wp-content" in html.lower():
        tech.add("WordPress CMS")
    if "drupal" in html.lower():
        tech.add("Drupal CMS")
    if "joomla" in html.lower():
        tech.add("Joomla CMS")

    if "react" in html.lower():
        tech.add("React.js")
    if "angular" in html.lower():
        tech.add("Angular")
    if "vue" in html.lower():
        tech.add("Vue.js")

    if "content-security-policy" in headers:
        tech.add("Content Security Policy Enabled")
    if "strict-transport-security" in headers:
        tech.add("HSTS Enabled")

    return tech

# ---------------- DNS RECORD ENUMERATION ----------------
def dns_records(domain):
    record_types = ["A", "MX", "NS", "TXT"]
    table = Table(title="DNS Records")
    table.add_column("Record Type", style="cyan")
    table.add_column("Value", style="green", overflow="fold")
    dns_data = ""

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                table.add_row(rtype, str(rdata))
                dns_data += f"{rtype}: {str(rdata)}\n"
        except:
            pass

    console.print(table)
    return dns_data

# ---------------- SUBDOMAIN ENUMERATION ----------------
def subdomain_enum(domain):
    table = Table(title="Discovered Subdomains (Passive)")
    table.add_column("Subdomain", style="yellow")
    subs = set()

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        data = requests.get(url, timeout=10).json()

        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                if domain in name:
                    subs.add(name.strip())

        if subs:
            for sub in sorted(subs):
                table.add_row(sub)
        else:
            table.add_row("No subdomains found")

        console.print(table)

    except:
        console.print("[yellow]⚠ Subdomain data unavailable[/yellow]")

    return subs

# ---------------- MAIN RECON ----------------
def gather_target_info(target):
    console.print(Panel(
        f"Target Information Gathering\nTarget: {target}",
        title="Reconnaissance"
    ))

    try:
        ip = socket.gethostbyname(target)
    except:
        console.print("[red]Invalid target[/red]")
        return

    basic = Table(title="Basic Target Info")
    basic.add_column("Field", style="cyan")
    basic.add_column("Value", style="green")

    basic.add_row("Target", target)
    basic.add_row("Resolved IP", ip)
    console.print(basic)

    # HTTP + Tech Detection
    headers = {}
    html = ""

    try:
        r = requests.get(f"http://{target}", timeout=5)
        headers = r.headers
        html = r.text
    except:
        pass

    header_table = Table(title="HTTP Headers")
    header_table.add_column("Header", style="yellow")
    header_table.add_column("Value", overflow="fold")

    for h, v in headers.items():
        header_table.add_row(h, v)

    console.print(header_table)

    tech = detect_technology(headers, html)
    tech_table = Table(title="Detected Technologies")
    tech_table.add_column("Technology", style="green")

    if tech:
        for t in sorted(tech):
            tech_table.add_row(t)
    else:
        tech_table.add_row("No technology fingerprint detected")

    console.print(tech_table)

    # GeoIP
    try:
        geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        geo_table = Table(title="IP Geolocation")
        geo_table.add_column("Field", style="cyan")
        geo_table.add_column("Value", style="green")

        for key in ["country", "regionName", "city", "isp", "org"]:
            geo_table.add_row(key.capitalize(), geo.get(key, "N/A"))

        console.print(geo_table)
    except:
        pass

    dns_data = dns_records(target)
    subdomains = subdomain_enum(target)

    console.print("[bold green]✔ Information gathering completed\n------------------------------------[/bold green]\n")
    
    # Ask user to export
    console.print("Do you want to export the results? (y/n): ", end="")
    export_choice = input().strip().lower()
    if export_choice == 'y':
        export_results(target, ip, headers, tech, dns_data, subdomains)
    
    console.print("\nDo you want to perform another recon? (y/n): ", end=" ")
    choice = input().strip().lower()
    if choice == 'y':
        main()
    else:
        console.print("[bold green]Exiting...\n----------------------[/bold green]")
        return "back"

# ---------------- RUN ----------------
def main():
    display_Banner("PyRecon", "Comprehensive Target Reconnaissance Tool")
    target = console.input("Enter domain or IP: ").strip()
    return gather_target_info(target)

if __name__ == "__main__":
    main()