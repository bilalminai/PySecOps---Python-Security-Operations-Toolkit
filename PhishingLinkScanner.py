import time
import re
import csv
import whois
import datetime
from urllib.parse import urlparse
from PyPDF2 import PdfReader
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()

def extract_links_from_file(file_path):
    """Extracts URLs from TXT, CSV, or PDF files."""
    urls = []
    ext = file_path.lower()
    try:
        if ext.endswith('.pdf'):
            reader = PdfReader(file_path)
            text = "".join([p.extract_text() for p in reader.pages])
        elif ext.endswith('.csv'):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                text = " ".join([",".join(row) for row in reader])
        else: # Default for .txt or others
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        
        # Regex to find URLs
        found = re.findall(r'(https?://[^\s,]+)', text)
        return list(dict.fromkeys(found)) # Remove duplicates while preserving order
    except Exception as e:
        console.print(f"[bold red]Error reading file:[/] {e}")
        return []

def analyze_link(url):
    """Core security engine returning detailed flags and a score."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    domain = parsed.netloc
    flags = []
    score = 0

    # 1. IP Address Check
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        flags.append("IP-Address Host")
        score += 40
    
    # 2. Length Check
    if len(url) > 75:
        flags.append("Excessive Length")
        score += 15

    # 3. Deceptive Symbols
    if "@" in url:
        flags.append("Auth-Masking (@)")
        score += 30

    # 4. HTTPS Check
    if parsed.scheme == 'http':
        flags.append("No Encryption")
        score += 20

    # 5. Suspicious TLDs
    risky_tlds = ['.zip', '.mov', '.top', '.xyz', '.work', '.click', '.gdn']
    if any(domain.endswith(tld) for tld in risky_tlds):
        flags.append(f"Risky TLD ({domain.split('.')[-1]})")
        score += 15

    # 6. WHOIS Domain Age
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        if creation:
            days = (datetime.datetime.now() - creation).days
            if days < 60:
                flags.append(f"New Domain ({days}d)")
                score += 35
    except:
        pass # WHOIS privacy or failure doesn't always mean phishing

    # Determine Verdict
    if score >= 65: verdict = "[bold red]MALICIOUS[/]"
    elif score >= 30: verdict = "[bold yellow]SUSPICIOUS[/]"
    else: verdict = "[bold green]CLEAN[/]"

    flag_str = ", ".join(flags) if flags else "[dim green]No Threats[/dim green]"
    return flag_str, score, verdict

def run_scanner():
    while True:
        console.clear()
        console.print(Panel.fit(
            "[bold cyan]🛡️ ADVANCED LINK GUARDIAN INTERFACE[/]\n[dim]High-Speed Phishing Intelligence[/dim]",
            border_style="bright_blue", padding=(1, 5),
            subtitle="[bold yellow]By PySecOps[/bold yellow]"
        ))

        # Mode Selection
        console.print("\n[bold white]SELECT SCAN MODE:[/]")
        console.print("[bold green]1.[/] Single URL Scanner")
        console.print("[bold green]2.[/] Bulk Link Scanner (PDF/CSV/TXT)")
        
        mode = Prompt.ask("\n[bold yellow]Choice[/]", choices=["1", "2"])
        
        targets = []
        if mode == "1":
            url = console.input("[bold white]➜ Paste URL to scan: [/]").strip()
            if url: targets.append(url)
        else:
            path = console.input("[bold white]➜ Enter file path: [/]").strip()
            with console.status("[bold yellow]Extracting links...[/]"):
                targets = extract_links_from_file(path)
            console.print(f"[cyan]ℹ Found {len(targets)} unique links in target file.[/cyan]")

        if not targets:
            console.print("[red]No valid links found to process.[/]")
            if not Confirm.ask("Try again?"): break
            continue

        # Real-time Table UI
        results_table = Table(
            title="\n[bold underline cyan]SEC-INTEL LIVE FEED[/]", 
            box=box.ROUNDED, 
            expand=True,
            header_style="bold magenta"
        )
        results_table.add_column("ID", width=4, justify="center")
        results_table.add_column("Target URL", ratio=3)
        results_table.add_column("Security Flags", ratio=3)
        results_table.add_column("Score", width=8, justify="center")
        results_table.add_column("Verdict", width=12, justify="right")

        # Start Animation and Live Appending
        console.print("\n[bold yellow]Initializing Security Engine...[/]")
        time.sleep(1)

        with Live(results_table, refresh_per_second=4):
            for i, link in enumerate(targets, 1):
                # Analyze the link
                flags, score, verdict = analyze_link(link)
                
                # Format score color
                s_color = "red" if score >= 60 else "yellow" if score >= 30 else "green"
                
                # Append row live
                results_table.add_row(
                    str(i), 
                    link[:50] + "..." if len(link) > 50 else link, 
                    flags, 
                    f"[{s_color}]{score}[/]", 
                    verdict
                )
                time.sleep(0.5) # Animation delay for visibility

        # Post-Scan Loop
        console.print("\n" + "━"*console.width)
        if not Confirm.ask("[bold cyan]Would you like to perform another scan?[/]"):
            console.print("[bold blue]Shutting down Guardian Engine. Stay safe![/]")
            return "back"
def main():
    try:
        return run_scanner()
    except KeyboardInterrupt:
        console.print("\n[red]Scanner terminated by user.[/]")