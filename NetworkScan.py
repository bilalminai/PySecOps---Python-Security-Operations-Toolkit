from logging import INFO
import nmap
import os
import sys
import time
import threading
import itertools
from datetime import datetime
from tabulate import tabulate
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

class ScannerEngine:
    def __init__(self):
        try:
            # Initializing Nmap with -V to check if it's installed
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print(f"{Fore.RED}Error: Nmap not found. Please install Nmap (https://nmap.org) and add it to your PATH.")
            sys.exit(1)

    def format_target(self, target):
        """Converts 3 octets (192.168.1) to 192.168.1.0/24."""
        octets = target.split('.')
        if len(octets) == 3:
            return f"{target}.0/24"
        return target

    def get_color_state(self, state):
        if state == 'open': return f"{Fore.GREEN}open"
        if state == 'closed': return f"{Fore.RED}closed"
        if state == 'filtered': return f"{Fore.YELLOW}filtered"
        return f"{Fore.CYAN}{state}"

    def animate(self, stop_event):
        """Displays an informative loading animation."""
        chars = itertools.cycle(['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'])
        for char in chars:
            if stop_event.is_set():
                break
            sys.stdout.write(f'\r{Fore.CYAN}[{char}] Scanning Engine Active... Please wait...')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * 50 + '\r')

    def execute_scan(self, target, args):
        target = self.format_target(target)
        print(f"\n{Fore.BLUE}[INFO] Initializing Detailed Scan...\n")
        print(f"{Fore.BLUE}[INFO] Target: {Fore.WHITE}{target}")
        print(f"{Fore.BLUE}[INFO] Parameters: {Fore.WHITE}{args}")
        
        stop_animation = threading.Event()
        animation_thread = threading.Thread(target=self.animate, args=(stop_animation,))
        animation_thread.start()

        start_time = datetime.now()
        try:
            # -T4 for speed, --stats-every for internal tracking
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
            
            # Extract basic host info
            hostname = h_obj.hostname() or "Unknown"
            mac = h_obj['addresses'].get('mac', 'N/A')
            vendor = h_obj['vendor'].get(mac, 'N/A')
            latency = h_obj.get('vendor', {}).get('latency', 'N/A') # May require root
            
            # Extract OS Info (if -O or -A was used)
            os_match = "N/A"
            if 'osmatch' in h_obj and h_obj['osmatch']:
                os_match = h_obj['osmatch'][0].get('name', 'N/A')

            # Detailed Port Data
            if 'tcp' in h_obj:
                for port, info in h_obj['tcp'].items():
                    scan_results.append({
                        "IP Address": host,
                        "Hostname": hostname,
                        "Port": port,
                        "State": self.get_color_state(info['state']),
                        "Service": info['name'],
                        "Version": f"{info.get('product', '')} {info.get('version', '')}".strip() or "N/A",
                        "Reason": info.get('reason', 'N/A'),
                        "OS Guess": os_match,
                        "MAC / Vendor": f"{mac} ({vendor})" if mac != 'N/A' else "N/A"
                    })
            else:
                # Fallback for Host Discovery
                state = h_obj.state()
                scan_results.append({
                    "IP Address": host,
                    "Hostname": hostname,
                    "Port": "N/A",
                    "State": f"{Fore.GREEN}UP" if state == 'up' else f"{Fore.RED}DOWN",
                    "Service": "N/A",
                    "Version": "N/A",
                    "Reason": h_obj.get('status', {}).get('reason', 'N/A'),
                    "OS Guess": os_match,
                    "MAC / Vendor": f"{mac} ({vendor})" if mac != 'N/A' else "N/A"
                })
        
        print(f"{Fore.GREEN}\n[*] Scan completed in {duration.total_seconds():.2f} seconds.")
        return scan_results, target

    def export_data(self, data, target):
        choice = input(f"\n{Fore.WHITE}Export these results to a .txt document? (y/n): ").lower()
        if choice == 'y':
            # Create filename using IP and precise timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            clean_ip = target.replace('/', '_').replace('.', '-')
            filename = f"Scan_{clean_ip}_{timestamp}.txt"
            
            # Ensure uniqueness
            if os.path.exists(filename):
                filename = f"Scan_{clean_ip}_{timestamp}_v2.txt"

            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"NETWORK SCAN REPORT\n")
                f.write(f"Target Scope: {target}\n")
                f.write(f"Timestamp:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 80 + "\n")
                # Using grid for the text file to keep it readable
                f.write(tabulate(data, headers="keys", tablefmt="grid"))
                f.write(f"\n\n[EOF] Total Records: {len(data)}")
            
            print(f"{Fore.CYAN}[+] Detailed report generated: {Fore.WHITE}{os.path.abspath(filename)}")

# --- Menu Functions (Procedural Logic) ---

def host_scan_menu(scanner):
    while True:
        print(f"\n{Fore.MAGENTA}--- HOST DISCOVERY OPTIONS ---\n")
        print(f"{Fore.CYAN}1. Ping Sweep {Style.BRIGHT}(-sn -PE) - {Style.DIM}Basic L3 Discovery")
        print(f"{Fore.CYAN}2. TCP SYN Ping {Style.BRIGHT}(-sn -PS) - {Style.DIM}Firewall Bypass")
        print(f"{Fore.CYAN}3. ARP Discovery {Style.BRIGHT}(-sn -PR) - {Style.DIM}Local Network")
        print(f"{Fore.CYAN}4. TCP ACK Ping {Style.BRIGHT}(-sn -PA) - {Style.DIM}Stateless Discovery")
        print(f"{Fore.RED}0. Back to Main Menu")
        
        choice = input(f"\n{Fore.WHITE}Select Option: ")
        if choice == '0': break
        
        args = {"1": "-sn -PE", "2": "-sn -PS", "3": "-sn -PR", "4": "-sn -PA"}.get(choice)
        if args:
            target = input(f"{Fore.CYAN}Enter IP/Subnet (e.g. 192.168.1): ")
            results, final_target = scanner.execute_scan(target, args)
            if results:
                print("\n" + tabulate(results, headers="keys", tablefmt="fancy_grid"))
                scanner.export_data(results, final_target)
            else:
                print(f"{Fore.RED}[!] No live hosts detected with this method.")
        else:
            print(f"{Fore.RED}Invalid selection.")

def port_scan_menu(scanner):
    while True:
        print(f"\n{Fore.MAGENTA}--- PORT DISCOVERY & RECON ---\n")
        options = {
            "1": (f"{Fore.CYAN}TCP Connect Scan", "-sT"),
            "2": (f"{Fore.CYAN}TCP Stealth (SYN)", "-sS"),
            "3": (f"{Fore.CYAN}FIN Scan (Inverse)", "-sF"),
            "4": (f"{Fore.CYAN}Xmas Scan (Inverse)", "-sX"),
            "5": (f"{Fore.CYAN}Null Scan (Inverse)", "-sN"),
            "6": (f"{Fore.CYAN}UDP Scan", "-sU"),
            "7": (f"{Fore.CYAN}ACK Scan (Firewall mapping)", "-sA"),
            "8": (f"{Fore.CYAN}Service/Version Detection", "-sV"),
            "9": (f"{Fore.CYAN}OS Discovery", "-O"),
            "10": (f"{Fore.CYAN}Aggressive (All-in-one)", "-A"),
            "11": (f"{Fore.CYAN}Zombie (Idle) Scan", "-sI")
        }
        for k, v in options.items():
            print(f"{k}. {v[0]} ({v[1]})")
        print(f"{Fore.RED}0. Back to Main Menu")

        choice = input(f"\n{Fore.WHITE}Select Option: ")
        if choice == '0': break

        if choice in options:
            Scan_name = options[choice][0]
            print(f"\n[INFO] Performing {Fore.WHITE}{Scan_name} scan...\n")
            target = input(f"{Fore.WHITE}Enter Target IP: ")
            arg = options[choice][1]
            if choice == "11":
                zombie = input(f"{Fore.WHITE}Enter Zombie (Idle) Host IP: ")
                target = input(f"{Fore.WHITE}Enter Target IP: ")
                arg = f"-sI {zombie}"
            
            results, final_target = scanner.execute_scan(target, arg)
            if results:
                print("\n" + tabulate(results, headers="keys", tablefmt="fancy_grid"))
                scanner.export_data(results, final_target)
        else:
            print(f"{Fore.RED}Invalid selection.")

def main():
    scanner = ScannerEngine()
    while True:
        print(f"\n{Fore.CYAN}╔═══════════════════════════════════╗")
        print(f"{Fore.CYAN}║                                   ║")
        print(f"{Fore.CYAN}║{Fore.MAGENTA}{Style.BRIGHT}          NETWORK SCANNER          {Fore.CYAN}║")
        print(f"{Fore.CYAN}║                                   ║")
        print(f"{Fore.CYAN}╚════════════{Fore.YELLOW}{Style.BRIGHT}By PySecOps{Fore.CYAN}════════════╝")
        # print(f"{Fore.YELLOW}           By PySecOps ")
        print(f"{Fore.CYAN}\n-------------------------------------\n")
        print(f"{Fore.CYAN}1. Host Scan  (Discover live devices)")
        print(f"{Fore.CYAN}2. Port Scan  (Detailed service discovery)")
        print(f"{Fore.CYAN}3. Full Scan  (Deep inspection - All ports)")
        print(f"{Fore.RED}0. Exit Application")

        m_choice = input(f"\n{Fore.WHITE}Select Scan Type : ")

        if m_choice == '1':
            host_scan_menu(scanner)
        elif m_choice == '2':
            port_scan_menu(scanner)
        elif m_choice == '3':
            target = input(f"{Fore.WHITE}Enter Target (e.g. 10.0.0.1 or 192.168.1): ")
            if not target or target == 0 :
                print(f"{Fore.RED}[!] Input Error: Target cannot be empty.\n")
                continue
            print(f"{Fore.YELLOW}[INFO] Performing Full Scan on {target}...\n")
            # Deep Scan: Full port range, Aggressive scripts, OS, and Versions
            results, final_target = scanner.execute_scan(target, "-p- -A -sV")
            if results:
                print("\n" + tabulate(results, headers="keys", tablefmt="fancy_grid"))
                scanner.export_data(results, final_target)
        elif m_choice == '0':
            print(f"{Fore.YELLOW}[!] Shutting down scanner...")
            return "back"
        else:
            print(f"{Fore.RED}[!] Input Error: Please choose 1-4.")

if __name__ == "__main__":
    main()