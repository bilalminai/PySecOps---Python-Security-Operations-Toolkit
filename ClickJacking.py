import requests
import os
import time
import threading
import sys
from tabulate import tabulate
from colorama import Fore, Back, Style, init

init(autoreset=True)

LOGO_PRINTED = False

def print_logo():
    global LOGO_PRINTED
    if not LOGO_PRINTED:
        logo = f"""
    {Fore.RED}
    ╔═══════════════════════════════════════╗
    ║     {Style.BRIGHT}CLICKJACKING VULNERABILITY TESTER ║
    ║                                       ║
    ║     {Fore.LIGHTCYAN_EX}{Style.DIM}Detect and Mitigate Clickjacking{Fore.RED}{Style.NORMAL}  ║
    ║                                       ║
    ╚═════════════{Fore.YELLOW}{Style.BRIGHT}By PySecOps{Fore.RED}{Style.NORMAL}═══════════════╝
    {Style.RESET_ALL}
    """
        print(logo)
        LOGO_PRINTED = True

class ClickjackingTester:
    def __init__(self):
        self.results = []
        self.stop_animation = False

    def animation(self, message):
        chars = "\\|/-"
        idx = 0
        while not self.stop_animation:
            sys.stdout.write(f"\r{Fore.CYAN}{message} {chars[idx % len(chars)]}{Style.RESET_ALL}")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(message) + 2) + "\r")

    def log_result(self, detected, location, bypass, action):
        self.results.append([detected, location, bypass, action])

    def scan_global(self, url):
        if not url.startswith("http"):
            url = "https://" + url
        
        self.stop_animation = False
        t = threading.Thread(target=self.animation, args=("Scanning remote headers",))
        t.start()

        try:
            response = requests.get(url, timeout=10)
            headers = response.headers
            self.stop_animation = True
            t.join()

            xfp = headers.get('X-Frame-Options', 'MISSING').upper()
            csp = headers.get('Content-Security-Policy', 'MISSING')

            if xfp == 'MISSING' and 'frame-ancestors' not in csp.lower():
                self.log_result(
                    f"{Fore.RED}VULNERABLE: No Framing Protection{Style.RESET_ALL}",
                    f"{Fore.YELLOW}HTTP Headers (Remote){Style.RESET_ALL}",
                    f"{Fore.YELLOW}Standard iframe embed{Style.RESET_ALL}",
                    f"{Fore.GREEN}Add 'X-Frame-Options: DENY' or CSP{Style.RESET_ALL}"
                )
            else:
                self.log_result(
                    f"{Fore.GREEN}PROTECTED: Headers Found{Style.RESET_ALL}",
                    "HTTP Headers",
                    "N/A",
                    "Keep headers updated"
                )
            
            print(f"\n{Fore.CYAN}Server Headers (Top 10):{Style.RESET_ALL}")
            for key, value in list(headers.items())[:10]:
                print(f"  {Fore.YELLOW}{key}{Style.RESET_ALL}: {value}")

        except Exception as e:
            self.stop_animation = True
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def scan_local(self, filepath):
        if not os.path.exists(filepath):
            print(f"{Fore.RED}File not found!{Style.RESET_ALL}")
            return

        self.stop_animation = False
        t = threading.Thread(target=self.animation, args=("Analyzing vulnerable segments",))
        t.start()
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            self.stop_animation = True
            t.join()

            print(f"\n{Fore.CYAN}--- Vulnerable Code Segment ---{Style.RESET_ALL}")
            vulnerable = True
            found_protection = False
            
            # First pass: Check for protection
            for i, line in enumerate(lines):
                if "http-equiv=\"X-Frame-Options\"" in line or "frame-ancestors" in line:
                    print(f"{Fore.GREEN}Line {i+1}: {line.strip()}{Style.RESET_ALL}")
                    self.log_result(
                        f"{Fore.GREEN}PROTECTED: Meta/CSP Found{Style.RESET_ALL}",
                        f"Line {i+1}", "N/A", "Verify server-side headers"
                    )
                    vulnerable = False
                    found_protection = True
                    break
            
            # Second pass: If vulnerable, show exactly where it can be tempered (the <head> tag)
            if vulnerable:
                for i, line in enumerate(lines):
                    if "<head>" in line.lower():
                        # Display a small snippet of the vulnerable area
                        start = max(0, i)
                        end = min(len(lines), i + 3)
                        
                        print(f"{Fore.YELLOW}[Target Segment Found]{Style.RESET_ALL}")
                        for idx in range(start, end):
                            prefix = ">>> " if idx == i else "    "
                            color = Fore.RED if idx == i else Fore.WHITE
                            print(f"{color}{prefix}Line {idx+1}: {lines[idx].strip()}{Style.RESET_ALL}")
                        
                        self.log_result(
                            f"{Fore.RED}VULNERABLE: No Meta Protection{Style.RESET_ALL}",
                            f"Line {i+1} (Header)", 
                            "UI Redressing", 
                            "Inject Protection after <head>"
                        )
                        break

        except Exception as e:
            self.stop_animation = True
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def display_results(self):
        headers = [f"{Fore.CYAN}Issue{Style.RESET_ALL}", 
                  f"{Fore.CYAN}Location{Style.RESET_ALL}", 
                  f"{Fore.CYAN}Bypass{Style.RESET_ALL}", 
                  f"{Fore.CYAN}Action{Style.RESET_ALL}"]
        print("\n" + tabulate(self.results, headers=headers, tablefmt="grid"))

    def export_report(self):
        choice = input(f"\n{Fore.CYAN}Export report to text? (y/n): {Style.RESET_ALL}").lower()
        if choice == 'y':
            filename = f"clickjacking_report_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                clean_results = [[str(item).replace('\x1b', '').split('m')[-1] for item in row] for row in self.results]
                f.write(tabulate(clean_results, headers=["Issue", "Location", "Bypass", "Action"], tablefmt="grid"))
            print(f"{Fore.GREEN}Report saved successfully: {filename}{Style.RESET_ALL}")

def main():
    print_logo()
    while True:
        tester = ClickjackingTester()
        print(f"\n{Fore.LIGHTBLUE_EX}{Style.BRIGHT}--- Clickjacking Tester Menu ---{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}1. Global Domain Check (Internet){Style.RESET_ALL}")
        print(f"{Fore.GREEN}2. Local File Check (HTML/JS){Style.RESET_ALL}")
        print(f"{Fore.RED}3. Exit{Style.RESET_ALL}\n")
        
        choice = input(f"{Fore.CYAN}Select option: {Style.RESET_ALL}")

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
            print(f"{Fore.GREEN}Exiting...{Style.RESET_ALL}")
            return "back"
        else:
            print(f"{Fore.RED}Invalid selection.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()