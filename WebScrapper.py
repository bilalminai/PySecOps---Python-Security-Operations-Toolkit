import requests
import time
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from Heading import *
from Banner import *
import whois
import builtwith
import os

# -------------------------------
# Unified Website Information Gathering
# -------------------------------
def collect_website_info(URL):
    data = {}
    try:
        response = requests.get(URL, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        print("\033[33;1m Examining Content...\n\033[0m")
        time.sleep(2)

        # ---------------- Domain & WHOIS ----------------
        domain = URL.split("//")[-1].split("/")[0]
        data['Domain'] = domain
        try:
            w = whois.whois(domain)
            data['Hosting Platform'] = w.registrar
            data['Hosting Date'] = str(w.creation_date)
            data['Location'] = w.country
        except Exception as e:
            data['Hosting Platform'] = f"Error: {e}"
            data['Hosting Date'] = "Not available"
            data['Location'] = "Not available"

        # ---------------- Technologies ----------------
        try:
            tech = builtwith.parse(URL)
            data['Technologies'] = tech
        except Exception as e:
            data['Technologies'] = f"Error: {e}"

        # ---------------- Page Title ----------------
        title = soup.find('title')
        data['Page Title'] = title.text if title else 'N/A'
        Header_Print("Page Title : ")
        print(f"{data['Page Title']}")

        # ---------------- Links ----------------
        links = []
        Header_Print("Links found: ")
        for link in soup.find_all('a'):
            href = link.get('href')
            text = link.get_text(strip=True)
            if href:
                links.append({'text': text, 'href': href})
                print(f"\33[31;1m - \033[0m \33[91;3m{text}: {href}\033[0m]")
        data['Links'] = links

        # ---------------- Headings ----------------
        headings = []
        Header_Print("Headings found: ")
        for heading in soup.find_all(['h1', 'h2', 'h3']):
            heading_text = heading.get_text(strip=True)
            headings.append(heading_text)
            print(f"  - {heading_text}")
        data['Headings'] = headings

        # ---------------- Paragraphs ----------------
        paragraphs = []
        Header_Print("Paragraphs: ")
        for para in soup.find_all('p')[:3]:
            para_text = para.get_text(strip=True)[:100]
            paragraphs.append(para_text)
            print(f"  - {para_text}...")
        data['Paragraphs'] = paragraphs

        # ---------------- Meta Tags ----------------
        metas = [meta.get('content') for meta in soup.find_all('meta') if meta.get('content')]
        data['Meta Tags'] = metas

        # ---------------- API Detection ----------------
        apis = []
        for script in soup.find_all('script'):
            if script.get('src') and 'api' in script.get('src').lower():
                apis.append(script.get('src'))
        data['API Integrations'] = apis if apis else "No obvious API references"

        # ---------------- Contact Details ----------------
        text = soup.get_text()
        emails = [word for word in text.split() if '@' in word]
        phones = [word for word in text.split() if word.isdigit() and len(word) >= 10]
        data['Contact Details'] = {'Emails': emails, 'Phones': phones}

        # ---------------- Weak Points ----------------
        weak_points = []
        if "https://" not in URL:
            weak_points.append("No HTTPS (insecure)")
        if "X-Powered-By" in response.headers:
            weak_points.append("Server reveals technology in headers")
        data['Weak Points'] = weak_points if weak_points else "No obvious weak points"

        return data

    except Exception as e:
        print(f"Error: {e}")
        return data


# -------------------------------
# Export Function
# -------------------------------
def export_data(data):
    
    # Use domain name or page title as default filename
    default_name = data.get('Domain', data.get('Page Title', 'website_data')).replace('www.', '').split('/')[0]
    filename = default_name + ".txt"
    
    # If file exists, create a new filename with a counter
    counter = 1
    original_filename = filename
    while os.path.exists(filename):
        name, ext = original_filename.rsplit('.', 1)
        filename = f"{name}_{counter}.{ext}"
        counter += 1
    
    try:
        with open(filename, 'w', encoding="utf-8") as f:
            for key, value in data.items():
                f.write(f"{key}: {value}\n")
        print(f"\033[42;1m.....Data exported to \033[42;3m {filename}......\033[0m")
    except Exception as e:
        print(f"Error exporting file: {e}")


# -------------------------------
# Main Program
# -------------------------------
def main():
    display_Banner("Web Scraper", "Python Web analyzer")
    target = input("Enter the domain url: \n\033[3;2;34;1mstarting with http:// or https://\033[0m - ")
    # Console.print("[[bold red]0[/bold red]] - Back to Main Menu\n")
    if target == "":
        print("No URL provided. Exiting...")
        return
    if target == "0":
        return "back"

    info = collect_website_info(target)

    Header_Print("Collected Website Information : ")
    for k, v in info.items():
        print(f"\033[35;1m{k}: \033[0m{v}")

    Header_Print("Export Options : ")
    choice = input("\n0 = export | 1 = exit : ")
    if choice == "0":
        export_data(info)
        return "back"
    else:
        print("Exiting...")
        return "back"
