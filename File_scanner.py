import os
import time
from Banner import *
from rich.console import Console
from rich.panel import Panel

console = Console()

import Banner

def load_keywords(keywords_file):
    """Load keywords from the Keywords.txt file"""
    try:
        with open(keywords_file, 'r', encoding='utf-8') as f:
            keywords = [line.strip().lower() for line in f if line.strip()]
        return keywords
    except FileNotFoundError:
        print(f"Error: {keywords_file} not found.")
        return []

def scan_file(file_path, keywords):
    """Scan a file for keywords"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
            
        found_keywords = []
        for keyword in keywords:
            if keyword in content:
                found_keywords.append(keyword)
        
        return found_keywords
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []



def main():
    console.clear()
    display_Banner("File_Scanner", "Comprehensive File Analysis Tool")
    print("\t\tWelcome to File Keyword Scanner")
    
    # Ask for file path
    file_path = input("\nEnter the file path to scan: ").strip()

    keywords_file = "Keywords.txt"

    # Check if file exists
    if not os.path.exists(file_path):
        print(f"Error: File not found - {file_path}")
        exit(1)


    # Load keywords
    keywords = load_keywords(keywords_file)
    if not keywords:
        print("No keywords to scan.")
        exit(1)

    # Scan file
    found_keywords = scan_file(file_path, keywords)

    # Print results
    print()
    if found_keywords:
        print(f"[ALERT] Suspicious keywords found in: {file_path}")
        for keyword in found_keywords:
            print(f"  - Keyword found: '{keyword}'")
    else:
        print("Nothing suspicious found")
    
    console.print(Panel("[bold green]File scanning completed\n-----------------------------------------------[/bold green]"))
    console.print("Do you want to scan another file? (y/n): ", end=" ")
    choice = input().strip().lower()
    if choice != 'y':
        return "back"
    else:
        return main()
