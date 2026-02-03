import os
import time
import json
import stat
import hashlib
import getpass
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileMovedEvent

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# ---------------- CONFIG ----------------
console = Console()
BASELINE_FILE = "file_baseline.json"
IGNORE_FILES = ["file_baseline.json"]

# Store selected directory globally
selected_directory = None

# ---------------- ASCII BANNER ----------------
BANNER = r"""
    🔐 File System Integrity Monitor

        ███████╗██╗███╗   ███╗
        ██╔════╝██║████╗ ████║
        █████╗  ██║██╔████╔██║
        ██╔══╝  ██║██║╚██╔╝██║
        ██║     ██║██║ ╚═╝ ██║
        ╚═╝     ╚═╝╚═╝     ╚═╝

     Secure File Change Detection
"""

# ---------------- AI MODEL ----------------
ai_model = IsolationForest(
    n_estimators=150,
    contamination=0.25,
    random_state=42
)

ai_model.fit(np.array([
    [0, 0, 0],
    [1, 0, 0],
    [0, 1, 0],
    [0, 0, 1],
    [2, 1, 1]
]))

def ai_risk_assessment(m, d, n):
    reasons = []
    if d > m and d > 0:
        reasons.append("High number of deletions")
    if m > 3:
        reasons.append("Multiple file modifications")
    if n > 2:
        reasons.append("Unexpected new files")

    if ai_model.predict([[m, d, n]])[0] == -1:
        return "HIGH", "; ".join(reasons) or "Anomalous file activity"
    return "LOW", "Normal behavior"

# ---------------- UTILS ----------------
def normalize(path):
    return os.path.abspath(path)

def slow_print(text, delay=0.03, style="cyan"):
    for line in text.splitlines():
        console.print(Text(line, style=style))
        time.sleep(delay)

def calculate_hash(path):
    try:
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except:
        return None

def get_metadata(path):
    st = os.stat(path)
    return {
        "size": st.st_size,
        "mtime": st.st_mtime,
        "permissions": stat.filemode(st.st_mode),
        "owner": getpass.getuser()
    }

# ---------------- BASELINE ----------------
def create_baseline(directory):
    directory = normalize(directory)
    baseline = {"__root__": directory, "files": {}}

    for root, _, files in os.walk(directory):
        for file in files:
            if file in IGNORE_FILES:
                continue
            path = normalize(os.path.join(root, file))
            h = calculate_hash(path)
            if h:
                baseline["files"][path] = {
                    "hash": h,
                    "meta": get_metadata(path)
                }

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

    console.print("[green]\n✔ Baseline created successfully...[/green]")


# ---------------- CHECK INTEGRITY ----------------
def check_integrity(directory):
    directory = normalize(directory)

    if not os.path.exists(BASELINE_FILE):
        console.print("[red]Baseline not found[/red]")
        return

    with open(BASELINE_FILE) as f:
        baseline = json.load(f)

    if baseline["__root__"] != directory:
        console.print(Panel(
            "Baseline directory mismatch.\nUse the SAME directory used during baseline creation.",
            title="Directory Error",
            style="red"
        ))
        return

    current = {}
    for root, _, files in os.walk(directory):
        for file in files:
            if file in IGNORE_FILES:
                continue
            path = normalize(os.path.join(root, file))
            h = calculate_hash(path)
            if h:
                current[path] = {
                    "hash": h,
                    "meta": get_metadata(path)
                }

    m = d = n = 0
    user = getpass.getuser()

    table = Table(title="File Integrity Report")
    table.add_column("File", overflow="fold")
    table.add_column("Status")
    table.add_column("Details")

    for path, base in baseline["files"].items():
        if path not in current:
            d += 1
            table.add_row(
                path,
                "[red]DELETED[/red]",
                f"Last known owner: {base['meta']['owner']} | Detected by: {user}"
            )
        else:
            curr = current[path]
            changes = []

            if base["hash"] != curr["hash"]:
                changes.append("Content changed")
            if base["meta"] != curr["meta"]:
                changes.append("Metadata changed")

            if changes:
                m += 1
                when = datetime.fromtimestamp(curr["meta"]["mtime"]).isoformat()
                table.add_row(
                    path,
                    "[yellow]MODIFIED[/yellow]",
                    f"{', '.join(changes)} | Modified at {when} | Detected by {user}"
                )

    for path in current:
        if path not in baseline["files"]:
            n += 1
            table.add_row(
                path,
                "[green]NEW[/green]",
                f"Owner: {current[path]['meta']['owner']} | Detected by {user}"
            )

    console.print(table)

    risk, reason = ai_risk_assessment(m, d, n)
    console.print(Panel(
        f"Modified : {m}\nDeleted  : {d}\nNew      : {n}\n\n"
        f"Risk Level : {risk}\nReason     : {reason}",
        title="AI Security Assessment",
        style="red" if risk == "HIGH" else "green"
    ))

# ---------------- LIVE MONITOR ----------------
class Monitor(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.is_directory:
            return

        user = getpass.getuser()
        now = datetime.now().isoformat()

        if isinstance(event, FileMovedEvent):
            console.print(Panel(
                f"Event : File name changed\n"
                f"Old   : {normalize(event.src_path)}\n"
                f"New   : {normalize(event.dest_path)}\n"
                f"Time  : {now}\n"
                f"Detected by : {user}",
                title="Live File Event",
                style="magenta"
            ))
            return

        if event.event_type == "deleted":
            console.print(Panel(
                f"Event : File deleted\n"
                f"File  : {normalize(event.src_path)}\n"
                f"Time  : {now}\n"
                f"Detected by : {user}",
                title="Live File Event",
                style="red"
            ))
            return

        if event.event_type == "created":
            console.print(Panel(
                f"Event : File created\n"
                f"File  : {normalize(event.src_path)}\n"
                f"Time  : {now}\n"
                f"Detected by : {user}",
                title="Live File Event",
                style="green"
            ))
            return

        if event.event_type == "modified":
            console.print(Panel(
                f"Event : File modified\n"
                f"File  : {normalize(event.src_path)}\n"
                f"Time  : {now}\n"
                f"Detected by : {user}",
                title="Live File Event",
                style="yellow"
            ))
            return


def live_monitor(directory):
    directory = normalize(directory)
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


def get_directory():
    console.print("\nEnter the directory to monitor/check integrity:")
    directory = console.input("Directory Path: ").strip()
    if not os.path.isdir(directory):
        console.print("[red]Invalid directory. Please try again.[/red]")
        return get_directory()
    return directory


# ---------------- MAIN ----------------
def main_menu():
    global selected_directory
    console.print("\n--------------------------------------------------------", style="bold cyan")
    console.print("\n\n[bold green]Select an option:[/bold green]\n")
    slow_print("1. Create Baseline", 0.05, "cyan")
    slow_print("2. Check File Integrity", 0.05, "cyan")
    slow_print("3. Live File Monitoring", 0.05, "cyan")
    slow_print("0. Back", 0.05, "red")
    choice = console.input("\nEnter choice: ").strip()
    
    if choice == "1":
        selected_directory = get_directory()
        create_baseline(selected_directory)
        return main_menu()
    elif choice == "2":
        if selected_directory is None:
            console.print("[red]Please create a baseline first![/red]")
            return main_menu()
        check_integrity(selected_directory)
        return main_menu()
    elif choice == "3":
        if selected_directory is None:
            console.print("[red]Please create a baseline first![/red]")
            return main_menu()
        live_monitor(selected_directory)
        return main_menu()
    elif choice == "0":
        console.print("[yellow]Exiting...[/yellow]")
        return "back"
    else:
        console.print("[red]Invalid choice[/red]")
        return main_menu()


def main():
    console.clear()
    slow_print(BANNER, delay=0.04, style="cyan")
    console.print("[bold yellow]\t     By PySecOps[/bold yellow]")
    return main_menu()
