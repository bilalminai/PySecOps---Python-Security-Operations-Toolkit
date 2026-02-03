# file_scanner_logo.py
import pyfiglet
import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

def display_Banner(LogoText, Title):
    console = Console()
    
    # Generate ASCII art text
    ascii_banner = pyfiglet.figlet_format(LogoText)
    
    print("\n")
    
    # Create styled text with colors and bold
    styled_text = Text(ascii_banner, style="bold cyan")
    
    # Print panel with colors
    panel_text = Text("By PySecOps", style="bold yellow")
    coloured_title = Text("🔍 " + Title, style="bold Green italic")
    console.print(Panel.fit(
        styled_text,
        title= coloured_title,
        border_style="cyan",
        subtitle=panel_text,
        padding=(1, 6)
    ))
    
    print("\n\n")


    # for testing purposes
# display_Banner("FileScanner", "Comprehensive File Analysis Tool")
