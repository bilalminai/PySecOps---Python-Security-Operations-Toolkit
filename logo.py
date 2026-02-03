import sys
import time
# from rich.console import Console
# Console = Console()
def print_logo():
    # ANSI escape sequences for 24-bit TrueColor
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[38;2;0;255;0m"  # Bright Green

    # The logo template using Unicode characters
    logo_template = [
        "  ┏━                ━┓  ",
        "        ▄▄████▄▄        ",
        "     ▄██▀▀    ▀▀██▄     ",
        "   ▄█▀    ▄▄▄▄    ▀█▄   ",
        "  █▀   ▄██▀▀▀▀██▄   ▀█  ",
        " █▀   █▀        ▀█   ▀█ ",
        " █    █          █    █ ",
        " ━━━━━━━━━━━━━━━━━━━━━━ ", # The scan line
        " █    █          █    █ ",
        " █▄   █▄        ▄█   ▄█ ",
        "  █▄   ▀██▄▄▄▄██▀   ▄█  ",
        "   ▀█▄    ▀▀▀▀    ▄█▀   ",
        "     ▀██▄▄    ▄▄██▀     ",
        "        ▀▀████▀▀        ",
        "  ┗━                ━┛  "
    ]

    print("\n")
    for y, line in enumerate(logo_template):
        colored_line = ""
        for x, char in enumerate(line):
            # Calculate a horizontal gradient: Purple (left) to Pink (right)
            # Purple: (120, 40, 200) -> Pink: (220, 60, 180)
            ratio = x / len(line)
            r = int(120 + (100 * ratio))
            g = int(40 + (20 * ratio))
            b = int(200 - (20 * ratio))
            
            # Apply color to the character
            color = f"\033[38;2;{r};{g};{b}m"
            colored_line += f"{color}{char}"
            time.sleep(0.01)  # Delay between characters
            
        print("    " + colored_line + RESET)
        # time.sleep(0.05)  # Delay between lines
    
    # Print "PySecOps" centered below the logo
    text = "PySecOps"
    print(" " * ((len(logo_template[0]) // 2) - (len(text) // 2) + 4) + BOLD + GREEN + text + RESET)
    print(f"\n\033[3;32;5m           by PySecOps Team \033[0m")
    print(f"\033[3;32;2m Vedant | Bilal | Pranjali | Umesh | Vignesh \n\033[0m")
    print("\n")

if __name__ == "__main__":
    # Check if the terminal supports colors
    if sys.platform == "win32":
        import os
        # os.system('color') # Enables ANSI support on Windows 10+
    print_logo()
