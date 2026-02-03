from logo import *  
from Banner import *
from rich.console import Console
from WebRecon import *
from WebScrapper import *
console = Console()

def main():
    console.print("\n[bold italic green]Select a feature from the list below:[/]\n")
    console.print("\n1. Network Scanner.\n" 
    "2. Web Scraper.\n" 
    "3. web Reconnasance .\n" 
    "4. password generator.\n" 
    "5. Clickjacking Tester.\n" 
    "6. file integrity checker.\n" 
    "7. phishing link scanner.\n" 
    "8. file scanner.\n"
    "9. Exit.\n", style="cyan")


    match input("Select a feature to proceed (1-8): "):
        case "1":
            import NetworkScan
            backto_main(NetworkScan.main())
        case "2":
            import WebScrapper
            backto_main(WebScrapper.main())
        case "3":
            import WebRecon
            backto_main(WebRecon.main())
        case "4":
            import PasswordGenerator
            backto_main(PasswordGenerator.main())
        case "5":
            import ClickJacking 
            backto_main(ClickJacking.main())
        case "6":
            import FileIntegrity
            backto_main(FileIntegrity.main())
        case "7":
            import PhishingLinkScanner
            backto_main(PhishingLinkScanner.main())
        case "8": 
            import File_scanner  
            backto_main(File_scanner.main())
        case "9":
            console.print("\n[bold red]Exiting PySecOps...\n-----------------------------------------------\n[/bold red]")
            return
        case _:
            console.print("[bold red]Invalid selection. Please restart the program and choose a valid option.[/bold red]")

def backto_main(result):
        if result == "back":
            console.print("\nReturning to main menu...\n------------------------------------------------", style="bold yellow")
            console.print("................................................", style="bold yellow")
            main()


if __name__ == "__main__":
    print_logo()
    print(f"\033[3;31;1m Welcome to PySecOps - Your Python Security Operations Toolkit! \n\033[0m")
    print("Initializing modules...\n")
    main()