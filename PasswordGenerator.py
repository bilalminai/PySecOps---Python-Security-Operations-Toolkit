import secrets
from rich.console import Console
from Banner import *


Console = Console()
SPECIALS = "!@#$%^&*"


def password_strength(password):
    length = len(password)
    categories = 0

    if any(c.islower() for c in password):
        categories += 1
    if any(c.isupper() for c in password):
        categories += 1
    if any(c.isdigit() for c in password):
        categories += 1
    if any(c in SPECIALS for c in password):
        categories += 1

    if length >= 12 and categories >= 4:
        return "Strong"
    elif length >= 8 and categories >= 3:
        return "Medium"
    else:
        return "Weak"

plaform_keywords = {
    "facebook": [ "fb", "face", "book", "meta", "social", "friend", "like", "share" ],
    "twitter": [ "tweet", "bird", "chirp", "follow", "hashtag", "trend", "dm" ],
    "instagram": [ "insta", "gram", "photo", "story", "filter", "like", "follow" ],
    "linkedin": [ "link", "connect", "network", "professional", "job", "career" ],
    "email": [ "mail", "inbox", "send", "receive", "compose", "draft" ],
    "github": [ "code", "repo", "commit", "branch", "pull", "merge" ],
    "amazon": [ "ama", "zon", "prime", "shop", "cart", "order", "kindle", "aws" ],
    "netflix": [ "net", "flix", "stream", "binge", "movie", "series", "show", "watch" ]
}

def generate_personalized_password(name, sec_word, number, name_len, platform_name):
    name_part = name[:name_len].capitalize()[0].upper() + name[:name_len].capitalize()[1:-1] + name[:name_len].capitalize()[-1].upper()
    word_part = sec_word.capitalize()
    number_part = secrets.choice([number[i:i+4] for i in range(len(number)-3)]) if len(number) >= 4 else number
    symbol = secrets.choice(SPECIALS)
    symbol_1 = secrets.choice(SPECIALS)
    platform_name = platform_name.lower() or "other"
    if platform_name in plaform_keywords:
        keywords = plaform_keywords[platform_name]
        global Social_keyword
        Social_keyword = secrets.choice(keywords)
        if any(kw in name.lower() or kw in sec_word.lower() for kw in keywords):
            symbol = secrets.choice(SPECIALS.replace('@', '').replace('#', ''))
            symbol_1 = secrets.choice(SPECIALS.replace('@', '').replace('#', ''))
    else:
        Social_keyword = platform_name or "Secure"


    password = f"{name_part}{symbol}{word_part}{number_part}{symbol_1}{str(Social_keyword).capitalize()}"
    return password

def main():

    display_Banner("Password Generator", "Secure and Personalized Passwords")
    repeat = True
    platformlist = "Facebook\nTwitter\nInstagram\nLinkedIn\nEmail\nGitHub\nAmazon\nNetflix\nothers"
    while repeat:
        name = Console.input("[bold dim]Enter your name: [/bold dim]").strip()
        sec_word = Console.input("[bold dim]Enter your second word: [/bold dim]").strip()
        number = Console.input("[bold dim]Enter your number : [/bold dim]").strip()
        if not number.isdigit():
            Console.print("[red]Error: Please enter only numbers[/red]")
            continue
        name_len = int(Console.input("[bold dim]How many characters from name to use? (min 3)  [/bold dim]") or "4")
        Console.print(f"[italic dim] {platformlist} [/italic dim]")
        platform = Console.input("[bold dim]For which account will you use this password? [/bold dim]").strip()

        while True:
            password = generate_personalized_password(name, sec_word, number, name_len, platform)
            strength = password_strength(password)
            if strength != "Weak":
                break

        Console.print("\n[green bold]Generated Password:[/green bold]", password)
        Console.print("[green bold]Password Strength:[/green bold]", strength)
        again = Console.input("\n[bold dim]Generate another password? (y/n): [/bold dim]").strip().lower()
        if again != 'y':
            repeat = False
            return "back"
