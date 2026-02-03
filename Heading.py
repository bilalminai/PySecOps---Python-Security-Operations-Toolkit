seperator = "\n--------------------------------------------------------\n"
def Header_Print(heading):
    print(f"\033[3;4;32;1m{seperator}\n\033[0m")
    print(f"\033[3;4;34;1m{heading}\n\033[0m")

def footer_Print():
    print(f"\033[3;4;35;1m{seperator}\n\033[0m")

# Header_Print("Sample Heading")
# footer_Print()