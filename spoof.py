from colorama import Fore, Style, init

# Initialize colorama for Windows compatibility
init()

def banner():
    # Colors from colorama
    yellow = Fore.YELLOW
    red = Fore.RED
    reset = Style.RESET_ALL

    syringe = f"""
       {yellow}______{reset}
       {yellow}__H__{reset}
        ["]
        [)] 
        [)] {red}
        |V.{reset}
    """
    print(syringe)

# Calling the function to display the banner
banner()
