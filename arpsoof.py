    from colorama import Fore, Style, init

# Initialize colorama for Windows compatibility
init()

def banner():
    print(f"""
{Fore.WHITE}       ___
     __{Fore.RED}H{Fore.WHITE}__
    {Fore.WHITE}[ {Fore.RED}*{Fore.WHITE}  ]
    {Fore.WHITE}[ {Fore.RED}){Fore.WHITE}  ]
    {Fore.WHITE}[ {Fore.RED}){Fore.WHITE}  ]
      | {Fore.RED}V{Fore.WHITE} |
{Style.RESET_ALL}
ARP Spoofing Tool - Ethical Hacking Demo
""")

if __name__ == "__main__":
    banner()
