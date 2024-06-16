from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

class Crint:
    @classmethod
    def info(cls, text):
        print(f"[{Fore.BLUE}*{Fore.RESET}] {text}\n")
    
    @classmethod
    def success(cls, text):
        print(f"[{Fore.GREEN}+{Fore.RESET}] {text}")

    @classmethod
    def error(cls, text):
        print(f"[{Fore.RED}!{Fore.RESET}] {text}")
    
    @classmethod
    def prompt(cls, text):
        user_input = input(f"[{Fore.MAGENTA}>{Fore.RESET}] {text}")
        return user_input