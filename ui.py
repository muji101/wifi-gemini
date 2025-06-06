# File: ui.py
from halo import Halo
from colorama import Fore, Style, init
from pyfiglet import Figlet

init(autoreset=True)

class UI:
    def __init__(self): 
        self.spinner = Halo(text_color='cyan')
        self.spinner_active = False
    
    def banner(self, text="WiFi Gemini"): 
        f = Figlet(font='slant'); print(Fore.CYAN + f.renderText(text)); print(Fore.YELLOW + " v5.0 Final - Plugin Architecture"); print("-" * 60)
        
    def info(self, text): print(f"{Fore.YELLOW}[*] {text}")
    def success(self, text): print(f"{Fore.GREEN}[+] {text}")
    def error(self, text): print(f"{Fore.RED}[!] {text}")
    def prompt(self, text): return input(f"{Fore.CYAN}[?] {text}")
    def header(self, text): print(f"\n{Style.BRIGHT}{Fore.CYAN}{'='*60}\n 🤖 {text.upper()}\n{'='*60}{Style.RESET_ALL}")
    
    def table(self, networks_with_wps_status):
        print(f"\n  {Fore.WHITE+Style.BRIGHT}{'No.':<5}{'SSID':<30}{'BSSID':<20}{'Channel':<10}{'WPS Active'}{Style.RESET_ALL}"); print(f"  {'-'*5}{'-'*30}{'-'*20}{'-'*10}{'-'*12}")
        for i, (net_info, wps_enabled) in enumerate(networks_with_wps_status):
            ssid, bssid, channel = net_info; color = Fore.GREEN if wps_enabled else Fore.RED; wps_text = "Yes" if wps_enabled else "No"
            print(color + f"  {i+1:<5}{ssid:<30}{bssid:<20}{channel:<10}{wps_text}"); print(Style.RESET_ALL)
            
    def start_spinner(self, text="Memproses..."): 
        if not self.spinner_active:
            self.spinner.text = text; self.spinner_active = True; self.spinner.start()
            
    def stop_spinner(self, success=True, new_text="Selesai."):
        if self.spinner_active:
            if success: self.spinner.succeed(new_text)
            else: self.spinner.fail(new_text)
            self.spinner_active = False

    def display_main_menu(self, plugins):
        self.header("PILIH JENIS SERANGAN")
        for i, plugin in enumerate(plugins):
            print(f" {Fore.CYAN}{i+1}.{Style.RESET_ALL} {plugin.name} {Fore.YELLOW}({plugin.description}){Style.RESET_ALL}")
        return self.prompt(f"Masukkan pilihan Anda (1-{len(plugins)}): ")