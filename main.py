# File: main.py
import os
import sys
import importlib.util
import configparser
from ui import UI
from common_utils import (
    check_root, 
    enable_monitor_mode, 
    disable_monitor_mode, 
    scan_networks, 
    select_target,
    load_sessions,
    clear_session
)

def load_config():
    config = configparser.ConfigParser(); config_file = 'config.ini'
    if not os.path.exists(config_file): UI().error(f"File '{config_file}' tidak ditemukan."); sys.exit(1)
    config.read(config_file); return config

def load_plugins(ui):
    plugins = []; plugin_path = 'attacks'
    if not os.path.isdir(plugin_path): return []
    for filename in os.listdir(plugin_path):
        if filename.endswith('.py') and not filename.startswith('__'):
            try:
                module_name = f"attacks.{filename[:-3]}"; spec = importlib.util.spec_from_file_location(module_name, os.path.join(plugin_path, filename))
                module = importlib.util.module_from_spec(spec); sys.modules[module_name] = module
                spec.loader.exec_module(module)
                if hasattr(module, 'AttackPlugin'): plugins.append(module.AttackPlugin)
            except Exception as e:
                ui.error(f"Gagal memuat plugin {filename}: {e}")
    return sorted(plugins, key=lambda p: p.name)

def resume_session_handler(ui, config, session_data):
    from attacks.handshake_attack import crack_with_aircrack, crack_with_hashcat
    
    ui.header(f"MELANJUTKAN SESI UNTUK '{session_data['ssid']}'")
    target_info = (session_data['ssid'], session_data['bssid'], None)
    result = None
    
    if session_data['type'] == 'aircrack':
        result = crack_with_aircrack(ui, config, target_info, session_data['capture_file'], session_data['wordlist'])
    elif session_data['type'] == 'hashcat':
        session_name = session_data['session_name']
        cmd = ['hashcat', f'--session={session_name}', '--restore']
        ui.info(f"Melanjutkan sesi hashcat '{session_name}'...")
        try:
            ui.start_spinner("Menjalankan hashcat restore..."); run_command(cmd)
            ui.stop_spinner(True, "Proses Hashcat Selesai.")
        except KeyboardInterrupt:
            ui.stop_spinner(False, "Sesi restore dihentikan."); return
        
        ui.info("Memeriksa hasil dari hashcat...")
        hash_file = session_data['hash_file']
        result, _ = run_command(['hashcat', '-m', '22000', '--show', f'--session={session_name}', hash_file])
        if result and ":" in result: result = f"KEY FOUND! (Hashcat)\n{result}"
        else: result = "Password tidak ditemukan setelah melanjutkan sesi."

    if result and "KEY FOUND!" in result:
        ui.success("Password ditemukan setelah melanjutkan sesi!")
        clear_session(ui, config, session_data['bssid'])
        generate_report(ui, config, target_info, [("Resume Session", result)])
    else:
        ui.error("Password masih belum ditemukan.")

def main():
    ui = UI(); config = load_config()
    ui.banner(); check_root(ui)

    saved_sessions = load_sessions(config)
    if saved_sessions:
        ui.header("SESI TERSIMPAN DITEMUKAN")
        bssid, session_data = next(iter(saved_sessions.items()))
        ui.info(f"Target: {session_data['ssid']} ({bssid})")
        choice = ui.prompt("Lanjutkan sesi ini? (y/n): ").lower()
        if choice == 'y':
            is_aggressive = (session_data.get('type') != 'aircrack')
            monitor_interface = enable_monitor_mode(ui, config.get('Interfaces', 'main_interface'), aggressive=is_aggressive)
            if monitor_interface:
                resume_session_handler(ui, config, session_data)
                disable_monitor_mode(ui, monitor_interface)
            return

    monitor_interface = None
    try:
        available_plugins = load_plugins(ui)
        if not available_plugins: ui.error("Tidak ada plugin serangan yang ditemukan di folder 'attacks/'."); return
        
        choice_str = ui.display_main_menu(available_plugins)
        try:
            choice = int(choice_str) - 1
            if not 0 <= choice < len(available_plugins): ui.error("Pilihan tidak valid."); return
        except (ValueError, KeyboardInterrupt): ui.error("\nInput tidak valid atau dibatalkan."); return
        
        selected_plugin_class = available_plugins[choice]
        plugin_instance = selected_plugin_class(ui, config)
        
        monitor_interface = enable_monitor_mode(ui, config.get('Interfaces', 'main_interface'), aggressive=plugin_instance.requires_aggressive_mode)
        if not monitor_interface: return

        networks = scan_networks(ui, monitor_interface)
        if not networks: ui.error("Tidak ada jaringan terdeteksi."); return
        target = select_target(ui, networks)
        if not target: return

        plugin_instance.run(monitor_interface, target)

    finally:
        ui.stop_spinner(success=True, new_text="Proses selesai.")
        if monitor_interface: disable_monitor_mode(ui, monitor_interface)
        ui.info("Membersihkan file sementara...")
        
        active_sessions = load_sessions(config)
        files_in_session = []
        for session in active_sessions.values():
            files_in_session.extend([session.get('capture_file'), session.get('hash_file')])
        
        filenames_config = config['Filenames']
        files_to_delete = [
            filenames_config['gemini_wordlist'], filenames_config['hashcat_hash'], 
            filenames_config['hashcat_potfile'], filenames_config['pmkid_capture'],
            f"{filenames_config['pmkid_capture']}-01.cap",
            filenames_config['pmkid_filter'], f"{config.get('Filenames', 'handshake_capture')}-01.cap"
        ]
        
        for f in files_to_delete:
            if f and os.path.exists(f) and f not in files_in_session:
                try: os.remove(f)
                except OSError: pass

if __name__ == "__main__":
    main()