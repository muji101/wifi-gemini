# WiFi Gemini v4.1

WiFi Gemini adalah sebuah framework pengujian keamanan Wi-Fi berbasis teks (TUI) yang dikembangkan dengan Python. Tool ini mengotomatiskan berbagai jenis serangan dan terintegrasi dengan Google Gemini AI untuk menghasilkan strategi serangan yang cerdas.

## Fitur Utama

- **Antarmuka Modern:** Tampilan berwarna dan interaktif dengan animasi spinner.
- **Multi-Attack Framework:** Mendukung beberapa vektor serangan dalam satu tool.
    - **Serangan WPA/WPA2 Handshake:** Metode klasik dengan alur serangan 3 tingkat.
    - **Serangan PMKID:** Metode modern yang lebih cepat (jika didukung target).
    - **Serangan WPS Pixie-Dust:** Sangat efektif melawan target dengan WPS yang rentan.
- **Integrasi Gemini AI:** Secara otomatis membuat *wordlist* yang sangat tertarget berdasarkan nama SSID jaringan.
- **Mode Monitor Adaptif:** Secara cerdas memilih metode aktivasi mode monitor untuk menjaga koneksi internet lain tetap aktif jika memungkinkan.
- **Konfigurasi Eksternal:** Mudah dikonfigurasi melalui file `config.ini` tanpa mengubah kode.

## Prasyarat & Instalasi

Proyek ini dirancang untuk berjalan di sistem operasi berbasis Debian/Ubuntu (seperti Kali Linux, Parrot OS, atau Ubuntu).

### Langkah 1: Instalasi Ketergantungan Sistem

Pertama, perbarui daftar paket Anda dan install semua command-line tools yang diperlukan.

```bash
sudo apt update
sudo apt install -y aircrack-ng hashcat hcxtools hcxdumptool reaver git make gcc libssl-dev libpcap-dev libcurl4-openssl-dev
```

### Langkah 2: Unduh Proyek

Unduh kode sumber dari repositori.

```bash
git clone https://github.com/muji101/wifi-gemini.git
cd wifi-gemini
```

### Langkah 3: Instalasi Ketergantungan Python

Buat file `requirements.txt` dan jalankan `pip` untuk menginstal semua library Python yang dibutuhkan.

```bash
# Perintah ini akan menginstal: requests, halo, colorama, pyfiglet
sudo pip3 install -r requirements.txt
```

## Konfigurasi

Sebelum menjalankan skrip, ada dua hal yang perlu dikonfigurasi.

### 1. File `config.ini`
Salin file contoh konfigurasi dan sesuaikan isinya dengan sistem Anda.

```bash
cp config.example.ini config.ini
nano config.ini
```
Pastikan `main_interface` dan `wordlist_dir` sudah benar.

### 2. Kunci API Gemini
Skrip ini memerlukan kunci API dari Google AI Studio.
- Dapatkan kunci API Anda dari [Google AI Studio](https://aistudio.google.com/app/apikey).
- Atur kunci tersebut sebagai *environment variable* di terminal Anda.

```bash
export GEMINI_API_KEY='MASUKKAN_KUNCI_API_ANDA_DI_SINI'
```

## Penggunaan

Setelah semua langkah di atas selesai, jalankan skrip dengan perintah berikut:

```bash
# Perintah lengkap untuk menjalankan skrip
export GEMINI_API_KEY='KUNCI_API_ANDA'; sudo -E python3 wifi_gemini.py
```
Anda akan disambut dengan banner dan menu utama untuk memilih jenis serangan. Ikuti petunjuk di layar.

---

### **PERINGATAN**
Tool ini dibuat untuk tujuan edukasi dan pengujian keamanan secara etis. Gunakan hanya pada jaringan yang Anda miliki atau yang Anda punya izin eksplisit untuk mengujinya. Penggunaan ilegal adalah tanggung jawab Anda sepenuhnya.