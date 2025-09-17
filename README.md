BridgeGuard: Sistem Deteksi Anomali Real-Time untuk Cross-Chain Bridge
BridgeGuard adalah sebuah sistem prototipe yang dirancang untuk memantau aktivitas di cross-chain bridge secara real-time dan mendeteksi transaksi yang berpotensi berbahaya atau anomali. Sistem ini menggabungkan kecepatan pemantauan WebSocket dengan kekuatan analisis logika deklaratif menggunakan Datalog dan Souffle, serta diperkaya dengan analisis laporan insiden oleh Large Language Model (LLM).

Proyek ini terinspirasi dari penelitian akademis XChainWatcher, namun difokuskan pada aplikasi real-time alih-alih analisis historis.

Fitur Utama
Pemantauan Real-Time: Terhubung langsung ke node Ethereum melalui WebSocket untuk mendapatkan data event dengan latensi minimal.

Analisis Logika Deklaratif: Menggunakan Datalog dan engine Souffle untuk menerapkan aturan keamanan yang kompleks dan mudah dimodifikasi tanpa harus mengubah kode Python.

Deteksi Anomali: Aturan bawaan untuk mendeteksi transaksi bernilai tinggi (HighValueEthDeposit) dan interaksi dengan token spesifik. Aturan dapat dengan mudah diperluas untuk mendeteksi pola lain.

Pengayaan Data (Data Enrichment): Secara otomatis mengambil data kontekstual tambahan (seperti timestamp dan gasPrice) melalui koneksi HTTP untuk analisis yang lebih mendalam.

Pelaporan Cerdas (LLM): (Opsional) Mengintegrasikan hasil analisis dengan LLM (OpenAI/GPT) untuk menghasilkan laporan insiden yang mudah dibaca dan dipahami oleh manusia.

Arsitektur Sistem
Sistem ini terdiri dari beberapa lapisan yang bekerja secara berurutan:

Lapisan Sumber Data (Data Source):

Penyedia Node: Infura

Jaringan: Ethereum Mainnet (atau Sepolia untuk pengujian)

Lapisan Pengumpulan & Pemrosesan (Fact Extractor):

Komponen: realtime_monitor.py

Tugas: Membuat koneksi WebSocket yang persisten, mendengarkan event (ETHDepositInitiated, ERC20DepositInitiated), melakukan pengayaan data via HTTP, dan mengubah data mentah menjadi fakta Datalog yang bersih dan terstruktur.

Lapisan Analisis (Analysis Engine):

Komponen: Souffle Datalog Engine & realtime_rules.dl

Tugas: Menerima fakta dari skrip Python dan mengevaluasinya terhadap "buku panduan investigasi" (realtime_rules.dl). Jika ada aturan yang cocok, Souffle akan menghasilkan output pelanggaran.

Lapisan Presentasi (Presentation Layer):

Komponen: realtime_monitor.py

Tugas: Menangkap output dari Souffle. Jika ada pelanggaran, sistem akan menampilkan alarm keamanan. Jika tidak, sistem akan menampilkan laporan transaksi normal. Jika terintegrasi dengan LLM, sistem akan meminta laporan insiden yang lebih detail.

Prasyarat
Sebelum memulai, pastikan sistem Anda memiliki perangkat lunak berikut:

Windows 10/11 dengan WSL 2.

Distribusi Ubuntu 22.04 LTS di dalam WSL.

Souffle Datalog Engine.

Python 3.11.9 (sangat direkomendasikan untuk di-install melalui pyenv).

Git.

API Keys:

Project ID dari Infura.

(Opsional) API Key dari OpenAI jika Anda ingin menggunakan fitur LLM.

Instalasi (Panduan untuk Pengguna Baru)
Jalankan semua perintah ini di dalam terminal Ubuntu 22.04 (WSL).

1. Clone Repositori

git clone https://github.com/URL-ANDA/NAMA-REPO-ANDA.git
cd NAMA-REPO-ANDA

2. Instalasi Peralatan Sistem (Souffle & Dependensi Build)

# 1. Update dan install prasyarat dasar
sudo apt update
sudo apt install -y software-properties-common wget gpg build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev git

# 2. Tambahkan repositori Souffle dan install
wget -qO- "https://souffle-lang.github.io/ppa/souffle-key.public" | sudo gpg --dearmor -o /usr/share/keyrings/souffle-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/souffle-archive-keyring.gpg] https://souffle-lang.github.io/ppa/ubuntu/ stable main" | sudo tee /etc/apt/sources.list.d/souffle.list
sudo apt update
sudo apt install souffle -y

3. Instalasi Python dengan pyenv (Sangat Direkomendasikan)

# 1. Install pyenv
curl https://pyenv.run | bash

# 2. Konfigurasi pyenv dan muat ulang terminal
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
exec "$SHELL"

# 3. Install Python 3.11.9 (Proses ini akan memakan waktu lama)
pyenv install 3.11.9
pyenv global 3.11.9

4. Setup Lingkungan Proyek

# 1. Buat virtual environment
python -m venv venv

# 2. Aktifkan virtual environment
source venv/bin/activate

# 3. Install semua pustaka Python yang dibutuhkan
pip install -r requirements.txt

Konfigurasi
Buat File .env
Salin file .env.example dan beri nama .env.

cp .env.example .env

Isi Variabel Environment
Buka file .env dan isi dengan kunci API Anda.

INFURA_PROJECT_ID="project_id_anda_dari_infura"
OPENAI_API_KEY="api_key_anda_dari_openai" # Hanya jika menggunakan LLM

Konfigurasi Aturan (realtime_rules.dl)
Buka file realtime_rules.dl untuk melihat dan memodifikasi aturan deteksi. Anda bisa mengubah ambang batas amount atau menambahkan aturan baru di sini.

Penggunaan
Setiap kali Anda membuka terminal baru, jangan lupa untuk mengaktifkan virtual environment terlebih dahulu!

# Pindah ke direktori proyek (jika perlu)
cd /path/ke/proyek/anda

# Aktifkan environment
source venv/bin/activate

# Jalankan skrip monitor utama
python realtime_monitor.py

Skrip akan berjalan dan mulai memonitor transaksi. Output akan muncul di terminal saat ada event baru yang terdeteksi.
