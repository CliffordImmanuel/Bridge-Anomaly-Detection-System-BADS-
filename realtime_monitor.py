import os
import json
import websocket
import ssl
import subprocess
from openai import OpenAI # <-- PERUBAHAN: Import library OpenAI
from web3 import Web3
from dotenv import load_dotenv

# Muat variabel dari file .env
load_dotenv()

# --- KONFIGURASI ---
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") # <-- PERUBAHAN: Kunci baru untuk OpenAI

# Validasi Kunci API
if not INFURA_PROJECT_ID or not OPENAI_API_KEY:
    print("--- ERROR --- Pastikan INFURA_PROJECT_ID dan OPENAI_API_KEY ada di file .env!")
    exit()

# --- PERUBAHAN: Konfigurasi Klien OpenAI ---
try:
    llm_client = OpenAI(api_key=OPENAI_API_KEY)
except Exception as e:
    print(f"--- ERROR --- Gagal mengkonfigurasi klien OpenAI: {e}")
    exit()


INFURA_WEBSOCKET_URL = f"wss://mainnet.infura.io/ws/v3/{INFURA_PROJECT_ID}"
BRIDGE_CONTRACT_ADDRESS = "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1"
PATH_TO_RULES_FILE = "realtime_rules.dl"

# --- KONFIGURASI UNTUK DUA EVENT ---
TARGET_ABIS = [
    {"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"from","type":"address"},{"indexed":True,"internalType":"address","name":"to","type":"address"},{"indexed":False,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":False,"internalType":"bytes","name":"extraData","type":"bytes"}],"name":"ETHDepositInitiated","type":"event"},
    {"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"l1Token","type":"address"},{"indexed":True,"internalType":"address","name":"l2Token","type":"address"},{"indexed":True,"internalType":"address","name":"from","type":"address"},{"indexed":False,"internalType":"address","name":"to","type":"address"},{"indexed":False,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":False,"internalType":"bytes","name":"extraData","type":"bytes"}],"name":"ERC20DepositInitiated","type":"event"}
]
TOPIC_HASHES = {
    "0x35d79ab81f2b2017e19afb5c5571778877782d7a8786f5907f93b0f4702f4f23": "ETHDepositInitiated",
    "0x718594027abd4eaed59f95162563e0cc6d0e8d5b86b1c7be8b1b0ac3343d0396": "ERC20DepositInitiated"
}

# Inisialisasi Web3
w3 = Web3()
bridge_contract = w3.eth.contract(address=Web3.to_checksum_address(BRIDGE_CONTRACT_ADDRESS), abi=TARGET_ABIS)

def get_llm_report(souffle_report, event_name, args):
    """Membuat laporan insiden yang mudah dibaca menggunakan LLM OpenAI."""
    print("   [INFO] Menghubungi Manajer SOC (OpenAI) untuk membuat laporan...")
    try:
        # Siapkan detail transaksi untuk prompt
        if event_name == "ETHDepositInitiated":
            amount_eth = Web3.from_wei(args['amount'], 'ether')
            transaction_details = (f"Jenis Event: Deposit ETH\n"
                                   f"Dari: {args['from']}\n"
                                   f"Ke: {args['to']}\n"
                                   f"Jumlah: {amount_eth:.6f} ETH")
        else: # ERC20DepositInitiated
            amount_token = Web3.from_wei(args['amount'], 'ether')
            transaction_details = (f"Jenis Event: Deposit Token ERC20\n"
                                   f"Token: {args['l1Token']}\n"
                                   f"Dari: {args['from']}\n"
                                   f"Ke: {args['to']}\n"
                                   f"Jumlah (diasumsikan 18 desimal): {amount_token:.6f}")

        # --- PERUBAHAN: Buat prompt untuk model Chat OpenAI ---
        system_prompt = "Anda adalah seorang analis keamanan blockchain senior."
        user_prompt = (f"Sebuah alarm keamanan baru saja terpicu.\n\n"
                       f"*Laporan Teknis dari Sistem Deteksi:*\n{souffle_report}\n\n"
                       f"*Detail Transaksi Pemicu:*\n{transaction_details}\n\n"
                       f"Tugas Anda: Berdasarkan dua data di atas, tulis sebuah laporan insiden singkat dalam format berikut:\n"
                       f"1. *Ringkasan Insiden:* Jelaskan dengan bahasa sederhana apa yang terjadi.\n"
                       f"2. *Potensi Risiko:* Jelaskan mengapa aktivitas ini dianggap berisiko.\n"
                       f"3. *Rekomendasi Tindakan:* Berikan satu langkah konkret yang harus segera dilakukan oleh operator.\n")

        # --- PERUBAHAN: Panggil API OpenAI ---
        response = llm_client.chat.completions.create(
            model="gpt-4o-mini", # atau model lain seperti "gpt-4"
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"   [ERROR LLM] Gagal membuat laporan: {e}")
        return "Gagal menghasilkan laporan dari LLM. Harap periksa laporan teknis."


def analyze_with_souffle(fact_string, event_name, args):
    """Memanggil Souffle dan jika ada alarm, minta LLM untuk menjelaskannya."""
    print(f"   [INFO] Menganalisis fakta...")
    try:
        command = ['souffle', PATH_TO_RULES_FILE, '-F', '-', '-D', '-']
        result = subprocess.run(command, input=fact_string, text=True, capture_output=True, check=False)

        if result.stderr:
             print(f"   [ERROR SOUFFLE]: {result.stderr}")

        if result.stdout.strip():
            # Cek apakah benar-benar ada data pelanggaran
            has_violation = "===============" in result.stdout
            
            if has_violation:
                # KONDISI 1: ADA PELANGGARAN ATURAN
                
                # Minta LLM untuk membuat laporan
                llm_report = get_llm_report(result.stdout.strip(), event_name, args)

                print("\n" + "="*30)
                print("🚨 LAPORAN INSIDEN (DARI LLM) 🚨")
                print(llm_report)
                print("="*30 + "\n")
            else:
                # Jika Souffle menghasilkan output (tabel kosong) tapi tidak ada pelanggaran
                print("\n" + "="*30)
                print("✅ TRANSAKSI NORMAL (LOLOS ATURAN) ✅")
                # ... (Detail transaksi normal ditampilkan di sini)
        else:
            # KONDISI 2: TIDAK ADA PELANGGARAN ATURAN
            print("\n" + "="*30)
            print("✅ TRANSAKSI NORMAL (LOLOS ATURAN) ✅")
            print(f"\n   Jenis Event: {event_name}")
            print("   --- Detail Transaksi ---")
            if event_name == "ETHDepositInitiated":
                amount_eth = Web3.from_wei(args['amount'], 'ether')
                print(f"     - From: {args['from']}")
                print(f"     - To:   {args['to']}")
                print(f"     - Amount: {amount_eth:.6f} ETH")
            elif event_name == "ERC20DepositInitiated":
                amount_token = Web3.from_wei(args['amount'], 'ether')
                print(f"     - Token: {args['l1Token']}")
                print(f"     - From:  {args['from']}")
                print(f"     - To:    {args['to']}")
                print(f"     - Amount (diasumsikan 18 desimal): {amount_token:.6f}")
            print("\n" + "="*30 + "\n")

    except Exception as e:
        print(f"   [ERROR]: Terjadi kesalahan saat menjalankan Souffle: {e}")

# ... (Sisa kode on_message, on_error, dll. tetap sama persis seperti versi final sebelumnya) ...

def on_message(ws, message):
    """Fungsi yang dijalankan setiap kali ada event baru."""
    data = json.loads(message)
    if "params" not in data or "result" not in data["params"]:
        return

    log_data_raw = data["params"]["result"]
    event_topic_hash = log_data_raw['topics'][0].lower() if log_data_raw.get('topics') else None

    fact_string = ""
    event_name_found = ""

    if event_topic_hash in TOPIC_HASHES:
        event_name_found = TOPIC_HASHES[event_topic_hash]
        try:
            log_copy = log_data_raw.copy()
            log_copy['topics'] = [Web3.to_bytes(hexstr=t) for t in log_copy['topics']]
            log_copy['data'] = Web3.to_bytes(hexstr=log_copy['data'])
            
            decoded_log = bridge_contract.events[event_name_found]().process_log(log_copy)
            args = decoded_log['args']

            if event_name_found == "ETHDepositInitiated":
                fact_string = (f"ETH\t{args['from']}\t{args['to']}\t\t\t"
                               f"{args['amount']}\t{Web3.to_hex(args['extraData'])}\n")
            elif event_name_found == "ERC20DepositInitiated":
                fact_string = (f"ERC20\t{args['l1Token']}\t{args['l2Token']}\t"
                               f"{args['from']}\t{args['to']}\t{args['amount']}\t"
                               f"{Web3.to_hex(args['extraData'])}\n")
            
            if fact_string:
                print("\n---------------------------------------")
                print(f"Event '{event_name_found}' diterima.")
                analyze_with_souffle(fact_string, event_name_found, args)

        except Exception as e:
            print(f"   [DEBUG] Gagal mem-parse {event_name_found}: {e}")

def on_error(ws, error):
    print(f"Error WebSocket: {error}")

def on_close(ws, close_status_code, close_msg):
    print("Koneksi WebSocket ditutup.")

def on_open(ws):
    print("Koneksi WebSocket dibuka. Memonitor event deposit ETH dan ERC20...")
    subscribe_message = {
        "jsonrpc": "2.0", "id": 1, "method": "eth_subscribe",
        "params": ["logs", {"address": BRIDGE_CONTRACT_ADDRESS, "topics": [list(TOPIC_HASHES.keys())]}]
    }
    ws.send(json.dumps(subscribe_message))

if __name__ == "__main__":
    print("Memulai Monitor Real-Time (Terintegrasi dengan LLM)...")
    ws = websocket.WebSocketApp(
        INFURA_WEBSOCKET_URL,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})