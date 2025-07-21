import os
import json
import websocket
import ssl
import subprocess
from web3 import Web3
from dotenv import load_dotenv

# Muat variabel dari file .env
load_dotenv()

# --- KONFIGURASI ---
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID")
if not INFURA_PROJECT_ID:
    print("--- ERROR --- INFURA_PROJECT_ID tidak ditemukan di file .env! Harap periksa kembali.")
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

def analyze_with_souffle(fact_string, event_name, args):
    """Memanggil Souffle dan menampilkan output sesuai kondisi."""
    print(f"   [INFO] Menganalisis fakta...")
    try:
        command = ['souffle', PATH_TO_RULES_FILE, '-F', '-', '-D', '-']
        result = subprocess.run(command, input=fact_string, text=True, capture_output=True, check=False)

        if result.stderr:
             print(f"   [ERROR SOUFFLE]: {result.stderr}")

        # --- LOGIKA PARSING FINAL YANG SANGAT ROBUST ---
        if result.stdout.strip():
            report_items = [] # Menyimpan laporan pelanggaran yang valid

            # Memisahkan output menjadi beberapa tabel berdasarkan pemisah '---'
            tables = result.stdout.strip().split('---------------')

            for table in tables:
                table = table.strip()
                if not table:
                    continue

                lines = table.split('\n')
                rule_name = lines[0].strip()
                
                # Cek jika ada baris data (setelah nama aturan, header, dan '===')
                if len(lines) > 3:
                    data_rows = lines[3:] # Data dimulai dari baris ke-4 (setelah nama, header, dan ===)
                    
                    # Hanya proses jika ada data nyata
                    if data_rows and "===" not in data_rows[0]:
                        report = f"\n   Aturan Terpicu: {rule_name}\n   --- Detail Pelanggaran ---"
                        
                        for row in data_rows:
                            if not row.strip() or "===" in row:
                                continue
                                
                            parts = row.split('\t')
                            if rule_name == "HighValueEthDeposit" and len(parts) == 3:
                                from_addr, to_addr, amount_wei_str = parts
                                amount_eth = Web3.from_wei(int(float(amount_wei_str)), 'ether')
                                report += (f"\n     - From: {from_addr}\n     - To:   {to_addr}"
                                           f"\n     - Amount: {amount_eth:.6f} ETH")
                            elif rule_name == "SpecificTokenDeposit" and len(parts) == 4:
                                token_addr, from_addr, to_addr, amount_str = parts
                                report += (f"\n     - Token: {token_addr} (WETH)\n     - From:  {from_addr}"
                                           f"\n     - To:    {to_addr}\n     - Amount (wei): {int(float(amount_str))}")
                        report_items.append(report)
            
            # Hanya tampilkan alarm jika kita benar-benar menemukan dan memformat hasil pelanggaran
            if report_items:
                print("\n" + "="*30)
                print("🚨 ALARM KEAMANAN TERPICU! 🚨")
                for item in report_items:
                    print(item)
                print("\n" + "="*30 + "\n")
            else:
                # Jika Souffle menghasilkan output (tabel kosong) tapi tidak ada pelanggaran
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
                    print(f"     - Token: {args['l1Token']}")
                    print(f"     - From:  {args['from']}")
                    print(f"     - To:    {args['to']}")
                    print(f"     - Amount (wei): {args['amount']}")
                print("\n" + "="*30 + "\n")
        else:
            # Jika Souffle tidak menghasilkan output sama sekali
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
                print(f"     - Token: {args['l1Token']}")
                print(f"     - From:  {args['from']}")
                print(f"     - To:    {args['to']}")
                print(f"     - Amount (wei): {args['amount']}")
            print("\n" + "="*30 + "\n")

    except FileNotFoundError:
        print("   [ERROR]: Perintah 'souffle' tidak ditemukan.")
    except Exception as e:
        print(f"   [ERROR]: Terjadi kesalahan saat menjalankan Souffle: {e}")

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
            
            # Panggil analyze_with_souffle dengan argumen tambahan
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
    print("Memulai Monitor Real-Time (ETH & ERC20)...")
    ws = websocket.WebSocketApp(
        INFURA_WEBSOCKET_URL,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
