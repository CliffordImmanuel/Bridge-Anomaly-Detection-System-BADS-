import os
import json
import websocket 
import ssl
from dotenv import load_dotenv
from web3 import Web3 

# Muat variabel dari file .env
load_dotenv()

# --- KONFIGURASI ---
ALCHEMY_API_KEY = os.getenv("ALCHEMY_API_KEY")
# Ganti dengan URL WebSocket dari aplikasi Alchemy Anda
# Pastikan ini adalah WSS (WebSocket Secure)
ALCHEMY_WEBSOCKET_URL = f"wss://eth-mainnet.g.alchemy.com/v2/pnsQr7wng3yNVJ_DI_G3j" # Contoh untuk Ethereum Mainnet

# --- Konfigurasi Smart Contract Bridge Anda ---
# Ganti dengan alamat smart contract bridge yang ingin Anda monitor
BRIDGE_CONTRACT_ADDRESS = "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1" 

# Ganti dengan ABI smart contract bridge Anda
# Ini adalah list dari dictionary (format JSON)
BRIDGE_CONTRACT_ABI = [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"localToken","type":"address"},{"indexed":True,"internalType":"address","name":"remoteToken","type":"address"},{"indexed":True,"internalType":"address","name":"from","type":"address"},{"indexed":False,"internalType":"address","name":"to","type":"address"},{"indexed":False,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":False,"internalType":"bytes","name":"extraData","type":"bytes"}],"name":"ERC20BridgeFinalized","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"localToken","type":"address"},{"indexed":True,"internalType":"address","name":"remoteToken","type":"address"},{"indexed":True,"internalType":"address","name":"from","type":"address"},{"indexed":False,"internalType":"address","name":"to","type":"address"},{"indexed":False,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":False,"internalType":"bytes","name":"extraData","type":"bytes"}],"name":"ERC20BridgeInitiated","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"l1Token","type":"address"},{"indexed":True,"internalType":"address","name":"l2Token","type":"address"},{"indexed":True,"internalType":"address","name":"from","type":"address"},{"indexed":False,"internalType":"address","name":"to","type":"address"},{"indexed":False,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":False,"internalType":"bytes","name":"extraData","type":"bytes"}],"name":"ERC20DepositInitiated","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"l1Token","type":"address"},{"indexed":True,"internalType":"address","name":"l2Token","type":"address"},{"indexed":True,"internalType":"address","name":"from","type":"address"},{"indexed":False,"internalType":"address","name":"to","type":"address"},{"indexed":False,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":False,"internalType":"bytes","name":"extraData","type":"bytes"}],"name":"ERC20WithdrawalFinalized","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"from","type":"address"},{"indexed":True,"internalType":"address","name":"to","type":"address"},{"indexed":False,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":False,"internalType":"bytes","name":"extraData","type":"bytes"}],"name":"ETHBridgeFinalized","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"from","type":"address"},{"indexed":True,"internalType":"address","name":"to","type":"address"},{"indexed":False,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":False,"internalType":"bytes","name":"extraData","type":"bytes"}],"name":"ETHBridgeInitiated","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"from","type":"address"},{"indexed":True,"internalType":"address","name":"to","type":"address"},{"indexed":False,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":False,"internalType":"bytes","name":"extraData","type":"bytes"}],"name":"ETHDepositInitiated","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"from","type":"address"},{"indexed":True,"internalType":"address","name":"to","type":"address"},{"indexed":False,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":False,"internalType":"bytes","name":"extraData","type":"bytes"}],"name":"ETHWithdrawalFinalized","type":"event"},{"anonymous":False,"inputs":[{"indexed":False,"internalType":"uint8","name":"version","type":"uint8"}],"name":"Initialized","type":"event"},{"inputs":[],"name":"MESSENGER","outputs":[{"internalType":"contract ICrossDomainMessenger","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OTHER_BRIDGE","outputs":[{"internalType":"contract StandardBridge","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_localToken","type":"address"},{"internalType":"address","name":"_remoteToken","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"uint32","name":"_minGasLimit","type":"uint32"},{"internalType":"bytes","name":"_extraData","type":"bytes"}],"name":"bridgeERC20","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_localToken","type":"address"},{"internalType":"address","name":"_remoteToken","type":"address"},{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"uint32","name":"_minGasLimit","type":"uint32"},{"internalType":"bytes","name":"_extraData","type":"bytes"}],"name":"bridgeERC20To","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint32","name":"_minGasLimit","type":"uint32"},{"internalType":"bytes","name":"_extraData","type":"bytes"}],"name":"bridgeETH","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint32","name":"_minGasLimit","type":"uint32"},{"internalType":"bytes","name":"_extraData","type":"bytes"}],"name":"bridgeETHTo","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"_l1Token","type":"address"},{"internalType":"address","name":"_l2Token","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"uint32","name":"_minGasLimit","type":"uint32"},{"internalType":"bytes","name":"_extraData","type":"bytes"}],"name":"depositERC20","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_l1Token","type":"address"},{"internalType":"address","name":"_l2Token","type":"address"},{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"uint32","name":"_minGasLimit","type":"uint32"},{"internalType":"bytes","name":"_extraData","type":"bytes"}],"name":"depositERC20To","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint32","name":"_minGasLimit","type":"uint32"},{"internalType":"bytes","name":"_extraData","type":"bytes"}],"name":"depositETH","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint32","name":"_minGasLimit","type":"uint32"},{"internalType":"bytes","name":"_extraData","type":"bytes"}],"name":"depositETHTo","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"}],"name":"deposits","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_localToken","type":"address"},{"internalType":"address","name":"_remoteToken","type":"address"},{"internalType":"address","name":"_from","type":"address"},{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"bytes","name":"_extraData","type":"bytes"}],"name":"finalizeBridgeERC20","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_from","type":"address"},{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"bytes","name":"_extraData","type":"bytes"}],"name":"finalizeBridgeETH","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"_l1Token","type":"address"},{"internalType":"address","name":"_l2Token","type":"address"},{"internalType":"address","name":"_from","type":"address"},{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"bytes","name":"_extraData","type":"bytes"}],"name":"finalizeERC20Withdrawal","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_from","type":"address"},{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"bytes","name":"_extraData","type":"bytes"}],"name":"finalizeETHWithdrawal","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"contract ICrossDomainMessenger","name":"_messenger","type":"address"},{"internalType":"contract ISuperchainConfig","name":"_superchainConfig","type":"address"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"l2TokenBridge","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"messenger","outputs":[{"internalType":"contract ICrossDomainMessenger","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"otherBridge","outputs":[{"internalType":"contract StandardBridge","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"paused","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"superchainConfig","outputs":[{"internalType":"contract ISuperchainConfig","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"version","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"stateMutability":"payable","type":"receive"}]
# Inisialisasi Web3 untuk parsing logs
# ... (di bagian monitor.py Anda) ...

# Inisialisasi Web3 untuk parsing logs
w3 = Web3()
bridge_contract = w3.eth.contract(address=Web3.to_checksum_address(BRIDGE_CONTRACT_ADDRESS), abi=BRIDGE_CONTRACT_ABI)

TARGET_TOPICS = [
    # Untuk event ETHDepositInitiated
    "0x35d79ab81f2b2017e19afb5c5571778877782d7a8786f5907f93b0f4702f4f23", 
    
    # Untuk event ERC20DepositInitiated
    "0x718594027abd4eaed59f95162563e0cc6d0e8d5b86b1c7be8b1b0ac3343d0396",
    
    # Untuk event ERC20WithdrawalFinalized
    # Signature: ERC20WithdrawalFinalized(address,address,address,address,uint256,bytes)
    "0x3ceee06c1e37648fcbb6ed52e17b3e1f275a1f8c7b22a84b2b84732431e046b3",
    
    # 1. ETHWithdrawalFinalized(address,address,uint256,bytes)
    "0x2ac69ee804d9a7a0984249f508dfab7cb2534b465b6ce1580f99a38ba9c5e631",
]

print("Memulai monitoring event logs dengan Python...")

# --- Fungsi untuk menangani pesan WebSocket ---
# --- Fungsi untuk menangani pesan WebSocket (VERSI FINAL) ---
# --- Fungsi untuk menangani pesan WebSocket (VERSI FINAL TERAKHIR) ---


def on_message(ws, message):
    data = json.loads(message)

    if "params" not in data or "result" not in data["params"]:
        return

    log_data = data["params"]["result"]
    
    parsed_log_data_for_web3 = log_data.copy()
    try:
        parsed_log_data_for_web3['data'] = Web3.to_bytes(hexstr=log_data.get('data', '0x'))
        parsed_log_data_for_web3['topics'] = [
            Web3.to_bytes(hexstr=topic_hex) for topic_hex in log_data.get('topics', [])
        ]
    except Exception as e:
        print(f"ERROR saat konversi data log: {e}")
        return

    print("\n---------------------------------------")
    print("Event Log Baru Diterima:")
    print(f"Blok Number: {int(log_data.get('blockNumber', '0x0'), 16)}")
    print(f"Transaction Hash: {log_data.get('transactionHash')}")

    try:
        if not log_data.get('topics'):
            print("WARNING: Log diterima tanpa topik, tidak dapat di-parse.")
            return

        event_signature_hash_from_log = log_data['topics'][0].lower()
        event_abi_matching_topic = None

        for event_abi in bridge_contract.abi:
            if event_abi.get("type") == "event":
                inputs = ",".join([i["type"] for i in event_abi["inputs"]])
                current_event_signature = f"{event_abi['name']}({inputs})"
                computed_hash_from_abi = Web3.to_hex(Web3.keccak(text=current_event_signature)).lower()

                if computed_hash_from_abi == event_signature_hash_from_log:
                    event_abi_matching_topic = event_abi
                    print(f"   >>> KECOCOKAN DITEMUKAN untuk event: {event_abi['name']} <<<")
                    break

        if event_abi_matching_topic:
            decoded_log = bridge_contract.events[event_abi_matching_topic['name']]().process_log(parsed_log_data_for_web3)
            
            # --- INI BAGIAN YANG DIPERBAIKI ---
            # Mengakses data menggunakan gaya dictionary ['key'] bukan .key
            print("   Hasil Parsing Event:")
            print(f"   - Nama Event: {decoded_log['event']}")
            print("   - Argumen:")
            for key, value in decoded_log['args'].items():
                if isinstance(value, bytes):
                    display_value = Web3.to_hex(value)
                else:
                    display_value = value
                print(f"     - {key}: {display_value}")
        else:
            print("   >>> GAGAL PARSING: Event signature tidak ditemukan di ABI.")
            print(f"   Signature Hash yang diterima: {event_signature_hash_from_log}")

    except Exception as e:
        print(f"ERROR: Terjadi kesalahan saat mem-parse log: {e}")
        print(f"   Log data mentah yang menyebabkan error: {json.dumps(log_data, indent=2)}")
    
    finally:
        print("---------------------------------------")

        # --- DI SINI ANDA AKAN MENGINTEGRASIKAN DENGAN XChainWatcher (Logika Datalog Anda) ---
        # Data yang sudah di-parse (decoded_log) ini adalah input bersih untuk mesin Datalog Anda.
        # Misalnya, jika Anda mendapatkan parsed_log.event == 'Lock' dan parsed_log.args.user serta parsed_log.args.amount
        # Anda bisa meneruskannya ke engine Datalog Anda untuk dicek dengan aturan.

def on_error(ws, error):
    print(f"Error WebSocket: {error}")

def on_close(ws, close_status_code, close_msg):
    print("Koneksi WebSocket ditutup.")

def on_open(ws):
    print("Koneksi WebSocket dibuka. Berlangganan event logs...")
    
    subscribe_message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_subscribe",
        "params": [
            "logs",
            {
                "address": Web3.to_checksum_address(BRIDGE_CONTRACT_ADDRESS),   
                "topics": [TARGET_TOPICS] 
            }
        ]
    }
    ws.send(json.dumps(subscribe_message))

# --- Main Logic ---
if __name__ == "__main__":
    # Menambahkan opsi sslopt untuk koneksi WSS
    websocket.enableTrace(True) # Untuk melihat log debug dari websocket-client
    ws = websocket.WebSocketApp(
        ALCHEMY_WEBSOCKET_URL,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )

    # Ini akan menjalankan loop WebSocket secara blocking.
    # Untuk aplikasi yang lebih kompleks, pertimbangkan menggunakan threading atau asyncio.
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})