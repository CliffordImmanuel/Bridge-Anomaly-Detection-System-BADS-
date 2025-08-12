import os
import json
import websocket
import ssl
import subprocess
import requests
import csv
import statistics
from openai import OpenAI
from datetime import datetime
from web3 import Web3, HTTPProvider
from dotenv import load_dotenv

load_dotenv()

INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

if not INFURA_PROJECT_ID or not OPENAI_API_KEY:
    print("--- ERROR --- Make sure INFURA_PROJECT_ID and OPENAI_API_KEY are in the .env file!")
    exit()

try:
    llm_client = OpenAI(api_key=OPENAI_API_KEY)
except Exception as e:
    print(f"--- ERROR --- Failed to configure OpenAI client: {e}")
    exit()


INFURA_WEBSOCKET_URL = f"wss://mainnet.infura.io/ws/v3/{INFURA_PROJECT_ID}"
INFURA_HTTP_URL = f"https://mainnet.infura.io/v3/{INFURA_PROJECT_ID}"
BRIDGE_CONTRACT_ADDRESS = "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1"
PATH_TO_RULES_FILE = "realtime_rules.dl"
CSV_LOG_FILE = "alerts_log.csv"

TARGET_ABIS = [
    {"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"from","type":"address"},{"indexed":True,"internalType":"address","name":"to","type":"address"},{"indexed":False,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":False,"internalType":"bytes","name":"extraData","type":"bytes"}],"name":"ETHDepositInitiated","type":"event"},
]

TOPIC_HASHES = {
    "0x35d79ab81f2b2017e19afb5c5571778877782d7a8786f5907f93b0f4702f4f23": "ETHDepositInitiated",
}

w3 = Web3()
try:
    w3_http = Web3(HTTPProvider(INFURA_HTTP_URL))
    if not w3_http.is_connected():
        print("--- ERROR --- Failed to connect to Infura. Check your INFURA_PROJECT_ID.")
        exit()
except Exception as e:
    print(f"--- ERROR --- Failed to connect to Infura: {e}")
    exit()
bridge_contract = w3.eth.contract(address=Web3.to_checksum_address(BRIDGE_CONTRACT_ADDRESS), abi=TARGET_ABIS)

def get_llm_report(event_name, args, enriched_data, souffle_report=None):
    # """Membuat laporan insiden yang mudah dibaca menggunakan LLM OpenAI."""
    print("   [INFO] LLM generating a report")
    try:
        if event_name == "ETHDepositInitiated":
            amount_eth = Web3.from_wei(args['amount'], 'ether')
            transaction_details = (f"Event Type: Deposit ETH\n"
                                   f"From: {args['from']}\n"
                                   f"To: {args['to']}\n"
                                   f"Amount: {amount_eth:.6f} ETH\n")
            list_transaction = get_list_transaction(args['from'])
        
        if enriched_data:
            ts_readable = datetime.fromtimestamp(enriched_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S UTC')
            gas_gwei = Web3.from_wei(enriched_data['gasPrice'], 'gwei')
            transaction_details += (f"\nTimestamp: {ts_readable}\n"
                                    f"Gas Price: {gas_gwei:.2f} Gwei\n"
                                    f"Nonce: {enriched_data['nonce']}")   
        
        system_prompt = "You are a senior blockchain security analyst."
        user_prompt =   (f"A security alert has just been triggered.\n\n"
                        f"*Technical Report from the Detection System:*\n{souffle_report}\n\n"
                        f"*Details of the Triggering Transaction:*\n{transaction_details}\n\n"
                        f"*List of transaction on the address:*\n{list_transaction}\n\n"
                        f"Your task:\n"
                        f"Based on the above information, analyze the potential security incident. If the sender and recipient addresses (from and to) are the same, "
                        f"consider it a common pattern in bridging transactions and *not automatically suspicious*, unless there are other indications (e.g., very large values, specific tokens, etc.).\n"
                        f"Use the list of transaction as a verification if the transacctions is a suspicious or not.\n\n"
                        f"Write a brief incident report using the following format:\n"
                        f"1. *Incident Summary:* Explain in simple terms what happened.\n"
                        f"2. *Potential Risk:* Explain why (or why not) this activity is considered risky.\n"
                        f"3. *Recommended Action:* Provide one concrete step that the operator should take immediately.\n")
        
        response = llm_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"   [ERROR LLM] Failed to generate report: {e}")
        return "Failed to generate a report from LLM. Please check the technical report."

def log_alert_to_csv(alert_data):
    """Mencatat alert ke file CSV."""
    try:
        with open(CSV_LOG_FILE, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                alert_data.get('timestamp'),
                alert_data.get('rule_name'),
                alert_data.get('event_type'),
                alert_data.get('from_address'),
                alert_data.get('to_address'),
                alert_data.get('amount'),
                alert_data.get('token_address', 'N/A'),
                alert_data.get('gasPrice'),
                alert_data.get('nonce')
            ])
        print(f"   [INFO] Alert for rule's {alert_data.get('rule_name')} has been logged to {CSV_LOG_FILE}")
    except Exception as e:
        print(f"   [ERROR] Failed to log alert to CSV: {e}")

def get_list_transaction(address):
    url = f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset=2&sort=desc&apikey={ETHERSCAN_API_KEY}"
    resp = requests.get(url).json()
    if resp['status'] == '1':
        return(resp)
    return 0

def get_median_gas():
    block = w3_http.eth.get_block('latest', full_transactions=True)

    gas_prices = [tx['gasPrice'] for tx in block.transactions]
    median_gas = statistics.median(gas_prices)
    # print(f"Median gas price: {w3.from_wei(median_gas, 'gwei')} gwei")
    return median_gas

def analyze_with_souffle(fact_string, event_name, args, enriched_data):
    # """Memanggil Souffle dan jika ada alarm, minta LLM untuk menjelaskannya."""
    print(f"   [INFO] Analyzing fact...")
    try:
        command = ['souffle', PATH_TO_RULES_FILE, '-F', '-', '-D', '-']
        result = subprocess.run(command, input=fact_string, text=True, capture_output=True, check=False)

        if result.stderr:
              print(f"   [ERROR SOUFFLE]: {result.stderr}")

        if result.stdout.strip():
            report_items = []

            tables = result.stdout.strip().split('---------------')

            for table in tables:
                table = table.strip()
                if not table:
                    continue

                lines = table.split('\n')
                rule_name = lines[0].strip()
                
                if len(lines) > 3:
                    data_rows = lines[3:] 
                    
                    if data_rows and "===" not in data_rows[0]:
                        report = f"\n   Triggered Rule: {rule_name}\n   --- Violation Details ---"
                        
                        for row in data_rows:
                            if not row.strip() or "===" in row:
                                continue
                                
                            parts = row.split('\t')

                            alert_data_for_csv = {
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'rule_name': rule_name,
                                'event_type': event_name,
                            }

                            if rule_name == "HighValueEthDeposit" and len(parts) == 3:
                                from_addr, to_addr, amount_wei_str = parts
                                amount_eth = Web3.from_wei(int(float(amount_wei_str)), 'ether')
                                report += (f"\n     - From: {from_addr}\n     - To:   {to_addr}"
                                           f"\n     - Amount: {amount_eth:.6f} ETH")
                                if enriched_data:
                                    ts_readable = datetime.fromtimestamp(enriched_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S UTC')
                                    gas_gwei = Web3.from_wei(enriched_data['gasPrice'], 'gwei')
                                    report += (f"\n     - Timestamp: {ts_readable}"
                                               f"\n     - Gas Price: {gas_gwei:.2f} Gwei"
                                               f"\n     - Nonce: {enriched_data['nonce']}")
                                alert_data_for_csv.update({
                                    'from_address': from_addr,
                                    'to_address': to_addr,
                                    'amount': f"{amount_eth:.6f} ETH",
                                    'gas_price_gwei': f"{gas_gwei:.2f}",
                                    'nonce': enriched_data.get('nonce')
                                })
                                log_alert_to_csv(alert_data_for_csv)
                            elif rule_name == "HighGasPrice" and len(parts) == 2:
                                gas_price_str, median_gas_str = parts
                                gas_gwei = Web3.from_wei(int(float(gas_price_str)), 'gwei')
                                median_gwei = Web3.from_wei(int(float(median_gas_str)), 'gwei')
                                report += (f"\n     - Gas Price: {gas_gwei:.2f} Gwei"
                                           f"\n     - Median Gas: {median_gwei:.2f} Gwei")
                        report_items.append(report)
            
            if report_items:
                llm_report = get_llm_report(event_name, args, enriched_data, report_items)

                print("\n" + "="*30)
                print("🚨 INCIDENT REPORT (FROM LLM) 🚨")
                for item in report_items:
                    print(item)
                print(llm_report)
                print("="*30 + "\n")
                return True
            else:
                print_normal_transaction(event_name, args, enriched_data)
                return False
        else:
            print_normal_transaction(event_name, args, enriched_data)
            return False

    except Exception as e:
        print(f"   [ERROR]: An error occurred while running Souffle.: {e}")
        return False
    
def print_normal_transaction(event_name, args, enriched_data):
    print("\n" + "="*30)
    print("✅ NORMAL TRANSACTION (PASSED RULES) ✅")
    print(f"\n   Event Type: {event_name}")
    print("   --- Transaction Detail ---")
    if event_name == "ETHDepositInitiated":
        amount_eth = Web3.from_wei(args['amount'], 'ether')
        print(f"     - From: {args['from']}")
        print(f"     - To:   {args['to']}")
        print(f"     - Amount: {amount_eth:.6f} ETH")
    if enriched_data:
        ts_readable = datetime.fromtimestamp(enriched_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S UTC')
        gas_gwei = Web3.from_wei(enriched_data['gasPrice'], 'gwei')
        print(f"     - Timestamp: {ts_readable}")
        print(f"     - Gas Price: {gas_gwei:.2f} Gwei")
        print(f"     - Nonce: {enriched_data['nonce']}")
    print("\n" + "="*30 + "\n")


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
            print("\n---------------------------------------")
            print(f"Event '{event_name_found}' detected. Processing...")

            tx_hash = log_data_raw['transactionHash']
            transaction_details = w3_http.eth.get_transaction(tx_hash)

            block_number = log_data_raw.get('blockNumber')
            block_details = w3_http.eth.get_block(block_number)

            enriched_data = {
                "timestamp": block_details['timestamp'],
                "gasPrice": transaction_details['gasPrice'],
                "nonce": transaction_details['nonce']
            }

            median_gas = get_median_gas()

            print("  [INFO] Investigating transaction details...")

            log_copy = log_data_raw.copy()
            log_copy['topics'] = [Web3.to_bytes(hexstr=t) for t in log_copy['topics']]
            log_copy['data'] = Web3.to_bytes(hexstr=log_copy['data'])
            
            decoded_log = bridge_contract.events[event_name_found]().process_log(log_copy)
            args = decoded_log['args']

            if event_name_found == "ETHDepositInitiated":
                fact_string = (f"ETH\t{args['from']}\t{args['to']}\t"
                               f"{args['amount']}\t{Web3.to_hex(args['extraData'])}\t"
                               f"{enriched_data['timestamp']}\t{enriched_data['gasPrice']}\t"
                               f"{enriched_data['nonce']}\t{median_gas}\n")
            
            if fact_string:
                print("\n---------------------------------------")
                print(f"Event '{event_name_found}' detected. Analyzing...")
                
                has_anomaly = analyze_with_souffle(fact_string, event_name_found, args, enriched_data)
                
                print(f"   [CLASSIFICATION] Anomaly Detected: {has_anomaly}")


        except Exception as e:
            print(f"   [DEBUG] Failed to parse {event_name_found}: {e}")

def on_error(ws, error):
    print(f"Error WebSocket: {error}")

def on_close(ws, close_status_code, close_msg):
    print("Koneksi WebSocket ditutup.")

def on_open(ws):
    print("Koneksi WebSocket dibuka. Memonitor event deposit ETH...")
    subscribe_message = {
        "jsonrpc": "2.0", "id": 1, "method": "eth_subscribe",
        "params": ["logs", {"address": BRIDGE_CONTRACT_ADDRESS, "topics": [list(TOPIC_HASHES.keys())]}]
    }
    ws.send(json.dumps(subscribe_message))

def setup_csv_log():
    """Membuat file CSV log jika belum ada."""
    if not os.path.exists(CSV_LOG_FILE):
        with open(CSV_LOG_FILE, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Rule Name', 'Event Type', 'From Address', 'To Address', 'Amount', 'Token Address'])
        print(f"   [INFO] Created CSV log file: {CSV_LOG_FILE}")

if __name__ == "__main__":
    print("Memulai Monitor Real-Time (Terintegrasi dengan LLM)...")
    setup_csv_log()
    ws = websocket.WebSocketApp(
        INFURA_WEBSOCKET_URL,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})