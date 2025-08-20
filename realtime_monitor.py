import os
import json
import websocket
import ssl
import subprocess
import requests
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

def get_llm_report(event_name, args, enriched_data, souffle_report):
    print("   [INFO] LLM generating a report")
    try:
        if event_name == "ETHDepositInitiated":
            amount_eth = Web3.from_wei(args['amount'], 'ether')
            transaction_details = (f"Event Type: Deposit ETH\n"
                                   f"From: {args['from']}\n"
                                   f"To: {args['to']}\n"
                                   f"Amount: {amount_eth:.6f} ETH\n")
            list_transaction = get_list_transaction(args['from'])
            list_median = get_median_gas_list(enriched_data['block'])
        
        if enriched_data:
            ts_readable = datetime.fromtimestamp(enriched_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S UTC')
            gas_gwei = Web3.from_wei(enriched_data['gasPrice'], 'gwei')
            transaction_details += (f"\nTimestamp: {ts_readable}\n"
                                    f"Gas Price: {gas_gwei:.2f} Gwei\n"
                                    f"Nonce: {enriched_data['nonce']}")   
        
        system_prompt = "You are a senior blockchain security analyst."
        user_prompt =  (f"A security alert has just been triggered.\n\n"
                 f"1. *Technical Report from Detection System (Soufflé):*\n{souffle_report}\n\n"
                 f"2. *Details of the Triggering Transaction:*\n{transaction_details}\n\n"
                 f"3. *Verification Data A - Sender's Transaction History:*\n{list_transaction}\n\n"
                 f"4. *Verification Data B - Median Gas in Neighbouring Blocks:*\n{list_median}\n\n"
                 f"**Your Task:**\n"
                 f"Based on all the information provided, your primary task is to verify the technical alert and produce a structured incident report. Follow these specific verification instructions:\n\n"
                 f"- **If the Technical Report indicates a `HighValueDeposit` violation**, your verification **must focus on Verification Data A (Sender's Transaction History)**. Analyze this history to determine if a transaction of this magnitude is normal for this specific sender or if it's a significant outlier. A high-value transfer from a historically high-volume address is less suspicious than one from a new or typically low-volume address.\n\n"
                 f"- **If the Technical Report indicates a `HighGasPrice` violation**, your verification **must focus on Verification Data B (Median Gas in Neighbouring Blocks)**. Analyze this data to determine if the high gas price is an isolated spike (more suspicious, could indicate a priority transaction for an exploit) or part of a wider network trend due to congestion (less suspicious).\n\n"
                 f"- For all cases, consider that `from` and `to` addresses being the same is a common bridging pattern and not automatically suspicious unless other risk factors are present.\n\n"
                 f"**Write your report using the following strict format:**\n\n"
                 f"**1. Classification:** (Your decision: *Anomalous* or *Normal*)\n"
                 f"**2. Incident Summary:** (Explain in simple terms what happened in this transaction.)\n"
                 f"**3. Potential Risk & Reasoning:** (Explain why this activity is considered risky or not. You **must** reference the specific verification data (`Data A` or `Data B`) in your reasoning to justify your classification.)\n"
                 f"**4. Recommended Action:** (Provide one concrete, immediate step for the operator.)")
        
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

def get_list_transaction(address):
    url = f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset=10&sort=desc&apikey={ETHERSCAN_API_KEY}"
    resp = requests.get(url).json()
    if resp['status'] == '1':
        return(resp)
    return 0

def get_current_median_gas(current_block):
    gas_prices = [tx['gasPrice'] for tx in current_block.transactions]
    median_gas = statistics.median(gas_prices)
    return median_gas

def get_median_gas_list(current_block):
    start_block = current_block - 5
    end_block = current_block + 5

    median_gas_list = []

    for block_number in range(start_block, end_block + 1):
        median_gas = get_current_median_gas(block_number)
        if median_gas is not None:
            median_gas_list.append(median_gas)

    return median_gas_list

def analyze_with_souffle(fact_string, event_name, args, enriched_data):
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
                        report = f"\n   Triggered Rule: {rule_name}\n   --- Transaction Details ---"
                        
                        for row in data_rows:
                            if not row.strip() or "===" in row:
                                continue
                                
                            parts = row.split('\t')

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
                amount_eth = Web3.from_wei(args['amount'], 'ether')
                print(f"     - From: {args['from']}")
                print(f"     - To:   {args['to']}")
                print(f"     - Amount: {amount_eth:.6f} ETH")
                if enriched_data:
                    ts_readable = datetime.fromtimestamp(enriched_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S UTC')
                    gas_gwei = Web3.from_wei(enriched_data['gasPrice'], 'gwei')
                    median_gas_gwei = Web3.from_wei(int(float(enriched_data['medianGas'])), 'gwei')
                    print(f"     - Timestamp: {ts_readable}")
                    print(f"     - Gas Price: {gas_gwei:.2f} Gwei")
                    print(f"     - Median Gas: {median_gas_gwei:.2f} Gwei")
                    print(f"     - Nonce: {enriched_data['nonce']}")
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
        print(f"     - Median Gas: {Web3.from_wei(int(float(enriched_data['medianGas'])), 'gwei'):.2f} Gwei")
        print(f"     - Nonce: {enriched_data['nonce']}")
    print("\n" + "="*30 + "\n")


def on_message(ws, message):
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
            block_details = w3_http.eth.get_block(block_number, full_transactions=True)
            median_gas = get_current_median_gas(block_details)

            enriched_data = {
                "timestamp": block_details['timestamp'],
                "gasPrice": transaction_details['gasPrice'],
                "nonce": transaction_details['nonce'],
                "medianGas": median_gas,
                "block": block_number
            }

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
                
                analyze_with_souffle(fact_string, event_name_found, args, enriched_data)

        except Exception as e:
            print(f"   [DEBUG] Failed to parse {event_name_found}: {e}")

def on_error(ws, error):
    print(f"Error WebSocket: {error}")

def on_close(ws, close_status_code, close_msg):
    print("WebSocket connection closed.")

def on_open(ws):
    print("WebSocket connection opened. Monitoring ETH deposit events...")
    subscribe_message = {
        "jsonrpc": "2.0", "id": 1, "method": "eth_subscribe",
        "params": ["logs", {"address": BRIDGE_CONTRACT_ADDRESS, "topics": [list(TOPIC_HASHES.keys())]}]
    }
    ws.send(json.dumps(subscribe_message))

if __name__ == "__main__":
    print("Starting The Real-Time Monitoring...")
    ws = websocket.WebSocketApp(
        INFURA_WEBSOCKET_URL,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})