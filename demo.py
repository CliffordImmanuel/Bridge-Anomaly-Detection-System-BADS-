import os
import json
import subprocess
import requests
import statistics
import time
from openai import OpenAI
from datetime import datetime
from web3 import Web3, HTTPProvider
from dotenv import load_dotenv

load_dotenv()

INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

try:
    llm_client = OpenAI(api_key=OPENAI_API_KEY)
except Exception as e:
    print(f"--- ERROR --- Failed to configure OpenAI client: {e}")
    exit()

INFURA_HTTP_URL = f"https://mainnet.infura.io/v3/{INFURA_PROJECT_ID}"
BRIDGE_CONTRACT_ADDRESS = "0x99C9fc46f92E8a1c0dec1b1747d010903e884be1"
PATH_TO_RULES_FILE = "realtime_rules.dl"

w3 = Web3()
try:
    w3_http = Web3(HTTPProvider(INFURA_HTTP_URL))
    if not w3_http.is_connected():
        print("--- ERROR --- Failed to connect to Infura. Check your INFURA_PROJECT_ID.")
        exit()
except Exception as e:
    print(f"--- ERROR --- Failed to connect to Infura: {e}")
    exit()

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

def get_current_median_gas(block):
    gas_prices = [tx['gasPrice'] for tx in block.transactions]
    median_gas = statistics.median(gas_prices)
    return median_gas

def get_median_gas_list(current_block):
    start_block = current_block - 5
    end_block = current_block + 5

    median_gas_list = []

    for block_number in range(start_block, end_block + 1):
        block_details = w3_http.eth.get_block(block_number, full_transactions=True)

            # Di kode kamu sebelumnya, get_current_median_gas menerima block_details
        median_gas = get_current_median_gas(block_details)
        if median_gas is not None:
            median_gas_gwei = Web3.from_wei(int(float(median_gas)), 'gwei')
            median_gas_list.append(median_gas_gwei)

    return median_gas_list

def analyze_with_souffle(fact_string, event_name, args, enriched_data):
    # """Memanggil Souffle dan jika ada alarm, minta LLM untuk menjelaskannya."""
    print(f"[INFO] Analyzing fact...")
    try:
        command = ['souffle', PATH_TO_RULES_FILE, '-F', '-', '-D', '-']
        result = subprocess.run(command, input=fact_string, text=True, capture_output=True, check=False)

        if result.stderr:
              print(f"[ERROR SOUFFLE]: {result.stderr}")

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
                    print(f"     - Median Gas (x3): {median_gas_gwei * 3:.2f} Gwei")
                    print(f"     - Nonce: {enriched_data['nonce']}")
                print(llm_report)
                print("="*30 + "\n")
                return "anomalous"
            else:
                print_normal_transaction(event_name, args, enriched_data)
                return "normal"
        else:
            print_normal_transaction(event_name, args, enriched_data)
            return "normal"

    except Exception as e:
        print(f"   [ERROR]: An error occurred while running Souffle.: {e}")
    
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

def process_historical_txlist(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)

    if data.get("status") != "1":
        print("--- ERROR --- JSON tidak valid / tidak ada transaksi")
        return

    #test count
    count = 0
    anomalous_count = 0
    normal_count = 0

    for tx in data["result"]:
        try:
            # hanya peduli transaksi ke Bridge + fungsi depositETH
            if tx["to"].lower() != BRIDGE_CONTRACT_ADDRESS.lower():
                continue

            fname = tx.get("functionName", "").lower()
            if not ("depositeth" in fname or "bridgeethto" in fname):
                continue

            print("\n---------------------------------------")
            print(f"[HISTORICAL] Deposit ETH detected. Processing {tx['hash']}")

            count += 1
            print(f"\n[PROGRESS] transaksi ke-{count}")

            block_number = int(tx["blockNumber"])
            block_details = w3_http.eth.get_block(block_number, full_transactions=True)
            median_gas = get_current_median_gas(block_details)

            enriched_data = {
                "timestamp": int(tx["timeStamp"]),
                "gasPrice": int(tx["gasPrice"]),
                "nonce": int(tx["nonce"]),
                "medianGas": median_gas,
                "block": block_number
            }

            # samakan format seperti decode event
            args = {
                "from": tx["from"],
                "to": tx["to"],
                "amount": int(tx["value"]),
                "extraData": tx["input"]  # tidak dipakai biasanya
            }

            fact_string = (f"ETH\t{args['from']}\t{args['to']}\t"
                           f"{args['amount']}\t{args['extraData']}\t"
                           f"{enriched_data['timestamp']}\t{enriched_data['gasPrice']}\t"
                           f"{enriched_data['nonce']}\t{median_gas}\n")
            
            # median_gas_list = get_median_gas_list(enriched_data['block'])
            # for val in median_gas_list:
            #     print(f"     - {val:.2f} Gwei")
            # print(median_gas_list)

            result = analyze_with_souffle(fact_string, "ETHDepositInitiated", args, enriched_data)
            if result == "anomalous":
                anomalous_count += 1
            elif result == "normal":
                normal_count += 1

        except Exception as e:
            print(f"[DEBUG] Failed to parse tx {tx.get('hash')}: {e}")
    
    print("\n========== SUMMARY ==========")
    print(f"Total transaksi diproses: {count}")
    print(f"Normal: {normal_count}")
    print(f"Anomali: {anomalous_count}")
    print("=============================\n")

if __name__ == "__main__":
    print("Starting Historical Transaction Analysis (from Etherscan JSON)...")
    process_historical_txlist("transactions_13-20.json")