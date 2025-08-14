import os
import json
import subprocess
import requests
import statistics
from openai import OpenAI
from datetime import datetime
from web3 import Web3, HTTPProvider
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

try:
    llm_client = OpenAI(api_key=OPENAI_API_KEY)
except Exception as e:
    print(f"--- ERROR --- Failed to configure OpenAI client: {e}")
    exit()

PATH_TO_RULES_FILE = "realtime_rules.dl"

w3 = Web3()

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
        
        with open("transactions.json", "w", encoding="utf-8") as f:
            json.dump(list_transaction, f, indent=4, ensure_ascii=False)

        print("Data transaksi berhasil disimpan ke transactions.json")
        
        system_prompt = "You are a senior blockchain security analyst."
        user_prompt =   (f"A security alert has just been triggered.\n\n"
                        f"*Technical Report from the Detection System:*\n{souffle_report}\n\n"
                        f"*Details of the Triggering Transaction:*\n{transaction_details}\n\n"
                        f"*List of transaction on the address:*\n{list_transaction}\n\n"
                        f"Your task:\n"
                        f"Based on the above information, analyze the potential security incident. If the sender and recipient addresses (from and to) are the same, "
                        f"consider it a common pattern in bridging transactions and *not automatically suspicious*, unless there are other indications (e.g., very large values, high gas price, etc.).\n"
                        f"Use the list of transaction as a verification if the transactions is a suspicious or not.\n\n"
                        f"Write your decision if the transaction is a suspicious or not and give your reasoning in a structure format:\n"
                        f"1. *Incident Summary:* Explain in simple terms what happened.\n"
                        f"2. *Potential Risk:* Explain why (or why not) this activity is considered risky.\n"
                        f"3. *Recommended Action:* Provide one concrete step that the operator should take immediately.\n"
                        f"4. Classification: Based on your verification, decide the classification for the transaction, "
                        f"if the transaction is considered an attack or anomaly, print True, else print False")
        
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

def get_median_gas(block):
    # block = w3_http.eth.get_block('latest', full_transactions=True)

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
