# 🛡️ Bridge Anomaly Detection System (BADS)

**BADS** is a prototype system designed to monitor activity on cross-chain bridges **in real-time** and detect potentially malicious or anomalous transactions.  
This system combines the speed of WebSocket monitoring with the analytical power of declarative logic using **Datalog** and **Soufflé**, further enhanced by incident report analysis from a **Large Language Model (LLM)**.  

> 📖 **Inspired by the academic research XChainWatcher**. BADS extends this idea by integrating an LLM for incident reporting and anomaly verification, focusing on actionable insights and reduced false positives.

---

## ✨ Key Features

- ⚡ **Real-Time Monitoring**: Connects directly to an Ethereum node via WebSocket to receive event data with minimal latency.  
- 🧠 **Declarative Logic Analysis**: Utilizes Datalog and the Soufflé engine to apply complex security rules that can be easily modified without changing the core Python code.  
- 🎯 **Anomaly Detection**: Comes with built-in rules to detect high-value transactions (*HighValueEthDeposit*) and interactions with specific tokens. The rulebook can be easily extended.  
- 🔗 **Data Enrichment**: Automatically fetches additional contextual data (e.g., timestamp and gasPrice) via HTTP for more in-depth analysis.  
- 🤖 **Intelligent Reporting (LLM)**: Integrates analysis results with an LLM to generate human-readable incident reports and verify whether detected anomalies are genuine, helping reduce false positives.

---

## 🏗️ System Architecture

1. **Data Source Layer**  
   - **Node Provider**: Infura  
   - **Network**: Ethereum Mainnet / Sepolia (testing)  

2. **Collection & Processing Layer (Fact Extractor)**  
   - **Component**: `realtime_monitor.py`  
   - **Task**: Establishes a persistent WebSocket connection, listens for events (`ETHDepositInitiated`, `ERC20DepositInitiated`), performs data enrichment via HTTP, and converts raw data into clean, structured Datalog facts.  

3. **Analysis Layer (Analysis Engine)**  
   - **Component**: Soufflé Datalog Engine + `realtime_rules.dl`  
   - **Task**: Evaluates facts against the rulebook. If a rule is matched, Soufflé generates a violation output.  

4. **Presentation Layer**  
   - **Component**: `realtime_monitor.py`  
   - **Task**: Displays a security alarm if a violation is detected and uses the LLM to verify whether the detected anomaly is genuine, also it requests a more detailed incident report or logs a normal transaction report. 

---

## ✅ Prerequisites

- Windows 10/11 with WSL 2  
- Ubuntu 22.04 LTS (inside WSL)  
- [Soufflé Datalog Engine](https://souffle-lang.github.io/)  
- Python **3.11.9** (recommended via `pyenv`)  
- Git  
- API Keys:
  - Infura Project ID  
  - OpenAI API Key  

---

## ⚙️ Installation

Run all commands inside your **Ubuntu 22.04 (WSL)** terminal.

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY-NAME.git
cd YOUR-REPOSITORY-NAME
```
### 2. Install System Tools (Soufflé & Build Dependencies)
```bash
sudo apt update
sudo apt install -y software-properties-common wget gpg build-essential \
  libssl-dev zlib1g-dev libbz2-dev libreadline-dev curl llvm \
  libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev git

wget -qO- "https://souffle-lang.github.io/ppa/souffle-key.public" \
  | sudo gpg --dearmor -o /usr/share/keyrings/souffle-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/souffle-archive-keyring.gpg] \
https://souffle-lang.github.io/ppa/ubuntu/ stable main" \
  | sudo tee /etc/apt/sources.list.d/souffle.list

sudo apt update
sudo apt install souffle -y
```
### 3. Install Python via pyenv
```bash
curl https://pyenv.run | bash

# Add configuration to .bashrc
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
exec "$SHELL"

pyenv install 3.11.9
pyenv global 3.11.9
```
### 4. Set Up Virtual Environment
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🔧 Configuration
Create the .env file from the example:


### 1. Create the .env file from the example:
``` bash
cp .env.example .env
```
### 2. Fill in your API keys:
``` bash
INFURA_PROJECT_ID="your_infura_project_id_here"
OPENAI_API_KEY="your_openai_api_key_here" 
``` 
### 3. Open realtime_rules.dl to adjust detection thresholds or add new rules.

---

## 🚀 Usage
Every time you open a new terminal, activate the virtual environment and run the monitor:

``` bash
cd /path/to/your/project
source venv/bin/activate
python realtime_monitor.py
```
The script will start monitoring transactions and display output in the terminal as new events are detected.
