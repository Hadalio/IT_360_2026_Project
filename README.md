# Cookiescope

**IT-360 SIEM & Digital Forensics, Instructor: Sean Sanders**

**Authors:** Jake Cirks, Ryan Kotrba, Xander Beachy

Cookiescope is a Python-based digital forensics toolkit that analyzes browser cookies, Windows event logs, and memory dumps, then combines the results into a structured report. It can also send findings to an Ollama-hosted LLM for an AI-generated forensic write-up.

## Features

- **Cookie analysis:** parses exported browser cookie JSON (Chrome, Edge, Firefox formats are normalized) and flags:
  - Known tracking, malicious, and fingerprinting domains
  - Suspicious TLDs (`.ru`, `.cn`, `.biz`, `.info`, `.top`, `.xyz`)
  - Session/auth cookies missing `Secure`, `HttpOnly`, or `SameSite` protections
  - Unusually long-lived authentication tokens
  - Third-party cookies and suspicious keywords in domains
- **Log analysis:** parses `.evtx` files (or plaintext logs) and flags suspicious events such as failed logons (4625), account creation (4720), audit log clearing (1102), new processes (4688), and service installs (4697, 7045).
- **Memory analysis:** runs Volatility 3 (`windows.pslist`) against a memory dump and flags suspicious processes such as `mimikatz.exe`, `cmd.exe`, `powershell.exe`, and `nc.exe`.
- **Report builder:** aggregates findings and flags from all modules into a single report.
- **AI analysis:** sends a forensic prompt to an Ollama server (default model `llama3.3:latest`) to produce a timeline, session analysis, suspicious-domain reasoning, cross-browser correlation, and a final report.

## Project Structure

| File | Purpose |
|---|---|
| `demo.py` | Entry point. Runs all modules, prints the report, and queries the LLM. |
| `forensic_tool.py` | `Forensic_tool` class with cookie, log, and memory analysis. |
| `report_builder.py` | `ReportBuilder` class that builds the summary and collects flags. |
| `ollama_client_demo.py` | `Ollamaclientdemo` class: API wrapper with persistent chat history. |


## Requirements

- Python 3.9+
- [Volatility 3](https://github.com/volatilityfoundation/volatility3), with the `vol` command available on your `PATH`
- Python packages:

```bash
pip install requests python-evtx
```

- Access to an Ollama-compatible API endpoint and an API key

## Setup

1. Clone the repository and install dependencies.
2. Place your evidence files in the project directory:
   - `cookies.json`: exported browser cookies
   - `logs.evtx`: Windows event log
   - `MemoryDump_Lab1.raw`: memory image
3. Set your API key as an environment variable:

```bash
# Linux / macOS
export API_KEY="your-api-key"

# Windows (PowerShell)
$env:API_KEY="your-api-key"
```

4. (Optional) Edit the server URL and model in `main.py`:

```python
client = Ollamaclient(
    url='http://sushi.it.ilstu.edu:8080',
    api_key=os.environ.get('API_KEY'),
    model="llama3.3:latest"
)
```

## Usage

```bash
python demo.py
```

The program will:

1. Analyze cookies, logs, and memory.
2. Print a forensic report with a summary, flags, and detailed findings per section.
3. Send a forensic analysis prompt to the LLM and print its response.

Chat history is saved to `history.json`. Use `Ollamaclient.reset()` to clear it or `trim_history()` to keep it small.

## Sources

- https://thepythoncode.com/article/extract-chrome-cookies-python

## Disclaimer

Built for educational use in IT-360. The tool's detections are heuristic and should not replace professional forensic tooling or analyst judgment.
