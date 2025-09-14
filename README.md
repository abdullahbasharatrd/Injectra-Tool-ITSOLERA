# Injectra Tool

Injectra ek **CLI-based penetration testing tool** hai jo XSS, SQL Injection, aur Command Injection payloads generate aur test karne ke liye banaya gaya hai.  
Iska purpose security researchers aur penetration testers ko payloads quickly generate aur customize karne me madad karna hai.

---

## ✨ Features
- **XSS Payloads**
  - Reflected, Stored, DOM-based, aur WAF bypass payloads generate karta hai:contentReference[oaicite:0]{index=0}.
  - Encoding options: Base64, URL, Unicode.
  - Payloads ko JSON file me export karne ki facility.

- **SQL Injection Payloads**
  - Error-based, Union-based, Blind-based aur WAF bypass payloads:contentReference[oaicite:1]{index=1}.
  - Automatic target testing with HTTP requests.
  - Result summary: working vs failed payloads.

- **Command Injection Payloads**
  - Linux aur Windows dono ke liye payloads:contentReference[oaicite:2]{index=2}.
  - Encoding support (Base64, URL, Hex, Unicode).
  - Basic obfuscation (e.g., `${IFS}`).
  - Clipboard copy option (agar `pyperclip` install ho).

---

## 📦 Installation

```bash
# Repository clone karein
git clone https://github.com/<your-username>/Injectra-Tool-ITSOLERA.git
cd Injectra-Tool-ITSOLERA

# Virtual environment setup (optional)
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

# Dependencies install karein
pip install -r requirements.txt
