# ⚔️ Chanakya — Offensive Security Recon & Vulnerability Assessment Framework

**Chanakya** is a Python-based offensive security and reconnaissance framework developed under the **JustHackIT** brand. It brings reconnaissance, automated discovery, vulnerability testing, API-based dorking, SQL injection automation, proxy validation, and security assessment modules into a unified command-line interface.

Inspired by the strategic thinking of **Chanakya**, the project is built around a simple principle:

> **“Know your enemy before the battle.” — Chanakya**

**Current Version:** `3.1.6`

---

## 📸 Screenshot

![Chanakya](/img/image.png "Chanakya terminal interface")

---

## ⚠️ Disclaimer

Chanakya is intended **only for authorized security testing, research, penetration testing, and educational purposes**.

Do not use Chanakya against systems, applications, networks, accounts, or infrastructure without explicit authorization.

The developer and contributors are not responsible for misuse, damage, data loss, service disruption, or unauthorized activity resulting from the use of this software.

By using Chanakya, you agree to take full responsibility for your actions.

---

## 🧠 What Is Chanakya?

Chanakya is designed to help security professionals automate repetitive stages of offensive security assessments.

Instead of relying on multiple unrelated command-line tools for every stage, Chanakya provides a single interface for performing reconnaissance, discovery, and controlled vulnerability assessment.

The project is actively developed under the **JustHackIT** cybersecurity initiative.

### Chanakya's approach

```text
Recon
  ↓
Discovery
  ↓
Enumeration
  ↓
Security Testing
  ↓
Evidence Collection
  ↓
Assessment
  ↓
Reporting
```

---

## 🚀 Features

Chanakya includes multiple security assessment capabilities, including:

```text
1. Port Scanning
   └─ Discover open ports on authorized targets.

2. Service Scanning
   └─ Identify services exposed on discovered ports.

3. Reconnaissance
   └─ Gather information useful during security assessments.

4. Dorking
   └─ Perform API-assisted search-based reconnaissance.

5. SQL Injection Testing
   └─ Perform controlled SQL injection assessment and automation.

6. Command Injection Testing
   └─ Validate suspected command injection using controlled canaries.

7. XSS Testing
   └─ Detect reflected input and analyze reflection context.

8. JWT Security Assessment
   └─ Analyze JWT structure, headers, claims, algorithms,
      expiration, and other configuration indicators.

9. Proxy Fetching & Validation
   └─ Fetch and validate proxies using concurrent requests.

10. AI-Assisted Security Analysis
    └─ Send collected assessment evidence to the configured
       Chanakya AI provider for additional analysis.

11. JSON Reporting
    └─ Store assessment evidence and results as structured reports.
```

> Available modules and menu options may change between releases.

---

## 🏗️ Project Structure

```text
Chanakya/
├── ai/
├── attack/
├── scanners/
├── utils/
├── img/
│
├── chanakya.py
├── dorks.txt
├── requirements.txt
├── README.md
├── LICENSE
│
└── reports/
    └── ...
```

### Important

Local/generated files such as the following should **not** be committed to the repository:

```text
.env
reports/
scanner.log
valid_proxies.txt
__pycache__/
*.pyc
virtual environments
local test files
```

Use `.gitignore` to keep environment-specific and generated data out of Git.

---

## 🧰 Technologies & Dependencies

Chanakya is primarily written in Python.

Major technologies and libraries used by the project include:

- Python 3
- Requests
- urllib3
- python-dotenv
- Nmap
- SQLMap
- Socket
- Concurrent futures
- JSON
- Regular expressions
- ANSI terminal colors
- Configured AI provider integrations

Depending on the enabled modules, additional system tools or API credentials may be required.

---

## 🛠️ Installation

### Prerequisites

Recommended prerequisites:

- Python 3.8+
- Git
- Internet connection
- Nmap
- SQLMap
- Required Python packages from `requirements.txt`

Some modules may require additional API credentials or system dependencies.

### Clone the Repository

```bash
git clone https://github.com/VirusZzHkP/Chanakya.git
cd Chanakya
```

### Create a Virtual Environment

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

Windows:

```powershell
python -m venv venv
venv\Scripts\activate
```

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

## 🔐 Environment Configuration

Chanakya may use environment variables for API credentials and other configuration.

Create a local `.env` file:

```text
SERPAPI_KEY=your_key_here
SCRAPINGANT_KEY=your_key_here
GOOGLE_CSE_API_KEY=your_key_here
GOOGLE_CSE_CX=your_custom_search_engine_id
# Primary AI provider
OPENAI_API_KEY=your_key_here
# Fallback AI provider
GEMINI_API_KEY=your_key_here
# Models
OPENAI_MODEL=gpt-5.4-mini
GEMINI_MODEL=gemini-3.5-flash
```

If AI functionality is enabled in your configuration, add the required credentials for your configured AI provider as appropriate.

### Never commit `.env`

Your `.env` file can contain secrets.

Make sure it is listed in `.gitignore`:

```gitignore
.env
.env.*
```

---

## 📄 Dork Configuration

For dork-based reconnaissance, maintain your authorized search queries in:

```text
dorks.txt
```

Example:

```text
site:example.com
site:example.com inurl:id=
site:example.com filetype:pdf
```

Only perform reconnaissance against targets and domains where you have appropriate authorization.

---

## 🚀 Usage

Start Chanakya with:

```bash
python3 chanakya.py
```

On Windows:

```powershell
python chanakya.py
```

Follow the interactive menu to select the required security assessment module.

---

## 🔎 Security Assessment Modules

### Port Scanning

Identify accessible TCP ports on an authorized target.

### Service Scanning

Perform basic service discovery against exposed ports.

### SQL Injection Testing

Chanakya can integrate SQL injection assessment capabilities and SQLMap-based testing.

Use only against applications where testing is explicitly authorized.

### Command Injection Testing

The command-injection validator uses controlled testing techniques and evidence collection.

It intentionally avoids:

- Reverse shells
- Persistence
- Arbitrary command execution
- Payload delivery
- Credential theft

### XSS Testing

The XSS module performs controlled reflection testing using unique inert canaries.

It focuses on:

- Input reflection
- Reflection count
- Reflection context
- HTML text context
- HTML attribute context
- JavaScript context
- CSS context
- HTML comments

The validator does not intentionally execute JavaScript.

### JWT Security Assessment

The JWT assessment module analyzes supplied JWTs for indicators such as:

- JWT structure
- Header configuration
- Algorithm selection
- Registered claims
- Expiration
- Issued-at timestamps
- Not-before timestamps
- Issuer
- Audience
- Subject
- Sensitive claim names
- Privilege-related claims
- Algorithm/key-type indicators

The module is intended for defensive assessment and does not brute-force signing secrets or generate forged privileged tokens.

---

## 🤖 AI-Assisted Analysis

Chanakya can provide collected assessment evidence to the configured AI analysis layer.

AI analysis is intended to help with:

- Interpreting findings
- Correlating evidence
- Explaining potential security impact
- Providing remediation-oriented context
- Prioritizing observations

AI output should be treated as **analysis assistance**, not as definitive proof of a vulnerability.

Always validate important findings manually.

---

## 📊 Reporting

Chanakya generates structured JSON evidence for supported assessment modules.

Reports are stored locally under the configured reports directory.

Example:

```text
reports/
├── attacks/
│   └── ...
├── xss/
│   └── ...
└── command_injection/
    └── ...
```

Generated reports may contain sensitive assessment information.

Do not publish or commit reports containing:

- Authentication tokens
- API keys
- Credentials
- Internal URLs
- Private infrastructure information
- Sensitive application data
- Personally identifiable information

---

## 🔒 Responsible Testing

Before running Chanakya against a target, ensure that you have permission to test it.

Good practice includes:

```text
✓ Written authorization
✓ Defined scope
✓ Approved target list
✓ Approved testing window
✓ Rate limits
✓ Emergency contact
✓ Data-handling requirements
✓ Reporting requirements
```

Avoid testing production systems aggressively unless the engagement explicitly permits it.

---

## 🧪 Development

Clone the repository:

```bash
git clone https://github.com/VirusZzHkP/Chanakya.git
cd Chanakya
```

Create a development environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run Chanakya:

```bash
python3 chanakya.py
```

Before submitting changes, verify that:

```text
- Secrets are not committed.
- .env is not committed.
- Generated reports are not committed.
- Local logs are not committed.
- Virtual environments are not committed.
- Temporary test files are not committed.
- New modules are correctly imported.
- Existing functionality remains operational.
```

---

## 📦 Version

Current release:

```text
Chanakya v3.1.6
```

---

## 🗺️ Roadmap

Future development may include:

```text
- Expanded reconnaissance modules
- Improved vulnerability detection
- Additional authentication testing
- Better evidence correlation
- Improved reporting
- Additional AI-assisted analysis
- Modular scanner architecture
- Performance improvements
- More automation workflows
```

The roadmap may evolve as Chanakya develops.

---

## 🏴 JustHackIT

Chanakya is developed under the **JustHackIT** cybersecurity brand.

### JustHackIT

**Website:** [justhackit.in](https://justhackit.in)

**Instagram:** [@justhackit.in](https://www.instagram.com/justhackit.in/)

**X:** [@JustHackIT_HQ](https://x.com/JustHackIT_HQ)

---

## 👨‍💻 Developer

**VirusZzWarning**

> Made with ♥ by VirusZzWarning

---

## 📜 License

Chanakya is distributed under the [MIT License](LICENSE).

---

## ⚔️ Final Note

Chanakya is built around the philosophy of strategic security testing:

```text
Observe.
Recon.
Understand.
Test.
Validate.
Report.
```

Use the tool responsibly, stay within scope, and always test with authorization.

> **Be the strategist, not the pawn.**

---

**Chanakya v3.1.6 · A JustHackIT Project**
