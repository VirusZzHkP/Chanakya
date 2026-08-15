# 🤝 Contributing to Chanakya

Thank you for your interest in contributing to **Chanakya** — an open-source offensive security reconnaissance and vulnerability assessment project under the **JustHackIT** brand.

Whether you are fixing a bug, improving documentation, adding a scanner, improving detection logic, or suggesting a feature, your contribution helps make Chanakya better.

> **Made with ♥ by Hrisikesh (VirusZzWarning)**  
> **JustHackIT — Cybersecurity. Research. Innovation.**

---

## 📌 Table of Contents

- [Getting Started](#-getting-started)
- [How to Contribute](#-how-to-contribute)
- [Development Guidelines](#-development-guidelines)
- [Security Scanner Guidelines](#-security-scanner-guidelines)
- [Code Style Guidelines](#-code-style-guidelines)
- [Issue Reporting](#-issue-reporting)
- [Security Vulnerability Reporting](#-security-vulnerability-reporting)
- [Pull Request Process](#-pull-request-process)
- [Code of Conduct](#-code-of-conduct)
- [License](#-license)

---

## 🚀 Getting Started

### 1. Fork the Repository

Fork the Chanakya repository on GitHub and clone your fork locally:

```bash
git clone https://github.com/VirusZzHkP/Chanakya.git
cd Chanakya
```

If you are working from your own fork, use your fork's URL instead.

### 2. Create a Development Branch

Do not make feature changes directly on `main`.

```bash
git checkout -b feature/your-feature-name
```

For bug fixes:

```bash
git checkout -b fix/your-fix-name
```

### 3. Create a Virtual Environment

It is recommended to use a dedicated Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

On Windows:

```powershell
python -m venv venv
venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure Your Environment

If the project requires environment variables, create a local `.env` file.

**Never commit `.env`, API keys, tokens, credentials, or other secrets to Git.**

---

## 🛠 How to Contribute

There are several ways to contribute to Chanakya:

- 🐛 Report bugs and unexpected behavior
- ✨ Propose new features
- 🔍 Improve reconnaissance capabilities
- 🛡️ Improve vulnerability detection and validation
- ⚙️ Improve scanner reliability and error handling
- 📚 Improve documentation and examples
- 🧪 Add or improve tests
- 🧹 Refactor and improve code quality
- 🚀 Improve CLI usability and performance
- 🌐 Improve compatibility across operating systems

Before implementing a large feature, consider opening an issue first so the proposed approach can be discussed.

---

## 🧠 Development Guidelines

Chanakya is a security-focused project. Contributions should prioritize:

1. **Accuracy** — avoid reporting vulnerabilities based only on weak or ambiguous signals.
2. **Safety** — scanners should minimize unnecessary impact on target systems.
3. **Evidence** — findings should contain useful evidence that allows a tester to reproduce and verify the result.
4. **Reliability** — network failures, malformed responses, timeouts, and unexpected input should be handled gracefully.
5. **Modularity** — keep scanners and supporting functionality separated into appropriate modules.
6. **Maintainability** — prefer clear, readable implementations over unnecessarily complex code.
7. **Responsible use** — functionality must remain intended for authorized security testing.

---

## 🛡️ Security Scanner Guidelines

When adding or modifying a scanner:

### Keep the Scanner Modular

Where practical, place scanner-specific logic inside the appropriate scanner module rather than adding large amounts of logic directly to `chanakya.py`.

### Provide a Stable Entry Point

Scanner modules should expose a predictable callable entry point so the Chanakya CLI can discover and invoke them consistently.

For example:

```python
def scan_example(target: str):
    ...
```

The exact function name should match the scanner loader/discovery mechanism used by the current project.

### Collect Evidence

A scanner should preferably record useful evidence such as:

- Target and parameter tested
- Request or test condition used
- HTTP status code
- Relevant response characteristics
- Detection result
- Confidence/verdict
- Reproduction information where appropriate

### Avoid Destructive Testing

Contributions should not introduce functionality that:

- Deletes or modifies unrelated target data
- Establishes persistence
- Deploys malware
- Creates unauthorized reverse shells
- Steals credentials or secrets
- Performs destructive exploitation
- Attempts to evade security controls for unauthorized access

Security validation should remain controlled and appropriate for authorized assessments.

---

## 🧹 Code Style Guidelines

Chanakya is primarily written in Python.

Please follow these conventions:

- Use **Python 3.8+** unless the project specifies a newer minimum version.
- Follow **PEP 8** where practical.
- Use descriptive names for variables, functions, and classes.
- Prefer small, focused functions.
- Add docstrings to public functions and classes.
- Keep comments focused on explaining non-obvious logic.
- Avoid commented-out or dead code.
- Handle expected exceptions explicitly.
- Avoid unnecessary global state.
- Keep user-facing CLI output consistent with the existing Chanakya interface.
- Do not hard-code API keys, passwords, tokens, or private credentials.

Before submitting a PR, review the changed files for accidental debug code, local paths, secrets, generated reports, and temporary files.

---

## 🧪 Testing

Before opening a pull request:

1. Run the application locally.
2. Verify the functionality you changed.
3. Test expected error conditions where practical.
4. Ensure existing functionality has not been unnecessarily broken.
5. Check that no secrets or local environment files are included.

If you add a new scanner or significant feature, include appropriate tests whenever practical.

**Do not commit:**

```text
.env
venv/
.venv/
__pycache__/
*.pyc
reports/
scanner.log
local configuration files
API keys
credentials
tokens
```

Use the repository's existing `.gitignore` rules and update them when a new generated/local artifact needs to be excluded.

---

## 🐞 Issue Reporting

Before opening an issue, search existing issues to determine whether the problem has already been reported.

If it has not been reported, open a new issue with:

- A clear and descriptive title
- A concise description of the problem
- Steps to reproduce
- Expected behavior
- Actual behavior
- Relevant error messages or logs
- Operating system
- Python version
- Chanakya version/commit, if available
- Screenshots or sanitized output where useful

Do **not** include:

- API keys
- Passwords
- Authentication tokens
- Private URLs containing credentials
- Personal information
- Sensitive customer or production data

Use sanitized examples instead.

---

## 🔐 Security Vulnerability Reporting

If you discover a security vulnerability **in Chanakya itself**, please do not publicly disclose the vulnerability before it has been reviewed.

Report security issues privately to:

**hrisikesh@justhackit.in**

Please include:

- A clear description of the vulnerability
- Affected component/file
- Steps to reproduce
- Security impact
- Proof of concept, where appropriate
- Suggested remediation, if available

Please do not include real credentials, private customer information, or sensitive production data in the report.

---

## ✅ Pull Request Process

### 1. Fork and Branch

Create a branch from the current `main` branch:

```bash
git checkout main
git pull origin main
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes

Implement the feature or fix while following the development and security guidelines above.

### 3. Review Your Changes

Check your working tree:

```bash
git status
```

Review the diff:

```bash
git diff
```

Make sure local files and secrets are not included.

### 4. Commit

Use a clear commit message:

```bash
git add .
git commit -m "feat: add example scanner"
```

Prefer concise, meaningful commit messages that describe the change.

### 5. Push

```bash
git push origin feature/your-feature-name
```

### 6. Open a Pull Request

Open a pull request against the `main` branch.

Your PR should explain:

- What was changed
- Why the change was needed
- How it was tested
- Any limitations or known issues
- Related issue numbers, if applicable

For example:

```text
Closes #12
```

### 7. Review

Pull requests may be reviewed for:

- Functionality
- Code quality
- Security implications
- False-positive/false-negative behavior
- Documentation
- Compatibility
- Maintainability

Changes may be requested before a PR is merged.

---

## 📝 Commit Message Suggestions

Use concise prefixes where appropriate:

```text
feat: add new scanner
fix: correct XSS detection logic
refactor: improve scanner discovery
docs: update installation instructions
test: add scanner validation tests
chore: update dependencies
security: harden request handling
```

These are recommendations rather than strict requirements unless the repository's contribution workflow specifies otherwise.

---

## 📜 Code of Conduct

By participating in the Chanakya community, you agree to follow the project's [**Code of Conduct**](CODE_OF_CONDUCT.md).

We expect all contributors to communicate professionally and respectfully.

---

## 📄 License

By contributing to Chanakya, you agree that your contributions will be licensed under the same license as the project.

Chanakya is distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 🌐 JustHackIT

Chanakya is developed under the **JustHackIT** cybersecurity brand.

- 🌐 Website: https://justhackit.in
- 📸 Instagram: https://www.instagram.com/justhackit.in/
- 𝕏 X: https://x.com/JustHackIT_HQ

---

## 🙌 Thank You

Every contribution matters — whether it is a bug fix, a scanner improvement, documentation update, test, refactor, or a new idea.

Thank you for helping improve **Chanakya** and the wider **JustHackIT** ecosystem.

**Made with ♥ by Hrisikesh (VirusZzWarning)**

> ⚔️ *Think strategically. Test responsibly. Stay one step ahead.*
