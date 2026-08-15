# 🔐 Chanakya Security Policy

**Chanakya** is an open-source offensive security reconnaissance and vulnerability assessment tool developed under the **JustHackIT** brand.

This document explains which Chanakya versions currently receive security attention and how to responsibly report vulnerabilities discovered in the project.

> **Current release:** v3.1.6  
> **Project:** Chanakya  
> **Maintainer:** Hrisikesh (VirusZzWarning) / JustHackIT

---

## 📌 Supported Versions

Security fixes and maintenance are focused on the latest stable release.

| Version | Support Status |
|---|---|
| **3.1.6** | ✅ Supported — Latest |
| **3.1.5 and earlier** | ⚠️ Legacy — Upgrade recommended |

Users are strongly encouraged to keep Chanakya updated to the latest stable release.

Security support for older versions may be limited or unavailable, particularly when a vulnerability has already been fixed in a newer release.

> **Note:** Version support may change as new releases are published.

---

## 📢 Reporting a Vulnerability

If you discover a security vulnerability or security-related flaw in Chanakya, please report it responsibly.

### 📬 Private Security Report

Send security reports to:

**📧 hrisikesh@justhackit.in**

For potentially sensitive vulnerabilities, **do not create a public GitHub Issue or Pull Request**. Private disclosure allows the issue to be investigated and addressed before technical details become publicly available.

GitHub recommends maintaining a `SECURITY.md` policy to provide clear instructions for reporting vulnerabilities, and public repositories can also use GitHub Security Advisories for private vulnerability coordination. citeturn0search0turn0search6

---

## 📝 What to Include

Please provide as much useful information as possible:

- A clear description of the vulnerability
- Affected version(s)
- Affected file, module, or component
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Security impact
- Proof of concept, where appropriate
- Relevant logs or screenshots
- Suggested remediation, if known

A good report should allow the maintainer to reproduce and understand the issue without unnecessary back-and-forth.

---

## 🔒 Sensitive Information

Please **do not** include the following in a public issue, pull request, or other public communication:

- API keys
- Passwords
- Authentication tokens
- Private keys
- Personal information
- Production credentials
- Private customer data
- Unredacted security logs containing sensitive information

If such information is required to reproduce the issue, provide it privately and only when necessary.

---

## 🕵️ Responsible Disclosure

We request that security researchers:

1. Report the vulnerability privately.
2. Provide enough information to reproduce and validate the issue.
3. Allow reasonable time for investigation and remediation.
4. Avoid publicly disclosing exploit details before coordinated disclosure.
5. Avoid accessing, modifying, deleting, or exfiltrating data that does not belong to you.
6. Test Chanakya only in environments you own or are explicitly authorized to assess.

We will make a reasonable effort to investigate legitimate reports and coordinate disclosure where appropriate.

---

## ⏱️ Response Expectations

We aim to handle security reports promptly.

The general process is:

1. **Acknowledgment** — The report is reviewed and acknowledged when received.
2. **Validation** — The issue is reproduced and its security impact assessed.
3. **Remediation** — A fix or mitigation is developed where appropriate.
4. **Release** — A patched release may be published when necessary.
5. **Disclosure** — Public disclosure may occur after remediation and coordination.

Response and remediation times may vary depending on severity, complexity, reproducibility, and maintainer availability.

---

## 🚨 Severity

Security issues may be evaluated based on factors such as:

- Exploitability
- Required privileges or user interaction
- Confidentiality impact
- Integrity impact
- Availability impact
- Scope of affected functionality
- Whether exploitation can affect users beyond the local execution environment

Not every bug constitutes a security vulnerability. Reports will be assessed on their actual security impact.

---

## 🛡️ Responsible Use of Chanakya

Chanakya is intended for:

- Security researchers
- Penetration testers
- Bug bounty hunters operating within program scope
- CTF participants
- Security students and educators
- Authorized security assessments
- Controlled security research environments

### ❌ Unauthorized Use

Do not use Chanakya to:

- Scan or attack systems without authorization
- Access accounts or data belonging to others
- Circumvent authorization controls
- Conduct destructive testing
- Disrupt third-party services
- Deploy malware or persistence
- Exfiltrate information
- Violate applicable laws, contracts, or terms of service

The responsibility for how Chanakya is used rests with the user.

---

## 🧪 Security Research on Chanakya

When testing Chanakya itself, use a controlled environment whenever possible.

Recommended practices include:

- Use isolated test targets.
- Use test credentials rather than real credentials.
- Avoid placing secrets in source code.
- Keep `.env` files outside version control.
- Review generated reports before sharing them.
- Sanitize logs before publishing them.
- Keep dependencies updated.
- Use the latest stable Chanakya release.

---

## 🔐 Repository Security Recommendations

Contributors and maintainers should take reasonable precautions to protect the repository and its users.

In particular:

- Never commit API keys, passwords, tokens, or private credentials.
- Keep local `.env` files out of Git.
- Review changes before pushing them.
- Keep dependencies reasonably up to date.
- Review security-sensitive scanner changes carefully.
- Use GitHub's available security features where appropriate.

GitHub recommends features such as dependency alerts, secret scanning, push protection, and code scanning to help protect repositories. citeturn0search1

---

## 📣 Public Issues

For ordinary bugs, feature requests, documentation problems, and non-sensitive issues, use the project's GitHub issue tracker.

For security vulnerabilities that could expose users, credentials, systems, or sensitive information, use:

**📧 hrisikesh@justhackit.in**

Do not publicly disclose sensitive vulnerability details before the issue has been investigated.

---

## 🌐 JustHackIT

Chanakya is part of the **JustHackIT** cybersecurity ecosystem.

- 🌐 Website: https://justhackit.in
- 📸 Instagram: https://www.instagram.com/justhackit.in/
- 𝕏 X: https://x.com/JustHackIT_HQ

---

## 📄 Related Project Documents

- [README](README.md)
- [CONTRIBUTING](CONTRIBUTING.md)
- [CODE OF CONDUCT](CODE_OF_CONDUCT.md)
- [LICENSE](LICENSE)

GitHub surfaces repository community-health documents such as security policies, contribution guidelines, and codes of conduct to help contributors understand project expectations. citeturn0search3turn0search5

---

## 🙏 Thank You

Thank you for helping keep **Chanakya**, its contributors, and its users secure.

Responsible security research and coordinated disclosure help improve the project for everyone.

**Made with ♥ by Hrisikesh (VirusZzWarning)**

> ⚔️ *Think strategically. Test responsibly. Stay one step ahead.*
