# 🕸️ Web Exploitation

This repository contains a focused collection of **Web Exploitation** challenges. Each challenge lives in its own folder and includes the vulnerable web app (or a minimal reproduction), exploit scripts, write-ups or notes, and any necessary tooling or test data.

---

## 📁 Folders Overview

| Folder             | Description                                 |
| ------------------ | ------------------------------------------- |
| 👉 [1](./chall/1/) | 🔗 [ – picoCTF]() · Difficulty: **🟢 Easy** |

---

## Notes

- Each web challenge is isolated in its own folder with relevant architecture, protections, and analysis notes.
- Protections like CSP, WAF rules, input validation/escaping, and framework-level sanitization are explicitly mentioned in the challenge notes.
- Difficulty levels for web challenges:

  - **🟢 Easy** – single vulnerability, low to no filtering, minimal setup (e.g., basic XSS, simple SQLi)
  - **🔵 Medium** – requires chaining or bypassing protections (e.g., stored XSS + CSP bypass, blind SQLi extraction)
  - **🔴 Hard** – multi-stage exploitation with anti-automation/waf, advanced bypasses, logic abuse across endpoints

---
