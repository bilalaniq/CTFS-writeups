# 🕸 Web Exploitation

This repository contains a focused collection of *Web Exploitation* challenges. Each challenge lives in its own folder and includes the vulnerable web app (or a minimal reproduction), exploit scripts, write-ups or notes, and any necessary tooling or test data.

---

## 📁 Folders Overview

| Folder            | Description                                                                                                                                                                                                                                                                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 👉 [1](./chall/1/) | 🔗 [SQLiLite – picoCTF](https://play.picoctf.org/practice/challenge/304?category=1&page=3) · SQL Injection · [burpsuite](https://www.kali.org/tools/burpsuite/) · Authentication Bypass · [curl](https://man7.org/linux/man-pages/man1/curl.1.html) · Difficulty: *🟢 Easy*                                                       |
| 👉 [2](./chall/2/) | 🔗 [SSTI1 – picoCTF](https://play.picoctf.org/practice/challenge/492?category=1&page=1) · [SSTI](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation) · [burpsuite](https://www.kali.org/tools/burpsuite/) · [curl](https://man7.org/linux/man-pages/man1/curl.1.html) · Difficulty: *🟢 Easy* |
| 👉 [3](./chall/3/) | 🔗 [Cookie-Monster-Secret-Recipe – picoCTF](https://play.picoctf.org/practice/challenge/469?category=1&page=1) · cookies · [burpsuite](https://www.kali.org/tools/burpsuite/) · [encoding.tools](https://encoding.tools/) · base64 · url-decoding · Difficulty: *🟢 Easy*                                                         |
| 👉 [4](./chall/4/) | 🔗 [WebDecode – picoCTF](https://play.picoctf.org/practice/challenge/427?category=1&page=1) · [encoding.tools](https://encoding.tools/) · base64 · Difficulty: *🟢 Easy*                                                                                                                                                          |
| 👉 [5](./chall/5/) | 🔗 [Unminify – picoCTF](https://play.picoctf.org/practice/challenge/426?category=1&page=1) · [Minification](<https://en.wikipedia.org/wiki/Minification_(programming)>) · [unminify](https://www.htmlstrip.com/unminify-html) · Difficulty: *🟢 Easy*                                                                             |
| 👉 [6](./chall/6/) | [rot13](https://rot13.com/) · Backdoor · Difficulty: *🟢 Easy*                                                                                                                                                                                                                                                                   |
| 👉 [7](./chall/7/) | [X-Forwarded-For](https://en.wikipedia.org/wiki/X-Forwarded-For) · `rate-limiting` · `ip-spoofing` · `brute-force` · Difficulty: *🔵 Medium*                                                                                                                                                                                     |
| 👉 [8](./chall/8/) | [.htaccess](https://httpd.apache.org/docs/current/howto/htaccess.html)· `php` · `apache` · `command-injection` ·`file-upload-bypass` · Difficulty: *🔵 Medium*                                                                                                                                                                   |
| 👉 [9](./chall/9/) | 🔗 [IntroToBurp – picoCTF](https://play.picoctf.org/practice/challenge/419?category=1&page=1) · `Burpsuit` · `secure-coding` · `logic-flaw` · Difficulty: *🟢 Easy*                                                                                                                                                               |

---

## Notes

- Each web challenge is isolated in its own folder with relevant architecture, protections, and analysis notes.
- Protections like CSP, WAF rules, input validation/escaping, and framework-level sanitization are explicitly mentioned in the challenge notes.
- Difficulty levels for web challenges:

  - *🟢 Easy* – single vulnerability, low to no filtering, minimal setup (e.g., basic XSS, simple SQLi)
  - *🔵 Medium* – requires chaining or bypassing protections (e.g., stored XSS + CSP bypass, blind SQLi extraction)
  - *🔴 Hard* – multi-stage exploitation with anti-automation/waf, advanced bypasses, logic abuse across endpoints

---