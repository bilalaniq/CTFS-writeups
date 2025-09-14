# 🛠️ Binary Exploitation Challenges

This repository contains a collection of reverse engineering and binary exploitation challenges.  
Each folder includes binaries, exploit scripts, and notes related to various security concepts and protection bypass techniques.

---

## 📁 Folders Overview

| Folder            | Description                                                                                                                                                                                                                                                                                                                                   |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 👉 [1](./chall/1/) | 🔗 [Flag-Hunters – picoCTF](https://play.picoctf.org/practice/challenge/472?bookmarked=0&category=3&page=1&solved=0) · Python · Logic · Difficulty: **🟢 Easy**                                                                                                                                                                                 |
| 👉 [2](./chall/2/) | 🔗 [Transformation – picoCTF](https://play.picoctf.org/practice/challenge/104?bookmarked=0&category=3&page=1&solved=0) · Unicode · Encoding · Difficulty: **🟢 Easy**                                                                                                                                                                           |
| 👉 [3](./chall/3/) | 🔗 [Vault-Door-Training – picoCTF](https://play.picoctf.org/practice/challenge/7?bookmarked=0&category=3&page=1&solved=0) · Beginner · Hardcoded Password · Difficulty: **🟢 Easy**                                                                                                                                                             |
| 👉 [4](./chall/4/) | 🔗 [WinAntiDbg0x100 – picoCTF](https://play.picoctf.org/practice/challenge/429?bookmarked=0&category=3&page=1&solved=0) · x86 · [x32dbg](https://x64dbg.com/) · Patching · Anti-Debugging · Difficulty: **🔵 Medium**                                                                                                                           |
| 👉 [5](./chall/5/) | 🔗 [WinAntiDbg0x200 – picoCTF](https://play.picoctf.org/practice/challenge/430?bookmarked=0&category=3&page=1&solved=0) · x86 · [x32dbg](https://x64dbg.com/) · [Ghidra](https://ghidralite.com/) · Patching · Anti-Debugging · Difficulty: **🔵 Medium**                                                                                       |
| 👉 [6](./chall/6/) | 🔗 [WinAntiDbg0x300 – picoCTF](https://play.picoctf.org/practice/challenge/431?bookmarked=0&category=3&page=1&solved=0) · GUI · [Ghidra](https://ghidralite.com/) · [UPX](https://github.com/upx/upx) · [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview) · Patching · Anti-Debugging · Difficulty: **🔵 Medium** |

---

## Notes

- Each challenge is isolated in its own folder with relevant architecture, protections, and exploit logic.
- Protections like NX, PIE, ASLR, and stack canaries are explicitly mentioned.
- Difficulty levels:
  - **🟢 Easy** – Basic exploitation with minimal setup  
  - **🔵 Medium** – Requires libc leaks, GOT/PLT abuse, or bypassing ASLR/Canary  
  - **🔴 Hard** – Advanced mitigations or complex logic to exploit
