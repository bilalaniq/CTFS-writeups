# 🛠️ Binary Exploitation Challenges

This repository contains a collection of binary exploitation challenges.  
Each folder includes binaries, exploit scripts, and notes related to various security concepts and protection bypass techniques.

---

## 📁 Folders Overview

| Folder        | Description                                                                                                                                                                                                                                                    |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 👉 [1](./1/)   | `64-bit` · `format string` · `buffer overflow` · `NX: Enabled` · `PIE: Enabled` · Difficulty: **🔵 Medium**                                                                                                                                                     |
| 👉 [2](./2/)   | `64-bit`, `32-bit` · `buffer overflow` · `NX: Enabled` · `ASLR: Enabled` · `system("/bin/sh")` · `libc leak` · `libc base calc` · Difficulty: **🔵 Medium**                                                                                                     |
| 👉 [3](./3/)   | `32-bit` · `format string` · `stack canary` · `canary leak` · `buffer overflow` · `NX: Enabled` · `ASLR: Enabled` · `ret2win` · Difficulty: **🔵 Medium**                                                                                                       |
| 👉 [4](./4/)   | `64-bit`, `32-bit` · `buffer overflow` · `NX: Enabled` · `ASLR: Enabled` · `ret2plt` · `libc leak` · `GOT usage` · Difficulty: **🔵 Medium**                                                                                                                    |
| 👉 [5](./5/)   | `32-bit` · `format string` · `NX: Enabled` · `ASLR: Enabled & Disabled` · `libc leak` · `ret2plt` · `GOT usage` · Difficulty: **🔵 Medium**                                                                                                                     |
| 👉 [6](./6/)   | 🔗 [PIE_TIME_1–picoCTF](https://play.picoctf.org/practice/challenge/490?category=6&page=1) · `64-bit` · `NX: Enabled` · `PIE: Enabled` · `Stack Canary` · Difficulty: **🟢 Easy**                                                                                |
| 👉 [7](./7/)   | 🔗 [PIE_TIME_2–picoCTF](https://play.picoctf.org/practice/challenge/491?category=6&page=1) · `64-bit` · `NX: Enabled` · `PIE: Enabled` · `Stack Canary` · Difficulty: **🔵 Medium**                                                                              |
| 👉 [8](./8/)   | 🔗 [format_string_0–picoCTF](https://play.picoctf.org/practice/challenge/433?category=6&page=1) · `64-bit` · `format string` · Difficulty: **🟢 Easy**                                                                                                           |
| 👉 [9](./9/)   | 🔗 [buffer_overflow_1–picoCTF](https://play.picoctf.org/practice/challenge/258?category=6&page=3) · `32-bit` · `buffer overflow` · `NX: Enabled` · `ROP` · Difficulty: **🟢 Easy**                                                                               |
| 👉 [10](./10/) | 🔗 [format_string_3–picoCTF](https://play.picoctf.org/practice/challenge/449?category=6&page=1) · `64-bit` · `format string` · `libc leak` · `GOT usage` · `GOT overwrite` · `system("/bin/sh")` · `PIE: Disabled` · `ASLR: Enabled` · Difficulty: **🔵 Medium** |
| 👉 [11](./11/) | 🔗 [Local_Target–picoCTF](https://play.picoctf.org/practice/challenge/399?category=6&page=2) ·  `64-bit` .  `buffer overflow` .   `Smash the stack` . · Difficulty: **🟢 Easy**                                                                                  |


---

## Notes

- Each challenge is isolated in its own folder with relevant architecture, protections, and exploit logic.
- Protections like NX, PIE, ASLR, and stack canaries are explicitly mentioned.
- Difficulty levels:
  - **🟢 Easy** – Basic exploitation with minimal setup
  - **🔵 Medium** – Requires libc leaks, GOT/PLT abuse, or bypassing ASLR/Canary
  - **🔴 Hard** – Advanced mitigations or complex logic to exploit
