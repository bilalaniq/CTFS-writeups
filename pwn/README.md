# 🛠️ Binary Exploitation Challenges

This repository contains a collection of binary exploitation challenges.  
Each folder includes binaries, exploit scripts, and notes related to various security concepts and protection bypass techniques.

---

## 📁 Folders Overview

| Folder      | Description                                                                                                                                                                    |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 👉 [1](./1/) | `64-bit` · `format string` · `buffer overflow` · `NX: Enabled` · `PIE: Enabled` · Difficulty: `Medium`                                                                         |
| 👉 [2](./2/) | `64-bit`, `32-bit` · `buffer overflow` · `NX: Enabled` · `ASLR: Enabled` · `system("/bin/sh")` · `libc leak` · `libc base calc` · Difficulty: `Medium`                         |
| 👉 [3](./3/) | `32-bit` · `format string` · `stack canary` · `canary leak` · `buffer overflow` · `NX: Enabled` · `ASLR: Enabled` · `ret2win` · Difficulty: `Medium`                           |
| 👉 [4](./4/) | `64-bit`, `32-bit` · `buffer overflow` · `NX: Enabled` · `ASLR: Enabled` · `ret2plt` · `libc leak` · `GOT usage` · Difficulty: `Medium`                                        |
| 👉 [5](./5/) | `32-bit` · `format string` · `NX: Enabled` · `ASLR: Enabled & Disabled` · `libc leak` · `ret2plt` · `GOT usage` · Difficulty: `Medium`                                         |
| 👉 [6](./6/) | 🔗 [PIE_TIME_1–picoCTF](https://play.picoctf.org/practice/challenge/490?category=6&page=1) · `64-bit` · `NX: Enabled` · `PIE: Enabled` · `Stack Canary` · Difficulty: `Easy`    |
| 👉 [6](./6/) | 🔗 [PIE_TIME_2–picoCTF](https://play.picoctf.org/practice/challenge/491?category=6&page=1) . `64-bit` . `NX: Enabled` . `PIE: Enabled` · `Stack Canary` .  Difficulty: `Medium` |

---

## Notes

- Each challenge is isolated in its own folder with relevant architecture, protections, and exploit logic.
- Protections like NX, PIE, ASLR, and stack canaries are explicitly mentioned.
- Difficulty levels (`Easy`, `Medium` , `Hard`) are based on the complexity of the exploit steps.

