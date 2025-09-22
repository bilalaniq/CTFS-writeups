# 🧩 Forensics

This repository contains a focused collection of **Forensics** challenges. Each challenge lives in its own folder and includes the forensic data (pcap, memory dump, disk image, registry hives, etc.), analysis scripts and commands, write-ups/notes, and any tooling or extraction artifacts needed to reproduce the solve.

---

## 📁 Folders Overview

| Folder             | Description                                 |
| ------------------ | ------------------------------------------- |
| 👉 [1](./chall/1/) | 🔗 [ – picoCTF]() · Difficulty: **🟢 Easy** |

---

## Notes

- Each forensics challenge is isolated in its own folder with relevant evidence types (pcap, memory dump, disk image, registry hives, etc.) and analysis notes.
- Evidence handling details like file checksums, timestamps, carving offsets, and any anti-forensic techniques or encryption are explicitly mentioned in the challenge notes.
- Difficulty levels for forensics challenges:

  - **🟢 Easy** – single artifact extraction or straightforward indicator (e.g., flag visible in `strings` output)
  - **🔵 Medium** – requires multi-step analysis (e.g., timelining, carving, protocol decoding, reconstruction)
  - **🔴 Hard** – large-scale or deep analysis (e.g., memory analysis + carved binary reverse engineering + timeline correlation)

---