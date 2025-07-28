# Exploit: Function Pointer Hijack via Leaked Address (PIE TIME PICOCTF)

This exploit targets a vulnerable binary (`vuln`) that allows the user to provide an arbitrary address to jump to via a function pointer. The binary leaks the address of `main()`, which is used to calculate the base address of the ELF due to PIE (Position Independent Executable) being enabled.

## 🔧 Exploit Strategy

1. **Leak Address of `main()`**  
   The binary prints the address of `main()` at runtime. We parse this to determine the actual base address of the binary in memory.

2. **Calculate Base Address**  
   Since PIE is enabled, function addresses are relative. We subtract the offset of `main` to get the base address.

3. **Resolve Address of `win()`**  
   Once we know the base, we compute the absolute address of `win()` using `elf.symbols['win']`.

4. **Send Payload**  
   The binary uses `scanf("%lx", &val)` to read an address, so we send the calculated address of `win()` as a hex string with `0x` prefix.

5. **Hijack the Control Flow**  
   The binary uses a function pointer to jump to the user-provided address. If correct, it jumps to `win()` and prints the flag.

---

## 🧠 Prerequisites

- Python 3
- [`pwntools`](https://docs.pwntools.com/en/stable/) (`pip install pwntools`)
- Local copy of the target binary (`./vuln`)
- For remote: Access to the CTF challenge server

---

## 🚀 Usage

### 🔍 Local Debug Mode

Make sure `LOCAL = True` in the script to test against your local binary.

```bash
python3 exploit.py
````

### 🌐 Remote Mode (CTF server)

Set `LOCAL = False` to run against the remote server:

```python
LOCAL = False
```

Then run:

```bash
python3 exploit.py
```

---

## 🧪 Sample Output

```
[*] Leaked address of main(): 0x7ffaeaad933d
[+] ELF base: 0x7ffaeaad8000
[+] Sending address of win(): 0x7ffaeaad816a
[*] Program output:
Enter the address to jump to, ex => 0x12345:
Your input: 0x7ffaeaad816a
You won!
picoCTF{...}
```

---

## 📂 Files

* `exploit.py` — the exploit script
* `vuln` — the vulnerable binary (not included here)
* `flag.txt` — file read by `win()` if exploited correctly

---

## 🔐 Binary Protections

Checked using `checksec`:

```
[*] '/path/to/vuln'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

We bypass PIE using the leaked address of `main()`.

---



