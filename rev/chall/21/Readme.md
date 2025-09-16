# **Bit-O-Asm-4**

## Description:

> Can you figure out what is in the eax register? Put your answer in the picoCTF flag format: picoCTF{n} where n is the contents of the eax register in the decimal number base. If the answer was 0x11 your flag would be picoCTF{17}.

We are given a small assembly snippet corresponding to `main`:

```
<+0>:     endbr64 
<+4>:     push   rbp
<+5>:     mov    rbp,rsp
<+8>:     mov    DWORD PTR [rbp-0x14],edi
<+11>:    mov    QWORD PTR [rbp-0x20],rsi
<+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a
<+22>:    cmp    DWORD PTR [rbp-0x4],0x2710
<+29>:    jle    0x55555555514e <main+37>
<+31>:    sub    DWORD PTR [rbp-0x4],0x65
<+35>:    jmp    0x555555555152 <main+41>
<+37>:    add    DWORD PTR [rbp-0x4],0x65
<+41>:    mov    eax,DWORD PTR [rbp-0x4]
<+44>:    pop    rbp
<+45>:    ret
```

---

### **Step-by-Step Analysis**

1. **Stack Setup:**

```asm
<+4>: push rbp
<+5>: mov rbp, rsp
```

* Standard function prologue. Establishes a new stack frame.

2. **Move Constants & Arguments:**

```asm
<+15>: mov DWORD PTR [rbp-0x4],0x9fe1a
```

* A local variable at `[rbp-0x4]` is set to `0x9fe1a` (hex).
* Decimal: `0x9fe1a = 654810`.

3. **Comparison and Conditional Jump:**

```asm
<+22>: cmp DWORD PTR [rbp-0x4],0x2710
<+29>: jle <main+37>
```

* Compares `[rbp-0x4]` with `0x2710` (decimal `10000`).
* `JLE` = Jump if Less or Equal (signed comparison).
* Since `654810 > 10000`, **JLE does not take the jump**. Execution continues to:

```asm
<+31>: sub DWORD PTR [rbp-0x4],0x65
```

* Subtracts `0x65` (decimal `101`) from `[rbp-0x4]`.
* `654810 - 101 = 654709`.

```asm
<+35>: jmp <main+41>
```

* Jumps over the next block.

4. **Skipped Block:**

```asm
<+37>: add DWORD PTR [rbp-0x4],0x65
```

* This would have been executed **if JLE was taken**, but it’s skipped.

5. **Move Result to EAX:**

```asm
<+41>: mov eax,DWORD PTR [rbp-0x4]
```

* The local variable `[rbp-0x4]` (currently `654709`) is moved into `eax`.

---

### **Conclusion**

* The final value in `EAX` is **654709** (decimal).
* Therefore, the flag in the picoCTF format is:

```
picoCTF{654709}
```

