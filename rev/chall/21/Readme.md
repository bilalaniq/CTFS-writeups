# **Bit-O-Asm-1** 

## Description:

We are asked to determine the value in the `EAX` register at the end of `main`. The flag format is:

```
picoCTF{n}
```

where `n` is the decimal value of `EAX`.

---

## **Given Assembly Snippet:**

```asm
<+0>:     endbr64 
<+4>:     push   rbp
<+5>:     mov    rbp,rsp
<+8>:     mov    DWORD PTR [rbp-0x4],edi
<+11>:    mov    QWORD PTR [rbp-0x10],rsi
<+15>:    mov    eax,0x30
<+20>:    pop    rbp
<+21>:    ret
```

---

## **Step-by-Step Analysis:**

1. **Function Prologue:**

```asm
<+4>: push rbp
<+5>: mov rbp,rsp
```

* Standard function prologue. Establishes a new stack frame.

2. **Storing Arguments (Not Affecting EAX):**

```asm
<+8>: mov DWORD PTR [rbp-0x4], edi
<+11>: mov QWORD PTR [rbp-0x10], rsi
```

* Saves the function arguments into local variables.
* `edi` and `rsi` are general-purpose registers for function arguments.
* This does **not** affect `EAX`.

3. **Set `EAX`:**

```asm
<+15>: mov eax,0x30
```

* The value `0x30` (hexadecimal) is moved into `EAX`.
* Decimal equivalent: `0x30 = 48`.

4. **Function Epilogue:**

```asm
<+20>: pop rbp
<+21>: ret
```

* Standard epilogue. Function returns with `EAX = 48`.

---

## **Conclusion:**

* The final value in `EAX` is **48** (decimal).
* Therefore, the flag is:

```
picoCTF{48}
```

