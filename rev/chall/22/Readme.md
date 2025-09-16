# **Bit-O-Asm-2**

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
<+8>:     mov    DWORD PTR [rbp-0x14],edi
<+11>:    mov    QWORD PTR [rbp-0x20],rsi
<+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a
<+22>:    mov    eax,DWORD PTR [rbp-0x4]
<+25>:    pop    rbp
<+26>:    ret
```

---

## **Step-by-Step Analysis:**

1. **Function Prologue:**

```asm
<+4>: push rbp
<+5>: mov rbp,rsp
```

* Sets up the stack frame. Standard function prologue.

2. **Storing Function Arguments:**

```asm
<+8>: mov DWORD PTR [rbp-0x14], edi
<+11>: mov QWORD PTR [rbp-0x20], rsi
```

* Stores the first and second arguments to local variables.
* Does **not** affect `EAX`.

3. **Set Local Variable `[rbp-0x4]`:**

```asm
<+15>: mov DWORD PTR [rbp-0x4], 0x9fe1a
```

* The local variable at `[rbp-0x4]` is assigned the value `0x9fe1a` (hexadecimal).
* Decimal equivalent:

```
0x9fe1a = 654234
```

4. **Move Value to `EAX`:**

```asm
<+22>: mov eax, DWORD PTR [rbp-0x4]
```

* Loads the value of `[rbp-0x4]` (which is `0x9fe1a`) into `EAX`.
* So `EAX = 654234`.

5. **Function Epilogue:**

```asm
<+25>: pop rbp
<+26>: ret
```

* Standard epilogue. Function returns with `EAX = 654234`.

---

## **Conclusion:**

* The final value in `EAX` is **654234**.
* Therefore, the flag is:

```
picoCTF{654234}
```

