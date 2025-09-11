## **vault-door-training** 


The challenge provides a Java program:

* It prompts the user for a vault password.
* It takes the input, strips the `picoCTF{}` wrapper, and passes it to the `checkPassword` function.
* The `checkPassword` function **contains the password in plaintext**:

```java
return password.equals("w4rm1ng_Up_w1tH_jAv4_3808d338b46");
```

* Goal: Determine the correct flag to gain “Access granted.”

---

### **Analysis**

1. The program **does not obscure the password**; it’s hardcoded in the source code.
2. The code removes the `picoCTF{}` part from the user input, so the flag is:

```
picoCTF{w4rm1ng_Up_w1tH_jAv4_3808d338b46}
```

3. There is no encryption, hash, or obfuscation. This is a **classic “read the source” challenge**.

---

### **Solution**

* Read the Java source code.
* Locate the hardcoded password in `checkPassword()`:

```java
"w4rm1ng_Up_w1tH_jAv4_3808d338b46"
```

* Wrap it in the `picoCTF{}` format for the flag:

```
picoCTF{w4rm1ng_Up_w1tH_jAv4_3808d338b46}
```

* Submitting this string will yield:

```
Access granted.
```


### **Tags**

```
Java, Source Code Analysis, Hardcoded Password, Beginner, CTF
```

---

✅ **Flag:**

```
picoCTF{w4rm1ng_Up_w1tH_jAv4_3808d338b46}
```

