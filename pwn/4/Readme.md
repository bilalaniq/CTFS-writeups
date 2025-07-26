# Exploit Examples for 32-bit and 64-bit Binaries

This repository contains exploit scripts and vulnerable binaries categorized by architecture.

- The [`32-bit/`](./32-bit/) directory includes exploits and binaries for 32-bit systems.
- The [`64-bit/`](./64-bit/) directory includes exploits and binaries for 64-bit systems.


Each folder has its own `exploit.py` and vulnerable binary (`vuln-32` or `vuln-64`).

👉 Navigate to the appropriate folder based on the architecture you want to test.


The source code of the file is:
```c
// gcc source.c -o vuln-32 -no-pie -fno-stack-protector -z execstack -m32
// gcc source.c -o vuln-64 -no-pie -fno-stack-protector -z execstack

#include <stdio.h>

void vuln() {
    puts("Come get me");

    char buffer[20];
    gets(buffer);
}

int main() {
    vuln();

    return 0;
}
```
