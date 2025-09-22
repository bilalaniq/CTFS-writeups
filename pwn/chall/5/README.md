# Exploit Examples for ASLR based and NON-ASLR based Binaries

This repository contains exploit scripts and vulnerable binaries categorized by ASLR configuration.

- The [`aslr_disabled/`](./ASLR_disabled/) directory includes exploits and binaries with ASLR disabled environments.
- The [aslr_enabled/`](./ASLR_enabled/) directory includes exploits and binaries with ASLR-enabled environments.


Each folder has its own `exploit.py` and vulnerable binary.

👉 Navigate to the appropriate folder based on whether ASLR is enabled or disabled, and then choose the exploit according to the architecture you're targeting.


The source code of the file is:
```c
#include <stdio.h>

void vuln() {
    char buffer[300];
    
    while(1) {
        fgets(buffer, sizeof(buffer), stdin);

        printf(buffer);
        puts("");
    }
}

int main() {
    vuln();

    return 0;
}
```
