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

