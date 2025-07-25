// gcc source.c -o vuln-32 -fno-stack-protector -z noexecstack -m32
// gcc source.c -o vuln-64 -fno-stack-protector -z noexecstack

#include <stdio.h>
#include <stdlib.h>

void vuln() {
    char buffer[20];

    printf("System is at: %lp\n", system);

    gets(buffer);
}

int main() {
    vuln();

    return 0;
}