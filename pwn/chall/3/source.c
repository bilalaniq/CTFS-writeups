//gcc source.c -o vuln-32 -no-pie -fstack-protector -m32
//gcc source.c -o vuln-64 -no-pie -fstack-protector


#include <stdio.h>

void vuln() {
    char buffer[64];

    puts("Leak me");
    gets(buffer);

    printf(buffer);
    puts("");

    puts("Overflow me");
    gets(buffer);
}

int main() {
    vuln();
}

void win() {
    puts("You won!");
}