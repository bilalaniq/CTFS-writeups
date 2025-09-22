// gcc source.c -o vuln -no-pie
#include <stdio.h>

void winner(int a, int b) {
    if(a == 0xdeadbeef && b == 0xdeadc0de) {
        puts("Great job!");
        return;
    }
    puts("Whelp, almost...?");
}

void vuln() {
    char buffer[0x60];
    printf("Try pivoting to: %p\n", buffer);
    fgets(buffer, 0x80, stdin);
}

int main() {
    vuln();    return 0;
}
