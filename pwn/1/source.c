#include <stdio.h>

void vuln() {
    char buffer[20];

    printf("What's your name?\n");
    gets(buffer);
    
    printf("Nice to meet you ");
    printf(buffer);
    printf("\n");

    puts("What's your message?");

    gets(buffer);
}

int main() {
    vuln();

    return 0;
}

void win() {
    puts("PIE bypassed! Great job :D");
}