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