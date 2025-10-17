// gcc -g -o chal -z execstack -fno-stack-protector -z norelro -no-pie -fcf-protection=none source.c -std=gnu99
// sudo sysctl -w kernel.randomize_va_space=0
#include <stdio.h>

void dump_stack(void) {
    unsigned long *rsp = __builtin_frame_address(0) + 0x10;
    unsigned long *rbp = __builtin_frame_address(1);
    
    for (unsigned long *p = rsp; p != rbp + 2; p++) {
        printf("%p: %016lx ", p, *p);
        if (p == rsp) {
            printf("<- rsp\n");
        } else if (p == rbp) {
            printf("<- rbp\n");
        } else {
            putchar('\n');
        }
    }
}

int main(void) {
    char buf[0x20];

    dump_stack();

    printf("Input: ");
    gets(buf);
    printf("Output: ");
    printf(buf);
    putchar('\n');

    dump_stack();
    return 0;
}

__attribute__((constructor))
void init(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}