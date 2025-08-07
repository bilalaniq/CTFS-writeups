// gcc -m32 -fno-stack-protector -no-pie -o vuln source.c

#include <unistd.h>
void vuln(void){
    char buf[64];
    read(STDIN_FILENO, buf, 200);
}
int main(int argc, char** argv){
    vuln();
}