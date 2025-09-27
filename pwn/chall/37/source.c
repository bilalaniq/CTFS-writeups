#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
 
/*
gcc -o chall source.c -fno-stack-protector -no-pie -Wl,-z,relro,-z,now,-z,noexecstack
*/
 
void callMeMaybe(){
    char *argv[] = { "/bin/bash", "-p", NULL };
    execve(argv[0], argv, NULL);
}
 
int main(int argc, char **argv){
 
    char buffer[256];
    int len, i;
 
    scanf("%s", buffer);
    len = strlen(buffer);
 
    printf("Hello %s\n", buffer);
 
    return 0;
}