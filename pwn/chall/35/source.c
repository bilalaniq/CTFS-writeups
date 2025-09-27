// i686-w64-mingw32-gcc -m32 -o chall.exe source.c -fno-stack-protector -static-libgcc

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#define DEFAULT_LEN 16

void admin_shell(void)
{
        system("type flag.txt");
}

int main(void)
{
        char buff[DEFAULT_LEN] = {0};

        gets(buff);
        for (int i = 0; i < DEFAULT_LEN; i++)
        {
                buff[i] = toupper(buff[i]);
        }
        printf("%s\n", buff);
}
