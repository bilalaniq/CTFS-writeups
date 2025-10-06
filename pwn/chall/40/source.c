// gcc -o chall source.c -no-pie -fno-stack-protector -z execstack -z norelro -Wl,-z,noseparate-code -static

#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#define PASSWORD ".passwd"
#define TMP_FILE "tmp_file.txt"

int main(void)
{
  int fd_tmp, fd_rd;
  char ch;

  if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) // The Debugger Becomes the Parent Process when used so PTRACE_TRACEME essentially asks: "Is my parent process a debugger that's already tracing me?"
  {
    printf("[-] Don't use a debugguer !\n");
    abort();
  }
  if ((fd_tmp = open(TMP_FILE, O_WRONLY | O_CREAT, 0444)) == -1) // No write permissions for anyone! But make it read-only for everyone
  {
    perror("[-] Can't create tmp file ");
    goto end;
  }

  if ((fd_rd = open(PASSWORD, O_RDONLY)) == -1)
  {
    perror("[-] Can't open file ");
    +goto end;
  }

  while (read(fd_rd, &ch, 1) == 1) // This 1 means: "Read exactly 1 byte at a time"
  {
    write(fd_tmp, &ch, 1); // This 1 means: "write exactly 1 byte at a time"
  }
  close(fd_rd);
  close(fd_tmp);
  usleep(250000);
end:
  unlink(TMP_FILE); // Deletes tmp_file.txt

  return 0;
}
