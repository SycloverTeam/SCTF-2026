#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
  int fd = open("/flag", O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "open /flag failed: %s\n", strerror(errno));
    return 1;
  }

  char buf[4096];
  for (;;) {
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) {
      fprintf(stderr, "read /flag failed: %s\n", strerror(errno));
      close(fd);
      return 1;
    }
    if (n == 0) {
      break;
    }
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = write(STDOUT_FILENO, buf + off, (size_t)(n - off));
      if (w < 0) {
        fprintf(stderr, "write stdout failed: %s\n", strerror(errno));
        close(fd);
        return 1;
      }
      off += w;
    }
  }

  close(fd);
  return 0;
}
