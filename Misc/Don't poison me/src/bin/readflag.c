#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    char buf[256];
    ssize_t n;
    int fd;

    setgid(0);
    setuid(0);

    fd = open("/flag", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (write(STDOUT_FILENO, buf, (size_t)n) != n) {
            close(fd);
            return 1;
        }
    }

    close(fd);
    return n < 0 ? 1 : 0;
}
