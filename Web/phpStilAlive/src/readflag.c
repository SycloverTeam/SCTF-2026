#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define FLAG_PATH "/lfag-9f1d7c2e-6a2c-4e54-9d7e-6cb10c4b8f9a"

int main(void)
{
    char buf[256];
    ssize_t n;
    int fd;

    setvbuf(stdout, NULL, _IONBF, 0);

    fd = open(FLAG_PATH, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        puts("flag is not ready");
        return 1;
    }

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t written = write(STDOUT_FILENO, buf + off, (size_t)(n - off));
            if (written < 0) {
                close(fd);
                return 1;
            }
            off += written;
        }
    }

    if (n < 0) {
        fprintf(stderr, "read failed: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
