// Disposable inert child: holds one scratch flock until parent watchdog EOF.
// This never opens Aegis Store, H2, packet flow, routes, or credentials.
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int lock = open(argv[1], O_RDWR | O_NOFOLLOW);
    if (lock < 0 || flock(lock, LOCK_EX) != 0) return 3;
    int ready = open(argv[2], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (ready < 0 || write(ready, "ready", 5) != 5 || close(ready) != 0) return 4;
    char byte;
    while (read(3, &byte, 1) > 0) {}
    close(lock);
    return 0;
}
