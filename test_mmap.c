#include <sys/mman.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

int main() {
    int fd;
    void* addr;

    fd = open("/dev/dax0.0", O_RDWR, 0644);
    printf("The fd is %d\n", fd);
    printf("The page size is %d\n", getpagesize());

    addr = mmap(NULL, (2 << 20), PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
    // assert(addr != MAP_FAILED);
    if((long)addr < 0) {
        printf("Mmap error\n");
        perror("mmap error");
    }
    printf("The addr is %ld\n", (long)addr);

    close(fd);
}
