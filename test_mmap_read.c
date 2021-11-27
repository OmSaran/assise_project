#include <sys/mman.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <mlfs/mlfs_interface.h>

int main() {
    init_fs();
    int fd;
    void* addr;

    fd = open("/mlfs/foo", O_RDWR, 0644);
    printf("The fd is %d\n", fd);

    addr = mmap(NULL, 6, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
    // assert(addr != MAP_FAILED);
    if((long)addr < 0) {
        printf("Mmap error\n");
        perror("mmap error");
    }
    printf("Mmap addr is %ld\n", (long)addr);
    printf("Read the following %s\n", (char *)addr);

    close(fd);
    shutdown_fs();
}
