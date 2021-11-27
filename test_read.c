#include <sys/mman.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#include <mlfs/mlfs_interface.h>

int main() {
    init_fs();
    int fd;
    int ret;
    void* addr;
    char buf[64];

    fd = open("/mlfs/foo", O_RDONLY, 0644);
    printf("The fd is %d\n", fd);

    ret = read(fd, buf, 6);
    assert(ret == 6);

    printf("Read the following %s\n", buf);
    close(fd);
    shutdown_fs();
}
