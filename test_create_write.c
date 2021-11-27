#include <sys/mman.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#define FILEPATH "/mlfs/foo"
// #define SIZE (4 << 10)
#define SIZE 6

int main() {
    int fd;
    int ret;
    int i;
    void* addr;
    char buf[SIZE];

    for(i=0; i<SIZE; i++) {
        buf[i] = 'a';
    }
    buf[SIZE-1] = '\0';

    fd = open(FILEPATH, O_CREAT | O_RDWR, 0644);
    printf("The fd is %d\n", fd);

    ret = ftruncate(fd, 0);
    assert(ret == 0);

    ret = write(fd, buf, SIZE);
    assert(ret == SIZE);

    close(fd);
}
