#include <sys/mman.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <mlfs/mlfs_interface.h>

#define SIZE 4096
#define FILEPATH "/mlfs/foo"
#define AUX_FILEPATH "/mlfs/aux"

void create_actual_file(char buf[]) {
    int ret;
    int fd;
    char temp;

    fd = open(FILEPATH, O_CREAT | O_RDWR | O_EXCL, 0644);
    assert(fd >= 0);
    printf("The fd is %d\n", fd);

    ret = ftruncate(fd, 0);
    assert(ret == 0);

    temp = buf[SIZE-1];
    buf[SIZE-1] = 'a';
    ret = write(fd, buf, SIZE);
    assert(ret == SIZE);
    buf[SIZE-1] = temp;

    close(fd);

    make_digest_request_async(100);
    wait_on_digesting();
}

void create_aux_file(char buf[]) {
    int ret;
    int fd;

    fd = open(AUX_FILEPATH, O_CREAT | O_RDWR | O_EXCL, 0644);
    assert(fd >= 0);
    printf("The fd is %d\n", fd);

    ret = write(fd, buf, SIZE);
    assert(ret == SIZE);

    close(fd);
    make_digest_request_async(100);
    wait_on_digesting();
}

void write_actual_file(char buf[]) {
    int ret;
    int fd;

    fd = open(FILEPATH, O_RDWR, 0644);
    assert(fd >= 0);
    printf("The fd is %d\n", fd);

    ret = pwrite(fd, buf, SIZE, SIZE);
    assert(ret == SIZE);

    close(fd);

    make_digest_request_async(100);
    wait_on_digesting();
}


int main() {
    init_fs();

    int fd, fd2;
    int ret;
    int i;
    void* addr;
    char buf[SIZE];

    for(i=0; i<SIZE; i++) {
        buf[i] = 'a';
    }
    buf[SIZE-1] = '\0';

    create_actual_file(buf);
    create_aux_file(buf);
    write_actual_file(buf);

    shutdown_fs();
}
