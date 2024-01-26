// Exploit is designed and tested for Ubuntu 18.04, kernel 4.19.35-arm64
// gcc -o cve-2021-42008 cve-2021-42008.c -s -lpthread
// sudo setcap cap_net_admin=eip cve-2021-42008
// docker run --cap-add NET_ADMIN --security-opt seccomp=unconfined --rm -it --name ubuntu-test ubuntu bash

#define _GNU_SOURCE


#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <time.h>


int main(int argc, char **argv)
{
    int ret = -1;
    int i = 0;
    struct timespec start, stop;

    printf("----- starting create char device file....... ret %d \n", ret);
    
    clock_gettime(CLOCK_REALTIME, &start);
    while(i < 20){
        i++;
        ret = mknod("charfile", S_IFCHR|0666, makedev(11,13));
    }
    clock_gettime(CLOCK_REALTIME, &stop);
    printf("start.tv_sec:%d, start.tv_nsec:%d\n", start.tv_sec, start.tv_nsec);
    printf("stop.tv_sec:%d, stop.tv_nsec:%d\n", start.tv_sec, start.tv_nsec);
    printf("----- created char device file!! i %d, ret %d\n", i, ret);
    
    return 0;
}

