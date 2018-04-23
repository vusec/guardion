
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "rowharm.h"

int rh_fd;

uint64_t get_overflows(void) {
    uint64_t overflows;
    int ret = ioctl(rh_fd, RH_IOC_GET_OVERFLOWS, &overflows);
    if (ret < 0) {
        perror("ioctl failed");
        return 0;
    }
    return overflows;
}
uint64_t get_delays(void) {
    uint64_t delays;
    int ret = ioctl(rh_fd, RH_IOC_GET_DELAYS, &delays);
    if (ret < 0) {
        perror("ioctl failed");
        return 0;
    }
    return delays;
}

void reset_overflows(void) {
    int ret = ioctl(rh_fd, RH_IOC_RST_OVERFLOWS, NULL);
    if (ret < 0) {
        perror("ioctl failed");
    }
}

void reset_delays(void) {
    int ret = ioctl(rh_fd, RH_IOC_RST_DELAYS, NULL);
    if (ret < 0) {
        perror("ioctl failed");
    }
}


int main(int argc, char *argv[]) {

    printf("[!] Connecting to nohammer kernel module /dev/rh...\n");
    rh_fd = open("/dev/rh", O_RDONLY);
    if (rh_fd < 0) 
    {
        perror("Could not open /dev/rh");
        exit(EXIT_FAILURE);
    }
    
    printf("Press ENTER to start\n");
    getchar();
    while (1) {
        reset_delays();
        reset_overflows();

        uint64_t overflows = get_overflows();
        uint64_t delays = get_delays();
        printf("- overflows: %llu\n", overflows);
        printf("- delays: %llu\n", delays);

        usleep(100000);
    }

}
