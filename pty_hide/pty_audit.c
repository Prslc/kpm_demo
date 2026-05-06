#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef STATX_UID
#define STATX_UID 0x0001
#endif
#ifndef __NR_statx
#define __NR_statx 291
#endif

#define STX_UID_OFFSET 0x14

static void check_with_statx(int num) {
    char path[32];
    snprintf(path, sizeof(path), "/dev/pts/%d", num);

    unsigned char buf[256] = {0};
    if (syscall(__NR_statx, AT_FDCWD, path, 0, STATX_UID, buf) == 0) {
        unsigned int uid = *(unsigned int *)(buf + STX_UID_OFFSET);
        printf("  %-16s  UID %5u %s\n", path, uid,
               uid == 0 ? "[ROOT]" : "");
    } else {
        printf("  %-16s  (statx failed)\n", path);
    }
}

static void check_with_stat(int num) {
    char path[32];
    snprintf(path, sizeof(path), "/dev/pts/%d", num);

    struct stat st;
    if (stat(path, &st) == 0) {
        printf("  %-16s  UID %5u %s\n", path, (unsigned int)st.st_uid,
               st.st_uid == 0 ? "[ROOT]" : "");
    } else {
        printf("  %-16s  (stat failed)\n", path);
    }
}

int main(void) {
    printf("=== statx ===\n");
    for (int i = 0; i <= 5; i++)
        check_with_statx(i);

    printf("\n=== stat ===\n");
    for (int i = 0; i <= 5; i++)
        check_with_stat(i);

    return 0;
}