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

#ifndef STATX_GID
#define STATX_GID 0x0002
#endif

#ifndef __NR_statx
#define __NR_statx 291
#endif

#define STX_UID_OFFSET 0x14
#define STX_GID_OFFSET 0x18

static void check_with_statx(const char *path) {
    unsigned char buf[256] = {0};
    if (syscall(__NR_statx, AT_FDCWD, path, 0, STATX_UID | STATX_GID, buf) == 0) {
        unsigned int uid = *(unsigned int *)(buf + STX_UID_OFFSET);
        unsigned int gid = *(unsigned int *)(buf + STX_GID_OFFSET);
        printf("  %-16s statx UID %5u  GID %5u %s\n",
               path, uid, gid,
               uid == 0 ? "[ROOT]" : "");
    }
}

static void check_with_stat(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        printf("  %-16s stat  UID %5u  GID %5u %s\n",
               path,
               (unsigned int)st.st_uid,
               (unsigned int)st.st_gid,
               st.st_uid == 0 ? "[ROOT]" : "");
    }
}

int main(void) {
    printf("=== statx ===\n");
    for (int i = 0; i <= 5; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/dev/pts/%d", i);
        if (access(path, F_OK) == 0)
            check_with_statx(path);
    }

    printf("\n=== stat  ===\n");
    for (int i = 0; i <= 5; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/dev/pts/%d", i);
        if (access(path, F_OK) == 0)
            check_with_stat(path);
    }

    return 0;
}