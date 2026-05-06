#include "pty_hide.h"

#include <common.h>
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <syscall.h>

KPM_NAME("pty_hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Prslc");
KPM_DESCRIPTION("Hide root-owned PTY to prevent su process detection");

typedef unsigned long (*copy_from_user_t)(void *to, const void __user *from, unsigned long n);
static copy_from_user_t p_copy_from_user = NULL;

static inline bool is_app_process(void)
{
    return current_uid() >= 10000;
}

static bool read_user_uid(const void __user *uaddr, unsigned int *uid)
{
    if (p_copy_from_user)
        return (p_copy_from_user(uid, uaddr, sizeof(*uid)) == 0);
    return false;
}

void after_stat_audit(hook_fargs4_t *args, void *udata)
{
    if ((long)args->ret != 0 || !is_app_process())
        return;

    const char __user *upath = (const char __user *)syscall_argn(args, 1);
    char kpath[32];
    if (compat_strncpy_from_user(kpath, upath, sizeof(kpath)) <= 0)
        return;

    if (strncmp(kpath, "/dev/pts/", 9) != 0)
        return;

    void __user *ustat = (void __user *)syscall_argn(args, 2);
    void __user *uid_addr = (char __user *)ustat + STAT_UID_OFFSET;
    void __user *gid_addr = (char __user *)ustat + STAT_GID_OFFSET;

    unsigned int orig_uid;
    if (!read_user_uid(uid_addr, &orig_uid) || orig_uid != 0)
        return;

    unsigned int fake_id = 2000;
    compat_copy_to_user(uid_addr, &fake_id, sizeof(fake_id));
    compat_copy_to_user(gid_addr, &fake_id, sizeof(fake_id));
    LOGI("spoofed fstatat: %s", kpath);
}

void after_statx_audit(hook_fargs5_t *args, void *udata)
{
    if ((long)args->ret != 0 || !is_app_process())
        return;

    const char __user *upath = (const char __user *)syscall_argn(args, 1);
    char kpath[32];
    if (compat_strncpy_from_user(kpath, upath, sizeof(kpath)) <= 0)
        return;

    if (strncmp(kpath, "/dev/pts/", 9) != 0)
        return;

    void __user *ustatx = (void __user *)syscall_argn(args, 4);
    void __user *uid_addr = (char __user *)ustatx + STATX_UID_OFFSET;
    void __user *gid_addr = (char __user *)ustatx + STATX_GID_OFFSET;

    unsigned int orig_uid;
    if (!read_user_uid(uid_addr, &orig_uid) || orig_uid != 0)
        return;

    unsigned int fake_id = 2000;
    compat_copy_to_user(uid_addr, &fake_id, sizeof(fake_id));
    compat_copy_to_user(gid_addr, &fake_id, sizeof(fake_id));
    LOGI("spoofed statx: %s", kpath);
}

static long pty_hide_init(const char *args, const char *event, void *reserved)
{
    p_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("copy_from_user");
    if (!p_copy_from_user)
        p_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("__arch_copy_from_user");

    if (!p_copy_from_user)
        LOGW("no copy_from_user available, module inactive");
    else
        LOGI("loaded, using copy_from_user/__arch_copy_from_user");

    hook_syscalln(__NR_newfstatat, 4, NULL, after_stat_audit, NULL);
    hook_syscalln(__NR_statx, 5, NULL, after_statx_audit, NULL);
    return 0;
}

static long pty_hide_exit(void *reserved)
{
    unhook_syscalln(__NR_newfstatat, NULL, after_stat_audit);
    unhook_syscalln(__NR_statx, NULL, after_statx_audit);
    LOGI("exit");
    return 0;
}

KPM_INIT(pty_hide_init);
KPM_EXIT(pty_hide_exit);