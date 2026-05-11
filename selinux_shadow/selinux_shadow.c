#include "selinux_shadow.h"

#include <common.h>
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/err.h>

KPM_NAME("selinux_shadow");
KPM_VERSION("1.3.0");
KPM_AUTHOR("Prslc");
KPM_DESCRIPTION("Sanitize SELinux transaction buffers to ensure policy integrity");

/**
 * Internal helper to search for a pattern within a memory block.
 * Necessary because SELinux buffers contain null bytes that break standard strstr.
 */
 static inline int k_memstr(const char *buffer, const char *target, size_t buf_len) {
    size_t target_len = strlen(target);
    if (target_len > buf_len || target_len == 0) return 0;
    for (size_t i = 0; i <= buf_len - target_len; i++) {
        if (memcmp(buffer + i, target, target_len) == 0) return 1;
    }
    return 0;
}

/**
 * Checks if the provided buffer contains any sensitive tokens.
 */
static bool is_sensitive_buffer(const char *buffer, size_t len) {
    if (!buffer || IS_ERR(buffer)) return false;
    for (size_t i = 0; i < sizeof(SENSITIVE_TOKENS) / sizeof(SENSITIVE_TOKENS[0]); i++) {
        if (k_memstr(buffer, SENSITIVE_TOKENS[i], len)) {
            return true;
        }
    }
    return false;
}

/**
 * Handle WRITE probes: Intercept attempts to set process attributes.
 * Forced override of the return value occurs here (After Hook).
 */
void after_setprocattr(hook_fargs3_t *args, void *udata)
{
    const char *ptr = (const char *)args->arg1;
    size_t len = (size_t)args->arg2;
    uid_t uid = current_uid();

    /* Only filter non-system/untrusted UIDs */
    if (uid >= 10000 && ptr) {
        size_t scan_len = (len < 128) ? len : 128;
        if (is_sensitive_buffer(ptr, scan_len)) {
            /* Force return -EINVAL (22) to mimic a "context not found" error */
            args->ret = (uint64_t)-22;
        }
    }
}

/**
 * Filter security contexts in simple_transaction_get to bypass specific detection logic.
 * Ref: https://github.com/LSPosed/DirtySepolicy/blob/master/app/src/main/java/org/lsposed/dirtysepolicy/AppZygote.java
 */
void after_simple_get(hook_fargs3_t *args, void *udata)
{
    char *kbuf = (char *)args->ret;
    unsigned int uid = current_uid();
    const size_t scan_range = 256;

    if (uid >= 10000 && kbuf && !IS_ERR(kbuf)) {
        // Block known root-related contexts by scanning the raw buffer
        if (is_sensitive_buffer(kbuf, scan_range)) {
            goto block;
        }
        
        // Block system_server policy probes
        // "2000000" -> execmem (1 << 25 in 'process' class)
        // Ref: security/selinux/include/classmap.h
        if (k_memstr(kbuf, "system_server", scan_range)) {
            if (k_memstr(kbuf, "2000000", scan_range)) {
                goto block;
            }
        }

        // Block ZygiskNext probe (Zygote -> adb_data_file)
        // " 8 "      -> Class: dir
        // "10000000" -> Perm:  search (1 << 28)
        if (k_memstr(kbuf, "u:r:zygote:s0", scan_range) &&
            k_memstr(kbuf, "u:object_r:adb_data_file:s0", scan_range)) {
            if (k_memstr(kbuf, " 8 ", scan_range) &&
                k_memstr(kbuf, "10000000", scan_range)) {
                goto block;
            }
        }

        return;

block:
        /* Truncate the buffer to hide evidence */
        if (kbuf && !IS_ERR(kbuf)) {
            kbuf[0] = '\0'; 
        }
        return;
    }
}

static long selinux_shadow_init(const char *args, const char *event, void *reserved)
{
    void *get_target = (void *)kallsyms_lookup_name("simple_transaction_get");
    void *set_target = (void *)kallsyms_lookup_name("selinux_setprocattr");
    
    // Hook Read: simple_transaction_get (After)
    if (get_target) {
        if (hook_wrap3(get_target, NULL, after_simple_get, NULL) != HOOK_NO_ERR) {
            LOGE("Failed to hook simple_transaction_get");
            return -1;
        }
    }

    // Hook Write: selinux_setprocattr (After)
    if (set_target) {
        if (hook_wrap3(set_target, NULL, after_setprocattr, NULL) != HOOK_NO_ERR) {
            LOGE("Failed to hook selinux_setprocattr");
            return -1;
        }
    }

    LOGI("Shadow active: Read/Write SELinux interception engaged");
    return 0;
}

static long selinux_shadow_exit(void *reserved)
{
    void *get_target = (void *)kallsyms_lookup_name("simple_transaction_get");
    void *set_target = (void *)kallsyms_lookup_name("selinux_setprocattr");

    if (get_target) hook_unwrap(get_target, NULL, after_simple_get);
    if (set_target) hook_unwrap(set_target, NULL, after_setprocattr);

    LOGI("Module unloaded\n");
    return 0;
}

KPM_INIT(selinux_shadow_init);
KPM_EXIT(selinux_shadow_exit);