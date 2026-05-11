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
KPM_VERSION("1.2.0");
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
 * Filter security contexts in simple_transaction_get to bypass specific detection logic.
 * Ref: https://github.com/LSPosed/DirtySepolicy/blob/master/app/src/main/java/org/lsposed/dirtysepolicy/AppZygote.java
 */
void after_simple_get(hook_fargs3_t *args, void *udata)
{
    char *kbuf = (char *)args->ret;
    unsigned int uid = current_uid();
    const size_t scan_range = 256;

    // Sensitive context keywords
    static const char *root_tokens[] = {
        "magisk","lsposed"
    };

    if (uid >= 10000 && kbuf && !IS_ERR(kbuf)) {
        // Block known root-related contexts by scanning the raw buffer
        for (int i = 0; i < sizeof(root_tokens) / sizeof(root_tokens[0]); i++) {
            if (k_memstr(kbuf, root_tokens[i], scan_range)) {
                LOGW("Blocked %s probe from UID %u", root_tokens[i], uid);
                goto block;
            }
        }
        
        // Block system_server policy probes
        // "2000000" -> execmem (1 << 25 in 'process' class)
        // Ref: security/selinux/include/classmap.h
        if (k_memstr(kbuf, "system_server", scan_range)) {
            if (k_memstr(kbuf, "2000000", scan_range)) {
                LOGW("Sanitizing system_server probe (UID %u)", uid);
                if (kbuf) kbuf[0] = '\0'; 
                return; 
            }
        }

        // Block ZygiskNext probe (Zygote -> adb_data_file)
        // " 8 "      -> Class: dir
        // "10000000" -> Perm:  search (1 << 28)
        if (k_memstr(kbuf, "u:r:zygote:s0", scan_range) &&
            k_memstr(kbuf, "u:object_r:adb_data_file:s0", scan_range)) {
            if (k_memstr(kbuf, " 8 ", scan_range) &&
                k_memstr(kbuf, "10000000", scan_range)) {
                LOGW("Blocked ZygiskNext probe");
                kbuf[0] = '\0';
                return;
            }
        }

        return;

block:
        // Return -EINVAL (22) to force checkSELinuxAccess to return false (denied/invalid)
        args->ret = (uint64_t)-22;
    }
}

static long selinux_shadow_init(const char *args, const char *event, void *reserved)
{
    void *target = (void *)kallsyms_lookup_name("simple_transaction_get");
    
    if (!target) {
        LOGE("Failed to find symbol: simple_transaction_get\n");
        return -1;
    }

    if (hook_wrap3(target, NULL, after_simple_get, NULL) != HOOK_NO_ERR) {
        LOGE("Failed to register hook on simple_transaction_get\n");
        return -1;
    }

    LOGI("Module loaded, auditing bypass active\n");
    return 0;
}

static long selinux_shadow_exit(void *reserved)
{
    void *target = (void *)kallsyms_lookup_name("simple_transaction_get");
    if (target) {
        hook_unwrap(target, NULL, after_simple_get);
    }
    LOGI("Module unloaded\n");
    return 0;
}

KPM_INIT(selinux_shadow_init);
KPM_EXIT(selinux_shadow_exit);