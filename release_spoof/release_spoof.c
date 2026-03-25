#include "release_spoof.h"
#include "kp_abi_uts.h"

#include <ktypes.h>
#include <kpmodule.h>
#include <ksyms.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <kputils.h>

KPM_NAME("kpm-release-spoof");
KPM_VERSION("1.0.4");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Prslc");
KPM_DESCRIPTION("Spoof kernel release string dynamically");

static void *kv_init_uts_ns;    // don't remove it

static char g_old_release[KP_UTS_LEN];
static struct kp_uts_namespace *g_ns = NULL;

static inline bool spoof_ready(void)
{
    return g_ns != NULL;
}

static int restore_release(char *__user out_msg, int outlen)
{
    strscpy(g_ns->name.release, g_old_release, KP_UTS_LEN);
    LOGI("restored release: %s", g_old_release);

    if (out_msg && outlen > 0) {
        const char *msg = "restored!";
        size_t len = strlen(msg) + 1;
        compat_copy_to_user(out_msg, msg, outlen < len ? outlen : len);
    }
    return 0;
}

static int set_release(const char *args, char *__user out_msg, int outlen)
{
    ssize_t ret = strscpy(g_ns->name.release, args, KP_UTS_LEN);

    if (ret < 0) {
        LOGW("copy failed");
        return -EINVAL;
    }

    LOGI("new release: %s", g_ns->name.release);

    if (out_msg && outlen > 0) {
        const char *msg = "spoof ok!";
        size_t len = strlen(msg) + 1;
        compat_copy_to_user(out_msg, msg, outlen < len ? outlen : len);
    }
    return 0;
}

static long release_spoof_init(const char *args, const char *event, void *reserved)
{
    kvar_lookup_name(init_uts_ns);
    void *tmp = kvar(init_uts_ns);

    if (!tmp) {
        LOGE("init_uts_ns lookup failed");
        return -ENOENT;
    }

    /*
     * Skip 4-byte kref/refcount at the head of uts_namespace 
     * to align with the name struct for this specific kernel.
     */
    g_ns = (struct kp_uts_namespace *)((char *)tmp + 4);

    /* Verify ABI alignment by checking sysname */
    if (strncmp(g_ns->name.sysname, "Linux", 5) != 0) {
        LOGE("ABI Alignment failed! Expected 'Linux', got '%s'", g_ns->name.sysname);
        g_ns = NULL;
        return -EINVAL;
    }

    /* Backup original release string */
    strscpy(g_old_release, g_ns->name.release, KP_UTS_LEN);

    LOGI("Initialized. Current: %s", g_old_release);
    return 0;
}

static long release_spoof_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!args || !args[0])
        return -EINVAL;

    if (!spoof_ready())
        return -EAGAIN;

    if (strncmp(args, "restore", 7) == 0)
        return restore_release(out_msg, outlen);

    return set_release(args, out_msg, outlen);
}

static long release_spoof_exit(void *reserved)
{
    if (spoof_ready() && g_old_release[0]) {
        strscpy(g_ns->name.release, g_old_release, KP_UTS_LEN);
        LOGI("restored on exit");
    }

    LOGI("exit");
    return 0;
}

KPM_INIT(release_spoof_init);
KPM_CTL0(release_spoof_control0);
KPM_EXIT(release_spoof_exit);
