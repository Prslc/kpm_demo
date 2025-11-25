#include <compiler.h>
#include <ktypes.h>
#include <kpmodule.h>
#include <ksyms.h>
#include <log.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/errno.h>

#define UTS_RELEASE_LEN 65
#define SCAN_SIZE       0x400  // number of bytes scanned

KPM_NAME("kpm_release_spoof");
KPM_VERSION("1.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Prslc");
KPM_DESCRIPTION("KPM: dynamically locate and spoof uname.release");

static char g_old_release[UTS_RELEASE_LEN] = "";
static char *g_release_ptr = NULL;

/* local helpers */
static inline bool k_isdigit(char c) {
    return (c >= '0' && c <= '9');
}

static inline bool is_visible_char(char c) {
    return (c >= 0x20 && c <= 0x7E);
}

/* check if a string looks like uname.release */
static bool validate_release_candidate(const char *s)
{
    bool has_dot = false;
    int i;

    if (!s || !k_isdigit(s[0]))
        return false;

    for (i = 0; i < UTS_RELEASE_LEN; i++) {
        char c = s[i];

        if (c == '\0')
            break;

        if (!is_visible_char(c))
            return false;

        if (c == '.')
            has_dot = true;
    }

    if (i == UTS_RELEASE_LEN)
        return false;

    return has_dot;
}

/*
 * Scan memory near init_uts_ns for a release-like string.
 * Pattern:
 *   - find "digit + '.'"
 *   - backtrack to the start of the digit sequence
 *   - validate the string
 */
static char *find_uname_release_field(void *base, size_t sz)
{
    char *b = (char *)base;

    if (!b || sz < 4)
        return NULL;

    for (size_t off = 0; off < sz - 3; off++) {
        char *p = b + off;

        if (!k_isdigit(p[0]) || p[1] != '.')
            continue;

        char *start = p;
        while (start > b && k_isdigit(start[-1]))
            start--;

        if (validate_release_candidate(start))
            return start;
    }

    return NULL;
}

static long kpm_uname_init(const char *args, const char *event, void *reserved)
{
    void *uts = (void *)kallsyms_lookup_name("init_uts_ns");

    pr_info("[kpm_release_spoof] init, event=%s args=%s\n",
          event, args ? args : "(null)");

    if (!uts) {
        logke("[kpm_release_spoof] init_uts_ns not found\n");
        return -ENOENT;
    }

    g_release_ptr = find_uname_release_field(uts, SCAN_SIZE);
    if (!g_release_ptr) {
        logke("[kpm_release_spoof] could not locate release string\n");
        return -EINVAL;
    }

    strncpy(g_old_release, g_release_ptr, UTS_RELEASE_LEN - 1);
    g_old_release[UTS_RELEASE_LEN - 1] = '\0';

    pr_info("[kpm_release_spoof] release found at %p: '%s'\n",
          g_release_ptr, g_old_release);

    return 0;
}

static long kpm_release_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!g_release_ptr)
        return -EINVAL;

    if (!args || args[0] == '\0') {
        strncpy(g_release_ptr, g_old_release, UTS_RELEASE_LEN - 1);
        g_release_ptr[UTS_RELEASE_LEN - 1] = '\0';
        pr_info("[kpm_release_spoof] release restored to '%s'\n", g_release_ptr);
        return 0;
    }

    strncpy(g_release_ptr, args, UTS_RELEASE_LEN - 1);
    g_release_ptr[UTS_RELEASE_LEN - 1] = '\0';
    pr_info("[kpm_release_spoof] release changed to '%s'\n", g_release_ptr);

    return 0;
}

static long kpm_uname_exit(void *reserved)
{
    if (g_release_ptr && g_old_release[0]) {
        strncpy(g_release_ptr, g_old_release, UTS_RELEASE_LEN - 1);
        g_release_ptr[UTS_RELEASE_LEN - 1] = '\0';
        pr_info("[kpm_release_spoof] release restored to '%s'\n", g_old_release);
    }

    pr_info("[kpm_release_spoof] exit\n");
    return 0;
}

KPM_INIT(kpm_uname_init);
KPM_CTL0(kpm_release_control0);
KPM_EXIT(kpm_uname_exit);