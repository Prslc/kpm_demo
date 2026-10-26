/*
 * path_hide / probe - KernelPatch module
 *
 * Target: Linux 4.19.157-perf (munch OS1.0.10.0.ULMCNXM)
 *
 * This module has two independent modes:
 *
 *   probe <uid>   Log every VFS lookup/readdir event for that uid, without
 *                 changing any behaviour.  Use it to verify that the hook
 *                 points fire and that the offsets below are correct.
 *
 *   hide on       Actually hide registered paths from processes whose uid is
 *                 >= minuid (default 10000) and which do not own the inode.
 *                 Register paths with "add <path>".
 *
 * Hook points (validated against the shipped Image; see path_hide.h):
 *   walk_component  (after)  every component walked by link_path_walk
 *   lookup_fast     (after)  dcache-hit lookup; covers walk_component fast
 *                            path and the inlined do_last fast path
 *   complete_walk   (after)  final component of open/stat/... before
 *                            may_open()/vfs_open()
 *   iterate_dir     (before/after) record the directory sb for this getdents
 *                            call, so filldir can match (dir_sb, ino)
 *   filldir64       (before) getdents64 entries
 *   filldir         (before) getdents entries
 *
 * Note: do_last()/lookup_open() are inlined into path_openat() in this
 * Image and have no symbols, so they cannot be hooked directly.
 */

#include "path_hide.h"

#include <common.h>
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <barrier.h>

/* Config directory.  Files are the source of truth; use "reload". */
#define PH_DIR "/data/local/tmp/path_hide"
#define PH_CONFIG_FILE PH_DIR "/config"
#define PH_PATHS_FILE PH_DIR "/paths"
#define PH_FILEBUF 8192

/* helpers resolved via kallsyms */

/*
 * GCC lowers __atomic_compare_exchange_n() to an outline call on arm64.
 * KPMs must not depend on libgcc symbols (KP resolves undefined symbols
 * against its own table), so provide the exact libgcc helper locally.
 * ABI: returns the old value; newval is stored when oldval matches.
 */
int __aarch64_cas4_acq_rel(int oldval, int newval, int *ptr)
{
    int old, fail;

    do {
        fail = 0;
        __asm__ __volatile__("ldaxr %w0, [%2]\n"
                             "cmp   %w0, %w3\n"
                             "b.ne  1f\n"
                             "stlxr %w1, %w4, [%2]\n"
                             "1:\n"
                             : "=&r"(old), "+r"(fail)
                             : "r"(ptr), "r"(oldval), "r"(newval)
                             : "memory");
    } while (fail);

    return old;
}

struct ph_path
{
    void *mnt;
    void *dentry;
};

typedef char *(*ph_dentry_path_raw_t)(void *dentry, char *buf, int buflen);
typedef int (*ph_kern_path_t)(const char *name, unsigned int flags, struct ph_path *path);
typedef void (*ph_path_put_t)(const struct ph_path *path);
typedef void (*ph_dput_t)(void *dentry);
typedef void *(*ph_ilookup_t)(void *sb, unsigned long ino);
typedef void (*ph_iput_t)(void *inode);
typedef struct file *(*ph_filp_open_t)(const char *name, int flags, umode_t mode);
typedef long (*ph_kernel_read_t)(struct file *file, void *buf, unsigned long count, loff_t *pos);
typedef int (*ph_filp_close_t)(struct file *file, void *id);
typedef void *(*ph_prepare_kernel_cred_t)(void *daemon);
typedef const void *(*ph_override_creds_t)(const void *new);
typedef void (*ph_revert_creds_t)(const void *old);
typedef void (*ph_put_cred_t)(void *cred);
typedef int (*ph_secctx_to_secid_t)(const char *secdata, u32 seclen, u32 *secid);
typedef void (*ph_selinux_cred_getsecid_t)(const void *cred, u32 *secid);

static ph_dentry_path_raw_t g_dentry_path_raw;
static ph_kern_path_t g_kern_path;
static ph_path_put_t g_path_put;
static ph_dput_t g_dput;
static ph_ilookup_t g_ilookup;
static ph_iput_t g_iput;
static ph_filp_open_t g_filp_open;
static ph_kernel_read_t g_kernel_read;
static ph_filp_close_t g_filp_close;
static ph_prepare_kernel_cred_t g_prepare_kernel_cred;
static ph_override_creds_t g_override_creds;
static ph_revert_creds_t g_revert_creds;
static ph_put_cred_t g_put_cred;
static ph_secctx_to_secid_t g_secctx_to_secid;
static ph_selinux_cred_getsecid_t g_selinux_cred_getsecid;

/* reload() is serialized: init runs before control can be called. */
static char g_filebuf[PH_FILEBUF];

/* configuration */

static volatile int g_hide; /* hide enabled?                 */
static volatile int g_min_uid = 10000; /* hide from uid >= min_uid      */
static volatile int g_probe_uid = -1; /* exact uid to trace, -1 = off  */
static volatile int g_probe_budget; /* remaining probe lines         */
static volatile int g_reload_active; /* reload() is reading files     */
static volatile uid_t g_reload_uid; /* uid of the reloading task     */
static char g_sctx_override[64]; /* "sctx=u:r:magisk:s0" load arg */
static char g_used_sctx[64]; /* scontext that actually read the config */

/* Runtime offsets; defaults from path_hide.h, overridable from config. */
static int g_off_nd_mnt = PH_OFF_ND_PATH_MNT;
static int g_off_nd_dentry = PH_OFF_ND_PATH_DENTRY;
static int g_off_nd_flags = PH_OFF_ND_FLAGS;
static int g_off_dentry_inode = PH_OFF_DENTRY_INODE;
static int g_off_inode_uid = PH_OFF_INODE_UID;
static int g_off_inode_sb = PH_OFF_INODE_SB;
static int g_off_inode_ino = PH_OFF_INODE_INO;
static int g_off_file_inode = PH_OFF_FILE_INODE;
static int g_off_cred_security = PH_OFF_CRED_SECURITY;
static int g_off_tsec_sid = PH_OFF_TSEC_SID;
static int g_off_tsec_create_sid = PH_OFF_TSEC_CREATE_SID;
static int g_off_tsec_keycreate_sid = PH_OFF_TSEC_KEYCREATE_SID;
static int g_off_tsec_sockcreate_sid = PH_OFF_TSEC_SOCKCREATE_SID;

/* path registry */

struct ph_entry
{
    u64 sb;
    u64 ino;
    u32 i_uid;
    char path[PH_MAX_PATH];
};

/*
 * Double-buffered registry: reload() builds the inactive buffer and swaps
 * g_active, so hiding is never disabled and readers never see a half-built
 * registry.  Manual "add" appends to the active buffer.
 */
static struct ph_entry g_entries[2][PH_MAX_ENTRIES];
static volatile int g_entry_count[2];
static volatile int g_active;

/*
 * ctx -> directory superblock, captured by the iterate_dir() hook and read
 * by the filldir hooks.  Keyed by ctx (unique per getdents call), not by
 * task, so it is safe across preemption/migration.  Lock-free slots.
 */
#define PH_DIR_MAP_N 32
struct ph_dir_slot
{
    void *ctx;
    void *sb;
    volatile int state; /* 0 free, -1 claiming, 1 ready */
};
static struct ph_dir_slot g_dir_slots[PH_DIR_MAP_N];

/* small utilities */

static inline bool ph_krange(const void *p)
{
    return (unsigned long)p >= 0xffff000000000000UL;
}

static inline bool ph_kptr(const void *p)
{
    unsigned long v = (unsigned long)p;
    return v >= 0xffff000000000000UL && !(v & 7);
}

static inline void *nd_mnt(void *nd)
{
    return *(void **)((char *)nd + g_off_nd_mnt);
}

static inline void *nd_dentry(void *nd)
{
    return *(void **)((char *)nd + g_off_nd_dentry);
}

static inline void *dentry_inode(void *dentry)
{
    return *(void **)((char *)dentry + g_off_dentry_inode);
}

static inline u64 inode_sb(void *inode)
{
    return *(u64 *)((char *)inode + g_off_inode_sb);
}

static inline u64 inode_ino(void *inode)
{
    return *(u64 *)((char *)inode + g_off_inode_ino);
}

static inline u32 inode_uid(void *inode)
{
    return *(u32 *)((char *)inode + g_off_inode_uid);
}

static inline u32 nd_flags(void *nd)
{
    return *(u32 *)((char *)nd + g_off_nd_flags);
}

static int ph_parse_u64(const char *s, u64 *out)
{
    u64 v = 0;
    int any = 0;

    while (*s == ' ')
        s++;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (u64)(*s - '0');
        s++;
        any = 1;
    }
    if (!any) return -EINVAL;
    *out = v;
    return 0;
}

static int ph_parse_hex(const char *s, u64 *out)
{
    u64 v = 0;
    int any = 0;

    while (*s == ' ')
        s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    for (;;) {
        int d;

        if (*s >= '0' && *s <= '9')
            d = *s - '0';
        else if (*s >= 'a' && *s <= 'f')
            d = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F')
            d = *s - 'A' + 10;
        else
            break;
        v = (v << 4) | (u64)d;
        s++;
        any = 1;
    }
    if (!any) return -EINVAL;
    *out = v;
    return 0;
}

static int ph_sputs(char *buf, int cap, int pos, const char *s)
{
    while (*s && pos < cap - 1)
        buf[pos++] = *s++;
    buf[pos] = 0;
    return pos;
}

static int ph_sput_u64(char *buf, int cap, int pos, u64 v)
{
    char tmp[24];
    int n = 0;

    if (v == 0) tmp[n++] = '0';
    while (v && n < (int)sizeof(tmp)) {
        tmp[n++] = '0' + (char)(v % 10);
        v /= 10;
    }
    while (n > 0 && pos < cap - 1)
        buf[pos++] = tmp[--n];
    buf[pos] = 0;
    return pos;
}

static int ph_sput_i64(char *buf, int cap, int pos, long v)
{
    if (v < 0) {
        if (pos < cap - 1) buf[pos++] = '-';
        buf[pos] = 0;
        return ph_sput_u64(buf, cap, pos, (u64)(-v));
    }
    return ph_sput_u64(buf, cap, pos, (u64)v);
}

static int ph_sput_hex(char *buf, int cap, int pos, u64 v)
{
    char tmp[16];
    int n = 0;

    if (!v) tmp[n++] = '0';
    while (v && n < (int)sizeof(tmp)) {
        int d = (int)(v & 0xf);
        tmp[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        v >>= 4;
    }
    while (n > 0 && pos < cap - 1)
        buf[pos++] = tmp[--n];
    buf[pos] = 0;
    return pos;
}

static int ph_sput_off(char *buf, int cap, int pos, const char *name, int v)
{
    pos = ph_sputs(buf, cap, pos, name);
    pos = ph_sputs(buf, cap, pos, "=");
    return ph_sput_hex(buf, cap, pos, (u64)v);
}

static char *ph_trim(char *s)
{
    char *e;

    while (*s == ' ' || *s == '\t' || *s == '\r')
        s++;
    e = s;
    while (*e)
        e++;
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
        *--e = 0;
    return s;
}

/*
 * Read a whole (small) file from the kernel.  The caller context must be
 * allowed to open the path; the control/init context is root/su on APatch.
 * Returns the number of bytes read, or a negative errno.
 */
static int ph_read_file(const char *path, char *buf, int cap)
{
    struct file *f;
    loff_t pos = 0;
    int total = 0;

    if (!g_filp_open || !g_kernel_read || !g_filp_close) return -ENOSYS;

    f = g_filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) return (int)PTR_ERR(f);

    while (total < cap - 1) {
        long n = g_kernel_read(f, buf + total, cap - 1 - total, &pos);

        if (n < 0) {
            total = (int)n;
            break;
        }
        if (!n) break;
        total += (int)n;
    }
    g_filp_close(f, NULL);

    if (total < 0) return total;
    buf[total] = 0;
    return total;
}

/* privileged file access */

/*
 * The control supercall runs in the caller's context; an app cannot read
 * /data/adb (u:object_r:adb_data_file).  Do what KernelPatch's commit_su()
 * does: prepare_kernel_cred() and write the SELinux SID directly into the
 * new cred's security blob.
 *
 * Do NOT use set_security_override(): selinux_kernel_act_as() checks
 * KERNEL_SERVICE__USE_AS_OVERRIDE against the caller and silently denies
 * apps, leaving the cred with the kernel SID.
 */
struct ph_cred
{
    const void *old;
    void *new;
};

static const char *const ph_cred_sctx[] = {
    "u:r:magisk:s0",
};

static u32 ph_strlen(const char *s)
{
    u32 n = 0;

    while (s[n])
        n++;
    return n;
}

/* put_cred() is inline; __put_cred() BUG_ONs unless usage is already 0. */
static int ph_atomic_dec_and_test(int *p)
{
    int old = __atomic_load_n(p, __ATOMIC_ACQUIRE);

    for (;;) {
        if (old <= 0) return 0;
        if (__atomic_compare_exchange_n(p, &old, old - 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return old == 1;
    }
}

static bool ph_set_cred_sid(void *cred, u32 sid)
{
    void *blob;
    u32 cur = 0;

    blob = *(void **)((char *)cred + g_off_cred_security);
    if (!ph_kptr(blob)) return false;

    /* Verify the offsets before writing anything. */
    if (g_selinux_cred_getsecid) {
        g_selinux_cred_getsecid(cred, &cur);
        if (*(u32 *)((char *)blob + g_off_tsec_sid) != cur) {
            LOGW("cred: security offset mismatch (%u vs %u)\n", (unsigned)*(u32 *)((char *)blob + g_off_tsec_sid),
                 (unsigned)cur);
            return false;
        }
    }

    *(u32 *)((char *)blob + g_off_tsec_sid) = sid;
    *(u32 *)((char *)blob + g_off_tsec_create_sid) = 0;
    *(u32 *)((char *)blob + g_off_tsec_keycreate_sid) = 0;
    *(u32 *)((char *)blob + g_off_tsec_sockcreate_sid) = 0;

    if (g_selinux_cred_getsecid) {
        cur = 0;
        g_selinux_cred_getsecid(cred, &cur);
        if (cur != sid) {
            LOGW("cred: SID write verify failed (%u != %u)\n", (unsigned)cur, (unsigned)sid);
            return false;
        }
    }
    return true;
}

static bool ph_cred_enter(struct ph_cred *cc, const char *sctx)
{
    void *new;
    u32 sid;

    cc->old = NULL;
    cc->new = NULL;

    if (!g_prepare_kernel_cred || !g_override_creds || !g_revert_creds || !g_put_cred || !g_secctx_to_secid || !sctx ||
        !sctx[0])
        return false;

    if (g_secctx_to_secid(sctx, ph_strlen(sctx), &sid) || !sid) return false;

    new = g_prepare_kernel_cred(NULL);
    if (!new) return false;

    if (!ph_set_cred_sid(new, sid)) {
        if (ph_atomic_dec_and_test((int *)new)) g_put_cred(new);
        return false;
    }

    cc->old = g_override_creds(new);
    cc->new = new;
    return true;
}

static void ph_cred_exit(struct ph_cred *cc)
{
    if (cc->old) g_revert_creds(cc->old);
    if (cc->new) {
        if (ph_atomic_dec_and_test((int *)cc->new)) g_put_cred(cc->new);
    }
    cc->old = NULL;
    cc->new = NULL;
}

/*
 * Try one scontext: direct SID write + override.  Returns true on success,
 * in which case the caller must call ph_priv_end().
 */
static bool ph_priv_begin(struct ph_cred *cc, const char *sctx)
{
    if (!ph_cred_enter(cc, sctx)) return false;

    g_reload_uid = current_uid(); /* now 0 */
    g_reload_active = 1;
    return true;
}

static void ph_priv_end(struct ph_cred *cc)
{
    g_reload_active = 0;
    ph_cred_exit(cc);
}

/*
 * Candidate iterator: the load-arg override goes first, then the defaults.
 * Returns NULL when exhausted.
 */
static const char *ph_sctx_candidate(int i)
{
    if (g_sctx_override[0]) {
        if (i == 0) return g_sctx_override;
        i--;
    }
    if (i < (int)(sizeof(ph_cred_sctx) / sizeof(ph_cred_sctx[0]))) return ph_cred_sctx[i];
    return NULL;
}

/* registry lookup */

static inline int ph_active_idx(void)
{
    return smp_load_acquire(&g_active) & 1;
}

static int ph_entry_snapshot(int *idx)
{
    int i = smp_load_acquire(&g_active) & 1;
    int n = smp_load_acquire(&g_entry_count[i]);

    if (n < 0) n = 0;
    if (n > PH_MAX_ENTRIES) n = PH_MAX_ENTRIES;
    *idx = i;
    return n;
}

static bool ph_match_inode(void *inode)
{
    u64 sb = inode_sb(inode);
    u64 ino = inode_ino(inode);
    int idx, n = ph_entry_snapshot(&idx);

    for (int i = 0; i < n; i++) {
        if (g_entries[idx][i].sb == sb && g_entries[idx][i].ino == ino) return true;
    }
    return false;
}

/*
 * readdir only gives us (ino, name), not the superblock.  For each registry
 * entry with the same ino, confirm via ilookup() that the inode really lives
 * on that sb.  This also handles the FUSE /sdcard case when the underlying
 * /data/media/0 path was registered: the FUSE readdir ino matches the
 * backing inode number.
 */
static bool ph_match_ino(u64 ino)
{
    int idx, n;

    if (!g_ilookup || !g_iput) return false;

    n = ph_entry_snapshot(&idx);
    for (int i = 0; i < n; i++) {
        void *inode;

        if (g_entries[idx][i].ino != ino) continue;
        inode = g_ilookup((void *)(unsigned long)g_entries[idx][i].sb, (unsigned long)ino);
        if (inode) {
            bool hide = inode_uid(inode) != current_uid();
            g_iput(inode);
            if (hide) return true;
        }
    }
    return false;
}

/* ctx -> directory sb map (for readdir) */

static void ph_dir_sb_store(void *ctx, void *sb)
{
    for (int i = 0; i < PH_DIR_MAP_N; i++) {
        int expected = 0;

        if (!__atomic_compare_exchange_n(&g_dir_slots[i].state, &expected, -1, false, __ATOMIC_ACQ_REL,
                                         __ATOMIC_ACQUIRE))
            continue;
        g_dir_slots[i].ctx = ctx;
        g_dir_slots[i].sb = sb;
        __atomic_store_n(&g_dir_slots[i].state, 1, __ATOMIC_RELEASE);
        return;
    }
}

static void ph_dir_sb_remove(void *ctx)
{
    for (int i = 0; i < PH_DIR_MAP_N; i++) {
        if (__atomic_load_n(&g_dir_slots[i].state, __ATOMIC_ACQUIRE) != 1) continue;
        if (g_dir_slots[i].ctx != ctx) continue;
        g_dir_slots[i].ctx = NULL;
        __atomic_store_n(&g_dir_slots[i].state, 0, __ATOMIC_RELEASE);
        return;
    }
}

static void *ph_dir_sb_lookup(void *ctx)
{
    for (int i = 0; i < PH_DIR_MAP_N; i++) {
        if (__atomic_load_n(&g_dir_slots[i].state, __ATOMIC_ACQUIRE) != 1) continue;
        if (g_dir_slots[i].ctx == ctx) return g_dir_slots[i].sb;
    }
    return NULL;
}

/*
 * Direct match: the directory sb is authoritative, so no inode lookup is
 * needed.  Returns 1 = hide, 0 = entry belongs to current uid, -1 = no match.
 */
static int ph_match_dir(void *sb, u64 ino)
{
    u64 sbv = (u64)(unsigned long)sb;
    int idx, n = ph_entry_snapshot(&idx);

    for (int i = 0; i < n; i++) {
        if (g_entries[idx][i].sb != sbv || g_entries[idx][i].ino != ino) continue;
        return g_entries[idx][i].i_uid != current_uid();
    }
    return -1;
}

static bool ph_match_readdir(void *ctx, u64 ino)
{
    void *sb = ctx ? ph_dir_sb_lookup(ctx) : NULL;

    if (sb) {
        int r = ph_match_dir(sb, ino);

        if (r >= 0) return r;
    }

    /*
     * Fallback for the FUSE /sdcard case: if only the backing
     * /data/media/0 path was registered, the directory sb is the FUSE sb
     * but the entry ino matches the backing inode.  This also covers a
     * full/expired ctx->sb slot.
     */
    return ph_match_ino(ino);
}

static inline bool ph_probe_on(void)
{
    int uid = g_probe_uid;
    return uid >= 0 && (int)current_uid() == uid;
}

/* Cheap first gate: skip all pointer work for unrelated processes. */
static inline bool ph_interesting(void)
{
    uid_t uid;

    if (!g_hide && g_probe_uid < 0) return false;
    if (g_reload_active && current_uid() == (uid_t)g_reload_uid) return false;

    uid = current_uid();
    if (g_hide && uid >= (u32)g_min_uid) return true;
    return g_probe_uid >= 0 && (int)uid == g_probe_uid;
}

static inline bool ph_should_hide(void)
{
    return g_hide && current_uid() >= (u32)g_min_uid;
}

static inline bool ph_is_hidden_inode(void *inode)
{
    if (!ph_should_hide()) return false;
    if (inode_uid(inode) == current_uid()) return false;
    return ph_match_inode(inode);
}

/* probe logging */

static void ph_log_path(const char *hook, void *inode, void *dentry)
{
    char buf[PH_MAX_PATH];
    const char *path = "?";

    if (g_probe_budget <= 0) return;
    g_probe_budget--;

    if (g_dentry_path_raw && ph_kptr(dentry)) {
        char *p = g_dentry_path_raw(dentry, buf, sizeof(buf));
        if (!IS_ERR_OR_NULL(p)) path = p;
    }

    LOGI("probe %s uid=%u ino=%llu iuid=%u path=%s\n", hook, (unsigned)current_uid(),
         (unsigned long long)(inode ? inode_ino(inode) : 0), (unsigned)(inode ? inode_uid(inode) : 0), path);
}

static void ph_log_filldir(const char *hook, const char *name, int namlen, u64 ino, void *sb)
{
    char nbuf[64];
    int n = namlen;

    if (g_probe_budget <= 0) return;
    g_probe_budget--;

    if (n < 0) n = 0;
    if (n > (int)sizeof(nbuf) - 1) n = sizeof(nbuf) - 1;
    if (name && ph_krange(name))
        memcpy(nbuf, name, n);
    else
        n = 0;
    nbuf[n] = 0;

    LOGI("probe %s uid=%u ino=%llu sb=%llx name=%s\n", hook, (unsigned)current_uid(), (unsigned long long)ino,
         (unsigned long long)(unsigned long)sb, nbuf);
}

/* hooks */

static void ph_after_walk_component(hook_fargs2_t *args, void *udata)
{
    void *nd = (void *)args->arg0;
    void *dentry, *inode;

    (void)udata;
    if (!ph_interesting()) return;
    if (!ph_kptr(nd)) return;
    dentry = nd_dentry(nd);
    if (!ph_kptr(dentry)) return;
    inode = dentry_inode(dentry);
    if (!ph_kptr(inode)) return;

    if (ph_probe_on()) ph_log_path("walk_component", inode, dentry);

    if ((int)args->ret != 0) return;
    if (!ph_is_hidden_inode(inode)) return;

    args->ret = (u64)(long)-ENOENT;
}

static void ph_after_lookup_fast(hook_fargs4_t *args, void *udata)
{
    void *nd = (void *)args->arg0;
    struct ph_path *path = (struct ph_path *)args->arg1;
    void *inode_slot = (void *)args->arg2;
    void *inode;

    (void)udata;
    if (!ph_interesting()) return;
    if ((int)args->ret <= 0) return;
    if (!ph_kptr(path) || !ph_kptr(inode_slot)) return;
    if (!ph_kptr(nd)) return;
    inode = *(void **)inode_slot;
    if (!ph_kptr(inode)) return;

    if (ph_probe_on()) ph_log_path("lookup_fast", inode, path->dentry);

    if (!ph_is_hidden_inode(inode)) return;

    if (nd_flags(nd) & PH_LOOKUP_RCU) {
        /*
         * Under RCU, lookup_fast() only borrowed mnt/dentry; there is
         * nothing to release.  Returning -ENOENT aborts the walk
         * exactly like the negative-dentry path does, without forcing
         * a ref-walk retry (which would be an obvious timing oracle).
         */
        args->ret = (u64)(int)-ENOENT;
        return;
    }

    /*
     * lookup_fast() owns one reference on path->dentry.  path->mnt is
     * borrowed from nd->path.mnt unless follow_managed() crossed a mount,
     * in which case path->mnt owns its own reference.  Mirror what
     * path_to_nameidata() would have done.
     */
    if (path->mnt == nd_mnt(nd)) {
        if (!g_dput || !ph_kptr(path->dentry)) return; /* cannot release cleanly: do not hide */
        g_dput(path->dentry);
    } else {
        if (!g_path_put) return;
        g_path_put(path);
    }

    args->ret = (u64)(int)-ENOENT;
}

static void ph_after_complete_walk(hook_fargs1_t *args, void *udata)
{
    void *nd = (void *)args->arg0;
    void *dentry, *inode;

    (void)udata;
    if (!ph_interesting()) return;
    if ((int)args->ret != 0) return;
    if (!ph_kptr(nd)) return;
    dentry = nd_dentry(nd);
    if (!ph_kptr(dentry)) return;
    inode = dentry_inode(dentry);
    if (!ph_kptr(inode)) return;

    if (ph_probe_on()) ph_log_path("complete_walk", inode, dentry);

    if (!ph_is_hidden_inode(inode)) return;

    args->ret = (u64)(int)-ENOENT;
}

static void ph_filldir_common(hook_fargs6_t *args, const char *hook)
{
    void *ctx = (void *)args->arg0;
    u64 ino = args->arg4;

    if (!ph_interesting()) return;

    if (ph_probe_on())
        ph_log_filldir(hook, (const char *)args->arg1, (int)args->arg2, ino, ctx ? ph_dir_sb_lookup(ctx) : NULL);

    if (!ph_should_hide()) return;
    if (!ph_match_readdir(ctx, ino)) return;

    args->skip_origin = 1;
    args->ret = 0;
}

static void ph_before_filldir64(hook_fargs6_t *args, void *udata)
{
    (void)udata;
    ph_filldir_common(args, "filldir64");
}

static void ph_before_filldir(hook_fargs6_t *args, void *udata)
{
    (void)udata;
    ph_filldir_common(args, "filldir");
}

/*
 * iterate_dir(file, ctx): remember which superblock this getdents call is
 * reading, so filldir can match (dir_sb, ino) directly instead of relying
 * on ilookup() and the inode cache.
 */
static void ph_before_iterate_dir(hook_fargs2_t *args, void *udata)
{
    void *file = (void *)args->arg0;
    void *ctx = (void *)args->arg1;
    void *inode, *sb;

    (void)udata;
    if (!ph_interesting()) return;
    if (!ph_kptr(file) || !ph_kptr(ctx)) return;
    inode = *(void **)((char *)file + g_off_file_inode);
    if (!ph_kptr(inode)) return;
    sb = (void *)(unsigned long)inode_sb(inode);
    if (!ph_kptr(sb)) return;
    ph_dir_sb_store(ctx, sb);
}

static void ph_after_iterate_dir(hook_fargs2_t *args, void *udata)
{
    void *ctx = (void *)args->arg1;

    (void)udata;
    if (ph_kptr(ctx)) ph_dir_sb_remove(ctx);
}

/* hook table */

struct ph_hook
{
    const char *name;
    int argno;
    void *before;
    void *after;
    unsigned long addr;
    bool installed;
};

static struct ph_hook g_hooks[] = {
    { "walk_component", 2, NULL, (void *)ph_after_walk_component, 0, false },
    { "lookup_fast", 4, NULL, (void *)ph_after_lookup_fast, 0, false },
    { "complete_walk", 1, NULL, (void *)ph_after_complete_walk, 0, false },
    { "iterate_dir", 2, (void *)ph_before_iterate_dir, (void *)ph_after_iterate_dir, 0, false },
    { "filldir64", 6, (void *)ph_before_filldir64, NULL, 0, false },
    { "filldir", 6, (void *)ph_before_filldir, NULL, 0, false },
};

static int ph_hooks_install(void)
{
    int n = 0;

    for (unsigned i = 0; i < sizeof(g_hooks) / sizeof(g_hooks[0]); i++) {
        hook_err_t err;

        if (g_hooks[i].installed) {
            n++;
            continue;
        }
        if (!g_hooks[i].addr) {
            g_hooks[i].addr = kallsyms_lookup_name(g_hooks[i].name);
            if (!g_hooks[i].addr) {
                LOGW("symbol not found: %s\n", g_hooks[i].name);
                continue;
            }
        }
        err = hook_wrap((void *)g_hooks[i].addr, g_hooks[i].argno, g_hooks[i].before, g_hooks[i].after, NULL);
        if (err) {
            LOGE("hook %s failed: %d\n", g_hooks[i].name, err);
            continue;
        }
        g_hooks[i].installed = true;
        n++;
        LOGI("hooked %s at %lx\n", g_hooks[i].name, g_hooks[i].addr);
    }
    return n;
}

static void ph_hooks_uninstall(void)
{
    int n = 0;

    for (unsigned i = 0; i < sizeof(g_hooks) / sizeof(g_hooks[0]); i++) {
        if (!g_hooks[i].installed) continue;
        hook_unwrap((void *)g_hooks[i].addr, g_hooks[i].before, g_hooks[i].after);
        g_hooks[i].installed = false;
        n++;
    }
    if (n) LOGI("unhooked %d\n", n);
}

/* Hooks are only needed while hiding or probing. */
static void ph_hooks_sync(void)
{
    if (g_hide || g_probe_uid >= 0)
        ph_hooks_install();
    else
        ph_hooks_uninstall();
}

/* control */

static void ph_reply(char *__user out_msg, int outlen, const char *msg)
{
    int len = 0;

    if (!out_msg || outlen <= 0) return;
    while (msg[len] && len < outlen - 1)
        len++;
    compat_copy_to_user(out_msg, msg, len + 1);
}

static int ph_resolve_path(const char *path, struct ph_entry *e)
{
    struct ph_path p = { 0 };
    void *inode;
    int err;

    if (!g_kern_path || !g_path_put) return -ENOSYS;

    err = g_kern_path(path, PH_LOOKUP_FOLLOW, &p);
    if (err) return err;

    inode = p.dentry ? dentry_inode(p.dentry) : NULL;
    if (!ph_kptr(inode)) {
        g_path_put(&p);
        return -ENOENT;
    }

    e->sb = inode_sb(inode);
    e->ino = inode_ino(inode);
    e->i_uid = inode_uid(inode);
    strscpy(e->path, path, PH_MAX_PATH);

    g_path_put(&p);
    return 0;
}

static void ph_copy_entry(struct ph_entry *dst, const struct ph_entry *src)
{
    dst->sb = src->sb;
    dst->ino = src->ino;
    dst->i_uid = src->i_uid;
    strscpy(dst->path, src->path, PH_MAX_PATH);
}

static int ph_add_path(const char *path)
{
    struct ph_entry tmp;
    int idx, n, err;

    err = ph_resolve_path(path, &tmp);
    if (err) return err;

    idx = ph_active_idx();
    n = smp_load_acquire(&g_entry_count[idx]);
    if (n < 0) n = 0;
    if (n >= PH_MAX_ENTRIES) return -ENOSPC;

    ph_copy_entry(&g_entries[idx][n], &tmp);

    /* Entries are append-only; clear()/reload() only reset the count. */
    smp_store_release(&g_entry_count[idx], n + 1);
    return 0;
}

/* config files */

/*
 * /data/adb/path_hide/paths:
 *   one absolute path per line, '#' comments, blank lines ignored
 *
 * /data/adb/path_hide/config:
 *   hide=1
 *   minuid=10000
 *   probe=off          # or probe=2000
 *   budget=200
 */
struct ph_offsets
{
    int nd_mnt;
    int nd_dentry;
    int nd_flags;
    int dentry_inode;
    int inode_uid;
    int inode_sb;
    int inode_ino;
    int file_inode;
    int cred_security;
    int tsec_sid;
    int tsec_create_sid;
    int tsec_keycreate_sid;
    int tsec_sockcreate_sid;
};

struct ph_cfg
{
    int hide;
    int minuid;
    int probe;
    int budget;
    int budget_set;
    struct ph_offsets offs;
};

static void ph_offsets_default(struct ph_offsets *o)
{
    o->nd_mnt = PH_OFF_ND_PATH_MNT;
    o->nd_dentry = PH_OFF_ND_PATH_DENTRY;
    o->nd_flags = PH_OFF_ND_FLAGS;
    o->dentry_inode = PH_OFF_DENTRY_INODE;
    o->inode_uid = PH_OFF_INODE_UID;
    o->inode_sb = PH_OFF_INODE_SB;
    o->inode_ino = PH_OFF_INODE_INO;
    o->file_inode = PH_OFF_FILE_INODE;
    o->cred_security = PH_OFF_CRED_SECURITY;
    o->tsec_sid = PH_OFF_TSEC_SID;
    o->tsec_create_sid = PH_OFF_TSEC_CREATE_SID;
    o->tsec_keycreate_sid = PH_OFF_TSEC_KEYCREATE_SID;
    o->tsec_sockcreate_sid = PH_OFF_TSEC_SOCKCREATE_SID;
}

static bool ph_off_valid(int v, int align)
{
    return v >= 0 && v < 0x1000 && !(v & (align - 1));
}

static int ph_off_pick(const char *name, int cur, int v, int align)
{
    if (ph_off_valid(v, align)) return v;
    LOGW("offsets: invalid %s=0x%x, keep 0x%x\n", name, (unsigned)v, (unsigned)cur);
    return cur;
}

static void ph_offsets_apply(const struct ph_offsets *o)
{
    g_off_nd_mnt = ph_off_pick("nd_mnt", g_off_nd_mnt, o->nd_mnt, 8);
    g_off_nd_dentry = ph_off_pick("nd_dentry", g_off_nd_dentry, o->nd_dentry, 8);
    g_off_nd_flags = ph_off_pick("nd_flags", g_off_nd_flags, o->nd_flags, 4);
    g_off_dentry_inode = ph_off_pick("dentry_inode", g_off_dentry_inode, o->dentry_inode, 8);
    g_off_inode_uid = ph_off_pick("inode_uid", g_off_inode_uid, o->inode_uid, 4);
    g_off_inode_sb = ph_off_pick("inode_sb", g_off_inode_sb, o->inode_sb, 8);
    g_off_inode_ino = ph_off_pick("inode_ino", g_off_inode_ino, o->inode_ino, 8);
    g_off_file_inode = ph_off_pick("file_inode", g_off_file_inode, o->file_inode, 8);
    g_off_cred_security = ph_off_pick("cred_security", g_off_cred_security, o->cred_security, 8);
    g_off_tsec_sid = ph_off_pick("tsec_sid", g_off_tsec_sid, o->tsec_sid, 4);
    g_off_tsec_create_sid = ph_off_pick("tsec_create_sid", g_off_tsec_create_sid, o->tsec_create_sid, 4);
    g_off_tsec_keycreate_sid = ph_off_pick("tsec_keycreate_sid", g_off_tsec_keycreate_sid, o->tsec_keycreate_sid, 4);
    g_off_tsec_sockcreate_sid =
        ph_off_pick("tsec_sockcreate_sid", g_off_tsec_sockcreate_sid, o->tsec_sockcreate_sid, 4);
}

static int ph_build_paths(int idx, int *ok, int *bad, int *denied)
{
    int len, pos = 0;

    *ok = 0;
    *bad = 0;
    *denied = 0;

    len = ph_read_file(PH_PATHS_FILE, g_filebuf, sizeof(g_filebuf));
    if (len < 0) return len;

    while (pos < len) {
        char *line = g_filebuf + pos;
        char *end = line;
        struct ph_entry tmp;
        int rc;

        while (end < g_filebuf + len && *end != '\n')
            end++;
        if (end < g_filebuf + len) {
            *end = 0;
            pos = (int)(end - g_filebuf) + 1;
        } else {
            pos = len;
        }

        line = ph_trim(line);
        if (!*line || *line == '#') continue;
        if (*ok >= PH_MAX_ENTRIES) {
            (*bad)++;
            continue;
        }
        rc = ph_resolve_path(line, &tmp);
        if (rc == 0) {
            ph_copy_entry(&g_entries[idx][*ok], &tmp);
            (*ok)++;
        } else {
            (*bad)++;
            if (rc == -EACCES || rc == -EPERM) (*denied)++;
        }
    }
    return 0;
}

static void ph_apply_config_line(char *line, struct ph_cfg *cfg)
{
    char *eq = strchr(line, '=');
    char *key, *val;
    u64 v;

    if (!eq) return;
    *eq = 0;
    key = ph_trim(line);
    val = ph_trim(eq + 1);

    if (!strncmp(key, "off_", 4)) {
        if (ph_parse_hex(val, &v)) return;
        if (!strcmp(key, "off_nd_mnt"))
            cfg->offs.nd_mnt = (int)v;
        else if (!strcmp(key, "off_nd_dentry"))
            cfg->offs.nd_dentry = (int)v;
        else if (!strcmp(key, "off_nd_flags"))
            cfg->offs.nd_flags = (int)v;
        else if (!strcmp(key, "off_dentry_inode"))
            cfg->offs.dentry_inode = (int)v;
        else if (!strcmp(key, "off_inode_uid"))
            cfg->offs.inode_uid = (int)v;
        else if (!strcmp(key, "off_inode_sb"))
            cfg->offs.inode_sb = (int)v;
        else if (!strcmp(key, "off_inode_ino"))
            cfg->offs.inode_ino = (int)v;
        else if (!strcmp(key, "off_file_inode"))
            cfg->offs.file_inode = (int)v;
        else if (!strcmp(key, "off_cred_security"))
            cfg->offs.cred_security = (int)v;
        else if (!strcmp(key, "off_tsec_sid"))
            cfg->offs.tsec_sid = (int)v;
        else if (!strcmp(key, "off_tsec_create_sid"))
            cfg->offs.tsec_create_sid = (int)v;
        else if (!strcmp(key, "off_tsec_keycreate_sid"))
            cfg->offs.tsec_keycreate_sid = (int)v;
        else if (!strcmp(key, "off_tsec_sockcreate_sid"))
            cfg->offs.tsec_sockcreate_sid = (int)v;
    } else if (!strcmp(key, "hide")) {
        if (!ph_parse_u64(val, &v)) cfg->hide = !!v;
    } else if (!strcmp(key, "minuid")) {
        if (!ph_parse_u64(val, &v)) cfg->minuid = (int)v;
    } else if (!strcmp(key, "probe")) {
        if (!strcmp(val, "off")) {
            cfg->probe = -1;
        } else if (!ph_parse_u64(val, &v)) {
            cfg->probe = (int)v;
            cfg->budget = PH_PROBE_BUDGET;
            cfg->budget_set = 1;
        }
    } else if (!strcmp(key, "budget")) {
        if (!ph_parse_u64(val, &v)) {
            cfg->budget = (int)v;
            cfg->budget_set = 1;
        }
    }
}

static int ph_parse_config(struct ph_cfg *cfg)
{
    int len, pos = 0;

    cfg->hide = 0;
    cfg->minuid = 10000;
    cfg->probe = -1;
    cfg->budget = PH_PROBE_BUDGET;
    cfg->budget_set = 0;
    ph_offsets_default(&cfg->offs);

    len = ph_read_file(PH_CONFIG_FILE, g_filebuf, sizeof(g_filebuf));
    if (len < 0) return len;

    while (pos < len) {
        char *line = g_filebuf + pos;
        char *end = line;

        while (end < g_filebuf + len && *end != '\n')
            end++;
        if (end < g_filebuf + len) {
            *end = 0;
            pos = (int)(end - g_filebuf) + 1;
        } else {
            pos = len;
        }

        line = ph_trim(line);
        if (!*line || *line == '#') continue;
        ph_apply_config_line(line, cfg);
    }
    return 0;
}

/*
 * Rebuild the registry from the config directory.  The new entries are built
 * into the inactive buffer while the old registry keeps hiding, then swapped
 * in with one release store.  Unlike the previous version there is no window
 * where hidden paths become visible during a reload.
 */
static int ph_reload(int *ok, int *bad)
{
    struct ph_cfg cfg;
    struct ph_cfg best_cfg;
    int idx, newidx, err, cerr, denied = 0;
    int best_ok = 0, best_bad = 0, best_cerr = 0, best_err = 0;
    int best_denied = 0;
    const char *chosen = NULL;
    bool have_best = false;

    *ok = 0;
    *bad = 0;

    idx = ph_active_idx();
    newidx = idx ^ 1;

    /* Attempt 1: the caller's own context. */
    g_reload_uid = current_uid();
    g_reload_active = 1;
    /* Config is read first because both parsers share g_filebuf. */
    cerr = ph_parse_config(&cfg);
    err = ph_build_paths(newidx, ok, bad, &denied);
    g_reload_active = 0;
    g_used_sctx[0] = 0;

    /*
     * App-context callers may be unable to read the config (and may be
     * unable to resolve some registered paths).  Try a root cred with a
     * directly-written SELinux SID for each candidate scontext; use the
     * first one that gets through.
     */
    if (cerr == -EACCES || cerr == -EPERM || err == -EACCES || err == -EPERM || denied) {
        for (int i = 0;; i++) {
            const char *sctx = ph_sctx_candidate(i);
            struct ph_cred cc;
            int ok2 = 0, bad2 = 0, cerr2, err2, denied2 = 0;

            if (!sctx) break;
            if (!ph_priv_begin(&cc, sctx)) continue;

            cerr2 = ph_parse_config(&cfg);
            err2 = ph_build_paths(newidx, &ok2, &bad2, &denied2);
            ph_priv_end(&cc);

            LOGI("reload: sctx %s cerr=%d err=%d denied=%d ok=%d\n", sctx, cerr2, err2, denied2, ok2);

            if (!(cerr2 == -EACCES || cerr2 == -EPERM || err2 == -EACCES || err2 == -EPERM || denied2)) {
                *ok = ok2;
                *bad = bad2;
                cerr = cerr2;
                err = err2;
                denied = denied2;
                chosen = sctx;
                break;
            }

            /* Remember a readable config even if some paths failed. */
            if (!have_best && cerr2 == 0) {
                best_cfg = cfg;
                best_ok = ok2;
                best_bad = bad2;
                best_cerr = cerr2;
                best_err = err2;
                best_denied = denied2;
                have_best = true;
            }
        }

        if (chosen) {
            strscpy(g_used_sctx, chosen, sizeof(g_used_sctx));
            LOGI("reload: using sctx %s\n", chosen);
        } else if (have_best) {
            cfg = best_cfg;
            *ok = best_ok;
            *bad = best_bad;
            cerr = best_cerr;
            err = best_err;
            denied = best_denied;
            LOGW("reload: no sctx fully worked, using best partial\n");
        } else {
            LOGW("reload: no sctx could read %s\n", PH_CONFIG_FILE);
        }
    }

    smp_store_release(&g_entry_count[newidx], *ok);
    smp_store_release(&g_active, newidx);

    ph_offsets_apply(&cfg.offs);

    g_min_uid = cfg.minuid;
    g_probe_uid = cfg.probe;
    if (cfg.budget_set) g_probe_budget = cfg.budget;
    g_hide = cfg.hide;

    ph_hooks_sync();

    LOGI("reload: cerr=%d err=%d denied=%d paths ok=%d fail=%d hide=%d minuid=%d probe=%d\n", cerr, err, denied, *ok,
         *bad, g_hide, g_min_uid, g_probe_uid);
    return err;
}

static long ph_control(const char *args, char *__user out_msg, int outlen)
{
    char reply[512];
    int pos = 0;
    u64 v;

    if (!args) return -EINVAL;

    while (*args == ' ')
        args++;

    if (!strcmp(args, "reload")) {
        int ok, bad;
        int err = ph_reload(&ok, &bad);

        pos = ph_sputs(reply, sizeof(reply), pos, err ? "reload err " : "reload ok ");
        if (err) pos = ph_sput_i64(reply, sizeof(reply), pos, err);
        pos = ph_sputs(reply, sizeof(reply), pos, " paths=");
        pos = ph_sput_u64(reply, sizeof(reply), pos, (u64)ok);
        pos = ph_sputs(reply, sizeof(reply), pos, " fail=");
        pos = ph_sput_u64(reply, sizeof(reply), pos, (u64)bad);
        pos = ph_sputs(reply, sizeof(reply), pos, " hide=");
        pos = ph_sput_u64(reply, sizeof(reply), pos, (u64)g_hide);
        pos = ph_sputs(reply, sizeof(reply), pos, " minuid=");
        pos = ph_sput_u64(reply, sizeof(reply), pos, (u64)g_min_uid);
        ph_reply(out_msg, outlen, reply);
        return 0;
    }

    if (!strncmp(args, "add ", 4)) {
        const char *path = args + 4;
        int err;

        while (*path == ' ')
            path++;
        g_reload_uid = current_uid();
        g_reload_active = 1;
        err = ph_add_path(path);
        g_reload_active = 0;

        if (err == -EACCES || err == -EPERM) {
            for (int i = 0;; i++) {
                const char *sctx = ph_sctx_candidate(i);
                struct ph_cred cc;

                if (!sctx) break;
                if (!ph_priv_begin(&cc, sctx)) continue;
                err = ph_add_path(path);
                ph_priv_end(&cc);
                if (err != -EACCES && err != -EPERM) break;
            }
        }
        pos = ph_sputs(reply, sizeof(reply), pos, err ? "add err " : "add ok ");
        pos = ph_sput_i64(reply, sizeof(reply), pos, err);
        ph_reply(out_msg, outlen, reply);
        return 0;
    }

    if (!strcmp(args, "clear")) {
        smp_store_release(&g_entry_count[ph_active_idx()], 0);
        ph_reply(out_msg, outlen, "cleared");
        return 0;
    }

    if (!strncmp(args, "hide ", 5)) {
        if (ph_parse_u64(args + 5, &v)) return -EINVAL;
        g_hide = !!v;
        ph_hooks_sync();
        pos = ph_sputs(reply, sizeof(reply), pos, "hide=");
        pos = ph_sput_u64(reply, sizeof(reply), pos, (u64)g_hide);
        ph_reply(out_msg, outlen, reply);
        return 0;
    }

    if (!strncmp(args, "minuid ", 7)) {
        if (ph_parse_u64(args + 7, &v)) return -EINVAL;
        g_min_uid = (int)v;
        pos = ph_sputs(reply, sizeof(reply), pos, "minuid=");
        pos = ph_sput_u64(reply, sizeof(reply), pos, (u64)g_min_uid);
        ph_reply(out_msg, outlen, reply);
        return 0;
    }

    if (!strncmp(args, "probe ", 6)) {
        const char *a = args + 6;

        while (*a == ' ')
            a++;
        if (!strcmp(a, "off")) {
            g_probe_uid = -1;
            ph_hooks_sync();
            ph_reply(out_msg, outlen, "probe off");
            return 0;
        }
        if (ph_parse_u64(a, &v)) return -EINVAL;
        g_probe_uid = (int)v;
        g_probe_budget = PH_PROBE_BUDGET;
        ph_hooks_sync();
        pos = ph_sputs(reply, sizeof(reply), pos, "probe uid=");
        pos = ph_sput_u64(reply, sizeof(reply), pos, v);
        ph_reply(out_msg, outlen, reply);
        return 0;
    }

    if (!strncmp(args, "budget ", 7)) {
        if (ph_parse_u64(args + 7, &v)) return -EINVAL;
        g_probe_budget = (int)v;
        ph_reply(out_msg, outlen, "budget reset");
        return 0;
    }

    if (!strcmp(args, "offsets")) {
        pos = ph_sput_off(reply, sizeof(reply), pos, "nd_mnt", g_off_nd_mnt);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "nd_dentry", g_off_nd_dentry);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "nd_flags", g_off_nd_flags);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "dentry_inode", g_off_dentry_inode);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "inode_uid", g_off_inode_uid);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "inode_sb", g_off_inode_sb);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "inode_ino", g_off_inode_ino);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "file_inode", g_off_file_inode);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "cred_security", g_off_cred_security);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "tsec_sid", g_off_tsec_sid);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "tsec_create", g_off_tsec_create_sid);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "tsec_keycreate", g_off_tsec_keycreate_sid);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "tsec_sockcreate", g_off_tsec_sockcreate_sid);
        ph_reply(out_msg, outlen, reply);
        return 0;
    }

    if (!strcmp(args, "selftest")) {
        int old_probe = g_probe_uid;
        int old_budget = g_probe_budget;
        struct ph_path p = { 0 };
        int err = -ENOSYS;

        g_probe_uid = (int)current_uid();
        g_probe_budget = 32;
        ph_hooks_sync();
        if (g_kern_path) {
            err = g_kern_path("/system/build.prop", PH_LOOKUP_FOLLOW, &p);
            if (!err && g_path_put) g_path_put(&p);
        }
        g_probe_uid = old_probe;
        g_probe_budget = old_budget;
        ph_hooks_sync();

        pos = ph_sputs(reply, sizeof(reply), pos, "selftest err=");
        pos = ph_sput_i64(reply, sizeof(reply), pos, err);
        pos = ph_sputs(reply, sizeof(reply), pos, ", check dmesg");
        ph_reply(out_msg, outlen, reply);
        return 0;
    }

    if (!strcmp(args, "status")) {
        int idx;
        int n = ph_entry_snapshot(&idx);

        pos = ph_sputs(reply, sizeof(reply), pos, "ver=");
        pos = ph_sputs(reply, sizeof(reply), pos, PH_VERSION);
        pos = ph_sputs(reply, sizeof(reply), pos, " hide=");
        pos = ph_sput_u64(reply, sizeof(reply), pos, (u64)g_hide);
        pos = ph_sputs(reply, sizeof(reply), pos, " minuid=");
        pos = ph_sput_u64(reply, sizeof(reply), pos, (u64)g_min_uid);
        pos = ph_sputs(reply, sizeof(reply), pos, " probe=");
        pos = ph_sput_i64(reply, sizeof(reply), pos, g_probe_uid);
        pos = ph_sputs(reply, sizeof(reply), pos, " budget=");
        pos = ph_sput_i64(reply, sizeof(reply), pos, g_probe_budget);
        pos = ph_sputs(reply, sizeof(reply), pos, " entries=");
        pos = ph_sput_u64(reply, sizeof(reply), pos, (u64)n);
        pos = ph_sputs(reply, sizeof(reply), pos, " sctx=");
        pos = ph_sputs(reply, sizeof(reply), pos, g_used_sctx[0] ? g_used_sctx : "none");
        ph_reply(out_msg, outlen, reply);
        return 0;
    }

    if (!strcmp(args, "list")) {
        int idx;
        int n = ph_entry_snapshot(&idx);

        for (int i = 0; i < n && pos < (int)sizeof(reply) - 1; i++) {
            pos = ph_sputs(reply, sizeof(reply), pos, g_entries[idx][i].path);
            pos = ph_sputs(reply, sizeof(reply), pos, " ino=");
            pos = ph_sput_u64(reply, sizeof(reply), pos, g_entries[idx][i].ino);
            pos = ph_sputs(reply, sizeof(reply), pos, "\n");
        }
        if (pos == 0) pos = ph_sputs(reply, sizeof(reply), pos, "(empty)");
        ph_reply(out_msg, outlen, reply);
        return 0;
    }

    ph_reply(out_msg, outlen,
             "usage: reload | offsets | selftest | add <path> | clear | hide <0|1> | "
             "minuid <n> | probe <uid|off> | budget <n> | status | list");
    return 0;
}

/* lifecycle */

static long ph_init(const char *args, const char *event, void *reserved)
{
    int resolved = 0;

    (void)event;
    (void)reserved;

    /* Load arg: "sctx=u:r:su:s0" overrides the scontext candidate list. */
    if (args) {
        const char *p = args;

        while (*p == ' ')
            p++;
        if (!strncmp(p, "sctx=", 5)) {
            const char *v = p + 5;
            int n = 0;

            while (v[n] && v[n] != ' ' && n < (int)sizeof(g_sctx_override) - 1) {
                g_sctx_override[n] = v[n];
                n++;
            }
            g_sctx_override[n] = 0;
            if (g_sctx_override[0]) LOGI("load arg: sctx=%s\n", g_sctx_override);
        }
    }

    g_dentry_path_raw = (ph_dentry_path_raw_t)kallsyms_lookup_name("dentry_path_raw");
    g_kern_path = (ph_kern_path_t)kallsyms_lookup_name("kern_path");
    g_path_put = (ph_path_put_t)kallsyms_lookup_name("path_put");
    g_dput = (ph_dput_t)kallsyms_lookup_name("dput");
    g_ilookup = (ph_ilookup_t)kallsyms_lookup_name("ilookup");
    g_iput = (ph_iput_t)kallsyms_lookup_name("iput");
    g_filp_open = (ph_filp_open_t)kallsyms_lookup_name("filp_open");
    g_kernel_read = (ph_kernel_read_t)kallsyms_lookup_name("kernel_read");
    g_filp_close = (ph_filp_close_t)kallsyms_lookup_name("filp_close");
    g_prepare_kernel_cred = (ph_prepare_kernel_cred_t)kallsyms_lookup_name("prepare_kernel_cred");
    g_override_creds = (ph_override_creds_t)kallsyms_lookup_name("override_creds");
    g_revert_creds = (ph_revert_creds_t)kallsyms_lookup_name("revert_creds");
    g_put_cred = (ph_put_cred_t)kallsyms_lookup_name("__put_cred");
    g_secctx_to_secid = (ph_secctx_to_secid_t)kallsyms_lookup_name("security_secctx_to_secid");
    g_selinux_cred_getsecid = (ph_selinux_cred_getsecid_t)kallsyms_lookup_name("selinux_cred_getsecid");

    for (unsigned i = 0; i < sizeof(g_hooks) / sizeof(g_hooks[0]); i++) {
        g_hooks[i].addr = kallsyms_lookup_name(g_hooks[i].name);
        if (g_hooks[i].addr)
            resolved++;
        else
            LOGW("symbol not found: %s\n", g_hooks[i].name);
    }

    LOGI("loaded: hooks_resolved=%d hide=%d minuid=%d "
         "(dentry_path_raw=%lx kern_path=%lx dput=%lx ilookup=%lx "
         "filp_open=%lx kernel_read=%lx)\n",
         resolved, g_hide, g_min_uid, (unsigned long)g_dentry_path_raw, (unsigned long)g_kern_path,
         (unsigned long)g_dput, (unsigned long)g_ilookup, (unsigned long)g_filp_open, (unsigned long)g_kernel_read);

    /* Load /data/local/tmp/path_hide/{paths,config} if present. */
    {
        int ok = 0, bad = 0;
        int err = ph_reload(&ok, &bad);

        if (err == -ENOENT)
            LOGI("no %s yet, registry empty\n", PH_PATHS_FILE);
        else if (err)
            LOGW("initial reload failed: %d\n", err);
    }

    LOGI("offsets: nd_mnt=%x nd_dentry=%x nd_flags=%x dentry_inode=%x "
         "inode_uid=%x inode_sb=%x inode_ino=%x file_inode=%x "
         "cred_security=%x tsec_sid=%x tsec_create=%x tsec_keycreate=%x "
         "tsec_sockcreate=%x\n",
         (unsigned)g_off_nd_mnt, (unsigned)g_off_nd_dentry, (unsigned)g_off_nd_flags, (unsigned)g_off_dentry_inode,
         (unsigned)g_off_inode_uid, (unsigned)g_off_inode_sb, (unsigned)g_off_inode_ino, (unsigned)g_off_file_inode,
         (unsigned)g_off_cred_security, (unsigned)g_off_tsec_sid, (unsigned)g_off_tsec_create_sid,
         (unsigned)g_off_tsec_keycreate_sid, (unsigned)g_off_tsec_sockcreate_sid);

    return 0;
}

static long ph_exit(void *reserved)
{
    (void)reserved;

    ph_hooks_uninstall();

    LOGI("exit\n");
    return 0;
}

KPM_NAME("path_hide");
KPM_VERSION(PH_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Prslc");
KPM_DESCRIPTION("Probe and hide VFS paths (4.19.157 munch)");

KPM_INIT(ph_init);
KPM_CTL0(ph_control);
KPM_EXIT(ph_exit);
