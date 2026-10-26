#include "ph_internal.h"

/* config state */
volatile int g_hide;
volatile int g_min_uid = 10000;
volatile int g_probe_uid = -1;
volatile int g_probe_budget;
volatile int g_reload_active;
volatile uid_t g_reload_uid;
char g_sctx_override[64];
char g_used_sctx[64];

/* reload() is serialized: init runs before control can be called. */
static char g_filebuf[PH_FILEBUF];

/* runtime offsets; defaults from path_hide.h, overridable from config */
int g_off_nd_mnt = PH_OFF_ND_PATH_MNT;
int g_off_nd_dentry = PH_OFF_ND_PATH_DENTRY;
int g_off_nd_flags = PH_OFF_ND_FLAGS;
int g_off_dentry_inode = PH_OFF_DENTRY_INODE;
int g_off_inode_uid = PH_OFF_INODE_UID;
int g_off_inode_sb = PH_OFF_INODE_SB;
int g_off_inode_ino = PH_OFF_INODE_INO;
int g_off_file_inode = PH_OFF_FILE_INODE;
int g_off_file_dentry = PH_OFF_FILE_DENTRY;
int g_off_vma_file = PH_OFF_VMA_FILE;
int g_off_seq_count = PH_OFF_SEQ_COUNT;
int g_off_task_fs = PH_OFF_TASK_FS;
int g_off_fs_pwd_dentry = PH_OFF_FS_PWD_DENTRY;
int g_off_fs_seq = PH_OFF_FS_SEQ;
int g_off_cred_security = PH_OFF_CRED_SECURITY;
int g_off_tsec_sid = PH_OFF_TSEC_SID;
int g_off_tsec_create_sid = PH_OFF_TSEC_CREATE_SID;
int g_off_tsec_keycreate_sid = PH_OFF_TSEC_KEYCREATE_SID;
int g_off_tsec_sockcreate_sid = PH_OFF_TSEC_SOCKCREATE_SID;

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
static const char *const ph_cred_sctx[] = {
    "u:r:magisk:s0",
};

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

/* Add a path, retrying with a privileged scontext if SELinux denies it. */
int ph_add_path_priv(const char *path)
{
    int err;

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
    return err;
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
    o->file_dentry = PH_OFF_FILE_DENTRY;
    o->vma_file = PH_OFF_VMA_FILE;
    o->seq_count = PH_OFF_SEQ_COUNT;
    o->task_fs = PH_OFF_TASK_FS;
    o->fs_pwd_dentry = PH_OFF_FS_PWD_DENTRY;
    o->fs_seq = PH_OFF_FS_SEQ;
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
    g_off_file_dentry = ph_off_pick("file_dentry", g_off_file_dentry, o->file_dentry, 8);
    g_off_vma_file = ph_off_pick("vma_file", g_off_vma_file, o->vma_file, 8);
    g_off_seq_count = ph_off_pick("seq_count", g_off_seq_count, o->seq_count, 8);
    g_off_task_fs = ph_off_pick("task_fs", g_off_task_fs, o->task_fs, 8);
    g_off_fs_pwd_dentry = ph_off_pick("fs_pwd_dentry", g_off_fs_pwd_dentry, o->fs_pwd_dentry, 8);
    g_off_fs_seq = ph_off_pick("fs_seq", g_off_fs_seq, o->fs_seq, 4);
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
        else if (!strcmp(key, "off_file_dentry"))
            cfg->offs.file_dentry = (int)v;
        else if (!strcmp(key, "off_vma_file"))
            cfg->offs.vma_file = (int)v;
        else if (!strcmp(key, "off_seq_count"))
            cfg->offs.seq_count = (int)v;
        else if (!strcmp(key, "off_task_fs"))
            cfg->offs.task_fs = (int)v;
        else if (!strcmp(key, "off_fs_pwd_dentry"))
            cfg->offs.fs_pwd_dentry = (int)v;
        else if (!strcmp(key, "off_fs_seq"))
            cfg->offs.fs_seq = (int)v;
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
int ph_reload(int *ok, int *bad)
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
