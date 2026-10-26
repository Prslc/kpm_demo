#include "ph_internal.h"

/* gating */

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

static struct ph_hook g_hooks[] = {
    { "walk_component", 2, NULL, (void *)ph_after_walk_component, 0, false },
    { "lookup_fast", 4, NULL, (void *)ph_after_lookup_fast, 0, false },
    { "complete_walk", 1, NULL, (void *)ph_after_complete_walk, 0, false },
    { "iterate_dir", 2, (void *)ph_before_iterate_dir, (void *)ph_after_iterate_dir, 0, false },
    { "filldir64", 6, (void *)ph_before_filldir64, NULL, 0, false },
    { "filldir", 6, (void *)ph_before_filldir, NULL, 0, false },
};

int ph_hooks_resolve(void)
{
    int n = 0;

    for (unsigned i = 0; i < sizeof(g_hooks) / sizeof(g_hooks[0]); i++) {
        g_hooks[i].addr = kallsyms_lookup_name(g_hooks[i].name);
        if (g_hooks[i].addr)
            n++;
        else
            LOGW("symbol not found: %s\n", g_hooks[i].name);
    }
    return n;
}

int ph_hooks_install(void)
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

void ph_hooks_uninstall(void)
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
void ph_hooks_sync(void)
{
    if (g_hide || g_probe_uid >= 0)
        ph_hooks_install();
    else
        ph_hooks_uninstall();
}
