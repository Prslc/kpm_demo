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

#include "ph_internal.h"

/* resolved once at module load */
ph_dentry_path_raw_t g_dentry_path_raw;
ph_kern_path_t g_kern_path;
ph_path_put_t g_path_put;
ph_dput_t g_dput;
ph_ilookup_t g_ilookup;
ph_iput_t g_iput;
ph_filp_open_t g_filp_open;
ph_kernel_read_t g_kernel_read;
ph_filp_close_t g_filp_close;
ph_prepare_kernel_cred_t g_prepare_kernel_cred;
ph_override_creds_t g_override_creds;
ph_revert_creds_t g_revert_creds;
ph_put_cred_t g_put_cred;
ph_secctx_to_secid_t g_secctx_to_secid;
ph_selinux_cred_getsecid_t g_selinux_cred_getsecid;

static long ph_init(const char *args, const char *event, void *reserved)
{
    int resolved;

    (void)event;
    (void)reserved;

    /* Load arg: "sctx=u:r:magisk:s0" overrides the scontext candidate list. */
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

    resolved = ph_hooks_resolve();

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
