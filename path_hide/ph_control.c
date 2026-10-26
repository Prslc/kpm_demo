#include "ph_internal.h"

static void ph_reply(char *__user out_msg, int outlen, const char *msg)
{
    int len = 0;

    if (!out_msg || outlen <= 0) return;
    while (msg[len] && len < outlen - 1)
        len++;
    compat_copy_to_user(out_msg, msg, len + 1);
}

long ph_control(const char *args, char *__user out_msg, int outlen)
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
        err = ph_add_path_priv(path);
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
        pos = ph_sput_off(reply, sizeof(reply), pos, "file_dentry", g_off_file_dentry);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "vma_file", g_off_vma_file);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "seq_count", g_off_seq_count);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "task_fs", g_off_task_fs);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "fs_pwd_dentry", g_off_fs_pwd_dentry);
        pos = ph_sputs(reply, sizeof(reply), pos, " ");
        pos = ph_sput_off(reply, sizeof(reply), pos, "fs_seq", g_off_fs_seq);
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
