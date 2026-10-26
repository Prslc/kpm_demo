#ifndef _KPM_PATH_HIDE_INTERNAL_H
#define _KPM_PATH_HIDE_INTERNAL_H

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
#define PH_DIR_MAP_N 32

struct ph_path
{
    void *mnt;
    void *dentry;
};

struct ph_entry
{
    u64 sb;
    u64 ino;
    u32 i_uid;
    char path[PH_MAX_PATH];
};

struct ph_dir_slot
{
    void *ctx;
    void *sb;
    volatile int state; /* 0 free, -1 claiming, 1 ready */
};

struct ph_cred
{
    const void *old;
    void *new;
};

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
    int vma_file;
    int seq_count;
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

struct ph_hook
{
    const char *name;
    int argno;
    void *before;
    void *after;
    unsigned long addr;
    bool installed;
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

/* resolved once in path_hide.c */
extern ph_dentry_path_raw_t g_dentry_path_raw;
extern ph_kern_path_t g_kern_path;
extern ph_path_put_t g_path_put;
extern ph_dput_t g_dput;
extern ph_ilookup_t g_ilookup;
extern ph_iput_t g_iput;
extern ph_filp_open_t g_filp_open;
extern ph_kernel_read_t g_kernel_read;
extern ph_filp_close_t g_filp_close;
extern ph_prepare_kernel_cred_t g_prepare_kernel_cred;
extern ph_override_creds_t g_override_creds;
extern ph_revert_creds_t g_revert_creds;
extern ph_put_cred_t g_put_cred;
extern ph_secctx_to_secid_t g_secctx_to_secid;
extern ph_selinux_cred_getsecid_t g_selinux_cred_getsecid;

/* config state, defined in ph_config.c */
extern volatile int g_hide;
extern volatile int g_min_uid;
extern volatile int g_probe_uid;
extern volatile int g_probe_budget;
extern volatile int g_reload_active;
extern volatile uid_t g_reload_uid;
extern char g_sctx_override[64];
extern char g_used_sctx[64];

/* runtime offsets, defined in ph_config.c */
extern int g_off_nd_mnt;
extern int g_off_nd_dentry;
extern int g_off_nd_flags;
extern int g_off_dentry_inode;
extern int g_off_inode_uid;
extern int g_off_inode_sb;
extern int g_off_inode_ino;
extern int g_off_file_inode;
extern int g_off_vma_file;
extern int g_off_seq_count;
extern int g_off_cred_security;
extern int g_off_tsec_sid;
extern int g_off_tsec_create_sid;
extern int g_off_tsec_keycreate_sid;
extern int g_off_tsec_sockcreate_sid;

/* registry, defined in ph_registry.c */
extern struct ph_entry g_entries[2][PH_MAX_ENTRIES];
extern volatile int g_entry_count[2];
extern volatile int g_active;
extern struct ph_dir_slot g_dir_slots[PH_DIR_MAP_N];

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

/* ph_util.c */
bool ph_krange(const void *p);
bool ph_kptr(const void *p);
int ph_parse_u64(const char *s, u64 *out);
int ph_parse_hex(const char *s, u64 *out);
int ph_sputs(char *buf, int cap, int pos, const char *s);
int ph_sput_u64(char *buf, int cap, int pos, u64 v);
int ph_sput_i64(char *buf, int cap, int pos, long v);
int ph_sput_hex(char *buf, int cap, int pos, u64 v);
int ph_sput_off(char *buf, int cap, int pos, const char *name, int v);
char *ph_trim(char *s);
u32 ph_strlen(const char *s);
int ph_atomic_dec_and_test(int *p);

/* ph_registry.c */
int ph_active_idx(void);
int ph_entry_snapshot(int *idx);
bool ph_match_inode(void *inode);
bool ph_match_ino(u64 ino);
bool ph_match_readdir(void *ctx, u64 ino);
void ph_dir_sb_store(void *ctx, void *sb);
void ph_dir_sb_remove(void *ctx);
void *ph_dir_sb_lookup(void *ctx);

/* ph_config.c */
int ph_reload(int *ok, int *bad);
int ph_add_path_priv(const char *path);

/* ph_hooks.c */
int ph_hooks_resolve(void);
int ph_hooks_install(void);
void ph_hooks_uninstall(void);
void ph_hooks_sync(void);

/* ph_control.c */
long ph_control(const char *args, char *__user out_msg, int outlen);

#endif /* _KPM_PATH_HIDE_INTERNAL_H */
