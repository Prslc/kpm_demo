#ifndef _KPM_PATH_HIDE_H
#define _KPM_PATH_HIDE_H

#define PH_VERSION "0.1.0"

// log
#define LOG_PREFIX "[path_hide] "

#define LOGI(fmt, ...) pr_info(LOG_PREFIX fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) pr_warn(LOG_PREFIX fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) pr_err(LOG_PREFIX fmt, ##__VA_ARGS__)

/*
 * Offsets verified against the device's actual boot image
 * (/home/prslc/Share/boot.img: stock 4.19.157-perf + KernelPatch 0.13.2)
 * and against the stock vendor Image.  KernelPatch only rewrites the first
 * Image entry branch to jump to its appended payload; every kernel text
 * byte (complete_walk / lookup_fast / walk_component / filldir64 /
 * inode_init_always / generic_fillattr / iterate_dir) is byte-identical.
 *
 * This kernel has no BTF and no RANDSTRUCT, so the layout follows
 * declaration order.  Re-derive these if the vendor build changes.
 */
#define PH_OFF_ND_PATH_MNT        0x00 /* nameidata.path.mnt */
#define PH_OFF_ND_PATH_DENTRY     0x08 /* nameidata.path.dentry */
#define PH_OFF_ND_INODE           0x30 /* nameidata.inode */
#define PH_OFF_ND_FLAGS           0x38 /* nameidata.flags */
#define PH_OFF_DENTRY_INODE       0x30 /* dentry.d_inode */
#define PH_OFF_INODE_UID          0x04 /* inode.i_uid (kuid_t) */
#define PH_OFF_INODE_SB           0x28 /* inode.i_sb */
#define PH_OFF_INODE_INO          0x40 /* inode.i_ino */
#define PH_OFF_FILE_INODE         0x20 /* file.f_inode */

/*
 * proc/maps offsets, derived from the actual Image:
 *   show_map_vma(): ldr x21,[vma,#0xa0]   -> vma->vm_file
 *   seq_write():    ldr x9,[seq,#0x18]    -> seq->count
 */
#define PH_OFF_VMA_FILE           0xa0
#define PH_OFF_SEQ_COUNT          0x18

/*
 * SELinux cred/SID offsets, derived from the actual Image:
 *   selinux_cred_getsecid(): ldr x8,[cred,#0x78]; ldr w8,[x8,#0x4]
 *   selinux_kernel_act_as(): tsec = cred->security (0x78); tsec->sid = 0x4
 * struct task_security_struct: osid 0, sid 4, exec_sid 8, create_sid 0xc,
 *                              keycreate_sid 0x10, sockcreate_sid 0x14.
 */
#define PH_OFF_CRED_SECURITY       0x78
#define PH_OFF_TSEC_SID            0x04
#define PH_OFF_TSEC_CREATE_SID     0x0c
#define PH_OFF_TSEC_KEYCREATE_SID  0x10
#define PH_OFF_TSEC_SOCKCREATE_SID 0x14

#define PH_LOOKUP_RCU             0x40 /* nameidata.flags & LOOKUP_RCU */
#define PH_LOOKUP_FOLLOW          0x01 /* kern_path() follow symlinks */

#define PH_MAX_ENTRIES            32
#define PH_MAX_PATH               256
#define PH_PROBE_BUDGET           200

#endif /* _KPM_PATH_HIDE_H */
