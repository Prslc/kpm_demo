/* SPDX-License-Identifier: GPL-2.0 */

/*
 * KP ABI shim for uts_namespace
 *
 * Source reference:
 *   Linux kernel v4.19.325
 *   include/linux/utsname.h
 *   https://elixir.bootlin.com/linux/v4.19.325/source/include/linux/utsname.h
 *
 * NOTE:
 *   Reduced ABI model for KP runtime only.
 *   Not a full kernel structure.
 */

#include <ktypes.h>

enum {
    KP_UTS_LEN = 65
};

struct kp_uts_name {
    char sysname[KP_UTS_LEN];
    char nodename[KP_UTS_LEN];
    char release[KP_UTS_LEN];
    char version[KP_UTS_LEN];
    char machine[KP_UTS_LEN];
    char domainname[KP_UTS_LEN];
};

struct kp_uts_namespace {
    struct kp_uts_name name;
    void *reserved[4];
};