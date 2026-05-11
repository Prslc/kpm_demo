#ifndef _KPM_SELINUX_SHADOW_H
#define _KPM_SELINUX_SHADOW_H

/* Unified list of sensitive security contexts to hide */
static const char *SENSITIVE_TOKENS[] = {
    "magisk",
    "lsposed",
    "xposed",
    "apatch"
};

#define LOG_PREFIX "[selinux_shadow] "

#define LOGI(fmt, ...) pr_info(LOG_PREFIX fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) pr_warn(LOG_PREFIX fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) pr_err(LOG_PREFIX fmt, ##__VA_ARGS__)

#endif