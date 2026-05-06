#ifndef _KPM_PTY_HIDE_H
#define _KPM_PTY_HIDE_H

#define __NR_newfstatat  79
#define __NR_statx       291

#define STAT_UID_OFFSET  24
#define STATX_UID_OFFSET 20

#define LOG_PREFIX "[pty_hide] "

#define LOGI(fmt, ...) pr_info(LOG_PREFIX fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) pr_warn(LOG_PREFIX fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) pr_err(LOG_PREFIX fmt, ##__VA_ARGS__)

#endif