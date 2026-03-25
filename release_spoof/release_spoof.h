#ifndef _KPM_RELEASE_SPOOF_H
#define _KPM_RELEASE_SPOOF_H

#define UTS_RELEASE_LEN 65
#define SCAN_SIZE       0x400     // number of bytes scanned

// log
#define LOG_PREFIX "[kpm_release_spoof] "
#define LOGI(fmt, ...) pr_info(LOG_PREFIX fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) pr_warn(LOG_PREFIX fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) pr_err(LOG_PREFIX fmt, ##__VA_ARGS__)

#endif