#ifndef APP_HIDE_MONITOR_H
#define APP_HIDE_MONITOR_H

#include <stdbool.h>

void start_app_hide_monitor(void);
bool app_hide_is_target(const char *executablePath);
void app_hide_perform_hide_sync(void);

#endif