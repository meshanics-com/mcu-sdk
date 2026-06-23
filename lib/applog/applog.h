/*
 * applog.h - a small in-RAM ring buffer that captures the agent's own log output
 * so it can be shipped to the control plane on request (the device has no
 * filesystem or journald). A Zephyr log backend feeds it; the agent snapshots it
 * when a heartbeat carries a log request.
 */
#ifndef MESHANICS_APPLOG_H
#define MESHANICS_APPLOG_H

#include <stddef.h>

/*
 * applog_snapshot copies the most recent captured log text (oldest-to-newest
 * within the retained window) into out, NUL-terminated, and returns the number
 * of bytes written (excluding the NUL). The buffer keeps the last
 * CONFIG_MESHANICS_LOG_BUF_SIZE bytes; older lines roll off.
 */
size_t applog_snapshot(char *out, size_t cap);

#endif /* MESHANICS_APPLOG_H */
