#ifndef EXECD_PROVIDER_H
#define EXECD_PROVIDER_H

#include <sys/types.h>

// Ask execd to prepare a trace on pid: it saves the process's exception ports
// and attaches with PT_ATTACHEXC so the next exec* is observed.
//
// Fire-and-forget: the round trip runs on a background queue because it must
// not block launchd's spawn path.
void execd_trace_process(pid_t pid);

// Cancel an in-flight trace on pid. Also asynchronous.
void execd_trace_process_cancel(pid_t pid);

// SIGKILL execd and drop the send right. Used before a userspace reboot.
void execd_provider_teardown(void);

#endif // EXECD_PROVIDER_H
