#ifndef EXECD_H
#define EXECD_H

#include <mach/mach.h>
#include <stdint.h>
#include <stdbool.h>

// Max concurrently traced processes. RootHide keeps an unbounded dictionary;
// a small fixed table is plenty here (one entry per no-inject app launch).
#define EXECD_MAX_TRACES 32

// Control protocol. Send with mach_msg; reply carries a single int64 result.
enum {
	EXECD_OP_TRACE_START  = 1,
	EXECD_OP_TRACE_CANCEL = 2,
};

struct execd_msg {
	mach_msg_header_t hdr;
	int64_t op;
	int32_t pid;
	int32_t _pad;
	uint64_t traced_flag_addr;
	uint64_t detached_flag_addr;
};

struct execd_reply {
	mach_msg_header_t hdr;
	int64_t result;
};

// Start tracing pid so its next exec* is observed. traced_flag_addr and
// detached_flag_addr are addresses in the target used to signal trace state
// back to the target itself (RootHide's mechanism); pass 0 to skip.
int execd_trace_start(pid_t pid, uint64_t traced_flag_addr, uint64_t detached_flag_addr);

// Cancel an in-flight trace: the pending SIGTRAP is treated as a cancel, the
// saved ports are restored and the process detaches.
int execd_trace_cancel(pid_t pid, uint64_t detached_flag_addr);

// The patch step run between "exec detected" and "ports restored".
//
// NOTE: this must be installed from *inside* execd. A function pointer cannot
// cross a process boundary, so launchdhook (a different process) cannot call
// this. Until execd has its own patch implementation, g_patch_hook stays NULL
// and execd only does the exception-port save/restore half of the trace.
void execd_set_patch_hook(int (*hook)(pid_t pid));

#endif // EXECD_H
