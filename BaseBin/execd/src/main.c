// execd — a standalone daemon that performs RootHide-style exec* tracing.
//
// Why this is a separate process (and not part of launchd):
//   ptrace(PT_ATTACHEXC) makes the caller the exception handler of the target.
//   Doing that inside launchd (pid 1) creates a launchd -> ptrace -> kernel ->
//   amfi -> launchd cycle. This is the same deadlock RootHide documents in its
//   jailbreakd server ("dead lock: jbd->ptrace->kernel->amfi port->launchd->
//   spawn amfid->jdb"); RootHide solves it by running exec tracing in a normal
//   userspace daemon. This file is that daemon.
//
// What it does:
//   1. Saves the target's current exception ports (so detection later sees the
//      same ports it would have seen with no jailbreak at all).
//   2. Installs its own exception port on the target and attaches with
//      PT_ATTACHEXC, so the target's exec* raises an EXC_SOFTWARE/EXC_SOFT_SIGNAL
//      to us instead of running unobserved.
//   3. On the SIGTRAP that marks the exec, restores the saved ports exactly and
//      PT_DETACHes. The target then looks untouched: no jailbreak exception
//      ports, no leftover signal handlers from the tracing itself.
//
// This mirrors RootHide's libroothider/src/exec_trace.m. The port save/restore
// logic is the whole point; the patching step that RootHide runs in between is
// intentionally left to a callback (g_patch_hook), because the patch function in
// Dopamine differs from RootHide's roothide_patch_proc.

#include <mach/mach.h>
#include <mach/exception_types.h>
#include <mach/thread_status.h>
#include <mach/arm/thread_status.h>
#include <mach/vm_map.h>
#include <mach/mach_types.h>
#include <mach/ndr.h>
#include <mach/exc.h>
#include <mach/message.h>

#include <mach-o/dyld_images.h>

#include <bsm/libbsm.h>
#include <errno.h>
#include <libproc.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

#include "execd.h"

// The public SDK ships sys/ptrace.h (it has PT_ATTACHEXC), but the enum values
// needed here are also defined in execd.h so the daemon does not depend on a
// particular SDK revision layout.
#ifndef PT_ATTACHEXC
#define PT_ATTACHEXC 14
#endif
#ifndef PT_DETACH
#define PT_DETACH 11
#endif
#ifndef PT_CONTINUE
#define PT_CONTINUE 7
#endif

#define EXECD_LOG_PATH "/var/mobile/Documents/execd_log.txt"

static void execd_log(const char *fmt, ...)
{
	FILE *f = fopen(EXECD_LOG_PATH, "a");
	if (!f) return;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fputc('\n', f);
	fclose(f);
}

// ---------------------------------------------------------------------------
// trace bookkeeping (one entry per traced pid)
// ---------------------------------------------------------------------------

typedef struct {
	pid_t pid;
	bool cancelled;

	// Flag words in the target's address space. The target writes 1 into
	// traced_flag once the tracer has taken it over; cancelled marks a cancel
	// in flight so the SIGTRAP handler can tell an exec from a cancel.
	uint64_t traced_flag_addr;
	uint64_t detached_flag_addr;

	mach_port_t task;

	// Saved exception ports, restored verbatim before detaching.
	exception_mask_t saved_masks[EXC_TYPES_COUNT];
	mach_port_t saved_ports[EXC_TYPES_COUNT];
	exception_behavior_t saved_behaviors[EXC_TYPES_COUNT];
	thread_state_flavor_t saved_flavors[EXC_TYPES_COUNT];
	mach_msg_type_number_t saved_exception_types_count;
} execd_trace_t;

static pthread_mutex_t g_trace_lock = PTHREAD_MUTEX_INITIALIZER;
static execd_trace_t *g_traces[EXECD_MAX_TRACES];

// Called once the target has exec'ed and before the ports are restored. Kept as
// a hook so this daemon stays independent of Dopamine's patch implementation.
static int (*g_patch_hook)(pid_t pid) = NULL;

void execd_set_patch_hook(int (*hook)(pid_t pid))
{
	g_patch_hook = hook;
}

static execd_trace_t *trace_lookup_locked(pid_t pid)
{
	for (int i = 0; i < EXECD_MAX_TRACES; i++) {
		if (g_traces[i] && g_traces[i]->pid == pid) return g_traces[i];
	}
	return NULL;
}

static void trace_remove_locked(execd_trace_t *trace)
{
	for (int i = 0; i < EXECD_MAX_TRACES; i++) {
		if (g_traces[i] == trace) {
			g_traces[i] = NULL;
			break;
		}
	}
	// Drop the refs we took when saving the ports.
	for (mach_msg_type_number_t i = 0; i < trace->saved_exception_types_count; i++) {
		if (MACH_PORT_VALID(trace->saved_ports[i])) {
			mach_port_deallocate(mach_task_self(), trace->saved_ports[i]);
		}
	}
	// The task port taken by task_for_pid in execd_trace_start. It is also
	// overwritten with the MIG-sent port in the exception handler, but that one
	// belongs to the message and is released there.
	if (MACH_PORT_VALID(trace->task)) {
		mach_port_deallocate(mach_task_self(), trace->task);
	}
	free(trace);
}

// ---------------------------------------------------------------------------
// exception server thread
// ---------------------------------------------------------------------------

static mach_port_t g_exception_port = MACH_PORT_NULL;

static void execd_restore_ports(execd_trace_t *trace, mach_port_t task)
{
	for (mach_msg_type_number_t i = 0; i < trace->saved_exception_types_count; i++) {
		kern_return_t kr = task_set_exception_ports(task,
			trace->saved_masks[i], trace->saved_ports[i],
			trace->saved_behaviors[i], trace->saved_flavors[i]);
		if (kr != KERN_SUCCESS) {
			execd_log("restore port[%u] failed: 0x%x", i, kr);
		}
	}
}

// Simplified exception handler. Uses the SDK's exception_raise MIG layout
// (mach/exc.h). The daemon only needs the exception type and code, not the
// register state, so the reply can be generic.
static void execd_handle_exception(mach_msg_header_t *msg, mach_port_t reply_port)
{
	__Request__exception_raise_t *req = (__Request__exception_raise_t *)msg;

	mach_port_t task_port = req->task.name;
	mach_port_t thread_port = req->thread.name;

	pid_t pid = 0;
	kern_return_t kr = pid_for_task(task_port, &pid);

	if (kr != KERN_SUCCESS || pid <= 0) {
		execd_log("pid_for_task failed: 0x%x", kr);
		goto reply;
	}

	pthread_mutex_lock(&g_trace_lock);
	execd_trace_t *trace = trace_lookup_locked(pid);

	if (!trace) {
		pthread_mutex_unlock(&g_trace_lock);
		goto reply;
	}

	if (req->exception != EXC_SOFTWARE || req->codeCnt != 2 || req->code[0] != EXC_SOFT_SIGNAL) {
		// Some other exception on a traced process: let it run and stay traced.
		pthread_mutex_unlock(&g_trace_lock);
		ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
		goto reply;
	}

	int signo = req->code[1];

	if (signo == SIGSTOP) {
		// Attach complete: resume immediately.
		pthread_mutex_unlock(&g_trace_lock);
		ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
		goto reply;
	}

	if (signo != SIGTRAP) {
		// Any other signal delivered while traced: pass it back to the target by
		// resuming with that signal, otherwise the process would hang here.
		int sig = (signo > 0 && signo < NSIG) ? signo : 0;
		pthread_mutex_unlock(&g_trace_lock);
		ptrace(PT_CONTINUE, pid, (caddr_t)1, sig);
		goto reply;
	}

	// SIGTRAP: either a real exec* or a cancel request. Decide which, but do the
	// expensive work (patching) with the lock dropped: the patch path can block
	// for a long time and must not stall start/cancel or re-enter this handler.
	bool cancelled = trace->cancelled;
	pthread_mutex_unlock(&g_trace_lock);

	if (!cancelled) {
		// Confirm this is really an exec before patching: dyld has not populated
		// its image list yet at this instant.
		bool isExec = false;
		uint32_t infoArrayCount = 0;
		vm_size_t readSize = 0;
		task_dyld_info_data_t dyldInfo = {0};
		mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
		kern_return_t tr = task_info(task_port, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
		if (tr == KERN_SUCCESS && dyldInfo.all_image_info_addr != 0) {
			uint64_t cntAddr = dyldInfo.all_image_info_addr
				+ offsetof(struct dyld_all_image_infos, infoArrayCount);
			tr = vm_read_overwrite(task_port, (vm_address_t)cntAddr,
				sizeof(infoArrayCount), (vm_address_t)&infoArrayCount, &readSize);
		}
		isExec = (tr == KERN_SUCCESS && readSize == sizeof(infoArrayCount) && infoArrayCount == 0);

		int (*patch)(pid_t) = g_patch_hook;
		if (isExec && patch) {
			if (patch(pid) != 0) {
				execd_log("patch hook failed for pid %d", pid);
			}
		}
		execd_log("exec detected for pid %d (isExec=%d)", pid, isExec);
	}

	// Restore the exact ports that were there before we attached, then detach.
	// This is the step that makes the target indistinguishable from a process
	// that was never traced.
	pthread_mutex_lock(&g_trace_lock);
	execd_restore_ports(trace, task_port);
	ptrace(PT_DETACH, pid, NULL, 0);
	trace_remove_locked(trace);
	pthread_mutex_unlock(&g_trace_lock);

reply:;
	// Reply header: mirror the send right back, id + 100 per the MIG convention.
	__Reply__exception_raise_t reply = {0};
	reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(msg->msgh_bits), 0);
	reply.Head.msgh_size = sizeof(reply);
	reply.Head.msgh_remote_port = msg->msgh_remote_port;
	reply.Head.msgh_local_port = MACH_PORT_NULL;
	reply.Head.msgh_id = msg->msgh_id + 100;
	reply.RetCode = KERN_SUCCESS;

	mach_msg(&reply.Head, MACH_SEND_MSG, reply.Head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

	if (MACH_PORT_VALID(task_port)) mach_port_deallocate(mach_task_self(), task_port);
	if (MACH_PORT_VALID(thread_port)) mach_port_deallocate(mach_task_self(), thread_port);
}

static void *exception_server(void *arg)
{
	mach_port_t port = (mach_port_t)(uintptr_t)arg;
	const vm_size_t bufSize = 4096;

	for (;;) {
		mach_msg_header_t *msg = malloc(bufSize);
		if (!msg) { usleep(10 * 1000); continue; }
		memset(msg, 0, bufSize);
		msg->msgh_size = bufSize;

		mach_msg_return_t ret = mach_msg(msg, MACH_RCV_MSG | MACH_RCV_LARGE, 0, bufSize,
			port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		if (ret != MACH_MSG_SUCCESS) {
			free(msg);
			usleep(10 * 1000);
			continue;
		}

		execd_handle_exception(msg, MACH_PORT_NULL);
		free(msg);
	}
	return NULL;
}

// ---------------------------------------------------------------------------
// public API: start / cancel
// ---------------------------------------------------------------------------

int execd_trace_start(pid_t pid, uint64_t traced_flag_addr, uint64_t detached_flag_addr)
{
	if (pid <= 0) return -1;

	pthread_mutex_lock(&g_trace_lock);
	if (trace_lookup_locked(pid)) {
		pthread_mutex_unlock(&g_trace_lock);
		return -2; // already traced
	}

	execd_trace_t *trace = calloc(1, sizeof(*trace));
	if (!trace) { pthread_mutex_unlock(&g_trace_lock); return -3; }
	trace->pid = pid;
	trace->traced_flag_addr = traced_flag_addr;
	trace->detached_flag_addr = detached_flag_addr;

	// task_get/set_exception_ports take a task port, not a pid.
	mach_port_t task = MACH_PORT_NULL;
	kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
	if (kr != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
		execd_log("task_for_pid(%d) failed: 0x%x", pid, kr);
		free(trace);
		pthread_mutex_unlock(&g_trace_lock);
		return -4;
	}
	trace->task = task;

	// task_get_exception_ports takes the array capacity in *count on the way in
	// and reports the filled entry count on the way out. Zero (from calloc)
	// would make the kernel fill nothing.
	trace->saved_exception_types_count = EXC_TYPES_COUNT;

	// Save the target's exception ports before changing anything.
	kr = task_get_exception_ports(task, EXC_MASK_SOFTWARE,
		trace->saved_masks, &trace->saved_exception_types_count,
		trace->saved_ports, trace->saved_behaviors, trace->saved_flavors);
	if (kr != KERN_SUCCESS) {
		execd_log("task_get_exception_ports(%d) failed: 0x%x", pid, kr);
		mach_port_deallocate(mach_task_self(), task);
		free(trace);
		pthread_mutex_unlock(&g_trace_lock);
		return -5;
	}

	bool inserted = false;
	for (int i = 0; i < EXECD_MAX_TRACES; i++) {
		if (!g_traces[i]) { g_traces[i] = trace; inserted = true; break; }
	}
	if (!inserted) {
		// Table full: refuse rather than attach a process we cannot track. An
		// attached-but-untracked target would receive no PT_CONTINUE from the
		// exception handler and stay stopped forever.
		execd_log("trace table full, refusing pid %d", pid);
		mach_port_deallocate(mach_task_self(), task);
		free(trace);
		pthread_mutex_unlock(&g_trace_lock);
		return -8;
	}
	pthread_mutex_unlock(&g_trace_lock);

	// Install our port, then attach. Ordering matters: PT_ATTACHEXC without an
	// exception port set does not reliably pause the target (see RootHide's
	// note in finish_process_trace).
	kr = task_set_exception_ports(task, EXC_MASK_SOFTWARE, g_exception_port,
		EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
	if (kr != KERN_SUCCESS) {
		execd_log("task_set_exception_ports(%d) failed: 0x%x", pid, kr);
		pthread_mutex_lock(&g_trace_lock);
		trace_remove_locked(trace);
		pthread_mutex_unlock(&g_trace_lock);
		return -6;
	}

	if (ptrace(PT_ATTACHEXC, pid, NULL, 0) != 0) {
		execd_log("PT_ATTACHEXC(%d) failed: %d", pid, errno);
		pthread_mutex_lock(&g_trace_lock);
		execd_restore_ports(trace, task);
		trace_remove_locked(trace);
		pthread_mutex_unlock(&g_trace_lock);
		return -7;
	}

	execd_log("tracing pid %d", pid);
	return 0;
}

int execd_trace_cancel(pid_t pid, uint64_t detached_flag_addr)
{
	pthread_mutex_lock(&g_trace_lock);
	execd_trace_t *trace = trace_lookup_locked(pid);
	if (trace) {
		trace->cancelled = true;
		trace->detached_flag_addr = detached_flag_addr;
	}
	pthread_mutex_unlock(&g_trace_lock);
	if (!trace) return -1;
	return kill(pid, SIGTRAP);
}

// ---------------------------------------------------------------------------
// daemon main: checkin with launchd, then serve requests
// ---------------------------------------------------------------------------

static int execd_server_loop(mach_port_t serverPort)
{
	execd_log("execd: server loop start");

	for (;;) {
		struct execd_msg msg = {0};
		mach_msg_return_t mr = mach_msg(&msg.hdr,
			MACH_RCV_MSG | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
			0, sizeof(msg), serverPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		if (mr != MACH_MSG_SUCCESS) continue;

		int64_t result = -1;
		if (msg.op == EXECD_OP_TRACE_START) {
			result = execd_trace_start(msg.pid, msg.traced_flag_addr, msg.detached_flag_addr);
		}
		else if (msg.op == EXECD_OP_TRACE_CANCEL) {
			result = execd_trace_cancel(msg.pid, msg.detached_flag_addr);
		}

		struct execd_reply reply = {0};
		reply.result = result;
		reply.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(msg.hdr.msgh_bits), 0);
		reply.hdr.msgh_size = sizeof(reply);
		reply.hdr.msgh_remote_port = msg.hdr.msgh_remote_port;
		reply.hdr.msgh_local_port = MACH_PORT_NULL;
		reply.hdr.msgh_id = msg.hdr.msgh_id + 100;
		mach_msg(&reply.hdr, MACH_SEND_MSG, reply.hdr.msgh_size, 0,
			MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	}
	return 0;
}

int main(int argc, char **argv)
{
	execd_log("execd: starting");

	// Create the exception port up front: the server thread needs it before any
	// trace can be installed.
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exception_port);
	mach_port_insert_right(mach_task_self(), g_exception_port, g_exception_port, MACH_MSG_TYPE_MAKE_SEND);

	pthread_t exThread;
	pthread_create(&exThread, NULL, exception_server, (void *)(uintptr_t)g_exception_port);

	// Server port for control messages.
	mach_port_t serverPort = MACH_PORT_NULL;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
	mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);

	// Check in with the parent (launchd) the same way hookd does: registered
	// ports passed by posix_spawnattr_set_registered_ports_np.
	mach_port_t *registeredPorts = NULL;
	mach_msg_type_number_t registeredCount = 0;
	kern_return_t kr = mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredCount);
	if (kr != KERN_SUCCESS || registeredCount < 3) {
		execd_log("execd: not launched from launchd, exiting");
		return -1;
	}

	mach_port_t checkinPort = registeredPorts[2];
	if (checkinPort == MACH_PORT_NULL) {
		execd_log("execd: checkinPort is NULL");
		return -1;
	}

	mach_msg_header_t hdr = {0};
	hdr.msgh_size = sizeof(hdr);
	hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
	hdr.msgh_remote_port = checkinPort;
	hdr.msgh_local_port = serverPort;
	hdr.msgh_id = 0x40000000;

	kr = mach_msg(&hdr, MACH_SEND_MSG, hdr.msgh_size, 0, 0, 0, 0);
	if (kr != KERN_SUCCESS) {
		execd_log("execd: checkin send failed 0x%x", kr);
		return -1;
	}
	vm_deallocate(mach_task_self(), (vm_address_t)registeredPorts,
		sizeof(mach_port_t) * registeredCount);

	return execd_server_loop(serverPort);
}
