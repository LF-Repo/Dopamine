#include "execd_provider.h"

// The wire protocol lives next to the daemon; both sides must agree on it
// byte for byte, so include that header rather than redeclaring the structs.
// launchdhook's Makefile adds -I../execd/src for this.
#include <execd.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/util.h>
#include <libjailbreak/inline_svc.h>
#include <mach/message.h>
#include <pthread.h>
#include <spawn.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <mach/mach.h>

// execd is spawned the same way hookd is: a checkin port is handed over through
// posix_spawnattr_set_registered_ports_np and the child sends its server port
// back to it. See hookd_provider.c for the reference implementation.
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

static pid_t gExecdPid = -1;
static mach_port_t gExecdPort = MACH_PORT_NULL;

// Upper bound for a synchronous start/cancel round trip. execd replies only
// after the ptrace round trip, which should be quick; a hang here must not
// stall launchd's spawn path indefinitely.
#define EXECD_REPLY_TIMEOUT_MS 5000

static int execd_start(pid_t *pid, mach_port_t *machPort)
{
	mach_port_t checkinPort = MACH_PORT_NULL;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &checkinPort);
	mach_port_insert_right(mach_task_self(), checkinPort, checkinPort, MACH_MSG_TYPE_MAKE_SEND);

	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ MACH_PORT_NULL, MACH_PORT_NULL, checkinPort }, 3);

	const char *envp[] = {
		"_SafeMode=1",
		NULL,
	};

	const char *path = JBROOT_PATH("/basebin/execd");
	int r = posix_spawn(pid, path, NULL, &attr, (char *[]){ (char *)path, NULL }, (char *const *)envp);
	posix_spawnattr_destroy(&attr);
	if (r != 0) {
		mach_port_deallocate(mach_task_self(), checkinPort);
		return r;
	}

	mach_msg_header_t hdr = { 0 };
	hdr.msgh_size = sizeof(hdr) + MAX_TRAILER_SIZE;
	kern_return_t kr = mach_msg(&hdr, MACH_RCV_MSG, 0, hdr.msgh_size, checkinPort, 0, 0);
	mach_port_deallocate(mach_task_self(), checkinPort);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	*machPort = hdr.msgh_remote_port;
	mach_port_mod_refs(mach_task_self(), *machPort, MACH_PORT_RIGHT_SEND, 1);
	mach_msg_destroy(&hdr);

	return 0;
}

// Returns 0 if execd is alive and gExecdPort is usable, otherwise respawns it.
static int execd_ensure_running(void)
{
	if (gExecdPid != -1) {
		int status = 0;
		// Call waitpid as inline syscall, same reason as hookd_provider: a hook
		// close to wait4 can otherwise crash launchd.
		int wpr = waitpid_inline(gExecdPid, &status, WNOHANG);
		if (wpr == 0) return 0; // still running
		gExecdPid = -1;
		if (MACH_PORT_VALID(gExecdPort)) {
			mach_port_deallocate(mach_task_self(), gExecdPort);
			gExecdPort = MACH_PORT_NULL;
		}
	}
	return execd_start(&gExecdPid, &gExecdPort);
}

static int64_t execd_send_command(int64_t op, pid_t targetPid, uint64_t tracedAddr, uint64_t detachedAddr)
{
	if (execd_ensure_running() != 0) {
		return -1;
	}

	struct execd_msg msg = { 0 };
	msg.op = op;
	msg.pid = targetPid;
	msg.traced_flag_addr = tracedAddr;
	msg.detached_flag_addr = detachedAddr;

	mach_port_t replyPort = mig_get_reply_port();

	msg.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	msg.hdr.msgh_size = sizeof(msg);
	msg.hdr.msgh_remote_port = gExecdPort;
	msg.hdr.msgh_local_port = replyPort;
	msg.hdr.msgh_voucher_port = 0;
	msg.hdr.msgh_id = 0x40000000;

	kern_return_t kr = mach_msg(&msg.hdr, MACH_SEND_MSG, msg.hdr.msgh_size, 0, 0, 0, 0);
	if (kr != KERN_SUCCESS) {
		mig_dealloc_reply_port(replyPort);
		return -1;
	}

	struct execd_reply reply = { 0 };
	reply.hdr.msgh_size = sizeof(reply);
	kr = mach_msg(&reply.hdr, MACH_RCV_MSG, 0, reply.hdr.msgh_size, replyPort, EXECD_REPLY_TIMEOUT_MS, 0);
	if (kr != KERN_SUCCESS) {
		// A timeout means execd is wedged; drop it so the next call respawns.
		if (kr == MACH_RCV_TIMED_OUT) {
			kill(gExecdPid, SIGKILL);
		}
		mig_dealloc_reply_port(replyPort);
		return -1;
	}

	int64_t result = reply.result;
	mach_msg_destroy(&reply.hdr);
	return result;
}

struct execd_async_req {
	int64_t op;
	pid_t pid;
};

static void *execd_async_worker(void *arg)
{
	struct execd_async_req *req = (struct execd_async_req *)arg;
	execd_send_command(req->op, req->pid, 0, 0);
	free(req);
	return NULL;
}

// Fire and forget on a detached thread. Must not block: this is called from
// launchd's posix_spawn path, and task_for_pid inside execd pulls in amfid,
// which launchd itself spawns. Blocking here would close that cycle.
static void execd_dispatch_async(int64_t op, pid_t pid)
{
	struct execd_async_req *req = malloc(sizeof(*req));
	if (!req) return;
	req->op = op;
	req->pid = pid;

	pthread_t thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	int r = pthread_create(&thread, &attr, execd_async_worker, req);
	pthread_attr_destroy(&attr);
	if (r != 0) {
		free(req);
	}
}

void execd_trace_process(pid_t pid)
{
	if (pid <= 0) return;
	// Nothing to unwind on failure: execd restores the ports on every failure
	// path, so a failed start just leaves the child untraced.
	execd_dispatch_async(EXECD_OP_TRACE_START, pid);
}

void execd_trace_process_cancel(pid_t pid)
{
	if (pid <= 0) return;
	execd_dispatch_async(EXECD_OP_TRACE_CANCEL, pid);
}

void execd_provider_teardown(void)
{
	if (gExecdPid != -1) {
		int status = 0;
		if (waitpid(gExecdPid, &status, WNOHANG) == 0) {
			kill(gExecdPid, SIGKILL);
			cmd_wait_for_exit(gExecdPid);
		}
		gExecdPid = -1;
	}
	if (MACH_PORT_VALID(gExecdPort)) {
		mach_port_deallocate(mach_task_self(), gExecdPort);
		gExecdPort = MACH_PORT_NULL;
	}
}
