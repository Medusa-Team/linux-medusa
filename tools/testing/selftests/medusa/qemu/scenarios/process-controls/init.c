// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void result(const char *name, bool passed)
{
	printf("MEDUSA_RESULT process-controls %s %s\n", name,
	       passed ? "PASS" : "FAIL");
	if (!passed) {
		printf("MEDUSA_DETAIL process-controls %s errno=%d (%s)\n",
		       name, errno, strerror(errno));
		failures++;
	}
}

static void mount_one(const char *source, const char *target, const char *type)
{
	if (mount(source, target, type, 0, NULL) < 0 && errno != EBUSY)
		perror(target);
}

static void test_fork(void)
{
	long denied_clone;
	pid_t pid;
	int status;

	errno = 0;
	denied_clone = syscall(SYS_clone, CLONE_FILES | SIGCHLD,
			       NULL, NULL, NULL, 0);
	if (denied_clone == 0)
		_exit(1);
	if (denied_clone > 0)
		waitpid((pid_t)denied_clone, &status, 0);
	result("fork_deny", denied_clone < 0 && errno == EACCES);

	pid = fork();
	if (pid == 0)
		_exit(0);
	result("fork_allow",
	       pid > 0 && waitpid(pid, &status, 0) == pid &&
	       WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_ptrace(void)
{
	bool denied = false;
	pid_t pid;
	int status;

	pid = fork();
	if (pid == 0) {
		alarm(5);
		pause();
		_exit(0);
	}
	if (pid > 0) {
		errno = 0;
		denied = ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0 &&
			 errno == EACCES;
	}
	if (pid > 0 && !denied &&
	    waitpid(pid, &status, 0) == pid && WIFSTOPPED(status))
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (pid > 0) {
		kill(pid, SIGTERM);
		waitpid(pid, &status, 0);
	}
	result("ptrace_attach_local_deny", denied);

	pid = fork();
	if (pid == 0) {
		errno = 0;
		_exit(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0 &&
		      errno == EACCES ? 0 : 1);
	}
	result("ptrace_traceme_local_deny",
	       pid > 0 && waitpid(pid, &status, 0) == pid &&
	       WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void dump_event_counters(void)
{
	char line[1024];
	FILE *events = fopen("/sys/kernel/security/medusa/events", "r");

	if (!events)
		return;
	while (fgets(line, sizeof(line), events))
		if (strstr(line, "event=fork ") ||
		    strstr(line, "event=ptrace "))
			fputs(line, stdout);
	fclose(events);
}

int main(void)
{
	setenv("PATH", "/sbin:/bin", 1);
	setvbuf(stdout, NULL, _IONBF, 0);
	mount_one("proc", "/proc", "proc");
	mount_one("sysfs", "/sys", "sysfs");
	mount_one("devtmpfs", "/dev", "devtmpfs");
	mount_one("securityfs", "/sys/kernel/security", "securityfs");
	sleep(2);

	test_fork();
	test_ptrace();
	dump_event_counters();
	printf("MEDUSA_RESULT process-controls complete %s\n",
	       failures ? "FAIL" : "PASS");
	sync();
	reboot(RB_POWER_OFF);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
