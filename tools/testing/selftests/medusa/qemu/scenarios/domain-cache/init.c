// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void result(const char *name, bool passed)
{
	printf("MEDUSA_RESULT domain-cache %s %s\n", name,
	       passed ? "PASS" : "FAIL");
	if (!passed) {
		printf("MEDUSA_DETAIL domain-cache %s errno=%d (%s)\n",
		       name, errno, strerror(errno));
		failures++;
	}
}

static void mount_one(const char *source, const char *target, const char *type)
{
	if (mount(source, target, type, 0, NULL) < 0 && errno != EBUSY)
		perror(target);
}

static void test_ptrace_cache(void)
{
	pid_t pid = fork();
	int status;
	bool denied = false;

	if (pid == 0) {
		alarm(2);
		pause();
		_exit(0);
	}
	if (pid > 0) {
		errno = 0;
		denied = ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0 &&
			 errno == EACCES;
		waitpid(pid, &status, 0);
	}
	result("ptrace_cached_deny", denied);
}

static void test_signal_cache(void)
{
	pid_t pid = fork();
	int status;
	bool denied = false;

	if (pid == 0) {
		alarm(2);
		pause();
		_exit(0);
	}
	if (pid > 0) {
		errno = 0;
		denied = kill(pid, SIGUSR1) < 0 && errno == EACCES;
		waitpid(pid, &status, 0);
	}
	result("signal_cached_deny", denied);
}

static void dump_event_counters(void)
{
	char line[1024];
	FILE *events = fopen("/sys/kernel/security/medusa/events", "r");

	if (!events)
		return;
	while (fgets(line, sizeof(line), events))
		if (strstr(line, "event=ptrace ") ||
		    strstr(line, "event=sendsig "))
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

	test_ptrace_cache();
	test_signal_cache();
	dump_event_counters();
	printf("MEDUSA_RESULT domain-cache complete %s\n",
	       failures ? "FAIL" : "PASS");
	sync();
	reboot(RB_POWER_OFF);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
