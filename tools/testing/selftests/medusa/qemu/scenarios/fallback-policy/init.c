// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

struct test_message {
	long type;
	char text[8];
};

static int failures;

static void result(const char *name, bool passed)
{
	printf("MEDUSA_RESULT fallback-policy %s %s\n",
	       name, passed ? "PASS" : "FAIL");
	if (!passed)
		failures++;
}

static bool read_file(const char *path, char *buffer, size_t size)
{
	ssize_t count;
	size_t used = 0;
	int fd;

	if (!size)
		return false;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;
	while (used < size - 1) {
		count = read(fd, buffer + used, size - 1 - used);
		if (count < 0) {
			close(fd);
			return false;
		}
		if (!count)
			break;
		used += (size_t)count;
	}
	close(fd);
	buffer[used] = '\0';
	return true;
}

static bool line_has(const char *text, const char *prefix, const char *value)
{
	const char *line = text;

	while (line && *line) {
		const char *end = strchr(line, '\n');
		size_t length = end ? (size_t)(end - line) : strlen(line);

		if (length >= strlen(prefix) &&
		    !strncmp(line, prefix, strlen(prefix)) &&
		    memmem(line, length, value, strlen(value)))
			return true;
		line = end ? end + 1 : NULL;
	}
	return false;
}

static pid_t read_constable_pid(void)
{
	char buffer[32];
	char *end;
	long pid;

	if (!read_file("/constable.pid", buffer, sizeof(buffer)))
		return -1;
	errno = 0;
	pid = strtol(buffer, &end, 10);
	if (errno || end == buffer || pid <= 1)
		return -1;
	return (pid_t)pid;
}

static bool wait_for_disconnect(void)
{
	char status[4096];
	int attempt;

	for (attempt = 0; attempt < 100; attempt++) {
		if (read_file("/sys/kernel/security/medusa/status",
			      status, sizeof(status)) &&
		    strstr(status, "authorization_server=disconnected\n"))
			return true;
		usleep(100000);
	}
	return false;
}

static double monotonic_seconds(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

int main(void)
{
	struct test_message message = { 1, "probe" };
	char events[65536];
	char status[4096];
	double started;
	double elapsed;
	pid_t constable;
	int id;

	setvbuf(stdout, NULL, _IONBF, 0);
	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	mkdir("/sys/kernel/security", 0755);
	mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL);

	sleep(1);
	constable = read_constable_pid();
	result("startup",
	       constable > 1 && kill(constable, 0) == 0 &&
	       read_file("/sys/kernel/security/medusa/status",
			 status, sizeof(status)) &&
	       strstr(status, "authorization_server=connected\n") &&
	       strstr(status, "protocol_state=ready\n"));
	result("policy_installed",
	       read_file("/sys/kernel/security/medusa/events",
			 events, sizeof(events)) &&
	       line_has(events, "event=ipc_msgsnd ",
			"fallback=baseline_deny"));

	id = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
	errno = 0;
	result("installed_deny",
	       id >= 0 &&
	       msgsnd(id, &message, sizeof(message.text), IPC_NOWAIT) < 0 &&
	       errno == EACCES);

	if (constable > 1)
		kill(constable, SIGKILL);
	result("disconnected", wait_for_disconnect());

	started = monotonic_seconds();
	errno = 0;
	result("installed_deny_survives_disconnect",
	       id >= 0 &&
	       msgsnd(id, &message, sizeof(message.text), IPC_NOWAIT) < 0 &&
	       errno == EACCES &&
	       (elapsed = monotonic_seconds() - started) < 1.0);

	if (id >= 0)
		msgctl(id, IPC_RMID, NULL);
	sleep(1);
	sync();
	reboot(RB_POWER_OFF);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
