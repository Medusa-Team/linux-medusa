// SPDX-License-Identifier: GPL-2.0-only

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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

#define FREEZER_CONTROL_KEY ((key_t)0x4d445343)

static int failures;

static void result(const char *name, bool passed)
{
	printf("MEDUSA_RESULT degraded %s %s\n", name,
	       passed ? "PASS" : "FAIL");
	if (!passed)
		failures++;
}

static pid_t read_constable_pid(void)
{
	FILE *file;
	long pid = -1;

	file = fopen("/constable.pid", "r");
	if (!file)
		return -1;
	if (fscanf(file, "%ld", &pid) != 1)
		pid = -1;
	fclose(file);
	return (pid_t)pid;
}

static pid_t find_constable_pid(void)
{
	struct dirent *entry;
	DIR *proc;

	proc = opendir("/proc");
	if (!proc)
		return -1;
	while ((entry = readdir(proc))) {
		char path[64];
		char status[256];
		char *end;
		long pid;
		int fd;
		ssize_t count;

		pid = strtol(entry->d_name, &end, 10);
		if (*entry->d_name == '\0' || *end != '\0' || pid <= 1)
			continue;
		snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		count = read(fd, status, sizeof(status) - 1);
		close(fd);
		if (count <= 0)
			continue;
		status[count] = '\0';
		if (strstr(status, "(constable)")) {
			closedir(proc);
			return (pid_t)pid;
		}
	}
	closedir(proc);
	return -1;
}

static bool wait_for_denial(int id)
{
	struct test_message message = { 1, "probe" };
	int attempt;

	for (attempt = 0; attempt < 100; attempt++) {
		errno = 0;
		if (msgsnd(id, &message, sizeof(message.text), IPC_NOWAIT) < 0 &&
		    errno == EACCES)
			return true;
		if (!errno)
			msgrcv(id, &message, sizeof(message.text), 0,
			       IPC_NOWAIT);
		usleep(100000);
	}
	return false;
}

static double monotonic_seconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return now.tv_sec + now.tv_nsec / 1000000000.0;
}

static bool send_control(const char *command)
{
	struct test_message message = { .type = 1 };

	strncpy(message.text, command, sizeof(message.text) - 1);
	/*
	 * The controller creates the first queue in this fresh IPC namespace.
	 * Address it directly so this test-only path does not need msgget()'s
	 * ipc_associate permission after the policy is active.
	 */
	if (msgsnd(0, &message, sizeof(message.text), 0) < 0) {
		perror("send freezer control");
		return false;
	}
	return true;
}

static int freezer_controller(void)
{
	struct test_message message;
	int control_id;
	int freeze_fd;
	int kill_fd;
	int ready_fd;

	freeze_fd = open("/sys/fs/cgroup/constable-test/cgroup.freeze",
			 O_WRONLY);
	kill_fd = open("/sys/fs/cgroup/constable-test/cgroup.kill", O_WRONLY);
	control_id = msgget(FREEZER_CONTROL_KEY, IPC_CREAT | 0600);
	if (freeze_fd < 0 || kill_fd < 0 || control_id != 0)
		return EXIT_FAILURE;
	ready_fd = open("/freezer-ready", O_WRONLY | O_CREAT, 0600);
	if (ready_fd < 0)
		return EXIT_FAILURE;
	close(ready_fd);

	for (;;) {
		if (msgrcv(control_id, &message, sizeof(message.text), 0, 0) < 0)
			return EXIT_FAILURE;
		message.text[sizeof(message.text) - 1] = '\0';
		if (!strcmp(message.text, "freeze")) {
			if (write(freeze_fd, "1", 1) != 1)
				return EXIT_FAILURE;
		} else if (!strcmp(message.text, "kill")) {
			if (write(kill_fd, "1", 1) != 1)
				return EXIT_FAILURE;
			msgctl(control_id, IPC_RMID, NULL);
			return EXIT_SUCCESS;
		}
	}
}

static bool freeze_constable(pid_t pid)
{
	(void)pid;
	if (!send_control("freeze"))
		return false;
	usleep(500000);
	return true;
}

int main(int argc, char **argv)
{
	struct test_message message = { 1, "lease" };
	pid_t initial;
	pid_t replacement;
	double started;
	double elapsed;
	int id;
	int send_result;

	if (argc == 2 && !strcmp(argv[1], "--freezer-controller"))
		return freezer_controller();

	setvbuf(stdout, NULL, _IONBF, 0);
	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);

	sleep(1);
	initial = find_constable_pid();
	if (initial <= 0)
		initial = read_constable_pid();
	result("startup", initial > 0 && kill(initial, 0) == 0);

	id = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
	if (id < 0) {
		perror("msgget");
		result("connected_delegation", false);
		result("timeout_fallback", false);
		goto out;
	}
	result("connected_delegation", wait_for_denial(id));

	result("constable_frozen", freeze_constable(initial));
	started = monotonic_seconds();
	errno = 0;
	send_result = msgsnd(id, &message, sizeof(message.text), IPC_NOWAIT);
	elapsed = monotonic_seconds() - started;
	result("timeout_fallback",
	       send_result == 0 && elapsed >= 4.0 && elapsed <= 10.0);

	started = monotonic_seconds();
	errno = 0;
	send_result = msgsnd(id, &message, sizeof(message.text), IPC_NOWAIT);
	elapsed = monotonic_seconds() - started;
	result("breaker_fast_fallback", send_result == 0 && elapsed < 1.0);

	send_control("kill");
	sleep(1);
	replacement = fork();
	if (replacement == 0) {
		execl("/sbin/constable", "constable", "-c",
		      "/etc/medusa.conf", "/etc/constable.conf", NULL);
		_exit(127);
	}
	result("reconnect", replacement > 0);
	result("delegation_recovered",
	       replacement > 0 && wait_for_denial(id));
	msgctl(id, IPC_RMID, NULL);

out:
	sleep(1);
	sync();
	reboot(RB_POWER_OFF);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
