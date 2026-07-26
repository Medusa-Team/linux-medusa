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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct test_message {
	long type;
	char text[8];
};

#define FREEZER_CONTROL_KEY ((key_t)0x4d445343)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

static int failures;

static bool read_file(const char *path, char *buffer, size_t size)
{
	ssize_t count;
	size_t used = 0;
	int fd;

	if (!size)
		return false;
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror(path);
		return false;
	}
	while (used < size - 1) {
		count = read(fd, buffer + used, size - 1 - used);
		if (count < 0) {
			perror(path);
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

static bool line_has(const char *buffer, const char *line_key,
		     const char *field)
{
	const char *line = strstr(buffer, line_key);
	const char *match;
	const char *end;

	if (!line)
		return false;
	end = strchr(line, '\n');
	if (!end)
		end = line + strlen(line);
	match = strstr(line, field);
	return match && match < end;
}

static unsigned long long event_degraded_count(const char *buffer,
					       const char *event)
{
	const char *line = strstr(buffer, event);
	const char *field;
	char *end;

	if (!line)
		return 0;
	field = strstr(line, " degraded_decisions=");
	if (!field)
		return 0;
	field += strlen(" degraded_decisions=");
	errno = 0;
	return strtoull(field, &end, 10);
}

static bool securityfs_is_root_only(void)
{
	static const char *const paths[] = {
		"/sys/kernel/security/medusa/status",
		"/sys/kernel/security/medusa/events",
	};
	struct stat status;
	pid_t child;
	int child_status;
	size_t index;

	for (index = 0; index < ARRAY_SIZE(paths); index++)
		if (stat(paths[index], &status) < 0 ||
		    (status.st_mode & 0777) != 0400)
			return false;

	child = fork();
	if (child < 0)
		return false;
	if (child == 0) {
		if (setgid(65534) < 0 || setuid(65534) < 0)
			_exit(2);
		for (index = 0; index < ARRAY_SIZE(paths); index++) {
			int fd;

			errno = 0;
			fd = open(paths[index], O_RDONLY);
			if (fd >= 0) {
				close(fd);
				_exit(1);
			}
			if (errno != EACCES)
				_exit(3);
		}
		_exit(0);
	}
	if (waitpid(child, &child_status, 0) != child)
		return false;
	return WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0;
}

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
	char events[65536];
	char status[4096];
	int id;
	int send_result;

	if (argc == 2 && !strcmp(argv[1], "--freezer-controller"))
		return freezer_controller();

	setvbuf(stdout, NULL, _IONBF, 0);
	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	mkdir("/sys/kernel/security", 0755);
	mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL);

	sleep(1);
	initial = find_constable_pid();
	if (initial <= 0)
		initial = read_constable_pid();
	result("startup", initial > 0 && kill(initial, 0) == 0);
	result("status_connected",
	       read_file("/sys/kernel/security/medusa/status",
			 status, sizeof(status)) &&
	       strstr(status, "protocol_version=3\n") &&
	       strstr(status, "authorization_server=connected\n") &&
	       strstr(status, "authorization_server_health=healthy\n") &&
	       strstr(status, "circuit_breaker=closed\n") &&
	       strstr(status, "pending_requests=0\n") &&
	       strstr(status, "pending_limit=1024\n") &&
	       strstr(status, "decision_lease_ms=5000\n"));
	result("events_visible",
	       read_file("/sys/kernel/security/medusa/events",
			 events, sizeof(events)) &&
	       line_has(events, "event=ipc_msgsnd ",
			"fallback=baseline_allow") &&
	       line_has(events, "event=ipc_msgsnd ",
			"subject_class=process") &&
	       line_has(events, "event=ipc_msgsnd ",
			"object_class=ipc"));
	result("status_root_only", securityfs_is_root_only());

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
	result("status_degraded",
	       read_file("/sys/kernel/security/medusa/status",
			 status, sizeof(status)) &&
	       strstr(status, "authorization_server=connected\n") &&
	       strstr(status, "authorization_server_health=unhealthy\n") &&
	       strstr(status, "circuit_breaker=open\n") &&
	       strstr(status, "health_reason=decision_timeout\n") &&
	       strstr(status, "pending_requests=0\n"));
	result("degraded_counter",
	       read_file("/sys/kernel/security/medusa/events",
			 events, sizeof(events)) &&
	       event_degraded_count(events, "event=ipc_perm ") >= 1);

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
	result("status_recovered",
	       read_file("/sys/kernel/security/medusa/status",
			 status, sizeof(status)) &&
	       strstr(status, "authorization_server=connected\n") &&
	       strstr(status, "authorization_server_health=healthy\n") &&
	       strstr(status, "circuit_breaker=closed\n") &&
	       strstr(status, "health_reason=healthy\n") &&
	       strstr(status, "pending_requests=0\n"));
	msgctl(id, IPC_RMID, NULL);

out:
	sleep(1);
	sync();
	reboot(RB_POWER_OFF);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
