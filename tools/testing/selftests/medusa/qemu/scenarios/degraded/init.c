// SPDX-License-Identifier: GPL-2.0-only

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
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
#define SECURITYFS_READERS 4
#define SECURITYFS_READ_ITERATIONS 700

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

static unsigned long long event_counter(const char *buffer, const char *event,
					const char *counter)
{
	const char *line = strstr(buffer, event);
	const char *field;
	char *end;
	char key[64];

	if (!line)
		return 0;
	snprintf(key, sizeof(key), " %s=", counter);
	field = strstr(line, key);
	if (!field)
		return 0;
	field += strlen(key);
	errno = 0;
	return strtoull(field, &end, 10);
}

static unsigned long long status_counter(const char *buffer,
					 const char *counter)
{
	const char *field = strstr(buffer, counter);
	char *end;

	if (!field)
		return 0;
	field += strlen(counter);
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

static bool securityfs_snapshot_is_consistent(void)
{
	char events[65536];
	char status[4096];
	size_t length;

	if (!read_file("/sys/kernel/security/medusa/status",
		       status, sizeof(status)) ||
	    !strstr(status, "kernel_release=") ||
	    !strstr(status, "protocol_version=3\n") ||
	    !strstr(status, "policy_generation=") ||
	    !strstr(status, "protocol_malformed_messages="))
		return false;
	length = strlen(status);
	if (!length || status[length - 1] != '\n')
		return false;
	if (!strstr(status, "protocol_state=disconnected\n") &&
	    !strstr(status, "protocol_state=handshaking\n") &&
	    !strstr(status, "protocol_state=ready\n"))
		return false;

	if (!read_file("/sys/kernel/security/medusa/events",
		       events, sizeof(events)) ||
	    !line_has(events, "event=ipc_msgsnd ", "decisions=") ||
	    !line_has(events, "event=ipc_msgsnd ", "fallback="))
		return false;
	length = strlen(events);
	return length && events[length - 1] == '\n';
}

static size_t start_securityfs_readers(pid_t *readers)
{
	size_t reader;

	for (reader = 0; reader < SECURITYFS_READERS; reader++) {
		pid_t child = fork();

		if (child < 0)
			break;
		if (child == 0) {
			int iteration;

			for (iteration = 0;
			     iteration < SECURITYFS_READ_ITERATIONS;
			     iteration++) {
				if (!securityfs_snapshot_is_consistent())
					_exit(EXIT_FAILURE);
				usleep(20000);
			}
			_exit(EXIT_SUCCESS);
		}
		readers[reader] = child;
	}
	return reader;
}

static bool wait_for_securityfs_readers(pid_t *readers, size_t count)
{
	bool passed = count == SECURITYFS_READERS;
	size_t reader;

	for (reader = 0; reader < count; reader++) {
		int status;

		if (waitpid(readers[reader], &status, 0) != readers[reader] ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
			passed = false;
	}
	return passed;
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

static pid_t start_handshake_holder(int *release_fd)
{
	char answer_packet[sizeof(uint64_t) * 2 + sizeof(int16_t)];
	uint64_t command;
	uint64_t request_id;
	int16_t answer;
	int attempt;
	int ready_pipe[2];
	int stop_pipe[2];
	char ready;
	pid_t child;

	if (pipe(ready_pipe) < 0)
		return -1;
	if (pipe(stop_pipe) < 0) {
		close(ready_pipe[0]);
		close(ready_pipe[1]);
		return -1;
	}
	child = fork();
	if (child < 0) {
		close(ready_pipe[0]);
		close(ready_pipe[1]);
		close(stop_pipe[0]);
		close(stop_pipe[1]);
		return -1;
	}
	if (child == 0) {
		int fd;
		bool passed = true;

		close(ready_pipe[0]);
		close(stop_pipe[1]);
		fd = open("/dev/medusa", O_RDWR);
		if (fd < 0)
			passed = false;

		for (attempt = 0; passed && attempt < 12; attempt++) {
			errno = 0;
			if (write(fd, "x", 1) != -1 || errno != EMSGSIZE)
				passed = false;
		}
		sleep(6);
		errno = 0;
		if (passed &&
		    (write(fd, "x", 1) != -1 || errno != EMSGSIZE))
			passed = false;
		usleep(200000);

		command = 0x81;
		request_id = UINT64_MAX - 1;
		answer = 2;
		memcpy(answer_packet, &command, sizeof(command));
		memcpy(answer_packet + sizeof(command), &request_id,
		       sizeof(request_id));
		memcpy(answer_packet + sizeof(command) + sizeof(request_id),
		       &answer, sizeof(answer));
		errno = 0;
		if (passed &&
		    (write(fd, answer_packet, sizeof(answer_packet)) != -1 ||
		     errno != EINVAL))
			passed = false;
		usleep(200000);

		request_id = UINT64_MAX;
		answer = 3;
		memcpy(answer_packet, &command, sizeof(command));
		memcpy(answer_packet + sizeof(command), &request_id,
		       sizeof(request_id));
		memcpy(answer_packet + sizeof(command) + sizeof(request_id),
		       &answer, sizeof(answer));
		errno = 0;
		if (passed &&
		    (write(fd, answer_packet, sizeof(answer_packet)) != -1 ||
		     errno != ENOENT))
			passed = false;
		usleep(200000);

		command = UINT64_C(0xdeadbeef);
		errno = 0;
		if (passed && (write(fd, &command, sizeof(command)) != -1 ||
			       errno != EFAULT))
			passed = false;

		ready = passed ? 1 : 0;
		if (write(ready_pipe[1], &ready, 1) != 1)
			passed = false;
		if (passed && read(stop_pipe[0], &ready, 1) != 1)
			passed = false;
		if (fd >= 0)
			close(fd);
		_exit(passed ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(ready_pipe[1]);
	close(stop_pipe[0]);
	if (read(ready_pipe[0], &ready, 1) != 1 || !ready) {
		close(ready_pipe[0]);
		close(stop_pipe[1]);
		waitpid(child, NULL, 0);
		return -1;
	}
	close(ready_pipe[0]);
	*release_fd = stop_pipe[1];
	return child;
}

int main(int argc, char **argv)
{
	struct test_message message = { 1, "lease" };
	pid_t initial;
	pid_t handshake;
	pid_t replacement;
	double started;
	double elapsed;
	char events[65536];
	char status[4096] = {};
	int id;
	int release_fd;
	int send_result;
	int handshake_status;
	bool handshake_released;
	unsigned long long initial_generation;
	pid_t securityfs_readers[SECURITYFS_READERS];
	size_t securityfs_reader_count = 0;
	bool securityfs_readers_waited = false;

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
	       strstr(status, "protocol_state=ready\n") &&
	       strstr(status, "policy_readiness=ready\n") &&
	       strstr(status, "authorization_server_health=healthy\n") &&
	       strstr(status, "circuit_breaker=closed\n") &&
	       strstr(status, "pending_requests=0\n") &&
	       strstr(status, "pending_limit=1024\n") &&
	       strstr(status, "decision_lease_ms=5000\n"));
	initial_generation =
		status_counter(status, "active_policy_generation=");
	result("generation_ready",
	       initial_generation > 0 &&
	       status_counter(status, "last_ready_policy_generation=") ==
		       initial_generation);
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
	securityfs_reader_count =
		start_securityfs_readers(securityfs_readers);

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
	       event_counter(events, "event=ipc_perm ",
			     "degraded_decisions") >= 1 &&
	       event_counter(events, "event=ipc_perm ", "delegated") >= 1 &&
	       event_counter(events, "event=ipc_perm ", "baseline") >= 1 &&
	       event_counter(events, "event=ipc_perm ", "timed_out") >= 1);

	started = monotonic_seconds();
	errno = 0;
	send_result = msgsnd(id, &message, sizeof(message.text), IPC_NOWAIT);
	elapsed = monotonic_seconds() - started;
	result("breaker_fast_fallback", send_result == 0 && elapsed < 1.0);

	send_control("kill");
	sleep(1);
	release_fd = -1;
	handshake = start_handshake_holder(&release_fd);
	result("handshake_started", handshake > 0);
	result("status_handshaking",
	       handshake > 0 &&
	       read_file("/sys/kernel/security/medusa/status",
			 status, sizeof(status)) &&
	       strstr(status, "authorization_server=handshaking\n") &&
	       strstr(status, "protocol_state=handshaking\n") &&
	       strstr(status, "policy_readiness=initializing\n") &&
	       strstr(status, "authorization_server_health=unavailable\n") &&
	       strstr(status, "circuit_breaker=not_ready\n") &&
	       strstr(status, "health_reason=initializing\n") &&
	       strstr(status, "active_policy_generation=0\n") &&
	       status_counter(status, "last_ready_policy_generation=") ==
		       initial_generation);
	result("protocol_error_counters",
	       handshake > 0 &&
	       status_counter(status, "protocol_malformed_messages=") >= 13 &&
	       status_counter(status, "protocol_invalid_answers=") >= 1 &&
	       status_counter(status, "protocol_unknown_commands=") >= 1 &&
	       status_counter(status, "protocol_unknown_requests=") >= 1);
	if (handshake > 0) {
		handshake_released = write(release_fd, "x", 1) == 1;
		close(release_fd);
		waitpid(handshake, &handshake_status, 0);
		result("handshake_closed",
		       handshake_released && WIFEXITED(handshake_status) &&
		       WEXITSTATUS(handshake_status) == 0);
	}
	result("status_disconnected",
	       read_file("/sys/kernel/security/medusa/status",
			 status, sizeof(status)) &&
	       strstr(status, "authorization_server=disconnected\n") &&
	       strstr(status, "protocol_state=disconnected\n") &&
	       strstr(status, "policy_readiness=unavailable\n") &&
	       strstr(status, "active_policy_generation=0\n") &&
	       status_counter(status, "last_ready_policy_generation=") ==
		       initial_generation);

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
	       strstr(status, "protocol_state=ready\n") &&
	       strstr(status, "policy_readiness=ready\n") &&
	       strstr(status, "authorization_server_health=healthy\n") &&
	       strstr(status, "circuit_breaker=closed\n") &&
	       strstr(status, "health_reason=healthy\n") &&
	       strstr(status, "pending_requests=0\n") &&
	       status_counter(status, "active_policy_generation=") >
		       initial_generation &&
	       status_counter(status, "last_ready_policy_generation=") ==
		       status_counter(status, "active_policy_generation="));
	result("securityfs_concurrent_reads",
	       wait_for_securityfs_readers(securityfs_readers,
					   securityfs_reader_count));
	securityfs_readers_waited = true;
	msgctl(id, IPC_RMID, NULL);

out:
	if (!securityfs_readers_waited)
		result("securityfs_concurrent_reads",
		       wait_for_securityfs_readers(securityfs_readers,
						   securityfs_reader_count));
	sleep(1);
	sync();
	reboot(RB_POWER_OFF);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
