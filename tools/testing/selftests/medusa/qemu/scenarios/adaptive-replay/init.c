// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/klog.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct test_message {
	long type;
	char text[8];
};

static int failures;

static void result(const char *name, bool passed)
{
	printf("MEDUSA_RESULT adaptive_replay %s %s\n", name,
	       passed ? "PASS" : "FAIL");
	if (!passed)
		failures++;
}

static pid_t constable_pid(void)
{
	FILE *file = fopen("/constable.pid", "r");
	long pid = -1;

	if (!file)
		return -1;
	if (fscanf(file, "%ld", &pid) != 1)
		pid = -1;
	fclose(file);
	return (pid_t)pid;
}

static unsigned long long active_generation(void)
{
	char line[256];
	FILE *file = fopen("/sys/kernel/security/medusa/status", "r");
	unsigned long long generation = 0;

	if (!file)
		return 0;
	while (fgets(line, sizeof(line), file)) {
		if (sscanf(line, "active_policy_generation=%llu",
			   &generation) == 1)
			break;
	}
	fclose(file);
	return generation;
}

static unsigned long long await_next_generation(unsigned long long old)
{
	unsigned long long generation = old;
	int attempt;

	for (attempt = 0; attempt < 100 && generation <= old; attempt++) {
		usleep(50000);
		generation = active_generation();
	}
	return generation;
}

static int marker_count(const char *marker)
{
	char *cursor;
	char *log;
	int count = 0;
	int log_size = klogctl(10, NULL, 0);

	log = log_size > 0 ? malloc(log_size + 1) : NULL;
	if (!log || klogctl(3, log, log_size) < 0) {
		free(log);
		return -1;
	}
	log[log_size] = '\0';
	for (cursor = log; (cursor = strstr(cursor, marker)); cursor++)
		count++;
	free(log);
	return count;
}

static bool send_message(int id)
{
	struct test_message message = { 1, "replay" };

	errno = 0;
	return msgsnd(id, &message, sizeof(message.text), 0) == 0;
}

static bool receive_is_denied(int id)
{
	struct test_message message;

	errno = 0;
	return msgrcv(id, &message, sizeof(message.text), 0, IPC_NOWAIT) < 0 &&
	       (errno == EACCES || errno == ENOMSG);
}

static unsigned long queue_depth(int id)
{
	struct msqid_ds status;

	if (msgctl(id, IPC_STAT, &status) < 0)
		return 0;
	return status.msg_qnum;
}

int main(void)
{
	unsigned long long generation;
	unsigned long long next_generation;
	pid_t pid;
	int id;
	bool first;
	bool second;

	setvbuf(stdout, NULL, _IONBF, 0);
	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	mkdir("/sys/kernel/security", 0755);
	mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL);
	sleep(2);

	pid = constable_pid();
	generation = active_generation();
	id = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
	if (pid <= 0 || generation == 0 || id < 0) {
		puts("MEDUSA_QEMU_FAIL adaptive_replay setup");
		failures++;
		goto out;
	}

	first = send_message(id);
	second = send_message(id);
	result("recorded_workload_allowed", first && second);
	sleep(1);
	result("allow_cached_once",
	       marker_count("MEDUSA_ADAPTIVE_RECORDED_ALLOW") == 1);

	if (kill(pid, SIGUSR1) < 0) {
		puts("MEDUSA_QEMU_FAIL adaptive_replay reload_signal");
		failures++;
		goto out;
	}
	next_generation = await_next_generation(generation);
	result("live_generation_commit", next_generation == generation + 1);
	result("constable_pid_stable", kill(pid, 0) == 0);

	first = receive_is_denied(id);
	second = receive_is_denied(id);
	result("withheld_negative_denied",
	       first && second && queue_depth(id) == 2);
	sleep(1);
	result("denial_not_cached",
	       marker_count("MEDUSA_ADAPTIVE_WITHHELD_DENY") == 4);

out:
	if (id >= 0)
		msgctl(id, IPC_RMID, NULL);
	sync();
	reboot(RB_POWER_OFF);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
