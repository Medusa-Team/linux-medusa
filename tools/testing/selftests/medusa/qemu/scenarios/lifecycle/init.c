// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
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
#include <unistd.h>

static int failures;

static void result(const char *name, bool passed)
{
	printf("MEDUSA_RESULT lifecycle %s %s\n", name,
	       passed ? "PASS" : "FAIL");
	if (!passed)
		failures++;
}

static void mount_one(const char *source, const char *target, const char *type)
{
	if (mount(source, target, type, 0, NULL) < 0 && errno != EBUSY)
		perror(target);
}

static pid_t read_initial_pid(void)
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

static pid_t find_constable_pid(void)
{
	struct dirent *entry;
	DIR *proc = opendir("/proc");

	if (!proc)
		return -1;
	while ((entry = readdir(proc))) {
		char path[64];
		char status[256];
		char *end;
		long pid = strtol(entry->d_name, &end, 10);
		int fd;
		ssize_t count;

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

static bool stop_process(pid_t pid)
{
	int status;
	int attempt;

	if (pid <= 0 || kill(pid, SIGTERM) < 0)
		return false;
	for (attempt = 0; attempt < 50; attempt++) {
		if (waitpid(pid, &status, WNOHANG) == pid)
			return true;
		if (kill(pid, 0) < 0 && errno == ESRCH)
			return true;
		usleep(100000);
	}
	return false;
}

static bool reloaded_policy_denies_message(void)
{
	struct {
		long type;
		char text[8];
	} message = { 1, "reload" };
	int id = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
	bool denied;

	if (id < 0)
		return false;
	errno = 0;
	denied = msgsnd(id, &message, sizeof(message.text), 0) < 0 &&
		 errno == EACCES;
	msgctl(id, IPC_RMID, NULL);
	return denied;
}

int main(void)
{
	pid_t initial;
	pid_t replacement;

	setvbuf(stdout, NULL, _IONBF, 0);
	mount_one("proc", "/proc", "proc");
	mount_one("sysfs", "/sys", "sysfs");
	mount_one("devtmpfs", "/dev", "devtmpfs");
	sleep(2);

	initial = read_initial_pid();
	if (initial <= 0 || kill(initial, 0) < 0)
		initial = find_constable_pid();
	result("startup", initial > 0 && kill(initial, 0) == 0);
	result("connected_operation",
	       mkdir("/tmp/medusa-connected", 0700) == 0);
	result("disconnect", stop_process(initial));

	errno = 0;
	result("disconnected_fail_open",
	       mkdir("/tmp/medusa-disconnected", 0700) == 0);

	replacement = fork();
	if (replacement == 0) {
		execl("/sbin/constable", "constable", "-c",
		      "/etc/medusa-reload.conf", "/etc/constable.conf", NULL);
		perror("restart constable");
		_exit(127);
	}
	sleep(2);
	result("restart", replacement > 0 && kill(replacement, 0) == 0);
	result("policy_reload", reloaded_policy_denies_message());

	sleep(1);
	sync();
	reboot(RB_POWER_OFF);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
