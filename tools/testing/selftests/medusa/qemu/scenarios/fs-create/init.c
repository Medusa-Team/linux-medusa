// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <unistd.h>

static int failures;

static void result(const char *name, bool passed)
{
	printf("MEDUSA_RESULT fs-create %s %s\n", name,
	       passed ? "PASS" : "FAIL");
	if (!passed) {
		printf("MEDUSA_DETAIL fs-create %s errno=%d (%s)\n",
		       name, errno, strerror(errno));
		failures++;
	}
}

static void mount_one(const char *source, const char *target, const char *type)
{
	if (mount(source, target, type, 0, NULL) < 0 && errno != EBUSY)
		perror(target);
}

static bool wait_for_policy_ready(void)
{
	char line[256];
	int attempt;

	for (attempt = 0; attempt < 1200; attempt++) {
		bool connected = false;
		bool ready = false;
		FILE *status;

		status = fopen("/sys/kernel/security/medusa/status", "r");
		if (status) {
			while (fgets(line, sizeof(line), status)) {
				if (!strcmp(line,
					    "authorization_server=connected\n"))
					connected = true;
				else if (!strcmp(line, "protocol_state=ready\n"))
					ready = true;
			}
			fclose(status);
			if (connected && ready)
				return true;
		}
		usleep(50000);
	}
	return false;
}

static void dump_create_counter(void)
{
	char line[1024];
	FILE *events;

	events = fopen("/sys/kernel/security/medusa/events", "r");
	if (!events)
		return;
	while (fgets(line, sizeof(line), events))
		if (strstr(line, "event=create "))
			fputs(line, stdout);
	fclose(events);
}

static void test_create(void)
{
	int fd;

	errno = 0;
	fd = open("/tmp/create-deny", O_CREAT | O_WRONLY, 0611);
	result("deny_before_create", fd < 0 && errno == EACCES);
	if (fd >= 0)
		close(fd);
	errno = 0;
	result("denied_path_absent",
	       access("/tmp/create-deny", F_OK) < 0 && errno == ENOENT);

	fd = creat("/tmp/creat-file", 0640);
	result("creat", fd >= 0);
	if (fd >= 0)
		close(fd);

	fd = open("/tmp/exclusive-file", O_CREAT | O_EXCL | O_WRONLY, 0600);
	result("exclusive_create", fd >= 0);
	if (fd >= 0)
		close(fd);

	fd = open("/tmp/open-file", O_CREAT | O_RDWR, 0644);
	result("create_open", fd >= 0);
	if (fd >= 0)
		close(fd);
}

int main(void)
{
	setenv("PATH", "/sbin:/bin", 1);
	setvbuf(stdout, NULL, _IONBF, 0);
	mount_one("proc", "/proc", "proc");
	mount_one("sysfs", "/sys", "sysfs");
	mount_one("devtmpfs", "/dev", "devtmpfs");
	mount_one("securityfs", "/sys/kernel/security", "securityfs");

	result("policy_ready", wait_for_policy_ready());
	test_create();
	dump_create_counter();
	printf("MEDUSA_RESULT fs-create complete %s\n",
	       failures ? "FAIL" : "PASS");

	sleep(1);
	sync();
	reboot(RB_POWER_OFF);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
