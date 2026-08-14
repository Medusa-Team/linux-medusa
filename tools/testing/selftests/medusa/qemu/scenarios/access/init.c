// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <unistd.h>

#define main medusa_access_main
#include "guest.c"
#undef main

static void mount_one(const char *source, const char *target, const char *type)
{
	if (mount(source, target, type, 0, NULL) < 0 && errno != EBUSY)
		perror(target);
}

static void dump_event_counters(void)
{
	char line[1024];
	FILE *events;

	events = fopen("/sys/kernel/security/medusa/events", "r");
	if (!events) {
		perror("medusa events");
		return;
	}

	while (fgets(line, sizeof(line), events))
		fputs(line, stdout);
	fclose(events);
}

int main(void)
{
	int status;

	setenv("PATH", "/sbin:/bin", 1);
	mount_one("proc", "/proc", "proc");
	mount_one("sysfs", "/sys", "sysfs");
	mount_one("devtmpfs", "/dev", "devtmpfs");
	mount_one("securityfs", "/sys/kernel/security", "securityfs");

	sleep(2);
	mount_one("tmpfs", "/tmp", "tmpfs");
	status = medusa_access_main();
	dump_event_counters();

	sleep(1);
	sync();
	reboot(RB_POWER_OFF);
	return status;
}
