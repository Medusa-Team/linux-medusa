// SPDX-License-Identifier: GPL-2.0-only

#define main medusa_network_benchmark_main
#include "../../network-bench.c"
#undef main

#include <sys/mount.h>
#include <sys/reboot.h>

static void mount_one(const char *source, const char *target, const char *type)
{
	if (mount(source, target, type, 0, NULL) < 0 && errno != EBUSY)
		perror(target);
}

int main(void)
{
	char mode[32] = {};
	char *newline;
	char *arguments[] = {
		"network-bench",
		mode,
		"100",
		"64",
		NULL,
	};
	FILE *mode_file;
	int result;

	setvbuf(stdout, NULL, _IONBF, 0);
	mount_one("proc", "/proc", "proc");
	mount_one("sysfs", "/sys", "sysfs");
	mount_one("devtmpfs", "/dev", "devtmpfs");
	mode_file = fopen("/etc/benchmark-mode", "r");
	if (!mode_file || !fgets(mode, sizeof(mode), mode_file)) {
		perror("benchmark mode");
		return EXIT_FAILURE;
	}
	fclose(mode_file);
	newline = strchr(mode, '\n');
	if (newline)
		*newline = '\0';

	sleep(2);
	result = medusa_network_benchmark_main(4, arguments);
	sync();
	reboot(RB_POWER_OFF);
	return result;
}
