// SPDX-License-Identifier: GPL-2.0-only

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/klog.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/reboot.h>
#include <unistd.h>

struct test_message {
	long type;
	char text[8];
};

int main(void)
{
	static const char marker[] = "MEDUSA_QEMU_DELEGATED_MSGSND";
	struct test_message message = { 1, "cache" };
	char *log;
	char *cursor;
	int count = 0;
	int log_size;
	int id;

	setvbuf(stdout, NULL, _IONBF, 0);
	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	sleep(2);

	id = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
	if (id < 0 ||
	    msgsnd(id, &message, sizeof(message.text), 0) < 0 ||
	    msgsnd(id, &message, sizeof(message.text), 0) < 0) {
		puts("MEDUSA_QEMU_FAIL cache ipc_operation");
		goto out;
	}
	msgctl(id, IPC_RMID, NULL);
	sleep(1);

	log_size = klogctl(10, NULL, 0);
	log = log_size > 0 ? malloc(log_size + 1) : NULL;
	if (!log || klogctl(3, log, log_size) < 0) {
		puts("MEDUSA_QEMU_FAIL cache kernel_log");
		free(log);
		goto out;
	}
	log[log_size] = '\0';
	for (cursor = log; (cursor = strstr(cursor, marker)); cursor++)
		count++;
	free(log);

	if (count == 1) {
		puts("MEDUSA_RESULT cache delegated_once PASS");
		puts("MEDUSA_RESULT cache second_operation_cached PASS");
	} else {
		printf("MEDUSA_QEMU_FAIL cache delegated_count=%d\n", count);
	}

out:
	sync();
	reboot(RB_POWER_OFF);
	return count == 1 ? EXIT_SUCCESS : EXIT_FAILURE;
}
