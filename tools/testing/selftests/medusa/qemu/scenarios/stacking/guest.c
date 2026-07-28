// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>

static int failures;

static void result(const char *name, bool passed)
{
	printf("MEDUSA_RESULT stacking %s %s\n", name,
	       passed ? "PASS" : "FAIL");
	if (!passed)
		failures++;
}

int main(void)
{
	errno = 0;
	result("apparmor_deny",
	       mkdir("/tmp/medusa-apparmor-denied", 0700) < 0 &&
	       errno == EACCES);
	result("allow_after_apparmor_deny",
	       mkdir("/tmp/medusa-apparmor-allowed", 0700) == 0);
	errno = 0;
	result("medusa_network_deny",
	       socket(AF_UNIX, SOCK_SEQPACKET, 0) < 0 && errno == EACCES);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
