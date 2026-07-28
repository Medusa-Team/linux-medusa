// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>

int main(void)
{
	int failures = 0;

	errno = 0;
	if (mkdir("/tmp/medusa-selinux-denied", 0700) >= 0 ||
	    errno != EACCES)
		failures++;

	errno = 0;
	if (socket(AF_UNIX, SOCK_SEQPACKET, 0) >= 0 || errno != EACCES)
		failures++;
	return failures != 0;
}
