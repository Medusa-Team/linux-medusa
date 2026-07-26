// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <sys/stat.h>

int main(void)
{
	errno = 0;
	if (mkdir("/tmp/medusa-selinux-denied", 0700) < 0 &&
	    errno == EACCES)
		return 0;
	return 1;
}
