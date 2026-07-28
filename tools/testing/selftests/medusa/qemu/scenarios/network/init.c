// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void result(const char *name, bool passed)
{
	printf("MEDUSA_RESULT network %s %s\n", name,
	       passed ? "PASS" : "FAIL");
	if (!passed) {
		printf("MEDUSA_DETAIL network %s errno=%d (%s)\n",
		       name, errno, strerror(errno));
		failures++;
	}
}

static void mount_one(const char *source, const char *target, const char *type)
{
	if (mount(source, target, type, 0, NULL) < 0 && errno != EBUSY)
		perror(target);
}

static void disable_printk_ratelimit(void)
{
	static const char value[] = "0\n";
	FILE *file = fopen("/proc/sys/kernel/printk_ratelimit", "w");

	if (!file)
		return;
	fwrite(value, 1, sizeof(value) - 1, file);
	fclose(file);
}

static void dump_inventory(const char *path)
{
	char line[1024];
	FILE *inventory = fopen(path, "r");

	if (!inventory) {
		perror(path);
		return;
	}
	while (fgets(line, sizeof(line), inventory))
		fputs(line, stdout);
	fclose(inventory);
}

static int inet_listener(struct sockaddr_in *address)
{
	socklen_t address_length = sizeof(*address);
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;
	memset(address, 0, sizeof(*address));
	address->sin_family = AF_INET;
	address->sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(fd, (struct sockaddr *)address, sizeof(*address)) < 0 ||
	    getsockname(fd, (struct sockaddr *)address, &address_length) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void test_create_and_addresses(void)
{
	struct sockaddr_in6 inet6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(9),
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	struct sockaddr_un unix_address = {
		.sun_family = AF_UNIX,
		.sun_path = { 0, 'm', 'e', 'd', 'u', 's', 'a', '-', 'd' },
	};
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	result("create_allow", fd >= 0);
	if (fd >= 0)
		close(fd);

	errno = 0;
	fd = socket(AF_INET, SOCK_SEQPACKET, 0);
	result("create_deny", fd < 0 && errno == EACCES);
	if (fd >= 0)
		close(fd);

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	errno = 0;
	result("unix_bind_deny",
	       fd >= 0 &&
	       bind(fd, (struct sockaddr *)&unix_address,
		    offsetof(struct sockaddr_un, sun_path) + 9) < 0 &&
	       errno == EACCES);
	if (fd >= 0)
		close(fd);

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	errno = 0;
	result("ipv6_connect_deny",
	       fd >= 0 &&
	       connect(fd, (struct sockaddr *)&inet6, sizeof(inet6)) < 0 &&
	       errno == EACCES);
	if (fd >= 0)
		close(fd);

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	errno = 0;
	result("unix_connect_deny",
	       fd >= 0 &&
	       connect(fd, (struct sockaddr *)&unix_address,
		       offsetof(struct sockaddr_un, sun_path) + 9) < 0 &&
	       errno == EACCES);
	if (fd >= 0)
		close(fd);
}

static void test_listen_connect_and_accept(void)
{
	struct sockaddr_in address;
	struct sockaddr_in6 inet6_address = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT,
	};
	struct sockaddr_un unix_address = {
		.sun_family = AF_UNIX,
		.sun_path = { 0, 'm', 'e', 'd', 'u', 's', 'a', '-', 's' },
	};
	int listener = inet_listener(&address);
	int accepted = -1;
	pid_t child = -1;
	int status;
	int unix_listener;
	int inet6_listener;

	result("ipv4_bind_allow", listener >= 0);
	result("listen_allow", listener >= 0 && listen(listener, 8) == 0);
	errno = 0;
	result("listen_deny",
	       listener >= 0 && listen(listener, 9) < 0 && errno == EACCES);
	if (listener >= 0)
		close(listener);

	unix_listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (unix_listener >= 0 &&
	    (bind(unix_listener, (struct sockaddr *)&unix_address,
		  offsetof(struct sockaddr_un, sun_path) + 9) < 0 ||
	     listen(unix_listener, 8) < 0)) {
		close(unix_listener);
		unix_listener = -1;
	}
	if (unix_listener >= 0)
		child = fork();
	if (child == 0) {
		int client = socket(AF_UNIX, SOCK_STREAM, 0);

		_exit(client >= 0 &&
		      connect(client, (struct sockaddr *)&unix_address,
			      offsetof(struct sockaddr_un, sun_path) + 9) == 0 ?
		      0 : 1);
	}
	if (unix_listener >= 0)
		accepted = accept(unix_listener, NULL, NULL);
	result("unix_connect_allow",
	       child > 0 && waitpid(child, &status, 0) == child &&
	       WIFEXITED(status) && WEXITSTATUS(status) == 0);
	result("accept_allow", accepted >= 0);
	if (accepted >= 0)
		close(accepted);
	if (unix_listener >= 0)
		close(unix_listener);

	inet6_listener = socket(AF_INET6, SOCK_STREAM, 0);
	if (inet6_listener >= 0 &&
	    (bind(inet6_listener, (struct sockaddr *)&inet6_address,
		  sizeof(inet6_address)) < 0 ||
	     listen(inet6_listener, 8) < 0)) {
		close(inet6_listener);
		inet6_listener = -1;
	}
	errno = 0;
	result("accept_deny",
	       inet6_listener >= 0 &&
	       accept(inet6_listener, NULL, NULL) < 0 && errno == EACCES);
	if (inet6_listener >= 0)
		close(inet6_listener);
}

static void test_send_and_receive(void)
{
	char buffer[8] = {};
	int pair[2] = { -1, -1 };
	ssize_t length;

	result("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
	result("send_allow",
	       pair[0] >= 0 && send(pair[0], "four", 4, 0) == 4);
	errno = 0;
	result("send_deny",
	       pair[0] >= 0 && send(pair[0], "five!", 5, 0) < 0 &&
	       errno == EACCES);

	errno = 0;
	length = pair[1] >= 0 ? recv(pair[1], buffer, 5, 0) : -1;
	result("receive_deny", length < 0 && errno == EACCES);
	length = pair[1] >= 0 ? recv(pair[1], buffer, 4, 0) : -1;
	result("receive_allow",
	       length == 4 && !memcmp(buffer, "four", 4));

	if (pair[0] >= 0)
		close(pair[0]);
	if (pair[1] >= 0)
		close(pair[1]);
}

static void test_degraded_baseline(void)
{
	struct sockaddr_un address = {
		.sun_family = AF_UNIX,
		.sun_path = { 0, 'm', 'e', 'd', 'u', 's', 'a', '-', 'f' },
	};
	FILE *file = fopen("/constable.pid", "r");
	long pid = -1;
	int fd;

	if (file) {
		if (fscanf(file, "%ld", &pid) != 1)
			pid = -1;
		fclose(file);
	}
	if (pid > 1)
		kill((pid_t)pid, SIGTERM);
	sleep(1);

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	errno = 0;
	result("degraded_bind_online_required_deny",
	       pid > 1 && fd >= 0 &&
	       bind(fd, (struct sockaddr *)&address,
		    offsetof(struct sockaddr_un, sun_path) + 9) < 0 &&
	       errno == EACCES);
	if (fd >= 0)
		close(fd);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setenv("PATH", "/sbin:/bin", 1);
	mount_one("proc", "/proc", "proc");
	disable_printk_ratelimit();
	mount_one("sysfs", "/sys", "sysfs");
	mount_one("devtmpfs", "/dev", "devtmpfs");
	mount_one("securityfs", "/sys/kernel/security", "securityfs");
	sleep(2);

	test_create_and_addresses();
	test_listen_connect_and_accept();
	test_send_and_receive();
	test_degraded_baseline();
	dump_inventory("/sys/kernel/security/medusa/events");
	dump_inventory("/sys/kernel/security/medusa/classes");

	printf("MEDUSA_RESULT network complete %s\n",
	       failures ? "FAIL" : "PASS");
	sleep(1);
	sync();
	reboot(RB_POWER_OFF);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
