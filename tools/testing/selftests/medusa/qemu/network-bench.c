// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static uint64_t monotonic_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
	return (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static unsigned int parse_count(const char *value, const char *name)
{
	char *end;
	unsigned long count;

	errno = 0;
	count = strtoul(value, &end, 10);
	if (errno || !*value || *end || !count || count > UINT_MAX) {
		fprintf(stderr, "invalid %s: %s\n", name, value);
		exit(EXIT_FAILURE);
	}
	return count;
}

static int make_listener(struct sockaddr_un *address, socklen_t *length)
{
	static const char name[] = "medusa-network-benchmark";
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;
	memset(address, 0, sizeof(*address));
	address->sun_family = AF_UNIX;
	memcpy(address->sun_path + 1, name, sizeof(name) - 1);
	*length = offsetof(struct sockaddr_un, sun_path) + sizeof(name);
	if (bind(fd, (struct sockaddr *)address, *length) < 0 ||
	    listen(fd, 128) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static uint64_t benchmark_connections(unsigned int iterations)
{
	struct sockaddr_un address;
	socklen_t address_length;
	uint64_t start;
	uint64_t elapsed;
	unsigned int i;
	int listener = make_listener(&address, &address_length);

	if (listener < 0) {
		perror("listener");
		exit(EXIT_FAILURE);
	}
	start = monotonic_ns();
	for (i = 0; i < iterations; i++) {
		int accepted;
		int client = socket(AF_UNIX, SOCK_STREAM, 0);

		if (client < 0 ||
		    connect(client, (struct sockaddr *)&address,
			    address_length) < 0) {
			perror("connect");
			exit(EXIT_FAILURE);
		}
		accepted = accept(listener, NULL, NULL);
		if (accepted < 0) {
			perror("accept");
			exit(EXIT_FAILURE);
		}
		close(accepted);
		close(client);
	}
	elapsed = monotonic_ns() - start;
	close(listener);
	return elapsed;
}

static uint64_t benchmark_messages(unsigned int iterations,
				   unsigned int payload_size)
{
	char *send_buffer = malloc(payload_size);
	char *receive_buffer = malloc(payload_size);
	uint64_t start;
	uint64_t elapsed;
	unsigned int i;
	int pair[2];

	if (!send_buffer || !receive_buffer) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	memset(send_buffer, 0xa5, payload_size);
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) < 0) {
		perror("socketpair");
		exit(EXIT_FAILURE);
	}
	start = monotonic_ns();
	for (i = 0; i < iterations; i++) {
		if (send(pair[0], send_buffer, payload_size, 0) !=
		    (ssize_t)payload_size ||
		    recv(pair[1], receive_buffer, payload_size, 0) !=
		    (ssize_t)payload_size) {
			perror("message");
			exit(EXIT_FAILURE);
		}
	}
	elapsed = monotonic_ns() - start;
	close(pair[0]);
	close(pair[1]);
	free(receive_buffer);
	free(send_buffer);
	return elapsed;
}

int main(int argc, char **argv)
{
	const char *mode;
	unsigned int iterations = 10000;
	unsigned int payload_size = 64;
	uint64_t connection_ns;
	uint64_t message_ns;
	double connection_rate;
	double message_rate;
	double mib_rate;

	if (argc < 2 || argc > 4) {
		fprintf(stderr,
			"usage: %s MODE [ITERATIONS [PAYLOAD_BYTES]]\n",
			argv[0]);
		return EXIT_FAILURE;
	}
	mode = argv[1];
	if (argc >= 3)
		iterations = parse_count(argv[2], "iterations");
	if (argc == 4)
		payload_size = parse_count(argv[3], "payload size");

	connection_ns = benchmark_connections(iterations);
	message_ns = benchmark_messages(iterations, payload_size);
	connection_rate = (double)iterations * 1000000000.0 / connection_ns;
	message_rate = (double)iterations * 1000000000.0 / message_ns;
	mib_rate = message_rate * payload_size / (1024.0 * 1024.0);

	printf("MEDUSA_BENCH mode=%s metric=connection_setup iterations=%u "
	       "ns_total=%" PRIu64 " ops_per_second=%.2f\n",
	       mode, iterations, connection_ns, connection_rate);
	printf("MEDUSA_BENCH mode=%s metric=message_throughput iterations=%u "
	       "payload_bytes=%u ns_total=%" PRIu64
	       " messages_per_second=%.2f mib_per_second=%.2f\n",
	       mode, iterations, payload_size, message_ns, message_rate, mib_rate);
	return EXIT_SUCCESS;
}
