// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/un.h>

#include "l1/socket.h"

static void ipv4_address_is_copied_and_tail_is_zero(struct kunit *test)
{
	struct sockaddr_in source = {
		.sin_family = AF_INET,
		.sin_port = cpu_to_be16(8443),
		.sin_addr.s_addr = cpu_to_be32(0xc0000201),
	};
	struct medusa_socket_address parsed;
	struct medusa_socket_address expected = {
		.family = AF_INET,
		.data_length = sizeof(parsed.value.inet),
		.addrlen = sizeof(source),
		.value.inet = {
			.port = cpu_to_be16(8443),
			.addr.s_addr = cpu_to_be32(0xc0000201),
		},
	};

	memset(&parsed, 0xa5, sizeof(parsed));
	KUNIT_ASSERT_EQ(test, 0,
			medusa_socket_address_parse(&parsed,
				(const struct sockaddr *)&source,
				sizeof(source)));
	KUNIT_EXPECT_MEMEQ(test, &parsed, &expected, sizeof(expected));
}

static void ipv6_address_preserves_scope_and_flow(struct kunit *test)
{
	struct sockaddr_in6 source = {
		.sin6_family = AF_INET6,
		.sin6_port = cpu_to_be16(5353),
		.sin6_flowinfo = cpu_to_be32(0x12345),
		.sin6_scope_id = 9,
	};
	struct medusa_socket_address parsed;

	source.sin6_addr.s6_addr[0] = 0xfe;
	source.sin6_addr.s6_addr[1] = 0x80;
	source.sin6_addr.s6_addr[15] = 1;

	KUNIT_ASSERT_EQ(test, 0,
			medusa_socket_address_parse(&parsed,
				(const struct sockaddr *)&source,
				sizeof(source)));
	KUNIT_EXPECT_EQ(test, (sa_family_t)AF_INET6, parsed.family);
	KUNIT_EXPECT_EQ(test, (__u16)sizeof(parsed.value.inet6),
			parsed.data_length);
	KUNIT_EXPECT_EQ(test, (__u32)sizeof(source), parsed.addrlen);
	KUNIT_EXPECT_EQ(test, source.sin6_port, parsed.value.inet6.port);
	KUNIT_EXPECT_EQ(test, source.sin6_flowinfo,
			parsed.value.inet6.flowinfo);
	KUNIT_EXPECT_MEMEQ(test, &source.sin6_addr,
			   &parsed.value.inet6.addr, sizeof(source.sin6_addr));
	KUNIT_EXPECT_EQ(test, source.sin6_scope_id,
			parsed.value.inet6.scope_id);
}

static void unix_abstract_name_is_bounded_and_not_stringified(struct kunit *test)
{
	struct sockaddr_un source = {
		.sun_family = AF_UNIX,
		.sun_path = { 0, 'm', 'e', 'd', 'u', 's', 'a' },
	};
	struct medusa_socket_address parsed;
	size_t name_length = 7;
	int addrlen = offsetof(struct sockaddr_un, sun_path) + name_length;

	memset(&parsed, 0xa5, sizeof(parsed));
	KUNIT_ASSERT_EQ(test, 0,
			medusa_socket_address_parse(&parsed,
				(const struct sockaddr *)&source, addrlen));
	KUNIT_EXPECT_EQ(test, (sa_family_t)AF_UNIX, parsed.family);
	KUNIT_EXPECT_EQ(test, (__u16)name_length, parsed.data_length);
	KUNIT_EXPECT_EQ(test, (__u32)addrlen, parsed.addrlen);
	KUNIT_EXPECT_MEMEQ(test, source.sun_path,
			   parsed.value.unix_addr.addrdata, name_length);
	KUNIT_EXPECT_TRUE(test,
		mem_is_zero(parsed.value.unix_addr.addrdata + name_length,
			    UNIX_PATH_MAX - name_length));
}

static void malformed_and_unsupported_addresses_are_rejected(struct kunit *test)
{
	struct sockaddr address = {
		.sa_family = AF_NETLINK,
	};
	struct medusa_socket_address parsed;

	KUNIT_EXPECT_EQ(test, -EINVAL,
			medusa_socket_address_parse(&parsed, &address, 0));
	KUNIT_EXPECT_EQ(test, -EAFNOSUPPORT,
			medusa_socket_address_parse(&parsed, &address,
						   sizeof(address)));

	address.sa_family = AF_INET;
	KUNIT_EXPECT_EQ(test, -EINVAL,
			medusa_socket_address_parse(&parsed, &address,
						   sizeof(address.sa_family)));
}

static struct kunit_case socket_address_test_cases[] = {
	KUNIT_CASE(ipv4_address_is_copied_and_tail_is_zero),
	KUNIT_CASE(ipv6_address_preserves_scope_and_flow),
	KUNIT_CASE(unix_abstract_name_is_bounded_and_not_stringified),
	KUNIT_CASE(malformed_and_unsupported_addresses_are_rejected),
	{}
};

static struct kunit_suite socket_address_test_suite = {
	.name = "medusa-socket-address-tests",
	.test_cases = socket_address_test_cases,
};

kunit_test_suite(socket_address_test_suite);
