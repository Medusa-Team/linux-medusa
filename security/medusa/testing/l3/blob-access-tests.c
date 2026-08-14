// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/fs.h>
#include <linux/ipc.h>
#include <linux/sched.h>
#include <net/sock.h>

#include "l1/inode.h"
#include "l1/ipc.h"
#include "l1/task.h"
#include "l1/socket.h"

static void blob_accessors_use_lsm_offsets(struct kunit *test)
{
	struct kern_ipc_perm *ipc;
	struct task_struct *task;
	struct inode *inode;
	void *task_blob;
	void *inode_blob;
	void *ipc_blob;
#ifdef CONFIG_SECURITY_NETWORK
	struct sock *sk;
	void *sock_blob;
#endif

	task = kunit_kzalloc(test, sizeof(*task), GFP_KERNEL);
	inode = kunit_kzalloc(test, sizeof(*inode), GFP_KERNEL);
	ipc = kunit_kzalloc(test, sizeof(*ipc), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, task);
	KUNIT_ASSERT_NOT_NULL(test, inode);
	KUNIT_ASSERT_NOT_NULL(test, ipc);

	task_blob = kunit_kzalloc(test, medusa_blob_sizes.lbs_task +
				 sizeof(struct medusa_l1_task_s), GFP_KERNEL);
	inode_blob = kunit_kzalloc(test, medusa_blob_sizes.lbs_inode +
				  sizeof(struct medusa_l1_inode_s), GFP_KERNEL);
	ipc_blob = kunit_kzalloc(test, medusa_blob_sizes.lbs_ipc +
				sizeof(struct medusa_l1_ipc_s), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, task_blob);
	KUNIT_ASSERT_NOT_NULL(test, inode_blob);
	KUNIT_ASSERT_NOT_NULL(test, ipc_blob);

	task->security = task_blob;
	inode->i_security = inode_blob;
	ipc->security = ipc_blob;

	KUNIT_EXPECT_PTR_EQ(test,
			    (char *)task_blob + medusa_blob_sizes.lbs_task,
			    (void *)task_security(task));
	KUNIT_EXPECT_PTR_EQ(test,
			    (char *)inode_blob + medusa_blob_sizes.lbs_inode,
			    (void *)inode_security(inode));
	KUNIT_EXPECT_PTR_EQ(test,
			    (char *)ipc_blob + medusa_blob_sizes.lbs_ipc,
			    (void *)ipc_security(ipc));

#ifdef CONFIG_SECURITY_NETWORK
	sk = kunit_kzalloc(test, sizeof(*sk), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, sk);
	sock_blob = kunit_kzalloc(test, medusa_blob_sizes.lbs_sock +
				 sizeof(struct medusa_l1_socket_s), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, sock_blob);
	sk->sk_security = sock_blob;

	KUNIT_EXPECT_PTR_EQ(test,
			    (char *)sock_blob + medusa_blob_sizes.lbs_sock,
			    (void *)sock_security(sk));
#endif
}

static struct kunit_case blob_access_test_cases[] = {
	KUNIT_CASE(blob_accessors_use_lsm_offsets),
	{}
};

static struct kunit_suite blob_access_test_suite = {
	.name = "medusa-blob-access-tests",
	.test_cases = blob_access_test_cases,
};

kunit_test_suite(blob_access_test_suite);
