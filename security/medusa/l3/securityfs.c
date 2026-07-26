// SPDX-License-Identifier: GPL-2.0-only

#include <generated/utsrelease.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/seq_file.h>

#include "l3/arch.h"
#include "l3/health.h"
#include "l3/pending.h"
#include "l3/registry.h"
#include "l3/securityfs.h"
#include "l4/comm.h"

static struct dentry *medusa_securityfs_dir;

static int medusa_status_show(struct seq_file *m, void *unused)
{
	struct medusa_registry_status status;
	const char *circuit_breaker;
	const char *health;
	const char *health_reason;

	medusa_registry_status_snapshot(&status);

	if (!status.connected) {
		circuit_breaker = "not_connected";
		health = "unavailable";
		health_reason = "disconnected";
	} else if (!status.health_known) {
		circuit_breaker = "unknown";
		health = "unknown";
		health_reason = "unknown";
	} else {
		circuit_breaker = status.healthy ? "closed" : "open";
		health = status.healthy ? "healthy" : "unhealthy";
		health_reason =
			medusa_health_reason_name(status.health_reason);
	}

	seq_printf(m, "kernel_release=%s\n", UTS_RELEASE);
	seq_printf(m, "protocol_version=%llu\n",
		   (unsigned long long)MEDUSA_COMM_VERSION);
	seq_printf(m, "authorization_server=%s\n",
		   status.connected ? "connected" : "disconnected");
	seq_printf(m, "authorization_server_name=%s\n",
		   status.connected ? status.server_name : "none");
	seq_printf(m, "authorization_server_health=%s\n", health);
	seq_printf(m, "circuit_breaker=%s\n", circuit_breaker);
	seq_printf(m, "health_reason=%s\n", health_reason);
	seq_printf(m, "policy_generation=%llu\n",
		   (unsigned long long)status.policy_generation);
	seq_printf(m, "pending_requests=%u\n",
		   medusa_pending_request_count());
	seq_printf(m, "pending_limit=%u\n", MEDUSA_PENDING_REQUEST_LIMIT);
	seq_printf(m, "decision_lease_ms=%u\n",
		   CONFIG_SECURITY_MEDUSA_DECISION_LEASE_MS);

	return 0;
}

static int medusa_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, medusa_status_show, NULL);
}

static const struct file_operations medusa_status_fops = {
	.open = medusa_status_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int medusa_events_show(struct seq_file *m, void *unused)
{
	return medusa_registry_events_seq_show(m);
}

static int medusa_events_open(struct inode *inode, struct file *file)
{
	return single_open(file, medusa_events_show, NULL);
}

static const struct file_operations medusa_events_fops = {
	.open = medusa_events_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

bool medusa_securityfs_file(const struct file *file)
{
	return file->f_op == &medusa_status_fops ||
	       file->f_op == &medusa_events_fops;
}

int __init medusa_securityfs_init(void)
{
	struct dentry *entry;

	medusa_securityfs_dir = securityfs_create_dir("medusa", NULL);
	if (IS_ERR(medusa_securityfs_dir))
		return PTR_ERR(medusa_securityfs_dir);

	entry = securityfs_create_file("status", 0400, medusa_securityfs_dir,
				       NULL, &medusa_status_fops);
	if (IS_ERR(entry))
		goto err;

	entry = securityfs_create_file("events", 0400, medusa_securityfs_dir,
				       NULL, &medusa_events_fops);
	if (IS_ERR(entry))
		goto err;

	med_pr_info("read-only status available in securityfs\n");
	return 0;

err:
	securityfs_remove(medusa_securityfs_dir);
	medusa_securityfs_dir = NULL;
	return PTR_ERR(entry);
}
