// SPDX-License-Identifier: GPL-2.0-only

#include <generated/utsrelease.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include "l3/audit_schema.h"
#include "l3/arch.h"
#include "l3/health.h"
#include "l3/pending.h"
#include "l3/protocol_stats.h"
#include "l3/registry.h"
#include "l3/securityfs.h"
#include <uapi/linux/medusa.h>

static struct dentry *medusa_securityfs_dir;

static int medusa_status_show(struct seq_file *m, void *unused)
{
	struct medusa_registry_status status;
	struct medusa_protocol_counter_snapshot protocol;
	const char *authorization_server;
	const char *circuit_breaker;
	const char *health;
	const char *health_reason;
	const char *policy_readiness;

	medusa_registry_status_snapshot(&status);
	medusa_protocol_counters_snapshot(&protocol);

	if (status.server_state == MEDUSA_AUTHSERVER_DISCONNECTED) {
		authorization_server = "disconnected";
		circuit_breaker = "not_connected";
		health = "unavailable";
		health_reason = "disconnected";
		policy_readiness = "unavailable";
	} else if (status.server_state != MEDUSA_AUTHSERVER_READY &&
		   status.server_state != MEDUSA_AUTHSERVER_DEGRADED) {
		authorization_server = "handshaking";
		circuit_breaker = "not_ready";
		health = "unavailable";
		health_reason = "initializing";
		policy_readiness = "initializing";
	} else if (!status.health_known) {
		authorization_server = "connected";
		circuit_breaker = "unknown";
		health = "unknown";
		health_reason = "unknown";
		policy_readiness = "ready";
	} else {
		authorization_server = "connected";
		circuit_breaker = status.healthy ? "closed" : "open";
		health = status.healthy ? "healthy" : "unhealthy";
		health_reason =
			medusa_health_reason_name(status.health_reason);
		policy_readiness = "ready";
	}

	seq_printf(m, "kernel_release=%s\n", UTS_RELEASE);
	seq_printf(m, "protocol_version=%u\n", MEDUSA_PROTOCOL_VERSION);
	seq_printf(m, "audit_schema_version=%u\n",
		   MEDUSA_AUDIT_SCHEMA_VERSION);
	seq_printf(m, "authorization_server=%s\n", authorization_server);
	seq_printf(m, "authorization_server_name=%s\n",
		   status.server_state == MEDUSA_AUTHSERVER_DISCONNECTED ?
			   "none" : status.server_name);
	seq_printf(m, "protocol_state=%s\n",
		   medusa_authserver_state_name(status.server_state));
	seq_printf(m, "policy_readiness=%s\n", policy_readiness);
	seq_printf(m, "authorization_server_health=%s\n", health);
	seq_printf(m, "circuit_breaker=%s\n", circuit_breaker);
	seq_printf(m, "health_reason=%s\n", health_reason);
	seq_printf(m, "policy_generation=%llu\n",
		   (unsigned long long)status.policy_generation);
	seq_printf(m, "active_policy_generation=%llu\n",
		   (unsigned long long)status.active_policy_generation);
	seq_printf(m, "last_ready_policy_generation=%llu\n",
		   (unsigned long long)status.last_ready_policy_generation);
	seq_printf(m, "pending_requests=%u\n",
		   medusa_pending_request_count());
	seq_printf(m, "pending_limit=%u\n",
		   medusa_pending_request_limit());
	seq_printf(m, "decision_lease_ms=%u\n",
		   medusa_decision_timeout_ms());
	seq_printf(m, "protocol_replies=%llu\n",
		   (unsigned long long)protocol.replies);
	seq_printf(m, "protocol_lease_renewals=%llu\n",
		   (unsigned long long)protocol.lease_renewals);
	seq_printf(m, "protocol_malformed_messages=%llu\n",
		   (unsigned long long)protocol.malformed_messages);
	seq_printf(m, "protocol_invalid_answers=%llu\n",
		   (unsigned long long)protocol.invalid_answers);
	seq_printf(m, "protocol_unknown_commands=%llu\n",
		   (unsigned long long)protocol.unknown_commands);
	seq_printf(m, "protocol_unknown_requests=%llu\n",
		   (unsigned long long)protocol.unknown_requests);
	seq_printf(m, "protocol_stale_requests=%llu\n",
		   (unsigned long long)protocol.stale_requests);

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

static int medusa_classes_show(struct seq_file *m, void *unused)
{
	return medusa_registry_classes_seq_show(m);
}

static int medusa_classes_open(struct inode *inode, struct file *file)
{
	return single_open(file, medusa_classes_show, NULL);
}

static const struct file_operations medusa_classes_fops = {
	.open = medusa_classes_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static ssize_t medusa_control_read(struct file *file, char __user *buffer,
				   size_t count, loff_t *position)
{
	unsigned int value = (uintptr_t)file->private_data ?
		medusa_decision_timeout_ms() :
		medusa_pending_request_limit();
	char text[24];
	int length;

	length = scnprintf(text, sizeof(text), "%u\n", value);
	return simple_read_from_buffer(buffer, count, position, text, length);
}

static ssize_t medusa_control_write(struct file *file,
				    const char __user *buffer, size_t count,
				    loff_t *position)
{
	unsigned int value;
	int error;

	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;
	if (*position)
		return -EINVAL;
	error = kstrtouint_from_user(buffer, count, 10, &value);
	if (error)
		return error;
	error = (uintptr_t)file->private_data ?
		medusa_decision_timeout_set_ms(value) :
		medusa_pending_request_set_limit(value);
	if (error)
		return error;
	*position += count;
	return count;
}

static int medusa_control_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

static const struct file_operations medusa_control_fops = {
	.open = medusa_control_open,
	.read = medusa_control_read,
	.write = medusa_control_write,
	.llseek = noop_llseek,
};

bool medusa_securityfs_file(const struct file *file)
{
	return file->f_op == &medusa_status_fops ||
	       file->f_op == &medusa_events_fops ||
	       file->f_op == &medusa_classes_fops;
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

	entry = securityfs_create_file("classes", 0400, medusa_securityfs_dir,
				       NULL, &medusa_classes_fops);
	if (IS_ERR(entry))
		goto err;

	entry = securityfs_create_file("pending_limit", 0600,
				       medusa_securityfs_dir, NULL,
				       &medusa_control_fops);
	if (IS_ERR(entry))
		goto err;

	entry = securityfs_create_file("decision_timeout_ms", 0600,
				       medusa_securityfs_dir, (void *)1UL,
				       &medusa_control_fops);
	if (IS_ERR(entry))
		goto err;

	med_pr_info("status and privileged transport controls available in securityfs\n");
	return 0;

err:
	securityfs_remove(medusa_securityfs_dir);
	medusa_securityfs_dir = NULL;
	return PTR_ERR(entry);
}
