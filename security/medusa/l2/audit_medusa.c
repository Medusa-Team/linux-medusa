// SPDX-License-Identifier: GPL-2.0-only

#include "l2/audit_medusa.h"

/* array for auditing med_answer,
 * if answers will be modified, think about that too
 */
static char *audit_answer[] = {
	"ERROR",
	"FORCE_ALLOW",
	"DENY",
	"FAKE_ALLOW",
	"ALLOW"
};

/*
 * medusa_pre - pre audit callback function to format audit record
 * @ab: audit buffer for formatting audit record
 * @pcad: passed common audit data for audit record
 *
 * vs log description:
 * ..._i: vs are intersect
 * ..._n: vs are not intersect
 */
//static void medusa_pre(struct audit_buffer *ab, void *pcad);
static void medusa_pre(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	audit_log_format(ab, "Medusa: op=%s", mad->function);

	audit_log_format(ab, " ans=");
	audit_log_format(ab, audit_answer[mad->ans + 1]);

	if (mad->ans == MED_DENY && mad->as == AS_NO_REQUEST) {
		/* TODO: create a data structure that will be able to store this
		 * information */
	}

	if (mad->as == AS_REQUEST)
		audit_log_format(ab, " as_request=1");
	else
		audit_log_format(ab, " as_request=0");
}

/*
 * medusa_audit_log_callback - callback to log audit record
 * @cad: common audit data to record
 * @medusa_post: post audit callback, unique for type of access, may be NULL
 */
void medusa_audit_log_callback(struct common_audit_data *cad,
			       void (*medusa_post)(struct audit_buffer *, void *))
{
	common_lsm_audit(cad, medusa_pre, medusa_post);
}

/*
 * medusa_simple_file_cb - print out path of a parent directory and a dentry
 * @cad: common audit data to record
 * @pcad: pointer to a struct common_audit_data
 *
 * pcad->medusa_audit_data should contain path and dentry
 */
void medusa_simple_file_cb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	medusa_path_mode_cb(ab, pcad);
	audit_log_format(ab, " name=");
	spin_lock(&mad->path.dentry->d_lock);
	audit_log_untrustedstring(ab, mad->path.dentry->d_name.name);
	spin_unlock(&mad->path.dentry->d_lock);
}

void medusa_path_mode_cb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	medusa_path_cb(ab, pcad);
	audit_log_format(ab, " mode=%d", mad->path.mode);
}

void medusa_path_cb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	audit_log_d_path(ab, " dir=", mad->path.path);
}
