// SPDX-License-Identifier: GPL-2.0-only

#include "l2/audit_medusa.h"

/* array for auditing med_answer,
 * if answers will be modified, think about that too
 */
static const char * const audit_answer[] = {
	"ERROR",
	"FORCE_ALLOW",
	"DENY",
	"FAKE_ALLOW",
	"ALLOW"
};

const char *medusa_audit_answer_name(enum medusa_answer_t answer)
{
	int index = answer + 1;

	if (index < 0 || index >= ARRAY_SIZE(audit_answer))
		return "INVALID";
	return audit_answer[index];
}

const char *medusa_audit_decision_source_name(enum medusa_decision_source source)
{
	switch (source) {
	case MEDUSA_DECISION_AUTH_SERVER:
		return "auth_server";
	case MEDUSA_DECISION_BASELINE:
		return "baseline";
	case MEDUSA_DECISION_ONLINE_REQUIRED:
		return "online_required";
	case MEDUSA_DECISION_INVALID_REPLY:
		return "invalid_reply";
	default:
		return "invalid";
	}
}

const char *medusa_audit_unavailable_name(enum medusa_unavailable_reason reason)
{
	switch (reason) {
	case MEDUSA_AVAILABLE:
		return "none";
	case MEDUSA_NO_AUTH_SERVER:
		return "no_auth_server";
	case MEDUSA_AUTH_SERVER_UNREACHABLE:
		return "auth_server_unreachable";
	case MEDUSA_AUTH_SERVER_UNHEALTHY:
		return "auth_server_unhealthy";
	default:
		return "invalid";
	}
}

void medusa_audit_apply_decision(struct medusa_audit_data *mad,
				 struct medusa_decision_result result)
{
	mad->ans = result.answer;
	mad->as = result.authserver_contacted ? AS_REQUEST : AS_NO_REQUEST;
	mad->decision_metadata = 1;
	mad->decision_source = result.source;
	mad->unavailable = result.unavailable;
}

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
	audit_log_format(ab, " ans=%s", medusa_audit_answer_name(mad->ans));

	if (mad->ans == MED_DENY && mad->as == AS_NO_REQUEST) {
		/* TODO: create a data structure that will be able to store this
		 * information */
	}

	if (mad->as == AS_REQUEST)
		audit_log_format(ab, " as_request=1");
	else
		audit_log_format(ab, " as_request=0");
	if (mad->decision_metadata) {
		audit_log_format(ab, " decision_source=%s",
				 medusa_audit_decision_source_name(
					 mad->decision_source));
		audit_log_format(ab, " unavailable=%s",
				 medusa_audit_unavailable_name(
					 mad->unavailable));
	}
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
