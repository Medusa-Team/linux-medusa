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
	return medusa_decision_source_name(source);
}

const char *medusa_audit_unavailable_name(enum medusa_unavailable_reason reason)
{
	return medusa_unavailable_reason_name(reason);
}

void medusa_audit_apply_decision(struct medusa_audit_data *mad,
				 struct medusa_decision_result result)
{
	mad->ans = result.answer;
	mad->as = result.authserver_contacted ? AS_REQUEST : AS_NO_REQUEST;
	mad->decision_metadata = 1;
	mad->decision_source = result.source;
	mad->unavailable = result.unavailable;
	mad->request_present = result.request_present;
	mad->request_id = result.request_id;
	mad->policy_generation = result.policy_generation;
}

void medusa_audit_apply_local(struct medusa_audit_data *mad,
			      enum medusa_answer_t answer,
			      enum medusa_decision_source source)
{
	mad->ans = answer;
	mad->as = AS_NO_REQUEST;
	mad->decision_metadata = 1;
	mad->decision_source = source;
	mad->unavailable = MEDUSA_AVAILABLE;
	mad->request_present = 0;
	mad->request_id = 0;
	mad->policy_generation = medusa_current_policy_generation();
}

enum medusa_answer_t medusa_audit_decision_result(
	const char *operation, struct medusa_decision_result result,
	bool audit_requested)
{
	struct common_audit_data cad;
	struct medusa_audit_data mad = { MEDUSA_AUDIT_DATA_INIT };

	medusa_audit_apply_decision(&mad, result);
	if (audit_requested || mad.unavailable != MEDUSA_AVAILABLE) {
		cad.type = LSM_AUDIT_DATA_NONE;
		cad.u.tsk = current;
		mad.function = operation;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, NULL);
	}
	return mad.ans;
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
		audit_log_format(ab, " policy_generation=%llu",
				 (unsigned long long)mad->policy_generation);
		audit_log_format(ab, " request_present=%u request_id=%llu",
				 mad->request_present,
				 (unsigned long long)mad->request_id);
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
