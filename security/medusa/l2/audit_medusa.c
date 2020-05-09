#include <linux/audit.h>
#include <linux/medusa/l2/audit_medusa.h>

/* array for auditing medusa answer */
static const char *audit_answer[] = {
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
 */
static void medusa_pre(struct audit_buffer *ab, void *pcad);
static void medusa_pre(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	if (mad->function) {
		audit_log_format(ab, "Medusa {op=%s", mad->function);
	}

	if (mad->med_answer) {
		audit_log_format(ab, " ans=");
		audit_log_string(ab, audit_answer[mad->med_answer+1]);
	}

	switch (mad->vsi) {
	case VS_INTERSECT:
		audit_log_format(ab, " vs={ intersect }");
		break;
	case VS_SW_N:
		if (vs_intersects((&(mad->vs.sw))->vss, (&(mad->vs.sw))->vst))
			audit_log_format(ab, " vs={ S , ");
		else
			audit_log_format(ab, " vs={ ~S , ");
		if (vs_intersects((&(mad->vs.sw))->vsw, (&(mad->vs.sw))->vst))
			audit_log_format(ab, "W }");
		else
			audit_log_format(ab, "~W }");
		break;
	case VS_SRW_N:
		if (vs_intersects((&(mad->vs.srw))->vss, (&(mad->vs.srw))->vst))
			audit_log_format(ab, " vs={ S , ");
		else
			audit_log_format(ab, " vs={ ~S , ");
		if (vs_intersects((&(mad->vs.srw))->vsr, (&(mad->vs.srw))->vst))
			audit_log_format(ab, "R , ");
		else
			audit_log_format(ab, "~R , ");
		if (vs_intersects((&(mad->vs.srw))->vsw, (&(mad->vs.srw))->vst))
			audit_log_format(ab, "W }");
		else
			audit_log_format(ab, "~W }");
		break;
	default:
		break;
	}

	switch (mad->event) {
	case EVENT_NONE:
		audit_log_format(ab, " access=none");
		break;
	case EVENT_MONITORED:
		audit_log_format(ab, " access=monitored");
		break;
	case EVENT_MONITORED_N:
		audit_log_format(ab, " access=refused");
		break;
	}
}

/*
 * medusa_audit_log_callback - callback to log audit record
 * @cad: common audit data to record
 * @medusa_post: post audit callback, unique for type of access, may be NULL
 */
void medusa_audit_log_callback(struct common_audit_data *cad,
		void (*medusa_post) (struct audit_buffer *, void *)) 
{
	if (medusa_post != NULL)
		common_lsm_audit(cad, medusa_pre, medusa_post);
	else
		common_lsm_audit(cad, medusa_pre, NULL);
}
