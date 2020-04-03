#include <linux/audit.h>
#include <linux/medusa/l2/audit_medusa.h>

static void medusa_pre(struct audit_buffer *ab, void *pcad){
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	audit_log_format(ab,"medusa {op=%s answer=",mad->function);
	switch (mad->med_answer) {
	case MED_OK:
		audit_log_format(ab,"MED_OK ");
		break;
	case MED_SKIP:
		audit_log_format(ab,"MED_SKIP ");
		break;
	case MED_NO:
		audit_log_format(ab,"MED_NO ");
		break;
	case MED_YES:
		audit_log_format(ab,"MED_YES ");
		break;
	case MED_ERR:
		audit_log_format(ab,"MED_ERR ");
		break;	
	}
}

static void medusa_post(struct audit_buffer *ab, void *pcad){
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;
	
	audit_log_format(ab, "{subj,obj}=");
	if (mad->med_subject != NULL && mad->med_object != NULL) {
		audit_log_format(ab,"valid vs_intersect={");
	} else {
		audit_log_format(ab, "invalid vs_intersect{");
	}

	switch (mad->vsi)
	case VSI_NONE:
		audit_log_format(ab, "none} ");
		break;
	case VSI_UNKNOWN:
		audit_log_format(ab, "unknown} ");
		break;
	case VSI_SW:
		audit_log_format(ab, "seeable,writeable} ");
		break;
	case VSI_SW_N:
		if (VS_INTERSECT(mad->med_subject->vss , mad->med_object->vs)) {
			audit_log_format(ab, "seeable,");
		} else {
			audit_log_format(ab, "~seeable,");
		}
		if(VS_INTERSECT(mad->med_subject->vsr , mad->med_object->vs)) {
			audit_log_format(ab,"writeable} ");
			break;
		} else {
			audit_log_format(ab,"~writeable} ");
			break;
		}
	case VSI_SRW:
		audit_log_format(ab, "seeable,readable,writeable} ");
		break;	
	case VSI_SRW_N:
		if (VS_INTERSECT(mad->med_subject->vss , mad->med_object->vs))
			audit_log_format(ab, "seeable,");
		else
			audit_log_format(ab, "~seeable,");
		if (VS_INTERSECT(mad->med_subject->vsr , mad->med_object->vs))
			audit_log_format(ab, "readable,");
		else
			audit_log_format(ab, "~readable,");
		if (VS_INTERSECT(mad->med_subject->vsw , mad->med_object->vs)) {
			audit_log_format(ab, "writeable} ");
			break;
		} else {
			audit_log_format(ab, "~writeable} ");
			break;
		}
	

	audit_log_format(ab, "access=");
	if(mad->event == EVENT_MONITORED) {
		audit_log_format(ab, "monitored");
	} else if (mad->event == EVENT_MONITORED_N) {
		audit_log_format(ab, "~monitored");
	} else {
		audit_log_format(ab, "unknown");
	}
}

void medusa_audit_log_callback(struct common_audit_data *cad){
	common_lsm_audit(cad, medusa_pre, medusa_post);	
}
