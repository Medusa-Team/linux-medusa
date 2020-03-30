#include <linux/lsm_audit.h>
#include <linux/medusa/l3/kobject.h>

#define VSI_NONE 1
#define VSI_UNKNOWN 2
#define VSI_SW 3
#define VSI_SW_N 5	
#define VSI_SRW 5
#define VSI_SRW_N 6

#define EVENT_UNKNOWN 1
#define EVENT_MONITORED 2
#define EVENT_MONITORED_N 3

struct medusa_audit_data {
	struct medusa_object_s med_object;
	struct medusa_subject_s med_subject;
	const char *function;//function name - audited as operation
	medusa_answer_t med_answer;
	char vsi;
	char event;
};

void medusa_audit_log_callback(struct common_audit_data *cad);
