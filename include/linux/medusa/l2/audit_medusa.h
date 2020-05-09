#include <linux/types.h>
#include <linux/lsm_audit.h>
#include <linux/medusa/l3/kobject.h>
#include <linux/medusa/l3/vsmodel.h>
/* @vsi: virtual spaces intersection flags */
#define VS_INTERSECT 1 /* Virtual spaces are intersected */
#define VS_SW_N 2 /* Virtual spaces see and write are not intersected */
#define VS_SRW_N 3 /* Virtual spaces see, read and write are not intersected */
/* @event: event flags */
#define EVENT_NONE 1
#define EVENT_MONITORED 2
#define EVENT_MONITORED_N 3

struct swvs {
	vs_t vst;
	vs_t vss;
	vs_t vsw;
};

struct srwvs {
	vs_t vst;
	vs_t vss;
	vs_t vsr;
	vs_t vsw;
};

struct medusa_audit_data {
	const char *function;
	medusa_answer_t med_answer;
	char event;
	char vsi;
	/* union of virtual spaces used in access
	 * @sw: vs of target, see and write
	 * @srw: vs of target, see, read and write
	 */
	union {
		struct swvs sw;
		struct srwvs srw;
	} vs;
	/* union of post audit callback data for audit log */
	union {
		char *filename;
		int mode;
		struct {
			dev_t dev;
			int mode;
		} mknod;
		struct {
			unsigned int ipc_class;
			u32 r_perm;
		} ipc_perm;
		struct {
			long m_type;
			size_t m_ts;
			int flg;
			unsigned int ipc_class;
			long type;
			pid_t target;
		} ipc_msg;
		struct {
			unsigned int ipc_class;
			char __user *shmaddr; 
			int shmflg;
		} ipc_shmat;
		struct {
			unsigned int ipc_class;
			unsigned int sem_num;
			int sem_op;
			int sem_flg;
			unsigned int nsops;
		   	int alter;
		} ipc_semop;
		struct {
			unsigned int ipc_class;
			int flcm;//flag or cmd
		} ipc;
	} pacb;
};

void medusa_audit_log_callback(struct common_audit_data *cad,
		void (*medusa_post) (struct audit_buffer *, void *));
