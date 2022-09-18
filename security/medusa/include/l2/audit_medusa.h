#include <linux/types.h>
#include <linux/lsm_audit.h>

#include "l3/constants.h"
#include "l3/vs_model.h"
/* @vsi: virtual spaces intersection flags */
#define VS_INTERSECT 1 /* Virtual spaces are intersected */
#define VS_SW_N 2 /* Virtual spaces see and write are not intersected */
#define VS_SRW_N 3 /* Virtual spaces see, read and write are not intersected */
/* @event: event flags */
#define EVENT_MONITORED 1
#define EVENT_MONITORED_N 2

struct swvs {
	struct vs_t vst;
	struct vs_t vss;
	struct vs_t vsw;
};

struct srwvs {
	struct vs_t vst;
	struct vs_t vss;
	struct vs_t vsr;
	struct vs_t vsw;
};

struct medusa_audit_data {
	const char *function;//medusa access type name
	enum medusa_answer_t med_answer;//medusa answer
	char event;//access type event flags information
	char vsi;//virtual spaces intersection flags

	// Path information for file operations
	const struct path *path;
	struct dentry *dentry;

	/* union of virtual spaces used in access
	 * @sw: vs of target, see and write
	 * @srw: vs of target, see, read and write
	 */
	union {
		struct swvs sw;
		struct srwvs srw;
	} vs;
	/* union of post audit callback data for audit log, some of the basic data are
	 * reused as other record type with same size and type of primitives,
	 * because it makes union smaller.
	 */
	union {
		const char *name;
		int mode;
		struct dentry *dentry2;
		struct {
			struct path *path;
			struct dentry *dentry;
		} rename;
		struct {
			dev_t dev;
			int mode;
		} mknod;
		struct {
			kuid_t uid;
			kgid_t gid;
		} chown;
		struct {
			unsigned int cmd;
			unsigned long arg;
		} fcntl;
		struct {
			unsigned int ipc_class;
			u32 perms;
		} ipc_perm;
		struct {
			long m_type;
			size_t m_ts;
			int flag;
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
void medusa_simple_file_cb(struct audit_buffer *ab, void *pcad);
void medusa_path_cb(struct audit_buffer *ab, void *pcad);
