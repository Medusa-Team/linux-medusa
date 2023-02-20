/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/types.h>
#include <linux/lsm_audit.h>

#include "l3/constants.h"
#include "l3/vs_model.h"

/* Values for &medusa_audit_data->as */
#define AS_NO_REQUEST 0
#define AS_REQUEST 1

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
	/** @function: medusa access type name TODO: change to a numeric code */
	const char *function;
	enum medusa_answer_t ans;
	/** @as: 1 if authorization server was contacted */
	char as : 1;

	/**
	 * union of virtual spaces used in access
	 * @sw: vs of target, see and write
	 * @srw: vs of target, see, read and write
	 * TODO: change to a pointer to a special structure
	 */
	union {
		struct swvs sw;
		struct srwvs srw;
	} vs;

	/**
	 * union of post audit callback data for audit log, some of the basic data are
	 * reused as other record type with same size and type of primitives,
	 * because it makes union smaller.
	 */
	union {
		struct {
			const struct path *path;
			int mode;
			struct dentry *dentry;
			dev_t dev;
		} path;
		struct {
			const struct path *path;
			kuid_t uid;
			kgid_t gid;
		} chown;
		struct {
			const struct path *dir;
			struct dentry *dentry;
			const char *name;
		} name;
		struct {
			const struct path *old_dir;
			const struct path *new_dir;
			struct dentry *old_dentry;
			struct dentry *new_dentry;
		};
		struct {
			const struct path *path;
			unsigned int cmd;
			unsigned long arg;
		} fcntl;
		struct {
			unsigned int ipc_class;
			int cmd;
		} ipc_ctl;
		struct {
			unsigned int ipc_class;
			u32 perms;
		} ipc_perm;
		struct {
			int flag;
			long m_type;
			size_t m_ts;
			long type;
			pid_t target;
			unsigned int ipc_class;
		} ipc;
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
			char __user *shmaddr;
			int shmflg;
		} ipc_shmat;
		/** @mask: for acctype_permission */
		int mask;
		struct {
			uid_t ruid;
			uid_t euid;
			uid_t suid;
			uid_t old_ruid;
			uid_t old_euid;
			uid_t old_suid;
		} setresuid;
	};
};

void medusa_audit_log_callback(struct common_audit_data *cad,
			       void (*medusa_post)(struct audit_buffer *, void *));
void medusa_simple_file_cb(struct audit_buffer *ab, void *pcad);
void medusa_path_mode_cb(struct audit_buffer *ab, void *pcad);
void medusa_path_cb(struct audit_buffer *ab, void *pcad);
