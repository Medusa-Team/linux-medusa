#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/limits.h>
#include <linux/medusa/l1/medusafs.h>
#include <linux/medusa/l3/registry.h>
#include <linux/medusa/l3/med_model.h>
#include "../l2/kobject_file.h"

#define TMPBUFLEN 20

struct dentry *medusafs_root_dir;
struct dentry *acctypes_dir;
struct dentry *get_vs_input;

static ssize_t medusa_read_version(struct file *filp, char __user *buf,
				   size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	
	length = scnprintf(tmpbuf, TMPBUFLEN, "%s\n", MEDUSA_VERSION_NUMBER);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static ssize_t medusa_read_acctypes(struct file *filp, char __user *buf,
				   size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	struct medusa_evtype_s *p;

	for (p = evtypes; p; p = p->next)
		if (strcmp(p->name, filp->f_path.dentry->d_parent->d_iname) == 0)
			break;

	if (!p)
		return -EFAULT;

	if (strcmp("allowed",filp->f_path.dentry->d_iname) == 0)
		length = scnprintf(tmpbuf, TMPBUFLEN, "%llu\n", p->allowed);
	else if (strcmp("denied",filp->f_path.dentry->d_iname) == 0)
		length = scnprintf(tmpbuf, TMPBUFLEN, "%llu\n", p->denied);
	else if (strcmp("audit",filp->f_path.dentry->d_iname) == 0)
		length = scnprintf(tmpbuf, TMPBUFLEN, "%d\n", p->audit);
	else
		return 0;
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static ssize_t medusa_write_audit(struct file *filp, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	bool input;
	struct medusa_evtype_s *p;

	if (*ppos != 0)
		return -EINVAL;
	if (count >= TMPBUFLEN)
		return -EINVAL;

	for (p = evtypes; p; p = p->next)
		if (strcmp(p->name, filp->f_path.dentry->d_parent->d_iname) == 0)
			break;

	if (!p)
		return -EFAULT;

	memset(tmpbuf, 0, TMPBUFLEN);
	if (copy_from_user(tmpbuf, buf, count))
		return -EFAULT;
	input = (bool)simple_strtol(tmpbuf, NULL, 10);
	if (input)
		p->audit=1;
	else
		p->audit=0;

	return count;
}

static ssize_t medusa_read_get_vs(struct file *filp, char __user *buf,
				   size_t count, loff_t *ppos)
{
	char *tmpbuf, *path, *tmpbuf_path;
	ssize_t length, output;
	struct inode *inode;
	
	tmpbuf = kmalloc(PATH_MAX + TMPBUFLEN, GFP_KERNEL);
	tmpbuf_path = kmalloc(PATH_MAX, GFP_KERNEL);

	if (get_vs_input == NULL) {
		length = scnprintf(tmpbuf, PATH_MAX + TMPBUFLEN, "No path written\n");
		goto out;
	}
	path = dentry_path_raw(get_vs_input, tmpbuf_path, PATH_MAX);
	inode = get_vs_input->d_inode;
	if (inode->i_security == NULL) {
		length = scnprintf(tmpbuf, PATH_MAX + TMPBUFLEN, "%s has no security struct\n", path);
		goto out;
	}
	length = scnprintf(tmpbuf, PATH_MAX + TMPBUFLEN, "%s - %u\n", path, inode_security(inode)->med_object.vs.vspack[0]);
out:
	output = simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
	kfree(tmpbuf);
	kfree(tmpbuf_path);
	return output;
}

static ssize_t medusa_write_get_vs(struct file *filp, const char __user *buf,
				              size_t count, loff_t *ppos)
{
	char *tmpbuf;
	struct path path;
	int err;

	if (*ppos != 0)
		return -EINVAL;
	if (count >= PATH_MAX)
		return -EINVAL;

	tmpbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (copy_from_user(tmpbuf, buf, count)) {
		kfree(tmpbuf);
		return -EFAULT;
	}
	tmpbuf[count-1]= '\0';

	err = kern_path(tmpbuf, LOOKUP_FOLLOW, &path);
	kfree(tmpbuf);
	if (err)
		return err;

	get_vs_input = path.dentry;
	return count;
}

const struct file_operations medusa_version_ops = 
{
	.read		= medusa_read_version,
	.llseek		= generic_file_llseek,
};

const struct file_operations medusa_acctypes_ops = 
{
	.read		= medusa_read_acctypes,
	.llseek		= generic_file_llseek,
};

const struct file_operations medusa_audit_ops = 
{
	.read		= medusa_read_acctypes,
	.write 		= medusa_write_audit,
	.llseek		= generic_file_llseek,
};

const struct file_operations medusa_get_vs_ops = 
{
	.read		= medusa_read_get_vs,
	.write 		= medusa_write_get_vs,
	.llseek		= generic_file_llseek,
};

/* create folder with files for acctype registered by med_register_evtype in registry.c in l3*/
void medusafs_register_evtype(char *name)
{
	struct dentry *acctype_dir;

	if (strcmp(name, "fuck") == 0 || strcmp(name, "getipc") == 0 || strcmp(name, "getfile") == 0
	    || strcmp(name, "getprocess") == 0 || strcmp(name, "get_socket") == 0)
		return;

	acctype_dir = securityfs_create_dir(name, acctypes_dir);
	securityfs_create_file("allowed", 0444, acctype_dir, NULL, &medusa_acctypes_ops);
	securityfs_create_file("denied", 0444, acctype_dir, NULL, &medusa_acctypes_ops);
	securityfs_create_file("audit", 0666, acctype_dir, NULL, &medusa_audit_ops);
}

/* Initiate filesystem */
static int __init init_medusafs(void)
{
	medusafs_root_dir = securityfs_create_dir("medusafs", NULL);
	securityfs_create_file("version", 0444, medusafs_root_dir, NULL, &medusa_version_ops);
	securityfs_create_file("get_vs", 0666, medusafs_root_dir, NULL, &medusa_get_vs_ops);
	acctypes_dir = securityfs_create_dir("acctypes", medusafs_root_dir);
	return 0;
}

__initcall(init_medusafs);
