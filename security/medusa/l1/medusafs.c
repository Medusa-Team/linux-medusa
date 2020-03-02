#include <linux/security.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/medusa/l1/medusafs.h>


#define MEDUSA_VERSION_NUMBER "1.0.0"
#define TMPSIZE 20
#define TMPBUFLEN 12

struct dentry *medusafs_root_dir;


static ssize_t medusa_read_version(struct file *filp, char __user *buf,
				   size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	length = scnprintf(tmpbuf, TMPBUFLEN, "%s\n", MEDUSA_VERSION_NUMBER);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

const struct file_operations medusa_version_ops = {
	.read		= medusa_read_version,
	.llseek		= generic_file_llseek,
};


void medusafs_register_evtype(char *name){
	securityfs_create_file(name, 0444, medusafs_root_dir, NULL, &medusa_version_ops);
}

/*
 * Initiate filesystem
 */
static int __init init_medusafs(void)
{
	struct dentry *acctypes_dir;
	medusafs_root_dir = securityfs_create_dir("medusafs", NULL);
	securityfs_create_file("version", 0444, medusafs_root_dir, NULL, &medusa_version_ops);
	acctypes_dir = securityfs_create_dir("acctypes", medusafs_root_dir);
	securityfs_create_file("test", 0444, acctypes_dir, NULL, &medusa_version_ops);
	return 0;
}



__initcall(init_medusafs);
