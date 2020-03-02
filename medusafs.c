#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pagemap.h> 	/* PAGE_CACHE_SIZE */
#include <linux/fs.h>     	/* This is where libfs stuff is declared */
#include <linux/mount.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>	/* copy_to_user */


#define MEDUSAFS_MAGIC 0x19920342
#define MEDUSA_VERSION_NUMBER "1.0.0"
#define TMPSIZE 20
#define TMPBUFLEN 12




static ssize_t medusa_read_version(struct file *filp, char __user *buf,
				   size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	length = scnprintf(tmpbuf, TMPBUFLEN, "%s\n", MEDUSA_VERSION_NUMBER);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations medusa_version_ops = {
	.read		= medusa_read_version,
	.llseek		= generic_file_llseek,
};



/*
 * Initiate filesystem
 */
static int __init init_medusafs(void)
{
	struct dentry *medusa_root_dir;
	struct dentry *acctypes_dir;
	medusa_root_dir = securityfs_create_dir("medusafs", NULL);
	securityfs_create_file("version", 0444, medusa_root_dir, NULL, &medusa_version_ops);
	acctypes_dir = securityfs_create_dir("acctypes", medusa_root_dir);
	securityfs_create_file("test", 0444, acctypes_dir, NULL, &medusa_version_ops);
	return 0;
}



__initcall(init_medusafs);
