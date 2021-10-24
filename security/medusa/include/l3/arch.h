#ifndef _MEDUSA_ARCH_H
#define _MEDUSA_ARCH_H
#include <linux/spinlock.h>
#include "l3/config.h"

/* data locks */
#define MED_DECLARE_LOCK_DATA(name)	extern rwlock_t name
#define MED_LOCK_DATA(name)		DEFINE_RWLOCK(name)
#define MED_LOCK_R(name)		{ 			\
					barrier(); 		\
					read_lock(&name);	\
					barrier();		\
					}

#define MED_LOCK_W(name)		{			\
					barrier();		\
					write_lock(&name);	\
					barrier();		\
					}
#define MED_UNLOCK_R(name)		{			\
					barrier();		\
					read_unlock(&name); 	\
					barrier();		\
					}
#define MED_UNLOCK_W(name)		{			\
					barrier();		\
					write_unlock(&name);	\
					barrier();		\
					}

/* debug output */
#ifdef CONFIG_MEDUSA_QUIET
#define med_pr_emerg(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define med_pr_alert(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define med_pr_crit(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define med_pr_err(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define med_pr_warn(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define med_pr_notice(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define med_pr_info(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define med_pr_debug(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define med_pr_devel(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#else
#define med_pr_emerg(fmt, ...) pr_emerg("medusa | " KBUILD_MODNAME ": " fmt, ##__VA_ARGS__)
#define med_pr_alert(fmt, ...) pr_alert("medusa | " KBUILD_MODNAME ": " fmt, ##__VA_ARGS__)
#define med_pr_crit(fmt, ...) pr_crit("medusa | " KBUILD_MODNAME ": " fmt, ##__VA_ARGS__)
#define med_pr_err(fmt, ...) pr_err("medusa | " KBUILD_MODNAME ": " fmt, ##__VA_ARGS__)
#define med_pr_warn(fmt, ...) pr_warn("medusa | " KBUILD_MODNAME ": " fmt, ##__VA_ARGS__)
#define med_pr_notice(fmt, ...) pr_notice("medusa | " KBUILD_MODNAME ": " fmt, ##__VA_ARGS__)
#define med_pr_info(fmt, ...) pr_info("medusa | " KBUILD_MODNAME ": " fmt, ##__VA_ARGS__)
#define med_pr_debug(fmt, ...) pr_debug("medusa | " KBUILD_MODNAME ": " fmt, ##__VA_ARGS__)
#define med_pr_devel(fmt, ...) pr_devel("medusa | " KBUILD_MODNAME ": " fmt, ##__VA_ARGS__)
#endif

/* non-atomic bit set/clear/test operations */
#include <linux/bitmap.h>
#define MED_SET_BIT(bitnr, ptr) set_bit((bitnr), (ptr).pack)
#define MED_CLR_BIT(bitnr, ptr) clear_bit((bitnr), (ptr).pack)
#define MED_TST_BIT(bitnr, ptr) test_bit((bitnr), (ptr).pack)

/* sanity checks for decision */
#include <linux/sched.h>
#include <linux/interrupt.h>
#define ARCH_CANNOT_DECIDE(x) (!in_task() || current->pid == 0)

/* linkage */ /* FIXME: is this needed? */
#include <linux/module.h>

#define MEDUSA_EXPORT_SYMBOL(symname) EXPORT_SYMBOL(x)
#define MEDUSA_INIT_FUNC(symname) module_init(symname)
#define MEDUSA_EXIT_FUNC(symname) module_exit(symname)
#define MEDUSA_KETCHUP MODULE_LICENSE("GPL");

#endif
