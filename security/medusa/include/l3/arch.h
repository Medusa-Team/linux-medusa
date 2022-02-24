/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_ARCH_H
#define _MEDUSA_ARCH_H
#include "l3/config.h"

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

/* sanity checks for decision */
#include <linux/sched.h>
#include <linux/interrupt.h>
#define ARCH_CANNOT_DECIDE(x) (!in_task() || current->pid == 0)

#endif
