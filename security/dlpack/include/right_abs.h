/* SPDX-License-Identifier: GPL-2.0-only */

//权限抽象组所使用的头文件
#ifndef _RIGHT_ABS_H
#define _RIGHT_ABS_H

#include <linux/sched.h>
#include <linux/types.h>
#include "dl_policy.h"


/*
 * typedef proc_rules - 进程安全上下文之进程所拥有的rules
 * dl_rules - 存储进程所拥有的rules的链表
 */
struct proc_rules {
	struct list_head rules;
};


int dlpack_file_open(struct file*);
int dlpack_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int should_check(void);
int securityfs_check(void);

#endif
