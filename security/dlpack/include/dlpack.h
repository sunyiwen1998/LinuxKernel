/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Header file for DLPack.
 */

#ifndef _DLPACK_DLPACK_H
#define _DLPACK_DLPACK_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/lsm_hooks.h>
#include <linux/seqlock.h>
#include "state.h"
#include "right_abs.h"

#define MAX_STATE_LEN 20

/**
 * typedef fsm - 状态机
 * @state_id: 状态机当前状态的状态号
 * @thread: 状态机关联的进程
 * @list: 状态机所在链表的节点
 */
struct fsm {
	seqlock_t fsm_lock;//定义顺序锁
	struct fsm_state *state;
	struct task_struct *thread;
	struct hlist_node list;
	int state_id;
};

/**
 * typedef task_ctx - 进程安全上下文
 * @fsms: 进程关联的状态机
 */
struct task_ctx {
	DECLARE_HASHTABLE(waiting_events, 6);
	int version;
	int satisfied;
	struct proc_rules *pr;
};

extern struct lsm_blob_sizes dlpack_blob_sizes;

static inline struct task_ctx *get_task_ctx(struct task_struct *task)
{
	return task->security + dlpack_blob_sizes.lbs_task;
}

extern struct fsm *dlpack_fsm;
extern int syscall_pattern_version;
extern struct list_head sysp_rules;
extern int sp_cnt;

void init_global_fsm(void);
int init_proc_perm(struct task_ctx *ctx);
void free_proc_perm(struct task_ctx *ctx);
int fsm_run(struct fsm *fsm, int event);
int init_event_timer(void);
unsigned int hash(const char *__kernel key);
struct fsm_state *get_global_state(void);
int get_task_state_id(struct task_struct *task);

#define MODULE_PREFIX "dlpack: "
#define _dlpack_pr(kind, fmt, ...) \
	pr_##kind(MODULE_PREFIX "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define dlpack_err(fmt, ...) _dlpack_pr(err, fmt, ##__VA_ARGS__)

#ifdef DEBUG 
#define dlpack_info(fmt, ...) _dlpack_pr(info, fmt, ##__VA_ARGS__)
#define dlpack_debug dlpack_info
#else
#define dlpack_info(fmt, ...) do {} while (0)
#define dlpack_debug(fmt, ...) do {} while (0)
#endif // DEBUG

#endif /* _DLPACK_DLPACK_H */
