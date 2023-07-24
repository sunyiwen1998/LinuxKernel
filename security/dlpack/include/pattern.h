/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _DLPACK_PATTERN_H
#define _DLPACK_PATTERN_H

#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/sched.h>
#include "state.h"

struct pattern {
	int evt_id;
	struct fsm_state *state;
	struct hlist_node node;
};

int process_syscall(struct task_ctx *ctx, char *event);
int task_init(struct task_ctx *ctx);
void task_free(struct task_ctx *ctx);
int copy_task_waiting(struct task_ctx *new_ctx, struct task_ctx *old_ctx);

#endif  /* _DLPACK_PATTERN_H */
