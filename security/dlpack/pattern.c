// SPDX-License-Identifier: GPL-2.0-only

#include <linux/sysctl.h>
#include <linux/slab.h>
#include "include/dlpack.h"
#include "include/state.h"
#include "include/event.h"
#include "include/pattern.h"

int syscall_pattern_version = 0;
struct list_head sysp_rules;

/**
 * task_init - 初始化进程syscall pattern机制
 * @ctx: 进程安全上下文
 *
 * Return:
 *   0: 成功初始化
 *   Others: 失败
 */
int task_init(struct task_ctx *ctx)
{
	struct fsm_state *state;
	struct fsm_trans_list *trans;
	struct pattern *cur;
	int bkt;

	state = get_trie_node(0);
	hash_init(ctx->waiting_events);
	ctx->satisfied = 0;
	ctx->version = 0;
	hash_for_each (state->trans, bkt, trans, node) {
		cur = kmalloc(sizeof(*cur), GFP_KERNEL);
		cur->evt_id = trans->event;
		cur->state = trans->next_state;
		hash_add(ctx->waiting_events, &cur->node, cur->evt_id);
	}

	return 0;
}

/**
 * copy_task_waiting - 复制初始化
 * @new_ctx: 子进程安全上下文
 * @old_ctx: 父进程安全上下文
 *
 * Return:
 *   0: 成功初始化
 *   Others: 失败
 */
int copy_task_waiting(struct task_ctx *new_ctx, struct task_ctx *old_ctx)
{
	int bkt;
	struct pattern *p, *cur;
	hash_init(new_ctx->waiting_events);
	hash_for_each (old_ctx->waiting_events, bkt, p, node) {
		cur = kmalloc(sizeof(*cur), GFP_KERNEL);
		cur->evt_id = p->evt_id;
		cur->state = p->state;
		hash_add(new_ctx->waiting_events, &cur->node, cur->evt_id);
	}
	new_ctx->satisfied = old_ctx->satisfied;
	new_ctx->version = old_ctx->version;

	return 0;
}

/**
 * task_free - 释放进程的syscall pattern相关资源
 * @ctx: 进程安全上下文
 *
 * Return:
 *   void
 */
void task_free(struct task_ctx *ctx)
{
	int bkt;
	struct pattern *p;
	struct hlist_node *next;

	hash_for_each_safe (ctx->waiting_events, bkt, next, p, node) {
		hash_del(&p->node);
		kfree(p);
	}
}

/**
 * process_syscall - 处理进程的执行的syscall
 * @ctx: 进程安全上下文
 * @event: syscall对应的事件名
 *
 * Return:
 *   0: 成功处理
 *   Others: 失败
 */
int process_syscall(struct task_ctx *ctx, char *event)
{
	int event_id;
	int bkt;
	struct pattern *p, *cur;
	struct fsm_trans_list *trans;
	struct hlist_node *next;
	bool is_end_state;

	if (ctx->version < syscall_pattern_version) {
		task_free(ctx);
		task_init(ctx);
		ctx->version = syscall_pattern_version;
	}

	event_id = get_event_id(event);
	if (event_id == -EINVAL) {
		return event_id;
	}

	hash_for_each_possible_safe(ctx->waiting_events, p, next, node, event_id) {
		if (p->evt_id == event_id) {
			is_end_state = true;
			hash_for_each(p->state->trans, bkt, trans, node) {
				cur = kmalloc(sizeof(*cur), GFP_KERNEL);
				cur->evt_id = trans->event;
				cur->state = trans->next_state;
				hash_add(ctx->waiting_events, &cur->node, cur->evt_id);
				is_end_state = false;
			}
			if (is_end_state) {
				ctx->satisfied = ctx->satisfied | (1ULL << p->state->syscall_pattern_id);
				dlpack_info("Proc %d satisfied syscall pattern %d.", current->pid, p->state->syscall_pattern_id);
			}
			hash_del(&p->node);
			kfree(p);
		}
	}
	
	return 0;
}