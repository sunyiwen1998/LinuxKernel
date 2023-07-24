// SPDX-License-Identifier: GPL-2.0-only
#include <linux/types.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "include/dlpack.h"
#include "include/state.h"
#include "include/event.h"

/**
 * add_trans - 添加状态转换规则
 * @ori: 原状态
 * @target: 目标状态
 * @event: 触发事件
 *
 * Return: 
 *   0: 成功添加状态转换规则
 *   Others: 失败
 */
int add_trans(struct fsm_state *ori_p, struct fsm_state *target_p, int event_id)
{
	struct fsm_trans_list *trans;

	if (!ori_p || !target_p) {
		return -EINVAL;
	}

	trans = kmalloc(sizeof(*trans), GFP_ATOMIC);
	if (!trans) {
		return -ENOMEM;
	}
	trans->event = event_id;
	trans->guard = NULL;
	trans->next_state = target_p;
	hash_add(ori_p->trans, &trans->node, trans->event);

	dlpack_info("Add trans: %d -> %d, trigger event %d.", ori_p->id, target_p->id,
		event_id);

	return 0;
}

/**
 * trans_del - 删除state的所有转换规则
 * @state: 原状态
 *
 * Return: void
 */
void trans_del(struct fsm_state *state)
{
	int bkt;
	struct fsm_trans_list *trans;
	struct hlist_node *next;

	hash_for_each_safe(state->trans, bkt, next, trans, node) {
		hash_del(&trans->node);
		kfree(trans);
	}
}