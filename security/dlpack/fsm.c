// SPDX-License-Identifier: GPL-2.0-only

#include <linux/sysctl.h>
#include <linux/slab.h>
#include "include/dlpack.h"
#include "include/state.h"

/**
 * init_global_fsm - 初始化全局状态机
 *
 * Return:
 *   void
 */
void init_global_fsm(void)
{
	dlpack_fsm = kmalloc(sizeof(*dlpack_fsm), GFP_KERNEL);
	dlpack_fsm->state_id = 0;
	seqlock_init(&dlpack_fsm->fsm_lock); //初始化锁
}

/**
 * get_global_state - 获取全局状态
 *
 * Return:
 *   state: 全局状态
 */
struct fsm_state *get_global_state(void)
{
	unsigned long seq;
	struct fsm_state *state;
 
	do { 
		seq = read_seqbegin(&dlpack_fsm->fsm_lock); 
		/* -------- 进入读临界区 ---------*/
		state = dlpack_fsm->state;
		/* -------- 退出写临界区 ---------*/
	} while (read_seqretry(&dlpack_fsm->fsm_lock, seq)); 
	
	return state;
}

/**
 * find_trans_item - 对输入的event寻找符合的状态转换表项
 * @state: 状态
 * @event: 事件ID
 *
 * Return: 目标表项，若找不到则返回NULL
 */
struct fsm_trans_list *find_trans_item(struct fsm_state *state, int event)
{
	struct fsm_trans_list *plist;

	hash_for_each_possible(state->trans, plist, node, event) {
		if (plist->event == event) {
			dlpack_info("Found trans table item.\n");
			return plist;
		}
	}
	//dlpack_info("Can't find trans table item.\n");
	return NULL;
}

/**
 * fsm_run - 对输入的event进行一次状态转换
 * @fsm: 状态机
 * @evt_id: 事件ID
 *
 * Return:
 *   0: 成功转换到下个状态
 *   1: 转换到下个状态失败（未通过guard）
 *   2: FSM failure, 例如无法找到满足条件的表项
 */
int fsm_run(struct fsm *fsm, int event)
{
	struct fsm_state *state, *next_state;
	struct fsm_trans_list *target_trans_item;
	int ori_state_id;

	if (event >= MAX_STATE_LEN) {
		dlpack_info("Event id too large.");
		return 1;
	}

	ori_state_id = fsm->state->id;
	fsm->state_id = fsm->state_id ^ (1 << event);

	if (fsm->state == get_state(1 << MAX_STATE_LEN)) {
		next_state = get_state(fsm->state_id);

		if (!next_state) {
			dlpack_info("Still not the state we care. Current atomic state: %d", fsm->state_id);
			return 2;
		}
	} else {
		target_trans_item = find_trans_item(fsm->state, event);

		if (!target_trans_item) {
			next_state = get_state(1 << MAX_STATE_LEN);
		} else if (target_trans_item->guard && !target_trans_item->guard(fsm)) {
			dlpack_info("Guard failed.\n");
			fsm->state_id = fsm->state_id ^ (1 << event);
			return 1;
		} else {
			next_state = target_trans_item->next_state;
		}
	}

	state = fsm->state;
	if (state->exit_action)
		state->exit_action(state);

	write_seqlock(&dlpack_fsm->fsm_lock);//禁止内核抢占
	/* -------- 进入写临界区 ---------*/
	fsm->state = next_state;
	/* -------- 退出写临界区 ---------*/
	write_sequnlock(&dlpack_fsm->fsm_lock);

	state = fsm->state;
	if (state->entry_action)
		state->entry_action(state);

	dlpack_info("State trans from %d to %d success. Current atomic state: %d", ori_state_id, fsm->state->id, fsm->state_id);

	return 0;
}
