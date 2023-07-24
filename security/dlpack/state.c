// SPDX-License-Identifier: GPL-2.0-only
#include <linux/types.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "include/dlpack.h"
#include "include/action.h"
#include "include/state.h"
#include "include/dl_policy.h"

static DEFINE_HASHTABLE(fsm_states, 10);
static DEFINE_HASHTABLE(trie_nodes, 8);

int _add_state(int id, bool is_state, int syscall_pattern_id) {
	struct fsm_state *state, *next_state;
	int i, ret;

	ret = 0;

	state = kmalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		return -ENOMEM;
	}

	state->id = id;
	hash_init(state->trans);
	state->entry_action = entry_print_state;
	state->exit_action = exit_print_state;
	state->syscall_pattern_id = syscall_pattern_id;
	if (is_state) {
		for (i = 0; i < MAX_STATE_LEN; i++) {
			next_state = get_state(id ^ (1 << i));
			if (next_state) {
				ret = add_trans(state, next_state, i);
				if (ret != 0) {
					goto free_state;
				}
				ret = add_trans(next_state, state, i);
				if (ret != 0) {
					goto free_state;
				}
			}
		}
		hash_add(fsm_states, &state->node, id);
		if (dlpack_fsm->state_id == id) {
			dlpack_fsm->state = state;
		}
	} else {
		hash_add(trie_nodes, &state->node, id);
	}
	INIT_LIST_HEAD(&state->rule_head);

	dlpack_info("Add state: %d", id);
	return ret;

free_state:
	kfree(state);
	return ret;
}

/**
 * add_state - 添加状态
 * @id: 状态号
 *
 * Return: 
 *   0: 成功添加状态
 *   Others: 失败
 */
int add_state(int id)
{
	return _add_state(id, true, 0);
}

/**
 * add_trie_node - 添加字典树节点
 * @id: 状态号
 *
 * Return: 
 *   0: 成功添加状态
 *   Others: 失败
 */
int add_trie_node(int id, int syscall_pattern_id)
{
	return _add_state(id, false, syscall_pattern_id);
}


#define _get_state(hashtable, _id)				\
	struct fsm_state *state;				\
								\
	hash_for_each_possible(hashtable, state, node, _id) {	\
		if (state->id == _id) {				\
			return state;				\
		}						\
	}							\
								\
	return NULL;						\

/**
 * get_state - 获得状态
 * @param id: 状态号
 *
 * Return: 状态指针
 */
struct fsm_state *get_state(int id)
{
	_get_state(fsm_states, id)
}

/**
 * get_trie_node - 获得字典树的节点
 * @param id: 状态号
 *
 * Return: 状态指针
 */
struct fsm_state *get_trie_node(int id)
{
	_get_state(trie_nodes, id)
}

/**
 * reset_states - 重置所有状态
 *
 * Return: void
 */
void reset_states(void)
{
	int bkt;
	struct fsm_state *state;
	struct hlist_node *next;

	dlpack_fsm->state = get_state(1 << MAX_STATE_LEN);

	hash_for_each_safe(fsm_states, bkt, next, state, node) {
		trans_del(state);
		rules_del(&state->rule_head);
		if (state->id != 1 << MAX_STATE_LEN) {
			hash_del(&state->node);
			kfree(state);
		}
	}

	hash_for_each_safe(trie_nodes, bkt, next, state, node) {
		trans_del(state);
		if (state->id != 0) {
			hash_del(&state->node);
			kfree(state);
		}
	}
	rules_del(&sysp_rules);
	sp_cnt = 1;
	syscall_pattern_version++;
}

/**
 * init_states - 初始化状态
 *
 * Return:
 *   0: 成功初始化
 *   Others: 初始化失败
 */
int init_states(void)
{
	int ret;

	ret = 0;

	ret = add_state(1 << MAX_STATE_LEN);
	if (ret != 0) {
		return ret;
	}
	dlpack_fsm->state = get_state(1 << MAX_STATE_LEN);

	return ret;
}

/**
 * init_trie - 初始化字典树
 *
 * Return:
 *   0: 成功初始化
 *   Others: 初始化失败
 */
int init_trie(void)
{
	int ret;
	
	ret = 0;
	ret = add_trie_node(0, -1);
	return ret;
}


/**
 * print_all_state - 展示所有state
 *
 * Return: void
 */
void print_all_state(void)
{
	int bkt;
	struct fsm_state *state;
	struct dl_rule *rule;

	hash_for_each(fsm_states, bkt, state, node) {
		dlpack_info("state: %d", state->id);
		list_for_each_entry(rule, &state->rule_head, node) {
			dlpack_info("keyword: %d, dl_safe_level: %d, rtype: %d, cap_num: %d, file_limits: %d, file_path: %s",
				rule->keyword, rule->dl_safe_level,
				rule->object.rtype, rule->object.limits,
				rule->object.limits,
				rule->object.file_path);
		}
	}
}