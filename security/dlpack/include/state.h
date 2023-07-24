/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _DLPACK_STATE_H
#define _DLPACK_STATE_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/hashtable.h>

/**
 * typedef action - action函数指针，在进入/离开state时调用
 * @arg:
 */
typedef void (*action)(void *arg);

/**
 * typedef constraint - transition约束函数
 * @arg:
 *
 * Return:
 *   0: 满足约束
 *   others: 不满足
 */
typedef int (*constraint)(void *arg);

/**
 * typedef fsm_state - FSM的state定义
 * @id: state id
 * @name: state名称
 * @entry_action: 进入state时执行的函数
 * @exit_action: 离开state时执行的函数
 * @trans: 状态转移表
 * @rule_head: 规则列表
 */
struct fsm_state {
	int id;
	//int atoms;
	//char name[MAX_STATE_LEN];
	action entry_action;
	action exit_action;
	DECLARE_HASHTABLE(trans, 4);
	struct list_head rule_head;
	struct hlist_node node;
	int syscall_pattern_id;
};

/**
 * typedef fsm_trans_list - 状态转换链表表项定义，原状态相同的在同一链表中
 * @list: 当前节点
 * @next_state: 下一个状态号
 * @event: 某个预定义的事件
 * @guard: 约束函数
 */
struct fsm_trans_list {
	struct hlist_node node;
	struct fsm_state *next_state;
	int event;
	constraint guard;
} __randomize_layout;

int add_state(int id);
int add_trie_node(int id, int syscall_pattern_id);
struct fsm_state *get_state(int id);
struct fsm_state *get_trie_node(int id);
int add_trans(struct fsm_state *ori_p, struct fsm_state *target_p, int event_id);
struct fsm_trans_list *find_trans_item(struct fsm_state *state, int event);
void reset_states(void);
int init_states(void);
int init_trie(void);
void trans_del(struct fsm_state *state);
void print_all_state(void);

#endif  /* _DLPACK_STATE_H */
