// SPDX-License-Identifier: GPL-2.0-only
#include <linux/stddef.h>
#include <linux/sysctl.h>
#include "include/dlpack.h"
#include "include/action.h"
#include "include/state.h"

/**
 * print_enter_state - 打印进入状态
 * @state: 状态名
 *
 * Return: 
 *   void
 */
static void print_enter_state(struct fsm_state *state)
{
	dlpack_info("Enter state %d(Process %d).\n", state->id, current->pid);
}

/**
 * print_exit_state - 打印退出状态
 * @state: 状态名
 *
 * Return: 
 *   void
 */
static void print_exit_state(struct fsm_state *state)
{
	dlpack_info("Exit state %d(Process %d).\n", state->id, current->pid);
}

/**
 * entry_print_state - 进入state时的action
 * @arg: action 参数
 *
 * Return: 
 *   void
 */
void entry_print_state(void *arg)
{
	print_enter_state((struct fsm_state *)arg);
}

/**
 * exit_print_state - 退出state时的action
 * @arg: action 参数
 *
 * Return: 
 *   void
 */
void exit_print_state(void *arg)
{
	print_exit_state((struct fsm_state *)arg);
}
