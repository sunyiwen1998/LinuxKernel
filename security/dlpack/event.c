// SPDX-License-Identifier: GPL-2.0-only
#include <linux/slab.h>
#include "include/dlpack.h"
#include "include/event.h"

DEFINE_HASHTABLE(events, 10);

static int cur_event_id = 0;

/**
 * add_event - 添加事件
 * @key: 事件名
 *
 * Return:
 *   0: 成功添加事件
 *   Others: 失败
 */
int add_event(char *key)
{
	struct event *evt;
	size_t size;

	evt = kmalloc(sizeof(*evt), GFP_KERNEL);
	if (!evt) {
		return -ENOMEM;
	}
	size = strlen(key);
	if (size > MAX_EVENT_LEN) {
		return -EINVAL;
	}
	evt->evt_id = cur_event_id++;
	strcpy(evt->name, key);
	hash_add(events, &evt->node, hash(key));

	dlpack_info("Add event %s.", key);

	return 0;
}

/**
 * get_event_id - 获得事件ID
 * @key: 事件名
 *
 * Return: 事件ID，负数表示不存在该事件
 */
int get_event_id(char *key)
{
	struct event *evt;
	size_t size;
	unsigned int keyi;

	size = strlen(key);
	keyi = hash(key);
	if (size > MAX_EVENT_LEN) {
		return -EINVAL;
	}
	hash_for_each_possible(events, evt, node, keyi) {
		if (!strcmp(evt->name, key)) {
			return evt->evt_id;
		}
	}
	return -EINVAL;
}

/**
 *init_events - 初始化事件
 *
 * Return: 
 *   0: 未状态
 *   1: 成功初始化
 */
int init_events(void)
{
	char event[MAX_EVENT_LEN];
	int ret;

	ret = 0;

	for (int i = 0; i < MAX_STATE_LEN; i++) {
		snprintf(event, MAX_EVENT_LEN, "ATOMIC_%d", i);
		ret = add_event(event);
		if (ret != 0) {
			return ret;
		}
	}

	return ret;
}
