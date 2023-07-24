/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _DLPACK_EVENT_H
#define _DLPACK_EVENT_H

#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/sched.h>

#define MAX_EVENT_LEN 30

struct event {
	int evt_id;
	char name[MAX_EVENT_LEN];
	struct hlist_node node;
};

int add_event(char *name);
int get_event_id(char *name);
char *get_event_name(int id);
int init_events(void);

#endif  /* _DLPACK_EVENT_H */
